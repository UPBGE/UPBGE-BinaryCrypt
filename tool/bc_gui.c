/* SPDX-License-Identifier: GPL-2.0-or-later */

/* bc_tool editor: raylib + raygui immediate mode GUI over a BC_Project.
 *
 * Idle frames block on input (event waiting), so the editor costs no CPU while untouched. While
 * encrypting, each frame hands about 12 ms to the batch job: the window stays responsive and the
 * progress bar is live, with no threads and no synchronization. */

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "raylib.h"

#include "raygui.h"

#include "bc_brand.h"
#include "bc_dialog.h"
#include "bc_embed.h"
#include "bc_font_data.h"
#include "bc_gui.h"
#include "bc_job.h"
#include "bc_key.h"
#include "bc_project.h"

/* Window icon from the embedded .ico. Windows takes it from the GLFW_ICON resource (bc_tool.rc)
 * instead; macOS windows have none. */
#if !defined(_WIN32) && !defined(__APPLE__)
#  define BC_WINDOW_ICON
#  include "bc_icon_data.h"
#endif

#define BC_TEXT_SIZE 20
#define BC_ROW 32
#define BC_GAP 8
#define BC_MARGIN 12
#define BC_LABEL_W 150
#define BC_BUTTON_W 130
#define BC_LOG_LINES 256
#define BC_LOG_VISIBLE 7
/* Fewest log lines: below them the page scrolls instead. Most: while the file list is folded the
 * log takes the room. */
#define BC_LOG_MIN 3
#define BC_LOG_ROWS_MAX 48
#define BC_JOB_BUDGET 0.012
#define BC_STATUS_H 26
/* Page scroll bar, in the right margin: the content gives up this width while the page scrolls. */
#define BC_SCROLL_W 8
/* Page scrolled by one wheel notch: two rows. */
#define BC_SCROLL_STEP (2 * (BC_ROW + BC_GAP))
/* raygui's icons, drawn at one pixel per texel (RAYGUI_ICON_SIZE, private to its implementation). */
#define BC_ICON_SIZE 16
/* Seconds between two checks of the files the fields name: they may appear while the tool is
 * open (the runtime copied into the game folder). Edits check again at once. */
#define BC_CHECK_PERIOD 1.0

/* Modifier of the keyboard shortcuts. */
#ifdef __APPLE__
#  define BC_SHORTCUT "Cmd"
#else
#  define BC_SHORTCUT "Ctrl"
#endif

typedef enum BC_Pending {
  BC_PENDING_NONE,
  BC_PENDING_NEW,
  BC_PENDING_OPEN_DIALOG,
  BC_PENDING_OPEN_PATH,
  BC_PENDING_QUIT,
} BC_Pending;

typedef struct BC_LogLine {
  BC_LogLevel level;
  char text[320];
} BC_LogLine;

/** What a field check found. A note is a few words drawn inside the field. */
typedef enum BC_FieldState {
  BC_FIELD_NONE,
  BC_FIELD_OK,
  BC_FIELD_ERROR,
} BC_FieldState;

typedef struct BC_Field {
  BC_FieldState state;
  const char *note;
} BC_Field;

/** Readiness of the project: per field, and what still blocks Encrypt. A subset of the checks of
 * bc_job_create, so a disabled Encrypt never blocks an export the job would accept. */
typedef struct BC_Check {
  BC_Field source, output, runtime, icon, provider;
  bool no_inputs;
  /** What to do before encrypting, empty when ready. */
  char todo[512];
} BC_Check;

typedef struct BC_FileType {
  char ext[BC_DATA_EXT_SIZE]; /* ".json", lowercase. */
  int count;
} BC_FileType;

/** An input as the list shows it, found by the scan: drawing needs no file system call. */
typedef struct BC_InputRow {
  /** A folder: its listed files, sorted, are one run [first, first + count). */
  int first, count;
  bool dir;
  /** What it gives: "3 blends · 4 scripts", "blend · 2.1 MB". */
  char info[64];
} BC_InputRow;

typedef struct BC_Gui {
  BC_Project project;
  char project_path[BC_PATH_MAX];
  bool modified;

  /* Text boxes mirror project fields while not being edited. */
  char source_text[BC_PATH_MAX];
  char output_text[BC_PATH_MAX];
  char player_text[BC_PATH_MAX];
  char game_text[BC_GAME_NAME_MAX + 16]; /* Room for the "  (main file)" note. */
  char icon_text[BC_PATH_MAX];
  char version_text[BC_PROJECT_VERSION_MAX];
  char company_text[BC_PROJECT_TEXT_MAX];
  char copyright_text[BC_PROJECT_TEXT_MAX];
  char key_file_text[BC_PATH_MAX];
  char provider_text[BC_PATH_MAX];
  char url_text[BC_PROJECT_URL_MAX];
  char update_text[16];
  bool source_edit, output_edit, player_edit, game_edit;
  bool icon_edit, version_edit, company_edit, copyright_edit;
  bool key_file_edit, provider_edit, url_edit, update_edit;
  /** Open dropdowns: drawn last, over the rows below them. */
  bool check_edit, manifest_edit, key_edit;

  /** Labels of the inputs, relative to the source folder. */
  char **items;
  int item_count;
  /** First row shown, and the selected input (-1: none). */
  int list_scroll, list_active;
  /** Per input: its folder row folded (its files hidden). */
  bool *input_folded;

  /* What the inputs give, listed as the export lists it. Walking folders, it runs only when the
   * inputs, the folders or the data file extensions change, or the window gets the focus back:
   * never per frame. */
  BC_FileList scan;
  bool scan_ok;
  char scan_error[BC_PATH_MAX + 64];
  unsigned inputs_revision, scan_revision;
  int scan_blends, scan_modules, scan_data;
  uint64_t scan_bytes;
  /** One per input, NULL until the first scan of the inputs. */
  BC_InputRow *input_rows;
  /** File types the inputs hold, every file met counted: .blend and .py first, then by name. */
  BC_FileType *types;
  int type_count, type_capacity, types_scroll;
  /** Files met by the listing running now (BC_Seen), NULL otherwise. */
  void *seen;
  bool focused;

  /** Sections open; folded they show their summary line only. Kept with the help panel switch and
   * the window size from one run to the next (bc_settings_path). */
  bool game_open, build_open, windows_open, protection_open;
  bool help;

  BC_Job *job;
  double job_start;
  /** Shown by the progress bar; kept after a run so a finished batch reads 100%. */
  float progress;

  BC_LogLine log[BC_LOG_LINES];
  int log_count;
  int log_next;
  /** Newest messages scrolled past, 0 when following the log. */
  int log_scroll;

  /** Page scrolled past the top of the window, in whole pixels; 0 while everything fits. */
  float scroll_y;
  /** Page thumb held: where the pointer took it, from its top. */
  bool scroll_drag;
  float scroll_grab;
  /** Where the file list and the log take the wheel themselves, as last drawn: empty while they
   * have nothing to scroll, so the wheel moves the page there. */
  Rectangle list_wheel, types_wheel, log_wheel;

  /** Bumped by every change of the project; the check follows it. */
  unsigned revision;
  unsigned check_revision;
  double check_time;
  BC_Check check;

  /** After a successful export: the game folder and executable, for Open and Run. */
  bool built;
  char built_dir[BC_PATH_MAX];
  char built_exe[BC_PATH_MAX];

  BC_Pending pending;
  char pending_path[BC_PATH_MAX];
  bool quit;
  char fingerprint[BC_FINGERPRINT_SIZE];
} BC_Gui;

/* -------------------------------------------------------------------------------------------- */
/* Log */

static void bc_gui_log(void *user, BC_LogLevel level, const char *message)
{
  BC_Gui *g = (BC_Gui *)user;
  BC_LogLine *line = &g->log[g->log_next];
  line->level = level;
  /* Long messages are cut to the line buffer: the full text also goes to the console. */
  snprintf(line->text, sizeof(line->text), "%.*s", (int)sizeof(line->text) - 1, message);
  g->log_next = (g->log_next + 1) % BC_LOG_LINES;
  if (g->log_count < BC_LOG_LINES) {
    g->log_count++;
  }
  if (g->log_scroll > 0 && g->log_scroll < g->log_count - 1) {
    g->log_scroll++; /* A reader scrolled back keeps the lines in front of them. */
  }
  fprintf(level == BC_LOG_INFO ? stdout : stderr, "%s\n", message);
}

static void bc_gui_logf(BC_Gui *g, BC_LogLevel level, const char *format, ...)
{
  char message[BC_PATH_MAX];
  va_list args;
  va_start(args, format);
  vsnprintf(message, sizeof(message), format, args);
  va_end(args);
  bc_gui_log(g, level, message);
}

/** The whole log, oldest first, to the clipboard. */
static void bc_gui_copy_log(BC_Gui *g)
{
  static char text[BC_LOG_LINES * (sizeof(((BC_LogLine *)0)->text) + 1)];
  size_t n = 0;
  for (int i = g->log_count - 1; i >= 0; i--) {
    const BC_LogLine *line = &g->log[(g->log_next - 1 - i + BC_LOG_LINES) % BC_LOG_LINES];
    n += (size_t)snprintf(text + n, sizeof(text) - n, "%s\n", line->text);
  }
  SetClipboardText(text);
  g->log_scroll = 0; /* Back to the newest line: the confirmation. */
  bc_gui_log(g, BC_LOG_INFO, "Log copied to the clipboard");
}

/* -------------------------------------------------------------------------------------------- */
/* Project state */

static void bc_gui_update_title(BC_Gui *g)
{
  char title[BC_PATH_MAX + 64];
  snprintf(title,
           sizeof(title),
           "UPBGE BinaryCrypt v" BC_TOOL_VERSION " - %s%s",
           g->project_path[0] ? bc_path_basename(g->project_path) : "new project",
           g->modified ? " *" : "");
  SetWindowTitle(title);
}

static void bc_gui_set_modified(BC_Gui *g)
{
  g->revision++;
  if (!g->modified) {
    g->modified = true;
    bc_gui_update_title(g);
  }
}

/** Rebuild the list labels: inputs relative to the source folder, folders with a trailing '/'. The
 * inputs changed: what they give is listed again. */
static void bc_gui_rebuild_items(BC_Gui *g)
{
  g->revision++;
  g->inputs_revision++;
  for (int i = 0; i < g->item_count; i++) {
    free(g->items[i]);
  }
  free(g->items);
  g->items = NULL;
  free(g->input_folded);
  g->input_folded = NULL;
  g->item_count = g->project.input_count;
  if (g->item_count == 0) {
    g->list_active = -1;
    return;
  }
  g->input_folded = (bool *)calloc((size_t)g->item_count, sizeof(bool));
  g->items = (char **)calloc((size_t)g->item_count, sizeof(char *));
  for (int i = 0; i < g->item_count; i++) {
    const char *input = g->project.inputs[i];
    char rel[BC_PATH_MAX];
    const char *shown = input;
    if (g->project.source_root[0] && bc_path_relative(rel, sizeof(rel), g->project.source_root, input)) {
      shown = rel;
    }
    const bool is_dir = bc_is_dir(input);
    const bool is_root = strcmp(shown, ".") == 0;
    const size_t size = strlen(shown) + 32;
    g->items[i] = (char *)malloc(size);
    snprintf(g->items[i], size, "%s%s", is_root ? "(whole source folder)" : shown, is_dir && !is_root ? "/" : "");
  }
  if (g->list_active >= g->item_count) {
    g->list_active = g->item_count - 1;
  }
}

/** Fit \a s into \a width by cutting its start ("...tail"): the end of a path, its file name,
 * is the informative part. */
static void bc_fit_left(const char *s, const float width, char *out, const size_t size)
{
  const Font font = GuiGetFont();
  const float spacing = (float)GuiGetStyle(DEFAULT, TEXT_SPACING);
  snprintf(out, size, "%s", s);
  if (MeasureTextEx(font, out, BC_TEXT_SIZE, spacing).x <= width) {
    return;
  }
  for (const char *tail = s + 1; *tail != '\0'; tail++) {
    snprintf(out, size, "...%s", tail);
    if (MeasureTextEx(font, out, BC_TEXT_SIZE, spacing).x <= width) {
      return;
    }
  }
  snprintf(out, size, "...");
}

/** New projects put the player in the conventional engine/ folder of the game. */
static void bc_gui_default_player(BC_Gui *g)
{
  if (g->project.player[0] == '\0') {
    snprintf(g->project.player, sizeof(g->project.player), "%s%s", BC_DEFAULT_PLAYER, bc_exe_extension());
  }
}

/** Name the game executable will get: the explicit name, else the main file name. */
static void bc_gui_effective_game_name(const BC_Gui *g, char *out, size_t size, bool *r_is_default)
{
  *r_is_default = g->project.game_name[0] == '\0';
  if (!*r_is_default) {
    snprintf(out, size, "%s", g->project.game_name);
    return;
  }
  snprintf(out, size, "%s", g->project.main[0] ? bc_path_basename(g->project.main) : "game");
  if (bc_path_has_extension(out, ".blend")) {
    out[strlen(out) - 6] = '\0';
  }
}

/** A path typed by the user: relative paths are taken from the project folder once the project
 * is saved, from the current folder before. Empty stays empty. */
static void bc_gui_resolve(BC_Gui *g, const char *text, char *out)
{
  out[0] = '\0';
  if (text[0] == '\0') {
    return;
  }
  if (g->project_path[0] != '\0' && !bc_path_is_absolute(text)) {
    char dir[BC_PATH_MAX];
    bc_path_dirname(dir, sizeof(dir), g->project_path);
    bc_path_join(out, BC_PATH_MAX, dir, text);
  }
  else {
    bc_path_make_absolute(out, BC_PATH_MAX, text);
  }
}

/** The player and the key provider are stored relative to the distribution root; accept an
 * absolute path inside it. */
static void bc_gui_set_dist_path(BC_Gui *g, const char *path, char *field, const size_t field_size, const char *what)
{
  char normalized[BC_PATH_MAX];
  snprintf(normalized, sizeof(normalized), "%s", path);
  bc_path_normalize(normalized);
  if (normalized[0] == '\0' || strcmp(normalized, ".") == 0) {
    field[0] = '\0';
  }
  else if (!bc_path_is_absolute(normalized)) {
    snprintf(field, field_size, "%s", normalized);
  }
  else {
    const char *dist = bc_project_dist_root(&g->project);
    char rel[BC_PATH_MAX];
    if (dist[0] == '\0' || !bc_path_relative(rel, sizeof(rel), dist, normalized)) {
      bc_gui_logf(g,
                  BC_LOG_ERROR,
                  "The %s must be inside the distribution folder ('%s'): copy it there first",
                  what,
                  dist[0] ? dist : "set the folders first");
      return;
    }
    snprintf(field, field_size, "%s", rel);
  }
  bc_gui_set_modified(g);
}

static void bc_gui_set_player(BC_Gui *g, const char *path)
{
  bc_gui_set_dist_path(g, path, g->project.player, sizeof(g->project.player), "player (with the UPBGE runtime)");
}

/** Add a dropped or picked path: a folder, or a file of any kind (.blend, module, data file). The
 * first one also seeds the source folder, the first .blend the main file. */
static void bc_gui_add_input(BC_Gui *g, const char *path)
{
  char normalized[BC_PATH_MAX];
  snprintf(normalized, sizeof(normalized), "%s", path);
  bc_path_normalize(normalized);
  const bool is_dir = bc_is_dir(normalized);
  if (g->project.source_root[0] == '\0') {
    if (is_dir) {
      snprintf(g->project.source_root, sizeof(g->project.source_root), "%s", normalized);
    }
    else {
      bc_path_dirname(g->project.source_root, sizeof(g->project.source_root), normalized);
    }
  }
  if (g->project.main[0] == '\0' && !is_dir && bc_path_has_extension(normalized, ".blend")) {
    snprintf(g->project.main, sizeof(g->project.main), "%s", normalized);
  }
  bc_project_add_input(&g->project, normalized);
  bc_gui_set_modified(g);
}

static void bc_gui_load(BC_Gui *g, const char *path)
{
  BC_Project loaded;
  char err[BC_PATH_MAX + 128];
  bc_project_init(&loaded);
  if (!bc_project_load(&loaded, path, err, sizeof(err))) {
    bc_gui_logf(g, BC_LOG_ERROR, "Cannot open '%s': %s", path, err);
    return;
  }
  bc_project_free(&g->project);
  g->project = loaded;
  bc_path_make_absolute(g->project_path, sizeof(g->project_path), path);
  g->modified = false;
  g->list_active = -1;
  g->built = false;
  bc_gui_rebuild_items(g);
  bc_gui_update_title(g);
  bc_gui_logf(g, BC_LOG_INFO, "Opened %s", g->project_path);
}

static bool bc_gui_save(BC_Gui *g, const bool ask_path)
{
  if (ask_path || g->project_path[0] == '\0') {
    char path[BC_PATH_MAX];
    const BC_DialogResult r = bc_dialog_save_file("Save project", "bcproj", path, sizeof(path));
    if (r == BC_DIALOG_UNAVAILABLE) {
      bc_gui_log(g, BC_LOG_ERROR, "No file dialog available: install zenity or kdialog");
    }
    if (r != BC_DIALOG_OK) {
      return false;
    }
    /* The default key file follows the project file's name: a project saved under a new name
     * keeps the key it already has (a published game must keep its key). */
    char key_file[BC_PATH_MAX];
    if (g->project.key_mode != BC_KEY_BUILD && g->project.key_file[0] == '\0' &&
        bc_project_key_file(&g->project, key_file, sizeof(key_file)) && bc_is_file(key_file))
    {
      snprintf(g->project.key_file, sizeof(g->project.key_file), "%s", key_file);
      bc_gui_logf(g, BC_LOG_INFO, "The project keeps its key file %s", key_file);
    }
    snprintf(g->project_path, sizeof(g->project_path), "%s", path);
  }
  char err[BC_PATH_MAX + 128];
  if (!bc_project_save(&g->project, g->project_path, err, sizeof(err))) {
    bc_gui_logf(g, BC_LOG_ERROR, "Cannot save: %s", err);
    return false;
  }
  bc_path_make_absolute(g->project.project_file, sizeof(g->project.project_file), g->project_path);
  g->modified = false;
  bc_gui_update_title(g);
  bc_gui_logf(g, BC_LOG_INFO, "Saved %s", g->project_path);
  return true;
}

static void bc_gui_reset(BC_Gui *g)
{
  bc_project_free(&g->project);
  bc_gui_default_player(g);
  g->project_path[0] = '\0';
  g->modified = false;
  g->list_active = -1;
  g->built = false;
  bc_gui_rebuild_items(g);
  bc_gui_update_title(g);
}

static void bc_gui_open_dialog(BC_Gui *g)
{
  char path[BC_PATH_MAX];
  const BC_DialogResult r = bc_dialog_open_files("Open project", "bcproj", false, path, sizeof(path));
  if (r == BC_DIALOG_OK) {
    bc_gui_load(g, path);
  }
  else if (r == BC_DIALOG_UNAVAILABLE) {
    bc_gui_log(g, BC_LOG_ERROR, "No file dialog available: install zenity or kdialog, or drop the .bcproj file on the window");
  }
}

/** Run \a action now, or ask first when it would discard unsaved changes. */
static void bc_gui_request(BC_Gui *g, const BC_Pending action, const char *path)
{
  if (path != NULL) {
    snprintf(g->pending_path, sizeof(g->pending_path), "%s", path);
  }
  if (g->modified) {
    g->pending = action;
    return;
  }
  switch (action) {
    case BC_PENDING_NEW:
      bc_gui_reset(g);
      break;
    case BC_PENDING_OPEN_DIALOG:
      bc_gui_open_dialog(g);
      break;
    case BC_PENDING_OPEN_PATH:
      bc_gui_load(g, g->pending_path);
      break;
    case BC_PENDING_QUIT:
      g->quit = true;
      break;
    case BC_PENDING_NONE:
      break;
  }
}

static void bc_gui_dialog_unavailable(BC_Gui *g)
{
  bc_gui_log(g,
             BC_LOG_WARNING,
             "No file dialog available on this system (install zenity or kdialog): type the path "
             "or drop files and folders on the window");
}

/* -------------------------------------------------------------------------------------------- */
/* Settings: how the editor looked, kept from one run to the next. A plain "key = value" file; a
 * missing, unknown or damaged line keeps its default. */

#define BC_WINDOW_MIN_W 1000
#define BC_WINDOW_MIN_H 500

static void bc_gui_load_settings(BC_Gui *g, int *r_width, int *r_height)
{
  g->help = true;
  g->game_open = g->build_open = true;
  g->windows_open = g->protection_open = false;
  /* Tall enough for every row of a Windows build with online keys, and still within a 1080p
   * screen with its taskbar. */
  *r_width = 1100;
  *r_height = 980;
  char path[BC_PATH_MAX];
  FILE *f = bc_settings_path(path, sizeof(path)) ? bc_fopen(path, "rb") : NULL;
  if (f == NULL) {
    return;
  }
  struct {
    const char *key;
    bool *value;
  } flags[] = {
      {"help", &g->help},
      {"game_open", &g->game_open},
      {"build_open", &g->build_open},
      {"windows_open", &g->windows_open},
      {"protection_open", &g->protection_open},
  };
  char line[128];
  while (fgets(line, sizeof(line), f) != NULL) {
    char key[32];
    int value;
    if (sscanf(line, " %31[a-z_] = %d", key, &value) != 2) {
      continue;
    }
    for (size_t i = 0; i < sizeof(flags) / sizeof(flags[0]); i++) {
      if (strcmp(key, flags[i].key) == 0) {
        *flags[i].value = value != 0;
      }
    }
    if (strcmp(key, "window_width") == 0 && value >= BC_WINDOW_MIN_W && value <= 16384) {
      *r_width = value;
    }
    else if (strcmp(key, "window_height") == 0 && value >= BC_WINDOW_MIN_H && value <= 16384) {
      *r_height = value;
    }
  }
  fclose(f);
}

/** Best effort: settings that cannot be written are simply the defaults next time. */
static void bc_gui_save_settings(const BC_Gui *g)
{
  char path[BC_PATH_MAX], dir[BC_PATH_MAX];
  if (!bc_settings_path(path, sizeof(path))) {
    return;
  }
  bc_path_dirname(dir, sizeof(dir), path);
  FILE *f = bc_mkdir_p(dir) ? bc_fopen(path, "wb") : NULL;
  if (f == NULL) {
    return;
  }
  fprintf(f,
          "# bc_tool editor settings\n"
          "help = %d\ngame_open = %d\nbuild_open = %d\nwindows_open = %d\nprotection_open = %d\n"
          "window_width = %d\nwindow_height = %d\n",
          g->help,
          g->game_open,
          g->build_open,
          g->windows_open,
          g->protection_open,
          GetScreenWidth(),
          GetScreenHeight());
  fclose(f);
}

/* -------------------------------------------------------------------------------------------- */
/* Job */

static void bc_gui_start(BC_Gui *g)
{
  bc_gui_log(g, BC_LOG_INFO, "-- Encrypting --");
  char launcher[BC_PATH_MAX];
  bc_tool_launcher_path(launcher, sizeof(launcher));
  g->job = bc_job_create(&g->project, bc_build_key(), launcher, bc_gui_log, g);
  g->progress = 0.0f;
  g->built = false;
  g->log_scroll = 0;
  if (g->job != NULL) {
    g->job_start = GetTime();
  }
}

static void bc_gui_stop(BC_Gui *g, const char *reason)
{
  bc_job_destroy(g->job);
  g->job = NULL;
  if (reason != NULL) {
    bc_gui_log(g, BC_LOG_WARNING, reason);
  }
}

static void bc_gui_tick_job(BC_Gui *g)
{
  const int result = bc_job_step(g->job, BC_JOB_BUDGET);
  g->progress = (float)bc_job_progress(g->job);
  if (result == 1) {
    return;
  }
  if (result == 0) {
    bc_gui_logf(g, BC_LOG_INFO, "Finished in %.2f s", GetTime() - g->job_start);
    char name[BC_GAME_NAME_MAX + 8];
    bool is_default;
    bc_gui_effective_game_name(g, name, BC_GAME_NAME_MAX, &is_default);
    strcat(name, bc_exe_extension());
    snprintf(g->built_dir, sizeof(g->built_dir), "%s", g->project.output_dir);
    g->built = bc_path_join(g->built_exe, sizeof(g->built_exe), g->built_dir, name);
  }
  else {
    bc_gui_log(g, BC_LOG_ERROR, "Encryption failed");
  }
  bc_gui_stop(g, NULL);
  g->revision++; /* Outputs exist now. */
}

/* -------------------------------------------------------------------------------------------- */
/* Readiness */

static void bc_field_set(BC_Field *f, const BC_FieldState state, const char *note)
{
  f->state = state;
  f->note = note;
}

static void bc_todo(BC_Check *c, const char *action)
{
  const size_t n = strlen(c->todo);
  snprintf(c->todo + n, sizeof(c->todo) - n, "%s%s", n ? "  \xc2\xb7  " : "", action);
}

static int bc_listed_compare(const void *key, const void *item)
{
  return strcmp((const char *)key, ((const BC_ListedFile *)item)->path);
}

/** Index of the main file among the listed files, -1 when it is not one of them. */
static int bc_gui_main_index(const BC_Gui *g)
{
  if (g->project.main[0] == '\0' || g->scan.count == 0) {
    return -1;
  }
  const BC_ListedFile *found = (const BC_ListedFile *)bsearch(
      g->project.main, g->scan.files, (size_t)g->scan.count, sizeof(BC_ListedFile), bc_listed_compare);
  return found ? (int)(found - g->scan.files) : -1;
}

/** "980 B", "12 KB", "2.1 MB", "140 MB", "1.2 GB": two or three digits are enough to compare. */
static void bc_format_size(const uint64_t bytes, char *out, const size_t size)
{
  static const char *const units[] = {"B", "KB", "MB", "GB", "TB"};
  double value = (double)bytes;
  int unit = 0;
  while (value >= 1000.0 && unit < 4) {
    value /= 1024.0;
    unit++;
  }
  snprintf(out, size, unit > 0 && value < 10.0 ? "%.1f %s" : "%.0f %s", value, units[unit]);
}

static void bc_gui_scan_log(void *user, const BC_LogLevel level, const char *message)
{
  BC_Gui *g = (BC_Gui *)user;
  if (level == BC_LOG_ERROR && g->scan_error[0] == '\0') {
    snprintf(g->scan_error, sizeof(g->scan_error), "%s", message);
  }
}

/** Add \a n files to type \a ext ("." and lowercase), a new row if it has none yet. Types are
 * few: a linear search. */
static void bc_gui_count_type(BC_Gui *g, const char *ext, const int n)
{
  for (int i = 0; i < g->type_count; i++) {
    if (strcmp(g->types[i].ext, ext) == 0) {
      g->types[i].count += n;
      return;
    }
  }
  if (g->type_count == g->type_capacity) {
    const int capacity = g->type_capacity ? 2 * g->type_capacity : 32;
    BC_FileType *types = (BC_FileType *)realloc(g->types, sizeof(BC_FileType) * (size_t)capacity);
    if (types == NULL) {
      return;
    }
    g->types = types;
    g->type_capacity = capacity;
  }
  snprintf(g->types[g->type_count].ext, sizeof(g->types[g->type_count].ext), "%s", ext);
  g->types[g->type_count].count = n;
  g->type_count++;
}

/** Files met by the listing, kept until it ends: overlapping inputs (a folder and a folder
 * inside it) meet a file more than once, and a file counts once. */
typedef struct BC_Seen {
  char **paths;
  int count, capacity;
} BC_Seen;

static void bc_gui_scan_seen(void *user, const char *path)
{
  BC_Seen *seen = (BC_Seen *)((BC_Gui *)user)->seen;
  if (seen->count == seen->capacity) {
    const int capacity = seen->capacity ? 2 * seen->capacity : 256;
    char **paths = (char **)realloc(seen->paths, sizeof(char *) * (size_t)capacity);
    if (paths == NULL) {
      return;
    }
    seen->paths = paths;
    seen->capacity = capacity;
  }
  const size_t n = strlen(path) + 1;
  char *copy = (char *)malloc(n);
  if (copy != NULL) {
    memcpy(copy, path, n);
    seen->paths[seen->count++] = copy;
  }
}

static int bc_string_compare(const void *a, const void *b)
{
  return strcmp(*(char *const *)a, *(char *const *)b);
}

/** Each file met once, counted under its type: its last extension, lowercase. Hidden files
 * (.DS_Store, .gitignore) and files without an extension are no type to choose. */
static void bc_gui_count_seen(BC_Gui *g, BC_Seen *seen)
{
  if (seen->count > 1) {
    qsort(seen->paths, (size_t)seen->count, sizeof(char *), bc_string_compare);
  }
  for (int i = 0; i < seen->count; i++) {
    const char *path = seen->paths[i];
    if (i > 0 && strcmp(path, seen->paths[i - 1]) == 0) {
      continue;
    }
    const char *name = bc_path_basename(path);
    const char *dot = strrchr(name, '.');
    if (name[0] == '.' || dot == NULL || dot[1] == '\0' || strlen(dot) >= BC_DATA_EXT_SIZE) {
      continue;
    }
    char ext[BC_DATA_EXT_SIZE];
    size_t n = 0;
    for (; dot[n] != '\0'; n++) {
      ext[n] = (char)tolower((unsigned char)dot[n]);
    }
    ext[n] = '\0';
    bc_gui_count_type(g, ext, 1);
  }
  for (int i = 0; i < seen->count; i++) {
    free(seen->paths[i]);
  }
  free(seen->paths);
  memset(seen, 0, sizeof(*seen));
}

/** .blend, then .py, then the other types by name. */
static int bc_type_compare(const void *a, const void *b)
{
  const char *x = ((const BC_FileType *)a)->ext, *y = ((const BC_FileType *)b)->ext;
  const int rx = strcmp(x, ".blend") == 0 ? 0 : strcmp(x, ".py") == 0 ? 1 : 2;
  const int ry = strcmp(y, ".blend") == 0 ? 0 : strcmp(y, ".py") == 0 ? 1 : 2;
  return rx != ry ? rx - ry : strcmp(x, y);
}

/** List what the inputs give, as the export does; count it per kind and per input, and count every
 * file met per type. */
static void bc_gui_refresh_scan(BC_Gui *g)
{
  if (g->scan_revision == g->inputs_revision) {
    return;
  }
  g->scan_revision = g->inputs_revision;
  g->revision++; /* The check reads the list. */
  bc_file_list_free(&g->scan);
  free(g->input_rows);
  g->input_rows = NULL;
  /* .blend and .py always have a row: what is always encrypted shows before any file is added. */
  g->type_count = 0;
  bc_gui_count_type(g, ".blend", 0);
  bc_gui_count_type(g, ".py", 0);
  g->scan_ok = false;
  g->scan_error[0] = '\0';
  g->scan_blends = g->scan_modules = g->scan_data = 0;
  g->scan_bytes = 0;
  const BC_Project *p = &g->project;
  if (p->input_count == 0 || p->source_root[0] == '\0') {
    return;
  }
  char ext[BC_DATA_EXT_MAX][BC_DATA_EXT_SIZE];
  char err[256];
  const int ext_count = bc_project_data_extensions(p, ext, BC_DATA_EXT_MAX, err, sizeof(err));
  if (ext_count < 0) {
    snprintf(g->scan_error, sizeof(g->scan_error), "File types: %s", err);
    return;
  }
  BC_Seen seen = {NULL, 0, 0};
  g->seen = &seen;
  g->scan_ok = bc_project_list_files(p, ext, ext_count, bc_gui_scan_log, bc_gui_scan_seen, g, &g->scan);
  g->seen = NULL;
  bc_gui_count_seen(g, &seen);
  int *counts[3] = {&g->scan_blends, &g->scan_modules, &g->scan_data};
  for (int i = 0; i < g->scan.count; i++) {
    (*counts[g->scan.files[i].kind])++;
    g->scan_bytes += g->scan.files[i].size;
  }
  /* A chosen type no file has (or one of two dots, "tar.gz", counted above as ".gz") keeps a row,
   * so it can be unticked: counted from the listed files. */
  for (int e = 0; e < ext_count; e++) {
    bool known = false;
    for (int i = 0; i < g->type_count && !known; i++) {
      known = strlen(g->types[i].ext) == strlen(ext[e]) && bc_path_has_extension(g->types[i].ext, ext[e]);
    }
    if (!known) {
      int n = 0;
      for (int f = 0; f < g->scan.count; f++) {
        n += g->scan.files[f].kind == BC_KIND_DATA && bc_path_has_extension(g->scan.files[f].path, ext[e]) ? 1 : 0;
      }
      char lower[BC_DATA_EXT_SIZE];
      size_t k = 0;
      for (; ext[e][k] != '\0'; k++) {
        lower[k] = (char)tolower((unsigned char)ext[e][k]);
      }
      lower[k] = '\0';
      bc_gui_count_type(g, lower, n);
    }
  }
  if (g->type_count > 1) {
    qsort(g->types, (size_t)g->type_count, sizeof(BC_FileType), bc_type_compare);
  }
  /* Per input, what it gives and, for a folder, where its files are among the sorted listed files. */
  g->input_rows = (BC_InputRow *)calloc((size_t)p->input_count, sizeof(BC_InputRow));
  for (int i = 0; g->input_rows != NULL && i < p->input_count; i++) {
    const char *input = p->inputs[i];
    BC_InputRow *row = &g->input_rows[i];
    char *text = row->info;
    row->dir = bc_is_dir(input);
    if (row->dir) {
      int n[3] = {0, 0, 0};
      int first = -1, count = 0;
      for (int f = 0; f < g->scan.count; f++) {
        if (bc_path_is_inside(input, g->scan.files[f].path)) {
          n[g->scan.files[f].kind]++;
          first = first < 0 ? f : first;
          count++;
        }
      }
      row->first = first < 0 ? 0 : first;
      row->count = count;
      static const char *const names[3][2] = {{"blend", "blends"}, {"script", "scripts"}, {"data file", "data files"}};
      for (int k = 0; k < 3; k++) {
        if (n[k] > 0) {
          const size_t used = strlen(text);
          snprintf(text + used, sizeof(row->info) - used, "%s%d %s", used ? "  \xc2\xb7  " : "", n[k], names[k][n[k] != 1]);
        }
      }
      if (text[0] == '\0') {
        snprintf(text, sizeof(row->info), "nothing to encrypt");
      }
    }
    else {
      uint64_t bytes = 0;
      char size[24];
      bc_file_size(input, &bytes);
      bc_format_size(bytes, size, sizeof(size));
      static const char *const kinds[3] = {"blend", "script", "data"};
      const int kind = bc_path_has_extension(input, ".blend") ? 0 : bc_path_has_extension(input, ".py") ? 1 : 2;
      snprintf(text, sizeof(row->info), "%s  \xc2\xb7  %s", kinds[kind], size);
    }
  }
}

/** Tick or untick a data file type: the project's extensions, written again without it or with it
 * added. */
static void bc_gui_toggle_type(BC_Gui *g, const char *type)
{
  char ext[BC_DATA_EXT_MAX][BC_DATA_EXT_SIZE];
  char err[256];
  const int count = bc_project_data_extensions(&g->project, ext, BC_DATA_EXT_MAX, err, sizeof(err));
  if (count < 0) {
    bc_gui_logf(g, BC_LOG_ERROR, "File types: %s", err);
    return;
  }
  char text[BC_PROJECT_TEXT_MAX] = "";
  bool removed = false;
  for (int i = 0; i < count; i++) {
    if (strlen(ext[i]) == strlen(type) && bc_path_has_extension(ext[i], type)) {
      removed = true;
      continue;
    }
    const size_t used = strlen(text);
    snprintf(text + used, sizeof(text) - used, "%s%s", used ? " " : "", ext[i] + 1);
  }
  if (!removed) {
    if (count == BC_DATA_EXT_MAX) {
      bc_gui_logf(g, BC_LOG_ERROR, "File types: more than %d", BC_DATA_EXT_MAX);
      return;
    }
    const size_t used = strlen(text);
    if ((size_t)snprintf(text + used, sizeof(text) - used, "%s%s", used ? " " : "", type + 1) >= sizeof(text) - used) {
      bc_gui_log(g, BC_LOG_ERROR, "File types: too many");
      return;
    }
  }
  snprintf(g->project.data_extensions, sizeof(g->project.data_extensions), "%s", text);
  bc_gui_set_modified(g);
  g->inputs_revision++;
}

/** Check what the fields name. Only stat calls, and only on change or every BC_CHECK_PERIOD:
 * nothing per frame. An empty required field is no error: its placeholder says "Required" and the
 * Encrypt row lists it, so a new project does not open in red. */
static void bc_gui_refresh_check(BC_Gui *g)
{
  if (g->check_revision == g->revision && GetTime() - g->check_time < BC_CHECK_PERIOD) {
    return;
  }
  g->check_revision = g->revision;
  g->check_time = GetTime();
  const BC_Project *p = &g->project;
  BC_Check *c = &g->check;
  memset(c, 0, sizeof(*c));

  if (p->source_root[0] == '\0') {
    bc_field_set(&c->source, BC_FIELD_NONE, NULL);
    bc_todo(c, "set the source folder");
  }
  else if (!bc_is_dir(p->source_root)) {
    bc_field_set(&c->source, BC_FIELD_ERROR, "not found");
    bc_todo(c, "the source folder does not exist");
  }
  else {
    bc_field_set(&c->source, BC_FIELD_OK, NULL);
  }

  if (p->output_dir[0] == '\0') {
    bc_field_set(&c->output, BC_FIELD_NONE, NULL);
    bc_todo(c, "set the output folder");
  }
  else if (p->source_root[0] != '\0' && bc_path_is_inside(p->output_dir, p->source_root)) {
    bc_field_set(&c->output, BC_FIELD_ERROR, "holds the sources");
    bc_todo(c, "choose an output folder outside the source folder");
  }
  else {
    bc_field_set(&c->output, BC_FIELD_OK, NULL);
  }

  /* The runtime lives in the game folder: nothing to check before there is one. */
  char path[BC_PATH_MAX];
  if (p->player[0] == '\0') {
    bc_field_set(&c->runtime, BC_FIELD_NONE, NULL);
    bc_todo(c, "set the UPBGE runtime");
  }
  else if (c->output.state == BC_FIELD_OK) {
    if (bc_path_join(path, sizeof(path), p->output_dir, p->player) && bc_is_file(path)) {
      bc_field_set(&c->runtime, BC_FIELD_OK, NULL);
    }
    else {
      bc_field_set(&c->runtime, BC_FIELD_ERROR, "not found");
      bc_todo(c, "copy the UPBGE runtime into the output folder");
    }
  }

  /* The main file is marked in the list: it must be one of the files the list gives. */
  if (p->input_count == 0) {
    c->no_inputs = true;
    bc_todo(c, "add files to encrypt");
  }
  else if (g->scan_error[0] != '\0') {
    bc_todo(c, "fix the file list");
  }
  else if (g->scan_ok && g->scan.count == 0) {
    bc_todo(c, "the list gives no files to encrypt");
  }
  if (p->main[0] == '\0') {
    bc_todo(c, "mark the main file (the star of a .blend in the list)");
  }
  else if (!bc_is_file(p->main)) {
    bc_todo(c, "the main file does not exist");
  }
  else if (!bc_path_has_extension(p->main, ".blend")) {
    bc_todo(c, "the main file must be a .blend");
  }
  else if (g->scan_ok && bc_gui_main_index(g) < 0) {
    bc_todo(c, "the main file is not in the list: mark another one");
  }

  if (bc_brand_supported() && p->icon[0] != '\0') {
    if (bc_is_file(p->icon)) {
      bc_field_set(&c->icon, BC_FIELD_OK, NULL);
    }
    else {
      bc_field_set(&c->icon, BC_FIELD_ERROR, "not found");
      bc_todo(c, "the icon does not exist");
    }
  }

  if (p->key_mode == BC_KEY_ONLINE) {
    if (p->key_provider[0] == '\0') {
      bc_field_set(&c->provider, BC_FIELD_NONE, NULL);
      bc_todo(c, "set the key provider");
    }
    else if (c->output.state == BC_FIELD_OK) {
      if (bc_path_join(path, sizeof(path), p->output_dir, p->key_provider) && bc_is_file(path)) {
        bc_field_set(&c->provider, BC_FIELD_OK, NULL);
      }
      else {
        bc_field_set(&c->provider, BC_FIELD_ERROR, "not found");
        bc_todo(c, "copy the key provider into the output folder");
      }
    }
  }
}

static bool bc_gui_ready(BC_Gui *g)
{
  bc_gui_refresh_check(g);
  return g->check.todo[0] == '\0';
}

/** A text field or a dropdown has the keyboard: shortcuts stay off. */
static bool bc_gui_editing(const BC_Gui *g)
{
  return g->source_edit || g->output_edit || g->player_edit || g->game_edit ||
         g->icon_edit || g->version_edit || g->company_edit || g->copyright_edit ||
         g->key_file_edit || g->provider_edit || g->url_edit || g->update_edit ||
         g->check_edit || g->manifest_edit || g->key_edit;
}

/* -------------------------------------------------------------------------------------------- */
/* Input events */

/** Ctrl (Cmd on macOS) + N, O, S, Shift+S and Enter. \return true when one was used. */
static bool bc_gui_shortcuts(BC_Gui *g)
{
  if (g->pending != BC_PENDING_NONE || g->job != NULL || bc_gui_editing(g)) {
    return false;
  }
#ifdef __APPLE__
  const bool command = IsKeyDown(KEY_LEFT_SUPER) || IsKeyDown(KEY_RIGHT_SUPER);
#else
  const bool command = IsKeyDown(KEY_LEFT_CONTROL) || IsKeyDown(KEY_RIGHT_CONTROL);
#endif
  if (!command) {
    return false;
  }
  if (IsKeyPressed(KEY_N)) {
    bc_gui_request(g, BC_PENDING_NEW, NULL);
  }
  else if (IsKeyPressed(KEY_O)) {
    bc_gui_request(g, BC_PENDING_OPEN_DIALOG, NULL);
  }
  else if (IsKeyPressed(KEY_S)) {
    bc_gui_save(g, IsKeyDown(KEY_LEFT_SHIFT) || IsKeyDown(KEY_RIGHT_SHIFT));
  }
  else if ((IsKeyPressed(KEY_ENTER) || IsKeyPressed(KEY_KP_ENTER)) && bc_gui_ready(g)) {
    bc_gui_start(g);
  }
  else {
    return false;
  }
  return true;
}

static void bc_gui_handle_drop(BC_Gui *g)
{
  FilePathList dropped = LoadDroppedFiles();
  for (unsigned int i = 0; i < dropped.count; i++) {
    if (bc_path_has_extension(dropped.paths[i], BC_PROJECT_EXTENSION)) {
      bc_gui_request(g, BC_PENDING_OPEN_PATH, dropped.paths[i]);
      break;
    }
    bc_gui_add_input(g, dropped.paths[i]);
  }
  UnloadDroppedFiles(dropped);
  bc_gui_rebuild_items(g);
}

/* -------------------------------------------------------------------------------------------- */
/* Drawing */

static Rectangle bc_rect(float x, float y, float w, float h)
{
  Rectangle r = {x, y, w, h};
  return r;
}

/* -------------------------------------------------------------------------------------------- */
/* Theme: the palette of upbge.org (near black, UPBGE orange) over Blender's neutral grays, set in
 * Montserrat, the typeface of upbge.org. */

/* 0xRRGGBB as a raygui style value (0xRRGGBBAA in an int). */
#define BC_RGB(rgb) ((int)(((unsigned)(rgb) << 8) | 0xffu))
#define BC_RGB_ACCENT 0xf99543 /* UPBGE orange. */
#define BC_RGB_ON_ACCENT 0x121212 /* Text on the accent: 8.9:1 contrast. */
/* Log levels: yellow and red, so a warning never reads as the accent. */
#define BC_RGB_WARNING 0xfbbf24
#define BC_RGB_ERROR 0xf87171
/* A field that checks out: green, never confused with the accent. */
#define BC_RGB_OK 0x4ade80
/* Placeholder text of an empty field: dimmer than labels, still legible. */
#define BC_RGB_HINT 0x707070
/* Page scroll thumb: quiet at rest, brighter under the pointer or held. */
#define BC_RGB_THUMB 0x4a4a4a
#define BC_RGB_THUMB_ACTIVE 0x6a6a6a

static void bc_gui_theme_upbge(void)
{
  /* DEFAULT colors are copied to every control when set: first the base, then the exceptions. */
  GuiSetStyle(DEFAULT, BORDER_COLOR_NORMAL, BC_RGB(0x404040));
  GuiSetStyle(DEFAULT, BASE_COLOR_NORMAL, BC_RGB(0x2a2a2a));
  GuiSetStyle(DEFAULT, TEXT_COLOR_NORMAL, BC_RGB(0xd8d8d8));
  GuiSetStyle(DEFAULT, BORDER_COLOR_FOCUSED, BC_RGB(BC_RGB_ACCENT));
  GuiSetStyle(DEFAULT, BASE_COLOR_FOCUSED, BC_RGB(0x353535));
  GuiSetStyle(DEFAULT, TEXT_COLOR_FOCUSED, BC_RGB(0xffffff));
  GuiSetStyle(DEFAULT, BORDER_COLOR_PRESSED, BC_RGB(BC_RGB_ACCENT));
  GuiSetStyle(DEFAULT, BASE_COLOR_PRESSED, BC_RGB(BC_RGB_ACCENT));
  GuiSetStyle(DEFAULT, TEXT_COLOR_PRESSED, BC_RGB(BC_RGB_ON_ACCENT));
  GuiSetStyle(DEFAULT, BORDER_COLOR_DISABLED, BC_RGB(0x2c2c2c));
  GuiSetStyle(DEFAULT, BASE_COLOR_DISABLED, BC_RGB(0x1e1e1e));
  GuiSetStyle(DEFAULT, TEXT_COLOR_DISABLED, BC_RGB(0x5c5c5c));
  GuiSetStyle(DEFAULT, BACKGROUND_COLOR, BC_RGB(0x181818));
  GuiSetStyle(DEFAULT, LINE_COLOR, BC_RGB(0x404040));
  GuiSetStyle(DEFAULT, TEXT_SIZE, BC_TEXT_SIZE);
  GuiSetStyle(DEFAULT, TEXT_SPACING, 0);
  GuiSetStyle(DEFAULT, TEXT_LINE_SPACING, BC_TEXT_SIZE + 4);
  GuiSetStyle(BUTTON, BORDER_WIDTH, 1);
  /* Labels a step dimmer than the values they name. */
  GuiSetStyle(LABEL, TEXT_COLOR_NORMAL, BC_RGB(0xa8a8a8));
  /* A text being edited: dark field, accent border and cursor, as in Blender. */
  GuiSetStyle(TEXTBOX, BASE_COLOR_PRESSED, BC_RGB(0x101010));
  GuiSetStyle(TEXTBOX, TEXT_COLOR_PRESSED, BC_RGB(0xffffff));
}

/** Montserrat at the UI size, rasterized once and drawn 1:1 with point sampling: crisp, no
 * scaling. raylib falls back to its own font when the data cannot be loaded. */
static Font bc_gui_load_font(void)
{
  /* The glyphs of the embedded subset (CMakeLists.txt): ASCII, Latin-1 and Latin Extended-A, which
   * cover the file names of most European languages, and typographic punctuation. */
  static const int extra[] = {0x2013, 0x2014, 0x2018, 0x2019, 0x201c, 0x201d, 0x2022, 0x2026, 0x20ac};
  int codepoints[(0x7e - 0x20 + 1) + (0x17f - 0xa0 + 1) + sizeof(extra) / sizeof(extra[0])];
  int n = 0;
  for (int c = 0x20; c <= 0x7e; c++) {
    codepoints[n++] = c;
  }
  for (int c = 0xa0; c <= 0x17f; c++) {
    codepoints[n++] = c;
  }
  for (size_t i = 0; i < sizeof(extra) / sizeof(extra[0]); i++) {
    codepoints[n++] = extra[i];
  }
  return LoadFontFromMemory(".ttf", bc_font_montserrat, bc_font_montserrat_size, BC_TEXT_SIZE, codepoints, n);
}

#ifdef BC_WINDOW_ICON
/** Title bar and taskbar icon: every image of res/binarycrypt.ico (all PNG), so the window manager
 * picks the size it draws instead of scaling a single one. */
static void bc_gui_set_window_icon(void)
{
  char err[128];
  if (!bc_brand_ico_check(bc_icon_ico, (size_t)bc_icon_ico_size, err, sizeof(err))) {
    return;
  }
  Image images[16];
  int count = 0;
  const int n = bc_icon_ico[4] | (bc_icon_ico[5] << 8);
  for (int i = 0; i < n && count < 16; i++) {
    /* ICONDIRENTRY: u32 bytes at 8, u32 offset at 12; inside the file (checked above). */
    const uint8_t *entry = bc_icon_ico + 6 + 16 * i;
    const uint32_t size = entry[8] | (uint32_t)entry[9] << 8 | (uint32_t)entry[10] << 16 | (uint32_t)entry[11] << 24;
    const uint32_t offset = entry[12] | (uint32_t)entry[13] << 8 | (uint32_t)entry[14] << 16 | (uint32_t)entry[15] << 24;
    Image image = LoadImageFromMemory(".png", bc_icon_ico + offset, (int)size);
    if (image.data != NULL) {
      ImageFormat(&image, PIXELFORMAT_UNCOMPRESSED_R8G8B8A8);
      images[count++] = image;
    }
  }
  if (count > 0) {
    SetWindowIcons(images, count);
  }
  for (int i = 0; i < count; i++) {
    UnloadImage(images[i]);
  }
}
#endif

/* -------------------------------------------------------------------------------------------- */
/* Tooltips, help and wrapped text. raygui draws a tooltip together with its control, so every
 * control drawn later paints over it, and on one line that can run past the window. Controls
 * register their help here instead: "Short line\nWhat it does, at length". The short line is the
 * tooltip of the control under the mouse, drawn last; the rest goes to the help panel at the
 * bottom of the window at once, as in Blender's status bar. */

/* Seconds the mouse rests on a control before its tooltip shows: Blender's UI_TOOLTIP_DELAY, and
 * the Windows default. */
#define BC_TIP_DELAY 0.5

/* Registered by the control under the mouse this frame. */
static const char *g_tip_text = NULL;
static Rectangle g_tip_anchor;
/* Tooltip of the control under the mouse since g_tip_since, and whether it was clicked since. */
static const char *g_tip_hover = NULL;
static double g_tip_since = 0;
static bool g_tip_clicked = false;
/* Counting down to a tooltip: the main loop must not block on input meanwhile. */
static bool g_tip_waiting = false;

static void bc_tip(const Rectangle anchor, const char *text)
{
  if (text != NULL && !GuiIsLocked() && GuiGetState() != STATE_DISABLED && IsCursorOnScreen() &&
      CheckCollisionPointRec(GetMousePosition(), anchor))
  {
    g_tip_text = text;
    g_tip_anchor = anchor;
  }
}

typedef struct BC_Span {
  const char *start;
  int length;
} BC_Span;

/* Longest text measured or drawn at once: tooltips and log lines are shorter. */
#define BC_SPAN_MAX 1024

/** \a span as a NUL-terminated string in \a buffer, for raylib's text functions. */
static const char *bc_span_text(const BC_Span *span, char buffer[BC_SPAN_MAX])
{
  const int n = span->length < BC_SPAN_MAX ? span->length : BC_SPAN_MAX - 1;
  memcpy(buffer, span->start, (size_t)n);
  buffer[n] = '\0';
  return buffer;
}

/** Split \a text into lines no wider than \a width, breaking at spaces (a word wider than a line
 * is cut). Leading spaces of continuation lines are dropped. \return the number of spans. */
static int bc_wrap(const char *text, const float width, const float spacing, BC_Span *spans, const int max_spans)
{
  const Font font = GuiGetFont();
  char buffer[BC_SPAN_MAX];
  int count = 0;
  const char *p = text;
  while (*p != '\0' && count < max_spans) {
    if (count > 0) {
      while (*p == ' ') {
        p++;
      }
      if (*p == '\0') {
        break;
      }
    }
    int length = 0;
    for (;;) {
      int next = length;
      while (p[next] == ' ') {
        next++;
      }
      while (p[next] != '\0' && p[next] != ' ') {
        next++;
      }
      if (next == length || next >= BC_SPAN_MAX) {
        break;
      }
      memcpy(buffer, p, (size_t)next);
      buffer[next] = '\0';
      if (MeasureTextEx(font, buffer, BC_TEXT_SIZE, spacing).x > width) {
        break;
      }
      length = next;
    }
    if (length == 0) {
      /* One word wider than the line: as many characters as fit, at least one. */
      length = 1;
      while (p[length] != '\0' && p[length] != ' ' && length + 1 < BC_SPAN_MAX) {
        memcpy(buffer, p, (size_t)length + 1);
        buffer[length + 1] = '\0';
        if (MeasureTextEx(font, buffer, BC_TEXT_SIZE, spacing).x > width) {
          break;
        }
        length++;
      }
    }
    spans[count].start = p;
    spans[count].length = length;
    count++;
    p += length;
  }
  return count;
}

static void bc_draw_span(const BC_Span *span, const float x, const float y, const float spacing, const Color color)
{
  char buffer[BC_SPAN_MAX];
  const Vector2 position = {x, y};
  DrawTextEx(GuiGetFont(), bc_span_text(span, buffer), position, BC_TEXT_SIZE, spacing, color);
}

/** Draw the tooltip registered this frame on top of everything, below its control or above it
 * when there is no room, inside the window: the short line of its help. Nothing without \a show
 * (Help off): the frame's registration is still consumed, so no countdown keeps frames coming. */
static void bc_gui_draw_tip(const bool show)
{
  const char *help = show ? g_tip_text : NULL;
  g_tip_text = NULL;
  /* Identity of the control: the pointer to its help, unchanged frame to frame. */
  const char *text = help;
  /* The delay counts from entering the control. A click hides the tooltip until the mouse leaves
   * the control, as in Blender and Windows: it would cover what the click changes. */
  if (text != g_tip_hover) {
    g_tip_hover = text;
    g_tip_since = GetTime();
    g_tip_clicked = false;
  }
  g_tip_clicked = g_tip_clicked || IsMouseButtonPressed(MOUSE_BUTTON_LEFT);
  g_tip_waiting = text != NULL && !g_tip_clicked && GetTime() - g_tip_since < BC_TIP_DELAY;
  if (text == NULL || g_tip_clicked || g_tip_waiting) {
    return;
  }
  char line[BC_SPAN_MAX];
  const char *end = strchr(help, '\n');
  const int n_line = end ? (int)(end - help) : (int)strlen(help);
  snprintf(line, sizeof(line), "%.*s", n_line < BC_SPAN_MAX ? n_line : BC_SPAN_MAX - 1, help);
  text = line;
  const float W = (float)GetScreenWidth();
  const float H = (float)GetScreenHeight();
  const float spacing = (float)GuiGetStyle(DEFAULT, TEXT_SPACING);
  const float line_h = BC_TEXT_SIZE + 4;
  const float max_w = (W - 2 * BC_MARGIN < 640 ? W - 2 * BC_MARGIN : 640) - 2 * BC_GAP;
  BC_Span spans[24];
  const int n = bc_wrap(text, max_w, spacing, spans, 24);
  float text_w = 0;
  for (int i = 0; i < n; i++) {
    char buffer[BC_SPAN_MAX];
    const float w = MeasureTextEx(GuiGetFont(), bc_span_text(&spans[i], buffer), BC_TEXT_SIZE, spacing).x;
    text_w = w > text_w ? w : text_w;
  }
  Rectangle box = {g_tip_anchor.x, g_tip_anchor.y + g_tip_anchor.height + 4, text_w + 2 * BC_GAP, (float)n * line_h + 2 * BC_GAP - 4};
  if (box.x + box.width > W - BC_MARGIN) {
    box.x = W - BC_MARGIN - box.width;
  }
  if (box.x < BC_MARGIN) {
    box.x = BC_MARGIN;
  }
  if (box.y + box.height > H - BC_MARGIN && g_tip_anchor.y - 4 - box.height >= BC_MARGIN) {
    box.y = g_tip_anchor.y - 4 - box.height;
  }
  DrawRectangleRec(box, GetColor((unsigned int)GuiGetStyle(DEFAULT, BASE_COLOR_NORMAL)));
  DrawRectangleLinesEx(box, 1, GetColor((unsigned int)GuiGetStyle(DEFAULT, BORDER_COLOR_FOCUSED)));
  const Color color = GetColor((unsigned int)GuiGetStyle(DEFAULT, TEXT_COLOR_NORMAL));
  for (int i = 0; i < n; i++) {
    bc_draw_span(&spans[i], box.x + BC_GAP, box.y + BC_GAP + (float)i * line_h, spacing, color);
  }
}

/** \a s cut at its end with "..." to fit \a width: hints read from their start. */
static void bc_fit_right(const char *s, const float width, char *out, const size_t size)
{
  const Font font = GuiGetFont();
  const float spacing = (float)GuiGetStyle(DEFAULT, TEXT_SPACING);
  snprintf(out, size, "%s", s);
  size_t n = strlen(out);
  while (n > 0 && MeasureTextEx(font, out, BC_TEXT_SIZE, spacing).x > width) {
    n--;
    snprintf(out, size, "%.*s...", (int)n, s);
  }
}

/** Where a text box draws its text (raygui: border, then padding), vertically centered. */
static Vector2 bc_text_origin(const Rectangle bounds)
{
  const Vector2 origin = {bounds.x + (float)(GuiGetStyle(TEXTBOX, BORDER_WIDTH) + GuiGetStyle(TEXTBOX, TEXT_PADDING)),
                          bounds.y + (bounds.height - BC_TEXT_SIZE) / 2};
  return origin;
}

/** Grey hint in an empty field that is not being edited: what goes there, or what empty means. */
static void bc_draw_placeholder(const Rectangle bounds, const char *hint, const float reserved)
{
  if (hint == NULL || GuiGetState() == STATE_DISABLED) {
    return;
  }
  char text[BC_PATH_MAX];
  bc_fit_right(hint, bounds.width - 16 - reserved, text, sizeof(text));
  DrawTextEx(GuiGetFont(), text, bc_text_origin(bounds), BC_TEXT_SIZE, (float)GuiGetStyle(DEFAULT, TEXT_SPACING), GetColor((unsigned int)BC_RGB(BC_RGB_HINT)));
}

/** Width a field check takes at the right end of its field. */
static float bc_field_width(const BC_Field *f)
{
  if (f == NULL || f->state == BC_FIELD_NONE) {
    return 0;
  }
  if (f->state == BC_FIELD_OK || f->note == NULL) {
    return BC_ICON_SIZE + BC_GAP;
  }
  return MeasureTextEx(GuiGetFont(), f->note, BC_TEXT_SIZE, (float)GuiGetStyle(DEFAULT, TEXT_SPACING)).x + 2 * BC_GAP;
}

/** A field check over a field that is not being edited: a green tick when it checks out; a red
 * frame and a short note at its right end when not. */
static void bc_draw_field(const Rectangle bounds, const BC_Field *f)
{
  if (f == NULL || f->state == BC_FIELD_NONE || GuiGetState() == STATE_DISABLED) {
    return;
  }
  const float cy = bounds.y + bounds.height / 2;
  if (f->state == BC_FIELD_OK) {
    /* A tick two pixels thick: raygui's icon is one pixel and reads grey at this size. */
    const float x0 = bounds.x + bounds.width - BC_ICON_SIZE - BC_GAP;
    const Color green = GetColor((unsigned int)BC_RGB(BC_RGB_OK));
    const Vector2 a = {x0 + 2, cy}, b = {x0 + 6, cy + 4}, c = {x0 + 14, cy - 5};
    DrawLineEx(a, b, 2.2f, green);
    DrawLineEx(b, c, 2.2f, green);
    return;
  }
  const Color red = GetColor((unsigned int)BC_RGB(BC_RGB_ERROR));
  DrawRectangleLinesEx(bounds, 1, red);
  if (f->note != NULL) {
    const float spacing = (float)GuiGetStyle(DEFAULT, TEXT_SPACING);
    const float w = MeasureTextEx(GuiGetFont(), f->note, BC_TEXT_SIZE, spacing).x;
    const Vector2 position = {bounds.x + bounds.width - BC_GAP - w, bounds.y + (bounds.height - BC_TEXT_SIZE) / 2};
    DrawTextEx(GuiGetFont(), f->note, position, BC_TEXT_SIZE, spacing, red);
  }
}

/** The one action of the window in the accent color. Disabled, it takes the disabled style. */
static bool bc_primary_button(const Rectangle bounds, const char *text)
{
  const int props[] = {BASE_COLOR_NORMAL, BORDER_COLOR_NORMAL, TEXT_COLOR_NORMAL, BASE_COLOR_FOCUSED, TEXT_COLOR_FOCUSED};
  const int values[] = {BC_RGB(BC_RGB_ACCENT), BC_RGB(BC_RGB_ACCENT), BC_RGB(BC_RGB_ON_ACCENT), BC_RGB(0xfbb072), BC_RGB(BC_RGB_ON_ACCENT)};
  int saved[5];
  for (int i = 0; i < 5; i++) {
    saved[i] = GuiGetStyle(BUTTON, props[i]);
    GuiSetStyle(BUTTON, props[i], values[i]);
  }
  const bool pressed = GuiButton(bounds, text) != 0;
  for (int i = 0; i < 5; i++) {
    GuiSetStyle(BUTTON, props[i], saved[i]);
  }
  return pressed;
}

/** Plain text box mirroring \a value, trimmed when confirmed. \a placeholder shows while it is
 * empty. Returns true when \a value changed. */
static bool bc_gui_text_field(Rectangle bounds,
                              const char *tooltip,
                              const char *placeholder,
                              char *text,
                              const size_t text_size,
                              char *value,
                              const size_t value_size,
                              bool *edit)
{
  if (!*edit) {
    snprintf(text, text_size, "%s", value);
  }
  bool changed = false;
  bc_tip(bounds, tooltip);
  if (GuiTextBox(bounds, text, (int)text_size - 1, *edit)) {
    if (*edit) {
      char *start = text;
      while (*start == ' ') {
        start++;
      }
      size_t n = strlen(start);
      while (n > 0 && start[n - 1] == ' ') {
        n--;
      }
      if (n >= value_size) {
        n = value_size - 1;
      }
      changed = strncmp(value, start, n) != 0 || value[n] != '\0';
      memcpy(value, start, n);
      value[n] = '\0';
    }
    *edit = !*edit;
  }
  if (!*edit && value[0] == '\0') {
    bc_draw_placeholder(bounds, placeholder, 0);
  }
  return changed;
}

/** Editable path row from \a x to \a right: label, text box, browse button. \a placeholder shows
 * while it is empty and \a field (may be NULL) tells whether what it names checks out. Returns
 * true when the button was hit and sets *r_committed when an edit was just confirmed. */
static bool bc_gui_path_row(const float x,
                            const float y,
                            const float right,
                            const float label_w,
                            const char *label,
                            const char *help,
                            const char *placeholder,
                            const BC_Field *field,
                            const char *value,
                            char *text,
                            bool *edit,
                            bool *r_committed)
{
  const float button_x = right - BC_BUTTON_W;
  const float box_w = button_x - BC_GAP - (x + label_w);
  const Rectangle box = bc_rect(x + label_w, y, box_w, BC_ROW);
  GuiLabel(bc_rect(x, y, label_w, BC_ROW), label);
  bc_tip(bc_rect(x, y, label_w + box_w, BC_ROW), help);
  *r_committed = false;
  /* The path gives up its start, never the check at the right end. */
  const float reserved = bc_field_width(field);
  if (!*edit) {
    bc_fit_left(value, box_w - 16 - reserved, text, BC_PATH_MAX);
  }
  const bool toggled = GuiTextBox(box, text, BC_PATH_MAX - 1, *edit) != 0;
  if (!*edit && !toggled) {
    if (value[0] == '\0') {
      bc_draw_placeholder(box, placeholder, reserved);
    }
    bc_draw_field(box, field);
  }
  if (toggled) {
    if (*edit) {
      *r_committed = true;
    }
    else {
      /* Editing starts on the full path, not on its shortened display. */
      snprintf(text, BC_PATH_MAX, "%s", value);
    }
    *edit = !*edit;
  }
  return GuiButton(bc_rect(button_x, y, BC_BUTTON_W, BC_ROW), "Browse...");
}

/** The page scroll bar, in the right margin while the page is taller than the window: the wheel
 * where no list under the pointer takes it, the thumb dragged, a click on the track pages. Run
 * before anything is laid out, so every control of the frame sees one offset; drawn at once, as
 * nothing else reaches the margin. Returns true when the wheel moved the page this frame: a list
 * the move brings under the pointer must not take the same notch. */
static bool bc_gui_scroll_page(BC_Gui *g, const float win_w, const float win_h, const float page_h, const bool interactive)
{
  const float max_scroll = page_h - win_h;
  if (max_scroll <= 0 || !interactive) {
    g->scroll_drag = false;
  }
  if (max_scroll <= 0) {
    g->scroll_y = 0;
    return false;
  }
  g->scroll_y = g->scroll_y > max_scroll ? max_scroll : g->scroll_y; /* The window grew. */
  const Vector2 mouse = GetMousePosition();
  const Rectangle hit = bc_rect(win_w - BC_MARGIN, 0, BC_MARGIN, win_h);
  const Rectangle track = bc_rect(win_w - BC_MARGIN, BC_GAP / 2, BC_SCROLL_W, win_h - BC_GAP);
  /* Thumb to track as window to page, never too short to grab. */
  float thumb_h = track.height * win_h / page_h;
  thumb_h = thumb_h < 3 * BC_GAP ? 3 * BC_GAP : thumb_h;
  const float travel = track.height - thumb_h;
  bool wheeled = false;
  if (interactive) {
    const float wheel = GetMouseWheelMove();
    if (wheel != 0 && !CheckCollisionPointRec(mouse, g->list_wheel) && !CheckCollisionPointRec(mouse, g->types_wheel) &&
        !CheckCollisionPointRec(mouse, g->log_wheel))
    {
      g->scroll_y -= wheel * BC_SCROLL_STEP;
      wheeled = true;
    }
    if (IsMouseButtonPressed(MOUSE_BUTTON_LEFT) && CheckCollisionPointRec(mouse, hit)) {
      const float thumb_y = track.y + travel * g->scroll_y / max_scroll;
      if (mouse.y < thumb_y) {
        g->scroll_y -= win_h - BC_ROW; /* A page, one row kept in sight. */
      }
      else if (mouse.y >= thumb_y + thumb_h) {
        g->scroll_y += win_h - BC_ROW;
      }
      else {
        g->scroll_drag = true;
        g->scroll_grab = mouse.y - thumb_y;
      }
    }
  }
  if (g->scroll_drag) {
    g->scroll_y = travel > 0 ? (mouse.y - g->scroll_grab - track.y) * max_scroll / travel : 0;
    if (!IsMouseButtonDown(MOUSE_BUTTON_LEFT)) {
      g->scroll_drag = false;
    }
  }
  /* Whole pixels: the font is drawn 1:1, a fractional offset would shift glyphs off the texel grid
   * and smear them. */
  const float clamped = g->scroll_y < 0 ? 0 : g->scroll_y > max_scroll ? max_scroll : g->scroll_y;
  g->scroll_y = (float)(int)(clamped + 0.5f);

  const float thumb_y = track.y + travel * g->scroll_y / max_scroll;
  const bool hot = g->scroll_drag || (interactive && CheckCollisionPointRec(mouse, hit));
  DrawRectangleRec(track, GetColor((unsigned int)GuiGetStyle(DEFAULT, BASE_COLOR_NORMAL)));
  DrawRectangleRec(bc_rect(track.x, thumb_y, track.width, thumb_h), GetColor((unsigned int)BC_RGB(hot ? BC_RGB_THUMB_ACTIVE : BC_RGB_THUMB)));
  return wheeled;
}

/* -------------------------------------------------------------------------------------------- */
/* Sections, file list, help panel */

/* Rows of the file list. */
#define BC_LIST_ROW 28
/* File list rows a taller window gives before the log grows past BC_LOG_MIN lines. */
#define BC_LIST_ROWS 8
/* Three text lines of help, the panel's padding: long help is written to fit. */
#define BC_HELP_LINES 3
#define BC_HELP_H (BC_HELP_LINES * 24 + BC_GAP)
/* A folded section: its header line, then the gap any section leaves. */
#define BC_FOLDED_H (2 * BC_GAP)

/** \a cond false: what follows is drawn disabled (unless everything already is). Pair with
 * #bc_enable_end. */
static bool bc_enable_begin(const bool cond)
{
  const bool change = !cond && GuiGetState() != STATE_DISABLED;
  if (change) {
    GuiDisable();
  }
  return change;
}

static void bc_enable_end(const bool changed)
{
  if (changed) {
    GuiEnable();
  }
}

/** Width of a button around \a text. */
static float bc_button_w(const char *text)
{
  return MeasureTextEx(GuiGetFont(), text, BC_TEXT_SIZE, (float)GuiGetStyle(DEFAULT, TEXT_SPACING)).x + 4 * BC_GAP;
}

/**
 * Section: a frame whose top line carries its title in the accent and, after it, a summary in the
 * hint color (red when \a summary_error; NULL: none). \a fold -1: always open; 0 folded: the top line only;
 * 1 open. A foldable section takes clicks on its whole header line and shows an arrow.
 * \return true when the header was clicked.
 */
static bool bc_section(const float y,
                       const float h,
                       const float inner,
                       const char *title,
                       const char *summary,
                       const bool summary_error,
                       const int fold,
                       const char *help)
{
  const float spacing = (float)GuiGetStyle(DEFAULT, TEXT_SPACING);
  const Font font = GuiGetFont();
  const Color line = GetColor((unsigned int)GuiGetStyle(DEFAULT, LINE_COLOR));
  const Color background = GetColor((unsigned int)GuiGetStyle(DEFAULT, BACKGROUND_COLOR));
  if (fold != 0) {
    GuiGroupBox(bc_rect(BC_MARGIN, y, inner, h), NULL);
  }
  else {
    DrawRectangleRec(bc_rect(BC_MARGIN, y, inner, 1), line);
  }
  const Rectangle header = bc_rect(BC_MARGIN, y - BC_ROW / 2, inner, BC_ROW);
  const bool disabled = GuiGetState() == STATE_DISABLED;
  const bool hot = fold >= 0 && !disabled && !GuiIsLocked() && IsCursorOnScreen() && CheckCollisionPointRec(GetMousePosition(), header);
  float x = BC_MARGIN + 12;
  const float title_w = MeasureTextEx(font, title, BC_TEXT_SIZE, spacing).x;
  const float arrow_w = fold >= 0 ? (float)(BC_ICON_SIZE + 4) : 0.0f;
  /* The texts sit on the line: the background clears it behind them. */
  DrawRectangleRec(bc_rect(x - 4, y - 1, arrow_w + title_w + 8, 3), background);
  if (fold >= 0) {
    const Color arrow = GetColor((unsigned int)(disabled ? GuiGetStyle(DEFAULT, TEXT_COLOR_DISABLED) :
                                                hot      ? BC_RGB(BC_RGB_ACCENT) :
                                                           GuiGetStyle(LABEL, TEXT_COLOR_NORMAL)));
    GuiDrawIcon(fold ? ICON_ARROW_DOWN_FILL : ICON_ARROW_RIGHT_FILL, (int)x, (int)(y - BC_ICON_SIZE / 2), 1, arrow);
    x += arrow_w;
  }
  const Vector2 title_at = {x, y - BC_TEXT_SIZE / 2};
  DrawTextEx(font, title, title_at, BC_TEXT_SIZE, spacing, GetColor((unsigned int)(disabled ? GuiGetStyle(DEFAULT, TEXT_COLOR_DISABLED) : BC_RGB(BC_RGB_ACCENT))));
  x += title_w + 2 * BC_GAP;
  if (summary != NULL && summary[0] != '\0') {
    char shown[BC_PATH_MAX];
    bc_fit_right(summary, BC_MARGIN + inner - 2 * BC_GAP - x, shown, sizeof(shown));
    const float w = MeasureTextEx(font, shown, BC_TEXT_SIZE, spacing).x;
    DrawRectangleRec(bc_rect(x - 4, y - 1, w + 8, 3), background);
    const Vector2 at = {x, y - BC_TEXT_SIZE / 2};
    const int rgba = disabled ? GuiGetStyle(DEFAULT, TEXT_COLOR_DISABLED) : BC_RGB(summary_error ? BC_RGB_ERROR : BC_RGB_HINT);
    DrawTextEx(font, shown, at, BC_TEXT_SIZE, spacing, GetColor((unsigned int)rgba));
  }
  if (fold < 0) {
    return false;
  }
  bc_tip(header, help);
  return hot && IsMouseButtonPressed(MOUSE_BUTTON_LEFT);
}

static void bc_gui_set_main(BC_Gui *g, const char *path)
{
  if (strcmp(g->project.main, path) != 0) {
    snprintf(g->project.main, sizeof(g->project.main), "%s", path);
    bc_gui_set_modified(g);
  }
}

/** Wheel over \a bounds scrolls \a scroll (rows) within [0, max]; the region is recorded so the
 * page leaves the wheel to it. */
static void bc_list_wheel(int *scroll, const int max_scroll, const Rectangle bounds, const bool live, const bool page_wheeled, Rectangle *r_region)
{
  if (live && !page_wheeled && max_scroll > 0 && CheckCollisionPointRec(GetMousePosition(), bounds)) {
    const float wheel = GetMouseWheelMove();
    *scroll -= wheel > 0 ? (int)(wheel + 0.5f) : (int)(wheel - 0.5f);
  }
  *scroll = *scroll < 0 ? 0 : *scroll > max_scroll ? max_scroll : *scroll;
  *r_region = max_scroll > 0 && GuiGetState() != STATE_DISABLED ? bounds : bc_rect(0, 0, 0, 0);
}

/** Thumb of a list scrolled by rows: its size and place in rows. */
static void bc_list_thumb(const Rectangle bounds, const int scroll, const int max_scroll, const int visible, const int rows)
{
  if (max_scroll <= 0) {
    return;
  }
  const float track_h = bounds.height - 2 * BC_GAP;
  const float thumb_h = track_h * (float)visible / (float)rows;
  const float at = (float)scroll / (float)max_scroll;
  DrawRectangleRec(bc_rect(bounds.x + bounds.width - BC_GAP, bounds.y + BC_GAP + (track_h - thumb_h) * at, 4, thumb_h),
                   GetColor((unsigned int)GuiGetStyle(DEFAULT, BORDER_COLOR_NORMAL)));
}

static void bc_list_frame(const Rectangle bounds)
{
  const bool disabled = GuiGetState() == STATE_DISABLED;
  DrawRectangleRec(bounds, GetColor((unsigned int)GuiGetStyle(DEFAULT, BACKGROUND_COLOR)));
  DrawRectangleLinesEx(bounds, 1, GetColor((unsigned int)GuiGetStyle(DEFAULT, disabled ? BORDER_COLOR_DISABLED : BORDER_COLOR_NORMAL)));
}

/**
 * The file list as a tree, drawn here instead of by raygui for its star and arrow column. Each
 * input is a row; a folder's files follow it, indented, unless it is folded. Every .blend has a
 * star: the main file's is orange, a click on another makes that one the main file. A click on an
 * input row selects it (Remove); the rows under a folder are its files, not inputs of their own.
 * Only the visible rows are formatted.
 */
static void bc_gui_file_list(BC_Gui *g, const Rectangle bounds, const bool page_wheeled)
{
  static const char *const kinds[3] = {"blend", "script", "data"};
  const float spacing = (float)GuiGetStyle(DEFAULT, TEXT_SPACING);
  const Font font = GuiGetFont();
  const bool disabled = GuiGetState() == STATE_DISABLED;
  /* raylib keeps the last position once the pointer has left the window: nothing is under it then. */
  const bool live = !disabled && !GuiIsLocked() && IsCursorOnScreen();
  const Vector2 mouse = GetMousePosition();
  const int inputs = g->project.input_count;
  /* Rows of each input: itself, then its files while open. Inputs are few. */
  int rows = 0;
  for (int i = 0; i < inputs; i++) {
    const bool open = g->input_rows != NULL && g->input_folded != NULL && !g->input_folded[i];
    rows += 1 + (open ? g->input_rows[i].count : 0);
  }
  const int visible = (int)((bounds.height - 4) / BC_LIST_ROW);
  const int max_scroll = rows > visible ? rows - visible : 0;

  bc_list_frame(bounds);
  bc_tip(bounds, "Files and folders to encrypt\nA folder shows the files it gives, each .blend with a star: the orange star marks the main file, the .blend the game starts. Click another star to change it.");
  bc_list_wheel(&g->list_scroll, max_scroll, bounds, live, page_wheeled, &g->list_wheel);
  if (rows == 0) {
    const char *empty = "Drop the game folder, or its files, on the window";
    const float w = MeasureTextEx(font, empty, BC_TEXT_SIZE, spacing).x;
    const Vector2 at = {bounds.x + (bounds.width - w) / 2, bounds.y + (bounds.height - BC_TEXT_SIZE) / 2};
    DrawTextEx(font, empty, at, BC_TEXT_SIZE, spacing, GetColor((unsigned int)BC_RGB(BC_RGB_HINT)));
    return;
  }
  const float row_w = bounds.width - 4 - (max_scroll > 0 ? 6 : 0);
  const Color text_color = GetColor((unsigned int)GuiGetStyle(DEFAULT, disabled ? TEXT_COLOR_DISABLED : TEXT_COLOR_NORMAL));
  const Color info_color = GetColor((unsigned int)BC_RGB(BC_RGB_HINT));
  const float slot_w = BC_ICON_SIZE + 2 * BC_GAP;
  /* Walk to the first visible row, then draw rows until the panel is full. */
  int input = 0, child = -1, r = 0;
  for (; input < inputs; input++) {
    const bool open = g->input_rows != NULL && g->input_folded != NULL && !g->input_folded[input];
    const int span = 1 + (open ? g->input_rows[input].count : 0);
    if (r + span > g->list_scroll) {
      child = g->list_scroll - r - 1; /* -1: the input row itself. */
      break;
    }
    r += span;
  }
  for (int drawn = 0; drawn < visible && input < inputs; drawn++) {
    const bool open = g->input_rows != NULL && g->input_folded != NULL && !g->input_folded[input];
    const bool is_dir = g->input_rows != NULL && g->input_rows[input].dir;
    const Rectangle row = bc_rect(bounds.x + 2, bounds.y + 2 + (float)drawn * BC_LIST_ROW, row_w, BC_LIST_ROW);
    const char *path;
    const char *label;
    char info[80];
    bool blend;
    float indent = 0;
    if (child < 0) {
      path = g->project.inputs[input];
      label = input < g->item_count ? g->items[input] : path;
      blend = !is_dir && bc_path_has_extension(path, ".blend");
      snprintf(info, sizeof(info), "%s", g->input_rows != NULL ? g->input_rows[input].info : "");
    }
    else {
      const BC_ListedFile *file = &g->scan.files[g->input_rows[input].first + child];
      path = file->path;
      /* Relative to its folder: the folder row says where. */
      const size_t n = strlen(g->project.inputs[input]);
      label = strncmp(path, g->project.inputs[input], n) == 0 && path[n] == '/' ? path + n + 1 : path;
      blend = file->kind == BC_KIND_BLEND;
      indent = slot_w;
      char size[24];
      bc_format_size(file->size, size, sizeof(size));
      if (file->size == 0 && !blend) {
        snprintf(info, sizeof(info), "%s  \xc2\xb7  empty, copied", kinds[file->kind]);
      }
      else {
        snprintf(info, sizeof(info), "%s  \xc2\xb7  %s", kinds[file->kind], size);
      }
    }
    const bool is_main = blend && strcmp(path, g->project.main) == 0;
    const bool hover = live && CheckCollisionPointRec(mouse, row);
    const Rectangle slot = bc_rect(row.x + indent, row.y, slot_w, BC_LIST_ROW);
    const bool slot_hover = hover && CheckCollisionPointRec(mouse, slot) && (blend || (child < 0 && is_dir));
    if (child < 0 && input == g->list_active) {
      DrawRectangleRec(row, GetColor((unsigned int)GuiGetStyle(DEFAULT, BASE_COLOR_FOCUSED)));
      DrawRectangleLinesEx(row, 1, GetColor((unsigned int)BC_RGB(BC_RGB_ACCENT)));
    }
    else if (hover) {
      DrawRectangleRec(row, GetColor((unsigned int)BC_RGB(0x222222)));
    }
    const int icon_y = (int)(row.y + (BC_LIST_ROW - BC_ICON_SIZE) / 2);
    if (blend) {
      const unsigned int rgb = is_main ? BC_RGB_ACCENT : slot_hover ? 0xa8a8a8 : 0x4a4a4a;
      GuiDrawIcon(ICON_STAR, (int)(slot.x + BC_GAP), icon_y, 1, GetColor((unsigned int)BC_RGB(rgb)));
      if (slot_hover) {
        bc_tip(slot, is_main ? "The main file\nThe .blend the game executable starts." : "Make it the main file\nThe .blend the game executable starts.");
      }
    }
    else if (child < 0 && is_dir) {
      GuiDrawIcon(open ? ICON_ARROW_DOWN_FILL : ICON_ARROW_RIGHT_FILL, (int)(slot.x + BC_GAP), icon_y, 1, GetColor((unsigned int)(slot_hover ? BC_RGB(BC_RGB_ACCENT) : GuiGetStyle(LABEL, TEXT_COLOR_NORMAL))));
      if (slot_hover) {
        bc_tip(slot, open ? "Hide the files of this folder" : "Show the files of this folder");
      }
    }
    const float text_x = slot.x + slot.width;
    const float info_w = MeasureTextEx(font, info, BC_TEXT_SIZE, spacing).x;
    const float info_x = row.x + row.width - BC_GAP - info_w;
    char shown[BC_PATH_MAX];
    bc_fit_left(label, info_x - 2 * BC_GAP - text_x, shown, sizeof(shown));
    const Vector2 text_at = {text_x, row.y + (BC_LIST_ROW - BC_TEXT_SIZE) / 2};
    DrawTextEx(font, shown, text_at, BC_TEXT_SIZE, spacing, text_color);
    const Vector2 info_at = {info_x, text_at.y};
    DrawTextEx(font, info, info_at, BC_TEXT_SIZE, spacing, info_color);
    if (hover && IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
      if (slot_hover && blend) {
        bc_gui_set_main(g, path);
      }
      else if (slot_hover) {
        g->input_folded[input] = open; /* Folds an open folder, opens a folded one. */
      }
      else if (child < 0) {
        g->list_active = input;
      }
    }
    /* Next row: the next file of this folder, or the next input. */
    child++;
    if (child >= (open ? g->input_rows[input].count : 0)) {
      input++;
      child = -1;
    }
  }
  bc_list_thumb(bounds, g->list_scroll, max_scroll, visible, rows);
}

/**
 * The types of the files the inputs hold, with how many there are and a tick box: .blend files
 * and Python modules are always encrypted, code the system or Python loads (.dll, .so, .pyc...)
 * never, any other type when ticked (the project's data file extensions).
 */
static void bc_gui_types_list(BC_Gui *g, const Rectangle bounds, const bool page_wheeled)
{
  const float spacing = (float)GuiGetStyle(DEFAULT, TEXT_SPACING);
  const Font font = GuiGetFont();
  const bool disabled = GuiGetState() == STATE_DISABLED;
  const bool live = !disabled && !GuiIsLocked() && IsCursorOnScreen();
  const Vector2 mouse = GetMousePosition();
  /* Header row, then the types. */
  const Rectangle list = bc_rect(bounds.x, bounds.y + BC_LIST_ROW, bounds.width, bounds.height - BC_LIST_ROW);
  const int visible = (int)((list.height - 4) / BC_LIST_ROW);
  const int max_scroll = g->type_count > visible ? g->type_count - visible : 0;
  bc_list_frame(bounds);
  bc_tip(bounds, "File types the list holds\n.blend files and Python modules are always encrypted; code (.dll, .so, .pyc...) never. Tick another type to encrypt its files too: the game reads them with bge.logic.decryptFile(path).");
  const Vector2 head_at = {bounds.x + BC_GAP, bounds.y + (BC_LIST_ROW - BC_TEXT_SIZE) / 2 + 2};
  DrawTextEx(font, "File types", head_at, BC_TEXT_SIZE, spacing, GetColor((unsigned int)GuiGetStyle(LABEL, disabled ? TEXT_COLOR_DISABLED : TEXT_COLOR_NORMAL)));
  DrawRectangleRec(bc_rect(bounds.x + 1, bounds.y + BC_LIST_ROW, bounds.width - 2, 1), GetColor((unsigned int)GuiGetStyle(DEFAULT, LINE_COLOR)));
  bc_list_wheel(&g->types_scroll, max_scroll, list, live, page_wheeled, &g->types_wheel);

  char ext[BC_DATA_EXT_MAX][BC_DATA_EXT_SIZE];
  char err[256];
  const int ext_count = bc_project_data_extensions(&g->project, ext, BC_DATA_EXT_MAX, err, sizeof(err));
  const float row_w = list.width - 4 - (max_scroll > 0 ? 6 : 0);
  for (int t = g->types_scroll; t < g->type_count && t < g->types_scroll + visible; t++) {
    const BC_FileType *type = &g->types[t];
    const Rectangle row = bc_rect(list.x + 2, list.y + 2 + (float)(t - g->types_scroll) * BC_LIST_ROW, row_w, BC_LIST_ROW);
    const BC_ExtensionRule rule = bc_project_extension_rule(type->ext);
    const bool always = rule == BC_EXTENSION_ALWAYS;
    const bool never = rule == BC_EXTENSION_NEVER;
    bool ticked = always;
    for (int i = 0; i < ext_count && !ticked; i++) {
      ticked = strlen(ext[i]) == strlen(type->ext) && bc_path_has_extension(ext[i], type->ext);
    }
    const bool choosable = !always && !never;
    const bool hover = live && choosable && CheckCollisionPointRec(mouse, row);
    if (hover) {
      DrawRectangleRec(row, GetColor((unsigned int)BC_RGB(0x222222)));
    }
    /* Tick box: the accent filled when ticked, grey when it cannot change. */
    const Rectangle box = bc_rect(row.x + BC_GAP, row.y + (BC_LIST_ROW - 16) / 2, 16, 16);
    const Color edge = GetColor((unsigned int)(!choosable || disabled ? GuiGetStyle(DEFAULT, BORDER_COLOR_DISABLED) :
                                               hover                 ? BC_RGB(BC_RGB_ACCENT) :
                                                                       GuiGetStyle(DEFAULT, BORDER_COLOR_NORMAL)));
    DrawRectangleLinesEx(box, 1, edge);
    if (ticked) {
      const unsigned int fill = choosable && !disabled ? BC_RGB_ACCENT : 0x5c5c5c;
      DrawRectangleRec(bc_rect(box.x + 3, box.y + 3, box.width - 6, box.height - 6), GetColor((unsigned int)BC_RGB(fill)));
    }
    char info[48];
    snprintf(info, sizeof(info), always ? "%d  \xc2\xb7  always" : never ? "%d  \xc2\xb7  never" : "%d", type->count);
    const float info_w = MeasureTextEx(font, info, BC_TEXT_SIZE, spacing).x;
    const float text_x = box.x + box.width + BC_GAP;
    const Vector2 text_at = {text_x, row.y + (BC_LIST_ROW - BC_TEXT_SIZE) / 2};
    char shown[BC_DATA_EXT_SIZE + 8];
    bc_fit_right(type->ext, row.x + row.width - BC_GAP - info_w - 2 * BC_GAP - text_x, shown, sizeof(shown));
    DrawTextEx(font, shown, text_at, BC_TEXT_SIZE, spacing, GetColor((unsigned int)GuiGetStyle(DEFAULT, choosable && !disabled ? TEXT_COLOR_NORMAL : TEXT_COLOR_DISABLED)));
    const Vector2 info_at = {row.x + row.width - BC_GAP - info_w, text_at.y};
    DrawTextEx(font, info, info_at, BC_TEXT_SIZE, spacing, GetColor((unsigned int)BC_RGB(BC_RGB_HINT)));
    if (hover && IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
      bc_gui_toggle_type(g, type->ext);
    }
  }
  bc_list_thumb(list, g->types_scroll, max_scroll, visible, g->type_count);
}

/** The help panel at the bottom: the help of the control under the pointer, as registered this
 * frame (call before #bc_gui_draw_tip), else what the editor is about. */
static void bc_gui_help_panel(const Rectangle bounds)
{
  const char *idle = "Point at a field or a button to see what it does here. Help, in the first row, hides this panel and the tooltips.";
  const char *help = g_tip_text;
  const char *text = idle;
  if (help != NULL) {
    const char *long_part = strchr(help, '\n');
    text = long_part ? long_part + 1 : help;
  }
  GuiStatusBar(bounds, NULL);
  const float spacing = (float)GuiGetStyle(DEFAULT, TEXT_SPACING);
  const float text_w = bounds.width - 2 * BC_GAP;
  BC_Span spans[BC_HELP_LINES + 1];
  const int n = bc_wrap(text, text_w, spacing, spans, BC_HELP_LINES + 1);
  const Color color = GetColor((unsigned int)(help ? GuiGetStyle(LABEL, TEXT_COLOR_NORMAL) : BC_RGB(BC_RGB_HINT)));
  for (int i = 0; i < n && i < BC_HELP_LINES; i++) {
    BC_Span span = spans[i];
    char buffer[BC_SPAN_MAX + 4];
    if (i == BC_HELP_LINES - 1 && n > BC_HELP_LINES) {
      /* Longer than the panel: the help texts are written to fit, this only guards. */
      snprintf(buffer, sizeof(buffer), "%.*s...", span.length > 3 ? span.length - 3 : 0, span.start);
      span.start = buffer;
      span.length = (int)strlen(buffer);
    }
    bc_draw_span(&span, bounds.x + BC_GAP, bounds.y + BC_GAP / 2 + (float)i * 24 + 2, spacing, color);
  }
}

static void bc_gui_draw(BC_Gui *g)
{
  const float W = (float)GetScreenWidth();
  const float win_h = (float)GetScreenHeight();
  const bool running = g->job != NULL;
  const bool modal = g->pending != BC_PENDING_NONE;
  const Font font = GuiGetFont();
  const float text_spacing = (float)GuiGetStyle(DEFAULT, TEXT_SPACING);
  char path[BC_PATH_MAX];
  BC_DialogResult r;

  if (modal) {
    g->check_edit = g->manifest_edit = g->key_edit = false;
  }
  /* An open dropdown takes every click until it closes: the rows under its list must not react. */
  const bool dropdown_open = g->check_edit || g->manifest_edit || g->key_edit;

  /* Heights, known before anything is drawn: with the shortest file list and log (BC_LOG_MIN
   * lines) they give the height of the page. A taller window gives the list rows first, up to
   * BC_LIST_ROWS (it is where the main blend and the types are chosen), then the log lines, then
   * the list the rest (the log all of it while the list is folded away); a shorter one scrolls the
   * page. Every section folds. */
  const bool online = g->project.key_mode == BC_KEY_ONLINE;
  const bool key_file_row = g->project.key_mode != BC_KEY_BUILD;
  /* Icon and version information only exist for Windows games: elsewhere the section stays folded
   * and disabled (the project keeps them, the job ignores them with a warning). */
  const bool brand = bc_brand_supported();
  const bool windows_open = brand && g->windows_open;
  const float list_min_h = 3 * BC_LIST_ROW + 4;
  const float game_fixed_h = 2 * BC_GAP + (BC_ROW + BC_GAP) + BC_GAP + (BC_ROW + BC_GAP); /* Without the list. */
  const float game_min_h = g->game_open ? game_fixed_h + list_min_h : BC_FOLDED_H;
  const float build_h = g->build_open ? (float)(2 * BC_GAP + 2 * (BC_ROW + BC_GAP)) : BC_FOLDED_H;
  const float windows_h = windows_open ? (float)(2 * BC_GAP + 2 * (BC_ROW + BC_GAP)) : BC_FOLDED_H;
  const int protection_rows = 2 + (key_file_row ? 1 : 0) + (online ? 2 : 0);
  const float protection_h = g->protection_open ? 2 * BC_GAP + (float)protection_rows * (BC_ROW + BC_GAP) : BC_FOLDED_H;
  const float help_h = g->help ? (float)(BC_GAP + BC_HELP_H) : 0.0f;
  const float bottom_min_h = (BC_ROW + BC_GAP) + (BC_LOG_MIN * 24 + BC_GAP) + help_h; /* Run row, log, help. */
  const float min_h = BC_MARGIN + (BC_ROW + 2 * BC_GAP) + (game_min_h + 2 * BC_GAP) + (build_h + 2 * BC_GAP) +
                      (windows_h + 2 * BC_GAP) + (protection_h + 2 * BC_GAP) + bottom_min_h + BC_MARGIN;
  const float page_h = min_h > win_h ? min_h : win_h;
  const float inner = W - 2 * BC_MARGIN - (page_h > win_h ? BC_SCROLL_W : 0);
  const float spare = page_h - min_h;
  const int log_max = g->game_open ? BC_LOG_VISIBLE : BC_LOG_ROWS_MAX;
  const float list_first = g->game_open ? (float)((BC_LIST_ROWS - 3) * BC_LIST_ROW) : 0.0f;
  int log_lines = BC_LOG_MIN + (spare > list_first ? (int)((spare - list_first) / 24) : 0);
  log_lines = log_lines > log_max ? log_max : log_lines;
  const float list_h = list_min_h + spare - (float)(log_lines - BC_LOG_MIN) * 24;
  const float game_h = g->game_open ? game_fixed_h + list_h : BC_FOLDED_H;
  /* A held thumb owns the pointer up to the frame of its release: a button under the pointer must
   * not take that release as a click. */
  const bool thumb_held = g->scroll_drag;
  const bool page_wheeled = bc_gui_scroll_page(g, W, win_h, page_h, !modal && !dropdown_open);
  const bool page_locked = thumb_held || g->scroll_drag;
  if (modal || dropdown_open || page_locked) {
    GuiLock();
  }
  bc_gui_refresh_scan(g);
  bc_gui_refresh_check(g);
  const BC_Check *check = &g->check;
  const float x0 = BC_MARGIN + BC_GAP;
  const float right = BC_MARGIN + inner - 2 * BC_GAP;
  const float dropdown_extra = 3 * BC_GAP + (float)(GuiGetStyle(DROPDOWNBOX, ARROW_PADDING) + BC_ICON_SIZE);
  bool committed;
  char resolved[BC_PATH_MAX];
  char summary[2 * BC_PATH_MAX]; /* Paths and names: cut to the window when drawn. */

  /* Toolbar, the page scrolled. */
  float y = BC_MARGIN - g->scroll_y;
  if (running) {
    GuiDisable();
  }
  float x = BC_MARGIN;
  bc_tip(bc_rect(x, y, BC_BUTTON_W, BC_ROW), "New project (" BC_SHORTCUT "+N)");
  if (GuiButton(bc_rect(x, y, BC_BUTTON_W, BC_ROW), "New")) {
    bc_gui_request(g, BC_PENDING_NEW, NULL);
  }
  x += BC_BUTTON_W + BC_GAP;
  bc_tip(bc_rect(x, y, BC_BUTTON_W, BC_ROW), "Open a project (" BC_SHORTCUT "+O)");
  if (GuiButton(bc_rect(x, y, BC_BUTTON_W, BC_ROW), "Open...")) {
    bc_gui_request(g, BC_PENDING_OPEN_DIALOG, NULL);
  }
  x += BC_BUTTON_W + BC_GAP;
  bc_tip(bc_rect(x, y, BC_BUTTON_W, BC_ROW), "Save the project (" BC_SHORTCUT "+S)");
  if (GuiButton(bc_rect(x, y, BC_BUTTON_W, BC_ROW), "Save")) {
    bc_gui_save(g, false);
  }
  x += BC_BUTTON_W + BC_GAP;
  bc_tip(bc_rect(x, y, BC_BUTTON_W, BC_ROW), "Save the project under another name (" BC_SHORTCUT "+Shift+S)");
  if (GuiButton(bc_rect(x, y, BC_BUTTON_W, BC_ROW), "Save as...")) {
    bc_gui_save(g, true);
  }
  {
    /* The help panel at the bottom and the tooltips, on or off together. */
    const float help_w = bc_button_w("Help");
    const Rectangle help_toggle = bc_rect(BC_MARGIN + inner - help_w, y, help_w, BC_ROW);
    bc_tip(help_toggle, "Show or hide the help\nThe panel at the bottom explains the field under the pointer, and a tooltip names it. Off: neither.");
    GuiToggle(help_toggle, "Help", &g->help);
  }
  y += BC_ROW + 2 * BC_GAP;

  /* 1 · Game: what gets encrypted. Its summary is what the list gives, as the export lists it. */
  {
    const bool error = g->scan_error[0] != '\0';
    if (error) {
      snprintf(summary, sizeof(summary), "%s", g->scan_error);
    }
    else if (g->project.input_count == 0) {
      snprintf(summary, sizeof(summary), "nothing to encrypt yet");
    }
    else {
      char size[24];
      bc_format_size(g->scan_bytes, size, sizeof(size));
      snprintf(summary,
               sizeof(summary),
               "%d blend%s  \xc2\xb7  %d script%s  \xc2\xb7  %d data file%s  \xc2\xb7  %s",
               g->scan_blends,
               g->scan_blends == 1 ? "" : "s",
               g->scan_modules,
               g->scan_modules == 1 ? "" : "s",
               g->scan_data,
               g->scan_data == 1 ? "" : "s",
               size);
      if (g->scan.skipped > 0) {
        const size_t n = strlen(summary);
        snprintf(summary + n, sizeof(summary) - n, "  \xc2\xb7  %d skipped (already encrypted)", g->scan.skipped);
      }
    }
    if (bc_section(y, game_h, inner, "1 \xc2\xb7 Game", summary, error, g->game_open ? 1 : 0, "Show or hide what gets encrypted\nThe source folder, the files and folders to encrypt and the main file. Folded, the line counts what the list gives.")) {
      g->game_open = !g->game_open;
    }
  }
  if (g->game_open) {
    y += 2 * BC_GAP;
    if (bc_gui_path_row(x0, y, right, BC_LABEL_W, "Source folder", "Root of the game sources\nEvery file to encrypt is inside it, and the output folder mirrors its tree with the same names, so relative paths, linked libraries and imports keep working.", "Required: drop your game folder on the window", &check->source, g->project.source_root, g->source_text, &g->source_edit, &committed)) {
      r = bc_dialog_pick_folder("Source folder", path, sizeof(path));
      if (r == BC_DIALOG_OK) {
        snprintf(g->project.source_root, sizeof(g->project.source_root), "%s", path);
        bc_gui_set_modified(g);
        bc_gui_rebuild_items(g);
      }
      else if (r == BC_DIALOG_UNAVAILABLE) {
        bc_gui_dialog_unavailable(g);
      }
    }
    if (committed) {
      bc_gui_resolve(g, g->source_text, resolved);
      snprintf(g->project.source_root, sizeof(g->project.source_root), "%s", resolved);
      bc_gui_set_modified(g);
      bc_gui_rebuild_items(g);
    }
    y += BC_ROW + BC_GAP;

    /* The files as a tree, and beside them the types they come in. The wheel moved the page: a
     * list it may have brought under the pointer sits this frame out. */
    const float types_w = 260;
    bc_gui_file_list(g, bc_rect(x0, y, right - x0 - types_w - BC_GAP, list_h), page_wheeled);
    bc_gui_types_list(g, bc_rect(right - types_w, y, types_w, list_h), page_wheeled);
    y += list_h + BC_GAP;

    /* Under the list: its buttons. */
    float bx = x0;
    const float add_files_w = bc_button_w("Add files..."), add_folder_w = bc_button_w("Add folder...");
    const float remove_w = bc_button_w("Remove"), clear_w = bc_button_w("Clear");
    bc_tip(bc_rect(bx, y, add_files_w, BC_ROW), "Add files to encrypt\nAny file inside the source folder: .blend files, Python modules (.py), and any other file as a data file.");
    if (GuiButton(bc_rect(bx, y, add_files_w, BC_ROW), "Add files...")) {
      char list[65536];
      r = bc_dialog_open_files("Add files", NULL, true, list, sizeof(list));
      if (r == BC_DIALOG_OK) {
        for (char *p = strtok(list, "\n"); p != NULL; p = strtok(NULL, "\n")) {
          bc_gui_add_input(g, p);
        }
        bc_gui_rebuild_items(g);
      }
      else if (r == BC_DIALOG_UNAVAILABLE) {
        bc_gui_dialog_unavailable(g);
      }
    }
    bx += add_files_w + BC_GAP;
    bc_tip(bc_rect(bx, y, add_folder_w, BC_ROW), "Add a folder to encrypt\nScanned with its subfolders for .blend files, Python modules and data files; hidden folders and the output folder are skipped.");
    if (GuiButton(bc_rect(bx, y, add_folder_w, BC_ROW), "Add folder...")) {
      r = bc_dialog_pick_folder("Add a folder (scanned for .blend, .py and data files)", path, sizeof(path));
      if (r == BC_DIALOG_OK) {
        bc_gui_add_input(g, path);
        bc_gui_rebuild_items(g);
      }
      else if (r == BC_DIALOG_UNAVAILABLE) {
        bc_gui_dialog_unavailable(g);
      }
    }
    bx += add_folder_w + BC_GAP;
    const bool has_selection = g->list_active >= 0 && g->list_active < g->project.input_count;
    bool changed = bc_enable_begin(has_selection);
    bc_tip(bc_rect(bx, y, remove_w, BC_ROW), "Remove the selected entry\nFrom this list only: the files stay on disk.");
    if (GuiButton(bc_rect(bx, y, remove_w, BC_ROW), "Remove") && has_selection) {
      bc_project_remove_input(&g->project, g->list_active);
      bc_gui_set_modified(g);
      bc_gui_rebuild_items(g);
    }
    bc_enable_end(changed);
    bx += remove_w + BC_GAP;
    changed = bc_enable_begin(g->project.input_count > 0);
    bc_tip(bc_rect(bx, y, clear_w, BC_ROW), "Remove every entry\nFrom this list only: the files stay on disk.");
    if (GuiButton(bc_rect(bx, y, clear_w, BC_ROW), "Clear") && g->project.input_count > 0) {
      bc_project_clear_inputs(&g->project);
      bc_gui_set_modified(g);
      bc_gui_rebuild_items(g);
    }
    bc_enable_end(changed);
    y += BC_ROW + BC_GAP + 2 * BC_GAP;
  }
  else {
    y += game_h + 2 * BC_GAP;
  }

  /* 2 · Build: where the game goes, under which name, with which runtime. */
  char game_name[BC_GAME_NAME_MAX];
  bool game_is_default;
  bc_gui_effective_game_name(g, game_name, sizeof(game_name), &game_is_default);
  {
    char player_dir[BC_PATH_MAX];
    bc_path_dirname(player_dir, sizeof(player_dir), g->project.player[0] ? g->project.player : ".");
    snprintf(summary,
             sizeof(summary),
             "%s%s%s here, runtime in %s/",
             game_name,
             bc_exe_extension(),
             g->project.manifest_mode == BC_MANIFEST_EXTERNAL ? " + " BC_MANIFEST_FILENAME : "",
             player_dir);
    const bool error = check->output.state == BC_FIELD_ERROR || check->runtime.state == BC_FIELD_ERROR;
    if (bc_section(y, build_h, inner, "2 \xc2\xb7 Build", summary, error, g->build_open ? 1 : 0, "Show or hide where the game goes\nThe output folder (the game folder you ship), the name of the game executable and the UPBGE runtime.")) {
      g->build_open = !g->build_open;
    }
  }
  if (g->build_open) {
    y += 2 * BC_GAP;
    char output_hint[BC_PATH_MAX];
    if (g->project.source_root[0] != '\0') {
      snprintf(output_hint, sizeof(output_hint), "Required, outside the source folder: for example %s_build", bc_path_basename(g->project.source_root));
    }
    else {
      snprintf(output_hint, sizeof(output_hint), "Required: the game folder you ship, outside the source folder");
    }
    if (bc_gui_path_row(x0, y, right, BC_LABEL_W, "Output folder", "The game folder you ship\nAn encrypted copy of the source tree with the same names, plus the game executable. It must be outside the source folder.", output_hint, &check->output, g->project.output_dir, g->output_text, &g->output_edit, &committed)) {
      r = bc_dialog_pick_folder("Output folder", path, sizeof(path));
      if (r == BC_DIALOG_OK) {
        snprintf(g->project.output_dir, sizeof(g->project.output_dir), "%s", path);
        bc_gui_set_modified(g);
        g->inputs_revision++; /* Skipped while scanning when inside the sources. */
      }
      else if (r == BC_DIALOG_UNAVAILABLE) {
        bc_gui_dialog_unavailable(g);
      }
    }
    if (committed) {
      bc_gui_resolve(g, g->output_text, resolved);
      snprintf(g->project.output_dir, sizeof(g->project.output_dir), "%s", resolved);
      bc_gui_set_modified(g);
      g->inputs_revision++;
    }
    y += BC_ROW + BC_GAP;

    /* Game name, then the runtime: one row. Empty name means "the main file name". */
    const char *game_help = "Name of the game executable\nThe only executable in the game folder (\".exe\" is added on Windows). Empty: the name of the main file.";
    const float game_x = x0 + BC_LABEL_W;
    float game_w = (right - game_x) * 0.3f;
    game_w = game_w < 180 ? 180 : game_w > 300 ? 300 : game_w;
    GuiLabel(bc_rect(x0, y, BC_LABEL_W, BC_ROW), "Game name");
    bc_tip(bc_rect(x0, y, BC_LABEL_W + game_w, BC_ROW), game_help);
    if (!g->game_edit) {
      snprintf(g->game_text, sizeof(g->game_text), "%s%s", game_name, game_is_default ? "  (main file)" : "");
    }
    if (GuiTextBox(bc_rect(game_x, y, game_w, BC_ROW), g->game_text, BC_GAME_NAME_MAX - 1, g->game_edit)) {
      if (g->game_edit) {
        /* Trim spaces at both ends: they are invisible and break the executable name on Windows. */
        char *start = g->game_text;
        while (*start == ' ') {
          start++;
        }
        size_t n = strlen(start);
        while (n > 0 && start[n - 1] == ' ') {
          n--;
        }
        snprintf(g->project.game_name, sizeof(g->project.game_name), "%.*s", (int)n, start);
        bc_gui_set_modified(g);
      }
      else {
        snprintf(g->game_text, sizeof(g->game_text), "%s", g->project.game_name);
      }
      g->game_edit = !g->game_edit;
    }
    const float runtime_x = game_x + game_w + 2 * BC_GAP;
    const float runtime_label_w = MeasureTextEx(font, "UPBGE runtime", BC_TEXT_SIZE, text_spacing).x + 2 * BC_GAP;
    if (bc_gui_path_row(runtime_x, y, right, runtime_label_w, "UPBGE runtime", "The UPBGE player inside the game folder\nWith its runtime (DLLs, python, datafiles) next to it: copy it into the output folder before encrypting. It is hashed: the game refuses any other player.", "Required: the player in the game folder", &check->runtime, g->project.player, g->player_text, &g->player_edit, &committed)) {
      r = bc_dialog_open_files("UPBGE player executable", NULL, false, path, sizeof(path));
      if (r == BC_DIALOG_OK) {
        bc_gui_set_player(g, path);
      }
      else if (r == BC_DIALOG_UNAVAILABLE) {
        bc_gui_dialog_unavailable(g);
      }
    }
    if (committed) {
      bc_gui_set_player(g, g->player_text);
    }
    y += BC_ROW + BC_GAP + 2 * BC_GAP;
  }
  else {
    y += build_h + 2 * BC_GAP;
  }

  /* 3 · Windows appearance: only where this build makes Windows games, folded and disabled
   * elsewhere. Any value set brands both the game executable and the player. */
  {
    if (brand) {
      const char *icon_name = g->project.icon[0] ? bc_path_basename(g->project.icon) : "UPBGE icon";
      snprintf(summary,
               sizeof(summary),
               "%s  \xc2\xb7  version %s%s%s",
               icon_name,
               g->project.game_version[0] ? g->project.game_version : "1.0.0.0",
               g->project.company[0] ? "  \xc2\xb7  " : "",
               g->project.company);
    }
    else {
      snprintf(summary, sizeof(summary), "Windows builds of bc_tool only");
    }
    const bool greyed = bc_enable_begin(brand);
    /* Open, its fields say what the summary would. */
    const bool clicked = bc_section(y, windows_h, inner, "3 \xc2\xb7 Windows appearance", windows_open ? NULL : summary, check->icon.state == BC_FIELD_ERROR, windows_open ? 1 : 0, "Show or hide the Windows appearance\nIcon and version information of the game executable and of the player, as Explorer, the taskbar and Alt-Tab show them.");
    bc_enable_end(greyed);
    if (clicked) {
      g->windows_open = !g->windows_open;
    }
    else if (windows_open) {
      const float row_y = y + 2 * BC_GAP;
      if (bc_gui_path_row(x0, row_y, right, BC_LABEL_W, "Icon", "Windows: icon of the game\nOf the game executable and of the game window (taskbar, Alt-Tab), any sizes in one .ico. Empty: the UPBGE icon.", "Optional: the UPBGE icon", &check->icon, g->project.icon, g->icon_text, &g->icon_edit, &committed)) {
        r = bc_dialog_open_files("Game icon", "ico", false, path, sizeof(path));
        if (r == BC_DIALOG_OK) {
          snprintf(g->project.icon, sizeof(g->project.icon), "%s", path);
          bc_gui_set_modified(g);
        }
        else if (r == BC_DIALOG_UNAVAILABLE) {
          bc_gui_dialog_unavailable(g);
        }
      }
      if (committed) {
        bc_gui_resolve(g, g->icon_text, resolved);
        snprintf(g->project.icon, sizeof(g->project.icon), "%s", resolved);
        bc_gui_set_modified(g);
      }
      const float vy = row_y + BC_ROW + BC_GAP;
      const float version_w = 130;
      const float company_label_w = MeasureTextEx(font, "Company", BC_TEXT_SIZE, text_spacing).x + 3 * BC_GAP;
      const float copyright_label_w = MeasureTextEx(font, "Copyright", BC_TEXT_SIZE, text_spacing).x + 3 * BC_GAP;
      const float free_w = right - (x0 + BC_LABEL_W) - version_w - company_label_w - copyright_label_w - 2 * BC_GAP;
      const float company_w = free_w / 2;
      const char *version_help = "Windows: version of the game\nUp to four numbers (1.2.0), shown in the properties of the executable. Empty: 1.0.0.0.";
      const char *company_help = "Windows: company\nShown in the properties of the executable.";
      const char *copyright_help = "Windows: copyright\nShown in the properties of the executable.";
      float fx = x0 + BC_LABEL_W;
      GuiLabel(bc_rect(x0, vy, BC_LABEL_W, BC_ROW), "Version");
      bc_tip(bc_rect(x0, vy, BC_LABEL_W, BC_ROW), version_help);
      if (bc_gui_text_field(bc_rect(fx, vy, version_w, BC_ROW), version_help, "1.0.0.0", g->version_text, sizeof(g->version_text), g->project.game_version, sizeof(g->project.game_version), &g->version_edit)) {
        bc_gui_set_modified(g);
      }
      fx += version_w + BC_GAP;
      GuiLabel(bc_rect(fx + BC_GAP, vy, company_label_w, BC_ROW), "Company");
      bc_tip(bc_rect(fx + BC_GAP, vy, company_label_w, BC_ROW), company_help);
      fx += company_label_w;
      if (bc_gui_text_field(bc_rect(fx, vy, company_w, BC_ROW), company_help, "Optional", g->company_text, sizeof(g->company_text), g->project.company, sizeof(g->project.company), &g->company_edit)) {
        bc_gui_set_modified(g);
      }
      fx += company_w + BC_GAP;
      GuiLabel(bc_rect(fx + BC_GAP, vy, copyright_label_w, BC_ROW), "Copyright");
      bc_tip(bc_rect(fx + BC_GAP, vy, copyright_label_w, BC_ROW), copyright_help);
      fx += copyright_label_w;
      if (bc_gui_text_field(bc_rect(fx, vy, right - fx, BC_ROW), copyright_help, "Optional", g->copyright_text, sizeof(g->copyright_text), g->project.copyright, sizeof(g->project.copyright), &g->copyright_edit)) {
        bc_gui_set_modified(g);
      }
    }
    y += windows_h + 2 * BC_GAP;
  }

  /* 4 · Protection: where the key comes from, what the game checks, where its manifest goes. */
  Rectangle key_box = {0}, check_box = {0}, manifest_box = {0};
  {
    static const char *const check_names[] = {"Player only", "Player + Libraries", "Player + Libraries + Python"};
    const char *key_text = g->project.key_mode == BC_KEY_BUILD ? "Build key" :
                           !online                             ? "Per project key" :
                           g->project.key_cache                ? "Online key, offline after 1st launch" :
                                                                 "Online key, always online";
    char rotation[48] = "";
    if (online && g->project.key_rotation) {
      snprintf(rotation, sizeof(rotation), ", new key per update (%u)", g->project.key_update ? g->project.key_update : 1u);
    }
    snprintf(summary,
             sizeof(summary),
             "%s%s  \xc2\xb7  Runtime Check: %s  \xc2\xb7  %s",
             key_text,
             rotation,
             check_names[g->project.integrity <= BC_INTEGRITY_PYTHON ? g->project.integrity : 0],
             g->project.manifest_mode == BC_MANIFEST_EXTERNAL ? "Separate manifest file" : "Embedded manifest");
    const bool error = check->provider.state == BC_FIELD_ERROR || (online && g->project.key_provider[0] == '\0');
    if (bc_section(y, protection_h, inner, "4 \xc2\xb7 Protection", g->protection_open ? NULL : summary, error, g->protection_open ? 1 : 0, "Show or hide the protection settings\nWhere the content key comes from, what the game executable checks before every launch and where its manifest goes.")) {
      g->protection_open = !g->protection_open;
      g->check_edit = g->manifest_edit = g->key_edit = false;
    }
    else if (g->protection_open) {
      float py = y + 2 * BC_GAP;
      /* Content key: a dropdown like the other modes, drawn last. Online, the two ways a player
       * gets the key follow it, labeled, as a toggle group: both always in sight. */
      {
        const float key_x = x0 + BC_LABEL_W;
        const float padding = (float)GuiGetStyle(TOGGLE, GROUP_PADDING);
        float key_w = MeasureTextEx(font, "Per project", BC_TEXT_SIZE, text_spacing).x + dropdown_extra;
        float cache_w = MeasureTextEx(font, "Offline after 1st launch", BC_TEXT_SIZE, text_spacing).x + 2 * BC_GAP;
        const float types_label_w = MeasureTextEx(font, "Online types", BC_TEXT_SIZE, text_spacing).x + 3 * BC_GAP;
        /* Narrow windows: dropdown and toggles shrink together rather than overlap, the label keeps
         * its width. One padding inside the toggle group. */
        const float room = right - key_x - BC_GAP - types_label_w - padding;
        const float needed = key_w + 2 * cache_w;
        if (needed > room) {
          key_w *= room / needed;
          cache_w *= room / needed;
        }
        GuiLabel(bc_rect(x0, py, BC_LABEL_W, BC_ROW), "Key");
        key_box = bc_rect(key_x, py, key_w, BC_ROW);
        if (online) {
          int cache = g->project.key_cache ? 1 : 0;
          float fx = key_x + key_w + BC_GAP;
          GuiLabel(bc_rect(fx + BC_GAP, py, types_label_w, BC_ROW), "Online types");
          fx += types_label_w;
          bc_tip(bc_rect(fx - types_label_w, py, types_label_w + 2 * cache_w + padding, BC_ROW),
                 "How often the key server is asked\nAlways online: at every launch. Offline after 1st launch: the key stays on the player's computer, protected for that user, and the game also starts without a connection.");
          GuiToggleGroup(bc_rect(fx, py, cache_w, BC_ROW), "Always online;Offline after 1st launch", &cache);
          if (cache != (g->project.key_cache ? 1 : 0)) {
            g->project.key_cache = cache != 0;
            bc_gui_set_modified(g);
          }
        }
        py += BC_ROW + BC_GAP;
      }
      if (key_file_row) {
        const char *help = online ? "Content keys of this game\nCreated on the first export. Keep the file private and back it up, and install it on the key server. Not inside the game folder. Empty: next to the project file." :
                                    "Key of this project\nCreated on the first export. Keep it private and back it up: updates of the published game need it. Not inside the game folder. Empty: next to the project file.";
        /* Empty: the default key file, shown as the path it resolves to. */
        char key_hint[BC_PATH_MAX + 16];
        char key_default[BC_PATH_MAX];
        if (g->project.project_file[0] != '\0' && bc_project_key_file(&g->project, key_default, sizeof(key_default))) {
          char shown[BC_PATH_MAX];
          bc_fit_left(key_default, inner - BC_LABEL_W - BC_BUTTON_W - 4 * BC_GAP - 16 - 120, shown, sizeof(shown));
          snprintf(key_hint, sizeof(key_hint), "%s  (default)", shown);
        }
        else {
          snprintf(key_hint, sizeof(key_hint), "Next to the project file once it is saved  (default)");
        }
        if (bc_gui_path_row(x0, py, right, BC_LABEL_W, "Key file", help, key_hint, NULL, g->project.key_file, g->key_file_text, &g->key_file_edit, &committed)) {
          r = bc_dialog_save_file("Key file", "key", path, sizeof(path));
          if (r == BC_DIALOG_OK) {
            snprintf(g->project.key_file, sizeof(g->project.key_file), "%s", path);
            bc_gui_set_modified(g);
          }
          else if (r == BC_DIALOG_UNAVAILABLE) {
            bc_gui_dialog_unavailable(g);
          }
        }
        if (committed) {
          bc_gui_resolve(g, g->key_file_text, resolved); /* Empty stays empty: the default key file. */
          snprintf(g->project.key_file, sizeof(g->project.key_file), "%s", resolved);
          bc_gui_set_modified(g);
        }
        py += BC_ROW + BC_GAP;
      }
      if (online) {
        const float key_x = x0 + BC_LABEL_W;
        const float url_label_w = MeasureTextEx(font, "URL", BC_TEXT_SIZE, text_spacing).x + 3 * BC_GAP;
        const float provider_w = (right - key_x - BC_BUTTON_W - url_label_w - 2 * BC_GAP) * 0.45f;
        const char *provider_help = "Key provider inside the game folder\nFor example engine/bc_provider_steam.exe: proves to the key server that the player owns the game.";
        const char *url_help = "Key server address\nGiven to the provider (https://...). Optional: a provider may know its server.";
        GuiLabel(bc_rect(x0, py, BC_LABEL_W, BC_ROW), "Provider");
        bc_tip(bc_rect(x0, py, BC_LABEL_W, BC_ROW), provider_help);
        const Rectangle provider_box = bc_rect(key_x, py, provider_w, BC_ROW);
        if (bc_gui_text_field(provider_box, provider_help, "Required: engine/bc_provider_steam.exe, for example", g->provider_text, sizeof(g->provider_text), g->project.key_provider, sizeof(g->project.key_provider), &g->provider_edit)) {
          char entered[BC_PATH_MAX];
          snprintf(entered, sizeof(entered), "%s", g->project.key_provider);
          bc_gui_set_dist_path(g, entered, g->project.key_provider, sizeof(g->project.key_provider), "key provider");
        }
        if (!g->provider_edit && g->project.key_provider[0] != '\0') {
          bc_draw_field(provider_box, &check->provider);
        }
        float fx = key_x + provider_w + BC_GAP;
        if (GuiButton(bc_rect(fx, py, BC_BUTTON_W, BC_ROW), "Browse...")) {
          r = bc_dialog_open_files("Key provider executable", NULL, false, path, sizeof(path));
          if (r == BC_DIALOG_OK) {
            bc_gui_set_dist_path(g, path, g->project.key_provider, sizeof(g->project.key_provider), "key provider");
          }
          else if (r == BC_DIALOG_UNAVAILABLE) {
            bc_gui_dialog_unavailable(g);
          }
        }
        fx += BC_BUTTON_W;
        GuiLabel(bc_rect(fx + 2 * BC_GAP, py, url_label_w, BC_ROW), "URL");
        bc_tip(bc_rect(fx + 2 * BC_GAP, py, url_label_w, BC_ROW), url_help);
        fx += url_label_w + BC_GAP;
        if (bc_gui_text_field(bc_rect(fx, py, right - fx, BC_ROW), url_help, "Optional: https://...", g->url_text, sizeof(g->url_text), g->project.key_url, sizeof(g->project.key_url), &g->url_edit)) {
          bc_gui_set_modified(g);
        }
        py += BC_ROW + BC_GAP;

        /* Key per update: one key for the life of the game, or a new key for each published
         * update (unchanged files keep theirs, so store patches stay small). */
        const float rotation_w = MeasureTextEx(font, "New key per update", BC_TEXT_SIZE, text_spacing).x + 4 * BC_GAP;
        GuiLabel(bc_rect(x0, py, BC_LABEL_W, BC_ROW), "Updates");
        bc_tip(bc_rect(x0, py, BC_LABEL_W + 2 * rotation_w + (float)GuiGetStyle(TOGGLE, GROUP_PADDING), BC_ROW),
               "One key, or a new key per update\nOne key: every file of every update uses it. New key per update: changed files get the new key of the update, unchanged ones keep theirs; a leaked key opens no later update.");
        int rotation_mode = g->project.key_rotation ? 1 : 0;
        GuiToggleGroup(bc_rect(key_x, py, rotation_w, BC_ROW), "One key;New key per update", &rotation_mode);
        if (rotation_mode != (g->project.key_rotation ? 1 : 0)) {
          g->project.key_rotation = rotation_mode != 0;
          bc_gui_set_modified(g);
        }
        if (g->project.key_rotation) {
          const float update_label_w = MeasureTextEx(font, "Update number", BC_TEXT_SIZE, text_spacing).x + 3 * BC_GAP;
          const float update_x = key_x + 2 * rotation_w + (float)GuiGetStyle(TOGGLE, GROUP_PADDING) + 2 * BC_GAP;
          const char *update_help = "Number of the update you publish\nRaise it for each update, then install the key file on the key server again. Exports with the same number reuse its key.";
          GuiLabel(bc_rect(update_x, py, update_label_w, BC_ROW), "Update number");
          bc_tip(bc_rect(update_x, py, update_label_w, BC_ROW), update_help);
          char update_value[16];
          snprintf(update_value, sizeof(update_value), "%u", g->project.key_update ? g->project.key_update : 1u);
          if (bc_gui_text_field(bc_rect(update_x + update_label_w, py, 90, BC_ROW), update_help, NULL, g->update_text, sizeof(g->update_text), update_value, sizeof(update_value), &g->update_edit)) {
            char *end;
            const unsigned long update = strtoul(update_value, &end, 10);
            if (update_value[0] >= '0' && update_value[0] <= '9' && *end == '\0' && update >= 1 && update <= 0xFFFFFFFFul) {
              g->project.key_update = (uint32_t)update;
              bc_gui_set_modified(g);
            }
            else {
              bc_gui_log(g, BC_LOG_ERROR, "The update number is a whole number from 1");
            }
          }
        }
        py += BC_ROW + BC_GAP;
      }
      /* What the game executable checks, and where its manifest goes: two dropdowns, drawn last. */
      const float check_w = MeasureTextEx(font, "Player + Libraries + Python", BC_TEXT_SIZE, text_spacing).x + dropdown_extra;
      const float manifest_label_w = MeasureTextEx(font, "Manifest", BC_TEXT_SIZE, text_spacing).x + 3 * BC_GAP;
      const float manifest_w = MeasureTextEx(font, "Separate file", BC_TEXT_SIZE, text_spacing).x + dropdown_extra;
      GuiLabel(bc_rect(x0, py, BC_LABEL_W, BC_ROW), "Runtime Check");
      check_box = bc_rect(x0 + BC_LABEL_W, py, check_w, BC_ROW);
      const float manifest_x = check_box.x + check_w + 2 * BC_GAP;
      GuiLabel(bc_rect(manifest_x, py, manifest_label_w, BC_ROW), "Manifest");
      manifest_box = bc_rect(manifest_x + manifest_label_w, py, manifest_w, BC_ROW);
    }
    y += protection_h + 2 * BC_GAP;
  }
  if (running) {
    GuiEnable();
  }

  /* Run controls: the one action; what it still needs, or how far it got; then, once the game
   * is written, the two ways to look at it. */
  {
    const bool ready = check->todo[0] == '\0';
    const float run_w = 200;
    float right_x = BC_MARGIN + inner;
    Rectangle open_box = {0}, play_box = {0};
    const bool show_built = g->built && !running;
    if (show_built) {
      const float play_w = bc_button_w("Run game");
      const float open_w = bc_button_w("Open game folder");
      right_x -= play_w;
      play_box = bc_rect(right_x, y, play_w, BC_ROW);
      right_x -= BC_GAP + open_w;
      open_box = bc_rect(right_x, y, open_w, BC_ROW);
    }
    const Rectangle run_box = bc_rect(BC_MARGIN, y, run_w, BC_ROW);
    bc_tip(run_box, running ? "Stop\nThe file in progress is removed, finished files are kept." : "Encrypt the files and write the game executable (" BC_SHORTCUT "+Enter)");
    if (!running && !ready) {
      GuiDisable();
    }
    const bool hit = running ? GuiButton(run_box, "Cancel") != 0 : bc_primary_button(run_box, "Encrypt");
    if (!running && !ready) {
      GuiEnable();
    }
    if (hit) {
      if (running) {
        bc_gui_stop(g, "Cancelled: the file in progress was removed, finished files are kept");
      }
      else {
        bc_gui_start(g);
      }
    }
    const float mid_x = BC_MARGIN + run_w + BC_GAP;
    const float mid_w = right_x - BC_GAP - mid_x;
    if (!running && !ready) {
      /* Static: the help panel and the tooltip read it after this block. */
      static char todo[sizeof(check->todo) + 16];
      char shown[sizeof(todo)];
      snprintf(todo, sizeof(todo), "To encrypt: %s", check->todo);
      bc_fit_right(todo, mid_w, shown, sizeof(shown));
      bc_tip(bc_rect(mid_x, y, mid_w, BC_ROW), todo);
      const Vector2 position = {mid_x, y + (BC_ROW - BC_TEXT_SIZE) / 2};
      DrawTextEx(font, shown, position, BC_TEXT_SIZE, text_spacing, GetColor((unsigned int)BC_RGB(BC_RGB_WARNING)));
    }
    else {
      float progress = g->progress;
      char percent[16];
      snprintf(percent, sizeof(percent), show_built ? "Done" : "%3d%%", (int)(progress * 100.0f + 0.5f));
      GuiProgressBar(bc_rect(mid_x, y, mid_w - 70, BC_ROW), NULL, percent, &progress, 0.0f, 1.0f);
    }
    if (show_built) {
      bc_tip(open_box, g->built_dir);
      if (GuiButton(open_box, "Open game folder") && !bc_shell_open_folder(g->built_dir)) {
        bc_gui_logf(g, BC_LOG_ERROR, "Cannot show '%s' in a file manager", g->built_dir);
      }
      bc_tip(play_box, g->built_exe);
      if (GuiButton(play_box, "Run game") && !bc_shell_run(g->built_exe)) {
        bc_gui_logf(g, BC_LOG_ERROR, "Cannot start '%s'", g->built_exe);
      }
    }
  }
  y += BC_ROW + BC_GAP;

  /* Log: newest lines at the bottom, colored by level, wrapped to the panel. Rows are gathered from
   * the newest message shown back, so only the visible messages are measured (the oldest one may
   * keep only its last rows), then drawn from the top. The wheel scrolls back by messages: no
   * message needs measuring to know where it is. */
  const float log_h = (float)log_lines * 24 + BC_GAP;
  const Rectangle log_box = bc_rect(BC_MARGIN, y, inner, log_h);
  /* Copy log sits in the bottom right corner: no row runs under it. */
  const float copy_w = bc_button_w("Copy log");
  const float log_text_w = inner - 4 * BC_GAP - copy_w; /* Room for the scroll bar and Copy log. */
  if (!GuiIsLocked() && !page_wheeled && CheckCollisionPointRec(GetMousePosition(), log_box)) {
    const float wheel = GetMouseWheelMove();
    if (wheel != 0) {
      g->log_scroll += wheel > 0 ? (int)(wheel + 0.5f) : (int)(wheel - 0.5f);
    }
  }
  /* Scrolled all the way back, the oldest messages fill the panel: as many as fit, measured from
   * the oldest (a few wraps, and only while scrolled back). */
  int max_scroll = 0;
  if (g->log_scroll > 0) {
    int fit = 0;
    int used = 0;
    for (int i = g->log_count - 1; i >= 0; i--) {
      BC_Span spans[BC_LOG_VISIBLE];
      const int n = bc_wrap(g->log[(g->log_next - 1 - i + BC_LOG_LINES) % BC_LOG_LINES].text, log_text_w, text_spacing, spans, BC_LOG_VISIBLE);
      if (fit > 0 && used + n > log_lines) {
        break;
      }
      used += n;
      fit++;
    }
    max_scroll = g->log_count - fit;
  }
  g->log_scroll = g->log_scroll < 0 ? 0 : g->log_scroll > max_scroll ? max_scroll : g->log_scroll;
  GuiPanel(log_box, NULL);
  BeginScissorMode((int)BC_MARGIN, (int)y, (int)inner, (int)log_h);
  BC_Span rows[BC_LOG_ROWS_MAX];
  Color row_colors[BC_LOG_ROWS_MAX];
  int row_count = 0;
  /* Rows left above the panel: the wheel has something to scroll back to. */
  bool log_more = false;
  int msg = g->log_scroll;
  for (; msg < g->log_count && row_count < log_lines; msg++) {
    const BC_LogLine *line = &g->log[(g->log_next - 1 - msg + BC_LOG_LINES) % BC_LOG_LINES];
    const int rgba = line->level == BC_LOG_ERROR   ? BC_RGB(BC_RGB_ERROR) :
                     line->level == BC_LOG_WARNING ? BC_RGB(BC_RGB_WARNING) :
                                                     GuiGetStyle(DEFAULT, TEXT_COLOR_NORMAL);
    BC_Span spans[BC_LOG_VISIBLE];
    const int n = bc_wrap(line->text, log_text_w, text_spacing, spans, BC_LOG_VISIBLE);
    int k = n - 1;
    for (; k >= 0 && row_count < log_lines; k--) {
      rows[row_count] = spans[k];
      row_colors[row_count] = GetColor((unsigned int)rgba);
      row_count++;
    }
    log_more = log_more || k >= 0;
  }
  log_more = log_more || msg < g->log_count;
  /* The log keeps the wheel wherever it can move: back to older rows, or forward to the newest. */
  g->log_wheel = log_more || g->log_scroll > 0 ? log_box : bc_rect(0, 0, 0, 0);
  for (int row = 0; row < row_count; row++) {
    const int k = row_count - 1 - row;
    bc_draw_span(&rows[k], BC_MARGIN + BC_GAP, y + BC_GAP / 2 + (float)row * 24, text_spacing, row_colors[k]);
  }
  /* Scroll bar once the log holds more messages than lines: its size and place in messages, above
   * Copy log. */
  if (g->log_count > log_lines) {
    const float track_h = log_h - 3 * BC_GAP - BC_STATUS_H;
    const float thumb_h = track_h * (float)log_lines / (float)g->log_count;
    const int range = g->log_count - log_lines; /* Messages, as for the thumb size. */
    const float at = 1.0f - (float)g->log_scroll / (float)(range > g->log_scroll ? range : g->log_scroll > 0 ? g->log_scroll : 1);
    const Rectangle thumb = {BC_MARGIN + inner - BC_GAP, y + BC_GAP + (track_h - thumb_h) * at, 4, thumb_h};
    DrawRectangleRec(thumb, GetColor((unsigned int)GuiGetStyle(DEFAULT, BORDER_COLOR_NORMAL)));
  }
  EndScissorMode();
  {
    const Rectangle copy = bc_rect(BC_MARGIN + inner - copy_w - BC_GAP / 2, y + log_h - BC_STATUS_H - BC_GAP / 2, copy_w, BC_STATUS_H);
    bc_tip(copy, "Copy the whole log\nTo the clipboard, to report a problem.");
    if (GuiButton(copy, "Copy log")) {
      bc_gui_copy_log(g);
    }
  }
  y += log_h + BC_GAP;
  const Rectangle help_box = bc_rect(BC_MARGIN, y, inner, BC_HELP_H);

  /* Dropdowns last: an open list lies over the rows below it. The open one is drawn after the
   * closed ones. */
  if (dropdown_open && !modal && !page_locked) {
    GuiUnlock();
  }
  if (running) {
    GuiDisable();
  }
  if (!dropdown_open) {
    bc_tip(check_box,
           "What the game executable checks before every launch\nPlayer only: the player. + Libraries: also every .dll, .so, .dylib, .pyd and .exe of the game folder. + Python: also .py, .pth and .zip files, and bytecode is removed. Each costs a hash at every launch.");
    bc_tip(manifest_box,
           "Where the manifest of the game goes\nEmbedded: one self-contained game executable. Separate file: the game executable is an untouched copy of bc_launcher, with " BC_MANIFEST_FILENAME " next to it (sign bc_launcher once).");
    bc_tip(key_box,
           "Where the game gets its content key\nPer project: the key of this project, masked in the game executable. Online: a key server gives it to players who own the game, through the key provider. Build key: the key built into this tool.");
  }
  int integrity = (int)g->project.integrity;
  int manifest_mode = (int)g->project.manifest_mode;
  int key_mode = (int)g->project.key_mode;
  struct {
    Rectangle box;
    const char *items;
    int *value;
    bool *edit;
  } dropdowns[] = {
      {check_box, "Player only;Player + Libraries;Player + Libraries + Python", &integrity, &g->check_edit},
      {manifest_box, "Embedded;Separate file", &manifest_mode, &g->manifest_edit},
      {key_box, "Per project;Online;Build key", &key_mode, &g->key_edit},
  };
  const int dropdown_count = (int)(sizeof(dropdowns) / sizeof(dropdowns[0]));
  /* Fixed before drawing: a click flips the flag, and the same click must not reach a dropdown
   * twice. A folded section has no dropdown to draw. */
  int open = -1;
  for (int i = 0; i < dropdown_count; i++) {
    open = *dropdowns[i].edit && dropdowns[i].box.width > 0 ? i : open;
  }
  for (int pass = 0; pass <= dropdown_count; pass++) {
    const int i = pass < dropdown_count ? pass : open;
    if (i < 0 || (pass < dropdown_count && i == open) || dropdowns[i].box.width <= 0) {
      continue;
    }
    if (GuiDropdownBox(dropdowns[i].box, dropdowns[i].items, dropdowns[i].value, *dropdowns[i].edit)) {
      *dropdowns[i].edit = !*dropdowns[i].edit;
    }
  }
  if (integrity != (int)g->project.integrity) {
    g->project.integrity = (BC_Integrity)integrity;
    bc_gui_set_modified(g);
  }
  if (manifest_mode != (int)g->project.manifest_mode) {
    g->project.manifest_mode = (BC_ManifestMode)manifest_mode;
    bc_gui_set_modified(g);
  }
  if (key_mode != (int)g->project.key_mode) {
    g->project.key_mode = (BC_KeyMode)key_mode;
    bc_gui_set_modified(g);
  }
  if (running) {
    GuiEnable();
  }

  /* The help of what the pointer rests on, then its tooltip (its first line). Help off: neither. */
  if (g->help) {
    bc_gui_help_panel(help_box);
  }
  bc_gui_draw_tip(g->help);

  /* Confirmation dialog on top of everything, over a dimmed editor: centered in the window, not on
   * the page. */
  if (modal) {
    GuiUnlock();
    DrawRectangleRec(bc_rect(0, 0, W, win_h), Fade(BLACK, 0.5f));
    const Rectangle box = bc_rect(W / 2 - 260, win_h / 2 - 90, 520, 180);
    if (g->pending == BC_PENDING_QUIT) {
      const int answer = GuiMessageBox(box, "Unsaved changes", "Save the project before closing?", "Save;Discard");
      if (answer >= 0) {
        g->pending = BC_PENDING_NONE;
        if (answer == 2 || bc_gui_save(g, false)) {
          g->quit = true;
        }
      }
    }
    else {
      const int answer = GuiMessageBox(box, "Unsaved changes", "Discard the changes to this project?", "Discard;Cancel");
      if (answer >= 0) {
        const BC_Pending action = g->pending;
        g->pending = BC_PENDING_NONE;
        if (answer == 1) {
          g->modified = false;
          bc_gui_request(g, action, NULL);
        }
      }
    }
  }
  if (page_locked) {
    GuiUnlock(); /* raygui's lock outlives the frame. */
  }
}

/* -------------------------------------------------------------------------------------------- */

int bc_gui_run(const char *project_path)
{
  /* Static: the editor state holds several path buffers and the log, too large for the stack. */
  static BC_Gui g;
  memset(&g, 0, sizeof(g));
  bc_project_init(&g.project);
  bc_gui_default_player(&g);
  g.list_active = -1;
  bc_key_fingerprint(bc_build_key(), g.fingerprint);

  int window_w, window_h;
  bc_gui_load_settings(&g, &window_w, &window_h);
  SetConfigFlags(FLAG_WINDOW_RESIZABLE);
  InitWindow(window_w, window_h, "UPBGE BinaryCrypt v" BC_TOOL_VERSION);
#ifdef BC_WINDOW_ICON
  bc_gui_set_window_icon();
#endif
  /* A smaller screen (laptops, or another screen than last time) gets a window that fits it, room
   * left for a taskbar and the title bar: the page scrolls. Centered again, as the window opened
   * centered for its first size. */
  {
    const int monitor = GetCurrentMonitor();
    const int fit_w = GetMonitorWidth(monitor) - 40;
    const int fit_h = GetMonitorHeight(monitor) - 100;
    const int w = fit_w > 0 && fit_w < GetScreenWidth() ? (fit_w < BC_WINDOW_MIN_W ? BC_WINDOW_MIN_W : fit_w) : GetScreenWidth();
    const int h = fit_h > 0 && fit_h < GetScreenHeight() ? (fit_h < BC_WINDOW_MIN_H ? BC_WINDOW_MIN_H : fit_h) : GetScreenHeight();
    if (w != GetScreenWidth() || h != GetScreenHeight()) {
      SetWindowSize(w, h);
      const Vector2 origin = GetMonitorPosition(monitor);
      SetWindowPosition((int)origin.x + (GetMonitorWidth(monitor) - w) / 2, (int)origin.y + (GetMonitorHeight(monitor) - h) / 2);
    }
  }
  /* Narrower, the rows that share their width (game name and runtime, the list buttons and data
   * files) run out of room; any height, the page scrolls. */
  SetWindowMinSize(BC_WINDOW_MIN_W, BC_WINDOW_MIN_H);
  SetExitKey(KEY_NULL);
  SetTargetFPS(60);
  bc_gui_theme_upbge();
  const Font font = bc_gui_load_font();
  GuiSetFont(font);
  GuiSetStyle(LISTVIEW, LIST_ITEMS_HEIGHT, 28);
  GuiSetStyle(LISTVIEW, TEXT_ALIGNMENT, TEXT_ALIGN_LEFT);
  GuiSetStyle(LISTVIEW, TEXT_PADDING, 8);
  /* Dropdowns read like the fields around them. */
  GuiSetStyle(DROPDOWNBOX, TEXT_ALIGNMENT, TEXT_ALIGN_LEFT);
  GuiSetStyle(DROPDOWNBOX, TEXT_PADDING, 8);

  if (project_path != NULL) {
    bc_gui_load(&g, project_path);
  }
  bc_gui_rebuild_items(&g);
  bc_gui_update_title(&g);
  bc_gui_logf(&g, BC_LOG_INFO, "Key %s built into this tool: bc_launcher must come from the same build", g.fingerprint);
  bc_gui_log(&g, BC_LOG_INFO, "Drop the game's files or folders on the window, copy the UPBGE runtime into the game folder's engine/, then Encrypt");

  /* Frames still to draw without waiting for input. The first ones: some systems send no expose
   * event. And one after each click or Enter: immediate mode handles them while drawing, so what
   * they change above their control (a dialog opening or closing, rows appearing) only shows in
   * the next frame, which event waiting would hold until the next input event. */
  int eager_frames = 3;
  while (!g.quit) {
    /* raylib keeps reporting the close request once made, so it is handled only when no dialog
     * is open; a failed save simply asks again. */
    if (WindowShouldClose() && g.pending == BC_PENDING_NONE) {
      if (g.job != NULL) {
        bc_gui_stop(&g, "Cancelled by closing the window");
      }
      bc_gui_request(&g, BC_PENDING_QUIT, NULL);
      if (g.quit) {
        break; /* Nothing unsaved: now, not after the next input event that event waiting waits for. */
      }
    }
    if (IsFileDropped()) {
      bc_gui_handle_drop(&g);
    }
    /* Back from another program (Blender, a file manager): files may have come or gone. */
    const bool focused = IsWindowFocused();
    if (focused && !g.focused) {
      g.inputs_revision++;
    }
    g.focused = focused;
    const bool shortcut = bc_gui_shortcuts(&g);
    if (g.job != NULL) {
      bc_gui_tick_job(&g);
    }
    BeginDrawing();
    ClearBackground(GetColor((unsigned int)GuiGetStyle(DEFAULT, BACKGROUND_COLOR)));
    bc_gui_draw(&g);
    const bool acted = shortcut || IsMouseButtonPressed(MOUSE_BUTTON_LEFT) || IsMouseButtonReleased(MOUSE_BUTTON_LEFT) ||
                       IsKeyPressed(KEY_ENTER) || IsKeyPressed(KEY_KP_ENTER);
    eager_frames = eager_frames > 1 ? eager_frames - 1 : acted ? 1 : 0;
    /* Decided before EndDrawing: it polls the input of the next frame, blocking when waiting. A
     * running job needs every frame, and so does a tooltip counting down (at most BC_TIP_DELAY,
     * once per control entered). Idle, the editor costs no CPU. */
    if (g.job != NULL || eager_frames > 0 || g_tip_waiting) {
      DisableEventWaiting();
    }
    else {
      EnableEventWaiting();
    }
    EndDrawing();
  }

  if (g.job != NULL) {
    bc_job_destroy(g.job);
  }
  bc_gui_save_settings(&g);
  for (int i = 0; i < g.item_count; i++) {
    free(g.items[i]);
  }
  free(g.items);
  bc_file_list_free(&g.scan);
  free(g.input_rows);
  free(g.input_folded);
  free(g.types);
  bc_project_free(&g.project);
  UnloadFont(font); /* No-op for raylib's own font. */
  CloseWindow();
  return 0;
}
