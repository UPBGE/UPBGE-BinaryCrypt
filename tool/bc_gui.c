/* SPDX-License-Identifier: GPL-2.0-or-later */

/* bc_tool editor: raylib + raygui immediate mode GUI over a BC_Project.
 *
 * Idle frames block on input (event waiting), so the editor costs no CPU while untouched. While
 * encrypting, each frame hands about 12 ms to the batch job: the window stays responsive and the
 * progress bar is live, with no threads and no synchronization. */

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
/* Fewest log lines: below them the page scrolls instead. */
#define BC_LOG_MIN 3
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
  BC_Field source, output, runtime, main, icon, provider;
  bool no_inputs;
  /** What to do before encrypting, empty when ready. */
  char todo[512];
} BC_Check;

typedef struct BC_Gui {
  BC_Project project;
  char project_path[BC_PATH_MAX];
  bool modified;

  /* Text boxes mirror project fields while not being edited. */
  char source_text[BC_PATH_MAX];
  char output_text[BC_PATH_MAX];
  char player_text[BC_PATH_MAX];
  char main_text[BC_PATH_MAX];
  char game_text[BC_GAME_NAME_MAX];
  char icon_text[BC_PATH_MAX];
  char version_text[BC_PROJECT_VERSION_MAX];
  char company_text[BC_PROJECT_TEXT_MAX];
  char copyright_text[BC_PROJECT_TEXT_MAX];
  char key_file_text[BC_PATH_MAX];
  char provider_text[BC_PATH_MAX];
  char url_text[BC_PROJECT_URL_MAX];
  char update_text[16];
  char data_text[BC_PROJECT_TEXT_MAX];
  bool source_edit, output_edit, player_edit, main_edit, game_edit;
  bool icon_edit, version_edit, company_edit, copyright_edit;
  bool key_file_edit, provider_edit, url_edit, update_edit, data_edit;
  /** Open dropdowns: drawn last, over the rows below them. */
  bool check_edit, manifest_edit, key_edit;

  char **items;
  int item_count;
  int list_scroll, list_active, list_focus;

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
  Rectangle list_wheel, log_wheel;

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
           "UPBGE BinaryCrypt - %s%s",
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

/** Rebuild the list labels: inputs relative to the source folder, folders with a trailing '/',
 * the main file marked. */
static void bc_gui_rebuild_items(BC_Gui *g)
{
  g->revision++;
  for (int i = 0; i < g->item_count; i++) {
    free(g->items[i]);
  }
  free(g->items);
  g->items = NULL;
  g->item_count = g->project.input_count;
  if (g->item_count == 0) {
    g->list_active = -1;
    return;
  }
  g->items = (char **)calloc((size_t)g->item_count, sizeof(char *));
  for (int i = 0; i < g->item_count; i++) {
    const char *input = g->project.inputs[i];
    char rel[BC_PATH_MAX];
    const char *shown = input;
    if (g->project.source_root[0] && bc_path_relative(rel, sizeof(rel), g->project.source_root, input)) {
      shown = rel;
    }
    const bool is_main = strcmp(input, g->project.main) == 0;
    const bool is_dir = bc_is_dir(input);
    const bool is_root = strcmp(shown, ".") == 0;
    const size_t size = strlen(shown) + 32;
    g->items[i] = (char *)malloc(size);
    snprintf(g->items[i],
             size,
             "%s%s%s",
             is_root ? "(whole source folder)" : shown,
             is_dir && !is_root ? "/" : "",
             is_main ? "   [main]" : "");
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

  bool listed = false;
  for (int i = 0; i < p->input_count && !listed; i++) {
    listed = bc_path_is_inside(p->inputs[i], p->main);
  }
  if (p->main[0] == '\0') {
    bc_field_set(&c->main, BC_FIELD_NONE, NULL);
    bc_todo(c, "set the main file");
  }
  else if (!bc_is_file(p->main)) {
    bc_field_set(&c->main, BC_FIELD_ERROR, "not found");
    bc_todo(c, "the main file does not exist");
  }
  else if (!bc_path_has_extension(p->main, ".blend")) {
    bc_field_set(&c->main, BC_FIELD_ERROR, "not a .blend");
    bc_todo(c, "the main file must be a .blend");
  }
  else if (p->input_count > 0 && !listed) {
    bc_field_set(&c->main, BC_FIELD_ERROR, "not listed");
    bc_todo(c, "add the main file to the files to encrypt");
  }
  else {
    bc_field_set(&c->main, BC_FIELD_OK, NULL);
  }

  if (p->input_count == 0) {
    c->no_inputs = true;
    bc_todo(c, "add files to encrypt");
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
  return g->source_edit || g->output_edit || g->player_edit || g->main_edit || g->game_edit ||
         g->icon_edit || g->version_edit || g->company_edit || g->copyright_edit ||
         g->key_file_edit || g->provider_edit || g->url_edit || g->update_edit || g->data_edit ||
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

/** raygui draws a group's frame and title in the same color: here the frame takes the line color
 * and the title the accent. */
static void bc_group_box(const Rectangle bounds, const char *title)
{
  GuiGroupBox(bounds, NULL);
  const float spacing = (float)GuiGetStyle(DEFAULT, TEXT_SPACING);
  const Vector2 size = MeasureTextEx(GuiGetFont(), title, BC_TEXT_SIZE, spacing);
  const Rectangle gap = {bounds.x + 8, bounds.y, size.x + 8, 1};
  DrawRectangleRec(gap, GetColor((unsigned int)GuiGetStyle(DEFAULT, BACKGROUND_COLOR)));
  const int rgba = GuiGetState() == STATE_DISABLED ? GuiGetStyle(DEFAULT, TEXT_COLOR_DISABLED) : BC_RGB(BC_RGB_ACCENT);
  const Vector2 position = {bounds.x + 12, bounds.y - size.y / 2};
  DrawTextEx(GuiGetFont(), title, position, BC_TEXT_SIZE, spacing, GetColor((unsigned int)rgba));
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
/* Tooltips and wrapped text. raygui draws a tooltip together with its control, so every control
 * drawn later paints over it, and on one line that can run past the window. Controls register
 * their tooltip here instead; the one under the mouse is drawn last, wrapped to the window. */

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
 * when there is no room, inside the window. */
static void bc_gui_draw_tip(void)
{
  const char *text = g_tip_text;
  g_tip_text = NULL;
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

/** Editable path row: label, text box, browse button. \a placeholder shows while it is empty and
 * \a field (may be NULL) tells whether what it names checks out. Returns true when the button was
 * hit and sets *r_committed when an edit was just confirmed. */
static bool bc_gui_path_row(float y,
                            float width,
                            const char *label,
                            const char *tooltip,
                            const char *placeholder,
                            const BC_Field *field,
                            const char *value,
                            char *text,
                            bool *edit,
                            bool *r_committed)
{
  const float x = BC_MARGIN + BC_GAP;
  const float box_w = width - BC_LABEL_W - BC_BUTTON_W - 4 * BC_GAP;
  const Rectangle box = bc_rect(x + BC_LABEL_W, y, box_w, BC_ROW);
  GuiLabel(bc_rect(x, y, BC_LABEL_W, BC_ROW), label);
  bc_tip(box, tooltip);
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
  return GuiButton(bc_rect(x + BC_LABEL_W + box_w + BC_GAP, y, BC_BUTTON_W, BC_ROW), "Browse...");
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
    if (wheel != 0 && !CheckCollisionPointRec(mouse, g->list_wheel) && !CheckCollisionPointRec(mouse, g->log_wheel)) {
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

static void bc_gui_draw(BC_Gui *g)
{
  const float W = (float)GetScreenWidth();
  const float win_h = (float)GetScreenHeight();
  const bool running = g->job != NULL;
  const bool modal = g->pending != BC_PENDING_NONE;
  char path[BC_PATH_MAX];
  BC_DialogResult r;

  if (modal) {
    g->check_edit = g->manifest_edit = g->key_edit = false;
  }
  /* An open dropdown takes every click until it closes: the rows under its list must not react. */
  const bool dropdown_open = g->check_edit || g->manifest_edit || g->key_edit;

  /* Rows shown, known before anything is drawn: with the shortest file list (its buttons) and log
   * (BC_LOG_MIN lines), they give the height of the page. A taller window stretches both; a shorter
   * one scrolls the page. */
  const bool online = g->project.key_mode == BC_KEY_ONLINE;
  const bool key_file_row = g->project.key_mode != BC_KEY_BUILD;
  /* Icon and version information only exist for Windows games: hidden where this build cannot make
   * one (the project keeps them, the job ignores them with a warning). */
  const bool brand_rows = bc_brand_supported();
  const int settings_rows = (online ? 12 : key_file_row ? 10 : 9) - (brand_rows ? 0 : 2);
  const float settings_h = (float)(settings_rows * (BC_ROW + BC_GAP) + 2 * BC_GAP);
  const float files_min_h = 5 * (BC_ROW + BC_GAP) + 3 * BC_GAP;
  const float bottom_min_h = BC_ROW + BC_LOG_MIN * 24 + 5 * BC_GAP + BC_STATUS_H; /* Run row, log, status bar. */
  const float min_h = BC_MARGIN + (BC_ROW + 2 * BC_GAP) + (settings_h + 2 * BC_GAP) + files_min_h + bottom_min_h + BC_MARGIN;
  const float page_h = min_h > win_h ? min_h : win_h;
  const float inner = W - 2 * BC_MARGIN - (page_h > win_h ? BC_SCROLL_W : 0);
  /* A held thumb owns the pointer up to the frame of its release: a button under the pointer must
   * not take that release as a click. */
  const bool thumb_held = g->scroll_drag;
  const bool page_wheeled = bc_gui_scroll_page(g, W, win_h, page_h, !modal && !dropdown_open);
  const bool page_locked = thumb_held || g->scroll_drag;
  if (modal || dropdown_open || page_locked) {
    GuiLock();
  }
  bc_gui_refresh_check(g);
  const BC_Check *check = &g->check;

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
  y += BC_ROW + 2 * BC_GAP;

  /* Settings. */
  bc_group_box(bc_rect(BC_MARGIN, y, inner, settings_h), "Settings");
  y += 2 * BC_GAP;
  bool committed;
  char resolved[BC_PATH_MAX];

  if (bc_gui_path_row(y, inner, "Source folder", "Root of the game sources: .blend files, Python modules, data files", "Required: drop your game folder on the window", &check->source, g->project.source_root, g->source_text, &g->source_edit, &committed)) {
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

  char output_hint[BC_PATH_MAX];
  if (g->project.source_root[0] != '\0') {
    snprintf(output_hint, sizeof(output_hint), "Required, outside the source folder: for example %s_build", bc_path_basename(g->project.source_root));
  }
  else {
    snprintf(output_hint, sizeof(output_hint), "Required: the game folder you ship, outside the source folder");
  }
  if (bc_gui_path_row(y, inner, "Output folder", "Encrypted copy of the source tree, with the same names: this is the game folder you ship", output_hint, &check->output, g->project.output_dir, g->output_text, &g->output_edit, &committed)) {
    r = bc_dialog_pick_folder("Output folder", path, sizeof(path));
    if (r == BC_DIALOG_OK) {
      snprintf(g->project.output_dir, sizeof(g->project.output_dir), "%s", path);
      bc_gui_set_modified(g);
    }
    else if (r == BC_DIALOG_UNAVAILABLE) {
      bc_gui_dialog_unavailable(g);
    }
  }
  if (committed) {
    bc_gui_resolve(g, g->output_text, resolved);
    snprintf(g->project.output_dir, sizeof(g->project.output_dir), "%s", resolved);
    bc_gui_set_modified(g);
  }
  y += BC_ROW + BC_GAP;

  /* Game name: the one executable players see. Empty means "the main file name". */
  char game_name[BC_GAME_NAME_MAX];
  bool game_is_default;
  bc_gui_effective_game_name(g, game_name, sizeof(game_name), &game_is_default);
  GuiLabel(bc_rect(BC_MARGIN + BC_GAP, y, BC_LABEL_W, BC_ROW), "Game name");
  if (!g->game_edit) {
    snprintf(g->game_text, sizeof(g->game_text), "%s%s", game_name, game_is_default ? "  (main file)" : "");
  }
  /* Manifest placement shares the row as a dropdown, right aligned with the path row buttons; the
   * runtime check shares the runtime row below, in the same column: one label width, one dropdown
   * width. Dropdowns are drawn last (a list opens over the rows below), as wide as the widest item
   * of the column plus room for the arrow. */
  const float text_spacing = (float)GuiGetStyle(DEFAULT, TEXT_SPACING);
  const float dropdown_extra = 3 * BC_GAP + (float)(GuiGetStyle(DROPDOWNBOX, ARROW_PADDING) + BC_ICON_SIZE);
  const float side_label_w = MeasureTextEx(GuiGetFont(), "Runtime Check", BC_TEXT_SIZE, text_spacing).x + 3 * BC_GAP;
  const float side_w = MeasureTextEx(GuiGetFont(), "Player + Libraries + Python", BC_TEXT_SIZE, text_spacing).x + dropdown_extra;
  const float side_x = BC_MARGIN + inner - 2 * BC_GAP - side_w;
  const float game_box_w = side_x - side_label_w - BC_GAP - (BC_MARGIN + BC_GAP + BC_LABEL_W);
  bc_tip(bc_rect(BC_MARGIN + BC_GAP + BC_LABEL_W, y, game_box_w, BC_ROW),
         "Name of the game executable (\".exe\" is added on Windows): the only executable in the game folder. "
         "Empty: the name of the main file");
  if (GuiTextBox(bc_rect(BC_MARGIN + BC_GAP + BC_LABEL_W, y, game_box_w, BC_ROW),
                 g->game_text,
                 BC_GAME_NAME_MAX - 1,
                 g->game_edit))
  {
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
  GuiLabel(bc_rect(side_x - side_label_w, y, side_label_w, BC_ROW), "Manifest");
  const Rectangle manifest_box = bc_rect(side_x, y, side_w, BC_ROW);
  y += BC_ROW + BC_GAP;

  /* The runtime, then the check of it the game executable makes. Its Browse button ends where the
   * game name field does (a path row ends 2 * BC_GAP inside its width). */
  GuiLabel(bc_rect(side_x - side_label_w, y, side_label_w, BC_ROW), "Runtime Check");
  const Rectangle check_box = bc_rect(side_x, y, side_w, BC_ROW);
  if (bc_gui_path_row(y, side_x - side_label_w + BC_GAP - BC_MARGIN, "UPBGE runtime", "UPBGE player inside the game folder, with its runtime (DLLs, python, datafiles) next to it. It is hashed: the game refuses any other player", "Required: the UPBGE player inside the game folder", &check->runtime, g->project.player, g->player_text, &g->player_edit, &committed)) {
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
  y += BC_ROW + BC_GAP;

  if (bc_gui_path_row(y, inner, "Main file", "The .blend the game executable starts", "Required: the .blend the game starts", &check->main, g->project.main, g->main_text, &g->main_edit, &committed)) {
    r = bc_dialog_open_files("Main .blend file", "blend", false, path, sizeof(path));
    if (r == BC_DIALOG_OK) {
      snprintf(g->project.main, sizeof(g->project.main), "%s", path);
      /* The main file must be encrypted too: add it unless an input already covers it. */
      bool covered = false;
      for (int i = 0; i < g->project.input_count && !covered; i++) {
        covered = bc_path_is_inside(g->project.inputs[i], path);
      }
      if (!covered) {
        bc_gui_add_input(g, path);
      }
      bc_gui_set_modified(g);
      bc_gui_rebuild_items(g);
    }
    else if (r == BC_DIALOG_UNAVAILABLE) {
      bc_gui_dialog_unavailable(g);
    }
  }
  if (committed) {
    bc_gui_resolve(g, g->main_text, resolved);
    snprintf(g->project.main, sizeof(g->project.main), "%s", resolved);
    bc_gui_set_modified(g);
    bc_gui_rebuild_items(g);
  }
  y += BC_ROW + BC_GAP;

  /* Windows branding, only where this build makes Windows games. Any value set brands both the
   * game executable and the player. */
  if (brand_rows) {
  if (bc_gui_path_row(y, inner, "Icon", "Windows: icon of the game executable and of the game window (taskbar, Alt-Tab), any sizes. Empty: keep the UPBGE icon", "Optional: the UPBGE icon", &check->icon, g->project.icon, g->icon_text, &g->icon_edit, &committed)) {
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
  y += BC_ROW + BC_GAP;

  {
    const float x0 = BC_MARGIN + BC_GAP + BC_LABEL_W;
    const float right = BC_MARGIN + inner - 2 * BC_GAP;
    const float version_w = 130;
    const float company_label_w = MeasureTextEx(GuiGetFont(), "Company", BC_TEXT_SIZE, text_spacing).x + 3 * BC_GAP;
    const float copyright_label_w = MeasureTextEx(GuiGetFont(), "Copyright", BC_TEXT_SIZE, text_spacing).x + 3 * BC_GAP;
    const float free_w = right - x0 - version_w - company_label_w - copyright_label_w - 2 * BC_GAP;
    const float company_w = free_w / 2;
    float fx = x0;
    GuiLabel(bc_rect(BC_MARGIN + BC_GAP, y, BC_LABEL_W, BC_ROW), "Version");
    if (bc_gui_text_field(bc_rect(fx, y, version_w, BC_ROW), "Windows: game version, up to four numbers (1.2.0). Empty: 1.0.0.0", "1.0.0.0", g->version_text, sizeof(g->version_text), g->project.game_version, sizeof(g->project.game_version), &g->version_edit)) {
      bc_gui_set_modified(g);
    }
    fx += version_w + BC_GAP;
    GuiLabel(bc_rect(fx + BC_GAP, y, company_label_w, BC_ROW), "Company");
    fx += company_label_w;
    if (bc_gui_text_field(bc_rect(fx, y, company_w, BC_ROW), "Windows: company shown in the executable properties", "Optional", g->company_text, sizeof(g->company_text), g->project.company, sizeof(g->project.company), &g->company_edit)) {
      bc_gui_set_modified(g);
    }
    fx += company_w + BC_GAP;
    GuiLabel(bc_rect(fx + BC_GAP, y, copyright_label_w, BC_ROW), "Copyright");
    fx += copyright_label_w;
    if (bc_gui_text_field(bc_rect(fx, y, right - fx, BC_ROW), "Windows: copyright shown in the executable properties", "Optional", g->copyright_text, sizeof(g->copyright_text), g->project.copyright, sizeof(g->project.copyright), &g->copyright_edit)) {
      bc_gui_set_modified(g);
    }
  }
  y += BC_ROW + BC_GAP;
  }

  /* Content key: the project's own (masked in the manifest), given by a key server through the
   * provider, or the one compiled into the launcher. */
  Rectangle key_box;
  {
    const float x0 = BC_MARGIN + BC_GAP + BC_LABEL_W;
    const float right = BC_MARGIN + inner - 2 * BC_GAP;
    const Font font = GuiGetFont();
    const float padding = (float)GuiGetStyle(TOGGLE, GROUP_PADDING);
    /* A dropdown like the other modes, drawn last. Online, the two ways a player gets the key follow
     * it, labeled, as a toggle group: both always in sight. */
    float key_w = MeasureTextEx(font, "Per project", BC_TEXT_SIZE, text_spacing).x + dropdown_extra;
    float cache_w = MeasureTextEx(font, "Offline after 1st launch", BC_TEXT_SIZE, text_spacing).x + 2 * BC_GAP;
    const float types_label_w = MeasureTextEx(font, "Online types", BC_TEXT_SIZE, text_spacing).x + 3 * BC_GAP;
    /* Narrow windows: dropdown and toggles shrink together rather than overlap, the label keeps its
     * width. One padding inside the toggle group. */
    const float room = right - x0 - BC_GAP - types_label_w - padding;
    const float needed = key_w + 2 * cache_w;
    if (needed > room) {
      key_w *= room / needed;
      cache_w *= room / needed;
    }
    GuiLabel(bc_rect(BC_MARGIN + BC_GAP, y, BC_LABEL_W, BC_ROW), "Key");
    key_box = bc_rect(x0, y, key_w, BC_ROW);
    if (online) {
      int cache = g->project.key_cache ? 1 : 0;
      float fx = x0 + key_w + BC_GAP;
      GuiLabel(bc_rect(fx + BC_GAP, y, types_label_w, BC_ROW), "Online types");
      fx += types_label_w;
      bc_tip(bc_rect(fx, y, 2 * cache_w + padding, BC_ROW),
             "Always online: the key server is asked at every launch. Offline after the first launch: the key stays on the player's computer (protected for that user) and the game also starts without a connection");
      GuiToggleGroup(bc_rect(fx, y, cache_w, BC_ROW), "Always online;Offline after 1st launch", &cache);
      if (cache != (g->project.key_cache ? 1 : 0)) {
        g->project.key_cache = cache != 0;
        bc_gui_set_modified(g);
      }
    }
    y += BC_ROW + BC_GAP;
  }
  if (key_file_row) {
    const char *tip = online ? "Content keys of this game, created on the first export. Keep the file private, back it up and install it on the key server; it must not be inside the game folder. Empty: next to the project file, named after it" : "Key of this project, created on the first export. Keep it private and back it up: updates of the published game need it. It must not be inside the game folder. Empty: next to the project file, named after it";
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
    if (bc_gui_path_row(y, inner, "Key file", tip, key_hint, NULL, g->project.key_file, g->key_file_text, &g->key_file_edit, &committed)) {
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
    y += BC_ROW + BC_GAP;
  }
  if (online) {
    const float x0 = BC_MARGIN + BC_GAP + BC_LABEL_W;
    const float right = BC_MARGIN + inner - 2 * BC_GAP;
    const float url_label_w = MeasureTextEx(GuiGetFont(), "URL", BC_TEXT_SIZE, text_spacing).x + 3 * BC_GAP;
    const float provider_w = (right - x0 - BC_BUTTON_W - url_label_w - 2 * BC_GAP) * 0.45f;
    GuiLabel(bc_rect(BC_MARGIN + BC_GAP, y, BC_LABEL_W, BC_ROW), "Provider");
    const Rectangle provider_box = bc_rect(x0, y, provider_w, BC_ROW);
    if (bc_gui_text_field(provider_box, "Key provider inside the game folder (for example engine/bc_provider_steam.exe): proves to the key server that the player owns the game", "Required: engine/bc_provider_steam.exe, for example", g->provider_text, sizeof(g->provider_text), g->project.key_provider, sizeof(g->project.key_provider), &g->provider_edit)) {
      char entered[BC_PATH_MAX];
      snprintf(entered, sizeof(entered), "%s", g->project.key_provider);
      bc_gui_set_dist_path(g, entered, g->project.key_provider, sizeof(g->project.key_provider), "key provider");
    }
    if (!g->provider_edit && g->project.key_provider[0] != '\0') {
      bc_draw_field(provider_box, &check->provider);
    }
    float fx = x0 + provider_w + BC_GAP;
    if (GuiButton(bc_rect(fx, y, BC_BUTTON_W, BC_ROW), "Browse...")) {
      r = bc_dialog_open_files("Key provider executable", NULL, false, path, sizeof(path));
      if (r == BC_DIALOG_OK) {
        bc_gui_set_dist_path(g, path, g->project.key_provider, sizeof(g->project.key_provider), "key provider");
      }
      else if (r == BC_DIALOG_UNAVAILABLE) {
        bc_gui_dialog_unavailable(g);
      }
    }
    fx += BC_BUTTON_W;
    GuiLabel(bc_rect(fx + 2 * BC_GAP, y, url_label_w, BC_ROW), "URL");
    fx += url_label_w + BC_GAP;
    if (bc_gui_text_field(bc_rect(fx, y, right - fx, BC_ROW), "Key server address, given to the provider (https://...). Optional: a provider may know its server", "Optional: https://...", g->url_text, sizeof(g->url_text), g->project.key_url, sizeof(g->project.key_url), &g->url_edit)) {
      bc_gui_set_modified(g);
    }
    y += BC_ROW + BC_GAP;

    /* Key per update: one key for the life of the game, or a new key for each published update
     * (unchanged files keep theirs, so store patches stay small). */
    const float rotation_w = MeasureTextEx(GuiGetFont(), "New key per update", BC_TEXT_SIZE, text_spacing).x + 4 * BC_GAP;
    GuiLabel(bc_rect(BC_MARGIN + BC_GAP, y, BC_LABEL_W, BC_ROW), "Updates");
    bc_tip(bc_rect(x0, y, 2 * rotation_w + (float)GuiGetStyle(TOGGLE, GROUP_PADDING), BC_ROW),
           "One key: every file of every update uses the same key. New key per update: files changed in an update get its new key, unchanged files keep their key and their bytes; a leaked key does not open later updates");
    int rotation = g->project.key_rotation ? 1 : 0;
    GuiToggleGroup(bc_rect(x0, y, rotation_w, BC_ROW), "One key;New key per update", &rotation);
    if (rotation != (g->project.key_rotation ? 1 : 0)) {
      g->project.key_rotation = rotation != 0;
      bc_gui_set_modified(g);
    }
    if (g->project.key_rotation) {
      const float update_label_w = MeasureTextEx(GuiGetFont(), "Update number", BC_TEXT_SIZE, text_spacing).x + 3 * BC_GAP;
      const float update_x = x0 + 2 * rotation_w + GuiGetStyle(TOGGLE, GROUP_PADDING) + 2 * BC_GAP;
      GuiLabel(bc_rect(update_x, y, update_label_w, BC_ROW), "Update number");
      char update_value[16];
      snprintf(update_value, sizeof(update_value), "%u", g->project.key_update ? g->project.key_update : 1u);
      if (bc_gui_text_field(bc_rect(update_x + update_label_w, y, 90, BC_ROW), "Raise it for each update you publish (then install the key file on the key server again). Exports with the same number reuse its key", NULL, g->update_text, sizeof(g->update_text), update_value, sizeof(update_value), &g->update_edit)) {
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
    y += BC_ROW + BC_GAP;
  }

  /* Distribution root summary. */
  {
    char info[3 * BC_PATH_MAX];
    char folder[BC_PATH_MAX];
    char player_dir[BC_PATH_MAX];
    char contents[BC_PATH_MAX + BC_GAME_NAME_MAX + 64];
    bc_path_dirname(player_dir, sizeof(player_dir), g->project.player[0] ? g->project.player : ".");
    snprintf(contents,
             sizeof(contents),
             "   (%s%s%s here, runtime in %s/)",
             game_name,
             bc_exe_extension(),
             g->project.manifest_mode == BC_MANIFEST_EXTERNAL ? " + " BC_MANIFEST_FILENAME : "",
             player_dir);
    /* The folder gets whatever width the description leaves: it is the part that can be cut. */
    const float text_spacing_info = (float)GuiGetStyle(DEFAULT, TEXT_SPACING);
    const float fixed_w = MeasureTextEx(GuiGetFont(), contents, BC_TEXT_SIZE, text_spacing_info).x +
                          MeasureTextEx(GuiGetFont(), "Game folder: ", BC_TEXT_SIZE, text_spacing_info).x;
    bc_fit_left(g->project.output_dir[0] ? g->project.output_dir : "-", inner - 4 * BC_GAP - fixed_w, folder, sizeof(folder));
    snprintf(info, sizeof(info), "Game folder: %s%s", folder, contents);
    GuiLabel(bc_rect(BC_MARGIN + BC_GAP, y, inner - 2 * BC_GAP, BC_ROW), info);
  }
  y += BC_ROW + 3 * BC_GAP;

  /* Files. */
  /* The log gives up lines (down to BC_LOG_MIN) before the file list gets shorter than its
   * buttons. Measured to the bottom of the page, in window coordinates like y. */
  const float page_bottom = page_h - g->scroll_y;
  const float spare = page_bottom - y - BC_MARGIN - files_min_h - (bottom_min_h - BC_LOG_MIN * 24);
  int log_lines = (int)(spare / 24);
  log_lines = log_lines < BC_LOG_MIN ? BC_LOG_MIN : log_lines > BC_LOG_VISIBLE ? BC_LOG_VISIBLE : log_lines;
  /* Run row, log, status bar. */
  const float bottom_h = BC_ROW + (float)log_lines * 24 + 5 * BC_GAP + BC_STATUS_H;
  const float files_h = page_bottom - y - bottom_h - BC_MARGIN;
  bc_group_box(bc_rect(BC_MARGIN, y, inner, files_h), "Files to encrypt (drop files or folders here)");
  const float list_x = BC_MARGIN + BC_GAP;
  const float list_y = y + 2 * BC_GAP;
  const float list_w = inner - BC_BUTTON_W - 4 * BC_GAP;
  const float list_h = files_h - 4 * BC_GAP - BC_ROW;
  const Rectangle list_box = bc_rect(list_x, list_y, list_w, list_h);
  /* The wheel moved the page: the list it may have brought under the pointer sits this frame out. */
  const bool list_locked = page_wheeled && !GuiIsLocked();
  if (list_locked) {
    GuiLock();
  }
  GuiListViewEx(list_box, (const char **)g->items, g->item_count, &g->list_scroll, &g->list_active, &g->list_focus);
  if (list_locked) {
    GuiUnlock();
  }
  /* raygui's list takes the wheel only while enabled and showing a scroll bar: its own test. */
  const bool list_scrolls = !running && (float)((GuiGetStyle(LISTVIEW, LIST_ITEMS_HEIGHT) + GuiGetStyle(LISTVIEW, LIST_ITEMS_SPACING)) * g->item_count) > list_h;
  g->list_wheel = list_scrolls ? list_box : bc_rect(0, 0, 0, 0);
  {
    /* Below the list, as wide: what else the folders give. */
    const float data_y = list_y + list_h + BC_GAP;
    const float label_w = MeasureTextEx(GuiGetFont(), "Data files", BC_TEXT_SIZE, text_spacing).x + 3 * BC_GAP;
    GuiLabel(bc_rect(list_x, data_y, label_w, BC_ROW), "Data files");
    if (bc_gui_text_field(bc_rect(list_x + label_w, data_y, list_w - label_w, BC_ROW),
                          "Extensions of the data files the folders also give, encrypted too (for example: json txt csv). The game reads them with bge.logic.decryptFile(path). Python modules (.py) are always encrypted",
                          "Optional: json txt csv, for example",
                          g->data_text,
                          sizeof(g->data_text),
                          g->project.data_extensions,
                          sizeof(g->project.data_extensions),
                          &g->data_edit))
    {
      bc_gui_set_modified(g);
    }
  }
  const float bx = list_x + list_w + BC_GAP;
  float by = list_y;
  if (GuiButton(bc_rect(bx, by, BC_BUTTON_W, BC_ROW), "Add files...")) {
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
  by += BC_ROW + BC_GAP;
  if (GuiButton(bc_rect(bx, by, BC_BUTTON_W, BC_ROW), "Add folder...")) {
    r = bc_dialog_pick_folder("Add a folder (scanned for .blend, .py and data files)", path, sizeof(path));
    if (r == BC_DIALOG_OK) {
      bc_gui_add_input(g, path);
      bc_gui_rebuild_items(g);
    }
    else if (r == BC_DIALOG_UNAVAILABLE) {
      bc_gui_dialog_unavailable(g);
    }
  }
  by += BC_ROW + BC_GAP;
  const bool has_selection = g->list_active >= 0 && g->list_active < g->project.input_count;
  if (GuiButton(bc_rect(bx, by, BC_BUTTON_W, BC_ROW), "Set as main") && has_selection) {
    const char *selected = g->project.inputs[g->list_active];
    if (bc_is_dir(selected) || !bc_path_has_extension(selected, ".blend")) {
      bc_gui_log(g, BC_LOG_WARNING, "The main file must be a .blend file");
    }
    else {
      snprintf(g->project.main, sizeof(g->project.main), "%s", selected);
      bc_gui_set_modified(g);
      bc_gui_rebuild_items(g);
    }
  }
  by += BC_ROW + BC_GAP;
  if (GuiButton(bc_rect(bx, by, BC_BUTTON_W, BC_ROW), "Remove") && has_selection) {
    bc_project_remove_input(&g->project, g->list_active);
    bc_gui_set_modified(g);
    bc_gui_rebuild_items(g);
  }
  by += BC_ROW + BC_GAP;
  if (GuiButton(bc_rect(bx, by, BC_BUTTON_W, BC_ROW), "Clear") && g->project.input_count > 0) {
    bc_project_clear_inputs(&g->project);
    bc_gui_set_modified(g);
    bc_gui_rebuild_items(g);
  }
  if (running) {
    GuiEnable();
  }
  y += files_h + 2 * BC_GAP;

  /* Run controls: the one action; what it still needs, or how far it got; then, once the game
   * is written, the two ways to look at it. */
  {
    const bool ready = check->todo[0] == '\0';
    const Font font = GuiGetFont();
    const float run_w = 200;
    float right_x = BC_MARGIN + inner;
    Rectangle open_box = {0}, play_box = {0};
    const bool show_built = g->built && !running;
    if (show_built) {
      const float play_w = MeasureTextEx(font, "Run game", BC_TEXT_SIZE, text_spacing).x + 4 * BC_GAP;
      const float open_w = MeasureTextEx(font, "Open game folder", BC_TEXT_SIZE, text_spacing).x + 4 * BC_GAP;
      right_x -= play_w;
      play_box = bc_rect(right_x, y, play_w, BC_ROW);
      right_x -= BC_GAP + open_w;
      open_box = bc_rect(right_x, y, open_w, BC_ROW);
    }
    const Rectangle run_box = bc_rect(BC_MARGIN, y, run_w, BC_ROW);
    bc_tip(run_box, running ? "Stop: the file in progress is removed, finished files are kept" : "Encrypt the files and write the game executable (" BC_SHORTCUT "+Enter)");
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
      char todo[sizeof(check->todo) + 16];
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
  const float log_text_w = inner - 3 * BC_GAP; /* Room for the scroll bar. */
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
  BC_Span rows[BC_LOG_VISIBLE];
  Color row_colors[BC_LOG_VISIBLE];
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
  /* Scroll bar once the log holds more messages than lines: its size and place in messages. */
  if (g->log_count > log_lines) {
    const float track_h = log_h - 2 * BC_GAP;
    const float thumb_h = track_h * (float)log_lines / (float)g->log_count;
    const int range = g->log_count - log_lines; /* Messages, as for the thumb size. */
    const float at = 1.0f - (float)g->log_scroll / (float)(range > g->log_scroll ? range : g->log_scroll > 0 ? g->log_scroll : 1);
    const Rectangle thumb = {BC_MARGIN + inner - BC_GAP, y + BC_GAP + (track_h - thumb_h) * at, 4, thumb_h};
    DrawRectangleRec(thumb, GetColor((unsigned int)GuiGetStyle(DEFAULT, BORDER_COLOR_NORMAL)));
  }
  EndScissorMode();
  y += log_h + BC_GAP;

  /* Status bar: the key of this build, and the log to the clipboard. */
  {
    char status[64];
    snprintf(status, sizeof(status), "Key %s", g->fingerprint);
    const float copy_w = MeasureTextEx(GuiGetFont(), "Copy log", BC_TEXT_SIZE, text_spacing).x + 4 * BC_GAP;
    bc_tip(bc_rect(BC_MARGIN, y, 300, BC_STATUS_H), "Fingerprint of the key built into this tool: the launcher must come from the same build");
    GuiStatusBar(bc_rect(BC_MARGIN, y, inner - copy_w - BC_GAP, BC_STATUS_H), status);
    bc_tip(bc_rect(BC_MARGIN + inner - copy_w, y, copy_w, BC_STATUS_H), "Copy the whole log, to report a problem");
    if (GuiButton(bc_rect(BC_MARGIN + inner - copy_w, y, copy_w, BC_STATUS_H), "Copy log")) {
      bc_gui_copy_log(g);
    }
  }

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
           "What the game executable checks before every launch. Player only: the player executable. Player + "
           "Libraries: also every .dll, .so, .dylib, .pyd and .exe of the game folder (a proxy DLL would run "
           "inside the player). Player + Libraries + Python: also .py, .pth and .zip files, and Python bytecode is "
           "removed (the game then compiles its scripts at every launch). Each level costs a hash of those files at "
           "every launch");
    bc_tip(manifest_box,
           "Embedded: one self-contained game executable. Separate file: the game executable is an "
           "untouched copy of bc_launcher and " BC_MANIFEST_FILENAME " goes next to it (sign "
           "bc_launcher once; strip, UPX and codesign stay harmless)");
    bc_tip(key_box,
           "Per project: a key of this project, from its key file, travels masked in the game executable (another game made with this tool has another key). Online: a key server gives it to players who own the game (Steam, Epic...) through the key provider; no shipped file holds it. Build key: the key compiled into this tool and the launcher");
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
   * twice. */
  int open = -1;
  for (int i = 0; i < dropdown_count; i++) {
    open = *dropdowns[i].edit ? i : open;
  }
  for (int pass = 0; pass <= dropdown_count; pass++) {
    const int i = pass < dropdown_count ? pass : open;
    if (i < 0 || (pass < dropdown_count && i == open)) {
      continue;
    }
    if (GuiDropdownBox(dropdowns[i].box, dropdowns[i].items, dropdowns[i].value, *dropdowns[i].edit)) {
      *dropdowns[i].edit = !*dropdowns[i].edit;
    }
  }
  if (running) {
    GuiEnable();
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

  bc_gui_draw_tip();

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

  SetConfigFlags(FLAG_WINDOW_RESIZABLE);
  /* Tall enough for every row of a Windows build with online keys, and still within a 1080p
   * screen with its taskbar. */
  InitWindow(1100, 980, "UPBGE BinaryCrypt");
#ifdef BC_WINDOW_ICON
  bc_gui_set_window_icon();
#endif
  /* A shorter screen (laptops) gets a window that fits it, room left for a taskbar and the title
   * bar: the page scrolls. Centered again, as the window opened centered for its first size. */
  {
    const int monitor = GetCurrentMonitor();
    const int fit_h = GetMonitorHeight(monitor) - 100;
    if (fit_h > 0 && fit_h < GetScreenHeight()) {
      SetWindowSize(GetScreenWidth(), fit_h < 500 ? 500 : fit_h);
      const Vector2 origin = GetMonitorPosition(monitor);
      SetWindowPosition((int)origin.x + (GetMonitorWidth(monitor) - GetScreenWidth()) / 2,
                        (int)origin.y + (GetMonitorHeight(monitor) - GetScreenHeight()) / 2);
    }
  }
  /* Narrower, the runtime path would have no room left beside the runtime check; any height, the
   * page scrolls. */
  SetWindowMinSize(1000, 500);
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
    }
    if (IsFileDropped()) {
      bc_gui_handle_drop(&g);
    }
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
  for (int i = 0; i < g.item_count; i++) {
    free(g.items[i]);
  }
  free(g.items);
  bc_project_free(&g.project);
  UnloadFont(font); /* No-op for raylib's own font. */
  CloseWindow();
  return 0;
}
