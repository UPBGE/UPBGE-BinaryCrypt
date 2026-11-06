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

#define BC_TEXT_SIZE 20
#define BC_ROW 32
#define BC_GAP 8
#define BC_MARGIN 12
#define BC_LABEL_W 150
#define BC_BUTTON_W 130
#define BC_LOG_LINES 256
#define BC_LOG_VISIBLE 7
#define BC_JOB_BUDGET 0.012

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
  bool source_edit, output_edit, player_edit, main_edit, game_edit;
  bool icon_edit, version_edit, company_edit, copyright_edit;
  bool key_file_edit, provider_edit, url_edit, update_edit;

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
  if (!g->modified) {
    g->modified = true;
    bc_gui_update_title(g);
  }
}

/** Rebuild the list labels: inputs relative to the source folder, folders with a trailing '/',
 * the main file marked. */
static void bc_gui_rebuild_items(BC_Gui *g)
{
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

/** Add a dropped or picked path. The first one also seeds the source folder and the main file. */
static void bc_gui_add_input(BC_Gui *g, const char *path)
{
  char normalized[BC_PATH_MAX];
  snprintf(normalized, sizeof(normalized), "%s", path);
  bc_path_normalize(normalized);
  const bool is_dir = bc_is_dir(normalized);
  if (!is_dir && !bc_path_has_extension(normalized, ".blend")) {
    bc_gui_logf(g, BC_LOG_WARNING, "Ignored '%s': not a .blend file or a folder", normalized);
    return;
  }
  if (g->project.source_root[0] == '\0') {
    if (is_dir) {
      snprintf(g->project.source_root, sizeof(g->project.source_root), "%s", normalized);
    }
    else {
      bc_path_dirname(g->project.source_root, sizeof(g->project.source_root), normalized);
    }
  }
  if (g->project.main[0] == '\0' && !is_dir) {
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
  }
  else {
    bc_gui_log(g, BC_LOG_ERROR, "Encryption failed");
  }
  bc_gui_stop(g, NULL);
}

/* -------------------------------------------------------------------------------------------- */
/* Input events */

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

/* -------------------------------------------------------------------------------------------- */
/* Tooltips and wrapped text. raygui draws a tooltip together with its control, so every control
 * drawn later paints over it, and on one line that can run past the window. Controls register
 * their tooltip here instead; the one under the mouse is drawn last, wrapped to the window. */

static const char *g_tip_text = NULL;
static Rectangle g_tip_anchor;

static void bc_tip(const Rectangle anchor, const char *text)
{
  if (text != NULL && !GuiIsLocked() && GuiGetState() != STATE_DISABLED &&
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
  if (g_tip_text == NULL) {
    return;
  }
  const float W = (float)GetScreenWidth();
  const float H = (float)GetScreenHeight();
  const float spacing = (float)GuiGetStyle(DEFAULT, TEXT_SPACING);
  const float line_h = BC_TEXT_SIZE + 4;
  const float max_w = (W - 2 * BC_MARGIN < 640 ? W - 2 * BC_MARGIN : 640) - 2 * BC_GAP;
  BC_Span spans[24];
  const int n = bc_wrap(g_tip_text, max_w, spacing, spans, 24);
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
  g_tip_text = NULL;
}

/** Plain text box mirroring \a value, trimmed when confirmed. Returns true when \a value changed. */
static bool bc_gui_text_field(Rectangle bounds,
                              const char *tooltip,
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
  return changed;
}

/** Editable path row: label, text box, browse button. Returns true when the button was hit and
 * sets *r_committed when an edit was just confirmed. */
static bool bc_gui_path_row(float y,
                            float width,
                            const char *label,
                            const char *tooltip,
                            const char *value,
                            char *text,
                            bool *edit,
                            bool *r_committed)
{
  const float x = BC_MARGIN + BC_GAP;
  const float box_w = width - BC_LABEL_W - BC_BUTTON_W - 4 * BC_GAP;
  GuiLabel(bc_rect(x, y, BC_LABEL_W, BC_ROW), label);
  bc_tip(bc_rect(x + BC_LABEL_W, y, box_w, BC_ROW), tooltip);
  *r_committed = false;
  if (!*edit) {
    bc_fit_left(value, box_w - 16, text, BC_PATH_MAX);
  }
  if (GuiTextBox(bc_rect(x + BC_LABEL_W, y, box_w, BC_ROW), text, BC_PATH_MAX - 1, *edit)) {
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

static void bc_gui_draw(BC_Gui *g)
{
  const float W = (float)GetScreenWidth();
  const float H = (float)GetScreenHeight();
  const float inner = W - 2 * BC_MARGIN;
  const bool running = g->job != NULL;
  const bool modal = g->pending != BC_PENDING_NONE;
  char path[BC_PATH_MAX];
  BC_DialogResult r;

  if (modal) {
    GuiLock();
  }

  /* Toolbar. */
  float y = BC_MARGIN;
  if (running) {
    GuiDisable();
  }
  float x = BC_MARGIN;
  if (GuiButton(bc_rect(x, y, BC_BUTTON_W, BC_ROW), "New")) {
    bc_gui_request(g, BC_PENDING_NEW, NULL);
  }
  x += BC_BUTTON_W + BC_GAP;
  if (GuiButton(bc_rect(x, y, BC_BUTTON_W, BC_ROW), "Open...")) {
    bc_gui_request(g, BC_PENDING_OPEN_DIALOG, NULL);
  }
  x += BC_BUTTON_W + BC_GAP;
  if (GuiButton(bc_rect(x, y, BC_BUTTON_W, BC_ROW), "Save")) {
    bc_gui_save(g, false);
  }
  x += BC_BUTTON_W + BC_GAP;
  if (GuiButton(bc_rect(x, y, BC_BUTTON_W, BC_ROW), "Save as...")) {
    bc_gui_save(g, true);
  }
  x += BC_BUTTON_W + 2 * BC_GAP;
  char key_label[64];
  snprintf(key_label, sizeof(key_label), "Key %s", g->fingerprint);
  bc_tip(bc_rect(W - BC_MARGIN - 260, y, 260, BC_ROW),
         "Fingerprint of the key built into this tool: the launcher must come from the same build");
  GuiLabel(bc_rect(W - BC_MARGIN - 260, y, 260, BC_ROW), key_label);
  y += BC_ROW + 2 * BC_GAP;

  /* Settings. */
  const bool online = g->project.key_mode == BC_KEY_ONLINE;
  const bool key_file_row = g->project.key_mode != BC_KEY_BUILD;
  const float settings_h = (float)((online ? 13 : key_file_row ? 11 : 10) * (BC_ROW + BC_GAP) + 2 * BC_GAP);
  bc_group_box(bc_rect(BC_MARGIN, y, inner, settings_h), "Settings");
  y += 2 * BC_GAP;
  bool committed;
  char resolved[BC_PATH_MAX];

  if (bc_gui_path_row(y, inner, "Source folder", "Root of the source .blend tree", g->project.source_root, g->source_text, &g->source_edit, &committed)) {
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

  GuiLabel(bc_rect(BC_MARGIN + BC_GAP, y, BC_LABEL_W, BC_ROW), "Output");
  int mode = (int)g->project.output_mode;
  const float toggle_w = (inner - BC_LABEL_W - 4 * BC_GAP) / 2;
  GuiToggleGroup(bc_rect(BC_MARGIN + BC_GAP + BC_LABEL_W, y, toggle_w, BC_ROW),
                 "Mirror into the output folder;Next to the sources (.upbgebc)",
                 &mode);
  if (mode != (int)g->project.output_mode) {
    g->project.output_mode = (BC_OutputMode)mode;
    bc_gui_set_modified(g);
  }
  y += BC_ROW + BC_GAP;

  const bool inplace = g->project.output_mode == BC_OUTPUT_INPLACE;
  if (inplace && !running) {
    GuiDisable();
  }
  if (bc_gui_path_row(y, inner, "Output folder", "Encrypted copy of the source tree, with the same names: this is the game folder you ship", g->project.output_dir, g->output_text, &g->output_edit, &committed)) {
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
  if (inplace && !running) {
    GuiEnable();
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
  /* Manifest placement shares the row, right aligned with the path row buttons. */
  const float text_spacing = (float)GuiGetStyle(DEFAULT, TEXT_SPACING);
  const float manifest_item_w = MeasureTextEx(GuiGetFont(), "Separate file", BC_TEXT_SIZE, text_spacing).x + 4 * BC_GAP;
  const float manifest_label_w = MeasureTextEx(GuiGetFont(), "Manifest", BC_TEXT_SIZE, text_spacing).x + 3 * BC_GAP;
  const float manifest_group_w = 2 * manifest_item_w + GuiGetStyle(TOGGLE, GROUP_PADDING);
  const float manifest_x = BC_MARGIN + inner - 2 * BC_GAP - manifest_group_w;
  /* Integrity level: a combo box between the name and the manifest group. */
  const float check_label_w = MeasureTextEx(GuiGetFont(), "Check", BC_TEXT_SIZE, text_spacing).x + 2 * BC_GAP;
  /* The selector button shows "2/3": the default style is too narrow for this font. */
  const int combo_button_w = (int)(MeasureTextEx(GuiGetFont(), "3/3", BC_TEXT_SIZE, text_spacing).x + 3 * BC_GAP);
  const float check_combo_w = MeasureTextEx(GuiGetFont(), "+ Libraries", BC_TEXT_SIZE, text_spacing).x + 4 * BC_GAP +
                              combo_button_w + GuiGetStyle(COMBOBOX, COMBO_BUTTON_SPACING);
  const float check_x = manifest_x - manifest_label_w - BC_GAP - check_combo_w;
  const float game_box_w = check_x - check_label_w - BC_GAP - (BC_MARGIN + BC_GAP + BC_LABEL_W);
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
  GuiLabel(bc_rect(check_x - check_label_w, y, check_label_w, BC_ROW), "Check");
  bc_tip(bc_rect(check_x, y, check_combo_w, BC_ROW),
         "What the game executable checks before every launch. Player: the player executable. + Libraries: "
         "also every .dll, .so, .dylib, .pyd and .exe of the game folder (a proxy DLL would run inside the "
         "player). + Python: also .py, .pth and .zip files, and Python bytecode is removed (the game then "
         "compiles its scripts at every launch). Each level costs a hash of those files at every launch");
  int integrity = (int)g->project.integrity;
  const int default_button_w = GuiGetStyle(COMBOBOX, COMBO_BUTTON_WIDTH);
  GuiSetStyle(COMBOBOX, COMBO_BUTTON_WIDTH, combo_button_w);
  GuiComboBox(bc_rect(check_x, y, check_combo_w, BC_ROW), "Player;+ Libraries;+ Python", &integrity);
  GuiSetStyle(COMBOBOX, COMBO_BUTTON_WIDTH, default_button_w);
  if (integrity != (int)g->project.integrity) {
    g->project.integrity = (BC_Integrity)integrity;
    bc_gui_set_modified(g);
  }
  GuiLabel(bc_rect(manifest_x - manifest_label_w, y, manifest_label_w, BC_ROW), "Manifest");
  bc_tip(bc_rect(manifest_x, y, manifest_group_w, BC_ROW),
         "Embedded: one self-contained game executable. Separate file: the game executable is an "
         "untouched copy of bc_launcher and " BC_MANIFEST_FILENAME " goes next to it (sign "
         "bc_launcher once; strip, UPX and codesign stay harmless)");
  int manifest_mode = (int)g->project.manifest_mode;
  GuiToggleGroup(bc_rect(manifest_x, y, manifest_item_w, BC_ROW), "Embedded;Separate file", &manifest_mode);
  if (manifest_mode != (int)g->project.manifest_mode) {
    g->project.manifest_mode = (BC_ManifestMode)manifest_mode;
    bc_gui_set_modified(g);
  }
  y += BC_ROW + BC_GAP;

  if (bc_gui_path_row(y, inner, "Player", "UPBGE player inside the game folder, with its runtime (DLLs, python, datafiles) next to it. It is hashed: the game refuses any other player", g->project.player, g->player_text, &g->player_edit, &committed)) {
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

  if (bc_gui_path_row(y, inner, "Main file", "The .blend the game executable starts", g->project.main, g->main_text, &g->main_edit, &committed)) {
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

  /* Windows branding: greyed out where it cannot apply (the launcher of this build is not a
   * Windows executable). Any value set brands both the game executable and the player. */
  const bool brand_off = !bc_brand_supported() && !running;
  if (brand_off) {
    GuiDisable();
  }
  if (bc_gui_path_row(y, inner, "Icon", "Windows: icon of the game executable and of the game window (taskbar, Alt-Tab), any sizes. Empty: keep the UPBGE icon", g->project.icon, g->icon_text, &g->icon_edit, &committed)) {
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
    if (bc_gui_text_field(bc_rect(fx, y, version_w, BC_ROW), "Windows: game version, up to four numbers (1.2.0). Empty: 1.0.0.0", g->version_text, sizeof(g->version_text), g->project.game_version, sizeof(g->project.game_version), &g->version_edit)) {
      bc_gui_set_modified(g);
    }
    fx += version_w + BC_GAP;
    GuiLabel(bc_rect(fx + BC_GAP, y, company_label_w, BC_ROW), "Company");
    fx += company_label_w;
    if (bc_gui_text_field(bc_rect(fx, y, company_w, BC_ROW), "Windows: company shown in the executable properties", g->company_text, sizeof(g->company_text), g->project.company, sizeof(g->project.company), &g->company_edit)) {
      bc_gui_set_modified(g);
    }
    fx += company_w + BC_GAP;
    GuiLabel(bc_rect(fx + BC_GAP, y, copyright_label_w, BC_ROW), "Copyright");
    fx += copyright_label_w;
    if (bc_gui_text_field(bc_rect(fx, y, right - fx, BC_ROW), "Windows: copyright shown in the executable properties", g->copyright_text, sizeof(g->copyright_text), g->project.copyright, sizeof(g->project.copyright), &g->copyright_edit)) {
      bc_gui_set_modified(g);
    }
  }
  if (brand_off) {
    GuiEnable();
  }
  y += BC_ROW + BC_GAP;

  /* Content key: the project's own (masked in the manifest), given by a key server through the
   * provider, or the one compiled into the launcher. */
  {
    const float x0 = BC_MARGIN + BC_GAP + BC_LABEL_W;
    const float right = BC_MARGIN + inner - 2 * BC_GAP;
    const Font font = GuiGetFont();
    const float padding = (float)GuiGetStyle(TOGGLE, GROUP_PADDING);
    float key_w = MeasureTextEx(font, "Per project", BC_TEXT_SIZE, text_spacing).x + 4 * BC_GAP;
    const int key_count = 3;
    float cache_w = MeasureTextEx(font, "Offline after 1st launch", BC_TEXT_SIZE, text_spacing).x + 2 * BC_GAP;
    /* Narrow windows: both groups shrink together rather than overlap. Paddings: two inside the
     * key group, one inside the cache group. */
    const float needed = key_count * key_w + 2 * cache_w + 3 * padding + 2 * BC_GAP;
    if (needed > right - x0) {
      key_w *= (right - x0) / needed;
      cache_w *= (right - x0) / needed;
    }
    GuiLabel(bc_rect(BC_MARGIN + BC_GAP, y, BC_LABEL_W, BC_ROW), "Key");
    bc_tip(bc_rect(x0, y, (float)key_count * key_w + (float)(key_count - 1) * padding, BC_ROW),
           "Per project: a key of this project, from its key file, travels masked in the game executable (another game made with this tool has another key). Online: a key server gives it to players who own the game (Steam, Epic...) through the key provider; no shipped file holds it. Build key: the key compiled into this tool and the launcher");
    int key_mode = (int)g->project.key_mode;
    GuiToggleGroup(bc_rect(x0, y, key_w, BC_ROW), "Per project;Online;Build key", &key_mode);
    if (key_mode != (int)g->project.key_mode) {
      g->project.key_mode = (BC_KeyMode)key_mode;
      bc_gui_set_modified(g);
    }
    if (online) {
      int cache = g->project.key_cache ? 1 : 0;
      const float cache_x = right - 2 * cache_w - padding;
      bc_tip(bc_rect(cache_x, y, 2 * cache_w + padding, BC_ROW),
             "Always online: the key server is asked at every launch. Offline after the first launch: the key stays on the player's computer (protected for that user) and the game also starts without a connection");
      GuiToggleGroup(bc_rect(cache_x, y, cache_w, BC_ROW), "Always online;Offline after 1st launch", &cache);
      if (cache != (g->project.key_cache ? 1 : 0)) {
        g->project.key_cache = cache != 0;
        bc_gui_set_modified(g);
      }
    }
    y += BC_ROW + BC_GAP;
  }
  if (key_file_row) {
    const char *tip = online ? "Content keys of this game, created on the first export. Keep the file private, back it up and install it on the key server; it must not be inside the game folder. Empty: next to the project file, named after it" : "Key of this project, created on the first export. Keep it private and back it up: updates of the published game need it. It must not be inside the game folder. Empty: next to the project file, named after it";
    if (bc_gui_path_row(y, inner, "Key file", tip, g->project.key_file, g->key_file_text, &g->key_file_edit, &committed)) {
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
    if (bc_gui_text_field(bc_rect(x0, y, provider_w, BC_ROW), "Key provider inside the game folder (for example engine/bc_provider_steam.exe): proves to the key server that the player owns the game", g->provider_text, sizeof(g->provider_text), g->project.key_provider, sizeof(g->project.key_provider), &g->provider_edit)) {
      char entered[BC_PATH_MAX];
      snprintf(entered, sizeof(entered), "%s", g->project.key_provider);
      bc_gui_set_dist_path(g, entered, g->project.key_provider, sizeof(g->project.key_provider), "key provider");
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
    if (bc_gui_text_field(bc_rect(fx, y, right - fx, BC_ROW), "Key server address, given to the provider (https://...). Optional: a provider may know its server", g->url_text, sizeof(g->url_text), g->project.key_url, sizeof(g->project.key_url), &g->url_edit)) {
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
      if (bc_gui_text_field(bc_rect(update_x + update_label_w, y, 90, BC_ROW), "Raise it for each update you publish (then install the key file on the key server again). Exports with the same number reuse its key", g->update_text, sizeof(g->update_text), update_value, sizeof(update_value), &g->update_edit)) {
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

  /* Distribution root summary, or the inplace caveat. */
  const int label_color = GuiGetStyle(LABEL, TEXT_COLOR_NORMAL);
  char info[3 * BC_PATH_MAX];
  if (inplace) {
    GuiSetStyle(LABEL, TEXT_COLOR_NORMAL, BC_RGB(BC_RGB_WARNING));
    snprintf(info, sizeof(info), "Linked libraries (//lib.blend) and getBlendFileList() only find .blend names: prefer mirror for multi-file games");
  }
  else {
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
  }
  GuiLabel(bc_rect(BC_MARGIN + BC_GAP, y, inner - 2 * BC_GAP, BC_ROW), info);
  GuiSetStyle(LABEL, TEXT_COLOR_NORMAL, label_color);
  y += BC_ROW + 3 * BC_GAP;

  /* Files. */
  /* The log gives up lines (down to 3) before the file list gets shorter than its buttons. */
  const float files_min_h = 5 * (BC_ROW + BC_GAP) + 3 * BC_GAP;
  const float spare = H - y - BC_MARGIN - files_min_h - (BC_ROW + 4 * BC_GAP);
  int log_lines = (int)(spare / 24);
  log_lines = log_lines < 3 ? 3 : log_lines > BC_LOG_VISIBLE ? BC_LOG_VISIBLE : log_lines;
  const float bottom_h = BC_ROW + BC_GAP + (float)log_lines * 24 + 3 * BC_GAP;
  const float files_h = H - y - bottom_h - BC_MARGIN;
  bc_group_box(bc_rect(BC_MARGIN, y, inner, files_h), "Files to encrypt (drop .blend files or folders here)");
  const float list_x = BC_MARGIN + BC_GAP;
  const float list_y = y + 2 * BC_GAP;
  const float list_w = inner - BC_BUTTON_W - 4 * BC_GAP;
  const float list_h = files_h - 3 * BC_GAP;
  GuiListViewEx(bc_rect(list_x, list_y, list_w, list_h),
                (const char **)g->items,
                g->item_count,
                &g->list_scroll,
                &g->list_active,
                &g->list_focus);
  const float bx = list_x + list_w + BC_GAP;
  float by = list_y;
  if (GuiButton(bc_rect(bx, by, BC_BUTTON_W, BC_ROW), "Add files...")) {
    char list[65536];
    r = bc_dialog_open_files("Add .blend files", "blend", true, list, sizeof(list));
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
    r = bc_dialog_pick_folder("Add a folder (scanned for .blend files)", path, sizeof(path));
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
    if (bc_is_dir(selected)) {
      bc_gui_log(g, BC_LOG_WARNING, "The main file must be a .blend file, not a folder");
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

  /* Run controls. */
  if (GuiButton(bc_rect(BC_MARGIN, y, 200, BC_ROW), running ? "Cancel" : "Encrypt")) {
    if (running) {
      bc_gui_stop(g, "Cancelled: the file in progress was removed, finished files are kept");
    }
    else {
      bc_gui_start(g);
    }
  }
  float progress = g->progress;
  char percent[16];
  snprintf(percent, sizeof(percent), "%3d%%", (int)(progress * 100.0f + 0.5f));
  GuiProgressBar(bc_rect(BC_MARGIN + 200 + BC_GAP, y, inner - 200 - BC_GAP - 70, BC_ROW),
                 NULL,
                 percent,
                 &progress,
                 0.0f,
                 1.0f);
  y += BC_ROW + BC_GAP;

  /* Log: newest lines at the bottom, colored by level, wrapped to the panel. Rows are gathered from
   * the newest message back, so only the visible messages are measured (the oldest one may keep
   * only its last rows), then drawn from the top. */
  const float log_h = (float)log_lines * 24 + BC_GAP;
  GuiPanel(bc_rect(BC_MARGIN, y, inner, log_h), NULL);
  BeginScissorMode((int)BC_MARGIN, (int)y, (int)inner, (int)log_h);
  BC_Span rows[BC_LOG_VISIBLE];
  Color row_colors[BC_LOG_VISIBLE];
  int row_count = 0;
  for (int i = 0; i < g->log_count && row_count < log_lines; i++) {
    const BC_LogLine *line = &g->log[(g->log_next - 1 - i + BC_LOG_LINES) % BC_LOG_LINES];
    const int rgba = line->level == BC_LOG_ERROR   ? BC_RGB(BC_RGB_ERROR) :
                     line->level == BC_LOG_WARNING ? BC_RGB(BC_RGB_WARNING) :
                                                     GuiGetStyle(DEFAULT, TEXT_COLOR_NORMAL);
    BC_Span spans[BC_LOG_VISIBLE];
    const int n = bc_wrap(line->text, inner - 2 * BC_GAP, text_spacing, spans, BC_LOG_VISIBLE);
    for (int k = n - 1; k >= 0 && row_count < log_lines; k--) {
      rows[row_count] = spans[k];
      row_colors[row_count] = GetColor((unsigned int)rgba);
      row_count++;
    }
  }
  for (int row = 0; row < row_count; row++) {
    const int k = row_count - 1 - row;
    bc_draw_span(&rows[k], BC_MARGIN + BC_GAP, y + BC_GAP / 2 + (float)row * 24, text_spacing, row_colors[k]);
  }
  EndScissorMode();

  bc_gui_draw_tip();

  /* Confirmation dialog on top of everything, over a dimmed editor. */
  if (modal) {
    GuiUnlock();
    DrawRectangleRec(bc_rect(0, 0, W, H), Fade(BLACK, 0.5f));
    const Rectangle box = bc_rect(W / 2 - 260, H / 2 - 90, 520, 180);
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
  InitWindow(1100, 980, "UPBGE BinaryCrypt");
  SetWindowMinSize(900, 860);
  SetExitKey(KEY_NULL);
  SetTargetFPS(60);
  bc_gui_theme_upbge();
  const Font font = bc_gui_load_font();
  GuiSetFont(font);
  GuiSetStyle(LISTVIEW, LIST_ITEMS_HEIGHT, 28);
  GuiSetStyle(LISTVIEW, TEXT_ALIGNMENT, TEXT_ALIGN_LEFT);
  GuiSetStyle(LISTVIEW, TEXT_PADDING, 8);

  if (project_path != NULL) {
    bc_gui_load(&g, project_path);
  }
  bc_gui_rebuild_items(&g);
  bc_gui_update_title(&g);
  bc_gui_log(&g, BC_LOG_INFO, "Drop .blend files or folders on the window, copy the UPBGE runtime into the game folder's engine/, then Encrypt");

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
    if (g.job != NULL) {
      bc_gui_tick_job(&g);
    }
    BeginDrawing();
    ClearBackground(GetColor((unsigned int)GuiGetStyle(DEFAULT, BACKGROUND_COLOR)));
    bc_gui_draw(&g);
    const bool acted = IsMouseButtonPressed(MOUSE_BUTTON_LEFT) || IsMouseButtonReleased(MOUSE_BUTTON_LEFT) ||
                       IsKeyPressed(KEY_ENTER) || IsKeyPressed(KEY_KP_ENTER);
    eager_frames = eager_frames > 1 ? eager_frames - 1 : acted ? 1 : 0;
    /* Decided before EndDrawing: it polls the input of the next frame, blocking when waiting. A
     * running job needs every frame. Idle, the editor costs no CPU. */
    if (g.job != NULL || eager_frames > 0) {
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
