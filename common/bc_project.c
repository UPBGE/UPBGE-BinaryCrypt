/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "bc_project.h"
#include "bc_runtime.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

void bc_project_init(BC_Project *p)
{
  memset(p, 0, sizeof(*p));
  p->key_mode = BC_KEY_PROJECT;
  p->integrity = BC_INTEGRITY_PYTHON;
}

bool bc_project_key_file(const BC_Project *p, char *out, const size_t size)
{
  if (p->key_file[0] != '\0') {
    return (size_t)snprintf(out, size, "%s", p->key_file) < size;
  }
  if (p->project_file[0] == '\0') {
    return false;
  }
  const size_t n = strlen(p->project_file);
  const size_t stem = bc_path_has_extension(p->project_file, BC_PROJECT_EXTENSION) ? n - strlen(BC_PROJECT_EXTENSION) : n;
  const int written = snprintf(out, size, "%.*s.key", (int)stem, p->project_file);
  return written > 0 && (size_t)written < size;
}

BC_KeyStore bc_project_key_store(const BC_Project *p)
{
  /* The file name without bc_exe_extension(), any case: Windows names are case-insensitive. */
  const char *name = bc_path_basename(p->key_provider);
  size_t n = strlen(name);
  const size_t ext = strlen(bc_exe_extension());
  if (ext > 0 && n > ext && bc_path_has_extension(name, bc_exe_extension())) {
    n -= ext;
  }
  for (int store = BC_STORE_STEAM; store <= BC_STORE_META; store++) {
    const char *provider = bc_key_store_provider((BC_KeyStore)store);
    if (n == strlen(provider)) {
      size_t i = 0;
      while (i < n && tolower((unsigned char)name[i]) == provider[i]) {
        i++;
      }
      if (i == n) {
        return (BC_KeyStore)store;
      }
    }
  }
  return BC_STORE_CUSTOM;
}

const char *bc_key_store_provider(const BC_KeyStore store)
{
  switch (store) {
    case BC_STORE_STEAM:
      return "bc_provider_steam";
    case BC_STORE_EPIC:
      return "bc_provider_epic";
    case BC_STORE_ITCH:
      return "bc_provider_itch";
    case BC_STORE_META:
      return "bc_provider_meta";
    default:
      return NULL;
  }
}

const char *bc_key_store_library(const BC_KeyStore store)
{
  /* The redistributable each provider links (keyserver/providers/CMakeLists.txt). */
#ifdef _WIN32
  return store == BC_STORE_STEAM ? "steam_api64.dll" : store == BC_STORE_EPIC ? "EOSSDK-Win64-Shipping.dll" : NULL;
#elif defined(__APPLE__)
  return store == BC_STORE_STEAM ? "libsteam_api.dylib" : store == BC_STORE_EPIC ? "libEOSSDK-Mac-Shipping.dylib" : NULL;
#else
  return store == BC_STORE_STEAM ? "libsteam_api.so" : store == BC_STORE_EPIC ? "libEOSSDK-Linux-Shipping.so" : NULL;
#endif
}

void bc_project_clear_inputs(BC_Project *p)
{
  for (int i = 0; i < p->input_count; i++) {
    free(p->inputs[i]);
  }
  p->input_count = 0;
}

void bc_project_free(BC_Project *p)
{
  bc_project_clear_inputs(p);
  free(p->inputs);
  bc_project_init(p);
}

bool bc_project_add_input(BC_Project *p, const char *path)
{
  char normalized[BC_PATH_MAX];
  if (strlen(path) >= sizeof(normalized)) {
    return false;
  }
  strcpy(normalized, path);
  bc_path_normalize(normalized);
  for (int i = 0; i < p->input_count; i++) {
    if (strcmp(p->inputs[i], normalized) == 0) {
      return true;
    }
  }
  if (p->input_count == p->input_capacity) {
    const int capacity = p->input_capacity ? p->input_capacity * 2 : 16;
    char **inputs = (char **)realloc(p->inputs, sizeof(char *) * (size_t)capacity);
    if (inputs == NULL) {
      return false;
    }
    p->inputs = inputs;
    p->input_capacity = capacity;
  }
  p->inputs[p->input_count] = (char *)malloc(strlen(normalized) + 1);
  if (p->inputs[p->input_count] == NULL) {
    return false;
  }
  strcpy(p->inputs[p->input_count++], normalized);
  return true;
}

void bc_project_remove_input(BC_Project *p, const int index)
{
  if (index < 0 || index >= p->input_count) {
    return;
  }
  free(p->inputs[index]);
  memmove(p->inputs + index,
          p->inputs + index + 1,
          sizeof(char *) * (size_t)(p->input_count - index - 1));
  p->input_count--;
}

/* Kinds of their own (the first two), and what the OS or Python loads as code. */
static const char *const bc_not_data[] = {".blend", ".py", ".pyw", ".pyc", ".pth", ".pyd", ".dll", ".so", ".dylib", ".exe"};

/** Index of \a ext in bc_not_data, -1 when it may be data. */
static int bc_not_data_index(const char *ext)
{
  const size_t n = strlen(ext);
  for (int i = 0; i < (int)(sizeof(bc_not_data) / sizeof(bc_not_data[0])); i++) {
    /* Same length and same suffix, ignoring case: the same extension. */
    if (n == strlen(bc_not_data[i]) && bc_path_has_extension(ext, bc_not_data[i])) {
      return i;
    }
  }
  return -1;
}

BC_ExtensionRule bc_project_extension_rule(const char *ext)
{
  const int i = bc_not_data_index(ext);
  return i < 0 ? BC_EXTENSION_DATA : i < 2 ? BC_EXTENSION_ALWAYS : BC_EXTENSION_NEVER;
}

int bc_project_data_extensions(const BC_Project *p, char out[][BC_DATA_EXT_SIZE], const int max, char *err, const size_t err_size)
{
  int count = 0;
  const char *c = p->data_extensions;
  while (*c != '\0') {
    if (*c == ' ' || *c == '\t' || *c == ',' || *c == ';') {
      c++;
      continue;
    }
    const char *start = c;
    while (*c != '\0' && *c != ' ' && *c != '\t' && *c != ',' && *c != ';') {
      c++;
    }
    const char *name = start;
    if (name[0] == '*') {
      name++;
    }
    if (name < c && name[0] == '.') {
      name++;
    }
    const size_t n = (size_t)(c - name);
    bool valid = n > 0 && n + 2 <= BC_DATA_EXT_SIZE;
    for (size_t i = 0; valid && i < n; i++) {
      valid = isalnum((unsigned char)name[i]) || name[i] == '_' || name[i] == '-' || name[i] == '.';
    }
    if (!valid) {
      snprintf(err, err_size, "'%.*s' is not a file extension", (int)(c - start), start);
      return -1;
    }
    if (count == max) {
      snprintf(err, err_size, "more than %d data extensions", max);
      return -1;
    }
    char ext[BC_DATA_EXT_SIZE];
    ext[0] = '.';
    memcpy(ext + 1, name, n);
    ext[n + 1] = '\0';
    const int i = bc_not_data_index(ext);
    if (i >= 0) {
      snprintf(err,
               err_size,
               i == 0 ? "'%s' files are always encrypted, as .blend files" :
               i == 1 ? "'%s' files are always encrypted, as Python modules" :
                        "'%s' cannot be a data extension: the player loads it as code",
               bc_not_data[i]);
      return -1;
    }
    memcpy(out[count++], ext, n + 2);
  }
  return count;
}

const char *bc_project_dist_root(const BC_Project *p)
{
  return p->output_dir;
}

const char *bc_project_player(const BC_Project *p)
{
  return p->upbge_dir[0] != '\0' ? BC_RUNTIME_DIR "/" BC_RUNTIME_PLAYER : p->player;
}

/* -------------------------------------------------------------------------------------------- */
/* Text format */

/** Cut a comment: '#' after a space or a tab, outside double quotes. A '#' glued to text is kept,
 * so "C:/Games#1" stays a path. */
static void bc_strip_comment(char *s)
{
  bool quoted = false;
  for (char *c = s; *c != '\0'; c++) {
    if (*c == '"') {
      quoted = !quoted;
    }
    else if (*c == '#' && !quoted && (c == s || c[-1] == ' ' || c[-1] == '\t')) {
      *c = '\0';
      return;
    }
  }
}

static char *bc_trim(char *s)
{
  while (*s == ' ' || *s == '\t') {
    s++;
  }
  char *end = s + strlen(s);
  while (end > s && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r' || end[-1] == '\n')) {
    end--;
  }
  *end = '\0';
  /* Optional double quotes keep leading or trailing spaces in a path. */
  if (end - s >= 2 && s[0] == '"' && end[-1] == '"') {
    end[-1] = '\0';
    s++;
  }
  return s;
}

/** Resolve a project file path against the project folder into an absolute normalized path. */
static bool bc_resolve(char *out, const char *project_dir, const char *value)
{
  return bc_path_join(out, BC_PATH_MAX, project_dir, value);
}

bool bc_project_load(BC_Project *p, const char *file_path, char *err, size_t err_size)
{
  bc_project_free(p);
  FILE *f = bc_fopen(file_path, "rb");
  if (f == NULL) {
    snprintf(err, err_size, "cannot open '%s'", file_path);
    return false;
  }
  char project_dir[BC_PATH_MAX];
  char normalized_file[BC_PATH_MAX];
  if (!bc_path_make_absolute(normalized_file, sizeof(normalized_file), file_path)) {
    fclose(f);
    snprintf(err, err_size, "invalid path '%s'", file_path);
    return false;
  }
  bc_path_dirname(project_dir, sizeof(project_dir), normalized_file);
  snprintf(p->project_file, sizeof(p->project_file), "%s", normalized_file);

  char line[BC_PATH_MAX + 64];
  int line_number = 0;
  int version = 0;
  bool ok = true;
  while (ok && fgets(line, sizeof(line), f) != NULL) {
    line_number++;
    if (strchr(line, '\n') == NULL && !feof(f)) {
      snprintf(err, err_size, "line %d is too long", line_number);
      ok = false;
      break;
    }
    char *text = line;
    if (line_number == 1 && strncmp(text, "\xEF\xBB\xBF", 3) == 0) {
      text += 3; /* UTF-8 byte order mark written by some editors. */
    }
    bc_strip_comment(text);
    text = bc_trim(text);
    if (text[0] == '\0' || text[0] == '#') {
      continue;
    }
    char *equals = strchr(text, '=');
    if (equals == NULL) {
      snprintf(err, err_size, "line %d: expected 'key = value'", line_number);
      ok = false;
      break;
    }
    *equals = '\0';
    const char *key = bc_trim(text);
    const char *value = bc_trim(equals + 1);

    if (strcmp(key, "version") == 0) {
      version = atoi(value);
      if (version > BC_PROJECT_VERSION) {
        /* Its keys and values mean nothing here: refused before reading them. */
        snprintf(err,
                 err_size,
                 "written by a newer bc_tool (project version %d, this one reads up to %d)",
                 version,
                 BC_PROJECT_VERSION);
        ok = false;
        break;
      }
    }
    else if (strcmp(key, "source_root") == 0) {
      ok = bc_resolve(p->source_root, project_dir, value);
    }
    else if (strcmp(key, "output_dir") == 0) {
      ok = bc_resolve(p->output_dir, project_dir, value);
    }
    else if (strcmp(key, "main") == 0) {
      ok = bc_resolve(p->main, project_dir, value);
    }
    else if (strcmp(key, "manifest") == 0) {
      if (strcmp(value, "embedded") == 0) {
        p->manifest_mode = BC_MANIFEST_EMBEDDED;
      }
      else if (strcmp(value, "external") == 0) {
        p->manifest_mode = BC_MANIFEST_EXTERNAL;
      }
      else {
        snprintf(err, err_size, "line %d: manifest must be 'embedded' or 'external'", line_number);
        ok = false;
        break;
      }
    }
    else if (strcmp(key, "icon") == 0) {
      ok = value[0] == '\0' || bc_resolve(p->icon, project_dir, value);
    }
    else if (strcmp(key, "game_version") == 0) {
      ok = (size_t)snprintf(p->game_version, sizeof(p->game_version), "%s", value) < sizeof(p->game_version);
    }
    else if (strcmp(key, "company") == 0) {
      ok = (size_t)snprintf(p->company, sizeof(p->company), "%s", value) < sizeof(p->company);
    }
    else if (strcmp(key, "copyright") == 0) {
      ok = (size_t)snprintf(p->copyright, sizeof(p->copyright), "%s", value) < sizeof(p->copyright);
    }
    else if (strcmp(key, "key") == 0) {
      ok = strcmp(value, "build") == 0 || strcmp(value, "online") == 0 || strcmp(value, "project") == 0;
      p->key_mode = strcmp(value, "online") == 0 ? BC_KEY_ONLINE :
                    strcmp(value, "build") == 0  ? BC_KEY_BUILD :
                                                   BC_KEY_PROJECT;
    }
    else if (strcmp(key, "key_file") == 0) {
      ok = value[0] == '\0' || bc_resolve(p->key_file, project_dir, value);
    }
    else if (strcmp(key, "key_provider") == 0) {
      ok = (size_t)snprintf(p->key_provider, sizeof(p->key_provider), "%s", value) < sizeof(p->key_provider);
      bc_path_normalize(p->key_provider);
    }
    else if (strcmp(key, "key_url") == 0) {
      ok = (size_t)snprintf(p->key_url, sizeof(p->key_url), "%s", value) < sizeof(p->key_url);
    }
    else if (strcmp(key, "key_rotation") == 0) {
      ok = strcmp(value, "off") == 0 || strcmp(value, "per_update") == 0;
      p->key_rotation = strcmp(value, "per_update") == 0;
    }
    else if (strcmp(key, "key_update") == 0) {
      char *end;
      const unsigned long update = strtoul(value, &end, 10);
      ok = value[0] >= '0' && value[0] <= '9' && *end == '\0' && update >= 1 && update <= 0xFFFFFFFFul;
      p->key_update = (uint32_t)update;
    }
    else if (strcmp(key, "integrity") == 0) {
      ok = true;
      if (strcmp(value, "player") == 0) {
        p->integrity = BC_INTEGRITY_PLAYER;
      }
      else if (strcmp(value, "native") == 0) {
        p->integrity = BC_INTEGRITY_NATIVE;
      }
      else if (strcmp(value, "python") == 0) {
        p->integrity = BC_INTEGRITY_PYTHON;
      }
      else {
        snprintf(err, err_size, "line %d: integrity must be 'player', 'native' or 'python'", line_number);
        ok = false;
        break;
      }
    }
    else if (strcmp(key, "key_cache") == 0) {
      ok = strcmp(value, "none") == 0 || strcmp(value, "permanent") == 0;
      p->key_cache = strcmp(value, "permanent") == 0;
    }
    else if (strcmp(key, "game_name") == 0) {
      ok = (size_t)snprintf(p->game_name, sizeof(p->game_name), "%s", value) < sizeof(p->game_name);
    }
    else if (strcmp(key, "upbge_dir") == 0) {
      ok = value[0] == '\0' || bc_resolve(p->upbge_dir, project_dir, value);
    }
    else if (strcmp(key, "player") == 0) {
      ok = (size_t)snprintf(p->player, sizeof(p->player), "%s", value) < sizeof(p->player);
      bc_path_normalize(p->player);
    }
    else if (strcmp(key, "data_extensions") == 0) {
      ok = (size_t)snprintf(p->data_extensions, sizeof(p->data_extensions), "%s", value) < sizeof(p->data_extensions);
      /* Checked here, not first by the export: the editor has no text field to fix the list in. */
      char ext[BC_DATA_EXT_MAX][BC_DATA_EXT_SIZE];
      char why[128];
      if (ok && bc_project_data_extensions(p, ext, BC_DATA_EXT_MAX, why, sizeof(why)) < 0) {
        snprintf(err, err_size, "line %d: data_extensions: %s", line_number, why);
        ok = false;
        break;
      }
    }
    else if (strcmp(key, "input") == 0) {
      char path[BC_PATH_MAX];
      ok = bc_resolve(path, project_dir, value) && bc_project_add_input(p, path);
    }
    else {
      /* Strict: a typo must not silently change what gets encrypted. */
      snprintf(err, err_size, "line %d: unknown key '%s'", line_number, key);
      ok = false;
      break;
    }
    if (!ok) {
      snprintf(err, err_size, "line %d: invalid value", line_number);
    }
  }
  fclose(f);
  if (ok && version < 1) {
    snprintf(err, err_size, "missing or invalid project version");
    ok = false;
  }
  if (!ok) {
    bc_project_free(p);
  }
  return ok;
}

/** Quote values that trimming or comment stripping would change on load. */
static void bc_write_value(FILE *f, const char *key, const char *value)
{
  const size_t n = strlen(value);
  const bool quote = n > 0 && (value[0] == ' ' || value[n - 1] == ' ' || value[0] == '#' ||
                               strstr(value, " #") != NULL || strstr(value, "\t#") != NULL);
  fprintf(f, quote ? "%s = \"%s\"\n" : "%s = %s\n", key, value);
}

/** Path as stored in the file: relative to the project folder when inside it, else absolute. */
static void bc_write_path(FILE *f, const char *key, const char *project_dir, const char *path)
{
  char rel[BC_PATH_MAX];
  const char *value = path;
  if (path[0] != '\0' && bc_path_relative(rel, sizeof(rel), project_dir, path)) {
    value = rel;
  }
  bc_write_value(f, key, value);
}

bool bc_project_save(const BC_Project *p, const char *file_path, char *err, size_t err_size)
{
  char normalized_file[BC_PATH_MAX];
  char project_dir[BC_PATH_MAX];
  if (!bc_path_make_absolute(normalized_file, sizeof(normalized_file), file_path)) {
    snprintf(err, err_size, "invalid path '%s'", file_path);
    return false;
  }
  bc_path_dirname(project_dir, sizeof(project_dir), normalized_file);

  char tmp_path[BC_PATH_MAX + 8];
  snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", normalized_file);
  FILE *f = bc_fopen(tmp_path, "wb");
  if (f == NULL) {
    snprintf(err, err_size, "cannot write '%s'", file_path);
    return false;
  }
  fprintf(f, "# UPBGE-BinaryCrypt project\nversion = %d\n", BC_PROJECT_VERSION);
  bc_write_path(f, "source_root", project_dir, p->source_root);
  if (p->output_dir[0] != '\0') {
    bc_write_path(f, "output_dir", project_dir, p->output_dir);
  }
  if (p->game_name[0] != '\0') {
    bc_write_value(f, "game_name", p->game_name);
  }
  fprintf(f, "manifest = %s\n", p->manifest_mode == BC_MANIFEST_EXTERNAL ? "external" : "embedded");
  if (p->icon[0] != '\0') {
    bc_write_path(f, "icon", project_dir, p->icon);
  }
  if (p->game_version[0] != '\0') {
    bc_write_value(f, "game_version", p->game_version);
  }
  if (p->company[0] != '\0') {
    bc_write_value(f, "company", p->company);
  }
  if (p->copyright[0] != '\0') {
    bc_write_value(f, "copyright", p->copyright);
  }
  fprintf(f, "key = %s\n", p->key_mode == BC_KEY_ONLINE ? "online" : p->key_mode == BC_KEY_BUILD ? "build" : "project");
  if (p->key_file[0] != '\0') {
    bc_write_path(f, "key_file", project_dir, p->key_file);
  }
  if (p->key_mode == BC_KEY_ONLINE || p->key_provider[0] != '\0' || p->key_url[0] != '\0') {
    if (p->key_provider[0] != '\0') {
      bc_write_value(f, "key_provider", p->key_provider);
    }
    if (p->key_url[0] != '\0') {
      bc_write_value(f, "key_url", p->key_url);
    }
    fprintf(f, "key_cache = %s\n", p->key_cache ? "permanent" : "none");
    fprintf(f, "key_rotation = %s\n", p->key_rotation ? "per_update" : "off");
    if (p->key_rotation) {
      fprintf(f, "key_update = %u\n", p->key_update ? p->key_update : 1);
    }
  }
  fprintf(f,
          "integrity = %s\n",
          p->integrity == BC_INTEGRITY_PLAYER ? "player" : p->integrity == BC_INTEGRITY_PYTHON ? "python" : "native");
  if (p->upbge_dir[0] != '\0') {
    bc_write_path(f, "upbge_dir", project_dir, p->upbge_dir);
  }
  bc_write_value(f, "player", p->player);
  if (p->main[0] != '\0') {
    bc_write_path(f, "main", project_dir, p->main);
  }
  if (p->data_extensions[0] != '\0') {
    bc_write_value(f, "data_extensions", p->data_extensions);
  }
  for (int i = 0; i < p->input_count; i++) {
    bc_write_path(f, "input", project_dir, p->inputs[i]);
  }
  if (fclose(f) != 0 || !bc_rename_replace(tmp_path, normalized_file)) {
    bc_remove(tmp_path);
    snprintf(err, err_size, "cannot write '%s'", file_path);
    return false;
  }
  return true;
}
