/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "bc_runtime.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

/* The record is read whole: far above any runtime (about 70 bytes a file). */
#define BC_RUNTIME_RECORD_MAX (64u << 20)
/* Suffix of a copy being written, renamed to its name once complete. */
#define BC_RUNTIME_TMP ".bc_tmp"

static void bc_runtime_error(char *err, const size_t err_size, const char *format, ...)
{
  va_list args;
  va_start(args, format);
  vsnprintf(err, err_size, format, args);
  va_end(args);
}

/* -------------------------------------------------------------------------------------------- */
/* What is copied */

/** File names compare like the file system does: case-insensitive on Windows. */
static bool bc_name_equal(const char *a, const char *b)
{
#ifdef _WIN32
  for (; *a != '\0' && *b != '\0'; a++, b++) {
    if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) {
      return false;
    }
  }
  return *a == *b;
#else
  return strcmp(a, b) == 0;
#endif
}

#ifndef __APPLE__
/** "5.4": the version folder (scripts, datafiles, the bundled Python). */
static bool bc_is_version_name(const char *name)
{
  const char *c = name;
  if (!isdigit((unsigned char)*c)) {
    return false;
  }
  while (isdigit((unsigned char)*c)) {
    c++;
  }
  if (*c++ != '.' || !isdigit((unsigned char)*c)) {
    return false;
  }
  while (isdigit((unsigned char)*c)) {
    c++;
  }
  return *c == '\0';
}
#endif

/** Entries of the UPBGE folder itself that the player needs. Everything else there (the editor,
 * build tools, .cmd files, oculus.json, .pdb, readme) stays out. */
static bool bc_runtime_top_allowed(const char *name, const bool is_dir)
{
#if defined(_WIN32)
  if (is_dir) {
    return bc_is_version_name(name) || bc_name_equal(name, "blender.crt") ||
           bc_name_equal(name, "blender.shared") || bc_name_equal(name, "license");
  }
  return bc_name_equal(name, BC_RUNTIME_PLAYER) || bc_name_equal(name, "copyright.txt") ||
         bc_path_has_extension(name, ".dll");
#elif defined(__APPLE__)
  /* Self-contained: its own version folder, libraries and text. */
  return is_dir && bc_name_equal(name, "Blenderplayer.app");
#else
  if (is_dir) {
    return bc_is_version_name(name) || bc_name_equal(name, "lib") || bc_name_equal(name, "license");
  }
  return bc_name_equal(name, BC_RUNTIME_PLAYER) || bc_name_equal(name, "copyright.txt");
#endif
}

/** Inside the copied folders: what never ships. Bytecode would be removed from the game folder
 * by the Python integrity level and copied again by every export; debug symbols help nobody but a
 * reverse engineer. */
static bool bc_runtime_never(const char *name, const bool is_dir)
{
  if (is_dir) {
    return strcmp(name, "__pycache__") == 0;
  }
  return bc_path_has_extension(name, ".pyc") || bc_path_has_extension(name, ".pyo") ||
         bc_path_has_extension(name, ".pdb") || strcmp(name, ".DS_Store") == 0;
}

/** A recorded path may only name a file below engine/: the record decides what gets removed. */
static bool bc_runtime_path_is_safe(const char *path)
{
#ifdef _WIN32
  if (strchr(path, ':') != NULL || strchr(path, '\\') != NULL) {
    return false;
  }
#endif
  if (path[0] == '\0' || path[0] == '/') {
    return false;
  }
  for (const char *segment = path; segment != NULL;) {
    const char *slash = strchr(segment, '/');
    const size_t n = slash ? (size_t)(slash - segment) : strlen(segment);
    if (n == 0 || (n == 1 && segment[0] == '.') || (n == 2 && segment[0] == '.' && segment[1] == '.')) {
      return false;
    }
    segment = slash ? slash + 1 : NULL;
  }
  return true;
}

/* -------------------------------------------------------------------------------------------- */
/* Listing */

typedef struct BC_RuntimeScan {
  BC_RuntimeCopy *c;
  /** Absolute path of the entry being visited; its path below the UPBGE folder starts at #rel.
   * One buffer for the whole walk: a level appends its name and cuts it off again. */
  char path[BC_PATH_MAX];
  size_t len, top_len, rel;
  bool ok;
  char *err;
  size_t err_size;
} BC_RuntimeScan;

static int bc_runtime_compare(const void *a, const void *b)
{
  return strcmp(((const BC_RuntimeFile *)a)->path, ((const BC_RuntimeFile *)b)->path);
}

/** Append a file. Its path goes into the name arena; #path holds the offset until the listing ends
 * (the arena may still move), see bc_runtime_begin. */
static bool bc_runtime_add(BC_RuntimeCopy *c, const char *rel, const uint64_t size, const uint64_t mtime)
{
  const size_t n = strlen(rel) + 1;
  if (c->names_size + n > c->names_capacity) {
    size_t capacity = c->names_capacity ? c->names_capacity : 64 * 1024;
    while (c->names_size + n > capacity) {
      capacity *= 2;
    }
    char *names = (char *)realloc(c->names, capacity);
    if (names == NULL) {
      return false;
    }
    c->names = names;
    c->names_capacity = capacity;
  }
  if (c->file_count == c->file_capacity) {
    const int capacity = c->file_capacity ? c->file_capacity * 2 : 1024;
    BC_RuntimeFile *files = (BC_RuntimeFile *)realloc(c->files, sizeof(BC_RuntimeFile) * (size_t)capacity);
    if (files == NULL) {
      return false;
    }
    c->files = files;
    c->file_capacity = capacity;
  }
  BC_RuntimeFile *f = &c->files[c->file_count++];
  memset(f, 0, sizeof(*f));
  f->path = (const char *)(uintptr_t)c->names_size;
  f->size = size;
  f->mtime = mtime;
  memcpy(c->names + c->names_size, rel, n);
  c->names_size += n;
  return true;
}

static void bc_runtime_scan_entry(void *user, const char *name, bool is_dir);

static void bc_runtime_scan_dir(BC_RuntimeScan *s)
{
  if (!bc_list_dir(s->path, bc_runtime_scan_entry, s) && s->ok) {
    bc_runtime_error(s->err, s->err_size, "Cannot list the folder '%s'", s->path);
    s->ok = false;
  }
}

static void bc_runtime_scan_entry(void *user, const char *name, const bool is_dir)
{
  BC_RuntimeScan *s = (BC_RuntimeScan *)user;
  if (!s->ok) {
    return;
  }
  const bool top = s->len == s->top_len;
  if (top ? !bc_runtime_top_allowed(name, is_dir) : bc_runtime_never(name, is_dir)) {
    return;
  }
  const size_t len = s->len;
  const size_t n = strlen(name);
  const size_t sep = s->path[len - 1] == '/' ? 0 : 1; /* A drive or file system root. */
  if (len + sep + n >= sizeof(s->path) || strchr(name, '\n') != NULL || strchr(name, '\r') != NULL) {
    bc_runtime_error(s->err, s->err_size, "Cannot copy '%s/%s': the path is too long or holds a line break", s->path, name);
    s->ok = false;
    return;
  }
  if (sep) {
    s->path[len] = '/';
  }
  memcpy(s->path + len + sep, name, n + 1);
  s->len = len + sep + n;
  if (is_dir) {
    bc_runtime_scan_dir(s);
  }
  else {
    uint64_t size, mtime;
    if (bc_file_stat(s->path, &size, &mtime)) {
      if (!bc_runtime_add(s->c, s->path + s->rel, size, mtime)) {
        bc_runtime_error(s->err, s->err_size, "Out of memory while listing '%s'", s->c->from);
        s->ok = false;
      }
    }
    else if (bc_is_dir(s->path)) {
      s->c->skipped++; /* A link to a folder: never followed, so no walk can loop. */
    }
    else {
      bc_runtime_error(s->err, s->err_size, "Cannot read '%s'", s->path);
      s->ok = false;
    }
  }
  s->len = len;
  s->path[len] = '\0';
}

/* -------------------------------------------------------------------------------------------- */
/* Record */

static bool bc_record_number(char **p, uint64_t *r_value)
{
  uint64_t value = 0;
  char *c = *p;
  if (*c < '0' || *c > '9') {
    return false;
  }
  while (*c >= '0' && *c <= '9') {
    const uint64_t digit = (uint64_t)(*c++ - '0');
    if (value > (UINT64_MAX - digit) / 10) {
      return false;
    }
    value = value * 10 + digit;
  }
  if (*c != ' ') {
    return false;
  }
  *r_value = value;
  *p = c + 1;
  return true;
}

/** Read the record of engine/ into \a r_rec (sorted, paths inside c->record). No record: none. A
 * record that cannot be read in full counts as none, with record_bad set: copying everything again
 * costs time once, removing a file by a wrong line could cost the game. */
static bool bc_runtime_load_record(BC_RuntimeCopy *c, BC_RuntimeFile **r_rec, int *r_count, char *err, const size_t err_size)
{
  *r_rec = NULL;
  *r_count = 0;
  char path[BC_PATH_MAX];
  uint64_t size, mtime;
  if (!bc_path_join(path, sizeof(path), c->to, BC_RUNTIME_RECORD) || !bc_file_stat(path, &size, &mtime)) {
    return true;
  }
  FILE *f = size <= BC_RUNTIME_RECORD_MAX ? bc_fopen(path, "rb") : NULL;
  if (f == NULL) {
    c->record_bad = true;
    return true;
  }
  if ((c->record = (char *)malloc((size_t)size + 1)) == NULL) {
    fclose(f);
    bc_runtime_error(err, err_size, "Out of memory while reading '%s'", path);
    return false;
  }
  const bool read = fread(c->record, 1, (size_t)size, f) == size;
  fclose(f);
  if (!read) {
    c->record_bad = true;
    return true;
  }
  c->record[size] = '\0';
  int lines = 1;
  for (const char *p = c->record; *p != '\0'; p++) {
    lines += *p == '\n';
  }
  BC_RuntimeFile *rec = (BC_RuntimeFile *)malloc(sizeof(BC_RuntimeFile) * (size_t)lines);
  if (rec == NULL) {
    bc_runtime_error(err, err_size, "Out of memory while reading '%s'", path);
    return false;
  }
  int count = 0;
  bool ok = true;
  for (char *line = c->record; ok && line != NULL;) {
    char *end = strchr(line, '\n');
    char *next = end ? end + 1 : NULL;
    if (end == NULL) {
      end = line + strlen(line);
    }
    if (end > line && end[-1] == '\r') {
      end--;
    }
    *end = '\0';
    if (line[0] != '\0' && line[0] != '#') {
      BC_RuntimeFile *r = &rec[count];
      char *p = line;
      ok = bc_record_number(&p, &r->size) && bc_record_number(&p, &r->mtime) && bc_runtime_path_is_safe(p);
      r->path = p;
      r->copy = false;
      count += ok;
    }
    line = next;
  }
  if (ok && count > 1) {
    qsort(rec, (size_t)count, sizeof(BC_RuntimeFile), bc_runtime_compare);
    for (int i = 1; ok && i < count; i++) {
      ok = strcmp(rec[i - 1].path, rec[i].path) != 0;
    }
  }
  if (!ok) {
    free(rec);
    c->record_bad = true;
    return true;
  }
  *r_rec = rec;
  *r_count = count;
  return true;
}

/* -------------------------------------------------------------------------------------------- */
/* Copy */

static bool bc_runtime_plan(BC_RuntimeCopy *c, char *err, size_t err_size);

bool bc_runtime_begin(BC_RuntimeCopy *c, const char *upbge_dir, const char *engine_dir, char *err, const size_t err_size)
{
  memset(c, 0, sizeof(*c));
  char player[BC_PATH_MAX];
  if ((size_t)snprintf(c->from, sizeof(c->from), "%s", upbge_dir) >= sizeof(c->from) ||
      (size_t)snprintf(c->to, sizeof(c->to), "%s", engine_dir) >= sizeof(c->to) || c->from[0] == '\0')
  {
    bc_runtime_error(err, err_size, "Invalid UPBGE folder '%s'", upbge_dir);
    return false;
  }
  if (!bc_is_dir(c->from)) {
    bc_runtime_error(err, err_size, "The UPBGE folder '%s' does not exist", c->from);
    return false;
  }
  if (!bc_path_join(player, sizeof(player), c->from, BC_RUNTIME_PLAYER) || !bc_is_file(player)) {
    bc_runtime_error(err,
                     err_size,
                     "The UPBGE folder '%s' has no %s: choose the folder of a UPBGE release, or the "
                     "bin folder of a build made with the player",
                     c->from,
                     BC_RUNTIME_PLAYER);
    return false;
  }

  /* The scan context is large (one path buffer): off the stack. */
  BC_RuntimeScan *s = (BC_RuntimeScan *)calloc(1, sizeof(BC_RuntimeScan));
  if (s == NULL) {
    bc_runtime_error(err, err_size, "Out of memory");
    return false;
  }
  s->c = c;
  s->ok = true;
  s->err = err;
  s->err_size = err_size;
  snprintf(s->path, sizeof(s->path), "%s", c->from);
  s->len = s->top_len = strlen(s->path);
  s->rel = s->len + (s->path[s->len - 1] == '/' ? 0 : 1);
  bc_runtime_scan_dir(s);
  const bool listed = s->ok;
  free(s);
  if (!listed) {
    bc_runtime_end(c);
    return false;
  }
  return bc_runtime_plan(c, err, err_size);
}

bool bc_runtime_begin_files(BC_RuntimeCopy *c,
                            const char *from_dir,
                            const char *const *names,
                            const int name_count,
                            const char *to_dir,
                            char *err,
                            const size_t err_size)
{
  memset(c, 0, sizeof(*c));
  if ((size_t)snprintf(c->from, sizeof(c->from), "%s", from_dir) >= sizeof(c->from) ||
      (size_t)snprintf(c->to, sizeof(c->to), "%s", to_dir) >= sizeof(c->to) || c->from[0] == '\0')
  {
    bc_runtime_error(err, err_size, "Invalid folder '%s'", from_dir);
    return false;
  }
  char path[BC_PATH_MAX];
  for (int i = 0; i < name_count; i++) {
    uint64_t size, mtime;
    /* One name per record line, directly in to_dir. */
    if (names[i][0] == '\0' || strpbrk(names[i], "/\\\n\r") != NULL || !bc_path_join(path, sizeof(path), c->from, names[i]) ||
        !bc_file_stat(path, &size, &mtime))
    {
      bc_runtime_error(err, err_size, "Cannot read '%s/%s'", c->from, names[i]);
      bc_runtime_end(c);
      return false;
    }
    if (!bc_runtime_add(c, names[i], size, mtime)) {
      bc_runtime_error(err, err_size, "Out of memory");
      bc_runtime_end(c);
      return false;
    }
  }
  return bc_runtime_plan(c, err, err_size);
}

/** Both listings done: compare c->files with the record of c->to, which decides what is copied and
 * what removed. Frees \a c on failure. */
static bool bc_runtime_plan(BC_RuntimeCopy *c, char *err, const size_t err_size)
{
  /* The arena is final: offsets become pointers. */
  for (int i = 0; i < c->file_count; i++) {
    c->files[i].path = c->names + (uintptr_t)c->files[i].path;
  }
  if (c->file_count > 1) {
    qsort(c->files, (size_t)c->file_count, sizeof(BC_RuntimeFile), bc_runtime_compare);
  }

  BC_RuntimeFile *rec;
  int rec_count;
  if (!bc_runtime_load_record(c, &rec, &rec_count, err, err_size)) {
    bc_runtime_end(c);
    return false;
  }
  if (rec_count > 0 && (c->stale = (const char **)malloc(sizeof(char *) * (size_t)rec_count)) == NULL) {
    free(rec);
    bc_runtime_end(c);
    bc_runtime_error(err, err_size, "Out of memory");
    return false;
  }
  /* Both sorted: one merge walk tells new, unchanged and gone files apart. */
  char dst[BC_PATH_MAX];
  int i = 0, j = 0;
  while (i < c->file_count || j < rec_count) {
    const int order = i == c->file_count ? 1 : j == rec_count ? -1 : strcmp(c->files[i].path, rec[j].path);
    if (order > 0) {
      c->stale[c->stale_count++] = rec[j++].path;
      continue;
    }
    BC_RuntimeFile *f = &c->files[i++];
    f->copy = true;
    if (order == 0) {
      const BC_RuntimeFile *r = &rec[j++];
      f->copy = r->size != f->size || r->mtime != f->mtime || !bc_path_join(dst, sizeof(dst), c->to, f->path) ||
                !bc_is_file(dst);
    }
    if (f->copy) {
      c->copy_count++;
      c->copy_bytes += f->size;
    }
  }
  free(rec);
  c->dirty = c->copy_count > 0 || c->stale_count > 0;
  return true;
}

/** Copy of \a path below engine/, and the temporary name it is written under. */
static bool bc_runtime_dst(const BC_RuntimeCopy *c, const char *path, char *dst, char *tmp)
{
  return bc_path_join(dst, BC_PATH_MAX, c->to, path) &&
         (size_t)snprintf(tmp, BC_PATH_MAX, "%s" BC_RUNTIME_TMP, dst) < BC_PATH_MAX;
}

/** Stop the file being copied: its temporary copy goes, the old copy stays as it was. */
static void bc_runtime_close(BC_RuntimeCopy *c)
{
  if (c->in != NULL) {
    fclose(c->in);
    c->in = NULL;
  }
  if (c->out != NULL) {
    fclose(c->out);
    c->out = NULL;
    char dst[BC_PATH_MAX], tmp[BC_PATH_MAX];
    if (bc_runtime_dst(c, c->files[c->next].path, dst, tmp)) {
      bc_remove(tmp);
    }
  }
}

static int bc_runtime_fail(BC_RuntimeCopy *c, char *err, const size_t err_size, const char *format, const char *path)
{
  bc_runtime_close(c);
  bc_runtime_error(err, err_size, format, path);
  return -1;
}

/** Remove a recorded file the UPBGE folder no longer has, then the folders it leaves empty (an old
 * version folder goes file by file); the first folder that is not empty stops the walk. */
static int bc_runtime_remove_stale(BC_RuntimeCopy *c, char *err, const size_t err_size)
{
  char path[BC_PATH_MAX], dir[BC_PATH_MAX];
  if (!bc_path_join(path, sizeof(path), c->to, c->stale[c->stale_next++])) {
    return 1;
  }
  if (!bc_remove(path)) {
    if (bc_is_file(path)) {
      bc_runtime_error(err, err_size, "Cannot remove the old copy '%s': close the game if it is running", path);
      return -1;
    }
    return 1; /* Already gone. */
  }
  c->removed++;
  bc_path_dirname(dir, sizeof(dir), path);
  while (strcmp(dir, c->to) != 0 && bc_path_is_inside(c->to, dir) && bc_remove_dir(dir)) {
    snprintf(path, sizeof(path), "%s", dir);
    bc_path_dirname(dir, sizeof(dir), path);
  }
  return 1;
}

int bc_runtime_step(BC_RuntimeCopy *c, uint8_t *buffer, const size_t buffer_size, char *err, const size_t err_size)
{
  /* Removals first: a file of the old runtime may share its name, in another case, with one of
   * the new runtime on a case-insensitive file system. */
  if (c->stale_next < c->stale_count) {
    return bc_runtime_remove_stale(c, err, err_size);
  }
  char src[BC_PATH_MAX], dst[BC_PATH_MAX], tmp[BC_PATH_MAX], dir[BC_PATH_MAX];
  if (c->in == NULL) {
    while (c->next < c->file_count && !c->files[c->next].copy) {
      c->next++;
    }
    if (c->next == c->file_count) {
      return 0;
    }
    const BC_RuntimeFile *f = &c->files[c->next];
    if (!bc_path_join(src, sizeof(src), c->from, f->path) || !bc_runtime_dst(c, f->path, dst, tmp)) {
      bc_runtime_error(err, err_size, "The path of '%s' is too long", f->path);
      return -1;
    }
    bc_path_dirname(dir, sizeof(dir), dst);
    if (strcmp(dir, c->made) != 0) {
      if (!bc_mkdir_p(dir)) {
        bc_runtime_error(err, err_size, "Cannot create the folder '%s'", dir);
        return -1;
      }
      snprintf(c->made, sizeof(c->made), "%s", dir);
    }
    if ((c->in = bc_fopen(src, "rb")) == NULL) {
      bc_runtime_error(err, err_size, "Cannot read '%s'", src);
      return -1;
    }
    if ((c->out = bc_fopen(tmp, "wb")) == NULL) {
      return bc_runtime_fail(c, err, err_size, "Cannot write '%s'", tmp);
    }
    return 1;
  }

  BC_RuntimeFile *f = &c->files[c->next];
  if (!bc_path_join(src, sizeof(src), c->from, f->path) || !bc_runtime_dst(c, f->path, dst, tmp)) {
    return bc_runtime_fail(c, err, err_size, "The path of '%s' is too long", f->path);
  }
  const size_t n = fread(buffer, 1, buffer_size, c->in);
  if (n > 0 && fwrite(buffer, 1, n, c->out) != n) {
    return bc_runtime_fail(c, err, err_size, "Cannot write '%s': is the disk full?", tmp);
  }
  c->done_bytes += n;
  if (n == buffer_size) {
    return 1;
  }
  const bool read_error = ferror(c->in) != 0;
  fclose(c->in);
  c->in = NULL;
  const bool write_error = fclose(c->out) != 0;
  c->out = NULL;
  if (read_error || write_error || !bc_copy_permissions(src, tmp)) {
    bc_remove(tmp);
    bc_runtime_error(err, err_size, "Cannot copy '%s' to '%s'", src, tmp);
    return -1;
  }
  /* The record keeps the listing's source stat: a source changed during the copy differs from it
   * at the next export and is copied again. */
  if (!bc_rename_replace(tmp, dst)) {
    bc_remove(tmp);
    bc_runtime_error(err, err_size, "Cannot replace '%s': close the game if it is running", dst);
    return -1;
  }
  c->copied++;
  c->next++;
  return 1;
}

const char *bc_runtime_current(const BC_RuntimeCopy *c)
{
  return c->in != NULL ? c->files[c->next].path : NULL;
}

bool bc_runtime_has(const BC_RuntimeCopy *c, const char *path)
{
  const BC_RuntimeFile probe = {path, 0, 0, false};
  return c->file_count > 0 &&
         bsearch(&probe, c->files, (size_t)c->file_count, sizeof(BC_RuntimeFile), bc_runtime_compare) != NULL;
}

bool bc_runtime_save(BC_RuntimeCopy *c, char *err, const size_t err_size)
{
  if (!c->dirty) {
    return true;
  }
  char path[BC_PATH_MAX], tmp[BC_PATH_MAX + 8];
  if (!bc_path_join(path, sizeof(path), c->to, BC_RUNTIME_RECORD) || !bc_mkdir_p(c->to)) {
    bc_runtime_error(err, err_size, "Cannot write the runtime record in '%s'", c->to);
    return false;
  }
  snprintf(tmp, sizeof(tmp), "%s.tmp", path);
  FILE *f = bc_fopen(tmp, "wb");
  if (f == NULL) {
    bc_runtime_error(err, err_size, "Cannot write '%s'", tmp);
    return false;
  }
  fputs("# Copied here by bc_tool (UPBGE-BinaryCrypt) from the UPBGE folder or the key provider's.\n"
        "# Per file: size and time of the source, path. A listed file the source no longer gives\n"
        "# is removed by the next export; files not listed are never touched.\n",
        f);
  for (int i = 0; i < c->file_count; i++) {
    const BC_RuntimeFile *r = &c->files[i];
    fprintf(f, "%llu %llu %s\n", (unsigned long long)r->size, (unsigned long long)r->mtime, r->path);
  }
  if (fclose(f) != 0 || !bc_rename_replace(tmp, path)) {
    bc_remove(tmp);
    bc_runtime_error(err, err_size, "Cannot write '%s'", path);
    return false;
  }
  c->dirty = false;
  return true;
}

void bc_runtime_end(BC_RuntimeCopy *c)
{
  bc_runtime_close(c);
  free(c->files);
  free(c->names);
  free((void *)c->stale);
  free(c->record);
  memset(c, 0, sizeof(*c));
}
