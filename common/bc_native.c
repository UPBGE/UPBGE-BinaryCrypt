/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "bc_native.h"

#include <stdlib.h>
#include <string.h>

#include "bc_platform.h"
#include "blake3.h"

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#endif

/* Deep enough for any real install (Python packages nest about 10 levels), shallow enough that a
 * crafted tree cannot exhaust the stack. */
#define BC_NATIVE_DEPTH_MAX 64
#define BC_NATIVE_READ_SIZE (1 << 20)

bool bc_is_native_code(const char *name)
{
  static const char *const extensions[] = {".exe", ".dll", ".pyd", ".so", ".dylib"};
  for (size_t i = 0; i < sizeof(extensions) / sizeof(extensions[0]); i++) {
    if (bc_path_has_extension(name, extensions[i])) {
      return true;
    }
  }
  /* Versioned shared objects: libfoo.so.1, libpython3.11.so.1.0. */
  for (const char *p = name; (p = strstr(p, ".so.")) != NULL; p++) {
    const char *q = p + 4;
    while ((*q >= '0' && *q <= '9') || *q == '.') {
      q++;
    }
    if (*q == '\0' && q != p + 4) {
      return true;
    }
  }
  return false;
}

bool bc_is_python_source(const char *name)
{
  return bc_path_has_extension(name, ".py") || bc_path_has_extension(name, ".pyw") ||
         bc_path_has_extension(name, ".pth") || bc_path_has_extension(name, ".zip");
}

bool bc_is_python_bytecode(const char *name)
{
  return bc_path_has_extension(name, ".pyc") || bc_path_has_extension(name, ".pyo");
}

typedef struct BC_Entry {
  char *name;
  bool is_dir;
} BC_Entry;

typedef struct BC_EntryList {
  BC_Entry *items;
  int count;
  int capacity;
  bool failed;
} BC_EntryList;

static void bc_collect(void *user, const char *name, const bool is_dir)
{
  BC_EntryList *list = (BC_EntryList *)user;
  if (list->failed) {
    return;
  }
  if (list->count == list->capacity) {
    const int capacity = list->capacity ? 2 * list->capacity : 64;
    BC_Entry *items = (BC_Entry *)realloc(list->items, (size_t)capacity * sizeof(BC_Entry));
    if (items == NULL) {
      list->failed = true;
      return;
    }
    list->items = items;
    list->capacity = capacity;
  }
  const size_t n = strlen(name) + 1;
  char *copy = (char *)malloc(n);
  if (copy == NULL) {
    list->failed = true;
    return;
  }
  memcpy(copy, name, n);
  list->items[list->count].name = copy;
  list->items[list->count].is_dir = is_dir;
  list->count++;
}

static int bc_entry_compare(const void *a, const void *b)
{
  return strcmp(((const BC_Entry *)a)->name, ((const BC_Entry *)b)->name);
}

/** Path equality for the skip list. Windows file names are case-insensitive, and the same file
 * can be named with another case on the command line than in its folder listing. */
static bool bc_same_path(const char *a, const char *b)
{
#ifdef _WIN32
  for (; *a && *b; a++, b++) {
    const char ca = (*a >= 'A' && *a <= 'Z') ? (char)(*a + 32) : *a;
    const char cb = (*b >= 'A' && *b <= 'Z') ? (char)(*b + 32) : *b;
    if (ca != cb) {
      return false;
    }
  }
  return *a == *b;
#else
  return strcmp(a, b) == 0;
#endif
}

typedef struct BC_NativeWalk {
  blake3_hasher digest;
  blake3_hasher file;
  const char *const *skip;
  int skip_count;
  /** NULL: removal only, nothing is hashed. */
  uint8_t *buffer;
  bool python;
  BC_NativeHold *hold;
  BC_NativeScan scan;
  /** bc_native_digest_records: the digest input, kept. */
  bool keep;
  uint8_t *records;
  size_t records_size, records_capacity;
} BC_NativeWalk;

/** Hash a record, and keep it when asked. */
static bool bc_native_record(BC_NativeWalk *w, const char *rel, const uint8_t hash[32])
{
  /* The NUL ends the path, so "a" + hash can never read as a longer path. */
  const size_t n = strlen(rel) + 1;
  blake3_hasher_update(&w->digest, rel, n);
  blake3_hasher_update(&w->digest, hash, 32);
  if (!w->keep) {
    return true;
  }
  if (w->records_size + n + 32 > w->records_capacity) {
    size_t capacity = w->records_capacity ? 2 * w->records_capacity : 64 * 1024;
    while (w->records_size + n + 32 > capacity) {
      capacity *= 2;
    }
    uint8_t *records = (uint8_t *)realloc(w->records, capacity);
    if (records == NULL) {
      return false;
    }
    w->records = records;
    w->records_capacity = capacity;
  }
  memcpy(w->records + w->records_size, rel, n);
  memcpy(w->records + w->records_size + n, hash, 32);
  w->records_size += n + 32;
  return true;
}

#ifdef _WIN32
/** Hash through a handle that denies writing and deleting to everyone, and keep it in the hold:
 * the file cannot change between this check and the player loading it. */
static bool bc_native_file_hash_held(BC_NativeWalk *w, const char *path, uint8_t r_hash[32])
{
  if (w->hold->count == w->hold->capacity) {
    const int capacity = w->hold->capacity ? 2 * w->hold->capacity : 256;
    void **handles = (void **)realloc(w->hold->handles, (size_t)capacity * sizeof(void *));
    if (handles == NULL) {
      return false;
    }
    w->hold->handles = handles;
    w->hold->capacity = capacity;
  }
  wchar_t *wpath = bc_utf16(path);
  HANDLE h = wpath ? CreateFileW(wpath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL) :
                     INVALID_HANDLE_VALUE;
  free(wpath);
  if (h == INVALID_HANDLE_VALUE) {
    return false;
  }
  w->hold->handles[w->hold->count++] = h;
  blake3_hasher_init(&w->file);
  DWORD n = 0;
  bool ok;
  while ((ok = ReadFile(h, w->buffer, BC_NATIVE_READ_SIZE, &n, NULL) != 0) && n > 0) {
    blake3_hasher_update(&w->file, w->buffer, n);
    w->scan.bytes += n;
  }
  blake3_hasher_finalize(&w->file, r_hash, 32);
  return ok;
}
#endif

static bool bc_native_file_hash(BC_NativeWalk *w, const char *path, uint8_t r_hash[32])
{
#ifdef _WIN32
  if (w->hold != NULL) {
    return bc_native_file_hash_held(w, path, r_hash);
  }
#endif
  FILE *f = bc_fopen(path, "rb");
  if (f == NULL) {
    return false;
  }
  blake3_hasher_init(&w->file);
  size_t n;
  while ((n = fread(w->buffer, 1, BC_NATIVE_READ_SIZE, f)) > 0) {
    blake3_hasher_update(&w->file, w->buffer, n);
    w->scan.bytes += n;
  }
  const bool ok = ferror(f) == 0;
  fclose(f);
  blake3_hasher_finalize(&w->file, r_hash, 32);
  return ok;
}

static bool bc_native_walk(BC_NativeWalk *w, const char *dir, const char *rel, const int depth)
{
  if (depth > BC_NATIVE_DEPTH_MAX) {
    return false;
  }
  BC_EntryList list = {NULL, 0, 0, false};
  bool ok = bc_list_dir(dir, bc_collect, &list) && !list.failed;
  if (ok && list.count > 1) {
    qsort(list.items, (size_t)list.count, sizeof(BC_Entry), bc_entry_compare);
  }
  for (int i = 0; ok && i < list.count; i++) {
    const BC_Entry *e = &list.items[i];
    char path[BC_PATH_MAX], sub[BC_PATH_MAX];
    const int n = rel[0] ? snprintf(sub, sizeof(sub), "%s/%s", rel, e->name) :
                           snprintf(sub, sizeof(sub), "%s", e->name);
    ok = n > 0 && (size_t)n < sizeof(sub) && bc_path_join(path, sizeof(path), dir, e->name);
    if (!ok) {
      break;
    }
    if (e->is_dir) {
      ok = bc_native_walk(w, path, sub, depth + 1);
      continue;
    }
    if (w->python && bc_is_python_bytecode(e->name)) {
      /* Removed rather than hashed (see bc_native.h). One that stays is somebody else's. */
      if (bc_remove(path)) {
        w->scan.bytecode_removed++;
      }
      else {
        snprintf(w->scan.locked, sizeof(w->scan.locked), "%s", path);
        ok = false;
      }
      continue;
    }
    if (w->buffer == NULL || !(bc_is_native_code(e->name) || (w->python && bc_is_python_source(e->name)))) {
      continue;
    }
    bool skipped = false;
    for (int s = 0; s < w->skip_count && !skipped; s++) {
      skipped = bc_same_path(sub, w->skip[s]);
    }
    if (skipped) {
      continue;
    }
    uint8_t hash[32];
    ok = bc_native_file_hash(w, path, hash) && bc_native_record(w, sub, hash);
    w->scan.files += ok;
  }
  for (int i = 0; i < list.count; i++) {
    free(list.items[i].name);
  }
  free(list.items);
  return ok;
}

static bool bc_native_digest_walk(const char *root,
                                  const char *const *skip,
                                  const int skip_count,
                                  const bool python,
                                  uint8_t r_digest[BC_NATIVE_DIGEST_SIZE],
                                  BC_NativeScan *r_scan,
                                  BC_NativeHold *hold,
                                  uint8_t **r_records,
                                  size_t *r_records_size)
{
  /* Its scan holds a path and its hashers about 4 KiB: keep it off the stack. Single threaded. */
  static BC_NativeWalk w;
  memset(&w, 0, sizeof(w));
  w.skip = skip;
  w.skip_count = skip_count;
  w.python = python;
  w.hold = hold;
  w.keep = r_records != NULL;
  w.buffer = (uint8_t *)malloc(BC_NATIVE_READ_SIZE);
  if (w.buffer == NULL) {
    return false;
  }
  blake3_hasher_init_derive_key(&w.digest, BC_NATIVE_CONTEXT);
  const bool ok = bc_native_walk(&w, root, "", 0);
  blake3_hasher_finalize(&w.digest, r_digest, BC_NATIVE_DIGEST_SIZE);
  free(w.buffer);
  if (r_scan != NULL) {
    *r_scan = w.scan;
  }
  if (r_records != NULL) {
    *r_records = ok ? w.records : NULL;
    *r_records_size = ok ? w.records_size : 0;
    if (!ok) {
      free(w.records);
    }
  }
  return ok;
}

bool bc_native_digest_held(const char *root,
                           const char *const *skip,
                           const int skip_count,
                           const bool python,
                           uint8_t r_digest[BC_NATIVE_DIGEST_SIZE],
                           BC_NativeScan *r_scan,
                           BC_NativeHold *hold)
{
  return bc_native_digest_walk(root, skip, skip_count, python, r_digest, r_scan, hold, NULL, NULL);
}

bool bc_native_digest_records(const char *root,
                              const char *const *skip,
                              const int skip_count,
                              const bool python,
                              uint8_t r_digest[BC_NATIVE_DIGEST_SIZE],
                              BC_NativeScan *r_scan,
                              uint8_t **r_records,
                              size_t *r_records_size)
{
  return bc_native_digest_walk(root, skip, skip_count, python, r_digest, r_scan, NULL, r_records, r_records_size);
}

void bc_native_records_digest(const uint8_t *records, const size_t size, uint8_t r_digest[BC_NATIVE_DIGEST_SIZE])
{
  blake3_hasher hasher;
  blake3_hasher_init_derive_key(&hasher, BC_NATIVE_CONTEXT);
  blake3_hasher_update(&hasher, records, size);
  blake3_hasher_finalize(&hasher, r_digest, BC_NATIVE_DIGEST_SIZE);
}

typedef struct BC_NativeEntry {
  const char *path;
  const uint8_t *hash;
} BC_NativeEntry;

static int bc_native_entry_compare(const void *a, const void *b)
{
  return strcmp(((const BC_NativeEntry *)a)->path, ((const BC_NativeEntry *)b)->path);
}

/** Records as entries sorted by path (walk order is not path order: "a.b" < "a/b" bytewise, but
 * the walk visits folder "a" before file "a.b"). \return the count, -1 if malformed. */
static int bc_native_entries(const uint8_t *records, const size_t size, BC_NativeEntry **r_entries)
{
  int count = 0;
  for (size_t at = 0; at < size; count++) {
    const uint8_t *nul = (const uint8_t *)memchr(records + at, 0, size - at);
    if (nul == NULL || nul == records + at || (size_t)(nul - records) + 1 + 32 > size) {
      return -1;
    }
    at = (size_t)(nul - records) + 1 + 32;
  }
  *r_entries = (BC_NativeEntry *)malloc(sizeof(BC_NativeEntry) * (size_t)(count ? count : 1));
  if (*r_entries == NULL) {
    return -1;
  }
  size_t at = 0;
  for (int i = 0; i < count; i++) {
    (*r_entries)[i].path = (const char *)records + at;
    at += strlen((const char *)records + at) + 1;
    (*r_entries)[i].hash = records + at;
    at += 32;
  }
  qsort(*r_entries, (size_t)count, sizeof(BC_NativeEntry), bc_native_entry_compare);
  return count;
}

int bc_native_compare(const uint8_t *reference,
                      const size_t reference_size,
                      const uint8_t *current,
                      const size_t current_size,
                      void (*fn)(void *user, const char *change, const char *path),
                      void *user)
{
  BC_NativeEntry *ref = NULL, *now = NULL;
  const int ref_count = bc_native_entries(reference, reference_size, &ref);
  const int now_count = ref_count < 0 ? -1 : bc_native_entries(current, current_size, &now);
  if (ref_count < 0 || now_count < 0) {
    free(ref);
    return -1;
  }
  /* Both sorted: one merge walk. */
  int changes = 0, i = 0, j = 0;
  while (i < ref_count || j < now_count) {
    const int order = i == ref_count ? 1 : j == now_count ? -1 : strcmp(ref[i].path, now[j].path);
    const char *change = order < 0                                    ? "removed" :
                         order > 0                                    ? "added" :
                         memcmp(ref[i].hash, now[j].hash, 32) != 0 ? "changed" :
                                                                        NULL;
    if (change != NULL) {
      fn(user, change, order < 0 ? ref[i].path : now[j].path);
      changes++;
    }
    i += order <= 0;
    j += order >= 0;
  }
  free(ref);
  free(now);
  return changes;
}

bool bc_native_digest(const char *root,
                      const char *const *skip,
                      const int skip_count,
                      const bool python,
                      uint8_t r_digest[BC_NATIVE_DIGEST_SIZE],
                      BC_NativeScan *r_scan)
{
  return bc_native_digest_held(root, skip, skip_count, python, r_digest, r_scan, NULL);
}

void bc_native_release(BC_NativeHold *hold)
{
#ifdef _WIN32
  for (int i = 0; i < hold->count; i++) {
    CloseHandle((HANDLE)hold->handles[i]);
  }
#endif
  free(hold->handles);
  hold->handles = NULL;
  hold->count = 0;
  hold->capacity = 0;
}

bool bc_remove_bytecode(const char *root, BC_NativeScan *r_scan)
{
  static BC_NativeWalk w;
  memset(&w, 0, sizeof(w));
  w.python = true;
  const bool ok = bc_native_walk(&w, root, "", 0);
  if (r_scan != NULL) {
    *r_scan = w.scan;
  }
  return ok;
}
