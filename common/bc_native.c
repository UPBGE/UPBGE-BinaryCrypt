/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "bc_native.h"

#include <stdlib.h>
#include <string.h>

#include "bc_platform.h"
#include "monocypher.h"

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
  crypto_blake2b_ctx ctx;
  const char *const *skip;
  int skip_count;
  /** NULL: removal only, nothing is hashed. */
  uint8_t *buffer;
  bool python;
  BC_NativeScan scan;
} BC_NativeWalk;

static bool bc_native_file_hash(BC_NativeWalk *w, const char *path, uint8_t r_hash[32])
{
  FILE *f = bc_fopen(path, "rb");
  if (f == NULL) {
    return false;
  }
  crypto_blake2b_ctx ctx;
  crypto_blake2b_init(&ctx, 32);
  size_t n;
  while ((n = fread(w->buffer, 1, BC_NATIVE_READ_SIZE, f)) > 0) {
    crypto_blake2b_update(&ctx, w->buffer, n);
    w->scan.bytes += n;
  }
  const bool ok = ferror(f) == 0;
  fclose(f);
  crypto_blake2b_final(&ctx, r_hash);
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
    ok = bc_native_file_hash(w, path, hash);
    if (ok) {
      /* The NUL ends the path, so "a" + hash can never read as a longer path. */
      crypto_blake2b_update(&w->ctx, (const uint8_t *)sub, strlen(sub) + 1);
      crypto_blake2b_update(&w->ctx, hash, sizeof(hash));
      w->scan.files++;
    }
  }
  for (int i = 0; i < list.count; i++) {
    free(list.items[i].name);
  }
  free(list.items);
  return ok;
}

bool bc_native_digest(const char *root,
                      const char *const *skip,
                      const int skip_count,
                      const bool python,
                      uint8_t r_digest[BC_NATIVE_DIGEST_SIZE],
                      BC_NativeScan *r_scan)
{
  static BC_NativeWalk w; /* Its scan holds a path: keep it off the stack. Single threaded. */
  memset(&w, 0, sizeof(w));
  w.skip = skip;
  w.skip_count = skip_count;
  w.python = python;
  w.buffer = (uint8_t *)malloc(BC_NATIVE_READ_SIZE);
  if (w.buffer == NULL) {
    return false;
  }
  crypto_blake2b_init(&w.ctx, BC_NATIVE_DIGEST_SIZE);
  crypto_blake2b_update(&w.ctx, (const uint8_t *)BC_NATIVE_CONTEXT, sizeof(BC_NATIVE_CONTEXT) - 1);
  const bool ok = bc_native_walk(&w, root, "", 0);
  crypto_blake2b_final(&w.ctx, r_digest);
  free(w.buffer);
  if (r_scan != NULL) {
    *r_scan = w.scan;
  }
  return ok;
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
