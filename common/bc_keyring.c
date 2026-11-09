/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "bc_keyring.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bc_key.h"
#include "bc_platform.h"

#ifndef _WIN32
#  include <sys/stat.h>
#endif

#define BC_KEYRING_LINE_MAX (BC_PATH_MAX + 128)

void bc_keyring_init(BC_KeyRing *r)
{
  memset(r, 0, sizeof(*r));
}

void bc_keyring_clear_records(BC_KeyRing *r)
{
  for (int i = 0; i < r->record_count; i++) {
    free(r->records[i].path);
  }
  r->record_count = 0;
}

void bc_keyring_wipe_keys(BC_KeyRing *r)
{
  crypto_wipe(r->keys, sizeof(r->keys));
}

void bc_keyring_free(BC_KeyRing *r)
{
  bc_keyring_clear_records(r);
  free(r->records);
  crypto_wipe(r->keys, sizeof(r->keys));
  bc_keyring_init(r);
}

int bc_keyring_find(const BC_KeyRing *r, const uint32_t update)
{
  for (int i = 0; i < r->key_count; i++) {
    if (r->updates[i] == update) {
      return i;
    }
  }
  return -1;
}

int bc_keyring_find_id(const BC_KeyRing *r, const uint8_t key_id[BC_KEY_ID_SIZE])
{
  for (int i = 0; i < r->key_count; i++) {
    uint8_t id[BC_KEY_ID_SIZE];
    bc_key_id(r->keys[i], id);
    if (memcmp(id, key_id, BC_KEY_ID_SIZE) == 0) {
      return i;
    }
  }
  return -1;
}

uint32_t bc_keyring_newest(const BC_KeyRing *r)
{
  return r->key_count > 0 ? r->updates[r->key_count - 1] : 0;
}

/** Insert keeping the update numbers sorted. */
static bool bc_keyring_insert(BC_KeyRing *r, const uint32_t update, const uint8_t key[BC_KEY_SIZE])
{
  if (r->key_count == BC_KEYS_MAX || update == 0 || bc_keyring_find(r, update) >= 0) {
    return false;
  }
  int i = r->key_count;
  while (i > 0 && r->updates[i - 1] > update) {
    r->updates[i] = r->updates[i - 1];
    memcpy(r->keys[i], r->keys[i - 1], BC_KEY_SIZE);
    i--;
  }
  r->updates[i] = update;
  memcpy(r->keys[i], key, BC_KEY_SIZE);
  r->key_count++;
  return true;
}

bool bc_keyring_add(BC_KeyRing *r, const uint32_t update)
{
  uint8_t key[BC_KEY_SIZE];
  const bool ok = bc_random_bytes(key, BC_KEY_SIZE) && bc_keyring_insert(r, update, key);
  crypto_wipe(key, sizeof(key));
  return ok;
}

/** First record whose path is not below \a path: where it is, or where it goes. */
static int bc_keyring_lower_bound(const BC_KeyRing *r, const char *path)
{
  /* Records arrive in path order (an export, a saved file): try the end before searching. */
  if (r->record_count == 0 || strcmp(r->records[r->record_count - 1].path, path) < 0) {
    return r->record_count;
  }
  int lo = 0, hi = r->record_count;
  while (lo < hi) {
    const int mid = lo + (hi - lo) / 2;
    if (strcmp(r->records[mid].path, path) < 0) {
      lo = mid + 1;
    }
    else {
      hi = mid;
    }
  }
  return lo;
}

const BC_KeyRecord *bc_keyring_record(const BC_KeyRing *r, const char *path)
{
  const int i = bc_keyring_lower_bound(r, path);
  return i < r->record_count && strcmp(r->records[i].path, path) == 0 ? &r->records[i] : NULL;
}

bool bc_keyring_set_record(BC_KeyRing *r,
                           const char *path,
                           const uint8_t hash[BC_FILE_HASH_SIZE],
                           const uint32_t update,
                           const uint64_t size,
                           const uint64_t mtime)
{
  const int i = bc_keyring_lower_bound(r, path);
  BC_KeyRecord *record = i < r->record_count && strcmp(r->records[i].path, path) == 0 ? &r->records[i] : NULL;
  if (record == NULL) {
    if (r->record_count == r->record_capacity) {
      const int capacity = r->record_capacity ? 2 * r->record_capacity : 64;
      BC_KeyRecord *records = (BC_KeyRecord *)realloc(r->records, sizeof(BC_KeyRecord) * (size_t)capacity);
      if (records == NULL) {
        return false;
      }
      r->records = records;
      r->record_capacity = capacity;
    }
    char *copy = (char *)malloc(strlen(path) + 1);
    if (copy == NULL) {
      return false;
    }
    strcpy(copy, path);
    /* Appending in path order moves nothing. */
    memmove(&r->records[i + 1], &r->records[i], sizeof(BC_KeyRecord) * (size_t)(r->record_count - i));
    record = &r->records[i];
    record->path = copy;
    r->record_count++;
  }
  memcpy(record->hash, hash, BC_FILE_HASH_SIZE);
  record->update = update;
  record->size = size;
  record->mtime = mtime;
  return true;
}

/* -------------------------------------------------------------------------------------------- */

static bool bc_hex32(const char *text, uint8_t out[32])
{
  char digits[BC_KEY_HEX_SIZE + 1];
  if (strlen(text) < BC_KEY_HEX_SIZE) {
    return false;
  }
  memcpy(digits, text, BC_KEY_HEX_SIZE);
  digits[BC_KEY_HEX_SIZE] = '\0';
  return bc_key_from_hex(digits, out);
}

/** Parse "<number> " at \a *p, advancing past the space. */
static bool bc_parse_update(const char **p, uint32_t *r_update)
{
  uint64_t value = 0;
  const char *c = *p;
  if (*c < '0' || *c > '9') {
    return false;
  }
  while (*c >= '0' && *c <= '9') {
    value = value * 10 + (uint64_t)(*c++ - '0');
    if (value > 0xFFFFFFFFu) {
      return false;
    }
  }
  if (*c != ' ' || value == 0) {
    return false;
  }
  *r_update = (uint32_t)value;
  *p = c + 1;
  return true;
}

/** Parse "<number> " at \a *p (any value, 0 included), advancing past the space. */
static bool bc_parse_u64(const char **p, uint64_t *r_value)
{
  uint64_t value = 0;
  const char *c = *p;
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

/** Hex digits and spaces only: the one key form, whatever its length (checked by the caller). */
static bool bc_is_hex_line(const char *p)
{
  for (; *p != '\0'; p++) {
    if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F') || *p == ' ')) {
      return false;
    }
  }
  return true;
}

/** A lowercase keyword, then a space or the end of the line. */
static bool bc_is_keyword_line(const char *p)
{
  const char *c = p;
  while ((*c >= 'a' && *c <= 'z') || *c == '_') {
    c++;
  }
  return c > p && (*c == ' ' || *c == '\0');
}

bool bc_keyring_load(BC_KeyRing *r, const char *path, char *err, const size_t err_size)
{
  bc_keyring_free(r);
  FILE *f = bc_fopen(path, "rb");
  if (f == NULL) {
    snprintf(err, err_size, "cannot open the key file '%s'", path);
    return false;
  }
  char line[BC_KEYRING_LINE_MAX];
  int line_number = 0;
  bool ok = true;
  bool single = false;
  while (ok && fgets(line, sizeof(line), f) != NULL) {
    line_number++;
    size_t n = strlen(line);
    while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) {
      line[--n] = '\0';
    }
    if (n == 0 || line[0] == '#') {
      continue;
    }
    const char *p = line;
    uint32_t update;
    uint8_t value[32];
    if (strncmp(p, "key ", 4) == 0) {
      p += 4;
      ok = !single && bc_parse_update(&p, &update) && strlen(p) == BC_KEY_HEX_SIZE && bc_hex32(p, value) &&
           bc_keyring_insert(r, update, value);
    }
    else if (strncmp(p, "file ", 5) == 0) {
      p += 5;
      uint64_t size = 0, mtime = 0;
      ok = bc_parse_update(&p, &update) && bc_hex32(p, value) && p[BC_KEY_HEX_SIZE] == ' ';
      if (ok) {
        p += BC_KEY_HEX_SIZE + 1;
        ok = bc_parse_u64(&p, &size) && bc_parse_u64(&p, &mtime) && *p != '\0' &&
             bc_keyring_set_record(r, p, value, update, size, mtime);
      }
    }
    else if (bc_is_hex_line(line)) {
      /* The one key form: 64 hex digits, possibly with spaces (bc_key_from_hex rules). */
      ok = r->key_count == 0 && bc_key_from_hex(line, value) && bc_keyring_insert(r, 1, value);
      single = true;
    }
    else {
      /* A keyword of a later bc_tool: skipped. Anything else is not a key file line. */
      ok = bc_is_keyword_line(line);
    }
    crypto_wipe(value, sizeof(value));
  }
  fclose(f);
  crypto_wipe(line, sizeof(line));
  if (ok && r->key_count == 0) {
    snprintf(err, err_size, "'%s' holds no key", path);
    ok = false;
  }
  else if (!ok) {
    snprintf(err, err_size, "'%s' line %d: not a BinaryCrypt key file line", path, line_number);
  }
  if (!ok) {
    bc_keyring_free(r);
  }
  return ok;
}

bool bc_keyring_save(const BC_KeyRing *r, const char *path, const bool single, char *err, const size_t err_size)
{
  char tmp_path[BC_PATH_MAX + 8];
  snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path);
  FILE *f = (single ? r->key_count == 1 : r->key_count > 0) ? bc_fopen(tmp_path, "wb") : NULL;
#ifndef _WIN32
  if (f != NULL) {
    chmod(tmp_path, 0600); /* Before any key byte is written. */
  }
#endif
  bool ok = f != NULL;
  char hex[BC_KEY_HEX_SIZE + 1];
  if (ok && single) {
    bc_key_to_hex(r->keys[0], hex);
    ok = fprintf(f, "%s\n", hex) > 0;
  }
  else if (ok) {
    ok = fprintf(f,
                 "# UPBGE-BinaryCrypt key file: private. Back it up, install it on the key server, never ship it.\n") > 0;
    for (int i = 0; ok && i < r->key_count; i++) {
      bc_key_to_hex(r->keys[i], hex);
      ok = fprintf(f, "key %u %s\n", r->updates[i], hex) > 0;
    }
    for (int i = 0; ok && i < r->record_count; i++) {
      bc_key_to_hex(r->records[i].hash, hex); /* Same hex form, 32 bytes. */
      ok = fprintf(f,
                   "file %u %s %llu %llu %s\n",
                   r->records[i].update,
                   hex,
                   (unsigned long long)r->records[i].size,
                   (unsigned long long)r->records[i].mtime,
                   r->records[i].path) > 0;
    }
  }
  crypto_wipe(hex, sizeof(hex));
  if (f != NULL && fclose(f) != 0) {
    ok = false;
  }
  ok = ok && bc_rename_replace(tmp_path, path);
  if (!ok) {
    if (f != NULL) {
      bc_remove(tmp_path);
    }
    snprintf(err, err_size, "cannot write the key file '%s'", path);
  }
  return ok;
}
