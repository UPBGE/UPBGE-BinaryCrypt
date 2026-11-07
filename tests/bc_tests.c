/* SPDX-License-Identifier: GPL-2.0-or-later */

/* Unit tests for the BinaryCrypt core. Usage: bc_tests <empty work folder>. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <wchar.h>
#  include <windows.h>
#else
#  include <sys/stat.h>
#  include <sys/wait.h>
#  include <unistd.h>
#endif

#include "bc_brand.h"
#include "bc_compress.h"
#include "bc_embed.h"
#include "bc_envelope.h"
#include "bc_job.h"
#include "bc_key.h"
#include "bc_keyring.h"
#include "bc_manifest.h"
#include "bc_native.h"
#include "bc_project.h"
#include "bc_seal.h"
#include "bc_test_decrypt.h"
#include "blake3.h"
#include "monocypher.h"

#include <zstd.h>

static int g_failures = 0;
static char g_work[BC_PATH_MAX];

#define CHECK(condition) \
  do { \
    if (!(condition)) { \
      fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #condition); \
      g_failures++; \
    } \
  } while (0)

#define CHECK_STR(a, b) \
  do { \
    if (strcmp((a), (b)) != 0) { \
      fprintf(stderr, "%s:%d: '%s' != '%s'\n", __FILE__, __LINE__, (a), (b)); \
      g_failures++; \
    } \
  } while (0)

static const uint8_t OTHER_KEY[BC_KEY_SIZE] = {9, 9, 9};

static void work_path(char *out, const char *rel)
{
  bc_path_join(out, BC_PATH_MAX, g_work, rel);
}

/** Write a stand-in .blend: the real magic then deterministic bytes. */
static void write_blend(const char *rel, size_t size, uint32_t seed)
{
  char path[BC_PATH_MAX], dir[BC_PATH_MAX];
  work_path(path, rel);
  bc_path_dirname(dir, sizeof(dir), path);
  bc_mkdir_p(dir);
  FILE *f = bc_fopen(path, "wb");
  for (size_t i = 0; i < size; i++) {
    seed ^= seed << 13;
    seed ^= seed >> 17;
    seed ^= seed << 5;
    fputc(i < 7 ? "BLENDER"[i] : (int)(seed & 0xff), f);
  }
  fclose(f);
}

static void write_text(const char *rel, const char *text)
{
  char path[BC_PATH_MAX], dir[BC_PATH_MAX];
  work_path(path, rel);
  bc_path_dirname(dir, sizeof(dir), path);
  bc_mkdir_p(dir);
  FILE *f = bc_fopen(path, "wb");
  fputs(text, f);
  fclose(f);
}

/** True when the container \a sealed_rel decrypts with the build key to the bytes of \a plain_rel. */
static bool decrypts_to(const char *sealed_rel, const char *plain_rel)
{
  char sealed[BC_PATH_MAX], plain_path[BC_PATH_MAX];
  work_path(sealed, sealed_rel);
  work_path(plain_path, plain_rel);
  uint8_t *plain, *expected;
  uint64_t plain_size, expected_size;
  if (!bc_test_decrypt(sealed, bc_build_key(), &plain, &plain_size)) {
    return false;
  }
  if (!bc_test_read_file(plain_path, &expected, &expected_size)) {
    free(plain);
    return false;
  }
  /* A .blend the export compressed: compare what Blender's reader would unwrap. */
  if (plain_size >= 4 && memcmp(plain, "\x28\xb5\x2f\xfd", 4) == 0 && expected_size >= 7 &&
      memcmp(expected, "BLENDER", 7) == 0)
  {
    uint8_t *unpacked = (uint8_t *)malloc((size_t)expected_size + 1);
    const size_t n = unpacked ? ZSTD_decompress(unpacked, (size_t)expected_size + 1, plain, (size_t)plain_size) : 0;
    free(plain);
    plain = unpacked;
    plain_size = (unpacked != NULL && !ZSTD_isError(n)) ? n : 0;
  }
  const bool ok = expected_size == plain_size && plain != NULL &&
                  memcmp(expected, plain, (size_t)plain_size) == 0;
  free(plain);
  free(expected);
  return ok;
}

/** The generic attack on a key stored in one piece: take every 32 byte window of \a path as a key
 * and compare its key id with \a key_id (what any container header names). Costs one keyed
 * BLAKE2b per byte of the file, about a second for a few MB. */
static bool file_holds_key(const char *path, const uint8_t key_id[BC_KEY_ID_SIZE])
{
  uint8_t *data, id[BC_KEY_ID_SIZE];
  uint64_t size;
  if (!bc_test_read_file(path, &data, &size)) {
    return false;
  }
  bool found = false;
  for (uint64_t i = 0; i + BC_KEY_SIZE <= size && !found; i++) {
    bc_key_id(data + i, id);
    found = memcmp(id, key_id, BC_KEY_ID_SIZE) == 0;
  }
  free(data);
  return found;
}

/** Kind byte of the container at \a rel (BC_KIND_*), -1 when unreadable. */
static int sealed_kind(const char *rel)
{
  char path[BC_PATH_MAX];
  uint8_t raw[BC_HEADER_SIZE];
  BC_Header header;
  work_path(path, rel);
  FILE *f = bc_fopen(path, "rb");
  const size_t n = f != NULL ? fread(raw, 1, sizeof(raw), f) : 0;
  if (f != NULL) {
    fclose(f);
  }
  return n == sizeof(raw) && bc_header_read(raw, &header) == BC_HEADER_OK ? header.kind : -1;
}

/** True when the container \a sealed decrypts with \a key. */
static bool decrypts_with(const char *sealed, const uint8_t key[BC_KEY_SIZE])
{
  uint8_t *plain;
  uint64_t plain_size;
  if (!bc_test_decrypt(sealed, key, &plain, &plain_size)) {
    return false;
  }
  free(plain);
  return true;
}

/* -------------------------------------------------------------------------------------------- */

static void test_paths(void)
{
  char p[BC_PATH_MAX];
  const char *cases[][2] = {
      {"/a/b/../c/./d/", "/a/c/d"},
      {"/../x", "/x"},
      {"a/../../b", "../b"},
      {"../../x", "../../x"},
      {"./", "."},
      {"", "."},
      {"/", "/"},
      {"a//b///c", "a/b/c"},
      {".hidden/..x/y", ".hidden/..x/y"},
      {"C:/games/../x", "C:/x"},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    snprintf(p, sizeof(p), "%s", cases[i][0]);
    bc_path_normalize(p);
    CHECK_STR(p, cases[i][1]);
  }
  CHECK(bc_path_relative(p, sizeof(p), "/game", "/game/levels/a.blend"));
  CHECK_STR(p, "levels/a.blend");
  CHECK(bc_path_relative(p, sizeof(p), "/game", "/game"));
  CHECK_STR(p, ".");
  CHECK(!bc_path_relative(p, sizeof(p), "/game", "/gameplay/a.blend"));
  CHECK(bc_path_relative(p, sizeof(p), "/", "/x/y"));
  CHECK_STR(p, "x/y");
  CHECK(bc_path_join(p, sizeof(p), "/a/b", "../c"));
  CHECK_STR(p, "/a/c");
  CHECK(bc_path_join(p, sizeof(p), "/a/b", "/abs"));
  CHECK_STR(p, "/abs");
  bc_path_dirname(p, sizeof(p), "/a/b.blend");
  CHECK_STR(p, "/a");
  bc_path_dirname(p, sizeof(p), "/b.blend");
  CHECK_STR(p, "/");
  CHECK_STR(bc_path_basename("/a/b.blend"), "b.blend");
  CHECK(bc_path_has_extension("x.BLEND", ".blend"));
  CHECK(!bc_path_has_extension("x.blend1", ".blend"));
}

static void test_key_hex(void)
{
  uint8_t key[BC_KEY_SIZE], back[BC_KEY_SIZE];
  char hex[BC_KEY_HEX_SIZE + 1];
  for (int i = 0; i < BC_KEY_SIZE; i++) {
    key[i] = (uint8_t)(i * 37 + 1);
  }
  bc_key_to_hex(key, hex);
  CHECK(bc_key_from_hex(hex, back) && memcmp(key, back, BC_KEY_SIZE) == 0);
  char spaced[200];
  snprintf(spaced, sizeof(spaced), "  %.32s\n%s\n", hex, hex + 32);
  CHECK(bc_key_from_hex(spaced, back) && memcmp(key, back, BC_KEY_SIZE) == 0);
  CHECK(!bc_key_from_hex("abcd", back));
  hex[5] = 'g';
  CHECK(!bc_key_from_hex(hex, back));
  char fingerprint[BC_FINGERPRINT_SIZE];
  bc_key_fingerprint(bc_build_key(), fingerprint);
  CHECK(strlen(fingerprint) == 16);

  /* Split storage: neither share is the key, every split differs, each joins back exactly. */
  uint8_t a[BC_KEY_SIZE], b[BC_KEY_SIZE], a2[BC_KEY_SIZE], b2[BC_KEY_SIZE];
  CHECK(bc_key_split(key, a, b) && bc_key_split(key, a2, b2));
  CHECK(memcmp(a, key, BC_KEY_SIZE) != 0 && memcmp(b, key, BC_KEY_SIZE) != 0);
  CHECK(memcmp(a, a2, BC_KEY_SIZE) != 0 && memcmp(b, b2, BC_KEY_SIZE) != 0);
  bc_key_join(a, b, back);
  CHECK(memcmp(back, key, BC_KEY_SIZE) == 0);
  bc_key_join(a2, b2, back);
  CHECK(memcmp(back, key, BC_KEY_SIZE) == 0);
}

/** Write a fake executable: \a size bytes, optionally starting with a minimal PE32+ header whose
 * security directory is filled later by fake_sign(). */
static void write_fake_exe(const char *path, size_t size, bool pe)
{
  uint8_t *data = (uint8_t *)calloc(1, size);
  for (size_t i = 0; i < size; i++) {
    data[i] = (uint8_t)(i * 7 + 3);
  }
  if (pe) {
    memset(data, 0, 0x200);
    data[0] = 'M';
    data[1] = 'Z';
    data[0x3c] = 0x80; /* e_lfanew */
    memcpy(data + 0x80, "PE\0\0", 4);
    uint8_t *optional = data + 0x80 + 24;
    optional[0] = 0x0b; /* PE32+ magic 0x20b */
    optional[1] = 0x02;
    optional[108] = 16; /* NumberOfRvaAndSizes */
  }
  FILE *f = bc_fopen(path, "wb");
  fwrite(data, 1, size, f);
  fclose(f);
  free(data);
}

/** Mimic signtool: append a certificate table on an 8 byte boundary and point the PE security
 * directory at it. */
static void fake_sign(const char *path)
{
  uint8_t *data;
  uint64_t size;
  CHECK(bc_test_read_file(path, &data, &size));
  CHECK(size % 8 == 0); /* bc_embed_write keeps the file aligned: no padding before the table. */
  const uint32_t table_size = 1504;
  uint8_t *signed_data = (uint8_t *)calloc(1, (size_t)size + table_size);
  memcpy(signed_data, data, (size_t)size);
  uint8_t *security = signed_data + 0x80 + 24 + 112 + 4 * 8;
  const uint32_t offset = (uint32_t)size;
  memcpy(security, &offset, 4);
  memcpy(security + 4, &table_size, 4);
  FILE *f = bc_fopen(path, "wb");
  fwrite(signed_data, 1, (size_t)size + table_size, f);
  fclose(f);
  free(data);
  free(signed_data);
}

static void test_manifest(void)
{
  BC_Manifest m, r;
  memset(&m, 0, sizeof(m));
  for (int i = 0; i < BC_PLAYER_HASH_SIZE; i++) {
    m.player_hash[i] = (uint8_t)i;
  }
  snprintf(m.player_path, sizeof(m.player_path), "engine/blenderplayer.exe");
  snprintf(m.main_path, sizeof(m.main_path), "game.blend");

  uint8_t data[BC_MANIFEST_MAX_SIZE];
  const size_t size = bc_manifest_encode(&m, bc_build_key(), data);
  CHECK(size > 0);
  CHECK(bc_manifest_decode(data, size, bc_build_key(), &r) == BC_MANIFEST_OK);
  CHECK_STR(r.player_path, m.player_path);
  CHECK_STR(r.main_path, m.main_path);
  CHECK(memcmp(r.player_hash, m.player_hash, BC_PLAYER_HASH_SIZE) == 0);
  CHECK(bc_manifest_decode(data, size, OTHER_KEY, &r) == BC_MANIFEST_WRONG_KEY);

  /* Flip one byte in each authenticated region: hash, paths, MAC. */
  const size_t offsets[] = {30, BC_MANIFEST_FIXED_SIZE + 2, size - 40, size - 1};
  for (size_t i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
    data[offsets[i]] ^= 1;
    CHECK(bc_manifest_decode(data, size, bc_build_key(), &r) == BC_MANIFEST_BAD_MAC);
    data[offsets[i]] ^= 1;
  }
  CHECK(bc_manifest_decode(data, size - 1, bc_build_key(), &r) == BC_MANIFEST_BAD_FORMAT);

  /* Paths escaping the game folder are refused even before encoding. */
  snprintf(m.player_path, sizeof(m.player_path), "../evil");
  CHECK(bc_manifest_encode(&m, bc_build_key(), data) == 0);
  snprintf(m.player_path, sizeof(m.player_path), "/abs/player");
  CHECK(bc_manifest_encode(&m, bc_build_key(), data) == 0);
  CHECK(bc_manifest_path_is_safe("a/..b/c.blend"));
  CHECK(!bc_manifest_path_is_safe("a/../b"));
  CHECK(!bc_manifest_path_is_safe("C:/x"));
  CHECK(!bc_manifest_path_is_safe("a\\b"));
  CHECK(!bc_manifest_path_is_safe("a//b"));

  /* Online key fields: authenticated like the rest. */
  snprintf(m.player_path, sizeof(m.player_path), "engine/blenderplayer.exe");
  m.flags = BC_MANIFEST_ONLINE_KEY | BC_MANIFEST_KEY_CACHE;
  m.key_count = 3;
  for (int i = 0; i < 3; i++) {
    memset(m.key_ids[i], 0xA0 + i, BC_KEY_ID_SIZE);
  }
  snprintf(m.provider_path, sizeof(m.provider_path), "engine/bc_provider_steam.exe");
  snprintf(m.key_url, sizeof(m.key_url), "https://keys.example.com/key?game=1");
  const size_t online_size = bc_manifest_encode(&m, bc_build_key(), data);
  CHECK(online_size > 0);
  CHECK(bc_manifest_decode(data, online_size, bc_build_key(), &r) == BC_MANIFEST_OK);
  CHECK(r.flags == m.flags && r.key_count == 3 && memcmp(r.key_ids, m.key_ids, 3 * BC_KEY_ID_SIZE) == 0);
  CHECK_STR(r.provider_path, m.provider_path);
  CHECK_STR(r.key_url, m.key_url);
  data[online_size - 40] ^= 1; /* Inside the key ids. */
  CHECK(bc_manifest_decode(data, online_size, bc_build_key(), &r) == BC_MANIFEST_BAD_MAC);
  m.key_count = 0; /* An online key game names at least one key. */
  CHECK(bc_manifest_encode(&m, bc_build_key(), data) == 0);
  m.key_count = 1;
  snprintf(m.provider_path, sizeof(m.provider_path), "../provider");
  CHECK(bc_manifest_encode(&m, bc_build_key(), data) == 0);
  snprintf(m.provider_path, sizeof(m.provider_path), "engine/provider");
  snprintf(m.key_url, sizeof(m.key_url), "https://x\n--evil");
  CHECK(bc_manifest_encode(&m, bc_build_key(), data) == 0);
  /* Without the online flag the provider and URL are not stored at all. */
  m.flags = 0;
  const size_t plain_size = bc_manifest_encode(&m, bc_build_key(), data);
  CHECK(plain_size > 0 && bc_manifest_decode(data, plain_size, bc_build_key(), &r) == BC_MANIFEST_OK);
  CHECK(r.flags == 0 && r.provider_path[0] == '\0' && r.key_url[0] == '\0');

  /* Native code digest: authenticated, combinable with every key mode. */
  m.flags = BC_MANIFEST_NATIVE_DIGEST;
  memset(m.native_digest, 0x6B, BC_NATIVE_DIGEST_SIZE);
  const size_t native_size = bc_manifest_encode(&m, bc_build_key(), data);
  CHECK(native_size == plain_size + BC_NATIVE_DIGEST_SIZE);
  CHECK(bc_manifest_decode(data, native_size, bc_build_key(), &r) == BC_MANIFEST_OK);
  CHECK(r.flags == BC_MANIFEST_NATIVE_DIGEST && memcmp(r.native_digest, m.native_digest, BC_NATIVE_DIGEST_SIZE) == 0);
  data[native_size - BC_MANIFEST_MAC_SIZE - 1] ^= 1;
  CHECK(bc_manifest_decode(data, native_size, bc_build_key(), &r) == BC_MANIFEST_BAD_MAC);
  m.flags = BC_MANIFEST_NATIVE_DIGEST | BC_MANIFEST_PYTHON_CHECK;
  CHECK(bc_manifest_encode(&m, bc_build_key(), data) == native_size);
  CHECK(bc_manifest_decode(data, native_size, bc_build_key(), &r) == BC_MANIFEST_OK && r.flags == m.flags);
  /* The Python level without a digest is meaningless: the encoder drops it, the decoder refuses it. */
  m.flags = BC_MANIFEST_PYTHON_CHECK;
  CHECK(bc_manifest_encode(&m, bc_build_key(), data) == plain_size);
  CHECK(bc_manifest_decode(data, plain_size, bc_build_key(), &r) == BC_MANIFEST_OK && r.flags == 0);
  m.flags = 0;

  /* Project key: one key id plus the masked key, both authenticated; never with the online flag. */
  m.flags = BC_MANIFEST_PROJECT_KEY;
  m.key_count = 1;
  memset(m.key_ids[0], 0x3C, BC_KEY_ID_SIZE);
  for (int i = 0; i < BC_KEY_SIZE; i++) {
    m.masked_key[i] = (uint8_t)(200 - i);
  }
  const size_t project_size = bc_manifest_encode(&m, bc_build_key(), data);
  CHECK(project_size > plain_size);
  CHECK(bc_manifest_decode(data, project_size, bc_build_key(), &r) == BC_MANIFEST_OK);
  CHECK(r.flags == BC_MANIFEST_PROJECT_KEY && r.key_count == 1);
  CHECK(memcmp(r.key_ids[0], m.key_ids[0], BC_KEY_ID_SIZE) == 0);
  CHECK(memcmp(r.masked_key, m.masked_key, BC_KEY_SIZE) == 0);
  CHECK(r.provider_path[0] == '\0' && r.key_url[0] == '\0');
  const size_t masked_at = project_size - BC_MANIFEST_MAC_SIZE - BC_KEY_SIZE;
  CHECK(memcmp(data + masked_at, m.masked_key, BC_KEY_SIZE) == 0);
  for (size_t i = masked_at; i < masked_at + BC_KEY_SIZE; i += 7) {
    data[i] ^= 0x80;
    CHECK(bc_manifest_decode(data, project_size, bc_build_key(), &r) == BC_MANIFEST_BAD_MAC);
    data[i] ^= 0x80;
  }
  m.flags = BC_MANIFEST_PROJECT_KEY | BC_MANIFEST_ONLINE_KEY;
  CHECK(bc_manifest_encode(&m, bc_build_key(), data) == 0);
  /* The mask depends on the build key, the key id and the player: a manifest copied next to
   * another player, or read with another build key, does not give the same key. */
  m.flags = BC_MANIFEST_PROJECT_KEY;
  uint8_t mask[BC_KEY_SIZE], other[BC_KEY_SIZE];
  bc_manifest_key_mask(bc_build_key(), &m, mask);
  bc_manifest_key_mask(OTHER_KEY, &m, other);
  CHECK(memcmp(mask, other, BC_KEY_SIZE) != 0);
  m.player_hash[0] ^= 1;
  bc_manifest_key_mask(bc_build_key(), &m, other);
  CHECK(memcmp(mask, other, BC_KEY_SIZE) != 0);
  m.player_hash[0] ^= 1;
  m.key_ids[0][0] ^= 1;
  bc_manifest_key_mask(bc_build_key(), &m, other);
  CHECK(memcmp(mask, other, BC_KEY_SIZE) != 0);
}

static void test_envelope(void)
{
  uint8_t key[BC_KEY_SIZE], key_id[BC_KEY_ID_SIZE], out[BC_KEY_SIZE];
  uint8_t secret[BC_X25519_SIZE], public_key[BC_X25519_SIZE];
  uint8_t secret2[BC_X25519_SIZE], public2[BC_X25519_SIZE];
  uint8_t envelope[BC_ENVELOPE_SIZE], envelope2[BC_ENVELOPE_SIZE];
  for (int i = 0; i < BC_KEY_SIZE; i++) {
    key[i] = (uint8_t)(i * 3 + 1);
  }
  bc_key_id(key, key_id);
  CHECK(bc_envelope_keypair(secret, public_key) && bc_envelope_keypair(secret2, public2));
  CHECK(bc_envelope_seal(key, key_id, public_key, envelope));
  CHECK(bc_envelope_open(envelope, key_id, secret, public_key, out) && memcmp(out, key, BC_KEY_SIZE) == 0);

  /* Every answer uses a fresh server key pair: different bytes, same key. */
  CHECK(bc_envelope_seal(key, key_id, public_key, envelope2));
  CHECK(memcmp(envelope, envelope2, BC_ENVELOPE_SIZE) != 0);
  CHECK(bc_envelope_open(envelope2, key_id, secret, public_key, out) && memcmp(out, key, BC_KEY_SIZE) == 0);

  /* Bound to this launch's key pair and to the key id; any modification is refused. */
  CHECK(!bc_envelope_open(envelope, key_id, secret2, public2, out));
  uint8_t other_id[BC_KEY_ID_SIZE];
  memcpy(other_id, key_id, BC_KEY_ID_SIZE);
  other_id[0] ^= 1;
  CHECK(!bc_envelope_open(envelope, other_id, secret, public_key, out));
  const int offsets[] = {0, 31, 32, 63, 64, 79};
  for (size_t i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
    envelope[offsets[i]] ^= 1;
    CHECK(!bc_envelope_open(envelope, key_id, secret, public_key, out));
    envelope[offsets[i]] ^= 1;
  }
  /* Small order points: the shared secret would be public. */
  static const uint8_t zero[BC_X25519_SIZE] = {0};
  CHECK(!bc_envelope_seal(key, key_id, zero, envelope2));
  memcpy(envelope2, envelope, BC_ENVELOPE_SIZE);
  memset(envelope2, 0, BC_X25519_SIZE);
  CHECK(!bc_envelope_open(envelope2, key_id, secret, public_key, out));
}

static void test_embed(void)
{
  char launcher[BC_PATH_MAX], game[BC_PATH_MAX], err[512];
  work_path(launcher, "embed/bc_launcher");
  work_path(game, "embed/MyGame");
  char dir[BC_PATH_MAX];
  bc_path_dirname(dir, sizeof(dir), launcher);
  bc_mkdir_p(dir);

  BC_Manifest m, r;
  memset(&m, 0, sizeof(m));
  m.player_hash[0] = 42;
  snprintf(m.player_path, sizeof(m.player_path), "engine/blenderplayer");
  snprintf(m.main_path, sizeof(m.main_path), "levels/start.blend");

  /* Every launcher size modulo 8: the padding must always land the trailer correctly. */
  for (size_t extra = 0; extra < 8; extra++) {
    write_fake_exe(launcher, 4000 + extra, false);
    CHECK(bc_embed_write(launcher, game, &m, bc_build_key(), err, sizeof(err)));
    uint64_t size;
    CHECK(bc_file_size(game, &size) && size % BC_EMBED_ALIGNMENT == 0);
    CHECK(bc_embed_read(game, bc_build_key(), &r) == BC_MANIFEST_OK);
    CHECK_STR(r.main_path, "levels/start.blend");
  }
  /* The launcher itself carries no game; a key from another build is refused. */
  CHECK(bc_embed_read(launcher, bc_build_key(), &r) == BC_MANIFEST_MISSING);
  CHECK(bc_embed_read(game, OTHER_KEY, &r) == BC_MANIFEST_WRONG_KEY);

  /* Tampering inside the embedded manifest. */
  uint8_t *data;
  uint64_t size;
  CHECK(bc_test_read_file(game, &data, &size));
  data[size - BC_EMBED_TRAILER_SIZE - 40] ^= 1;
  FILE *f = bc_fopen(game, "wb");
  fwrite(data, 1, (size_t)size, f);
  fclose(f);
  free(data);
  CHECK(bc_embed_read(game, bc_build_key(), &r) == BC_MANIFEST_BAD_MAC);

  /* Code signing after export: the manifest is still found in front of the signature. */
  write_fake_exe(launcher, 9001, true);
  CHECK(bc_embed_write(launcher, game, &m, bc_build_key(), err, sizeof(err)));
  fake_sign(game);
  CHECK(bc_embed_read(game, bc_build_key(), &r) == BC_MANIFEST_OK);
  CHECK_STR(r.player_path, "engine/blenderplayer");

#ifndef _WIN32
  CHECK(access(game, X_OK) == 0);
#endif

  /* External manifest: the game executable is the signed launcher, byte for byte. */
  write_fake_exe(launcher, 9000, true);
  fake_sign(launcher);
  CHECK(bc_embed_write(launcher, game, NULL, bc_build_key(), err, sizeof(err)));
  uint8_t *a = NULL, *b = NULL;
  uint64_t na = 0, nb = 0;
  CHECK(bc_test_read_file(launcher, &a, &na) && bc_test_read_file(game, &b, &nb));
  CHECK(na == nb && memcmp(a, b, (size_t)na) == 0);
  free(a);
  free(b);
  CHECK(bc_embed_read(game, bc_build_key(), &r) == BC_MANIFEST_MISSING);

  char file[BC_PATH_MAX];
  work_path(file, "embed/" BC_MANIFEST_FILENAME);
  CHECK(bc_manifest_file_read(file, bc_build_key(), &r) == BC_MANIFEST_MISSING);
  CHECK(bc_manifest_file_write(file, &m, bc_build_key(), err, sizeof(err)));
  CHECK(bc_manifest_file_read(file, bc_build_key(), &r) == BC_MANIFEST_OK);
  CHECK_STR(r.main_path, "levels/start.blend");
  CHECK(bc_manifest_file_read(file, OTHER_KEY, &r) == BC_MANIFEST_WRONG_KEY);
  CHECK(bc_test_read_file(file, &data, &size));
  data[size - 1] ^= 1;
  f = bc_fopen(file, "wb");
  fwrite(data, 1, (size_t)size, f);
  fclose(f);
  CHECK(bc_manifest_file_read(file, bc_build_key(), &r) == BC_MANIFEST_BAD_MAC);
  /* Trailing garbage changes the size: refused as malformed, never partially parsed. */
  data[size - 1] ^= 1;
  f = bc_fopen(file, "wb");
  fwrite(data, 1, (size_t)size, f);
  fputc(0, f);
  fclose(f);
  free(data);
  CHECK(bc_manifest_file_read(file, bc_build_key(), &r) == BC_MANIFEST_BAD_FORMAT);
  char big[BC_MANIFEST_MAX_SIZE + 100];
  memset(big, 'x', sizeof(big) - 1);
  big[sizeof(big) - 1] = '\0';
  write_text("embed/" BC_MANIFEST_FILENAME, big);
  CHECK(bc_manifest_file_read(file, bc_build_key(), &r) == BC_MANIFEST_BAD_FORMAT);
}

/* -------------------------------------------------------------------------------------------- */
/* Branding */

static void st32(uint8_t *p, const uint32_t v)
{
  p[0] = (uint8_t)v;
  p[1] = (uint8_t)(v >> 8);
  p[2] = (uint8_t)(v >> 16);
  p[3] = (uint8_t)(v >> 24);
}

/** .ico holding one solid 32 bpp bitmap per size: BITMAPINFOHEADER (height doubled, the AND mask
 * follows the colors), BGRA pixels, then the 1 bpp AND mask. */
static uint8_t *make_ico(const int *sizes, const int count, const uint32_t bgra, size_t *r_size)
{
  size_t total = 6 + 16 * (size_t)count;
  for (int i = 0; i < count; i++) {
    const size_t s = (size_t)sizes[i];
    total += 40 + s * s * 4 + s * ((s + 31) / 32 * 4);
  }
  uint8_t *ico = (uint8_t *)calloc(1, total);
  ico[2] = 1;
  ico[4] = (uint8_t)count;
  uint32_t offset = 6 + 16 * (uint32_t)count;
  for (int i = 0; i < count; i++) {
    const uint32_t s = (uint32_t)sizes[i];
    const uint32_t bytes = 40 + s * s * 4 + s * ((s + 31) / 32 * 4);
    uint8_t *entry = ico + 6 + 16 * i;
    entry[0] = entry[1] = (uint8_t)(s >= 256 ? 0 : s);
    entry[4] = 1;  /* planes */
    entry[6] = 32; /* bits per pixel */
    st32(entry + 8, bytes);
    st32(entry + 12, offset);
    uint8_t *image = ico + offset;
    st32(image, 40);
    st32(image + 4, s);
    st32(image + 8, 2 * s);
    image[12] = 1;
    image[14] = 32;
    for (uint32_t px = 0; px < s * s; px++) {
      st32(image + 40 + px * 4, bgra);
    }
    offset += bytes;
  }
  *r_size = total;
  return ico;
}

#ifdef _WIN32
#  include <windows.h>

/** Icon group \a group of \a exe holds exactly the images of \a ico, in order. */
static bool exe_group_equals_ico(const char *exe, const wchar_t *group, const uint8_t *ico)
{
  wchar_t *w = bc_utf16(exe);
  HMODULE m = LoadLibraryExW(w, NULL, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
  free(w);
  if (m == NULL) {
    return false;
  }
  HRSRC r = FindResourceW(m, group, MAKEINTRESOURCEW(14));
  const uint8_t *g = r ? (const uint8_t *)LockResource(LoadResource(m, r)) : NULL;
  bool equal = g != NULL && g[4] == ico[4] && g[5] == ico[5];
  for (int i = 0; equal && i < ico[4]; i++) {
    const uint8_t *entry = ico + 6 + 16 * i;
    const WORD id = (WORD)(g[6 + 14 * i + 12] | (g[6 + 14 * i + 13] << 8));
    HRSRC ri = FindResourceW(m, MAKEINTRESOURCEW(id), MAKEINTRESOURCEW(3));
    const DWORD size = ri ? SizeofResource(m, ri) : 0;
    const void *image = ri ? LockResource(LoadResource(m, ri)) : NULL;
    uint32_t bytes, offset;
    memcpy(&bytes, entry + 8, 4);
    memcpy(&offset, entry + 12, 4);
    equal = image != NULL && memcmp(g + 6 + 14 * i, entry, 12) == 0 && size == bytes &&
            memcmp(image, ico + offset, bytes) == 0;
  }
  FreeLibrary(m);
  return equal;
}

/** Version string as Explorer reads it. */
static bool exe_version_string(const char *exe, const wchar_t *name, char *out, size_t size)
{
  wchar_t *w = bc_utf16(exe);
  DWORD handle = 0;
  const DWORD n = GetFileVersionInfoSizeW(w, &handle);
  void *data = n ? malloc(n) : NULL;
  wchar_t query[128];
  swprintf(query, 128, L"\\StringFileInfo\\040904B0\\%ls", name);
  wchar_t *value = NULL;
  UINT len = 0;
  const bool ok = data != NULL && GetFileVersionInfoW(w, 0, n, data) &&
                  VerQueryValueW(data, query, (void **)&value, &len) && len > 0 &&
                  bc_utf8(value, out, size);
  free(data);
  free(w);
  return ok;
}

/** A second icon group with a numeric ID, like the player's .blend file icon. */
static bool add_raw_group(const char *exe, const WORD group_id, const uint8_t *ico, const WORD first_id)
{
  wchar_t *w = bc_utf16(exe);
  HANDLE h = BeginUpdateResourceW(w, FALSE);
  free(w);
  if (h == NULL) {
    return false;
  }
  uint8_t group[6 + 14 * 16];
  memcpy(group, ico, 6);
  BOOL ok = TRUE;
  for (int i = 0; i < ico[4]; i++) {
    const uint8_t *entry = ico + 6 + 16 * i;
    uint32_t bytes, offset;
    memcpy(&bytes, entry + 8, 4);
    memcpy(&offset, entry + 12, 4);
    memcpy(group + 6 + 14 * i, entry, 12);
    group[6 + 14 * i + 12] = (uint8_t)(first_id + i);
    group[6 + 14 * i + 13] = 0;
    ok = ok && UpdateResourceW(h, MAKEINTRESOURCEW(3), MAKEINTRESOURCEW(first_id + i), 0x409, (void *)(ico + offset), bytes);
  }
  ok = ok && UpdateResourceW(h, MAKEINTRESOURCEW(14), MAKEINTRESOURCEW(group_id), 0x409, group, 6 + 14 * ico[4]);
  return EndUpdateResourceW(h, !ok) && ok;
}

static bool same_file(const char *a, const char *b)
{
  uint8_t *da, *db;
  uint64_t na, nb;
  if (!bc_test_read_file(a, &da, &na)) {
    return false;
  }
  if (!bc_test_read_file(b, &db, &nb)) {
    free(da);
    return false;
  }
  const bool equal = na == nb && memcmp(da, db, (size_t)na) == 0;
  free(da);
  free(db);
  return equal;
}

static void copy_file(const char *from, const char *to)
{
  char err[512], dir[BC_PATH_MAX];
  bc_path_dirname(dir, sizeof(dir), to);
  bc_mkdir_p(dir);
  CHECK(bc_embed_write(from, to, NULL, bc_build_key(), err, sizeof(err)));
}

static void test_brand_exe(void)
{
  char self[BC_PATH_MAX], exe[BC_PATH_MAX], before[BC_PATH_MAX], err[512], text[256];
  CHECK(bc_exe_path(self, sizeof(self)));
  work_path(exe, "brand/player.exe");
  work_path(before, "brand/before.exe");
  copy_file(self, exe);

  /* A player-like executable: the .blend file icon is icon group 1. */
  size_t size;
  const int file_sizes[] = {16, 32};
  uint8_t *file_icon = make_ico(file_sizes, 2, 0xFF00FF00, &size);
  CHECK(add_raw_group(exe, 1, file_icon, 1));

  const int sizes_a[] = {16, 32, 48};
  uint8_t *ico_a = make_ico(sizes_a, 3, 0xFFFF0000, &size);
  BC_Branding b;
  memset(&b, 0, sizeof(b));
  b.ico = ico_a;
  b.ico_size = size;
  b.product = "My G\xC3\xA4me";
  b.company = "Studio";
  b.copyright = "";
  b.original_filename = "player.exe";
  b.version[0] = 1;
  b.version[1] = 2;
  b.version[2] = 3;
  CHECK(bc_brand_exe(exe, &b, err, sizeof(err)) == BC_BRAND_CHANGED);
  CHECK(exe_group_equals_ico(exe, L"APPICON", ico_a));
  CHECK(exe_group_equals_ico(exe, MAKEINTRESOURCEW(1), file_icon));
  CHECK(exe_version_string(exe, L"ProductName", text, sizeof(text)) && strcmp(text, "My G\xC3\xA4me") == 0);
  CHECK(exe_version_string(exe, L"FileDescription", text, sizeof(text)) && strcmp(text, "My G\xC3\xA4me") == 0);
  CHECK(exe_version_string(exe, L"FileVersion", text, sizeof(text)) && strcmp(text, "1.2.3.0") == 0);
  CHECK(exe_version_string(exe, L"CompanyName", text, sizeof(text)) && strcmp(text, "Studio") == 0);
  CHECK(exe_version_string(exe, L"OriginalFilename", text, sizeof(text)) && strcmp(text, "player.exe") == 0);
  CHECK(!exe_version_string(exe, L"LegalCopyright", text, sizeof(text)));

  /* Same branding again: the file is not rewritten (a signature and the hash survive). */
  copy_file(exe, before);
  CHECK(bc_brand_exe(exe, &b, err, sizeof(err)) == BC_BRAND_UNCHANGED);
  CHECK(same_file(exe, before));

  /* Fewer, then more images than the current group; group 1 never changes. */
  const int sizes_c[] = {24};
  uint8_t *ico_c = make_ico(sizes_c, 1, 0xFF0000FF, &size);
  b.ico = ico_c;
  CHECK(bc_brand_exe(exe, &b, err, sizeof(err)) == BC_BRAND_CHANGED);
  CHECK(exe_group_equals_ico(exe, L"APPICON", ico_c));
  CHECK(exe_group_equals_ico(exe, MAKEINTRESOURCEW(1), file_icon));
  const int sizes_d[] = {16, 24, 32, 48, 64};
  uint8_t *ico_d = make_ico(sizes_d, 5, 0xFFFFFFFF, &size);
  b.ico = ico_d;
  CHECK(bc_brand_exe(exe, &b, err, sizeof(err)) == BC_BRAND_CHANGED);
  CHECK(exe_group_equals_ico(exe, L"APPICON", ico_d));
  CHECK(exe_group_equals_ico(exe, MAKEINTRESOURCEW(1), file_icon));

  /* Version only: the icon stays. */
  b.ico = NULL;
  b.version[0] = 7;
  CHECK(bc_brand_exe(exe, &b, err, sizeof(err)) == BC_BRAND_CHANGED);
  CHECK(exe_group_equals_ico(exe, L"APPICON", ico_d));
  CHECK(exe_version_string(exe, L"ProductVersion", text, sizeof(text)) && strcmp(text, "7.2.3.0") == 0);

  /* Not an executable: refused, nothing left behind. */
  char not_exe[BC_PATH_MAX], tmp[BC_PATH_MAX + 16];
  write_text("brand/notes.exe", "just text");
  work_path(not_exe, "brand/notes.exe");
  CHECK(bc_brand_exe(not_exe, &b, err, sizeof(err)) == BC_BRAND_ERROR);
  snprintf(tmp, sizeof(tmp), "%s.brand.tmp", exe);
  CHECK(!bc_is_file(tmp));
  free(file_icon);
  free(ico_a);
  free(ico_c);
  free(ico_d);
}
#endif

static void test_brand(void)
{
  uint16_t v[4];
  CHECK(bc_brand_parse_version("1", v) && v[0] == 1 && v[1] == 0 && v[3] == 0);
  CHECK(bc_brand_parse_version("1.2.3.65535", v) && v[1] == 2 && v[2] == 3 && v[3] == 65535);
  const char *bad_versions[] = {"", "1.", ".1", "1..2", "1.2.3.4.5", "65536", "v1", "1.2a", " 1"};
  for (size_t i = 0; i < sizeof(bad_versions) / sizeof(bad_versions[0]); i++) {
    CHECK(!bc_brand_parse_version(bad_versions[i], v));
  }

  const int sizes[] = {16, 32, 48};
  size_t size;
  char err[256];
  uint8_t *ico = make_ico(sizes, 3, 0xFF0000FF, &size);
  CHECK(bc_brand_ico_check(ico, size, err, sizeof(err)));
  CHECK(!bc_brand_ico_check(ico, size - 1, err, sizeof(err)) && strstr(err, "outside") != NULL);
  ico[2] = 2; /* A cursor file. */
  CHECK(!bc_brand_ico_check(ico, size, err, sizeof(err)) && strstr(err, "not an .ico") != NULL);
  ico[2] = 1;
  uint32_t first_offset;
  memcpy(&first_offset, ico + 6 + 12, 4);
  ico[first_offset] = 'X';
  CHECK(!bc_brand_ico_check(ico, size, err, sizeof(err)) && strstr(err, "neither PNG") != NULL);
  memcpy(ico + first_offset, "\x89PNG", 4);
  CHECK(bc_brand_ico_check(ico, size, err, sizeof(err)));
  free(ico);

#ifdef _WIN32
  CHECK(bc_brand_supported());
  test_brand_exe();
#else
  CHECK(!bc_brand_supported());
#endif
}

static void test_native(void)
{
  CHECK(bc_is_native_code("player.exe") && bc_is_native_code("Python311.DLL"));
  CHECK(bc_is_native_code("_ssl.pyd") && bc_is_native_code("libGL.so") && bc_is_native_code("libz.dylib"));
  CHECK(bc_is_native_code("libpython3.11.so.1.0") && bc_is_native_code("libtbb.so.12"));
  CHECK(!bc_is_native_code("bge.py") && !bc_is_native_code("bge.cpython-311.pyc") && !bc_is_native_code("a.pth"));
  CHECK(!bc_is_native_code("level.blend") && !bc_is_native_code("notes.so.txt") && !bc_is_native_code("x.so."));
  CHECK(!bc_is_native_code("readme") && !bc_is_native_code("so"));
  CHECK(bc_is_python_source("bge.py") && bc_is_python_source("tool.PYW") && bc_is_python_source("a.pth"));
  CHECK(bc_is_python_source("python311.zip") && !bc_is_python_source("bge.pyc") && !bc_is_python_source("x.pyd"));
  CHECK(bc_is_python_bytecode("bge.cpython-311.pyc") && bc_is_python_bytecode("old.PYO") && !bc_is_python_bytecode("a.py"));

  write_text("native/game.exe", "launcher");
  write_text("native/engine/player.exe", "player");
  write_text("native/engine/python311.dll", "python");
  write_text("native/engine/lib/libtbb.so.12", "tbb");
  write_text("native/engine/4.5/python/lib/_ssl.pyd", "ssl");
  write_text("native/engine/4.5/python/lib/bge.py", "print()");
  write_text("native/data/level.blend", "BLENDER");
  char root[BC_PATH_MAX], path[BC_PATH_MAX];
  work_path(root, "native");
  const char *skip[2] = {"game.exe", "engine/player.exe"};
  uint8_t base[BC_NATIVE_DIGEST_SIZE], d[BC_NATIVE_DIGEST_SIZE], py[BC_NATIVE_DIGEST_SIZE];
  static BC_NativeScan scan;
  CHECK(bc_native_digest(root, skip, 2, false, base, &scan) && scan.files == 3 && scan.bytes == 12);
  /* Libraries level: Python sources and bytecode, data, the skipped game executable and player
   * are not covered, and nothing is removed. */
  write_text("native/engine/4.5/python/lib/bge.py", "print('changed')");
  write_text("native/engine/4.5/python/lib/__pycache__/bge.cpython-311.pyc", "bytecode");
  write_text("native/engine/4.5/python/lib/site-packages/evil.pth", "import os");
  write_text("native/data/level.blend", "BLENDER2");
  write_text("native/game.exe", "launcher with another manifest");
  write_text("native/engine/player.exe", "branded player");
  CHECK(bc_native_digest(root, skip, 2, false, d, &scan) && memcmp(d, base, sizeof(d)) == 0 && scan.bytecode_removed == 0);
  work_path(path, "native/engine/4.5/python/lib/__pycache__/bge.cpython-311.pyc");
  CHECK(bc_is_file(path));
  /* A changed, added, removed or moved library is. */
  write_text("native/engine/python311.dll", "proxy");
  CHECK(bc_native_digest(root, skip, 2, false, d, NULL) && memcmp(d, base, sizeof(d)) != 0);
  write_text("native/engine/python311.dll", "python");
  CHECK(bc_native_digest(root, skip, 2, false, d, NULL) && memcmp(d, base, sizeof(d)) == 0);
  write_text("native/engine/version.dll", "proxy");
  CHECK(bc_native_digest(root, skip, 2, false, d, NULL) && memcmp(d, base, sizeof(d)) != 0);
  work_path(path, "native/engine/version.dll");
  bc_remove(path);
  work_path(path, "native/engine/lib/libtbb.so.12");
  bc_remove(path);
  CHECK(bc_native_digest(root, skip, 2, false, d, NULL) && memcmp(d, base, sizeof(d)) != 0);
  write_text("native/engine/libtbb.so.12", "tbb");
  CHECK(bc_native_digest(root, skip, 2, false, d, NULL) && memcmp(d, base, sizeof(d)) != 0);
  work_path(path, "native/engine/libtbb.so.12");
  bc_remove(path);
  write_text("native/engine/lib/libtbb.so.12", "tbb");
  CHECK(bc_native_digest(root, skip, 2, false, d, NULL) && memcmp(d, base, sizeof(d)) == 0);
  /* Without the skip list the game executable and the player count too. */
  CHECK(bc_native_digest(root, NULL, 0, false, d, &scan) && scan.files == 5 && memcmp(d, base, sizeof(d)) != 0);
  work_path(path, "native/missing");
  CHECK(!bc_native_digest(path, NULL, 0, false, d, NULL));

  /* Python level: Python sources count too, bytecode is removed on the way and never counts. */
  CHECK(bc_native_digest(root, skip, 2, true, py, &scan) && scan.files == 5 && scan.bytecode_removed == 1);
  CHECK(memcmp(py, base, sizeof(py)) != 0);
  work_path(path, "native/engine/4.5/python/lib/__pycache__/bge.cpython-311.pyc");
  CHECK(!bc_is_file(path));
  write_text("native/engine/4.5/python/lib/__pycache__/bge.cpython-311.pyc", "written by the last run");
  write_text("native/engine/4.5/python/lib/os.pyc", "sourceless bytecode");
  CHECK(bc_native_digest(root, skip, 2, true, d, &scan) && memcmp(d, py, sizeof(d)) == 0 && scan.bytecode_removed == 2);
  write_text("native/engine/4.5/python/lib/bge.py", "print('patched')");
  CHECK(bc_native_digest(root, skip, 2, true, d, NULL) && memcmp(d, py, sizeof(d)) != 0);
  write_text("native/engine/4.5/python/lib/bge.py", "print('changed')");
  write_text("native/engine/4.5/python/lib/site-packages/sitecustomize.py", "import dump");
  CHECK(bc_native_digest(root, skip, 2, true, d, NULL) && memcmp(d, py, sizeof(d)) != 0);
  work_path(path, "native/engine/4.5/python/lib/site-packages/sitecustomize.py");
  bc_remove(path);
  write_text("native/engine/4.5/python/python311.zip", "zip");
  CHECK(bc_native_digest(root, skip, 2, true, d, NULL) && memcmp(d, py, sizeof(d)) != 0);
  work_path(path, "native/engine/4.5/python/python311.zip");
  bc_remove(path);
  CHECK(bc_native_digest(root, skip, 2, true, d, NULL) && memcmp(d, py, sizeof(d)) == 0);
  write_text("native/game_scripts/__pycache__/menu.cpython-311.pyc", "left by a test run");
  CHECK(bc_remove_bytecode(root, &scan) && scan.bytecode_removed == 1 && scan.files == 0);
  /* Bytecode that cannot be removed (a folder the player cannot write) fails, naming it. Root
   * ignores folder permissions, so this part needs an unprivileged user. */
#ifndef _WIN32
  if (geteuid() != 0) {
    char dir[BC_PATH_MAX];
    write_text("native/locked/x.pyc", "planted");
    work_path(dir, "native/locked");
    chmod(dir, 0555);
    CHECK(!bc_native_digest(root, skip, 2, true, d, &scan) && strstr(scan.locked, "x.pyc") != NULL);
    chmod(dir, 0755);
    CHECK(bc_remove_bytecode(root, NULL));
  }
#endif

  /* Held files: same digest. Windows: nobody can write, replace or delete them until released. */
  BC_NativeHold hold = {NULL, 0, 0};
  CHECK(bc_native_digest_held(root, skip, 2, true, d, &scan, &hold) && memcmp(d, py, sizeof(d)) == 0);
  work_path(path, "native/engine/python311.dll");
#ifdef _WIN32
  CHECK(hold.count == scan.files);
  {
    char moved[BC_PATH_MAX];
    work_path(moved, "native/engine/python311.old");
    FILE *f = bc_fopen(path, "r+b");
    CHECK(f == NULL);
    if (f != NULL) {
      fclose(f);
    }
    CHECK(!bc_rename_replace(path, moved) && !bc_remove(path));
    bc_native_release(&hold);
    f = bc_fopen(path, "r+b");
    CHECK(f != NULL);
    if (f != NULL) {
      fclose(f);
    }
  }
#else
  CHECK(hold.count == 0);
#endif
  bc_native_release(&hold);
  CHECK(hold.handles == NULL && hold.count == 0);

  /* BLAKE3 kernels (SIMD picked at run time) against the Rust reference implementation, on an
   * input large enough to take the widest path the CPU has. */
  {
    static uint8_t data[1 << 20];
    for (size_t i = 0; i < sizeof(data); i++) {
      data[i] = (uint8_t)(i % 251);
    }
    static const uint8_t expected[32] = {0x74, 0xcb, 0x44, 0x1f, 0xd0, 0x87, 0x76, 0x4c, 0xa9, 0xc3, 0x69,
                                         0x4d, 0xa7, 0x42, 0xeb, 0xe3, 0x0c, 0xbe, 0xb3, 0x06, 0x0a, 0x17,
                                         0x00, 0x9c, 0xa8, 0x18, 0x25, 0xc7, 0xa8, 0xd1, 0x03, 0x43};
    uint8_t hash[32];
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, data, sizeof(data));
    blake3_hasher_finalize(&hasher, hash, sizeof(hash));
    CHECK(memcmp(hash, expected, sizeof(hash)) == 0);
  }
}

static void test_seal(void)
{
  /* Sizes around chunk boundaries (64 KiB). */
  const size_t sizes[] = {7, 65535, 65536, 65537, 3 * 65536 + 123};
  for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
    char in_rel[64], out_rel[64], in[BC_PATH_MAX], out[BC_PATH_MAX], err[512];
    snprintf(in_rel, sizeof(in_rel), "seal/in_%zu.blend", sizes[i]);
    snprintf(out_rel, sizeof(out_rel), "seal/out/sub/in_%zu.blend", sizes[i]);
    write_blend(in_rel, sizes[i], (uint32_t)(i + 1));
    work_path(in, in_rel);
    work_path(out, out_rel);
    BC_Sealer s;
    uint8_t hash[BC_PLAIN_HASH_SIZE];
    CHECK(bc_hash_file(in, hash));
    CHECK(bc_seal_begin(&s, bc_build_key(), BC_KIND_BLEND, in, out, hash, hash, err, sizeof(err)));
    int r;
    while ((r = bc_seal_step(&s, err, sizeof(err))) == 1) {
    }
    CHECK(r == 0);
    CHECK(decrypts_to(out_rel, in_rel));
    char tmp[BC_PATH_MAX + 8];
    snprintf(tmp, sizeof(tmp), "%s.tmp", out);
    CHECK(!bc_is_file(tmp));
  }

  /* Deterministic: the same file sealed twice with the same key gives the same bytes (unchanged
   * files stay unchanged in store patches); another key gives other bytes. */
  char in[BC_PATH_MAX], a[BC_PATH_MAX], b[BC_PATH_MAX], c2[BC_PATH_MAX], err[512];
  uint8_t hash[BC_PLAIN_HASH_SIZE];
  work_path(in, "seal/in_65537.blend");
  work_path(a, "seal/twice_a.blend");
  work_path(b, "seal/twice_b.blend");
  work_path(c2, "seal/other_key.blend");
  CHECK(bc_hash_file(in, hash));
  BC_Sealer s;
  CHECK(bc_seal_begin(&s, bc_build_key(), BC_KIND_BLEND, in, a, hash, hash, err, sizeof(err)));
  while (bc_seal_step(&s, err, sizeof(err)) == 1) {
  }
  CHECK(bc_seal_begin(&s, bc_build_key(), BC_KIND_BLEND, in, b, hash, hash, err, sizeof(err)));
  while (bc_seal_step(&s, err, sizeof(err)) == 1) {
  }
  CHECK(bc_seal_begin(&s, OTHER_KEY, BC_KIND_BLEND, in, c2, hash, hash, err, sizeof(err)));
  while (bc_seal_step(&s, err, sizeof(err)) == 1) {
  }
  uint8_t *da = NULL, *db = NULL, *dc = NULL;
  uint64_t na = 0, nb = 0, nc = 0;
  CHECK(bc_test_read_file(a, &da, &na) && bc_test_read_file(b, &db, &nb) && bc_test_read_file(c2, &dc, &nc));
  CHECK(na == nb && memcmp(da, db, (size_t)na) == 0);
  CHECK(na == nc && memcmp(da + BC_HEADER_SIZE, dc + BC_HEADER_SIZE, (size_t)na - BC_HEADER_SIZE) != 0);
  free(da);
  free(db);
  free(dc);

  /* Up to date: made from this source with this key, recognized from the header alone. */
  CHECK(bc_seal_output_is_current(bc_build_key(), BC_KIND_BLEND, a, hash));
  CHECK(!bc_seal_output_is_current(OTHER_KEY, BC_KIND_BLEND, a, hash));
  {
    uint8_t other[BC_PLAIN_HASH_SIZE];
    memcpy(other, hash, sizeof(other));
    other[5] ^= 1;
    CHECK(!bc_seal_output_is_current(bc_build_key(), BC_KIND_BLEND, a, other));
    /* Sealed from a transform of the source (another plaintext hash): still current for the
     * source, with another nonce than the source sealed as it is. */
    CHECK(bc_seal_begin(&s, bc_build_key(), BC_KIND_BLEND, in, c2, hash, other, err, sizeof(err)));
    while (bc_seal_step(&s, err, sizeof(err)) == 1) {
    }
    CHECK(bc_seal_output_is_current(bc_build_key(), BC_KIND_BLEND, c2, other) && !bc_seal_output_is_current(bc_build_key(), BC_KIND_BLEND, c2, hash));
    uint8_t *x = NULL, *y = NULL;
    uint64_t nx = 0, ny = 0;
    CHECK(bc_test_read_file(a, &x, &nx) && bc_test_read_file(c2, &y, &ny));
    CHECK(nx == ny && memcmp(x + BC_OFS_NONCE_PREFIX, y + BC_OFS_NONCE_PREFIX, BC_NONCE_PREFIX_SIZE) != 0);
    free(x);
    free(y);
    /* A truncated container or a damaged header is not current. */
    FILE *f = bc_fopen(c2, "r+b");
    if (f != NULL) {
      fseek(f, BC_OFS_SOURCE_ID, SEEK_SET);
      fputc(0, f);
      fclose(f);
    }
    CHECK(!bc_seal_output_is_current(bc_build_key(), BC_KIND_BLEND, c2, other));
  }

  /* The plaintext must still match the hash the nonce came from: otherwise the output is dropped
   * (a nonce derived from other data must never encrypt this one). */
  uint8_t wrong[BC_PLAIN_HASH_SIZE];
  memcpy(wrong, hash, sizeof(wrong));
  wrong[0] ^= 1;
  bc_remove(b);
  CHECK(bc_seal_begin(&s, bc_build_key(), BC_KIND_BLEND, in, b, wrong, hash, err, sizeof(err)));
  int result;
  while ((result = bc_seal_step(&s, err, sizeof(err))) == 1) {
  }
  CHECK(result < 0 && strstr(err, "changed while") != NULL && !bc_is_file(b));

  /* Refusals: already sealed, not a blend, empty. */
  CHECK(!bc_seal_begin(&s, bc_build_key(), BC_KIND_BLEND, a, b, hash, hash, err, sizeof(err)));
  CHECK(strstr(err, "already encrypted") != NULL);
  write_text("seal/notes.blend", "just text");
  work_path(in, "seal/notes.blend");
  CHECK(!bc_seal_begin(&s, bc_build_key(), BC_KIND_BLEND, in, b, hash, hash, err, sizeof(err)));
  CHECK(strstr(err, "not a .blend") != NULL);
  write_text("seal/empty.blend", "");
  work_path(in, "seal/empty.blend");
  CHECK(!bc_seal_begin(&s, bc_build_key(), BC_KIND_BLEND, in, b, hash, hash, err, sizeof(err)));

  /* zstd compressed blend files (Blender's "Compress" option) are accepted as they are. */
  char zstd_like[32] = "\x28\xb5\x2f\xfd" "compressed payload";
  write_text("seal/compressed.blend", zstd_like);
  work_path(in, "seal/compressed.blend");
  CHECK(bc_seal_begin(&s, bc_build_key(), BC_KIND_BLEND, in, b, hash, hash, err, sizeof(err)));
  bc_seal_abort(&s);

  /* Modules and data files: any content but a container. The kind is in the header (and so in
   * the nonce and the associated data), and an output of another kind is never current. */
  write_text("seal/menu.py", "MENU = 1\n");
  work_path(in, "seal/menu.py");
  work_path(b, "seal/out/menu.py");
  CHECK(bc_hash_file(in, hash));
  CHECK(!bc_seal_begin(&s, bc_build_key(), BC_KIND_BLEND, in, b, hash, hash, err, sizeof(err)) && strstr(err, "not a .blend") != NULL);
  CHECK(bc_seal_begin(&s, bc_build_key(), BC_KIND_PYTHON, in, b, hash, hash, err, sizeof(err)));
  while ((result = bc_seal_step(&s, err, sizeof(err))) == 1) {
  }
  CHECK(result == 0 && decrypts_to("seal/out/menu.py", "seal/menu.py") && sealed_kind("seal/out/menu.py") == BC_KIND_PYTHON);
  CHECK(bc_seal_output_is_current(bc_build_key(), BC_KIND_PYTHON, b, hash));
  CHECK(!bc_seal_output_is_current(bc_build_key(), BC_KIND_DATA, b, hash));
  CHECK(sealed_kind("seal/twice_a.blend") == BC_KIND_BLEND);
  work_path(c2, "seal/out/resealed.bin");
  CHECK(!bc_seal_begin(&s, bc_build_key(), BC_KIND_DATA, b, c2, hash, hash, err, sizeof(err)) && strstr(err, "already encrypted") != NULL);
  CHECK(!bc_is_file(c2));
}

/** "BLENDER" then \a size bytes of text-like data: compresses like real .blend data does. */
static void write_compressible_blend(const char *rel, size_t size)
{
  char path[BC_PATH_MAX], dir[BC_PATH_MAX];
  work_path(path, rel);
  bc_path_dirname(dir, sizeof(dir), path);
  bc_mkdir_p(dir);
  FILE *f = bc_fopen(path, "wb");
  fputs("BLENDER-v405", f);
  for (size_t i = 0; i < size; i++) {
    fputc("vertex normal uv material object mesh "[(i * 7 + i / 64) % 38], f);
  }
  fclose(f);
}

static bool compress_file(const char *in, const char *out, BC_Compressor *c)
{
  char err[512];
  if (!bc_compress_begin(c, in, out, err, sizeof(err))) {
    return false;
  }
  int r;
  while ((r = bc_compress_step(c, err, sizeof(err))) == 1) {
  }
  return r == 0;
}

static void test_compress(void)
{
  CHECK(bc_blend_is_uncompressed((const uint8_t *)"BLENDER-v405", 12));
  CHECK(!bc_blend_is_uncompressed((const uint8_t *)"\x28\xb5\x2f\xfd", 4));
  CHECK(!bc_blend_is_uncompressed((const uint8_t *)"BLEND", 5));

  /* 2.5 frames: what Blender's reader expects of a compressed .blend, frame by frame. */
  const size_t size = 2 * BC_COMPRESS_FRAME_SIZE + BC_COMPRESS_FRAME_SIZE / 2;
  write_compressible_blend("compress/in.blend", size - 12);
  char in[BC_PATH_MAX], out[BC_PATH_MAX], again[BC_PATH_MAX];
  work_path(in, "compress/in.blend");
  work_path(out, "compress/out.zst");
  work_path(again, "compress/again.zst");
  BC_Compressor c;
  CHECK(compress_file(in, out, &c));
  uint8_t *src = NULL, *z = NULL, *z2 = NULL;
  uint64_t src_size = 0, z_size = 0, z2_size = 0;
  CHECK(bc_test_read_file(in, &src, &src_size) && bc_test_read_file(out, &z, &z_size));
  CHECK(src_size == size && z_size == c.out_size && z_size < src_size / 4);
  uint8_t hash[BC_PLAIN_HASH_SIZE];
  CHECK(bc_hash_file(out, hash) && memcmp(hash, c.out_hash, sizeof(hash)) == 0);
  /* Whole stream: every frame, the seek table skipped. */
  uint8_t *unpacked = (uint8_t *)malloc(size + 1);
  CHECK(unpacked != NULL);
  if (unpacked != NULL && src != NULL && z != NULL) {
    const size_t n = ZSTD_decompress(unpacked, size + 1, z, (size_t)z_size);
    CHECK(!ZSTD_isError(n) && n == size && memcmp(unpacked, src, size) == 0);
    /* Seek table at the end: 3 frames, flags 0, magic; then each frame alone. */
    const uint8_t *footer = z + z_size - 9;
    CHECK(footer[0] == 3 && footer[4] == 0 && memcmp(footer + 5, "\xb1\xea\x92\x8f", 4) == 0);
    const uint8_t *table = z + z_size - 9 - 3 * 8;
    CHECK(memcmp(table - 8, "\x5e\x2a\x4d\x18", 4) == 0);
    size_t offset = 0, plain_offset = 0;
    for (int i = 0; i < 3; i++) {
      const uint32_t csize = (uint32_t)table[8 * i] | (uint32_t)table[8 * i + 1] << 8 |
                             (uint32_t)table[8 * i + 2] << 16 | (uint32_t)table[8 * i + 3] << 24;
      const uint32_t usize = (uint32_t)table[8 * i + 4] | (uint32_t)table[8 * i + 5] << 8 |
                             (uint32_t)table[8 * i + 6] << 16 | (uint32_t)table[8 * i + 7] << 24;
      CHECK(usize == (i < 2 ? BC_COMPRESS_FRAME_SIZE : BC_COMPRESS_FRAME_SIZE / 2));
      const size_t n1 = ZSTD_decompress(unpacked, size, z + offset, csize);
      CHECK(!ZSTD_isError(n1) && n1 == usize && memcmp(unpacked, src + plain_offset, usize) == 0);
      offset += csize;
      plain_offset += usize;
    }
  }
  free(unpacked);
  /* Deterministic: the same bytes again. */
  CHECK(compress_file(in, again, &c));
  CHECK(bc_test_read_file(again, &z2, &z2_size) && z2_size == z_size && memcmp(z, z2, (size_t)z_size) == 0);
  free(src);
  free(z);
  free(z2);
  /* A missing input leaves no output. */
  char err[256], missing[BC_PATH_MAX];
  work_path(missing, "compress/missing.blend");
  bc_remove(again);
  CHECK(!bc_compress_begin(&c, missing, again, err, sizeof(err)) && !bc_is_file(again));
}

static void test_keyring(void)
{
  char path[BC_PATH_MAX], err[512];
  BC_KeyRing r, q;
  bc_keyring_init(&r);
  bc_keyring_init(&q);
  /* The one key form (also bc_tool --export-key) reads as update 1. */
  write_text("ring/single.key", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n");
  work_path(path, "ring/single.key");
  CHECK(bc_keyring_load(&r, path, err, sizeof(err)) && r.key_count == 1 && r.updates[0] == 1 && r.keys[0][31] == 0x1f);
  /* Keys stay sorted by update; numbers are unique and start at 1. */
  CHECK(bc_keyring_add(&r, 5) && bc_keyring_add(&r, 3));
  CHECK(!bc_keyring_add(&r, 3) && !bc_keyring_add(&r, 0));
  CHECK(r.updates[0] == 1 && r.updates[1] == 3 && r.updates[2] == 5 && bc_keyring_newest(&r) == 5);
  uint8_t hash[BC_FILE_HASH_SIZE];
  memset(hash, 0xAB, sizeof(hash));
  CHECK(bc_keyring_set_record(&r, "levels/level 1.blend", hash, 3));
  CHECK(bc_keyring_set_record(&r, "game.blend", hash, 1));
  work_path(path, "ring/ring.key");
  CHECK(bc_keyring_save(&r, path, false, err, sizeof(err)));
#ifndef _WIN32
  struct stat st;
  CHECK(stat(path, &st) == 0 && (st.st_mode & 0777) == 0600);
#endif
  CHECK(bc_keyring_load(&q, path, err, sizeof(err)) && q.key_count == 3 && q.record_count == 2);
  CHECK(memcmp(q.keys, r.keys, 3 * BC_KEY_SIZE) == 0 && q.updates[2] == 5);
  const BC_KeyRecord *record = bc_keyring_record(&q, "levels/level 1.blend");
  CHECK(record != NULL && record->update == 3 && memcmp(record->hash, hash, sizeof(hash)) == 0);
  uint8_t id[BC_KEY_ID_SIZE];
  bc_key_id(q.keys[1], id);
  CHECK(bc_keyring_find_id(&q, id) == 1 && bc_keyring_find(&q, 5) == 2 && bc_keyring_find(&q, 4) == -1);
  /* The one key form holds exactly one key. */
  CHECK(!bc_keyring_save(&r, path, true, err, sizeof(err)));
  /* Damaged files are refused with the line. */
  write_text("ring/bad.key", "key 1 nothex\n");
  work_path(path, "ring/bad.key");
  CHECK(!bc_keyring_load(&q, path, err, sizeof(err)) && strstr(err, "line 1") != NULL);
  write_text("ring/mixed.key", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\nkey 2 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n");
  work_path(path, "ring/mixed.key");
  CHECK(!bc_keyring_load(&q, path, err, sizeof(err)));
  write_text("ring/empty.key", "# nothing\n");
  work_path(path, "ring/empty.key");
  CHECK(!bc_keyring_load(&q, path, err, sizeof(err)) && strstr(err, "no key") != NULL);
  bc_keyring_free(&r);
  bc_keyring_free(&q);
}

static void test_project(void)
{
  char path[BC_PATH_MAX], err[512];
  write_text("proj/game.bcproj",
             "# comment\n"
             "version = 1\n"
             "source_root = src\n"
             "output_dir = \" dist with spaces \"\n"
             "player = engine/blenderplayer\n"
             "main = src/game.blend\n"
             "input = src\n"
             "input = src/../src/extra.blend\n");
  work_path(path, "proj/game.bcproj");
  BC_Project p;
  bc_project_init(&p);
  CHECK(bc_project_load(&p, path, err, sizeof(err)));
  char expected[BC_PATH_MAX];
  work_path(expected, "proj/src");
  CHECK_STR(p.source_root, expected);
  work_path(expected, "proj/ dist with spaces ");
  CHECK_STR(p.output_dir, expected);
  CHECK_STR(p.player, "engine/blenderplayer");
  CHECK(p.input_count == 2);
  work_path(expected, "proj/src/extra.blend");
  CHECK(p.input_count == 2 && strcmp(p.inputs[1], expected) == 0);
  /* Per project key by default, its key file next to the project file unless one is chosen. */
  char key_path[BC_PATH_MAX];
  CHECK(p.key_mode == BC_KEY_PROJECT);
  work_path(expected, "proj/game.key");
  CHECK(bc_project_key_file(&p, key_path, sizeof(key_path)));
  CHECK_STR(key_path, expected);

  /* Save then load again: identical project, paths stored relative. */
  char saved[BC_PATH_MAX];
  work_path(saved, "proj/saved.bcproj");
  CHECK(bc_project_save(&p, saved, err, sizeof(err)));
  BC_Project q;
  bc_project_init(&q);
  CHECK(bc_project_load(&q, saved, err, sizeof(err)));
  CHECK_STR(q.source_root, p.source_root);
  CHECK_STR(q.output_dir, p.output_dir);
  CHECK_STR(q.main, p.main);
  CHECK(q.input_count == p.input_count);
  uint8_t *text;
  uint64_t text_size;
  CHECK(bc_test_read_file(saved, &text, &text_size));
  CHECK(text_size > 0 && strstr((char *)text, "source_root = src\n") != NULL);
  CHECK(strstr((char *)text, "key = project\n") != NULL);
  CHECK(strstr((char *)text, "integrity = python\n") != NULL);
  free(text);
  CHECK(q.key_mode == BC_KEY_PROJECT);
  CHECK(q.manifest_mode == BC_MANIFEST_EMBEDDED);
  bc_project_free(&q);

  /* Manifest placement survives a round trip; a missing key means embedded (older projects). */
  p.manifest_mode = BC_MANIFEST_EXTERNAL;
  CHECK(bc_project_save(&p, saved, err, sizeof(err)));
  CHECK(bc_project_load(&q, saved, err, sizeof(err)) && q.manifest_mode == BC_MANIFEST_EXTERNAL);
  bc_project_free(&q);
  bc_project_free(&p);
  /* Branding keys, inline comments and values that need quoting. */
  write_text("proj/brand.bcproj",
             "version = 1   # format version\n"
             "manifest = embedded\t# embedded | external\n"
             "icon = art/game.ico\n"
             "game_version = 1.2.0 # optional\n"
             "company = Studio#1\n"
             "copyright = \"(c) 2026 #1 Studio \"\n");
  work_path(path, "proj/brand.bcproj");
  CHECK(bc_project_load(&p, path, err, sizeof(err)));
  work_path(expected, "proj/art/game.ico");
  CHECK_STR(p.icon, expected);
  CHECK_STR(p.game_version, "1.2.0");
  CHECK_STR(p.company, "Studio#1");
  CHECK_STR(p.copyright, "(c) 2026 #1 Studio ");
  CHECK(bc_project_save(&p, saved, err, sizeof(err)));
  CHECK(bc_project_load(&q, saved, err, sizeof(err)));
  CHECK_STR(q.icon, p.icon);
  CHECK_STR(q.copyright, p.copyright);
  CHECK_STR(q.company, p.company);
  bc_project_free(&q);
  bc_project_free(&p);

  /* Online key settings. */
  write_text("proj/online.bcproj",
             "version = 1\n"
             "key = online\n"
             "key_file = ../keys/game.key\n"
             "key_provider = engine/./bc_provider_steam.exe\n"
             "key_url = https://keys.example.com/key\n"
             "key_cache = permanent\n");
  work_path(path, "proj/online.bcproj");
  CHECK(bc_project_load(&p, path, err, sizeof(err)));
  CHECK(p.key_mode == BC_KEY_ONLINE && p.key_cache);
  work_path(expected, "keys/game.key");
  CHECK_STR(p.key_file, expected);
  CHECK_STR(p.key_provider, "engine/bc_provider_steam.exe");
  CHECK(bc_project_save(&p, saved, err, sizeof(err)) && bc_project_load(&q, saved, err, sizeof(err)));
  CHECK(q.key_mode == BC_KEY_ONLINE && q.key_cache);
  CHECK_STR(q.key_file, p.key_file);
  CHECK_STR(q.key_provider, p.key_provider);
  CHECK_STR(q.key_url, p.key_url);
  bc_project_free(&q);
  bc_project_free(&p);
  write_text("proj/build.bcproj", "version = 1\nkey = build\nintegrity = python\n");
  work_path(path, "proj/build.bcproj");
  CHECK(bc_project_load(&p, path, err, sizeof(err)) && p.key_mode == BC_KEY_BUILD);
  CHECK(p.integrity == BC_INTEGRITY_PYTHON);
  CHECK(bc_project_save(&p, saved, err, sizeof(err)) && bc_project_load(&q, saved, err, sizeof(err)));
  CHECK(q.key_mode == BC_KEY_BUILD && q.integrity == BC_INTEGRITY_PYTHON);
  bc_project_free(&q);
  bc_project_free(&p);
  /* A project never saved has no place for its key file until one is chosen. */
  CHECK(p.key_mode == BC_KEY_PROJECT && !bc_project_key_file(&p, key_path, sizeof(key_path)));
  write_text("proj/bad_key.bcproj", "version = 1\nkey = cloud\n");
  work_path(path, "proj/bad_key.bcproj");
  CHECK(!bc_project_load(&p, path, err, sizeof(err)));
  write_text("proj/bad_integrity.bcproj", "version = 1\nintegrity = everything\n");
  work_path(path, "proj/bad_integrity.bcproj");
  CHECK(!bc_project_load(&p, path, err, sizeof(err)) && strstr(err, "integrity") != NULL);

  write_text("proj/bad_manifest.bcproj", "version = 1\nmanifest = outside\n");
  work_path(path, "proj/bad_manifest.bcproj");
  CHECK(!bc_project_load(&p, path, err, sizeof(err)) && strstr(err, "manifest must be") != NULL);

  /* Data extensions: stored as typed, split by bc_project_data_extensions. */
  {
    char ext[BC_DATA_EXT_MAX][BC_DATA_EXT_SIZE];
    write_text("proj/data.bcproj", "version = 1\ndata_extensions = json, .TXT;*.csv  tar.gz\n");
    work_path(path, "proj/data.bcproj");
    CHECK(bc_project_load(&p, path, err, sizeof(err)));
    CHECK_STR(p.data_extensions, "json, .TXT;*.csv  tar.gz");
    CHECK(bc_project_data_extensions(&p, ext, BC_DATA_EXT_MAX, err, sizeof(err)) == 4);
    CHECK_STR(ext[0], ".json");
    CHECK_STR(ext[1], ".TXT");
    CHECK_STR(ext[2], ".csv");
    CHECK_STR(ext[3], ".tar.gz");
    CHECK(bc_project_save(&p, saved, err, sizeof(err)) && bc_project_load(&q, saved, err, sizeof(err)));
    CHECK_STR(q.data_extensions, p.data_extensions);
    bc_project_free(&q);
    const char *refused[][2] = {{"json py", "Python modules"}, {"blend", "scenes"}, {".DLL", "as code"}, {"pyd", "as code"}, {"j/son", "not a file extension"}, {"json .", "not a file extension"}, {"*", "not a file extension"}};
    for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]); i++) {
      snprintf(p.data_extensions, sizeof(p.data_extensions), "%s", refused[i][0]);
      CHECK(bc_project_data_extensions(&p, ext, BC_DATA_EXT_MAX, err, sizeof(err)) == -1 && strstr(err, refused[i][1]) != NULL);
    }
    snprintf(p.data_extensions, sizeof(p.data_extensions), "a b c");
    CHECK(bc_project_data_extensions(&p, ext, 2, err, sizeof(err)) == -1 && strstr(err, "more than 2") != NULL);
    p.data_extensions[0] = '\0';
    CHECK(bc_project_data_extensions(&p, ext, BC_DATA_EXT_MAX, err, sizeof(err)) == 0);
    bc_project_free(&p);
  }

  /* Strictness. The output always mirrors into another folder: there is no output mode. */
  write_text("proj/typo.bcproj", "version = 1\nsource_rot = src\n");
  work_path(path, "proj/typo.bcproj");
  CHECK(!bc_project_load(&p, path, err, sizeof(err)) && strstr(err, "unknown key") != NULL);
  write_text("proj/mode.bcproj", "version = 1\noutput_mode = inplace\n");
  work_path(path, "proj/mode.bcproj");
  CHECK(!bc_project_load(&p, path, err, sizeof(err)) && strstr(err, "unknown key 'output_mode'") != NULL);
  write_text("proj/version.bcproj", "version = 2\n");
  work_path(path, "proj/version.bcproj");
  CHECK(!bc_project_load(&p, path, err, sizeof(err)));
}

typedef struct LogCapture {
  int errors;
  int warnings;
  bool player_branded;
  int encrypted;
  int up_to_date;
  int copied;
  char last_encrypted[1024];
  char last_error[1024];
  char last_warning[1024];
} LogCapture;

static void capture_log(void *user, BC_LogLevel level, const char *message)
{
  LogCapture *c = (LogCapture *)user;
  if (strstr(message, "Player icon and version information updated") != NULL) {
    c->player_branded = true;
  }
  if (strncmp(message, "Encrypted ", 10) == 0) {
    c->encrypted++;
    snprintf(c->last_encrypted, sizeof(c->last_encrypted), "%s", message);
  }
  c->up_to_date += strncmp(message, "Up to date ", 11) == 0;
  c->copied += strncmp(message, "Copied ", 7) == 0;
  if (level == BC_LOG_WARNING) {
    c->warnings++;
    snprintf(c->last_warning, sizeof(c->last_warning), "%s", message);
  }
  if (level == BC_LOG_ERROR) {
    c->errors++;
    snprintf(c->last_error, sizeof(c->last_error), "%s", message);
  }
}

/* Fake launcher used by the job tests: any file works, the job only copies it. */
static char g_launcher[BC_PATH_MAX];

static int run_job(const BC_Project *p, LogCapture *c)
{
  memset(c, 0, sizeof(*c));
  BC_Job *job = bc_job_create(p, bc_build_key(), g_launcher, capture_log, c);
  if (job == NULL) {
    return -2;
  }
  int r;
  /* A tiny budget exercises resuming across many steps, like the GUI does per frame. */
  while ((r = bc_job_step(job, 0.0)) == 1) {
  }
  bc_job_destroy(job);
  return r;
}

static void test_job(void)
{
  write_blend("job/src/game.blend", 70000, 11);
  write_blend("job/src/levels/one.blend", 1000, 12);
  write_blend("job/src/levels/deep/two.BLEND", 200000, 13);
  write_text("job/src/levels/readme.txt", "not encrypted");
  write_blend("job/src/.git/ignored.blend", 100, 14);
  write_text("job/dist/engine/player", "pretend this is the UPBGE player");
  work_path(g_launcher, "job/tool/bc_launcher");
  write_text("job/tool/bc_launcher", "pretend this is the launcher");
  /* An output folder inside the sources must be skipped by the scan. */
  write_blend("job/src/out_inside/stale.blend", 100, 15);

  BC_Project p;
  bc_project_init(&p);
  p.key_mode = BC_KEY_BUILD; /* decrypts_to() checks with the build key. */
  char path[BC_PATH_MAX];
  work_path(p.source_root, "job/src");
  work_path(p.output_dir, "job/dist");
  snprintf(p.player, sizeof(p.player), "engine/player");
  work_path(p.main, "job/src/game.blend");
  work_path(path, "job/src");
  bc_project_add_input(&p, path);
  work_path(path, "job/src/game.blend"); /* Listed twice on purpose: deduplicated. */
  bc_project_add_input(&p, path);

  LogCapture c;
  CHECK(run_job(&p, &c) == 0);
  CHECK(c.errors == 0);
  CHECK(decrypts_to("job/dist/game.blend", "job/src/game.blend"));
  CHECK(decrypts_to("job/dist/levels/one.blend", "job/src/levels/one.blend"));
  CHECK(decrypts_to("job/dist/levels/deep/two.BLEND", "job/src/levels/deep/two.BLEND"));
  /* Uncompressed .blend files are compressed before sealing. */
  {
    uint8_t *plain = NULL;
    uint64_t plain_size = 0;
    work_path(path, "job/dist/game.blend");
    CHECK(bc_test_decrypt(path, bc_build_key(), &plain, &plain_size) && plain_size >= 4 &&
          memcmp(plain, "\x28\xb5\x2f\xfd", 4) == 0);
    free(plain);
  }
  /* Deterministic: exporting again keeps the outputs (up to date, not even compressed again),
   * and sealing one again from scratch writes the very same bytes. */
  {
    uint8_t *first, *second;
    uint64_t first_size, second_size;
    work_path(path, "job/dist/levels/deep/two.BLEND");
    CHECK(bc_test_read_file(path, &first, &first_size));
    CHECK(run_job(&p, &c) == 0 && c.encrypted == 0 && c.up_to_date > 0);
    const int files = c.up_to_date;
    bc_remove(path);
    CHECK(run_job(&p, &c) == 0 && c.encrypted == 1 && c.up_to_date == files - 1);
    CHECK(bc_test_read_file(path, &second, &second_size));
    CHECK(first_size == second_size && memcmp(first, second, (size_t)first_size) == 0);
    free(first);
    free(second);
    char tmp[BC_PATH_MAX + 16];
    snprintf(tmp, sizeof(tmp), "%s.zst.tmp", path);
    CHECK(!bc_is_file(tmp));
  }
  /* Typical .blend data shrinks; the log says by how much. */
  write_compressible_blend("job/src/levels/text.blend", 300000);
  CHECK(run_job(&p, &c) == 0 && c.encrypted == 1 && strstr(c.last_encrypted, "compressed to") != NULL);
  CHECK(decrypts_to("job/dist/levels/text.blend", "job/src/levels/text.blend"));
  {
    uint64_t sealed_size = 0;
    work_path(path, "job/dist/levels/text.blend");
    CHECK(bc_file_size(path, &sealed_size) && sealed_size < 300000 / 4);
  }
  work_path(path, "job/src/levels/text.blend");
  bc_remove(path);
  work_path(path, "job/dist/levels/text.blend");
  bc_remove(path);
  work_path(path, "job/dist/levels/readme.txt");
  CHECK(!bc_is_file(path));
  work_path(path, "job/dist/.git/ignored.blend");
  CHECK(!bc_is_file(path));

  /* Game executable named after the main file by default, manifest inside. */
  BC_Manifest m;
  char exe_name[64];
  snprintf(exe_name, sizeof(exe_name), "job/dist/game%s", bc_exe_extension());
  work_path(path, exe_name);
  CHECK(bc_embed_read(path, bc_build_key(), &m) == BC_MANIFEST_OK);
  CHECK_STR(m.player_path, "engine/player");
  CHECK_STR(m.main_path, "game.blend");

  /* Explicit game name. */
  snprintf(p.game_name, sizeof(p.game_name), "My Game");
  CHECK(run_job(&p, &c) == 0);
  snprintf(exe_name, sizeof(exe_name), "job/dist/My Game%s", bc_exe_extension());
  work_path(path, exe_name);
  CHECK(bc_embed_read(path, bc_build_key(), &m) == BC_MANIFEST_OK);

  /* Online key: a content key created outside the game folder encrypts the files, the manifest
   * says where the launcher gets it. */
  {
    char key_file[BC_PATH_MAX], game_blend[BC_PATH_MAX];
    write_text("job/dist/engine/provider", "pretend this is a key provider");
    p.key_mode = BC_KEY_ONLINE;
    work_path(p.key_file, "job/content.key");
    snprintf(p.key_provider, sizeof(p.key_provider), "engine/provider");
    snprintf(p.key_url, sizeof(p.key_url), "https://keys.example.com/key");
    CHECK(run_job(&p, &c) == 0 && c.errors == 0 && c.warnings == 1);
    snprintf(key_file, sizeof(key_file), "%s", p.key_file);
    uint8_t *text, content_key[BC_KEY_SIZE], *plain;
    uint64_t text_size, plain_size;
    CHECK(bc_test_read_file(key_file, &text, &text_size));
    text = (uint8_t *)realloc(text, (size_t)text_size + 1);
    text[text_size] = '\0';
    CHECK(bc_key_from_hex((const char *)text, content_key));
    free(text);
    work_path(game_blend, "job/dist/game.blend");
    CHECK(bc_test_decrypt(game_blend, content_key, &plain, &plain_size));
    free(plain);
    CHECK(!decrypts_to("job/dist/game.blend", "job/src/game.blend")); /* Not the build key. */
    CHECK(bc_embed_read(path, bc_build_key(), &m) == BC_MANIFEST_OK);
    uint8_t content_id[BC_KEY_ID_SIZE];
    bc_key_id(content_key, content_id);
    CHECK((m.flags & BC_MANIFEST_KEY_FLAGS) == BC_MANIFEST_ONLINE_KEY && m.key_count == 1 && memcmp(m.key_ids[0], content_id, BC_KEY_ID_SIZE) == 0);
    CHECK_STR(m.provider_path, "engine/provider");
    CHECK_STR(m.key_url, "https://keys.example.com/key");
    /* The next export reuses the key. */
    CHECK(run_job(&p, &c) == 0 && c.errors == 0 && c.warnings == 0);
    CHECK(bc_test_decrypt(game_blend, content_key, &plain, &plain_size));
    free(plain);
    /* Refusals: a key file that would ship, a missing provider. */
    work_path(p.key_file, "job/dist/content.key");
    CHECK(run_job(&p, &c) == -2 && strstr(c.last_error, "inside the game folder") != NULL);
    snprintf(p.key_file, sizeof(p.key_file), "%s", key_file);
    snprintf(p.key_provider, sizeof(p.key_provider), "engine/missing");
    CHECK(run_job(&p, &c) == -2 && strstr(c.last_error, "Key provider not found") != NULL);
    write_text("job/bad.key", "not a key");
    work_path(p.key_file, "job/bad.key");
    snprintf(p.key_provider, sizeof(p.key_provider), "engine/provider");
    CHECK(run_job(&p, &c) == -2 && strstr(c.last_error, "key file") != NULL);

    /* Key per update. Update 1 seals everything with key 1. */
    BC_KeyRing ring;
    char err[512], one_out[BC_PATH_MAX];
    uint8_t *one_before, *one_after, *game_before, *game_after;
    uint64_t one_before_size, one_after_size, game_before_size, game_after_size;
    bc_keyring_init(&ring);
    work_path(p.key_file, "job/ring.key");
    work_path(one_out, "job/dist/levels/one.blend");
    p.key_rotation = true;
    p.key_update = 1;
    CHECK(run_job(&p, &c) == 0 && c.errors == 0 && c.warnings == 1);
    CHECK(bc_keyring_load(&ring, p.key_file, err, sizeof(err)) && ring.key_count == 1 && ring.updates[0] == 1);
    CHECK(ring.record_count >= 3 && bc_keyring_record(&ring, "levels/one.blend") != NULL);
    CHECK(bc_embed_read(path, bc_build_key(), &m) == BC_MANIFEST_OK && m.key_count == 1);
    CHECK(bc_test_read_file(one_out, &one_before, &one_before_size));
    CHECK(bc_test_read_file(game_blend, &game_before, &game_before_size));
    /* Exporting the same update again (between releases) changes nothing at all. */
    CHECK(run_job(&p, &c) == 0 && c.errors == 0 && c.warnings == 0);
    CHECK(bc_test_read_file(game_blend, &game_after, &game_after_size));
    CHECK(game_after_size == game_before_size && memcmp(game_after, game_before, (size_t)game_after_size) == 0);
    free(game_after);
    /* Update 2 changes game.blend only: it gets key 2, the other files keep key 1 byte for byte. */
    write_blend("job/src/game.blend", 70000, 99);
    p.key_update = 2;
    CHECK(run_job(&p, &c) == 0 && c.errors == 0 && c.warnings == 1);
    CHECK(bc_keyring_load(&ring, p.key_file, err, sizeof(err)) && ring.key_count == 2);
    CHECK(bc_test_read_file(one_out, &one_after, &one_after_size));
    CHECK(one_after_size == one_before_size && memcmp(one_after, one_before, (size_t)one_after_size) == 0);
    CHECK(bc_test_decrypt(one_out, ring.keys[0], &plain, &plain_size));
    free(plain);
    CHECK(bc_test_decrypt(game_blend, ring.keys[1], &plain, &plain_size));
    free(plain);
    CHECK(!bc_test_decrypt(game_blend, ring.keys[0], &plain, &plain_size));
    const BC_KeyRecord *record = bc_keyring_record(&ring, "game.blend");
    CHECK(record != NULL && record->update == 2);
    uint8_t ids[2][BC_KEY_ID_SIZE];
    bc_key_id(ring.keys[0], ids[0]);
    bc_key_id(ring.keys[1], ids[1]);
    CHECK(bc_embed_read(path, bc_build_key(), &m) == BC_MANIFEST_OK && m.key_count == 2);
    CHECK(memcmp(m.key_ids, ids, sizeof(ids)) == 0);
    free(one_before);
    free(one_after);
    free(game_before);
    /* The update number cannot go back. */
    p.key_update = 1;
    CHECK(run_job(&p, &c) == -2 && strstr(c.last_error, "cannot go back") != NULL);
    /* An update without changes adds a key nobody uses: the manifest only names used keys. */
    p.key_update = 3;
    CHECK(run_job(&p, &c) == 0 && c.errors == 0);
    CHECK(bc_embed_read(path, bc_build_key(), &m) == BC_MANIFEST_OK && m.key_count == 2);
    /* Switching back to one key: everything is sealed with the newest key, the key file keeps its
     * keys and records. */
    p.key_rotation = false;
    CHECK(run_job(&p, &c) == 0 && c.errors == 0);
    CHECK(bc_embed_read(path, bc_build_key(), &m) == BC_MANIFEST_OK && m.key_count == 1);
    CHECK(bc_keyring_load(&ring, p.key_file, err, sizeof(err)) && ring.key_count == 3 && ring.record_count >= 3);
    bc_keyring_free(&ring);
    write_blend("job/src/game.blend", 70000, 11);
    p.key_update = 0;

    p.key_mode = BC_KEY_BUILD;
    CHECK(run_job(&p, &c) == 0);
  }

  /* Per project key: created in a key file outside the game folder, carried masked in the
   * manifest. A scan of the game executable for the key finds nothing. */
  {
    char game_blend[BC_PATH_MAX], key_file[BC_PATH_MAX], err[512];
    uint8_t project_key[BC_KEY_SIZE], mask[BC_KEY_SIZE], unmasked[BC_KEY_SIZE], id[BC_KEY_ID_SIZE];
    uint8_t *before, *after;
    uint64_t before_size, after_size;
    BC_KeyRing ring;
    work_path(game_blend, "job/dist/game.blend");
    p.key_mode = BC_KEY_PROJECT;
    p.key_file[0] = '\0';
    CHECK(run_job(&p, &c) == -2 && strstr(c.last_error, "Choose a key file") != NULL);
    work_path(key_file, "job/project.key");
    bc_remove(key_file);
    snprintf(p.key_file, sizeof(p.key_file), "%s", key_file);
    CHECK(run_job(&p, &c) == 0 && c.errors == 0 && c.warnings == 1);
    bc_keyring_init(&ring);
    CHECK(bc_keyring_load(&ring, key_file, err, sizeof(err)) && ring.key_count == 1);
    memcpy(project_key, ring.keys[0], BC_KEY_SIZE);
    bc_keyring_free(&ring);
    CHECK(decrypts_with(game_blend, project_key));
    CHECK(!decrypts_to("job/dist/game.blend", "job/src/game.blend"));
    CHECK(bc_embed_read(path, bc_build_key(), &m) == BC_MANIFEST_OK);
    CHECK((m.flags & BC_MANIFEST_KEY_FLAGS) == BC_MANIFEST_PROJECT_KEY && m.key_count == 1);
    /* The Python level is the default: the digest of the game folder's code and Python files,
     * without the game executable and the player. */
    {
      char dist[BC_PATH_MAX], exe_rel[BC_PATH_MAX];
      uint8_t digest[BC_NATIVE_DIGEST_SIZE];
      work_path(dist, "job/dist");
      CHECK(bc_path_relative(exe_rel, sizeof(exe_rel), dist, path));
      const char *skip[2] = {exe_rel, m.player_path};
      CHECK((m.flags & BC_MANIFEST_NATIVE_DIGEST) && (m.flags & BC_MANIFEST_PYTHON_CHECK));
      CHECK(bc_native_digest(dist, skip, 2, true, digest, NULL));
      CHECK(memcmp(digest, m.native_digest, BC_NATIVE_DIGEST_SIZE) == 0);
      p.integrity = BC_INTEGRITY_NATIVE;
      CHECK(run_job(&p, &c) == 0 && bc_embed_read(path, bc_build_key(), &m) == BC_MANIFEST_OK);
      CHECK((m.flags & BC_MANIFEST_NATIVE_DIGEST) && !(m.flags & BC_MANIFEST_PYTHON_CHECK));
      CHECK(bc_native_digest(dist, skip, 2, false, digest, NULL));
      CHECK(memcmp(digest, m.native_digest, BC_NATIVE_DIGEST_SIZE) == 0);
      p.integrity = BC_INTEGRITY_PLAYER;
      CHECK(run_job(&p, &c) == 0 && bc_embed_read(path, bc_build_key(), &m) == BC_MANIFEST_OK);
      CHECK(!(m.flags & (BC_MANIFEST_NATIVE_DIGEST | BC_MANIFEST_PYTHON_CHECK)));
      /* Python level: the bytecode left by a test run is removed by the export. */
      char pyc[BC_PATH_MAX];
      write_text("job/dist/scripts/__pycache__/menu.cpython-311.pyc", "left by a test run");
      write_text("job/dist/scripts/menu.py", "print()");
      work_path(pyc, "job/dist/scripts/__pycache__/menu.cpython-311.pyc");
      p.integrity = BC_INTEGRITY_PYTHON;
      CHECK(run_job(&p, &c) == 0 && bc_embed_read(path, bc_build_key(), &m) == BC_MANIFEST_OK);
      CHECK((m.flags & BC_MANIFEST_NATIVE_DIGEST) && (m.flags & BC_MANIFEST_PYTHON_CHECK) && !bc_is_file(pyc));
      CHECK(bc_native_digest(dist, skip, 2, true, digest, NULL));
      CHECK(memcmp(digest, m.native_digest, BC_NATIVE_DIGEST_SIZE) == 0);
      work_path(pyc, "job/dist/scripts/menu.py");
      bc_remove(pyc);
      p.integrity = BC_INTEGRITY_NATIVE;
      CHECK(run_job(&p, &c) == 0 && bc_embed_read(path, bc_build_key(), &m) == BC_MANIFEST_OK);
    }
    bc_key_id(project_key, id);
    CHECK(memcmp(m.key_ids[0], id, BC_KEY_ID_SIZE) == 0);
    bc_manifest_key_mask(bc_build_key(), &m, mask);
    for (int i = 0; i < BC_KEY_SIZE; i++) {
      unmasked[i] = m.masked_key[i] ^ mask[i];
    }
    CHECK(memcmp(unmasked, project_key, BC_KEY_SIZE) == 0);
    CHECK(!file_holds_key(path, id));
    /* Control: the same scan finds a key stored in one piece, wherever it is. */
    {
      char planted[BC_PATH_MAX];
      work_path(planted, "job/planted.bin");
      FILE *f = bc_fopen(planted, "wb");
      for (int i = 0; i < 4097; i++) {
        fputc((i * 131) & 0xff, f);
      }
      fwrite(project_key, 1, BC_KEY_SIZE, f);
      fputs("trailing bytes", f);
      fclose(f);
      CHECK(file_holds_key(planted, id));
      bc_remove(planted);
    }
    /* The next export reuses the key: unchanged files keep their bytes, and are not even
     * encrypted or written again. */
    CHECK(bc_test_read_file(game_blend, &before, &before_size));
    CHECK(run_job(&p, &c) == 0 && c.errors == 0 && c.warnings == 0);
    CHECK(c.encrypted == 0 && c.up_to_date >= 3);
    CHECK(bc_test_read_file(game_blend, &after, &after_size));
    CHECK(before_size == after_size && memcmp(before, after, (size_t)after_size) == 0);
    free(after);
    /* A truncated or grown output is sealed again; damage past the header keeps the size and the
     * header, so the export trusts it (the player's MAC check catches it). */
    {
      FILE *f = bc_fopen(game_blend, "ab");
      fputc(0, f);
      fclose(f);
      CHECK(run_job(&p, &c) == 0 && c.encrypted == 1);
      CHECK(bc_test_read_file(game_blend, &after, &after_size));
      CHECK(before_size == after_size && memcmp(before, after, (size_t)after_size) == 0);
      free(after);
      f = bc_fopen(game_blend, "r+b");
      fseek(f, -1, SEEK_END);
      fputc(0x5A, f);
      fclose(f);
      CHECK(run_job(&p, &c) == 0 && c.encrypted == 0);
      CHECK(!decrypts_with(game_blend, project_key));
      bc_remove(game_blend);
      CHECK(run_job(&p, &c) == 0 && c.encrypted == 1 && decrypts_with(game_blend, project_key));
    }
    free(before);
    /* A key per update needs the key server: still one key, with a warning. */
    p.key_rotation = true;
    p.key_update = 2;
    CHECK(run_job(&p, &c) == 0 && c.errors == 0 && c.warnings == 1);
    CHECK(bc_embed_read(path, bc_build_key(), &m) == BC_MANIFEST_OK && m.key_count == 1);
    CHECK(memcmp(m.key_ids[0], id, BC_KEY_ID_SIZE) == 0);
    p.key_rotation = false;
    p.key_update = 0;
    /* A key file inside the game folder would ship with it. */
    work_path(p.key_file, "job/dist/project.key");
    CHECK(run_job(&p, &c) == -2 && strstr(c.last_error, "inside the game folder") != NULL);
    /* No key file chosen: next to the project file, named after it. */
    p.key_file[0] = '\0';
    work_path(p.project_file, "job/game.bcproj");
    work_path(key_file, "job/game.key");
    bc_remove(key_file);
    CHECK(run_job(&p, &c) == 0 && c.errors == 0 && strstr(c.last_warning, "Created the project key") != NULL);
    CHECK(bc_is_file(key_file));
    p.project_file[0] = '\0';
    p.key_mode = BC_KEY_BUILD;
    CHECK(run_job(&p, &c) == 0);
  }

  /* External manifest: untouched launcher copy plus the manifest file; going back to embedded
   * removes the file so a game folder never ships both. */
  {
    char manifest_file[BC_PATH_MAX];
    work_path(manifest_file, "job/dist/" BC_MANIFEST_FILENAME);
    p.manifest_mode = BC_MANIFEST_EXTERNAL;
    CHECK(run_job(&p, &c) == 0 && c.errors == 0);
    CHECK(bc_embed_read(path, bc_build_key(), &m) == BC_MANIFEST_MISSING);
    uint8_t *exe = NULL, *launcher = NULL;
    uint64_t exe_size = 0, launcher_size = 0;
    CHECK(bc_test_read_file(path, &exe, &exe_size) &&
          bc_test_read_file(g_launcher, &launcher, &launcher_size));
    CHECK(exe_size == launcher_size && memcmp(exe, launcher, (size_t)exe_size) == 0);
    free(exe);
    free(launcher);
    CHECK(bc_manifest_file_read(manifest_file, bc_build_key(), &m) == BC_MANIFEST_OK);
    CHECK_STR(m.main_path, "game.blend");
    p.manifest_mode = BC_MANIFEST_EMBEDDED;
    CHECK(run_job(&p, &c) == 0 && c.errors == 0);
    CHECK(!bc_is_file(manifest_file));
    CHECK(bc_embed_read(path, bc_build_key(), &m) == BC_MANIFEST_OK);
#ifndef _WIN32
    /* The game executable must not take the manifest file's name in either mode. */
    snprintf(p.game_name, sizeof(p.game_name), BC_MANIFEST_FILENAME);
    CHECK(run_job(&p, &c) == -2 && strstr(c.last_error, BC_MANIFEST_FILENAME) != NULL);
    snprintf(p.game_name, sizeof(p.game_name), "My Game");
#endif
  }

  /* An old encrypted output found while scanning is skipped with a warning, not re-encrypted. */
  {
    uint8_t *sealed;
    uint64_t sealed_size;
    char from[BC_PATH_MAX], to[BC_PATH_MAX];
    work_path(from, "job/dist/game.blend");
    work_path(to, "job/src/levels/old_output.blend");
    CHECK(bc_test_read_file(from, &sealed, &sealed_size));
    FILE *f = bc_fopen(to, "wb");
    fwrite(sealed, 1, (size_t)sealed_size, f);
    fclose(f);
    free(sealed);
    CHECK(run_job(&p, &c) == 0);
    CHECK(c.errors == 0 && c.warnings == 1);
    work_path(path, "job/dist/levels/old_output.blend");
    CHECK(!bc_is_file(path));
    bc_remove(to);
  }

  /* Python modules and data files, mirror output only. Folders give .py files and the data
   * extensions, any file can be listed; empty ones are copied as they are. */
  {
    char empty[BC_PATH_MAX];
    uint64_t size = 1;
    write_text("job/src/scripts/__init__.py", "");
    write_text("job/src/scripts/menu.py", "import json\nMENU = 1\n");
    write_text("job/src/data/level.json", "{\"level\": 1}");
    write_text("job/src/data/empty.json", "");
    write_text("job/src/data/notes.md", "not a data extension");
    write_text("job/src/data/listed.bin", "listed on its own");
    work_path(path, "job/src/data/listed.bin");
    bc_project_add_input(&p, path);
    snprintf(p.data_extensions, sizeof(p.data_extensions), "json");
    CHECK(run_job(&p, &c) == 0 && c.errors == 0 && c.copied == 2);
    CHECK(decrypts_to("job/dist/scripts/menu.py", "job/src/scripts/menu.py") && sealed_kind("job/dist/scripts/menu.py") == BC_KIND_PYTHON);
    CHECK(decrypts_to("job/dist/data/level.json", "job/src/data/level.json") && sealed_kind("job/dist/data/level.json") == BC_KIND_DATA);
    CHECK(decrypts_to("job/dist/data/listed.bin", "job/src/data/listed.bin") && sealed_kind("job/dist/data/listed.bin") == BC_KIND_DATA);
    CHECK(sealed_kind("job/dist/game.blend") == BC_KIND_BLEND);
    work_path(empty, "job/dist/scripts/__init__.py");
    CHECK(bc_is_file(empty) && bc_file_size(empty, &size) && size == 0);
    work_path(empty, "job/dist/data/empty.json");
    CHECK(bc_is_file(empty) && bc_file_size(empty, &size) && size == 0);
    work_path(path, "job/dist/data/notes.md");
    CHECK(!bc_is_file(path));
    /* Unchanged: nothing written again, empty copies included. */
    CHECK(run_job(&p, &c) == 0 && c.encrypted == 0 && c.copied == 0 && c.up_to_date >= 7);
    /* Online keys: an empty copy uses no key, the manifest names the one the others use. */
    p.key_mode = BC_KEY_ONLINE;
    work_path(p.key_file, "job/content.key");
    snprintf(p.key_provider, sizeof(p.key_provider), "engine/provider");
    CHECK(run_job(&p, &c) == 0 && c.errors == 0);
    work_path(path, exe_name);
    CHECK(bc_embed_read(path, bc_build_key(), &m) == BC_MANIFEST_OK && m.key_count == 1);
    p.key_mode = BC_KEY_BUILD;
    p.key_file[0] = p.key_provider[0] = '\0';
    CHECK(run_job(&p, &c) == 0 && c.errors == 0);
    /* Refusals: the main file is a scene, data extensions are data. */
    work_path(p.main, "job/src/scripts/menu.py");
    CHECK(run_job(&p, &c) == -2 && strstr(c.last_error, "must be a .blend") != NULL);
    work_path(p.main, "job/src/game.blend");
    snprintf(p.data_extensions, sizeof(p.data_extensions), "json py");
    CHECK(run_job(&p, &c) == -2 && strstr(c.last_error, "Data files:") != NULL);
    p.data_extensions[0] = '\0';
    const char *remove[] = {"job/src/scripts/__init__.py", "job/src/scripts/menu.py", "job/src/data/level.json", "job/src/data/empty.json", "job/src/data/notes.md", "job/src/data/listed.bin"};
    for (size_t i = 0; i < sizeof(remove) / sizeof(remove[0]); i++) {
      work_path(path, remove[i]);
      bc_remove(path);
    }
    bc_project_clear_inputs(&p);
    work_path(path, "job/src");
    bc_project_add_input(&p, path);
  }

  /* Mirror output inside the source tree: its content is not encrypted again. */
  work_path(p.output_dir, "job/src/out_inside");
  write_text("job/src/out_inside/engine/player", "player");
  CHECK(run_job(&p, &c) == 0);
  work_path(path, "job/src/out_inside/out_inside/stale.blend");
  CHECK(!bc_is_file(path));
  CHECK(decrypts_to("job/src/out_inside/game.blend", "job/src/game.blend"));
#ifndef _WIN32
  /* Branding settings only matter for Windows games: ignored with a warning elsewhere. */
  snprintf(p.company, sizeof(p.company), "Studio");
  CHECK(run_job(&p, &c) == 0 && c.errors == 0 && c.warnings == 1);
  p.company[0] = '\0';
#endif

  /* Refusals with a precise reason. Encrypting into the source folder itself is not possible: the
   * outputs keep the sources' names. */
  p.output_dir[0] = '\0';
  CHECK(run_job(&p, &c) == -2 && strstr(c.last_error, "output folder is not set") != NULL);
  work_path(p.output_dir, "job/dist");
  snprintf(p.player, sizeof(p.player), "engine/missing");
  CHECK(run_job(&p, &c) == -2 && strstr(c.last_error, "Player not found") != NULL);
  snprintf(p.player, sizeof(p.player), "../outside");
  CHECK(run_job(&p, &c) == -2 && strstr(c.last_error, "relative path") != NULL);
  snprintf(p.player, sizeof(p.player), "engine/player");
  work_path(p.main, "job/src/elsewhere.blend");
  CHECK(run_job(&p, &c) == -2 && strstr(c.last_error, "not among") != NULL);
  work_path(p.main, "job/src/game.blend");
  work_path(p.output_dir, "job/src");
  CHECK(run_job(&p, &c) == -2 && strstr(c.last_error, "must not be") != NULL);
  work_path(p.output_dir, "job");
  CHECK(run_job(&p, &c) == -2 && strstr(c.last_error, "must not be") != NULL);
  work_path(p.output_dir, "job/dist");
  const char *bad_names[] = {"a/b", "x:y", "trailing.", "trailing ", "..", "q?"};
  for (size_t i = 0; i < sizeof(bad_names) / sizeof(bad_names[0]); i++) {
    snprintf(p.game_name, sizeof(p.game_name), "%s", bad_names[i]);
    CHECK(run_job(&p, &c) == -2 && strstr(c.last_error, "not a valid game name") != NULL);
  }
#ifndef _WIN32
  /* Without ".exe" the name can collide with the runtime folder or an encrypted output (on
   * Windows "engine.exe" and "game.blend.exe" are distinct files, so both are valid there). */
  snprintf(p.game_name, sizeof(p.game_name), "engine");
  CHECK(run_job(&p, &c) == -2 && strstr(c.last_error, "clashes") != NULL);
  snprintf(p.game_name, sizeof(p.game_name), "game.blend");
  CHECK(run_job(&p, &c) == -2 && strstr(c.last_error, "would overwrite") != NULL);
#endif
  p.game_name[0] = '\0';
  work_path(g_launcher, "job/tool/missing_launcher");
  CHECK(run_job(&p, &c) == -2 && strstr(c.last_error, "Launcher not found") != NULL);
  bc_project_free(&p);
}

#ifdef _WIN32
/** Through the job: the player is branded before hashing, the game executable before the manifest
 * is appended, and an already branded player is never rewritten. */
static void test_brand_job(void)
{
  char self[BC_PATH_MAX], player[BC_PATH_MAX], launcher[BC_PATH_MAX], icon[BC_PATH_MAX];
  char game[BC_PATH_MAX], before[BC_PATH_MAX], manifest_file[BC_PATH_MAX], text[256];
  CHECK(bc_exe_path(self, sizeof(self)));
  work_path(player, "bjob/dist/engine/player.exe");
  work_path(launcher, "bjob/tool/bc_launcher.exe");
  copy_file(self, player);
  copy_file(self, launcher);
  write_blend("bjob/src/game.blend", 5000, 21);
  const int sizes[] = {16, 32, 256};
  size_t size;
  uint8_t *ico = make_ico(sizes, 3, 0xFF336699, &size);
  work_path(icon, "bjob/game.ico");
  FILE *f = bc_fopen(icon, "wb");
  fwrite(ico, 1, size, f);
  fclose(f);

  BC_Project p;
  bc_project_init(&p);
  p.key_mode = BC_KEY_BUILD;
  work_path(p.source_root, "bjob/src");
  work_path(p.output_dir, "bjob/dist");
  snprintf(p.player, sizeof(p.player), "engine/player.exe");
  work_path(p.main, "bjob/src/game.blend");
  bc_project_add_input(&p, p.main);
  snprintf(p.game_name, sizeof(p.game_name), "Branded");
  snprintf(p.icon, sizeof(p.icon), "%s", icon);
  snprintf(p.game_version, sizeof(p.game_version), "3.1");
  snprintf(p.company, sizeof(p.company), "Studio");
  char saved_launcher[BC_PATH_MAX];
  snprintf(saved_launcher, sizeof(saved_launcher), "%s", g_launcher);
  snprintf(g_launcher, sizeof(g_launcher), "%s", launcher);

  LogCapture c;
  CHECK(run_job(&p, &c) == 0 && c.errors == 0 && c.player_branded);
  work_path(game, "bjob/dist/Branded.exe");
  BC_Manifest m;
  CHECK(bc_embed_read(game, bc_build_key(), &m) == BC_MANIFEST_OK);
  /* The manifest authenticates the player as shipped, i.e. branded. */
  uint8_t *data;
  uint64_t n;
  uint8_t hash[BC_PLAYER_HASH_SIZE];
  CHECK(bc_test_read_file(player, &data, &n));
  blake3_hasher hasher;
  blake3_hasher_init(&hasher);
  blake3_hasher_update(&hasher, data, (size_t)n);
  blake3_hasher_finalize(&hasher, hash, sizeof(hash));
  free(data);
  CHECK(memcmp(hash, m.player_hash, sizeof(hash)) == 0);
  CHECK(exe_group_equals_ico(player, L"APPICON", ico));
  CHECK(exe_group_equals_ico(game, L"APPICON", ico));
  CHECK(exe_version_string(player, L"FileDescription", text, sizeof(text)) && strcmp(text, "Branded") == 0);
  CHECK(exe_version_string(player, L"OriginalFilename", text, sizeof(text)) && strcmp(text, "player.exe") == 0);
  CHECK(exe_version_string(game, L"OriginalFilename", text, sizeof(text)) && strcmp(text, "Branded.exe") == 0);
  CHECK(exe_version_string(game, L"FileVersion", text, sizeof(text)) && strcmp(text, "3.1.0.0") == 0);

  /* Exporting again leaves the branded player byte for byte as it is. */
  work_path(before, "bjob/player_before.exe");
  copy_file(player, before);
  CHECK(run_job(&p, &c) == 0 && c.errors == 0 && !c.player_branded);
  CHECK(same_file(player, before));

  /* External manifest: branded executable, manifest in its file. */
  p.manifest_mode = BC_MANIFEST_EXTERNAL;
  CHECK(run_job(&p, &c) == 0 && c.errors == 0);
  work_path(manifest_file, "bjob/dist/" BC_MANIFEST_FILENAME);
  CHECK(bc_embed_read(game, bc_build_key(), &m) == BC_MANIFEST_MISSING);
  CHECK(bc_manifest_file_read(manifest_file, bc_build_key(), &m) == BC_MANIFEST_OK);
  CHECK(exe_group_equals_ico(game, L"APPICON", ico));
  p.manifest_mode = BC_MANIFEST_EMBEDDED;

  /* Invalid settings fail before any output is written. */
  snprintf(p.game_version, sizeof(p.game_version), "1.x");
  CHECK(run_job(&p, &c) == -2 && strstr(c.last_error, "not a version") != NULL);
  snprintf(p.game_version, sizeof(p.game_version), "3.1");
  write_text("bjob/bad.ico", "not an icon");
  work_path(p.icon, "bjob/bad.ico");
  CHECK(run_job(&p, &c) == -2 && strstr(c.last_error, "Invalid icon") != NULL);
  char tmp[BC_PATH_MAX + 16];
  snprintf(tmp, sizeof(tmp), "%s.brand.tmp", game);
  CHECK(!bc_is_file(tmp));

  snprintf(g_launcher, sizeof(g_launcher), "%s", saved_launcher);
  free(ico);
  bc_project_free(&p);
}
#endif

int main(int argc, char **argv)
{
  /* Helper for the end to end test: a valid multi-size .ico. */
  if (argc == 3 && strcmp(argv[1], "--write-ico") == 0) {
    const int sizes[] = {16, 32, 48, 256};
    size_t size;
    uint8_t *ico = make_ico(sizes, 4, 0xFF2080F0, &size);
    FILE *f = bc_fopen(argv[2], "wb");
    const bool ok = f != NULL && fwrite(ico, 1, size, f) == size;
    if (f != NULL) {
      fclose(f);
    }
    free(ico);
    return ok ? 0 : 1;
  }
  /* Helper for the end to end test: run <exe> with an inheritable pipe holding a marker, its
   * value in BC_TEST_LEAK, as a store client or a script might leave one. The launcher must not
   * pass it on to the player (bc_fake_player checks). Exits with <exe>'s exit code. */
  if (argc == 3 && strcmp(argv[1], "--spawn-leaking") == 0) {
#ifdef _WIN32
    HANDLE read_end, write_end;
    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
    DWORD written = 0;
    if (!CreatePipe(&read_end, &write_end, &sa, 0) || !WriteFile(write_end, "LEAKED", 6, &written, NULL)) {
      return 2;
    }
    char value[32];
    snprintf(value, sizeof(value), "%llu", (unsigned long long)(uintptr_t)read_end);
    SetEnvironmentVariableA("BC_TEST_LEAK", value);
    wchar_t *wexe = bc_utf16(argv[2]);
    wchar_t cmd[BC_PATH_MAX + 2];
    swprintf(cmd, BC_PATH_MAX + 2, L"\"%ls\"", wexe);
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    if (!CreateProcessW(wexe, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
      return 2;
    }
    free(wexe);
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 2;
    GetExitCodeProcess(pi.hProcess, &code);
    return (int)code;
#else
    int fds[2];
    if (pipe(fds) != 0 || write(fds[1], "LEAKED", 6) != 6) {
      return 2;
    }
    char value[32];
    snprintf(value, sizeof(value), "%d", fds[0]);
    setenv("BC_TEST_LEAK", value, 1);
    const pid_t pid = fork();
    if (pid == 0) {
      execl(argv[2], argv[2], (char *)NULL);
      _exit(127);
    }
    int status = 0;
    if (pid < 0 || waitpid(pid, &status, 0) < 0) {
      return 2;
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : 2;
#endif
  }
  /* Helper for the end to end test: does <file> hold, in one piece, the key <container> is
   * encrypted with? Prints the answer; exit 2 only when a file cannot be read. */
  if (argc == 4 && strcmp(argv[1], "--find-key") == 0) {
    uint8_t *container, id[BC_KEY_ID_SIZE];
    uint64_t size;
    if (!bc_test_read_file(argv[3], &container, &size)) {
      return 2;
    }
    const bool valid = size >= BC_HEADER_SIZE;
    if (valid) {
      memcpy(id, container + BC_OFS_KEY_ID, BC_KEY_ID_SIZE);
    }
    free(container);
    uint8_t *probe;
    if (!valid || !bc_test_read_file(argv[2], &probe, &size)) {
      return 2;
    }
    free(probe);
    printf("%s\n", file_holds_key(argv[2], id) ? "key found" : "key not found");
    return 0;
  }
  if (argc != 2 || !bc_path_make_absolute(g_work, sizeof(g_work), argv[1]) ||
      !bc_mkdir_p(g_work))
  {
    fprintf(stderr, "usage: bc_tests <work folder>\n");
    return 2;
  }
  test_paths();
  test_key_hex();
  test_manifest();
  test_envelope();
  test_embed();
  test_native();
  test_seal();
  test_compress();
  test_project();
  test_brand();
  test_keyring();
  test_job();
#ifdef _WIN32
  test_brand_job();
#endif
  if (g_failures != 0) {
    fprintf(stderr, "%d check(s) failed\n", g_failures);
    return 1;
  }
  printf("all checks passed\n");
  return 0;
}
