/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "bc_manifest.h"

#include <string.h>

bool bc_manifest_path_is_safe(const char *path)
{
  if (path[0] == '\0' || path[0] == '/' || strchr(path, '\\') || strchr(path, ':')) {
    return false;
  }
  /* Reject ".." as a whole segment; names merely containing dots are fine. */
  for (const char *segment = path; segment != NULL;) {
    const char *slash = strchr(segment, '/');
    const size_t n = slash ? (size_t)(slash - segment) : strlen(segment);
    if (n == 0 || (n == 2 && segment[0] == '.' && segment[1] == '.')) {
      return false;
    }
    segment = slash ? slash + 1 : NULL;
  }
  return true;
}

static void bc_manifest_mac(const uint8_t key[BC_KEY_SIZE],
                            const uint8_t *body,
                            size_t body_size,
                            uint8_t mac[BC_MANIFEST_MAC_SIZE])
{
  crypto_blake2b_ctx ctx;
  crypto_blake2b_keyed_init(&ctx, BC_MANIFEST_MAC_SIZE, key, BC_KEY_SIZE);
  crypto_blake2b_update(&ctx, (const uint8_t *)BC_MANIFEST_CONTEXT, sizeof(BC_MANIFEST_CONTEXT) - 1);
  crypto_blake2b_update(&ctx, body, body_size);
  crypto_blake2b_final(&ctx, mac);
}

bool bc_manifest_url_is_valid(const char *url)
{
  const size_t n = strlen(url);
  if (n >= BC_MANIFEST_URL_MAX) {
    return false;
  }
  for (size_t i = 0; i < n; i++) {
    if ((unsigned char)url[i] < 32 || url[i] == 127) {
      return false;
    }
  }
  return true;
}

void bc_manifest_key_mask(const uint8_t build_key[BC_KEY_SIZE], const BC_Manifest *m, uint8_t r_mask[BC_KEY_SIZE])
{
  crypto_blake2b_ctx ctx;
  crypto_blake2b_keyed_init(&ctx, BC_KEY_SIZE, build_key, BC_KEY_SIZE);
  crypto_blake2b_update(&ctx, (const uint8_t *)BC_PROJECT_KEY_CONTEXT, sizeof(BC_PROJECT_KEY_CONTEXT) - 1);
  crypto_blake2b_update(&ctx, m->key_ids[0], BC_KEY_ID_SIZE);
  crypto_blake2b_update(&ctx, m->player_hash, BC_PLAYER_HASH_SIZE);
  crypto_blake2b_final(&ctx, r_mask);
}

size_t bc_manifest_encode(const BC_Manifest *m,
                          const uint8_t key[BC_KEY_SIZE],
                          uint8_t out[BC_MANIFEST_MAX_SIZE])
{
  const bool online = (m->flags & BC_MANIFEST_ONLINE_KEY) != 0;
  const bool project = (m->flags & BC_MANIFEST_PROJECT_KEY) != 0;
  const bool native = (m->flags & BC_MANIFEST_NATIVE_DIGEST) != 0;
  const char *provider = online ? m->provider_path : "";
  const char *url = online ? m->key_url : "";
  const size_t key_count = online ? m->key_count : project ? 1 : 0;
  if (online && project) {
    return 0;
  }
  const char *fields[4] = {m->player_path, m->main_path, provider, url};
  size_t lengths[4];
  for (int i = 0; i < 4; i++) {
    lengths[i] = strlen(fields[i]);
  }
  if (!bc_manifest_path_is_safe(m->player_path) || !bc_manifest_path_is_safe(m->main_path) ||
      lengths[0] >= BC_MANIFEST_PATH_MAX || lengths[1] >= BC_MANIFEST_PATH_MAX ||
      (online && (!bc_manifest_path_is_safe(provider) || lengths[2] >= BC_MANIFEST_PATH_MAX ||
                  !bc_manifest_url_is_valid(url) || key_count == 0 || key_count > BC_KEYS_MAX)))
  {
    return 0;
  }
  memset(out, 0, BC_MANIFEST_FIXED_SIZE);
  memcpy(out, BC_MANIFEST_MAGIC, 8);
  bc_store_u16(out + 8, BC_MANIFEST_VERSION);
  bc_store_u16(out + 10, (uint16_t)lengths[0]);
  bc_store_u16(out + 12, (uint16_t)lengths[1]);
  const uint16_t key_flags = online ? (uint16_t)(m->flags & (BC_MANIFEST_ONLINE_KEY | BC_MANIFEST_KEY_CACHE)) :
                             project ? (uint16_t)BC_MANIFEST_PROJECT_KEY :
                                       0;
  const uint16_t check_flags = native ? (uint16_t)(m->flags & (BC_MANIFEST_NATIVE_DIGEST | BC_MANIFEST_PYTHON_CHECK)) : 0;
  bc_store_u16(out + 14, (uint16_t)(key_flags | check_flags));
  bc_key_id(key, out + 16);
  memcpy(out + 24, m->player_hash, BC_PLAYER_HASH_SIZE);
  bc_store_u16(out + 56, (uint16_t)key_count);
  bc_store_u16(out + 58, (uint16_t)lengths[2]);
  bc_store_u16(out + 60, (uint16_t)lengths[3]);
  /* Optional features, extension size and reserved bytes stay zero: no feature uses them yet. */
  size_t size = BC_MANIFEST_FIXED_SIZE;
  for (int i = 0; i < 4; i++) {
    memcpy(out + size, fields[i], lengths[i]);
    size += lengths[i];
  }
  memcpy(out + size, m->key_ids, key_count * BC_KEY_ID_SIZE);
  size += key_count * BC_KEY_ID_SIZE;
  if (project) {
    memcpy(out + size, m->masked_key, BC_KEY_SIZE);
    size += BC_KEY_SIZE;
  }
  if (native) {
    memcpy(out + size, m->native_digest, BC_NATIVE_DIGEST_SIZE);
    size += BC_NATIVE_DIGEST_SIZE;
  }
  bc_manifest_mac(key, out, size, out + size);
  return size + BC_MANIFEST_MAC_SIZE;
}

/** Copy a length-prefixed text field; false when it holds a NUL (strlen would disagree). */
static bool bc_copy_text(char *dst, const uint8_t *src, const size_t n)
{
  memcpy(dst, src, n);
  dst[n] = '\0';
  return strlen(dst) == n;
}

BC_ManifestResult bc_manifest_decode(const uint8_t *buffer,
                                     const size_t total,
                                     const uint8_t key[BC_KEY_SIZE],
                                     BC_Manifest *r_manifest)
{
  if (total < BC_MANIFEST_FIXED_SIZE + BC_MANIFEST_MAC_SIZE || total > BC_MANIFEST_MAX_SIZE ||
      memcmp(buffer, BC_MANIFEST_MAGIC, 8) != 0)
  {
    return BC_MANIFEST_BAD_FORMAT;
  }
  const uint16_t version = bc_load_u16(buffer + 8);
  const uint16_t flags = bc_load_u16(buffer + 14);
  if (version > BC_MANIFEST_VERSION || (flags & ~BC_MANIFEST_REQUIRED_KNOWN) != 0) {
    return BC_MANIFEST_NEWER;
  }
  if (version != BC_MANIFEST_VERSION) {
    return BC_MANIFEST_BAD_FORMAT;
  }
  const size_t lengths[4] = {
      bc_load_u16(buffer + 10), bc_load_u16(buffer + 12), bc_load_u16(buffer + 58), bc_load_u16(buffer + 60)};
  const size_t key_count = bc_load_u16(buffer + 56);
  const size_t extension_size = bc_load_u16(buffer + 64);
  const bool project = (flags & BC_MANIFEST_PROJECT_KEY) != 0;
  const bool native = (flags & BC_MANIFEST_NATIVE_DIGEST) != 0;
  /* The extension sits last, under the MAC: skipped, as no feature this launcher knows uses it. */
  const size_t body_size = BC_MANIFEST_FIXED_SIZE + lengths[0] + lengths[1] + lengths[2] +
                           lengths[3] + key_count * BC_KEY_ID_SIZE + (project ? BC_KEY_SIZE : 0) +
                           (native ? BC_NATIVE_DIGEST_SIZE : 0) + extension_size;
  if (lengths[0] >= BC_MANIFEST_PATH_MAX || lengths[1] >= BC_MANIFEST_PATH_MAX ||
      lengths[2] >= BC_MANIFEST_PATH_MAX || lengths[3] >= BC_MANIFEST_URL_MAX ||
      key_count > BC_KEYS_MAX || extension_size > BC_MANIFEST_EXTENSION_MAX ||
      body_size + BC_MANIFEST_MAC_SIZE != total || ((flags & BC_MANIFEST_PYTHON_CHECK) && !native))
  {
    return BC_MANIFEST_BAD_FORMAT;
  }

  uint8_t key_id[BC_KEY_ID_SIZE];
  bc_key_id(key, key_id);
  if (memcmp(buffer + 16, key_id, BC_KEY_ID_SIZE) != 0) {
    return BC_MANIFEST_WRONG_KEY;
  }
  uint8_t mac[BC_MANIFEST_MAC_SIZE];
  bc_manifest_mac(key, buffer, body_size, mac);
  /* Constant time comparison: no timing hint about how much of a forged MAC matched. */
  if (crypto_verify32(mac, buffer + body_size) != 0) {
    return BC_MANIFEST_BAD_MAC;
  }

  memset(r_manifest, 0, sizeof(*r_manifest));
  r_manifest->flags = flags;
  memcpy(r_manifest->player_hash, buffer + 24, BC_PLAYER_HASH_SIZE);
  const uint8_t *text = buffer + BC_MANIFEST_FIXED_SIZE;
  char *fields[4] = {r_manifest->player_path, r_manifest->main_path, r_manifest->provider_path, r_manifest->key_url};
  bool ok = true;
  for (int i = 0; i < 4; i++) {
    ok = bc_copy_text(fields[i], text, lengths[i]) && ok;
    text += lengths[i];
  }
  r_manifest->key_count = (uint16_t)key_count;
  memcpy(r_manifest->key_ids, text, key_count * BC_KEY_ID_SIZE);
  text += key_count * BC_KEY_ID_SIZE;
  if (project) {
    memcpy(r_manifest->masked_key, text, BC_KEY_SIZE);
    text += BC_KEY_SIZE;
  }
  if (native) {
    memcpy(r_manifest->native_digest, text, BC_NATIVE_DIGEST_SIZE);
  }
  /* Defense in depth: even an authentic manifest may only point inside the game folder. */
  const bool online = (flags & BC_MANIFEST_ONLINE_KEY) != 0;
  if (!ok || !bc_manifest_path_is_safe(r_manifest->player_path) ||
      !bc_manifest_path_is_safe(r_manifest->main_path) || (online && project) ||
      (online ? key_count == 0 : key_count != (project ? 1u : 0u)) ||
      (online && (!bc_manifest_path_is_safe(r_manifest->provider_path) ||
                  !bc_manifest_url_is_valid(r_manifest->key_url))))
  {
    return BC_MANIFEST_BAD_PATH;
  }
  return BC_MANIFEST_OK;
}

const char *bc_manifest_result_string(const BC_ManifestResult result)
{
  switch (result) {
    case BC_MANIFEST_OK:
      return "ok";
    case BC_MANIFEST_IO_ERROR:
      return "the game executable or its manifest cannot be read";
    case BC_MANIFEST_MISSING:
      return "this executable carries no game and there is no " BC_MANIFEST_FILENAME " next to it: "
             "export the game with bc_tool";
    case BC_MANIFEST_BAD_FORMAT:
      return "the game manifest is corrupt";
    case BC_MANIFEST_NEWER:
      return "the game was exported by a newer bc_tool: use the bc_launcher of that bc_tool";
    case BC_MANIFEST_WRONG_KEY:
      return "the game was encrypted by a different tool build than this launcher";
    case BC_MANIFEST_BAD_MAC:
      return "the game manifest has been modified";
    case BC_MANIFEST_BAD_PATH:
      return "the manifest points outside the game folder";
  }
  return "unknown error";
}
