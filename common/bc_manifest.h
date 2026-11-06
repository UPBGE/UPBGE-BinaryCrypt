/* SPDX-License-Identifier: GPL-2.0-or-later */

/* Manifest: written by the tool into the game executable (see bc_embed.h), read by the launcher.
 *
 * It names the player executable to run, its expected BLAKE2b hash and the main blend file, says
 * where the content key comes from (the project key stored here, a key server through a provider
 * (bc_envelope.h), or the build key itself), and is authenticated with the build key. Editing it
 * (for example to accept a modified player that dumps decrypted data) requires the key, so the
 * launcher refuses any manifest it did not get from the matching tool build. This file is
 * private to UPBGE-BinaryCrypt: the UPBGE player never reads it.
 *
 * Layout (integers little endian):
 *    0   8  magic "UPBGEBCM"
 *    8   2  version (4)
 *   10   2  player path length P
 *   12   2  main path length M
 *   14   2  flags (BC_MANIFEST_ONLINE_KEY, BC_MANIFEST_KEY_CACHE, BC_MANIFEST_PROJECT_KEY,
 *           BC_MANIFEST_NATIVE_DIGEST, BC_MANIFEST_PYTHON_CHECK)
 *   16   8  key id of the build key (see bc_key_id)
 *   24  32  BLAKE2b-256 of the player executable
 *   56   2  number K of content keys (online: 1..BC_KEYS_MAX, project key: 1, build key: 0)
 *   58   6  reserved, 0
 *   64   2  provider path length V (online key only, else 0)
 *   66   2  key server URL length U (online key only, may be 0)
 *   68   P  player path, UTF-8, relative to the manifest folder, '/' separators
 *       M  main blend path, same rules
 *       V  key provider path, same rules
 *       U  key server URL, UTF-8, no control characters (given to the provider as is)
 *     8*K  key ids of the content keys the game's files are sealed with (a key per update: one
 *          per update that still has files in the game), oldest first
 *      32  project key only: the project key XOR bc_manifest_key_mask (never stored as itself)
 *      32  native digest only: bc_native_digest of the game folder (bc_native.h), over native
 *          code, plus Python files with BC_MANIFEST_PYTHON_CHECK
 *  end  32  MAC: keyed BLAKE2b-256 (build key) of BC_MANIFEST_CONTEXT || all preceding bytes
 */

#ifndef BC_MANIFEST_H
#define BC_MANIFEST_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "bc_native.h"
#include "binarycrypt_format.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BC_MANIFEST_MAGIC "UPBGEBCM"
#define BC_MANIFEST_VERSION 4
#define BC_MANIFEST_FIXED_SIZE 68
#define BC_MANIFEST_MAC_SIZE 32
#define BC_MANIFEST_PATH_MAX 1024
#define BC_MANIFEST_URL_MAX 1024
#define BC_PLAYER_HASH_SIZE 32
#define BC_MANIFEST_MAX_SIZE \
  (BC_MANIFEST_FIXED_SIZE + 3 * BC_MANIFEST_PATH_MAX + BC_MANIFEST_URL_MAX + \
   BC_KEYS_MAX * BC_KEY_ID_SIZE + BC_KEY_SIZE + BC_NATIVE_DIGEST_SIZE + BC_MANIFEST_MAC_SIZE)

/** The content key comes from a key server through the provider, not from the build key. */
#define BC_MANIFEST_ONLINE_KEY (1 << 0)
/** Online key: keep it on this computer after the first launch (offline play afterwards). */
#define BC_MANIFEST_KEY_CACHE (1 << 1)
/** The content key is the project's own key, stored masked in the manifest. */
#define BC_MANIFEST_PROJECT_KEY (1 << 2)
/** The launcher checks the native code of the game folder against the digest stored here. */
#define BC_MANIFEST_NATIVE_DIGEST (1 << 3)
/** With BC_MANIFEST_NATIVE_DIGEST: the digest also covers Python files, and the launcher removes
 * Python bytecode before the launch and after the player exits. */
#define BC_MANIFEST_PYTHON_CHECK (1 << 4)
#define BC_MANIFEST_KEY_FLAGS (BC_MANIFEST_ONLINE_KEY | BC_MANIFEST_KEY_CACHE | BC_MANIFEST_PROJECT_KEY)
#define BC_PROJECT_KEY_CONTEXT "UPBGE-BinaryCrypt project key v1"
/* Domain separation: the MAC key is the build key, so the input is prefixed with a context that
 * no other keyed BLAKE2b in the system uses. */
#define BC_MANIFEST_CONTEXT "UPBGE-BinaryCrypt manifest v1"

typedef struct BC_Manifest {
  uint8_t player_hash[BC_PLAYER_HASH_SIZE];
  char player_path[BC_MANIFEST_PATH_MAX];
  char main_path[BC_MANIFEST_PATH_MAX];
  /* Online key only; zero/empty otherwise. */
  uint16_t flags;
  uint16_t key_count;
  uint8_t key_ids[BC_KEYS_MAX][BC_KEY_ID_SIZE];
  char provider_path[BC_MANIFEST_PATH_MAX];
  char key_url[BC_MANIFEST_URL_MAX];
  /* Project key only: the key XOR bc_manifest_key_mask. */
  uint8_t masked_key[BC_KEY_SIZE];
  /* BC_MANIFEST_NATIVE_DIGEST only. */
  uint8_t native_digest[BC_NATIVE_DIGEST_SIZE];
} BC_Manifest;

/** Mask of the project key: keyed BLAKE2b (build key) over its key id and the player hash, so it
 * differs per game. XOR with it both hides and recovers the key. Obfuscation: the build key ships
 * in the launcher. */
void bc_manifest_key_mask(const uint8_t build_key[BC_KEY_SIZE], const BC_Manifest *m, uint8_t r_mask[BC_KEY_SIZE]);

typedef enum BC_ManifestResult {
  BC_MANIFEST_OK = 0,
  BC_MANIFEST_IO_ERROR,
  BC_MANIFEST_MISSING,
  BC_MANIFEST_BAD_FORMAT,
  BC_MANIFEST_WRONG_KEY,
  BC_MANIFEST_BAD_MAC,
  BC_MANIFEST_BAD_PATH,
} BC_ManifestResult;

/** True for a non-empty relative path with '/' separators, no root, drive or ".." segment. */
bool bc_manifest_path_is_safe(const char *path);

/** Key server URL: shorter than BC_MANIFEST_URL_MAX, no control characters (it becomes a command
 * line argument of the provider). Empty is valid. */
bool bc_manifest_url_is_valid(const char *url);

/** Serialize and authenticate \a m. \return the size written to \a out, 0 when a path is unsafe or
 * too long. */
size_t bc_manifest_encode(const BC_Manifest *m,
                          const uint8_t key[BC_KEY_SIZE],
                          uint8_t out[BC_MANIFEST_MAX_SIZE]);

/** Authenticate and parse a manifest. Paths are validated with #bc_manifest_path_is_safe. */
BC_ManifestResult bc_manifest_decode(const uint8_t *data,
                                     size_t size,
                                     const uint8_t key[BC_KEY_SIZE],
                                     BC_Manifest *r_manifest);

const char *bc_manifest_result_string(BC_ManifestResult result);

#ifdef __cplusplus
}
#endif

#endif /* BC_MANIFEST_H */
