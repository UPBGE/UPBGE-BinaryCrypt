/* SPDX-License-Identifier: GPL-2.0-or-later */

/* Manifest: written by the tool into the game executable (see bc_embed.h), read by the launcher.
 *
 * It names the player executable to run, its expected BLAKE3 hash and the main blend file, says
 * where the content key comes from (the project key stored here, a key server through a provider
 * (bc_envelope.h), or the build key itself), and is authenticated with the build key. Editing it
 * (for example to accept a modified player that dumps decrypted data) requires the key, so the
 * launcher refuses any manifest it did not get from the matching tool build. This file is
 * private to UPBGE-BinaryCrypt: the UPBGE player never reads it.
 *
 * Layout (integers little endian):
 *    0   8  magic "UPBGEBCM"
 *    8   2  version (BC_MANIFEST_VERSION)
 *   10   2  player path length P
 *   12   2  main path length M
 *   14   2  required features: BC_MANIFEST_ONLINE_KEY, BC_MANIFEST_KEY_CACHE,
 *           BC_MANIFEST_PROJECT_KEY, BC_MANIFEST_NATIVE_DIGEST, BC_MANIFEST_PYTHON_CHECK
 *   16   8  key id of the build key (see bc_key_id)
 *   24  32  BLAKE3-256 of the player executable
 *   56   2  number K of content keys (online: 1..BC_KEYS_MAX, project key: 1, build key: 0)
 *   58   2  provider path length V (online key only, else 0)
 *   60   2  key server URL length U (online key only, may be 0)
 *   62   2  optional features: what the player shows, BC_MANIFEST_SHOW_*
 *   64   2  extension size X, at most BC_MANIFEST_EXTENSION_MAX
 *   66  62  reserved, 0
 *  128   P  player path, UTF-8, relative to the manifest folder, '/' separators
 *       M  main blend path, same rules
 *       V  key provider path, same rules
 *       U  key server URL, UTF-8, no control characters (given to the provider as is)
 *     8*K  key ids of the content keys the game's files are sealed with (a key per update: one
 *          per update that still has files in the game), oldest first
 *      32  project key only: the project key XOR bc_manifest_key_mask (never stored as itself)
 *      32  native digest only: bc_native_digest of the game folder (bc_native.h), over native
 *          code, plus Python files with BC_MANIFEST_PYTHON_CHECK
 *       X  extension: data a newer bc_tool adds under a feature bit, skipped by launchers that do
 *          not know it
 *  end  32  MAC: keyed BLAKE3-256 (build key) of BC_MANIFEST_CONTEXT || all preceding bytes
 *
 * Evolution, as for the container header (binarycrypt_format.h): the version changes only for a
 * redesign; a launcher refuses a manifest with a required feature it does not know (exported by a
 * newer bc_tool: it matters with the separate manifest, where a launcher signed once may outlive
 * tool updates) and ignores unknown optional features; reserved bytes are zero when written and
 * never looked at; new fixed fields go into them, new variable data into the extension. Every
 * byte is under the MAC.
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
#define BC_MANIFEST_VERSION 1
#define BC_MANIFEST_FIXED_SIZE 128
#define BC_MANIFEST_EXTENSION_MAX 4096
#define BC_MANIFEST_MAC_SIZE 32
#define BC_MANIFEST_PATH_MAX 1024
#define BC_MANIFEST_URL_MAX 1024
#define BC_PLAYER_HASH_SIZE 32
#define BC_MANIFEST_MAX_SIZE \
  (BC_MANIFEST_FIXED_SIZE + 3 * BC_MANIFEST_PATH_MAX + BC_MANIFEST_URL_MAX + \
   BC_KEYS_MAX * BC_KEY_ID_SIZE + BC_KEY_SIZE + BC_NATIVE_DIGEST_SIZE + BC_MANIFEST_EXTENSION_MAX + \
   BC_MANIFEST_MAC_SIZE)

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
/* Optional features: debug displays for test builds, passed to the player. A launcher that does
 * not know one starts the game without it. */
/** Windows: the player gets a console window (else it runs without one). */
#define BC_MANIFEST_SHOW_CONSOLE (1 << 0)
/** -g show_framerate = 1 */
#define BC_MANIFEST_SHOW_FRAMERATE (1 << 1)
/** -g show_profile = 1: time per frame of logic, physics, rendering... */
#define BC_MANIFEST_SHOW_PROFILE (1 << 2)
/** -g show_physics = 1: physics shapes and contacts. */
#define BC_MANIFEST_SHOW_PHYSICS (1 << 3)
/** -g show_properties = 1: the debug properties. */
#define BC_MANIFEST_SHOW_PROPERTIES (1 << 4)
/* Required features this launcher understands. */
#define BC_MANIFEST_REQUIRED_KNOWN \
  (BC_MANIFEST_KEY_FLAGS | BC_MANIFEST_NATIVE_DIGEST | BC_MANIFEST_PYTHON_CHECK)
#define BC_PROJECT_KEY_CONTEXT "UPBGE-BinaryCrypt project key v1"
/* Domain separation: the MAC key is the build key, so the input is prefixed with a context that
 * no other keyed hash in the system uses. */
#define BC_MANIFEST_CONTEXT "UPBGE-BinaryCrypt manifest v1"
/* External manifest next to the game executable. Chosen at build time
 * (BINARYCRYPT_MANIFEST_FILENAME): the launcher must find it before it has read anything, and with
 * the external manifest the game executable is a byte-identical launcher copy, so the name cannot
 * travel with the game. */
#ifndef BC_MANIFEST_FILENAME
#  define BC_MANIFEST_FILENAME "binarycrypt.manifest"
#endif

typedef struct BC_Manifest {
  uint8_t player_hash[BC_PLAYER_HASH_SIZE];
  char player_path[BC_MANIFEST_PATH_MAX];
  char main_path[BC_MANIFEST_PATH_MAX];
  /* Online key only; zero/empty otherwise. */
  uint16_t flags;
  /** Optional features (BC_MANIFEST_SHOW_*); unknown bits are kept and ignored. */
  uint16_t options;
  uint16_t key_count;
  uint8_t key_ids[BC_KEYS_MAX][BC_KEY_ID_SIZE];
  char provider_path[BC_MANIFEST_PATH_MAX];
  char key_url[BC_MANIFEST_URL_MAX];
  /* Project key only: the key XOR bc_manifest_key_mask. */
  uint8_t masked_key[BC_KEY_SIZE];
  /* BC_MANIFEST_NATIVE_DIGEST only. */
  uint8_t native_digest[BC_NATIVE_DIGEST_SIZE];
} BC_Manifest;

/** Mask of the project key: keyed BLAKE3 (build key) over its key id and the player hash, so it
 * differs per game. XOR with it both hides and recovers the key. */
void bc_manifest_key_mask(const uint8_t build_key[BC_KEY_SIZE], const BC_Manifest *m, uint8_t r_mask[BC_KEY_SIZE]);

typedef enum BC_ManifestResult {
  BC_MANIFEST_OK = 0,
  BC_MANIFEST_IO_ERROR,
  BC_MANIFEST_MISSING,
  BC_MANIFEST_BAD_FORMAT,
  /** Another version, or a required feature this launcher does not know. */
  BC_MANIFEST_NEWER,
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
