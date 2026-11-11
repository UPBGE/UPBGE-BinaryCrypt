/* SPDX-License-Identifier: GPL-2.0-or-later */

/* The key of this build and its text form.
 *
 * The key is produced by bc_keygen while building (random by default, or read from the file named
 * by the BINARYCRYPT_KEY_FILE CMake option) into a header inside the build directory. It never
 * appears in the sources, in compile flags or in build logs. The tool and the launcher built
 * together share it; nothing else ever contains it. */

#ifndef BC_KEY_H
#define BC_KEY_H

#include <stdbool.h>
#include <stdint.h>

#include "binarycrypt_format.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BC_KEY_HEX_SIZE (2 * BC_KEY_SIZE)
#define BC_FINGERPRINT_SIZE (2 * BC_KEY_ID_SIZE + 1)

/** Key compiled into this executable. It is stored as two shares, never as the key itself:
 * scanning the binary for 32 bytes that match a key id (in a container header or a manifest)
 * finds nothing. Obfuscation, not secrecy: see the README. */
const uint8_t *bc_build_key(void);
/** Wipe the joined build key; the next bc_build_key() joins it again. The launcher calls it
 * before starting the player, so the key does not sit in its memory for the whole game. */
void bc_build_key_forget(void);

#define BC_KEY_SHARE_CONTEXT "UPBGE-BinaryCrypt key share v1"
/** Random bytes around each share in the binaries (bc_keygen). */
#define BC_KEY_BLOCK_SIZE 4096

/** \a r_b = key XOR BLAKE3 derive_key(context, a) with \a r_a random. False if randomness failed. */
bool bc_key_split(const uint8_t key[BC_KEY_SIZE], uint8_t r_a[BC_KEY_SIZE], uint8_t r_b[BC_KEY_SIZE]);
/** Inverse of bc_key_split. */
void bc_key_join(const uint8_t a[BC_KEY_SIZE], const uint8_t b[BC_KEY_SIZE], uint8_t r_key[BC_KEY_SIZE]);

/** Public fingerprint of the build key (hex of #bc_key_id): safe to display, lets a developer
 * match a tool build with a launcher build. */
void bc_key_fingerprint(const uint8_t key[BC_KEY_SIZE], char out[BC_FINGERPRINT_SIZE]);

/** Parse 64 hex digits; whitespace is ignored, anything else is an error. */
bool bc_key_from_hex(const char *text, uint8_t key[BC_KEY_SIZE]);
void bc_key_to_hex(const uint8_t key[BC_KEY_SIZE], char out[BC_KEY_HEX_SIZE + 1]);

#ifdef __cplusplus
}
#endif

#endif /* BC_KEY_H */
