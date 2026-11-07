/* SPDX-License-Identifier: GPL-2.0-or-later */

/* Streaming container writer: seals one .blend into a BinaryCrypt container chunk by chunk, so
 * memory use is one chunk regardless of file size and a caller can interleave other work (a GUI
 * frame) between chunks.
 *
 * Deterministic: the nonce prefix is derived from the key, the header parameters and the hash of
 * the plaintext, so sealing the same file with the same key gives the same container byte for
 * byte. Unchanged files stay unchanged across exports and store patches (Steam, Epic) only carry
 * what really changed. A nonce repeats only when the plaintext repeats: no keystream is ever
 * reused for different data. The plaintext is hashed again while sealing; if it changed since the
 * caller hashed it, the output is discarded.
 *
 * The plaintext may be a transform of the source file (bc_compress.h): the header's source id
 * commits to the source, so a later export recognizes an up-to-date container from the source's
 * hash alone, without transforming it again. The source id never derives the nonce on its own:
 * a transform that gave other bytes (another zstd version) gets another nonce. */

#ifndef BC_SEAL_H
#define BC_SEAL_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "bc_platform.h"
#include "binarycrypt_format.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BC_PLAIN_HASH_SIZE 32
#define BC_NONCE_CONTEXT "UPBGE-BinaryCrypt nonce v1"
#define BC_SOURCE_ID_CONTEXT "UPBGE-BinaryCrypt source v1"

typedef struct BC_Sealer {
  FILE *in;
  crypto_blake2b_ctx hash;
  uint8_t plain_hash[BC_PLAIN_HASH_SIZE];
  uint8_t source_hash[BC_PLAIN_HASH_SIZE];
  FILE *out;
  const uint8_t *key;
  BC_Header header;
  uint8_t header_raw[BC_HEADER_SIZE];
  uint64_t next_chunk;
  uint64_t chunk_count;
  /** One chunk of plaintext followed by room for its MAC; sealed in place. */
  uint8_t *buffer;
  char in_path[BC_PATH_MAX];
  char out_path[BC_PATH_MAX];
  char tmp_path[BC_PATH_MAX];
} BC_Sealer;

/**
 * Open \a in_path, check that it is a .blend (plain, gzip or zstd) and not already sealed, and
 * start writing the container to a temporary file next to \a out_path (parent directories are
 * created). \a plain_hash is the BLAKE2b-256 of the input (#bc_hash_file), \a source_hash that of
 * the file the input was made from (the same when sealed as it is). On failure nothing is left on
 * disk and \a err holds the reason.
 */
bool bc_seal_begin(BC_Sealer *s,
                   const uint8_t key[BC_KEY_SIZE],
                   const char *in_path,
                   const char *out_path,
                   const uint8_t plain_hash[BC_PLAIN_HASH_SIZE],
                   const uint8_t source_hash[BC_PLAIN_HASH_SIZE],
                   char *err,
                   size_t err_size);

/**
 * Seal the next chunk.
 * \return 1 when chunks remain, 0 when the container is complete and has atomically replaced
 * \a out_path, -1 on failure (temporary output removed, reason in \a err).
 */
int bc_seal_step(BC_Sealer *s, char *err, size_t err_size);

/** Plaintext bytes consumed so far. */
uint64_t bc_seal_bytes_done(const BC_Sealer *s);

/** Stop early: close everything and remove the temporary output. Safe after completion. */
void bc_seal_abort(BC_Sealer *s);

/** BLAKE2b-256 of a whole file in one call (the job hashes in slices instead). */
bool bc_hash_file(const char *path, uint8_t r_hash[BC_PLAIN_HASH_SIZE]);

/** Header that sealing \a plain_size bytes with plaintext hash \a plain_hash, made from a source
 * hashing to \a source_hash, under \a key writes. Deterministic: the source id is a keyed hash of
 * the source hash, the nonce prefix a keyed hash of the other fields and the plaintext hash. */
void bc_seal_header(const uint8_t key[BC_KEY_SIZE],
                    uint64_t plain_size,
                    const uint8_t plain_hash[BC_PLAIN_HASH_SIZE],
                    const uint8_t source_hash[BC_PLAIN_HASH_SIZE],
                    BC_Header *r_header);

/** True when \a out_path already holds a container this tool made from a source hashing to
 * \a source_hash under \a key: current format and chunk size, same key id and source id, and the
 * exact size its header announces. An export then skips it (no new bytes, no new timestamp, no
 * transform). Only the header is read: damage past it goes unnoticed here, and is caught by the
 * player's MAC check. The source id is keyed: nobody without the key can forge a match. */
bool bc_seal_output_is_current(const uint8_t key[BC_KEY_SIZE],
                               const char *out_path,
                               const uint8_t source_hash[BC_PLAIN_HASH_SIZE]);

/** True when \a path already is a BinaryCrypt container (checks the magic only). */
bool bc_file_is_container(const char *path);

#ifdef __cplusplus
}
#endif

#endif /* BC_SEAL_H */
