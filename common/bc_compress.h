/* SPDX-License-Identifier: GPL-2.0-or-later */

/* zstd compression of a .blend before sealing it, one frame per step.
 *
 * Encrypted data does not compress: a store that compresses its downloads (Steam compresses each
 * 1 MB chunk it ships) would ship an encrypted .blend at full size. Compressing first gives that
 * size back. The output is what Blender writes with File > Save > Compress: independent zstd
 * frames of 1 MiB of input at level 3, then the seek table of the zstd seekable format, so the
 * player opens and seeks in it as in a .blend Blender compressed (its reader also unwraps zstd
 * inside a container). Single threaded: the same input and zstd version give the same bytes.
 *
 * Memory: one input frame and one output frame, whatever the file size. */

#ifndef BC_COMPRESS_H
#define BC_COMPRESS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "bc_platform.h"
#include "bc_seal.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Blender's ZSTD_CHUNK_SIZE and ZSTD_COMPRESSION_LEVEL (writefile.cc). */
#define BC_COMPRESS_FRAME_SIZE (1 << 20)
#define BC_COMPRESS_LEVEL 3

typedef struct BC_Compressor {
  FILE *in;
  FILE *out;
  void *cctx; /* ZSTD_CCtx, kept out of this header. */
  uint8_t *in_buffer;
  uint8_t *out_buffer;
  size_t out_capacity;
  /** Seek table: compressed then uncompressed size of every frame. */
  uint32_t *frames;
  int frame_count;
  int frame_capacity;
  crypto_blake2b_ctx hash;
  uint64_t in_done;
  /** Set when bc_compress_step returns 0: size and BLAKE2b-256 of the output (the plaintext the
   * sealer gets). */
  uint64_t out_size;
  uint8_t out_hash[BC_PLAIN_HASH_SIZE];
  char in_path[BC_PATH_MAX];
  char out_path[BC_PATH_MAX];
} BC_Compressor;

/** True for a .blend Blender did not compress: its first bytes are "BLENDER". */
bool bc_blend_is_uncompressed(const uint8_t *first, size_t n);

/** Start compressing \a in_path into \a out_path (replaced). False with \a err on failure. */
bool bc_compress_begin(BC_Compressor *c, const char *in_path, const char *out_path, char *err, size_t err_size);

/** Compress the next frame. \return 1 when input remains, 0 when \a out_path is complete (closed,
 * out_size and out_hash set), -1 on failure (output removed, reason in \a err). */
int bc_compress_step(BC_Compressor *c, char *err, size_t err_size);

/** Close everything; with \a remove_output, also delete the output. Safe in any state. */
void bc_compress_end(BC_Compressor *c, bool remove_output);

#ifdef __cplusplus
}
#endif

#endif /* BC_COMPRESS_H */
