/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "bc_compress.h"

#include <stdlib.h>
#include <string.h>

#include <zstd.h>

/* Seekable format (contrib/seekable_format in the zstd sources), as Blender writes it: a
 * skippable frame holding one (compressed size, uncompressed size) pair per frame, then the
 * frame count, a flags byte (0: no per-frame checksums) and a second magic. */
#define BC_ZSTD_SKIPPABLE_MAGIC 0x184D2A5Eu
#define BC_ZSTD_SEEKABLE_MAGIC 0x8F92EAB1u

bool bc_blend_is_uncompressed(const uint8_t *first, const size_t n)
{
  return n >= 7 && memcmp(first, "BLENDER", 7) == 0;
}

void bc_compress_end(BC_Compressor *c, const bool remove_output)
{
  if (c->in != NULL) {
    fclose(c->in);
    c->in = NULL;
  }
  if (c->out != NULL) {
    fclose(c->out);
    c->out = NULL;
  }
  if (remove_output && c->out_path[0] != '\0') {
    bc_remove(c->out_path);
  }
  ZSTD_freeCCtx((ZSTD_CCtx *)c->cctx);
  c->cctx = NULL;
  free(c->in_buffer);
  free(c->out_buffer);
  free(c->frames);
  c->in_buffer = c->out_buffer = NULL;
  c->frames = NULL;
}

bool bc_compress_begin(BC_Compressor *c, const char *in_path, const char *out_path, char *err, const size_t err_size)
{
  memset(c, 0, sizeof(*c));
  snprintf(c->in_path, sizeof(c->in_path), "%s", in_path);
  c->in = bc_fopen(in_path, "rb");
  if (c->in == NULL) {
    snprintf(err, err_size, "cannot read '%s'", in_path);
    return false;
  }
  c->cctx = ZSTD_createCCtx();
  c->in_buffer = (uint8_t *)malloc(BC_COMPRESS_FRAME_SIZE);
  c->out_capacity = ZSTD_compressBound(BC_COMPRESS_FRAME_SIZE);
  c->out_buffer = (uint8_t *)malloc(c->out_capacity);
  if (c->cctx == NULL || c->in_buffer == NULL || c->out_buffer == NULL) {
    snprintf(err, err_size, "out of memory");
    bc_compress_end(c, false);
    return false;
  }
  snprintf(c->out_path, sizeof(c->out_path), "%s", out_path);
  c->out = bc_fopen(out_path, "wb");
  if (c->out == NULL) {
    snprintf(err, err_size, "cannot write '%s'", out_path);
    c->out_path[0] = '\0';
    bc_compress_end(c, false);
    return false;
  }
  crypto_blake2b_init(&c->hash, BC_PLAIN_HASH_SIZE);
  return true;
}

static bool bc_compress_write(BC_Compressor *c, const void *data, const size_t size)
{
  crypto_blake2b_update(&c->hash, (const uint8_t *)data, size);
  c->out_size += size;
  return fwrite(data, 1, size, c->out) == size;
}

static bool bc_compress_write_u32(BC_Compressor *c, const uint32_t v)
{
  const uint8_t b[4] = {(uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24)};
  return bc_compress_write(c, b, sizeof(b));
}

/** The skippable frame after the data frames: Blender's reader seeks with it. */
static bool bc_compress_write_seek_table(BC_Compressor *c)
{
  bool ok = bc_compress_write_u32(c, BC_ZSTD_SKIPPABLE_MAGIC) &&
            bc_compress_write_u32(c, (uint32_t)c->frame_count * 8 + 9);
  for (int i = 0; ok && i < 2 * c->frame_count; i++) {
    ok = bc_compress_write_u32(c, c->frames[i]);
  }
  const uint8_t flags = 0;
  return ok && bc_compress_write_u32(c, (uint32_t)c->frame_count) && bc_compress_write(c, &flags, 1) &&
         bc_compress_write_u32(c, BC_ZSTD_SEEKABLE_MAGIC);
}

int bc_compress_step(BC_Compressor *c, char *err, const size_t err_size)
{
  const size_t n = fread(c->in_buffer, 1, BC_COMPRESS_FRAME_SIZE, c->in);
  if (n > 0) {
    if (c->frame_count == c->frame_capacity) {
      const int capacity = c->frame_capacity ? 2 * c->frame_capacity : 256;
      uint32_t *frames = (uint32_t *)realloc(c->frames, (size_t)capacity * 2 * sizeof(uint32_t));
      if (frames == NULL) {
        snprintf(err, err_size, "out of memory");
        bc_compress_end(c, true);
        return -1;
      }
      c->frames = frames;
      c->frame_capacity = capacity;
    }
    /* Each frame alone, as Blender does: any frame decompresses without the ones before it. */
    const size_t size = ZSTD_compressCCtx((ZSTD_CCtx *)c->cctx, c->out_buffer, c->out_capacity, c->in_buffer, n, BC_COMPRESS_LEVEL);
    if (ZSTD_isError(size)) {
      snprintf(err, err_size, "cannot compress '%s': %s", c->in_path, ZSTD_getErrorName(size));
      bc_compress_end(c, true);
      return -1;
    }
    if (!bc_compress_write(c, c->out_buffer, size)) {
      snprintf(err, err_size, "write error on '%s' (disk full?)", c->out_path);
      bc_compress_end(c, true);
      return -1;
    }
    c->frames[2 * c->frame_count] = (uint32_t)size;
    c->frames[2 * c->frame_count + 1] = (uint32_t)n;
    c->frame_count++;
    c->in_done += n;
  }
  if (n == BC_COMPRESS_FRAME_SIZE) {
    return 1;
  }
  if (ferror(c->in)) {
    snprintf(err, err_size, "cannot read '%s'", c->in_path);
    bc_compress_end(c, true);
    return -1;
  }
  const bool ok = bc_compress_write_seek_table(c);
  crypto_blake2b_final(&c->hash, c->out_hash);
  const bool closed = fclose(c->out) == 0;
  c->out = NULL;
  if (!ok || !closed) {
    snprintf(err, err_size, "write error on '%s' (disk full?)", c->out_path);
    bc_compress_end(c, true);
    return -1;
  }
  bc_compress_end(c, false);
  return 0;
}
