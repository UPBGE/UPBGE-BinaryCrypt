/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "bc_seal.h"

#include <stdlib.h>
#include <string.h>

/* Large stdio buffers turn the 64 KiB chunk traffic into few big system calls. */
#define BC_IO_BUFFER_SIZE (1 << 20)

typedef enum BC_InputKind {
  BC_INPUT_BLEND,
  BC_INPUT_SEALED,
  BC_INPUT_UNKNOWN,
} BC_InputKind;

/** Same first-bytes signatures Blender's reader accepts: plain, gzip and zstd blend files. */
static BC_InputKind bc_classify(const uint8_t *b, size_t n)
{
  if (n >= 7 && memcmp(b, "BLENDER", 7) == 0) {
    return BC_INPUT_BLEND;
  }
  if (n >= BC_MAGIC_SNIFF_SIZE && memcmp(b, BC_MAGIC, BC_MAGIC_SNIFF_SIZE) == 0) {
    return BC_INPUT_SEALED;
  }
  if (n >= 3 && b[0] == 0x1f && b[1] == 0x8b && b[2] == 0x08) {
    return BC_INPUT_BLEND;
  }
  if (n >= 4) {
    const uint32_t magic = (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) |
                           ((uint32_t)b[3] << 24);
    if (magic == 0xFD2FB528u || (magic >> 4) == 0x184D2A5u) {
      return BC_INPUT_BLEND;
    }
  }
  return BC_INPUT_UNKNOWN;
}

static void bc_seal_close(BC_Sealer *s, const bool remove_output)
{
  if (s->in != NULL) {
    fclose(s->in);
    s->in = NULL;
  }
  if (s->out != NULL) {
    fclose(s->out);
    s->out = NULL;
  }
  if (remove_output && s->tmp_path[0] != '\0') {
    bc_remove(s->tmp_path);
  }
  s->tmp_path[0] = '\0';
  free(s->buffer);
  s->buffer = NULL;
}

bool bc_seal_begin(BC_Sealer *s,
                   const uint8_t key[BC_KEY_SIZE],
                   const char *in_path,
                   const char *out_path,
                   const uint8_t plain_hash[BC_PLAIN_HASH_SIZE],
                   const uint8_t source_hash[BC_PLAIN_HASH_SIZE],
                   char *err,
                   size_t err_size)
{
  memset(s, 0, sizeof(*s));
  s->key = key;
  memcpy(s->plain_hash, plain_hash, BC_PLAIN_HASH_SIZE);
  memcpy(s->source_hash, source_hash, BC_PLAIN_HASH_SIZE);
  crypto_blake2b_init(&s->hash, BC_PLAIN_HASH_SIZE);
  snprintf(s->in_path, sizeof(s->in_path), "%s", in_path);

  uint64_t plain_size;
  if (!bc_file_size(in_path, &plain_size)) {
    snprintf(err, err_size, "cannot read '%s'", in_path);
    return false;
  }
  if (plain_size == 0 || plain_size > BC_PLAIN_SIZE_MAX) {
    snprintf(err, err_size, "'%s' is empty or too large", in_path);
    return false;
  }

  s->in = bc_fopen(in_path, "rb");
  if (s->in == NULL) {
    snprintf(err, err_size, "cannot open '%s'", in_path);
    return false;
  }
  uint8_t first[8];
  const size_t n = fread(first, 1, sizeof(first), s->in);
  switch (bc_classify(first, n)) {
    case BC_INPUT_BLEND:
      break;
    case BC_INPUT_SEALED:
      snprintf(err, err_size, "'%s' is already encrypted", in_path);
      bc_seal_close(s, false);
      return false;
    case BC_INPUT_UNKNOWN:
      snprintf(err, err_size, "'%s' is not a .blend file", in_path);
      bc_seal_close(s, false);
      return false;
  }
  rewind(s->in);
  setvbuf(s->in, NULL, _IOFBF, BC_IO_BUFFER_SIZE);

  bc_seal_header(key, plain_size, plain_hash, source_hash, &s->header);
  bc_header_write(&s->header, s->header_raw);
  s->chunk_count = bc_chunk_count(&s->header);

  char dir[BC_PATH_MAX];
  bc_path_dirname(dir, sizeof(dir), out_path);
  const int out_len = snprintf(s->out_path, sizeof(s->out_path), "%s", out_path);
  const int tmp_len = snprintf(s->tmp_path, sizeof(s->tmp_path), "%s.tmp", out_path);
  if (out_len < 0 || (size_t)tmp_len >= sizeof(s->tmp_path) || !bc_mkdir_p(dir)) {
    s->tmp_path[0] = '\0';
    snprintf(err, err_size, "cannot create the output folder '%s'", dir);
    bc_seal_close(s, false);
    return false;
  }
  s->out = bc_fopen(s->tmp_path, "wb");
  s->buffer = (uint8_t *)malloc(((size_t)1 << s->header.chunk_log2) + BC_MAC_SIZE);
  if (s->out == NULL || s->buffer == NULL) {
    snprintf(err, err_size, "cannot write '%s'", s->tmp_path);
    bc_seal_close(s, s->out != NULL);
    return false;
  }
  setvbuf(s->out, NULL, _IOFBF, BC_IO_BUFFER_SIZE);
  if (fwrite(s->header_raw, 1, BC_HEADER_SIZE, s->out) != BC_HEADER_SIZE) {
    snprintf(err, err_size, "cannot write '%s'", s->tmp_path);
    bc_seal_close(s, true);
    return false;
  }
  return true;
}

int bc_seal_step(BC_Sealer *s, char *err, size_t err_size)
{
  const uint64_t index = s->next_chunk;
  const size_t size = (size_t)bc_chunk_plain_size(&s->header, index);

  if (fread(s->buffer, 1, size, s->in) != size) {
    snprintf(err, err_size, "'%s' changed while it was being read", s->in_path);
    bc_seal_close(s, true);
    return -1;
  }
  crypto_blake2b_update(&s->hash, s->buffer, size);
  uint8_t nonce[BC_NONCE_SIZE];
  bc_chunk_nonce(s->header.nonce_prefix, index, nonce);
  /* Sealed in place: the MAC lands right after the ciphertext, ready to write in one call. */
  crypto_aead_lock(s->buffer,
                   s->buffer + size,
                   s->key,
                   nonce,
                   s->header_raw,
                   BC_HEADER_SIZE,
                   s->buffer,
                   size);
  if (fwrite(s->buffer, 1, size + BC_MAC_SIZE, s->out) != size + BC_MAC_SIZE) {
    snprintf(err, err_size, "write error on '%s' (disk full?)", s->tmp_path);
    bc_seal_close(s, true);
    return -1;
  }
  s->next_chunk++;
  if (s->next_chunk < s->chunk_count) {
    return 1;
  }

  /* Last chunk: the input must end exactly here and still hash as before. Otherwise the nonce
   * belongs to other data: the output must never be used. */
  uint8_t hash[BC_PLAIN_HASH_SIZE];
  crypto_blake2b_final(&s->hash, hash);
  if (fgetc(s->in) != EOF || crypto_verify32(hash, s->plain_hash) != 0) {
    snprintf(err, err_size, "'%s' changed while it was being read", s->in_path);
    bc_seal_close(s, true);
    return -1;
  }
  fclose(s->in);
  s->in = NULL;
  const bool flushed = fclose(s->out) == 0;
  s->out = NULL;
  if (!flushed || !bc_rename_replace(s->tmp_path, s->out_path)) {
    snprintf(err, err_size, "cannot write '%s'", s->out_path);
    bc_seal_close(s, true);
    return -1;
  }
  s->tmp_path[0] = '\0';
  bc_seal_close(s, false);
  return 0;
}

uint64_t bc_seal_bytes_done(const BC_Sealer *s)
{
  const uint64_t done = s->next_chunk << s->header.chunk_log2;
  return done < s->header.plain_size ? done : s->header.plain_size;
}

void bc_seal_abort(BC_Sealer *s)
{
  bc_seal_close(s, true);
}

bool bc_hash_file(const char *path, uint8_t r_hash[BC_PLAIN_HASH_SIZE])
{
  FILE *f = bc_fopen(path, "rb");
  uint8_t *buffer = (uint8_t *)malloc(BC_IO_BUFFER_SIZE);
  bool ok = f != NULL && buffer != NULL;
  crypto_blake2b_ctx ctx;
  crypto_blake2b_init(&ctx, BC_PLAIN_HASH_SIZE);
  size_t n;
  while (ok && (n = fread(buffer, 1, BC_IO_BUFFER_SIZE, f)) > 0) {
    crypto_blake2b_update(&ctx, buffer, n);
  }
  ok = ok && !ferror(f);
  crypto_blake2b_final(&ctx, r_hash);
  if (f != NULL) {
    fclose(f);
  }
  free(buffer);
  return ok;
}

static void bc_source_id(const uint8_t key[BC_KEY_SIZE],
                         const uint8_t source_hash[BC_PLAIN_HASH_SIZE],
                         uint8_t r_id[BC_SOURCE_ID_SIZE])
{
  crypto_blake2b_ctx ctx;
  crypto_blake2b_keyed_init(&ctx, BC_SOURCE_ID_SIZE, key, BC_KEY_SIZE);
  crypto_blake2b_update(&ctx, (const uint8_t *)BC_SOURCE_ID_CONTEXT, sizeof(BC_SOURCE_ID_CONTEXT) - 1);
  crypto_blake2b_update(&ctx, source_hash, BC_PLAIN_HASH_SIZE);
  crypto_blake2b_final(&ctx, r_id);
}

void bc_seal_header(const uint8_t key[BC_KEY_SIZE],
                    const uint64_t plain_size,
                    const uint8_t plain_hash[BC_PLAIN_HASH_SIZE],
                    const uint8_t source_hash[BC_PLAIN_HASH_SIZE],
                    BC_Header *r_header)
{
  memset(r_header, 0, sizeof(*r_header));
  r_header->version = BC_FORMAT_VERSION;
  r_header->chunk_log2 = BC_CHUNK_LOG2_DEFAULT;
  r_header->plain_size = plain_size;
  bc_key_id(key, r_header->key_id);
  bc_source_id(key, source_hash, r_header->source_id);
  /* Nonce prefix = keyed BLAKE2b over every header field (nonce still zero) and the plaintext
   * hash: equal only for the same plaintext sealed the same way. */
  uint8_t raw[BC_HEADER_SIZE];
  bc_header_write(r_header, raw);
  crypto_blake2b_ctx ctx;
  crypto_blake2b_keyed_init(&ctx, BC_NONCE_PREFIX_SIZE, key, BC_KEY_SIZE);
  crypto_blake2b_update(&ctx, (const uint8_t *)BC_NONCE_CONTEXT, sizeof(BC_NONCE_CONTEXT) - 1);
  crypto_blake2b_update(&ctx, raw, BC_HEADER_SIZE);
  crypto_blake2b_update(&ctx, plain_hash, BC_PLAIN_HASH_SIZE);
  crypto_blake2b_final(&ctx, r_header->nonce_prefix);
}

bool bc_seal_output_is_current(const uint8_t key[BC_KEY_SIZE],
                               const char *out_path,
                               const uint8_t source_hash[BC_PLAIN_HASH_SIZE])
{
  uint8_t raw[BC_HEADER_SIZE], key_id[BC_KEY_ID_SIZE], source_id[BC_SOURCE_ID_SIZE];
  uint64_t size;
  FILE *f = bc_fopen(out_path, "rb");
  if (f == NULL) {
    return false;
  }
  const size_t n = fread(raw, 1, sizeof(raw), f);
  fclose(f);
  BC_Header header;
  if (n != sizeof(raw) || bc_header_read(raw, &header) != BC_HEADER_OK ||
      header.chunk_log2 != BC_CHUNK_LOG2_DEFAULT || !bc_file_size(out_path, &size) ||
      size != bc_container_size(&header))
  {
    return false;
  }
  bc_key_id(key, key_id);
  bc_source_id(key, source_hash, source_id);
  return memcmp(header.key_id, key_id, BC_KEY_ID_SIZE) == 0 &&
         memcmp(header.source_id, source_id, BC_SOURCE_ID_SIZE) == 0;
}

bool bc_file_is_container(const char *path)
{
  uint8_t first[BC_MAGIC_SNIFF_SIZE];
  FILE *f = bc_fopen(path, "rb");
  if (f == NULL) {
    return false;
  }
  const size_t n = fread(first, 1, sizeof(first), f);
  fclose(f);
  return bc_classify(first, n) == BC_INPUT_SEALED;
}
