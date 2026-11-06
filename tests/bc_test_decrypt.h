/* SPDX-License-Identifier: GPL-2.0-or-later */

/* Reference container decryptor for the tests: written straight from binarycrypt_format.h,
 * independent from both the tool's writer and UPBGE's reader, so a bug on one side cannot hide
 * behind the same bug on the other. Loads everything in memory: test sizes only. */

#ifndef BC_TEST_DECRYPT_H
#define BC_TEST_DECRYPT_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bc_platform.h"
#include "binarycrypt_format.h"

static bool bc_test_read_file(const char *path, uint8_t **r_data, uint64_t *r_size)
{
  uint64_t size;
  if (!bc_file_size(path, &size)) {
    return false;
  }
  FILE *f = bc_fopen(path, "rb");
  uint8_t *data = (uint8_t *)malloc(size ? (size_t)size : 1);
  const bool ok = f != NULL && data != NULL && fread(data, 1, (size_t)size, f) == size;
  if (f != NULL) {
    fclose(f);
  }
  if (!ok) {
    free(data);
    return false;
  }
  *r_data = data;
  *r_size = size;
  return true;
}

/** Decrypt the container at \a path. Returns false on any format or authentication error. */
static bool bc_test_decrypt(const char *path,
                            const uint8_t key[BC_KEY_SIZE],
                            uint8_t **r_plain,
                            uint64_t *r_plain_size)
{
  uint8_t *file;
  uint64_t file_size;
  if (!bc_test_read_file(path, &file, &file_size)) {
    return false;
  }
  BC_Header header = {0};
  uint8_t key_id[BC_KEY_ID_SIZE];
  bc_key_id(key, key_id);
  bool ok = file_size >= BC_HEADER_SIZE && bc_header_read(file, &header) == BC_HEADER_OK &&
            memcmp(header.key_id, key_id, BC_KEY_ID_SIZE) == 0 &&
            bc_container_size(&header) == file_size;
  uint8_t *plain = ok ? (uint8_t *)malloc((size_t)header.plain_size) : NULL;
  ok = ok && plain != NULL;
  for (uint64_t i = 0; ok && i < bc_chunk_count(&header); i++) {
    const size_t n = (size_t)bc_chunk_plain_size(&header, i);
    const uint8_t *chunk = file + bc_chunk_offset(&header, i);
    uint8_t nonce[BC_NONCE_SIZE];
    bc_chunk_nonce(header.nonce_prefix, i, nonce);
    ok = crypto_aead_unlock(plain + (i << header.chunk_log2),
                            chunk + n,
                            key,
                            nonce,
                            file,
                            BC_HEADER_SIZE,
                            chunk,
                            n) == 0;
  }
  free(file);
  if (!ok) {
    free(plain);
    return false;
  }
  *r_plain = plain;
  *r_plain_size = header.plain_size;
  return true;
}

#endif /* BC_TEST_DECRYPT_H */
