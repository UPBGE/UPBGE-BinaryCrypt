/* SPDX-License-Identifier: GPL-2.0-or-later */

/* Key text helpers. Kept apart from bc_key.c so bc_keygen can use them without linking the key it
 * is about to generate. */

#include "bc_key.h"
#include "bc_platform.h"
#include "blake3.h"

static const char bc_hex_digits[] = "0123456789abcdef";

static int bc_hex_value(const char c)
{
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

bool bc_key_from_hex(const char *text, uint8_t key[BC_KEY_SIZE])
{
  int nibbles = 0;
  for (const char *c = text; *c != '\0'; c++) {
    if (*c == ' ' || *c == '\t' || *c == '\r' || *c == '\n') {
      continue;
    }
    const int v = bc_hex_value(*c);
    if (v < 0 || nibbles >= BC_KEY_HEX_SIZE) {
      return false;
    }
    if (nibbles % 2 == 0) {
      key[nibbles / 2] = (uint8_t)(v << 4);
    }
    else {
      key[nibbles / 2] |= (uint8_t)v;
    }
    nibbles++;
  }
  return nibbles == BC_KEY_HEX_SIZE;
}

void bc_key_to_hex(const uint8_t key[BC_KEY_SIZE], char out[BC_KEY_HEX_SIZE + 1])
{
  for (int i = 0; i < BC_KEY_SIZE; i++) {
    out[2 * i] = bc_hex_digits[key[i] >> 4];
    out[2 * i + 1] = bc_hex_digits[key[i] & 15];
  }
  out[BC_KEY_HEX_SIZE] = '\0';
}

void bc_key_fingerprint(const uint8_t key[BC_KEY_SIZE], char out[BC_FINGERPRINT_SIZE])
{
  uint8_t id[BC_KEY_ID_SIZE];
  bc_key_id(key, id);
  for (int i = 0; i < BC_KEY_ID_SIZE; i++) {
    out[2 * i] = bc_hex_digits[id[i] >> 4];
    out[2 * i + 1] = bc_hex_digits[id[i] & 15];
  }
  out[2 * BC_KEY_ID_SIZE] = '\0';
}

/* A key derived from share a: BLAKE3's derive_key mode, under a context string used nowhere else. */
static void bc_key_share_mask(const uint8_t a[BC_KEY_SIZE], uint8_t r_mask[BC_KEY_SIZE])
{
  blake3_hasher hasher;
  blake3_hasher_init_derive_key(&hasher, BC_KEY_SHARE_CONTEXT);
  blake3_hasher_update(&hasher, a, BC_KEY_SIZE);
  blake3_hasher_finalize(&hasher, r_mask, BC_KEY_SIZE);
}

bool bc_key_split(const uint8_t key[BC_KEY_SIZE], uint8_t r_a[BC_KEY_SIZE], uint8_t r_b[BC_KEY_SIZE])
{
  if (!bc_random_bytes(r_a, BC_KEY_SIZE)) {
    return false;
  }
  bc_key_share_mask(r_a, r_b);
  for (int i = 0; i < BC_KEY_SIZE; i++) {
    r_b[i] ^= key[i];
  }
  return true;
}

void bc_key_join(const uint8_t a[BC_KEY_SIZE], const uint8_t b[BC_KEY_SIZE], uint8_t r_key[BC_KEY_SIZE])
{
  bc_key_share_mask(a, r_key);
  for (int i = 0; i < BC_KEY_SIZE; i++) {
    r_key[i] ^= b[i];
  }
}
