/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "bc_envelope.h"

#include <string.h>

#include "bc_platform.h"

static const uint8_t bc_zero_nonce[12] = {0};

bool bc_envelope_keypair(uint8_t r_secret[BC_X25519_SIZE], uint8_t r_public[BC_X25519_SIZE])
{
  if (!bc_random_bytes(r_secret, BC_X25519_SIZE)) {
    return false;
  }
  crypto_x25519_public_key(r_public, r_secret);
  return true;
}

/** Shared AEAD key, or false for an all-zero shared secret (the peer sent a small order point:
 * the "secret" would be known to anyone). */
static bool bc_envelope_derive(const uint8_t shared[32],
                               const uint8_t client_public[BC_X25519_SIZE],
                               const uint8_t server_public[BC_X25519_SIZE],
                               uint8_t r_key[32])
{
  static const uint8_t zero[32] = {0};
  if (crypto_verify32(shared, zero) == 0) {
    return false;
  }
  crypto_blake2b_ctx ctx;
  crypto_blake2b_init(&ctx, 32);
  crypto_blake2b_update(&ctx, (const uint8_t *)BC_ENVELOPE_CONTEXT, sizeof(BC_ENVELOPE_CONTEXT) - 1);
  crypto_blake2b_update(&ctx, shared, 32);
  crypto_blake2b_update(&ctx, client_public, BC_X25519_SIZE);
  crypto_blake2b_update(&ctx, server_public, BC_X25519_SIZE);
  crypto_blake2b_final(&ctx, r_key);
  return true;
}

bool bc_envelope_seal(const uint8_t key[BC_KEY_SIZE],
                      const uint8_t key_id[BC_KEY_ID_SIZE],
                      const uint8_t client_public[BC_X25519_SIZE],
                      uint8_t r_envelope[BC_ENVELOPE_SIZE])
{
  uint8_t secret[32], shared[32], aead_key[32];
  if (!bc_envelope_keypair(secret, r_envelope)) {
    return false;
  }
  crypto_x25519(shared, secret, client_public);
  const bool ok = bc_envelope_derive(shared, client_public, r_envelope, aead_key);
  if (ok) {
    crypto_aead_ctx ctx;
    crypto_aead_init_ietf(&ctx, aead_key, bc_zero_nonce);
    crypto_aead_write(&ctx, r_envelope + 32, r_envelope + 64, key_id, BC_KEY_ID_SIZE, key, BC_KEY_SIZE);
    crypto_wipe(&ctx, sizeof(ctx));
  }
  crypto_wipe(secret, sizeof(secret));
  crypto_wipe(shared, sizeof(shared));
  crypto_wipe(aead_key, sizeof(aead_key));
  return ok;
}

bool bc_envelope_open(const uint8_t envelope[BC_ENVELOPE_SIZE],
                      const uint8_t key_id[BC_KEY_ID_SIZE],
                      const uint8_t client_secret[BC_X25519_SIZE],
                      const uint8_t client_public[BC_X25519_SIZE],
                      uint8_t r_key[BC_KEY_SIZE])
{
  uint8_t shared[32], aead_key[32];
  crypto_x25519(shared, client_secret, envelope);
  bool ok = bc_envelope_derive(shared, client_public, envelope, aead_key);
  if (ok) {
    crypto_aead_ctx ctx;
    crypto_aead_init_ietf(&ctx, aead_key, bc_zero_nonce);
    ok = crypto_aead_read(&ctx, r_key, envelope + 64, key_id, BC_KEY_ID_SIZE, envelope + 32, BC_KEY_SIZE) == 0;
    crypto_wipe(&ctx, sizeof(ctx));
  }
  if (!ok) {
    crypto_wipe(r_key, BC_KEY_SIZE);
  }
  crypto_wipe(shared, sizeof(shared));
  crypto_wipe(aead_key, sizeof(aead_key));
  return ok;
}
