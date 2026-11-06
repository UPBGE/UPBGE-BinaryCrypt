/* SPDX-License-Identifier: GPL-2.0-or-later */

/* Key envelope: how a key server hands a content key to one launch of the game.
 *
 * The launcher makes a fresh X25519 key pair for every launch and gives the public half to the key
 * provider, which forwards it to the server. The server answers with the content key sealed for
 * that public key only: the provider, a proxy, or anyone watching the HTTPS traffic with a forged
 * root certificate sees nothing usable.
 *
 * Envelope (80 bytes):
 *    0  32  server public key B (fresh X25519 key pair per answer)
 *   32  32  content key, encrypted
 *   64  16  Poly1305 tag
 *
 *   s = X25519(b, A) = X25519(a, B), refused when all zero (small order point)
 *   k = BLAKE2b-256(BC_ENVELOPE_CONTEXT || s || A || B)
 *   ciphertext, tag = ChaCha20-Poly1305 (RFC 8439)(k, nonce = 12 zero bytes, ad = key id)
 *
 * k is unique to the pair of fresh key pairs, so the constant nonce never repeats under one key.
 * The key id as associated data binds the answer to the game asked for. Plain RFC primitives: the
 * reference server implements it with Python's "cryptography" package in a few lines. */

#ifndef BC_ENVELOPE_H
#define BC_ENVELOPE_H

#include <stdbool.h>
#include <stdint.h>

#include "binarycrypt_format.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BC_ENVELOPE_SIZE 80
#define BC_X25519_SIZE 32
#define BC_ENVELOPE_CONTEXT "UPBGE-BinaryCrypt key envelope v1"

/** Fresh key pair for one request. */
bool bc_envelope_keypair(uint8_t r_secret[BC_X25519_SIZE], uint8_t r_public[BC_X25519_SIZE]);

/** Server side: seal \a key for \a client_public. False on a small order public key. */
bool bc_envelope_seal(const uint8_t key[BC_KEY_SIZE],
                      const uint8_t key_id[BC_KEY_ID_SIZE],
                      const uint8_t client_public[BC_X25519_SIZE],
                      uint8_t r_envelope[BC_ENVELOPE_SIZE]);

/** Launcher side: open an envelope. False when it was not sealed for this key pair and key id. */
bool bc_envelope_open(const uint8_t envelope[BC_ENVELOPE_SIZE],
                      const uint8_t key_id[BC_KEY_ID_SIZE],
                      const uint8_t client_secret[BC_X25519_SIZE],
                      const uint8_t client_public[BC_X25519_SIZE],
                      uint8_t r_key[BC_KEY_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* BC_ENVELOPE_H */
