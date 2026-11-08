/* SPDX-License-Identifier: GPL-2.0-or-later */

/* Key file of an online key game: its content keys and, with a key per update, which key each
 * file of the game was sealed with.
 *
 * Text, private: bc_tool refuses a key file inside the game folder, and the key server needs a
 * copy. Two forms:
 *
 *   One key (also what bc_tool --export-key writes):
 *     <64 hexadecimal digits>
 *
 *   Key per update:
 *     # comment
 *     key <update> <64 hex>
 *     file <update> <64 hex: BLAKE2b-256 of the source .blend> <path inside the game folder>
 *
 * The one key form reads as the key of update 1, so a game can switch to a key per update later
 * and keep its published files. Keys are kept sorted by update number.
 *
 * Evolution: a later bc_tool may add lines starting with a new lowercase keyword. Readers (this
 * one and the reference key server) skip keywords they do not know, so older ones keep reading
 * the keys. */

#ifndef BC_KEYRING_H
#define BC_KEYRING_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "binarycrypt_format.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BC_FILE_HASH_SIZE 32

typedef struct BC_KeyRecord {
  char *path;
  uint8_t hash[BC_FILE_HASH_SIZE];
  uint32_t update;
} BC_KeyRecord;

typedef struct BC_KeyRing {
  uint32_t updates[BC_KEYS_MAX];
  uint8_t keys[BC_KEYS_MAX][BC_KEY_SIZE];
  int key_count;
  BC_KeyRecord *records;
  int record_count;
  int record_capacity;
} BC_KeyRing;

void bc_keyring_init(BC_KeyRing *r);
/** Wipes the keys. */
void bc_keyring_free(BC_KeyRing *r);
void bc_keyring_clear_records(BC_KeyRing *r);

bool bc_keyring_load(BC_KeyRing *r, const char *path, char *err, size_t err_size);
/** Atomic, readable by its owner only. \a single writes the one key form (exactly one key). */
bool bc_keyring_save(const BC_KeyRing *r, const char *path, bool single, char *err, size_t err_size);

/** Index of the key of \a update, or -1. */
int bc_keyring_find(const BC_KeyRing *r, uint32_t update);
/** Index of the key whose bc_key_id is \a key_id, or -1. */
int bc_keyring_find_id(const BC_KeyRing *r, const uint8_t key_id[BC_KEY_ID_SIZE]);
/** Highest update number, 0 for an empty ring. */
uint32_t bc_keyring_newest(const BC_KeyRing *r);
/** New random key for \a update. False when it exists, the ring is full or randomness failed. */
bool bc_keyring_add(BC_KeyRing *r, uint32_t update);

const BC_KeyRecord *bc_keyring_record(const BC_KeyRing *r, const char *path);
bool bc_keyring_set_record(BC_KeyRing *r, const char *path, const uint8_t hash[BC_FILE_HASH_SIZE], uint32_t update);

#ifdef __cplusplus
}
#endif

#endif /* BC_KEYRING_H */
