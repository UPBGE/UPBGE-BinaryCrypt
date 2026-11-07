/* SPDX-License-Identifier: GPL-2.0-or-later */

/** \file
 * \ingroup intern_binarycrypt
 *
 * BinaryCrypt container format and launcher -> player key hand-off.
 *
 * ============================================================================================
 * SYNC NOTE: this header is the contract between two repositories and exists as an IDENTICAL
 * copy in both of them:
 *   - upbge/intern/binarycrypt/binarycrypt_format.h        (player side: decryption only)
 *   - UPBGE-BinaryCrypt/common/binarycrypt_format.h        (encryption tool and launcher)
 * Both copies MUST be kept byte-for-byte in sync. Any change to the layout or the semantics
 * below requires bumping #BC_FORMAT_VERSION: readers reject unknown versions, so a mismatch
 * fails loudly instead of decoding garbage.
 * ============================================================================================
 *
 * Container layout (all integers little endian):
 *
 *   [ header: 64 bytes ][ chunk 0 ][ chunk 1 ] ... [ chunk N-1 ]
 *   chunk i = [ ciphertext: plain_len(i) bytes ][ MAC: 16 bytes ]
 *
 * Every chunk is sealed independently with XChaCha20-Poly1305 (Monocypher crypto_aead_lock):
 *   - nonce(i)        = nonce_prefix (16 bytes) || u64le(i)
 *   - associated data = the 64 header bytes exactly as stored on disk
 * Binding the header as associated data means that editing any header field, reordering chunks,
 * splicing chunks from another container or truncating the file all make a MAC check fail.
 * Independent chunks give O(1) random access, so a reader can serve seeks by decrypting a single
 * chunk and never needs the whole plaintext in memory.
 *
 * Key hand-off (launcher -> player), never through argv or files:
 *   The launcher creates an anonymous pipe, lets the child inherit the read end and stores its
 *   value in the environment variable #BC_KEY_PIPE_ENV as a decimal integer (POSIX: the file
 *   descriptor; Windows: the HANDLE value). It then writes one or more raw keys, #BC_KEY_SIZE
 *   bytes each and at most #BC_KEYS_MAX, and closes its write end. The player reads up to end of
 *   file once at startup, closes the descriptor and removes the variable from its environment.
 *   Each container names its key by key id (header): a game updated with a new key per update
 *   ships files sealed with several keys, all handed over together.
 */

#ifndef __BINARYCRYPT_FORMAT_H__
#define __BINARYCRYPT_FORMAT_H__

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "monocypher.h"

#ifdef __cplusplus
extern "C" {
#endif

/* "UPBGEBC" + 0x1A. Disjoint from every other first-bytes signature Blender sniffs ("BLENDER",
 * gzip 1F 8B, zstd 28 B5 2F FD) and from the legacy spindle "STC"/"DYC" tags. 0x1A (SUB) stops
 * text tools from dumping the binary as text. */
#define BC_MAGIC "UPBGEBC\x1A"
#define BC_MAGIC_SIZE 8
/* Blender sniffs 7 bytes before choosing a reader: matching on 7 is enough to dispatch, the full
 * 8 byte magic is validated by #bc_header_read. */
#define BC_MAGIC_SNIFF_SIZE 7

#define BC_FORMAT_VERSION 2

#define BC_HEADER_SIZE 64
#define BC_KEY_SIZE 32
#define BC_MAC_SIZE 16
#define BC_NONCE_SIZE 24
#define BC_NONCE_PREFIX_SIZE 16
#define BC_KEY_ID_SIZE 8
#define BC_SOURCE_ID_SIZE 16
/** Keys one launch can hand over: the player keeps them in a fixed table, searched per file open. */
#define BC_KEYS_MAX 64

/* 64 KiB: measured AEAD throughput is flat from 16 KiB to 1 MiB, so the size is chosen for cache
 * residency: the decrypted chunk stays in L2 while the reader copies it out. The 16 byte MAC
 * costs 0.02% of size at this granularity. */
#define BC_CHUNK_LOG2_DEFAULT 16
#define BC_CHUNK_LOG2_MIN 12
#define BC_CHUNK_LOG2_MAX 24

/* Upper bound for plain_size (256 TiB). Keeps every offset computed from header fields far below
 * INT64_MAX, so 64-bit offset arithmetic cannot overflow on hostile headers. */
#define BC_PLAIN_SIZE_MAX (UINT64_C(1) << 48)

/* What a container holds. Each reader opens its own kind only: Blender's file reader a .blend, the
 * player's importer a Python module, the script API (bge.logic.decryptFile) data. So no script
 * can be handed the decrypted bytes of a scene or of a module's source. */
#define BC_KIND_BLEND 0
#define BC_KIND_PYTHON 1
#define BC_KIND_DATA 2
#define BC_KIND_MAX BC_KIND_DATA

#define BC_KEY_PIPE_ENV "UPBGE_BC_KEY_PIPE"

/* Domain separation string for the key identifier: the key id must never be reusable as any
 * other value derived from the same key. */
#define BC_KEY_ID_CONTEXT "UPBGE-BinaryCrypt key id v1"

/* Header field offsets inside the 64 byte header. */
#define BC_OFS_MAGIC 0
#define BC_OFS_VERSION 8       /* u16 */
#define BC_OFS_CHUNK_LOG2 10   /* u8 */
#define BC_OFS_KIND 11         /* u8, BC_KIND_* */
#define BC_OFS_RESERVED0 12    /* 4 bytes, must be 0 */
#define BC_OFS_PLAIN_SIZE 16   /* u64 */
#define BC_OFS_KEY_ID 24       /* 8 bytes */
#define BC_OFS_NONCE_PREFIX 32 /* 16 bytes */
/* 16 bytes, opaque to readers (authenticated like every header byte): the writer's commitment to
 * the file it sealed, which may differ from the plaintext (a .blend compressed while sealing). It
 * lets the writer tell an up-to-date container from its source without reading the payload. */
#define BC_OFS_SOURCE_ID 48

typedef struct BC_Header {
  uint16_t version;
  uint8_t chunk_log2;
  uint8_t kind;
  uint64_t plain_size;
  uint8_t key_id[BC_KEY_ID_SIZE];
  uint8_t nonce_prefix[BC_NONCE_PREFIX_SIZE];
  uint8_t source_id[BC_SOURCE_ID_SIZE];
} BC_Header;

typedef enum BC_HeaderResult {
  BC_HEADER_OK = 0,
  BC_HEADER_BAD_MAGIC,
  BC_HEADER_BAD_VERSION,
  BC_HEADER_CORRUPT,
} BC_HeaderResult;

/* -------------------------------------------------------------------------------------------- */
/* Explicit little endian (de)serialization: struct memory layout and host endianness never leak
 * into the file. */

static inline uint16_t bc_load_u16(const uint8_t *p)
{
  return (uint16_t)(p[0] | (p[1] << 8));
}

static inline uint64_t bc_load_u64(const uint8_t *p)
{
  uint64_t v = 0;
  for (int i = 7; i >= 0; i--) {
    v = (v << 8) | p[i];
  }
  return v;
}

static inline void bc_store_u16(uint8_t *p, uint16_t v)
{
  p[0] = (uint8_t)v;
  p[1] = (uint8_t)(v >> 8);
}

static inline void bc_store_u64(uint8_t *p, uint64_t v)
{
  for (int i = 0; i < 8; i++) {
    p[i] = (uint8_t)(v >> (8 * i));
  }
}

static inline int bc_is_zero(const uint8_t *p, size_t size)
{
  uint8_t acc = 0;
  for (size_t i = 0; i < size; i++) {
    acc |= p[i];
  }
  return acc == 0;
}

/* -------------------------------------------------------------------------------------------- */
/* Header */

static inline void bc_header_write(const BC_Header *header, uint8_t out[BC_HEADER_SIZE])
{
  memset(out, 0, BC_HEADER_SIZE);
  memcpy(out + BC_OFS_MAGIC, BC_MAGIC, BC_MAGIC_SIZE);
  bc_store_u16(out + BC_OFS_VERSION, header->version);
  out[BC_OFS_CHUNK_LOG2] = header->chunk_log2;
  out[BC_OFS_KIND] = header->kind;
  bc_store_u64(out + BC_OFS_PLAIN_SIZE, header->plain_size);
  memcpy(out + BC_OFS_KEY_ID, header->key_id, BC_KEY_ID_SIZE);
  memcpy(out + BC_OFS_NONCE_PREFIX, header->nonce_prefix, BC_NONCE_PREFIX_SIZE);
  memcpy(out + BC_OFS_SOURCE_ID, header->source_id, BC_SOURCE_ID_SIZE);
}

/**
 * Parse and validate a stored header. Strict on every field but the source id: reserved bytes must
 * be zero and the kind known, so a future version can give them meaning without old readers
 * misinterpreting files.
 * An empty payload is rejected because the header is only authenticated through the chunks.
 */
static inline BC_HeaderResult bc_header_read(const uint8_t in[BC_HEADER_SIZE], BC_Header *header)
{
  if (memcmp(in + BC_OFS_MAGIC, BC_MAGIC, BC_MAGIC_SIZE) != 0) {
    return BC_HEADER_BAD_MAGIC;
  }
  header->version = bc_load_u16(in + BC_OFS_VERSION);
  if (header->version != BC_FORMAT_VERSION) {
    return BC_HEADER_BAD_VERSION;
  }
  header->chunk_log2 = in[BC_OFS_CHUNK_LOG2];
  header->kind = in[BC_OFS_KIND];
  header->plain_size = bc_load_u64(in + BC_OFS_PLAIN_SIZE);
  memcpy(header->key_id, in + BC_OFS_KEY_ID, BC_KEY_ID_SIZE);
  memcpy(header->nonce_prefix, in + BC_OFS_NONCE_PREFIX, BC_NONCE_PREFIX_SIZE);
  memcpy(header->source_id, in + BC_OFS_SOURCE_ID, BC_SOURCE_ID_SIZE);

  if (header->chunk_log2 < BC_CHUNK_LOG2_MIN || header->chunk_log2 > BC_CHUNK_LOG2_MAX ||
      header->kind > BC_KIND_MAX || header->plain_size == 0 || header->plain_size > BC_PLAIN_SIZE_MAX ||
      !bc_is_zero(in + BC_OFS_RESERVED0, 4))
  {
    return BC_HEADER_CORRUPT;
  }
  return BC_HEADER_OK;
}

/* -------------------------------------------------------------------------------------------- */
/* Chunk geometry. All results fit in 64 bits for any header accepted by #bc_header_read. */

static inline uint64_t bc_chunk_count(const BC_Header *header)
{
  const uint64_t chunk_size = UINT64_C(1) << header->chunk_log2;
  return (header->plain_size + chunk_size - 1) >> header->chunk_log2;
}

/** Plaintext length of chunk \a index: full chunks except a possibly shorter last one. */
static inline uint64_t bc_chunk_plain_size(const BC_Header *header, uint64_t index)
{
  const uint64_t chunk_size = UINT64_C(1) << header->chunk_log2;
  const uint64_t begin = index << header->chunk_log2;
  const uint64_t remaining = header->plain_size - begin;
  return remaining < chunk_size ? remaining : chunk_size;
}

/** File offset of chunk \a index (start of its ciphertext). */
static inline uint64_t bc_chunk_offset(const BC_Header *header, uint64_t index)
{
  const uint64_t chunk_stride = (UINT64_C(1) << header->chunk_log2) + BC_MAC_SIZE;
  return BC_HEADER_SIZE + index * chunk_stride;
}

/** Exact size of a well formed container: anything else is truncated or has trailing data. */
static inline uint64_t bc_container_size(const BC_Header *header)
{
  return BC_HEADER_SIZE + header->plain_size + bc_chunk_count(header) * BC_MAC_SIZE;
}

/* -------------------------------------------------------------------------------------------- */
/* Crypto parameters */

/**
 * XChaCha20 takes a 192-bit nonce: 128 random bits per file make a collision between two files
 * sealed with the same key negligible, and the 64-bit chunk index makes every chunk nonce within
 * a file unique. Including the index also authenticates chunk position.
 */
static inline void bc_chunk_nonce(const uint8_t nonce_prefix[BC_NONCE_PREFIX_SIZE],
                                  uint64_t index,
                                  uint8_t out[BC_NONCE_SIZE])
{
  memcpy(out, nonce_prefix, BC_NONCE_PREFIX_SIZE);
  bc_store_u64(out + BC_NONCE_PREFIX_SIZE, index);
}

/**
 * Short public fingerprint of a key: a keyed BLAKE2b of a fixed context string. It lets a reader
 * report "this file was sealed with a different key" up front instead of a generic MAC failure,
 * and reveals nothing usable about the key itself.
 */
static inline void bc_key_id(const uint8_t key[BC_KEY_SIZE], uint8_t out[BC_KEY_ID_SIZE])
{
  crypto_blake2b_keyed(out,
                       BC_KEY_ID_SIZE,
                       key,
                       BC_KEY_SIZE,
                       (const uint8_t *)BC_KEY_ID_CONTEXT,
                       sizeof(BC_KEY_ID_CONTEXT) - 1);
}

#ifdef __cplusplus
}
#endif

#endif /* __BINARYCRYPT_FORMAT_H__ */
