/* SPDX-License-Identifier: MIT */

/* Shared part of the reference key providers (MIT, so a provider may link a store's proprietary
 * SDK). A provider is started by the game launcher as
 *
 *   provider <key url or "-"> <key ids: hex, comma separated> <client public key hex> [game args]
 *
 * proves to the key server that the player owns the game, and prints the server's answer: one
 * "BCENVELOPE <hex>" line per key id, in the same order, or "BCERROR <message>". Everything else
 * it prints (store SDK logs) is ignored by the launcher.
 *
 * Request sent to the key server (HTTP POST, JSON):
 *   {"platform": "steam" | "epic" | "dev", "ticket": "...", "key_ids": ["..."], "client_public": "..."}
 * Answer: 200 {"envelopes": ["<160 hex>", ...]}, otherwise {"error": "<message for the player>"}. */

#ifndef BC_PROVIDER_H
#define BC_PROVIDER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct BCP_Request {
  const char *url;           /* key server URL */
  const char *key_ids;       /* 16 hex digits each, comma separated */
  const char *client_public; /* 64 hex digits */
  int argc;                  /* the game executable's own arguments */
  char **argv;
} BCP_Request;

/** Parse the launcher's arguments; prints BCERROR and returns false when they are wrong.
 * \a default_url is used when the launcher passes "-" (no URL in the game's project). */
bool bcp_parse_args(int argc, char **argv, const char *default_url, BCP_Request *r_request);

/** Value of a "-NAME=value" game argument (Epic passes -AUTH_PASSWORD=<exchange code>). */
const char *bcp_find_arg(const BCP_Request *request, const char *prefix);

/** Send the ownership proof, print the protocol line. \return the provider's exit code. */
int bcp_exchange(const BCP_Request *request, const char *platform, const char *ticket);

/** Print "BCERROR <message>". \return 1 (exit code). */
int bcp_fail(const char *format, ...);

void bcp_hex(const uint8_t *data, size_t size, char *out);

#ifdef __cplusplus
}
#endif

#endif /* BC_PROVIDER_H */
