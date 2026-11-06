/* SPDX-License-Identifier: GPL-2.0-or-later */

/* Online content key (manifest flag BC_MANIFEST_ONLINE_KEY).
 *
 * The content key is not in any shipped file: a key server gives it to players who own the game.
 * The launcher only talks to the key provider, a separate program in the game folder written for
 * the store (Steam, Epic...) under any license, so it can link the store's proprietary SDK:
 *
 *   provider <key url or "-"> <key ids: hex, comma separated> <client public key hex> [game args]
 *
 * The provider proves ownership to the key server however the store requires, forwards the key
 * ids and the client public key, and prints the server's answer, one envelope (bc_envelope.h)
 * per key id in the same order, as lines of its standard output or error:
 *
 *   BCENVELOPE <160 hex digits>       one per key id, exit code 0
 *   BCERROR <message for the player>  failure, any exit code
 *
 * A game with a key per update has one key per update that still has files in it; only the keys
 * missing from the cache are asked for.
 *
 * Other output lines (store SDK logs) are ignored. The game executable's own arguments go to the
 * provider, never to the player: stores pass login tokens that way (Epic: -AUTH_PASSWORD=...).
 *
 * With BC_MANIFEST_KEY_CACHE the keys are kept on this computer after the first launch, so the
 * game also starts offline afterwards: protected with DPAPI on Windows (bound to the Windows
 * user), elsewhere with a key derived from the build key, the machine id and the user id. */

#ifndef BC_ONLINE_H
#define BC_ONLINE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "bc_manifest.h"

/** Seconds the provider may take: store logins can be slow, but a hung provider must not leave
 * the player staring at nothing forever. */
#define BC_PROVIDER_TIMEOUT 60
#define BC_PROVIDER_OUTPUT_MAX 65536

/** Fill \a r_keys with the m->key_count keys named by m->key_ids, in the same order. */
bool bc_online_keys(const char *game_dir,
                    const BC_Manifest *m,
                    int argc,
                    char **argv,
                    uint8_t r_keys[][BC_KEY_SIZE],
                    char *err,
                    size_t err_size);

#endif /* BC_ONLINE_H */
