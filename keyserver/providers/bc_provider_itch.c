/* SPDX-License-Identifier: MIT */

/* itch.io key provider: proves ownership with the player's itch.io login.
 *
 * The itch app starts the game with ITCHIO_API_KEY set (a key for this game and this session)
 * when the game's .itch.toml asks for it:
 *
 *   [[actions]]
 *   name = "play"
 *   path = "MyGame.exe"
 *   scope = "profile:me"
 *
 * The game executable passes its environment to the provider, which sends the key to the key
 * server. The server finds the player's itch.io account with it, then asks itch.io, with the
 * developer's own API key, whether that account bought or claimed the game (bc_keyserver.py,
 * "itch" section). Games downloaded from the itch.io web page and started without the app have no
 * key: they cannot start.
 *
 * No SDK: always built. */

#include <stdlib.h>

#include "bc_provider.h"

#ifndef BCP_ITCH_KEY_URL
#  define BCP_ITCH_KEY_URL NULL /* Or bake your key server in: -DBCP_ITCH_KEY_URL="\"https://...\"" */
#endif

int main(int argc, char **argv)
{
  BCP_Request request;
  if (!bcp_parse_args(argc, argv, BCP_ITCH_KEY_URL, &request)) {
    return 1;
  }
  const char *key = getenv("ITCHIO_API_KEY");
  if (key == NULL || key[0] == '\0') {
    return bcp_fail("start the game from the itch app: it gives the game your itch.io login");
  }
  return bcp_exchange(&request, "itch", key);
}
