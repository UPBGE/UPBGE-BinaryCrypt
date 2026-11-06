# Key server and key providers (reference, MIT)

Everything needed to ship a UPBGE-BinaryCrypt game with an **online key** (`key = online` in the
project): the content key is in no shipped file, a key server gives it to players who prove they
own the game. This folder is MIT licensed, unlike the rest of the repository, so that a provider
can link a store's proprietary SDK (Steamworks, EOS), which a GPL program cannot.

```
game executable ──runs──> key provider ──HTTPS──> key server
 (launcher)       <─envelope──          <─envelope──
```

1. The game executable (launcher) makes a fresh X25519 key pair and starts the **provider** named
   in its manifest.
2. The provider obtains a proof of ownership from the store (Steam ticket, Epic token) and sends
   it to the **key server** together with the game's key id and the launcher's public key.
3. The key server checks the proof and answers with the content key sealed for that public key
   (an *envelope*). Only that launch of the game can open it: the provider, a proxy, or anyone
   reading the HTTPS traffic with a forged root certificate sees nothing usable.

| File | What it is |
|---|---|
| `bc_keyserver.py` | Key server: Steam, Epic and development tokens. Python 3.8+ with `cryptography` (40 or newer). |
| `keyserver.example.json` | Its configuration. |
| `providers/bc_provider_steam.cpp` | Steam provider (Encrypted App Tickets). |
| `providers/bc_provider_epic.c` | Epic Games Store provider (EOS ownership tokens). |
| `providers/bc_provider_dev.c` | Development provider: a shared token, no store. |
| `providers/bc_provider.c` | Shared provider code: protocol, HTTPS (WinHTTP on Windows, libcurl elsewhere). |
| `tests/test_keyserver.py` | Tests, including the whole chain with the real launcher. |

## Status

| Part | Tested |
|---|---|
| Envelope, launcher side, key cache, provider protocol | Yes: Linux, Windows (Wine), with the launcher. |
| Key server: protocol, development tokens | Yes: Python tests, and the whole chain launcher → `bc_provider_dev` → server on Linux (libcurl) and Windows (WinHTTP under Wine). |
| Key server: Epic token checks | Signature, expiry, client id and entitlement logic tested with tokens signed by the tests. **Not tested with a real Epic token**: the exact shape of the `ent` entries is not publicly documented, `EpicTokens.owns()` accepts both plain ids and objects holding the id. Check it with a real token. |
| Key server: Steam ticket checks | Calls Valve's documented functions; **not tested** (needs the Steamworks SDK library). |
| `bc_provider_steam`, `bc_provider_epic` | Written against the SDKs' documented APIs and syntax checked; **not built against the real SDKs** (not redistributable). Build and test them with your SDK before shipping. |

## Setting up a game

1. **Project.** In `bc_tool`, set *Key* to *Online*; the *Key file* is created on the first
   export, next to the project file unless you choose another place outside the game folder. Set
   the *Provider* (for example `engine/bc_provider_steam.exe`, copied into the game folder
   beforehand) and the server *URL*.
   *Offline after 1st launch* keeps the keys on the player's computer after one successful launch.
   Copy the provider and the store's libraries (`steam_api64.dll`, `EOSSDK-Win64-Shipping.dll`...)
   into the game folder **before exporting**: with the integrity check (libraries by default) the
   game refuses libraries added or changed after the export. Shipping these libraries next to a
   GPL game is mere aggregation, which the GPL permits: only the provider, a separate MIT program,
   loads them, never the launcher or the player, and they are needed only with an online key.
   *New key per update* gives every published update its own key (see the main README).
2. **Key server.** Copy the key file to the server and list the game in the configuration:

   ```json
   {"games": [{"name": "My Game", "key_file": "keys/mygame.key",
               "steam": {...}, "epic": {...}}]}
   ```

   The key file is the only copy of the content keys: **back it up**. Without it, no update of the
   published game can ever be encrypted for the players who already own it. With a key per update,
   copy it to the server again after exporting each new update, before publishing it: the server
   reads every `key` line of the file (the `file` lines are `bc_tool`'s bookkeeping).
3. **Run it over HTTPS:**
   `python3 bc_keyserver.py config.json --listen 0.0.0.0:8443 --tls-cert fullchain.pem --tls-key privkey.pem`,
   or keep the default `127.0.0.1:8080` behind a TLS reverse proxy (Caddy, nginx). It prints the
   number of keys of every game. Restart it after installing an updated key file.

### Steam

- On the *Encrypted App Ticket Key* page of your app's App Admin in Steamworks, generate the key
  and put it (64 hex digits) in the `steam.ticket_key` field. Never ship it.
- `steam.library`: Valve's `sdkencryptedappticket` library for the server's platform, from the
  Steamworks SDK (under `public/steam/lib/`).
- Build the provider: `cmake -S keyserver/providers -B build-providers -DBCP_STEAMWORKS_SDK=<sdk>`,
  then copy `bc_provider_steam(.exe)` and `steam_api64.dll` / `libsteam_api.so` into the game
  folder. To test outside Steam, put a `steam_appid.txt` with your app id in the game folder (never
  ship it).
- Steam allows one ticket request per minute; a relaunch within that minute reuses the previous
  ticket (`max_age` must allow it, default one hour).

### Epic Games Store

- Build the provider with your product's values from the Epic Developer Portal:
  `-DBCP_EOS_SDK=<SDK> -DBCP_EPIC_PRODUCT_ID=... -DBCP_EPIC_SANDBOX_ID=... -DBCP_EPIC_DEPLOYMENT_ID=...
  -DBCP_EPIC_CLIENT_ID=... -DBCP_EPIC_CLIENT_SECRET=... -DBCP_EPIC_CATALOG_ITEM_ID=...`
  (client credentials of a *GameClient* policy, which are meant to ship in games). Copy
  `EOSSDK-Win64-Shipping.dll` next to it.
- The Epic launcher passes `-AUTH_PASSWORD=<exchange code>` to the game executable, which forwards
  its arguments to the provider (never to the player).
- Server: `epic.client_id` and `epic.catalog_item_ids`. Tokens are verified with Epic's public keys
  (RS512), fetched once per key id.

### Your own store or license system

Copy `bc_provider_dev.c`, send whatever proves ownership (for example a license key the player
typed in a small dialog) as the `ticket` with a platform name of your own, and add the check to
`KeyServer.verify` in `bc_keyserver.py`.

## Protocol

**Launcher → provider** (command line; working directory is the game folder):

```
provider <key server URL or "-"> <key ids: 16 hex each, comma separated> <client public key: 64 hex> [game arguments...]
```

A game with a key per update asks for several keys at once (only those missing from the cache).
The provider prints, on standard output or error, one `BCENVELOPE` line per key id in the same
order, or one `BCERROR` line; the launcher ignores every other line (store SDK logs):

```
BCENVELOPE <160 hex digits>         one per key id, success
BCERROR <message for the player>    failure
```

The launcher waits at most 60 seconds.

**Provider → key server:** `POST <URL>`, `Content-Type: application/json`:

```json
{"platform": "steam", "ticket": "<proof>", "key_ids": ["<16 hex>", "..."], "client_public": "<64 hex>"}
```

Answer `200 {"envelopes": ["<160 hex>", "..."]}` (same order as `key_ids`, all keys of one game),
or an error status with `{"error": "<message for the player>"}`.

**Envelope** (80 bytes) = server public key B (32) ‖ encrypted content key (32) ‖ tag (16):

```
s   = X25519(b, A)                      refused if all zero
k   = BLAKE2b-256("UPBGE-BinaryCrypt key envelope v1" ‖ s ‖ A ‖ B)
out = ChaCha20-Poly1305 (RFC 8439)(k, nonce = 12 zero bytes, ad = key id, content key)
```

`key id` = keyed BLAKE2b-64 of `"UPBGE-BinaryCrypt key id v1"` with the content key
(`bc_key_id`). `bc_keyserver.seal()` is the reference implementation, 6 lines of Python.

## Limits

- Every player downloads the same files from the store, so every player gets the same content key.
  A player who owns the game can extract it from memory while the game runs and share it; nothing
  on the client side prevents that. What the online key adds: the key is not in any shipped file
  (no extraction without buying the game), and it belongs to the project instead of the
  BinaryCrypt build.
- With one key, revoking a leaked key means encrypting the game again with a new key file and
  publishing an update. With a key per update, every update already brings a new key for what it
  changes: a leaked key keeps opening only the files it was used for.
- The reference server has no rate limiting: put it behind a proxy that has some.
