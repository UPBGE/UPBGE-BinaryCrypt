#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reference key server for UPBGE-BinaryCrypt online keys.

Gives a game's content key to players who prove they own it, sealed for one launch of the game
(see common/bc_envelope.h). Protocol:

    POST /key  {"platform": "steam" | "epic" | "itch" | "meta" | "dev", "ticket": "...",
                "key_ids": ["<16 hex>", ...], "client_public": "<64 hex>"}
    200 {"envelopes": ["<160 hex>", ...]}       one per key id, same order
    4xx {"error": "<message shown to the player>"}

A game with a key per update has one key per update (its key file holds them all): a launch asks
for the keys its files use. Owners may get every key of their game.

Usage:
    python3 bc_keyserver.py config.json [--listen 127.0.0.1:8080] [--tls-cert C --tls-key K]

Requires Python 3.8+ and the "cryptography" package. Serve it over HTTPS: either give it a
certificate, or put it behind a TLS reverse proxy (Caddy, nginx). Configuration: see
keyserver.example.json and README.md.
"""

import argparse
import base64
import ctypes
import hashlib
import hmac
import json
import os
import re
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

KEY_ID_CONTEXT = b"UPBGE-BinaryCrypt key id v1"
ENVELOPE_CONTEXT = b"UPBGE-BinaryCrypt key envelope v1"
REQUEST_MAX = 64 * 1024


class Denied(Exception):
    """Ownership not proven. The message reaches the player."""


def key_id(key):
    """Same as bc_key_id(): keyed BLAKE2b, 8 bytes."""
    return hashlib.blake2b(KEY_ID_CONTEXT, digest_size=8, key=key).digest()


def seal(key, client_public):
    """Envelope for one launch: fresh X25519 pair, BLAKE2b key derivation, ChaCha20-Poly1305."""
    server = X25519PrivateKey.generate()
    server_public = server.public_key().public_bytes_raw()
    # Raises ValueError for a small order point (all zero shared secret).
    shared = server.exchange(X25519PublicKey.from_public_bytes(client_public))
    aead_key = hashlib.blake2b(ENVELOPE_CONTEXT + shared + client_public + server_public, digest_size=32).digest()
    return server_public + ChaCha20Poly1305(aead_key).encrypt(bytes(12), key, key_id(key))


def read_key_file(path):
    """All keys of a key file: the one key form (64 hex digits) or "key <update> <hex>" lines
    (common/bc_keyring.h; "file" lines are bc_tool's own bookkeeping, and lines with a keyword of
    a later bc_tool are skipped, as bc_tool does)."""
    with open(path, encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    hex_lines = [line for line in lines if all(c in "0123456789abcdefABCDEF " for c in line)]
    keys = [bytes.fromhex(line.split()[2]) for line in lines if line.split()[0] == "key"]
    if not keys and len(hex_lines) == 1:
        keys = [bytes.fromhex("".join(hex_lines[0].split()))]
    if not keys or any(len(key) != 32 for key in keys):
        raise ValueError(f"{path}: not a BinaryCrypt key file")
    return keys


# ------------------------------------------------------------------------------------------------
# Steam: Encrypted App Tickets, decrypted with Valve's sdkencryptedappticket library.


class SteamTickets:
    """Wraps sdkencryptedappticket (Steamworks SDK, redistributable_bin) through ctypes."""

    def __init__(self, library):
        lib = ctypes.CDLL(library)
        lib.SteamEncryptedAppTicket_BDecryptTicket.argtypes = [
            ctypes.c_char_p, ctypes.c_uint32, ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint32), ctypes.c_char_p, ctypes.c_int]
        lib.SteamEncryptedAppTicket_BDecryptTicket.restype = ctypes.c_bool
        for name in ("SteamEncryptedAppTicket_BIsTicketForApp", "SteamEncryptedAppTicket_BUserOwnsAppInTicket"):
            getattr(lib, name).argtypes = [ctypes.c_char_p, ctypes.c_uint32, ctypes.c_uint32]
            getattr(lib, name).restype = ctypes.c_bool
        lib.SteamEncryptedAppTicket_GetTicketIssueTime.argtypes = [ctypes.c_char_p, ctypes.c_uint32]
        lib.SteamEncryptedAppTicket_GetTicketIssueTime.restype = ctypes.c_uint32
        self.lib = lib
        self.lock = threading.Lock()

    def check(self, ticket_hex, config):
        try:
            ticket = bytes.fromhex(ticket_hex)
        except ValueError:
            raise Denied("invalid Steam ticket")
        ticket_key = bytes.fromhex(config["ticket_key"])
        app_id = int(config["app_id"])
        decrypted = ctypes.create_string_buffer(4096)
        size = ctypes.c_uint32(len(decrypted))
        with self.lock:  # The library makes no thread safety promise.
            if not self.lib.SteamEncryptedAppTicket_BDecryptTicket(ticket, len(ticket), decrypted, ctypes.byref(size), ticket_key, len(ticket_key)):
                raise Denied("invalid Steam ticket")
            if not self.lib.SteamEncryptedAppTicket_BIsTicketForApp(decrypted, size.value, app_id):
                raise Denied("the Steam ticket is for another game")
            if not self.lib.SteamEncryptedAppTicket_BUserOwnsAppInTicket(decrypted, size.value, app_id):
                raise Denied("this Steam account does not own the game")
            issued = self.lib.SteamEncryptedAppTicket_GetTicketIssueTime(decrypted, size.value)
        if time.time() - issued > float(config.get("max_age", 3600)):
            raise Denied("the Steam ticket is too old: restart Steam")


# ------------------------------------------------------------------------------------------------
# Epic: ownership verification tokens, JWTs signed RS512 with Epic's keys.

EPIC_KEY_URL = ("https://ecommerceintegration-public-service-ecomprod02.ol.epicgames.com"
                "/ecommerceintegration/api/public/publickeys/{kid}")


def b64url(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class EpicTokens:
    def __init__(self, key_url=EPIC_KEY_URL):
        self.key_url = key_url
        self.keys = {}
        self.lock = threading.Lock()

    def public_key(self, kid):
        with self.lock:
            if kid in self.keys:
                return self.keys[kid]
        with urllib.request.urlopen(self.key_url.format(kid=kid), timeout=10) as answer:
            jwk = json.loads(answer.read())
        key = rsa.RSAPublicNumbers(int.from_bytes(b64url(jwk["e"]), "big"), int.from_bytes(b64url(jwk["n"]), "big")).public_key()
        with self.lock:
            self.keys[kid] = key
        return key

    @staticmethod
    def owns(entitlement, item_ids):
        # The shape of "ent" entries is not publicly documented: accept an entry equal to a
        # catalog item id, or an object holding it as one of its values. Check with a real token.
        if isinstance(entitlement, str):
            return entitlement in item_ids
        if isinstance(entitlement, dict):
            return any(value in item_ids for value in entitlement.values() if isinstance(value, str))
        return False

    def check(self, token, config):
        parts = token.split(".")
        if len(parts) != 3:
            raise Denied("invalid Epic ownership token")
        try:
            header = json.loads(b64url(parts[0]))
            claims = json.loads(b64url(parts[1]))
            signature = b64url(parts[2])
        except ValueError:
            raise Denied("invalid Epic ownership token")
        kid = header.get("kid", "")
        if header.get("alg") != "RS512" or not re.fullmatch(r"[A-Za-z0-9_\-]{1,128}", kid):
            raise Denied("invalid Epic ownership token")
        try:
            self.public_key(kid).verify(signature, f"{parts[0]}.{parts[1]}".encode(), padding.PKCS1v15(), hashes.SHA512())
        except InvalidSignature:
            raise Denied("invalid Epic ownership token")
        now = time.time()
        if "exp" in claims and now > float(claims["exp"]) + 60:
            raise Denied("the Epic ownership token expired")
        if "iat" in claims and now - float(claims["iat"]) > float(config.get("max_age", 600)):
            raise Denied("the Epic ownership token is too old")
        if config.get("client_id") and claims.get("clid") != config["client_id"]:
            raise Denied("the Epic ownership token is for another product")
        item_ids = set(config.get("catalog_item_ids", []))
        if not any(self.owns(entitlement, item_ids) for entitlement in claims.get("ent") or []):
            raise Denied("this Epic account does not own the game")


# ------------------------------------------------------------------------------------------------
# Store APIs over HTTPS: itch.io and Meta.


def http_json(url, headers=None, form=None):
    """GET, or POST of form fields; returns (status, JSON object). An error status with a JSON body
    is an answer too (the stores explain refusals that way); anything else raises RuntimeError,
    which the player sees as "try again later"."""
    data = urllib.parse.urlencode(form).encode() if form is not None else None
    request = urllib.request.Request(url, data=data, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=10) as answer:
            status, raw = answer.status, answer.read()
    except urllib.error.HTTPError as error:
        status, raw = error.code, error.read()
    try:
        body = json.loads(raw)
    except ValueError:
        body = None
    if not isinstance(body, dict):
        raise RuntimeError(f"{url.split('?')[0]}: status {status}, no JSON object")
    return status, body


# itch.io: the key the itch app gives a game whose .itch.toml asks for scope "profile:me". It names
# the player's account; the developer's own API key then asks whether that account bought or
# claimed the game (download keys cover both).

ITCH_API = "https://api.itch.io"


class ItchKeys:
    def __init__(self, api=ITCH_API, fetch=http_json):
        self.api = api
        self.fetch = fetch

    def check(self, ticket, config):
        if not re.fullmatch(r"[A-Za-z0-9._\-]{8,8192}", ticket):
            raise Denied("invalid itch.io login: start the game from the itch app")
        status, answer = self.fetch(f"{self.api}/profile", {"Authorization": f"Bearer {ticket}"})
        user = answer.get("user") if status == 200 else None
        if not isinstance(user, dict) or not isinstance(user.get("id"), int):
            if status >= 500:
                raise RuntimeError(f"itch.io profile: {status}")
            raise Denied("the itch.io login expired: start the game from the itch app again")
        game_id = config["game_id"]
        query = urllib.parse.urlencode({"user_id": user["id"]})
        status, answer = self.fetch(f"{self.api}/games/{game_id}/download_keys?{query}",
                                    {"Authorization": f"Bearer {config['api_key']}"})
        key = answer.get("download_key") if status == 200 else None
        if isinstance(key, dict) and key.get("game_id") == game_id:
            return
        if "no download key found" in (answer.get("errors") or []):
            raise Denied("this itch.io account does not own the game")
        raise RuntimeError(f"itch.io download keys: {status} {answer.get('errors')}")


# Meta (Meta Horizon Store): the user id and a one-use nonce (user proof). Meta checks the nonce,
# which proves who the player is, then whether that account owns the app; the app secret signs both
# calls and never leaves the server. Both need the app's Data Use Checkup to grant "User ID" and
# "In-app purchases and/or downloadable content".

META_GRAPH = "https://graph.oculus.com"


class MetaUsers:
    def __init__(self, graph=META_GRAPH, fetch=http_json):
        self.graph = graph
        self.fetch = fetch

    def check(self, ticket, config):
        user_id, _, nonce = ticket.partition(":")
        if not re.fullmatch(r"[0-9]{1,20}", user_id) or not re.fullmatch(r"[\x21-\x7e]{1,1024}", nonce):
            raise Denied("invalid Meta user proof")
        app_id = config["app_id"]
        token = f"OC|{app_id}|{config['app_secret']}"
        status, answer = self.fetch(f"{self.graph}/user_nonce_validate",
                                    form={"access_token": token, "nonce": nonce, "user_id": user_id})
        if status != 200:
            raise RuntimeError(f"Meta user_nonce_validate: {status} {answer.get('error')}")
        if answer.get("is_valid") is not True:
            raise Denied("the Meta user proof was refused: start the game again")
        status, answer = self.fetch(f"{self.graph}/{app_id}/verify_entitlement",
                                    form={"access_token": token, "user_id": user_id})
        if status != 200:
            raise RuntimeError(f"Meta verify_entitlement: {status} {answer.get('error')}")
        if answer.get("success") is not True:
            raise Denied("this Meta account does not own the game")


# ------------------------------------------------------------------------------------------------
# Server


class Game:
    def __init__(self, config, base_dir):
        self.name = config.get("name", "game")
        self.keys = {key_id(key): key for key in read_key_file(os.path.join(base_dir, config["key_file"]))}
        self.steam = config.get("steam")
        self.epic = config.get("epic")
        self.itch = config.get("itch")
        self.meta = config.get("meta")
        self.dev_tokens = config.get("dev_tokens", [])
        # Checked once here: a wrong setting stops the server, not a player.
        if self.itch and not (isinstance(self.itch.get("game_id"), int) and self.itch.get("api_key")):
            raise ValueError(f"{self.name}: itch needs an integer game_id and an api_key")
        if self.meta and not (re.fullmatch(r"[0-9]{1,20}", str(self.meta.get("app_id", ""))) and self.meta.get("app_secret")):
            raise ValueError(f"{self.name}: meta needs app_id (digits) and app_secret")
        if self.meta:
            self.meta = dict(self.meta, app_id=str(self.meta["app_id"]))


class KeyServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, config, base_dir, quiet=False):
        self.games = {}
        for entry in config["games"]:
            self.add_game(Game(entry, base_dir))
        libraries = {entry["steam"]["library"] for entry in config["games"] if entry.get("steam")}
        self.steam = {library: SteamTickets(library) for library in libraries}
        self.epic = EpicTokens(config.get("epic_key_url", EPIC_KEY_URL))
        self.itch = ItchKeys()
        self.meta = MetaUsers()
        self.quiet = quiet
        super().__init__(address, Handler)

    def add_game(self, game):
        for game_key_id in game.keys:
            self.games[game_key_id] = game

    def verify(self, game, platform, ticket):
        if platform == "steam" and game.steam:
            self.steam[game.steam["library"]].check(ticket, game.steam)
        elif platform == "epic" and game.epic:
            self.epic.check(ticket, game.epic)
        elif platform == "itch" and game.itch:
            self.itch.check(ticket, game.itch)
        elif platform == "meta" and game.meta:
            self.meta.check(ticket, game.meta)
        elif platform == "dev" and game.dev_tokens:
            if not any(hmac.compare_digest(ticket.encode(), token.encode()) for token in game.dev_tokens):
                raise Denied("access denied")
        else:
            raise Denied(f"this game is not sold on '{platform}'")


class Handler(BaseHTTPRequestHandler):
    server_version = "UPBGE-BinaryCrypt-keyserver/1"

    def reply(self, status, **body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        if self.path.split("?")[0] != "/key":
            return self.reply(404, error="not found")
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > REQUEST_MAX:
            return self.reply(413, error="request too large")
        try:
            request = json.loads(self.rfile.read(length))
            platform = str(request["platform"])
            ticket = str(request["ticket"])
            key_ids = [bytes.fromhex(value) for value in request["key_ids"]]
            client_public = bytes.fromhex(request["client_public"])
            if not 1 <= len(key_ids) <= 64 or any(len(value) != 8 for value in key_ids) or len(client_public) != 32:
                raise ValueError
        except (ValueError, KeyError, TypeError):
            return self.reply(400, error="invalid request")
        games = {self.server.games.get(value) for value in key_ids}
        if None in games or len(games) != 1:
            return self.reply(404, error="this game (or this update of it) is not served by this key server")
        game = games.pop()
        try:
            self.server.verify(game, platform, ticket)
            envelopes = [seal(game.keys[value], client_public).hex() for value in key_ids]
        except Denied as denied:
            self.log_message("%s %s: denied (%s)", game.name, platform, denied)
            return self.reply(403, error=str(denied))
        except ValueError:
            return self.reply(400, error="invalid request")
        except Exception as error:  # A store's key endpoint down, a broken library...
            self.log_message("%s %s: error %r", game.name, platform, error)
            return self.reply(503, error="the key server cannot check ownership right now: try again later")
        self.log_message("%s %s: %d key(s) sent", game.name, platform, len(envelopes))
        return self.reply(200, envelopes=envelopes)

    def log_message(self, format, *args):
        if not self.server.quiet:
            sys.stderr.write("%s %s\n" % (self.address_string(), format % args))


def main():
    parser = argparse.ArgumentParser(description="UPBGE-BinaryCrypt reference key server")
    parser.add_argument("config", help="JSON configuration (see keyserver.example.json)")
    parser.add_argument("--listen", default="127.0.0.1:8080", help="address:port (default 127.0.0.1:8080)")
    parser.add_argument("--tls-cert", help="certificate chain (PEM) to serve HTTPS directly")
    parser.add_argument("--tls-key", help="private key (PEM) of the certificate")
    args = parser.parse_args()

    with open(args.config, encoding="utf-8") as f:
        config = json.load(f)
    host, port = args.listen.rsplit(":", 1)
    server = KeyServer((host, int(port)), config, os.path.dirname(os.path.abspath(args.config)))
    if args.tls_cert:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(args.tls_cert, args.tls_key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    for game in {id(game): game for game in server.games.values()}.values():
        platforms = [name for name, on in (("steam", game.steam), ("epic", game.epic), ("itch", game.itch),
                                           ("meta", game.meta), ("dev", game.dev_tokens)) if on]
        print(f"{game.name}: {len(game.keys)} key(s), {', '.join(platforms) or 'no platform'}")
    print(f"listening on {'https' if args.tls_cert else 'http'}://{args.listen}/key")
    server.serve_forever()


if __name__ == "__main__":
    main()
