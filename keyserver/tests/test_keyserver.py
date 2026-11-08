# SPDX-License-Identifier: MIT
"""Tests for the reference key server, and the whole online key chain when the environment names
the binaries: BC_TOOL, BC_PLAYER (bc_fake_player), BC_PROVIDER_DEV, BC_TEST_WORK."""

import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import threading
import time
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import bc_keyserver as ks  # noqa: E402

from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding, rsa  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305  # noqa: E402

KEY = bytes(range(32))
KEY2 = bytes(range(100, 132))


def open_envelope(envelope, game_key_id, client_secret):
    """Launcher side, written independently of the server code."""
    client = X25519PrivateKey.from_private_bytes(client_secret)
    client_public = client.public_key().public_bytes_raw()
    shared = client.exchange(X25519PublicKey.from_public_bytes(envelope[:32]))
    aead_key = hashlib.blake2b(ks.ENVELOPE_CONTEXT + shared + client_public + envelope[:32], digest_size=32).digest()
    return ChaCha20Poly1305(aead_key).decrypt(bytes(12), envelope[32:], game_key_id)


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class EnvelopeTest(unittest.TestCase):
    def test_round_trip(self):
        secret = os.urandom(32)
        public = X25519PrivateKey.from_private_bytes(secret).public_key().public_bytes_raw()
        envelope = ks.seal(KEY, public)
        self.assertEqual(len(envelope), 80)
        self.assertEqual(open_envelope(envelope, ks.key_id(KEY), secret), KEY)

    def test_small_order_point(self):
        with self.assertRaises(ValueError):
            ks.seal(KEY, bytes(32))


class EpicTest(unittest.TestCase):
    def setUp(self):
        self.signing = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.epic = ks.EpicTokens()
        self.epic.public_key = lambda kid: self.signing.public_key()
        self.config = {"client_id": "client", "catalog_item_ids": ["item"], "max_age": 600}

    def token(self, claims, alg="RS512"):
        head = b64url(json.dumps({"alg": alg, "kid": "k1", "typ": "JWT"}).encode())
        body = b64url(json.dumps(claims).encode())
        signature = self.signing.sign(f"{head}.{body}".encode(), padding.PKCS1v15(), hashes.SHA512())
        return f"{head}.{body}.{b64url(signature)}"

    def claims(self, **extra):
        claims = {"sub": "account", "clid": "client", "ent": [{"catalogItemId": "item"}], "iat": time.time()}
        claims.update(extra)
        return claims

    def test_owner(self):
        self.epic.check(self.token(self.claims()), self.config)
        self.epic.check(self.token(self.claims(ent=["item"])), self.config)

    def test_refusals(self):
        cases = [
            self.token(self.claims(ent=[])),
            self.token(self.claims(ent=[{"catalogItemId": "other"}])),
            self.token(self.claims(clid="someone else")),
            self.token(self.claims(iat=time.time() - 3600)),
            self.token(self.claims(exp=time.time() - 120)),
            self.token(self.claims(), alg="none"),
            self.token(self.claims())[:-4] + "AAAA",
            "not.a token",
        ]
        for token in cases:
            with self.assertRaises(ks.Denied):
                self.epic.check(token, self.config)


class ServerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = os.path.join(os.environ.get("BC_TEST_WORK", "/tmp"), "keyserver_unit")
        shutil.rmtree(cls.dir, ignore_errors=True)
        os.makedirs(cls.dir)
        with open(os.path.join(cls.dir, "game.key"), "w") as f:
            f.write(KEY.hex() + "\n")
        # A key per update: the bc_tool key file form, with its file records, and a line with a
        # keyword of a later bc_tool, which must be skipped.
        with open(os.path.join(cls.dir, "updates.key"), "w") as f:
            f.write(f"# comment\nkey 1 {KEY2.hex()}\nkey 2 {bytes(32).hex()}\nfile 1 {bytes(32).hex()} levels/a b.blend\n"
                    "label 2 Winter update\n")
        config = {"games": [{"name": "Test", "key_file": "game.key", "dev_tokens": ["letmein"]},
                            {"name": "Updated", "key_file": "updates.key", "dev_tokens": ["letmein"]}]}
        cls.server = ks.KeyServer(("127.0.0.1", 0), config, cls.dir, quiet=True)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.server.server_address[1]}/key"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def post(self, body):
        request = urllib.request.Request(self.url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=10) as answer:
                return answer.status, json.loads(answer.read())
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read())

    def test_protocol(self):
        secret = os.urandom(32)
        public = X25519PrivateKey.from_private_bytes(secret).public_key().public_bytes_raw()
        request = {"platform": "dev", "ticket": "letmein", "key_ids": [ks.key_id(KEY).hex()], "client_public": public.hex()}
        status, answer = self.post(request)
        self.assertEqual(status, 200)
        self.assertEqual(open_envelope(bytes.fromhex(answer["envelopes"][0]), ks.key_id(KEY), secret), KEY)
        self.assertEqual(self.post(dict(request, ticket="wrong"))[0], 403)
        self.assertEqual(self.post(dict(request, platform="steam"))[0], 403)
        self.assertEqual(self.post(dict(request, key_ids=["00" * 8]))[0], 404)
        self.assertEqual(self.post(dict(request, key_ids=[]))[0], 400)
        # Several keys of one game, answered in the order asked.
        ids = [ks.key_id(bytes(32)), ks.key_id(KEY2)]
        status, answer = self.post(dict(request, key_ids=[value.hex() for value in ids]))
        self.assertEqual(status, 200)
        self.assertEqual([open_envelope(bytes.fromhex(e), i, secret) for e, i in zip(answer["envelopes"], ids)], [bytes(32), KEY2])
        # Keys of two different games are never mixed in one answer.
        self.assertEqual(self.post(dict(request, key_ids=[ks.key_id(KEY).hex(), ks.key_id(KEY2).hex()]))[0], 404)
        self.assertEqual(self.post(dict(request, client_public="zz"))[0], 400)
        self.assertEqual(self.post(dict(request, client_public="00" * 32))[0], 400)  # Small order point.


@unittest.skipUnless(os.environ.get("BC_PROVIDER_DEV"), "BC_TOOL, BC_PLAYER and BC_PROVIDER_DEV not given")
class ChainTest(unittest.TestCase):
    """bc_tool export, then: launcher -> bc_provider_dev -> this key server -> launcher -> player."""

    def export(self, work):
        export = subprocess.run([os.environ["BC_TOOL"], "--batch", os.path.join(work, "game.bcproj")], capture_output=True, text=True)
        self.assertEqual(export.returncode, 0, export.stdout + export.stderr)

    def run_game(self, token, **env):
        environment = dict(os.environ, BC_DEV_TOKEN=token, BC_TEST_EXPECTED=self.source, **env)
        return subprocess.run([self.game], capture_output=True, text=True, env=environment, timeout=120)

    def test_chain(self):
        work = os.path.join(os.environ.get("BC_TEST_WORK", "/tmp"), "keyserver_chain")
        shutil.rmtree(work, ignore_errors=True)
        os.makedirs(os.path.join(work, "src"))
        os.makedirs(os.path.join(work, "dist", "engine"))
        self.source = os.path.join(work, "src", "game.blend")
        with open(self.source, "wb") as f:
            f.write(b"BLENDER-v405" + os.urandom(150000))
        for binary in ("BC_PLAYER", "BC_PROVIDER_DEV"):
            shutil.copy2(os.environ[binary], os.path.join(work, "dist", "engine"))
        player = os.path.basename(os.environ["BC_PLAYER"])
        provider = os.path.basename(os.environ["BC_PROVIDER_DEV"])

        # The key server address is known before the export: bind first, serve later.
        server = ks.KeyServer(("127.0.0.1", 0), {"games": []}, work, quiet=True)
        url = f"http://127.0.0.1:{server.server_address[1]}/key"
        with open(os.path.join(work, "game.bcproj"), "w") as f:
            f.write(f"version = 1\nsource_root = src\noutput_dir = dist\ngame_name = game\n"
                    f"player = engine/{player}\nmain = src/game.blend\ninput = src\n"
                    f"key = online\nkey_file = game.key\nkey_provider = engine/{provider}\nkey_url = {url}\n")
        self.export(work)
        self.game = os.path.join(work, "dist", "game" + (".exe" if os.name == "nt" else ""))

        server.add_game(ks.Game({"name": "game", "key_file": "game.key", "dev_tokens": ["letmein"]}, work))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            run = self.run_game("letmein")
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertIn("decrypted correctly", run.stdout + run.stderr)
            run = self.run_game("wrong")
            self.assertNotEqual(run.returncode, 0)
            self.assertIn("access denied", run.stderr)

            # Key per update: update 2 changes a level, the game then needs both keys in one go.
            os.makedirs(os.path.join(work, "src", "levels"))
            level = os.path.join(work, "src", "levels", "one.blend")
            with open(level, "wb") as f:
                f.write(b"BLENDER-v405" + os.urandom(70000))
            with open(os.path.join(work, "game.bcproj"), "a") as f:
                f.write("key_rotation = per_update\nkey_update = 1\n")
            self.export(work)
            with open(level, "ab") as f:
                f.write(b"update 2")
            with open(os.path.join(work, "game.bcproj"), "a") as f:
                f.write("key_update = 2\n")
            self.export(work)
            server.add_game(ks.Game({"name": "game", "key_file": "game.key", "dev_tokens": ["letmein"]}, work))
            run = self.run_game("letmein")
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertIn("decrypted correctly", run.stdout + run.stderr)
        finally:
            server.shutdown()
            server.server_close()
        run = self.run_game("letmein")
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("cannot reach the key server", run.stderr)


if __name__ == "__main__":
    unittest.main()
