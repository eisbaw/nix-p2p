#!/usr/bin/env python3
"""Shared narinfo/signing/serving helpers for the fixture generator and gate.

Both scripts/gen-fixtures.py (writes the fixture cache) and
scripts/check-fixtures.py (proves it bites) need to parse narinfos, compute
Nix's signature fingerprint and sign with the test key. Those three things
must agree exactly or the gate would be testing its own bugs, so they live
here once rather than twice.

The test signing key is DERIVED from the seed phrase below rather than stored
as a key file. Be precise about what that buys, because it is easy to
misread: the seed phrase IS committed, so the private key is fully
reconstructible by anyone holding this repository. It is not secret and must
never be treated as such. What derivation avoids is a committed
high-entropy base64 blob - the thing secret scanners flag, mirrors copy and
downstream forks have to special-case forever - in a repo that runs a
`secret-scan` policy. Determinism is unaffected: ed25519 public keys and
signatures are functions of the seed, and fixtures/workload.lock.json pins the
resulting public key so drift in the derivation is a hard failure.
"""

from __future__ import annotations

import base64
import functools
import hashlib
import http.server
import threading
from contextlib import contextmanager
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

# The key name appears verbatim in every fixture Sig line and in the harness's
# trusted-public-keys. It is deliberately unlike any real cache key name.
KEY_NAME = "nix-p2p-test-1"
KEY_SEED_PHRASE = b"nix-p2p UNSAFE TEST ONLY fixture signing key v1"
# The derived public key is deliberately NOT pinned here. A constant sitting
# two lines below the seed it is derived from only catches an edit to one of
# them, and any coordinated edit sails past it. fixtures/workload.lock.json
# holds the pin instead: it is committed, external to this derivation, and
# readable by task-5's container nix.conf without importing Python.

# A second, deliberately untrusted keypair. Used by the gate to forge a
# well-formed signature from a key the client does not trust - the exact
# shape of a hostile mirror. Never written into the fixture cache.
FOREIGN_KEY_NAME = "nix-p2p-foreign-1"
FOREIGN_SEED_PHRASE = b"nix-p2p UNSAFE TEST ONLY foreign attacker key v1"

# The fixture pins StoreDir in nix-cache-info; References fields in narinfos
# are basenames and must be re-prefixed with it to rebuild the fingerprint.
STORE_DIR = "/nix/store"


def repo_root() -> Path:
    """Workspace root, derived from this file's location (scripts/ lives in it)."""
    return Path(__file__).resolve().parent.parent


def keypair(seed_phrase: bytes = KEY_SEED_PHRASE, name: str = KEY_NAME):
    """Return (name, private_key, nix_secret_line, nix_public_line).

    Nix's on-disk key format is `<name>:<base64>`, where the secret's base64
    payload is libsodium's 64-byte secret key (32-byte seed || 32-byte public
    key) and the public one is the bare 32-byte public key.
    """
    seed = hashlib.sha256(seed_phrase).digest()
    private = Ed25519PrivateKey.from_private_bytes(seed)
    public_raw = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    secret_line = f"{name}:{base64.b64encode(seed + public_raw).decode()}"
    public_line = f"{name}:{base64.b64encode(public_raw).decode()}"
    return name, private, secret_line, public_line


def parse_narinfo(text: str) -> list[tuple[str, str]]:
    """Parse a narinfo into ordered (key, value) pairs.

    Order is preserved because the gate rewrites narinfos and a reordered file
    would be a second, uncontrolled difference from the pristine fixture.
    """
    pairs = []
    for line in text.splitlines():
        if not line.strip():
            continue
        key, sep, value = line.partition(": ")
        if not sep:
            raise ValueError(f"malformed narinfo line: {line!r}")
        pairs.append((key, value))
    return pairs


def format_narinfo(pairs: list[tuple[str, str]]) -> str:
    return "".join(f"{k}: {v}\n" for k, v in pairs)


def field(pairs: list[tuple[str, str]], key: str) -> str:
    for k, v in pairs:
        if k == key:
            return v
    raise KeyError(f"narinfo has no {key} field")


def replace_field(
    pairs: list[tuple[str, str]], key: str, value: str
) -> list[tuple[str, str]]:
    if not any(k == key for k, _ in pairs):
        raise KeyError(f"narinfo has no {key} field to replace")
    return [(k, value if k == key else v) for k, v in pairs]


def fingerprint(pairs: list[tuple[str, str]]) -> bytes:
    """Rebuild the string Nix signs: 1;<path>;<narHash>;<narSize>;<refs>.

    References are stored in the narinfo as basenames and signed as absolute
    store paths - getting that wrong yields signatures that verify nowhere,
    so the gate's positive control is what proves this function correct.
    """
    refs = [r for r in field(pairs, "References").split() if r]
    return ";".join(
        [
            "1",
            field(pairs, "StorePath"),
            field(pairs, "NarHash"),
            field(pairs, "NarSize"),
            ",".join(f"{STORE_DIR}/{r}" for r in refs),
        ]
    ).encode()


def sign_narinfo(
    pairs: list[tuple[str, str]], private: Ed25519PrivateKey, name: str
) -> list[tuple[str, str]]:
    """Replace the Sig field with a fresh signature over the current fields."""
    sig = base64.b64encode(private.sign(fingerprint(pairs))).decode()
    return replace_field(pairs, "Sig", f"{name}:{sig}")


def verify_narinfo(pairs: list[tuple[str, str]], public_line: str) -> bool:
    """True iff the narinfo's single Sig verifies against `public_line`."""
    name, _, b64 = public_line.partition(":")
    public = Ed25519PublicKey.from_public_bytes(base64.b64decode(b64))
    sig_name, _, sig_b64 = field(pairs, "Sig").partition(":")
    if sig_name != name:
        return False
    try:
        public.verify(base64.b64decode(sig_b64), fingerprint(pairs))
    except InvalidSignature:
        return False
    return True


class _QuietHandler(http.server.SimpleHTTPRequestHandler):
    """SimpleHTTPRequestHandler without the per-request stderr noise."""

    def log_message(self, fmt, *args):  # noqa: A002 - signature fixed by stdlib
        pass


@contextmanager
def static_server(directory: Path):
    """Serve `directory` over HTTP on an ephemeral loopback port.

    A Nix binary cache is nothing but static files, so the mock upstream needs
    nothing more than this. Yielding the base URL (not a fixed port) keeps
    concurrent gate runs from colliding.
    """
    handler = functools.partial(_QuietHandler, directory=str(directory))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
