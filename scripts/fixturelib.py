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
import json
import os
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

# Dropped into every generated tree. Nothing without it is ever deleted or
# renamed away, so pointing --out at a directory that matters cannot destroy it.
OUT_MARKER = ".nix-p2p-fixture-out"

# Tiers are a property of the WORKLOAD, so they live in the lock rather than in
# the generator: the gate has to know which payloads a given tier must contain
# in order to reject a tree that is missing one. Without that, a shrunken plan
# or a partially published tree verifies whatever it happens to hold.
TIER_FAST = "fast"
TIER_FULL = "full"
TIERS = (TIER_FAST, TIER_FULL)

NIX_BASE32_ALPHABET = "0123456789abcdfghijklmnpqrsvwxyz"


def repo_root() -> Path:
    """Workspace root, derived from this file's location (scripts/ lives in it)."""
    return Path(__file__).resolve().parent.parent


def lock_path(repo: Path) -> Path:
    return repo / "fixtures" / "workload.lock.json"


class LockError(Exception):
    """The committed lock is unusable, so nothing can be proven against it."""


def load_lock(repo: Path) -> dict:
    """Read AND validate the lock. An unusable lock is never a soft signal.

    Validation belongs here rather than at each use site because the lock is
    the definition of the frozen workload: a field this file does not
    understand cannot be allowed to mean "no constraint". A misspelled tier
    (`fasst`) used to do exactly that - `expected_attrs` matched it against
    neither tier, so the payload silently dropped out of the fast tier's
    required set and a tree missing it verified green.
    """
    path = lock_path(repo)
    try:
        lock = json.loads(path.read_text())
    except OSError as exc:
        raise LockError(f"cannot read {path}: {exc}") from exc
    except ValueError as exc:
        raise LockError(f"{path} is not valid JSON: {exc}") from exc

    for key in ("workload_version", "public_key", "paths"):
        if key not in lock:
            raise LockError(f"{path} has no {key!r}")
    if not isinstance(lock["paths"], dict) or not lock["paths"]:
        raise LockError(f"{path} pins no payloads")
    for attr, pinned in lock["paths"].items():
        missing = [
            k
            for k in ("store_path", "compression", "nar_hash", "file_hash", "tier")
            if k not in pinned
        ]
        if missing:
            raise LockError(f"{path}: payload {attr!r} is missing {missing}")
        if pinned["tier"] not in TIERS:
            raise LockError(
                f"{path}: payload {attr!r} declares tier {pinned['tier']!r}, which is "
                f"not one of {list(TIERS)}. An unknown tier would quietly excuse the "
                "payload from every tier's required set."
            )
    return lock


def expected_attrs(lock: dict, tier: str) -> set[str]:
    """Payload names a tree of `tier` must contain - no more, no fewer.

    `full` is a superset of `fast`, so a full tree owes every payload. Tier
    values are validated in load_lock, so an unrecognised one can never reach
    this comparison and silently match nothing.
    """
    if tier not in TIERS:
        raise ValueError(f"unknown tier {tier!r}")
    if tier == TIER_FULL:
        return set(lock["paths"])
    return {a for a, p in lock["paths"].items() if p["tier"] == TIER_FAST}


def nix_base32(data: bytes) -> str:
    """Nix's base32 (its own alphabet, emitted most-significant-first).

    Needed to turn a recomputed SHA-256 back into the `sha256:<52 chars>` form
    a narinfo carries, so a NAR blob on disk can be checked against the hash
    that is pinned for it.
    """
    length = (len(data) * 8 - 1) // 5 + 1
    out = []
    for n in range(length - 1, -1, -1):
        bit = n * 5
        byte, offset = divmod(bit, 8)
        value = data[byte] >> offset
        if byte + 1 < len(data):
            value |= data[byte + 1] << (8 - offset)
        out.append(NIX_BASE32_ALPHABET[value & 0x1F])
    return "".join(out)


def file_hash_of(path: Path) -> str:
    """`sha256:<nix-base32>` of a file, in the form narinfos use."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return "sha256:" + nix_base32(digest.digest())


# Fixed metadata for every generated file. Without this the tree's modes are
# whatever the developer's umask happened to be (022 -> 644/755, 077 ->
# 600/700), so two "byte-identical" trees could differ to rsync, tar, a
# container image build, or a static server deciding a file is unreadable.
# mtime 1 mirrors what Nix itself canonicalises store paths to.
TREE_FILE_MODE = 0o644
TREE_DIR_MODE = 0o755
TREE_SECRET_MODE = 0o600
TREE_MTIME = 1


def normalise_tree(root: Path, secret_names: frozenset[str] = frozenset()) -> None:
    """Make the tree's metadata a function of the workload, not of the umask.

    The contract this file promises consumers is byte-for-byte reproducibility
    of a served binary cache. Contents alone were normalised before; modes and
    mtimes were inherited from the process umask, so the same workload produced
    different trees under `umask 022` and `umask 077`. Normalising is cheap and
    keeps the promise whole, which matters as soon as anything copies the tree
    with rsync/tar rather than reading it over HTTP.
    """
    for path in sorted(root.rglob("*"), reverse=True):
        if path.is_symlink():
            raise ValueError(f"unexpected symlink in generated tree: {path}")
        if path.is_dir():
            path.chmod(TREE_DIR_MODE)
        else:
            path.chmod(
                TREE_SECRET_MODE if path.name in secret_names else TREE_FILE_MODE
            )
        os.utime(path, (TREE_MTIME, TREE_MTIME))
    root.chmod(TREE_DIR_MODE)
    os.utime(root, (TREE_MTIME, TREE_MTIME))


def lock_problems(manifest: dict, lock: dict) -> list[str]:
    """Every way a generated tree can fail to be the pinned workload.

    Returns problems rather than raising so both the generator (which checks a
    STAGED tree before publishing it) and the gate (which checks a published
    one) can share one definition of "matches the lock" and still report in
    their own voice. A shared list is also why a missing payload cannot degrade
    into a printed note in one caller and a hard failure in the other.
    """
    problems = []
    if lock["workload_version"] != manifest.get("workload_version"):
        problems.append(
            f"workload_version is {manifest.get('workload_version')!r}, lock pins "
            f"{lock['workload_version']!r}"
        )
    if lock["public_key"] != manifest.get("public_key"):
        problems.append(
            f"public_key is {manifest.get('public_key')!r}, lock pins "
            f"{lock['public_key']!r}"
        )

    tier = manifest.get("tier")
    if tier not in TIERS:
        problems.append(f"manifest declares unknown tier {tier!r}")
        return problems

    # Counted BEFORE collapsing to a set. Set equality compares membership, so
    # a manifest listing `zstd` twice and omitting `lib` has the same attr set
    # as a correct one minus a payload - the cardinality check is what makes
    # "exactly this workload" mean exactly.
    listed = [entry["attr"] for entry in manifest.get("paths", [])]
    duplicates = sorted({a for a in listed if listed.count(a) > 1})
    if duplicates:
        problems.append(
            f"manifest lists {duplicates} more than once ({len(listed)} entries, "
            f"{len(set(listed))} distinct); payload identity must be unique"
        )

    present = set(listed)
    required = expected_attrs(lock, tier)
    # Set EQUALITY, not containment. A missing payload means the tree is not
    # the workload it claims to be - whether the plan shrank, a copy failed, or
    # someone edited the manifest - and an extra one means it is a workload
    # nobody pinned. Both are red.
    for missing in sorted(required - present):
        problems.append(f"tier {tier!r} requires payload {missing!r}, which is absent")
    for extra in sorted(present - required):
        problems.append(
            f"payload {extra!r} is present but not pinned for tier {tier!r}"
        )

    for entry in manifest.get("paths", []):
        pinned = lock["paths"].get(entry["attr"])
        if pinned is None:
            continue  # already reported as an extra
        for key in ("store_path", "compression", "nar_hash", "file_hash"):
            if pinned[key] != entry.get(key):
                problems.append(
                    f"payload {entry['attr']!r}: {key} is {entry.get(key)!r}, lock "
                    f"pins {pinned[key]!r}"
                )
    return problems


def blob_problems(cache: Path, manifest: dict) -> list[str]:
    """Check the NAR blobs themselves against the hashes the manifest pins.

    The manifest and the lock can agree perfectly about a file that is missing
    or corrupt, so metadata comparison alone lets a deleted 110 MiB blob pass.
    This is deliberately independent of any optional check: a fixture whose
    bytes are gone is never usable, whatever flags were passed.
    """
    problems = []
    for entry in manifest.get("paths", []):
        blob = cache / entry["url"]
        if not blob.is_file():
            problems.append(f"payload {entry['attr']!r}: {entry['url']} is missing")
            continue
        size = blob.stat().st_size
        if size != entry["file_size"]:
            problems.append(
                f"payload {entry['attr']!r}: {entry['url']} is {size} bytes, "
                f"manifest says {entry['file_size']}"
            )
            continue
        actual = file_hash_of(blob)
        if actual != entry["file_hash"]:
            problems.append(
                f"payload {entry['attr']!r}: {entry['url']} hashes to {actual}, "
                f"manifest pins {entry['file_hash']}"
            )
    return problems


def keypair(seed_phrase: bytes = KEY_SEED_PHRASE, name: str = KEY_NAME):
    """Return (name, private_key, nix_secret_line, nix_public_line).

    Nix's on-disk key format is `<name>:<base64>`, where the secret's base64
    payload is libsodium's 64-byte secret key (32-byte seed || 32-byte public
    key) and the public one is the bare 32-byte public key.

    The ed25519 seed is SHA-256 of the phrase - a plain 32-byte digest, which
    is exactly what `from_private_bytes` wants. It is NOT SHAKE256; that is the
    XOF used for the payload BYTES in fixtures/workload.nix, where an arbitrary
    output length is the whole point. Earlier revisions of these docs said
    SHAKE256 here, which was simply wrong about the code. The key was not
    rotated to match the prose: SHA-256 of a fixed phrase is a perfectly good
    deterministic seed for a worthless test key, the derivation is unchanged,
    and rotating would have invalidated the lock and every generated tree to
    fix a comment. The docs were corrected instead.
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
