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
import stat
import threading
from contextlib import contextmanager
from pathlib import Path, PurePosixPath

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

# Publication layout. A fixture tree is published as an IMMUTABLE generation
# directory plus one symlink:
#
#   <out>/generations/gen-<manifest-sha>/   built, validated, then never touched
#   <out>/current -> generations/gen-<...>  flipped with a single os.replace
#
# Every consumer - the gate, `just fixtures-serve`, task-5's containers -
# resolves through `current`, and that resolution lives HERE so there is one
# definition of "the published tree". The previous design renamed whole trees
# aside on publish and on rollback, which is where four review rounds of
# transaction bugs came from; a symlink swap is one atomic syscall with no
# recoverable-but-stranded intermediate state to describe.
GENERATIONS_DIR = "generations"
CURRENT_LINK = "current"


def generation_link_target(name: str) -> str:
    """The `current` symlink's target - RELATIVE, deliberately.

    A relative target keeps the publication root self-contained: it survives
    being moved, bind-mounted into a container under a different path, or
    copied with `cp -a`. An absolute target would silently point outside.
    """
    return f"{GENERATIONS_DIR}/{name}"


def resolve_current(out_root: Path) -> Path | None:
    """The generation `<out_root>/current` points at, or None.

    None covers every way there is nothing trustworthy to resolve: no link at
    all, a `current` that is not a symlink, or a link that does not name a
    direct child of `<out_root>/generations`. The last is confinement, and it
    is the same species as the manifest-url check below: `current` is joined
    onto the publication root by every consumer, so an unconfined target
    (`../../somewhere`, an absolute path) would have the gate verify - and the
    mock upstream serve - a directory that is not a generation at all. Only the
    exact shape publication produces is accepted.

    The generator treats None as "publish over it", which repairs a malformed
    link; the gate treats it as "nothing is published", which refuses.
    """
    link = out_root / CURRENT_LINK
    if not link.is_symlink():
        return None
    target = Path(os.path.normpath(os.path.join(out_root, os.readlink(link))))
    if target.parent != out_root / GENERATIONS_DIR or target.name in ("", ".", ".."):
        return None
    # Confining the link TEXT is not enough: the final component may itself be
    # a symlink, so `generations/gen-x -> /elsewhere` satisfied every check
    # above while the gate read /elsewhere/manifest.json and the mock upstream
    # served /elsewhere/cache. A generation is a real directory, always.
    if target.is_symlink():
        return None
    return target


# Tiers are a property of the WORKLOAD, so they live in the lock rather than in
# the generator: the gate has to know which payloads a given tier must contain
# in order to reject a tree that is missing one. Without that, a shrunken plan
# or a partially published tree verifies whatever it happens to hold.
TIER_FAST = "fast"
TIER_FULL = "full"
TIERS = (TIER_FAST, TIER_FULL)
# Ordered, so "at least this tier" is a comparison rather than a special case
# for the one tier anybody happened to pass. A third tier added to TIERS but
# not to this map is a KeyError at the comparison, not a silently satisfied
# requirement.
TIER_RANK = {TIER_FAST: 0, TIER_FULL: 1}

# The lock's schema, stated EXHAUSTIVELY rather than as a minimum. An
# unrecognised field used to be accepted, ignored, and then silently erased the
# next time --write-lock rewrote the file - so a reviewer could add a pin to the
# lock, see it survive review, and never learn that nothing read it and the next
# regeneration deleted it. Same fail-open species as the unknown tier and the
# accepted subset: input this file does not understand must never mean "no
# constraint". Adding a field is therefore a two-line change (here and at its
# use site), which is the point.
LOCK_TOP_KEYS = frozenset({"workload_version", "public_key", "paths"})
LOCK_PAYLOAD_KEYS = frozenset(
    {"store_path", "compression", "nar_hash", "file_hash", "tier"}
)

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

    if not isinstance(lock, dict):
        raise LockError(f"{path} is not a JSON object")
    for key in sorted(LOCK_TOP_KEYS):
        if key not in lock:
            raise LockError(f"{path} has no {key!r}")
    unknown = sorted(set(lock) - LOCK_TOP_KEYS)
    if unknown:
        raise LockError(
            f"{path} has unrecognised top-level field(s) {unknown}. Nothing reads "
            "them, and the next --write-lock would erase them without a word, so "
            f"they cannot be allowed to look like a pin. Known fields are "
            f"{sorted(LOCK_TOP_KEYS)}."
        )
    if not isinstance(lock["paths"], dict) or not lock["paths"]:
        raise LockError(f"{path} pins no payloads")
    for attr, pinned in lock["paths"].items():
        if not isinstance(pinned, dict):
            raise LockError(f"{path}: payload {attr!r} is not a JSON object")
        missing = sorted(LOCK_PAYLOAD_KEYS - set(pinned))
        if missing:
            raise LockError(f"{path}: payload {attr!r} is missing {missing}")
        extra = sorted(set(pinned) - LOCK_PAYLOAD_KEYS)
        if extra:
            raise LockError(
                f"{path}: payload {attr!r} has unrecognised field(s) {extra}. Same "
                "reason as above: an ignored field is a pin that is not a pin. "
                f"Known fields are {sorted(LOCK_PAYLOAD_KEYS)}."
            )
        if pinned["tier"] not in TIERS:
            raise LockError(
                f"{path}: payload {attr!r} declares tier {pinned['tier']!r}, which is "
                f"not one of {list(TIERS)}. An unknown tier would quietly excuse the "
                "payload from every tier's required set."
            )
    return lock


def expected_attrs(lock: dict, tier: str) -> set[str]:
    """Payload names a tree of `tier` must contain - no more, no fewer.

    A tier owes every payload pinned at its rank or below, so `full` owes
    everything and `fast` owes the fast payloads. Written as a RANK comparison
    rather than "full means all, anything else means fast", which was a third
    instance of the fail-open species this file has fixed twice: with a third
    tier in TIERS, `expected_attrs(lock, "medium")` returned only the fast set,
    so a medium-tier payload was excused from every tier's required set and a
    tree missing it verified green. load_lock's tier validation does not help -
    the tier is perfectly valid, it is this branch that loses it.
    """
    if tier not in TIERS:
        raise ValueError(f"unknown tier {tier!r}")
    return {
        a for a, p in lock["paths"].items() if TIER_RANK[p["tier"]] <= TIER_RANK[tier]
    }


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


def tree_digest(root: Path) -> dict[str, str]:
    """Contents AND metadata, per entry - directories included.

    Lives here rather than in the gate because two callers need exactly one
    answer to "are these two trees the same": the gate's determinism check, and
    the generator, which uses it to decide whether an already-installed
    generation really is the immutable thing its name claims.

    Contents alone were compared before, so two trees generated under different
    umasks (022 -> 644/755, 077 -> 600/700) were reported identical while being
    materially different to rsync, tar, an image build, or a server deciding a
    file is unreadable. gen-fixtures normalises modes and mtimes; including
    them here is what proves the normalisation happened rather than assuming it.

    What the mtime component can and cannot catch, so it is not over-read: the
    generator writes the same fixed mtime into both trees, so comparing them
    detects EXTERNAL mutation of a tree, never drift in the generator itself -
    if normalisation broke, both sides would break identically and still
    compare equal. The mode component has the same shape. What actually pins
    the intended values is that they are constants in this file, reviewable in
    a diff.
    """
    digest = {}
    # The ROOT is an entry too. Omitting it meant two trees whose top-level
    # directory differed (0700 vs 0755) compared equal - the one directory a
    # consumer must be able to traverse was the one nothing checked.
    for path in [root, *sorted(root.rglob("*"))]:
        info = path.lstat()
        if path.is_symlink():
            body = f"symlink:{os.readlink(path)}"
        elif stat.S_ISDIR(info.st_mode):
            body = "dir"
        elif not stat.S_ISREG(info.st_mode):
            # Anything that is not a regular file gets its own token instead of
            # being read. read_bytes() on a FIFO blocks forever on open, which
            # turned a tampered generation into a hang rather than a refusal -
            # and this digest is what install_generation uses to decide whether
            # an existing generation is intact.
            body = f"special:{stat.S_IFMT(info.st_mode):#o}"
        else:
            body = hashlib.sha256(path.read_bytes()).hexdigest()
        digest["." if path == root else str(path.relative_to(root))] = (
            # Nanoseconds, not int(st_mtime): truncating to seconds made 1.1s
            # and 1.9s compare equal, so sub-second drift was invisible.
            f"{body} mode={info.st_mode & 0o7777:04o} mtime_ns={info.st_mtime_ns}"
        )
    return digest


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


def confined_blob(cache: Path, url) -> tuple[Path | None, str | None]:
    """Resolve a manifest `url` INSIDE `cache`, or say why it is not allowed.

    Returns (path, None) or (None, problem). A narinfo URL is a cache-relative
    location like `nar/<hash>.nar.xz`, and every consumer joins it onto a
    directory - so an unconfined value turns the manifest into a way to name
    any file on the host. With `../../outside.nar` the blob checks below
    happily hashed a file that was never in the tree, and the generator then
    PUBLISHED a cache whose own blob was missing: the checks passed by reading
    something else. Confinement is enforced here, at the single place the join
    happens, rather than at each caller.

    Three separate refusals, because each catches a different trick:
      * non-canonical or absolute or `..`-bearing text (pure string reasoning,
        so it holds even if nothing exists on disk yet);
      * a resolved path outside the cache root (catches a symlink that escapes);
      * a symlink anywhere along the way (catches an escape that happens to
        land back inside, and matches normalise_tree, which forbids symlinks in
        a generated tree at all).
    """
    if not isinstance(url, str) or not url:
        return None, f"url is {url!r}, which is not a non-empty string"
    pure = PurePosixPath(url)
    if pure.is_absolute():
        return None, f"url {url!r} is absolute; it must be relative to the cache"
    if ".." in pure.parts:
        return None, f"url {url!r} traverses '..'; it must stay inside the cache"
    if pure.as_posix() != url:
        return None, (
            f"url {url!r} is not a canonical relative path (it would normalise to "
            f"{pure.as_posix()!r}); refusing to guess what it means"
        )
    probe = cache
    for part in pure.parts:
        probe = probe / part
        if probe.is_symlink():
            return None, (
                f"url {url!r} is reached through the symlink {probe}; a served "
                "blob must be a real file inside the cache"
            )
    candidate = cache / url
    try:
        root, resolved = cache.resolve(), candidate.resolve()
    except OSError as error:
        return None, f"url {url!r} cannot be resolved: {error}"
    if not resolved.is_relative_to(root):
        return None, (
            f"url {url!r} resolves to {resolved}, which is outside the cache root "
            f"{root}"
        )
    return candidate, None


def narinfo_name(store_path: str) -> str:
    """`<hash>.narinfo`, the filename a client asks for. Defined once."""
    return f"{PurePosixPath(store_path).name.split('-')[0]}.narinfo"


def completeness_problems(cache: Path, manifest: dict) -> list[str]:
    """The files a served cache must contain besides its NAR blobs.

    A binary cache is `nix-cache-info` plus one narinfo per path plus the
    blobs. blob_problems() covers only the last of those, which left a real
    hole: deleting `nix-cache-info` or a narinfo from a published tree produced
    a tree the GATE rejects and the GENERATOR happily reused, so
    `just fixtures` reported success, `just test` failed, and the failure's own
    advice was to run `just fixtures`. An unbreakable loop out of a one-file
    deletion, escapable only by `rm -rf` - which is documented nowhere except
    for the layout migration.

    Split out rather than folded into blob_problems() because these are
    presence checks on files whose contents other checks own (the gate compares
    nix-cache-info against an independently stated expectation, and narinfo
    signatures are verified at generation time). Shared so "is this tree the
    workload" means one thing to the generator's reuse shortcut and to the gate.
    """
    problems = []
    if not (cache / "nix-cache-info").is_file():
        problems.append("nix-cache-info is missing; the cache advertises nothing")
    for entry in manifest.get("paths", []):
        store_path = entry.get("store_path")
        if not isinstance(store_path, str) or not store_path:
            problems.append(f"payload {entry.get('attr')!r} has no store_path")
            continue
        narinfo, refusal = confined_blob(cache, narinfo_name(store_path))
        if refusal is not None:
            problems.append(f"payload {entry.get('attr')!r}: {refusal}")
        elif not narinfo.is_file():
            problems.append(
                f"payload {entry.get('attr')!r}: {narinfo_name(store_path)} is "
                "missing, so the path it describes cannot be substituted"
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
        blob, refusal = confined_blob(cache, entry.get("url"))
        if refusal is not None:
            problems.append(f"payload {entry.get('attr')!r}: {refusal}")
            continue
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
