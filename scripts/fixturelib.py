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
signatures are functions of the seed, and each fixture family's tracked review
baseline pins the resulting public key so drift in the derivation is a hard
failure.
"""

from __future__ import annotations

import base64
import copy
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
# them, and any coordinated edit sails past it. Each selected family's tracked
# baseline holds the pin instead: it is external to this derivation and visible
# in version control.

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
# The AUTHORITATIVE lock lives here, INSIDE each generation. `current` points at
# the generation, so one symlink flip commits the tree and its lock together.
GEN_LOCK_NAME = "lock.json"
# Retention is "the published generation and the one before it". That claim was
# made in round 5 and not implemented: the warm reuse path had no idea what the
# predecessor was and collected it immediately, so a reader that resolved a
# PATH (rather than holding a descriptor) got ENOENT after publish+reuse. A
# second symlink is the whole implementation - a pointer, not duplicated state -
# and it makes the retention claim auditable with `ls -l fixtures/out`.
PREVIOUS_LINK = "previous"


def generation_link_target(name: str) -> str:
    """The `current` symlink's target - RELATIVE, deliberately.

    A relative target keeps the publication root self-contained: it survives
    being moved, bind-mounted into a container under a different path, or
    copied with `cp -a`. An absolute target would silently point outside.
    """
    return f"{GENERATIONS_DIR}/{name}"


def anchored_generations(out_root: Path) -> Path | None:
    """`<out_root>/generations`, but only if it REALLY is inside out_root.

    Every deletion this tooling performs happens under this directory, so it is
    the single anchor the whole publication root hangs from. Confining the
    `current` link's text was not enough: with `generations` itself a symlink to
    somewhere else, the link text `generations/gen-x` was perfectly well-formed,
    the gate verified a tree outside the root, and the collector deleted a
    marked directory outside the root. Comparing the resolved path against the
    resolved root is what makes "inside" mean inside rather than "spelled like
    it is inside".

    Returns None rather than raising: the generator repairs this by refusing
    loudly with a remediation, the gate refuses to verify. Both need to say it
    in their own voice.
    """
    generations = out_root / GENERATIONS_DIR
    if generations.is_symlink() or not generations.is_dir():
        return None
    try:
        anchored = generations.resolve(strict=True)
        root = out_root.resolve(strict=True)
    except OSError:
        return None
    # `not is_symlink()` already implies this for a direct child; the explicit
    # comparison is what a reader (and an auditor) can check without having to
    # reconstruct that argument, and it survives the directory being replaced
    # by something cleverer later.
    if anchored != root / GENERATIONS_DIR:
        return None
    return generations


def _resolve_generation_link(out_root: Path, link_name: str) -> Path | None:
    """Resolve one of the publication symlinks to a real generation directory.

    Shared by `current` and `previous` so the two cannot drift apart in how
    strictly they are confined - the collector trusts both.
    """
    link = out_root / link_name
    if not link.is_symlink():
        return None
    generations = anchored_generations(out_root)
    if generations is None:
        return None
    target = Path(os.path.normpath(os.path.join(out_root, os.readlink(link))))
    if target.parent != generations or target.name in ("", ".", ".."):
        return None
    # The final component may itself be a symlink, so `generations/gen-x ->
    # /elsewhere` satisfied every check above while the gate read
    # /elsewhere/manifest.json. A generation is a real directory, always.
    if target.is_symlink() or not target.is_dir():
        return None
    return target


def resolve_current(out_root: Path) -> Path | None:
    """The generation `<out_root>/current` points at, or None.

    None covers every way there is nothing trustworthy to resolve: no link, a
    `current` that is not a symlink, a target that is not a direct child of an
    anchored `generations/`, or a target that is itself a symlink. `current` is
    joined onto the publication root by every consumer, so an unconfined target
    would have the gate verify - and the mock upstream serve - a directory that
    is not a generation at all.

    The generator treats None as "publish over it", which repairs a malformed
    link; the gate treats it as "nothing is published", which refuses.
    """
    return _resolve_generation_link(out_root, CURRENT_LINK)


def resolve_previous(out_root: Path) -> Path | None:
    """The generation retained for readers that resolved `current` before the
    last flip. Same confinement as `current`; None when there is none."""
    return _resolve_generation_link(out_root, PREVIOUS_LINK)


# Tiers are a property of the WORKLOAD, so they live in the lock rather than in
# the generator: the gate has to know which payloads a given tier must contain
# in order to reject a tree that is missing one. Without that, a shrunken plan
# or a partially published tree verifies whatever it happens to hold.
TIER_FAST = "fast"
TIER_FULL = "full"
TIER_WIDE = "wide"
TIERS = (TIER_FAST, TIER_FULL, TIER_WIDE)
# `wide` is a separate fixture family, not a larger canonical tier.  The
# inclusion relation is therefore explicit rather than a total rank: full may
# satisfy a fast request, while neither canonical tier can satisfy wide (and a
# wide tree cannot masquerade as the four-path J2 workload).
TIER_INCLUDES = {
    TIER_FAST: frozenset({TIER_FAST}),
    TIER_FULL: frozenset({TIER_FAST, TIER_FULL}),
    TIER_WIDE: frozenset({TIER_WIDE}),
}

FIXTURE_CLASS_WIDE = "wide_closure"
WIDE_ROOT_ATTR = "wide-root"
WIDE_MEMBER_PREFIX = "wide-member-"
WIDE_MEMBER_COUNT = 128
WIDE_BASELINE_NAME = "wide_closure.lock.json"

# Integer-only, reviewable limits.  NarSize is the signed, uncompressed size;
# disk accounting is a separate cache-filesystem safety bound.
WIDE_BUDGETS = {
    "member_count_min": 128,
    "member_count_max": 512,
    "closure_path_count_min": 129,
    "closure_path_count_max": 513,
    "total_nar_size_min": 256 * 1024 * 1024,
    "total_nar_size_max": 2 * 1024 * 1024 * 1024,
    "cache_apparent_size_max": 512 * 1024 * 1024,
    "cache_allocated_size_max": 512 * 1024 * 1024,
}

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
WIDE_LOCK_TOP_KEYS = LOCK_TOP_KEYS | frozenset(
    {
        "fixture_class",
        "root_attr",
        "cardinality",
        "totals",
        "budgets",
        "disk_accounting",
    }
)
WIDE_LOCK_PAYLOAD_KEYS = LOCK_PAYLOAD_KEYS | frozenset(
    {
        "nar_size",
        "file_size",
        "url",
        "references",
        "role",
        "cache_apparent_size",
        "cache_allocated_size",
    }
)
WIDE_CARDINALITY_KEYS = frozenset({"member_count", "root_count", "closure_path_count"})
WIDE_TOTAL_KEYS = frozenset(
    {"nar_size", "file_size", "cache_apparent_size", "cache_allocated_size"}
)
WIDE_DISK_ACCOUNTING_KEYS = frozenset(
    {
        "scope",
        "block_unit_bytes",
        "nix_cache_info_apparent_size",
        "nix_cache_info_allocated_size",
    }
)

NIX_BASE32_ALPHABET = "0123456789abcdfghijklmnpqrsvwxyz"


def repo_root() -> Path:
    """Workspace root, derived from this file's location (scripts/ lives in it)."""
    return Path(__file__).resolve().parent.parent


def lock_path(repo: Path, tier: str = TIER_FULL) -> Path:
    if tier == TIER_WIDE:
        name = WIDE_BASELINE_NAME
    elif tier in (TIER_FAST, TIER_FULL):
        name = "workload.lock.json"
    else:
        raise ValueError(f"unknown fixture tier {tier!r}")
    return repo / "fixtures" / name


class LockError(Exception):
    """The committed lock is unusable, so nothing can be proven against it."""


# THREAT MODEL, so that this does not get reopened as an unbounded problem.
# The anchoring below defends against exactly two things: (1) an ancestor
# directory being swapped for a symlink CONCURRENTLY, after a path was resolved
# and before it is used, and (2) an ancestor that is ALREADY a symlink being
# silently written through, so the tooling edits a file outside the tree it
# believes it is editing. It does NOT claim to defend a host where an attacker
# already has write access under this uid: such an attacker edits a tracked
# fixture baseline directly and no amount of descriptor discipline
# helps. What is bought is that the fixture tooling cannot be TRICKED into
# reaching outside its own root - which matters because it deletes directories
# and rewrites the file that defines the frozen workload.
#
# The mechanism: resolve the root once, hold an O_NOFOLLOW|O_DIRECTORY
# descriptor on it, and perform every subsequent operation relative to that
# descriptor. `openat` does not re-walk ancestors, so a swap after the open
# cannot redirect anything; where a real path must be handed to another process
# (nix, an HTTP server), the path is re-checked against the held descriptor's
# (dev, ino) first.

DIR_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY | os.O_CLOEXEC


def open_dir(path_or_name, dir_fd: int | None = None) -> int:
    """Open a directory descriptor, never following a symlink at the leaf.

    With `dir_fd`, `path_or_name` is a single component resolved by the kernel
    relative to that descriptor - which is the whole point: no ancestor is
    consulted, so no ancestor can be swapped underneath it.
    """
    return os.open(path_or_name, DIR_FLAGS, dir_fd=dir_fd)


def same_inode(fd: int, path: Path) -> bool:
    """Does `path` still name the directory `fd` holds open?

    The check for the places a real path has to leave this process. A held
    descriptor keeps pointing at the right inode no matter what happens to the
    names above it; a path does not, so before handing one out it is compared
    back to the anchor.
    """
    try:
        held, named = os.fstat(fd), os.stat(path)
    except OSError:
        return False
    return (held.st_dev, held.st_ino) == (named.st_dev, named.st_ino)


def read_at(dir_fd: int, name: str) -> str:
    """Read one file by name relative to an anchored directory descriptor.

    Used for tracked baseline locks and WORKLOAD_VERSION - the files that define
    frozen workloads. A symlink at the file itself is refused by O_NOFOLLOW;
    an ancestor cannot participate at all, because resolution starts at the
    descriptor. Reading through either would launder someone else's file into a
    green run.
    """
    descriptor = os.open(
        name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd
    )
    try:
        with os.fdopen(descriptor, "r", closefd=False) as handle:
            return handle.read()
    finally:
        os.close(descriptor)


@contextmanager
def anchored_fixtures_dir(repo: Path):
    """Hold a descriptor on `<repo>/fixtures` for the duration of a block.

    `fixtures` being a symlink is refused here rather than discovered later:
    with it pointing elsewhere, commit_lock wrote an unrelated file outside the
    repository and reported success, and load_lock read that file back.
    """
    try:
        descriptor = open_dir(repo / "fixtures")
    except OSError as error:
        raise LockError(
            f"cannot open {repo / 'fixtures'} as a plain directory: {error}. If it "
            "is a symlink, remove it - this tooling refuses to read or write the "
            "frozen workload through one."
        ) from error
    try:
        yield descriptor
    finally:
        os.close(descriptor)


def _validate_exact_int_object(
    value,
    integer_keys: frozenset[str],
    source: str,
    field_name: str,
    allowed_extra: frozenset[str] = frozenset(),
) -> None:
    """Validate a closed metadata object whose named values are integers."""
    if not isinstance(value, dict):
        raise LockError(f"{source}: {field_name} is not a JSON object")
    expected = integer_keys | allowed_extra
    if set(value) != expected:
        raise LockError(
            f"{source}: {field_name} fields are {sorted(value)}, expected "
            f"{sorted(expected)}"
        )
    for key in sorted(integer_keys):
        item = value[key]
        if isinstance(item, bool) or not isinstance(item, int) or item < 0:
            raise LockError(
                f"{source}: {field_name}.{key} must be a non-negative integer"
            )


def validate_lock(lock, source: str) -> dict:
    """Validate a parsed lock structure from any source. Shared, so the same
    schema binds the AUTHORITATIVE lock inside a generation and the demoted
    baseline in git.

    A field this file does not understand cannot be allowed to mean "no
    constraint". A misspelled tier (`fasst`) used to do exactly that -
    `expected_attrs` matched it against neither tier, so the payload silently
    dropped out of the fast tier's required set and a tree missing it verified
    green.
    """
    if not isinstance(lock, dict):
        raise LockError(f"{source} is not a JSON object")
    is_wide = lock.get("fixture_class") == FIXTURE_CLASS_WIDE
    top_keys = WIDE_LOCK_TOP_KEYS if is_wide else LOCK_TOP_KEYS
    payload_keys = WIDE_LOCK_PAYLOAD_KEYS if is_wide else LOCK_PAYLOAD_KEYS
    for key in sorted(top_keys):
        if key not in lock:
            raise LockError(f"{source} has no {key!r}")
    unknown = sorted(set(lock) - top_keys)
    if unknown:
        raise LockError(
            f"{source} has unrecognised top-level field(s) {unknown}. Nothing reads "
            "them, and the next --write-lock would erase them without a word, so "
            f"they cannot be allowed to look like a pin. Known fields are "
            f"{sorted(top_keys)}."
        )
    if "fixture_class" in lock and not is_wide:
        raise LockError(
            f"{source} declares unknown fixture_class {lock['fixture_class']!r}; "
            f"the only extended class is {FIXTURE_CLASS_WIDE!r}"
        )
    if not isinstance(lock["paths"], dict) or not lock["paths"]:
        raise LockError(f"{source} pins no payloads")
    for attr, pinned in lock["paths"].items():
        if not isinstance(pinned, dict):
            raise LockError(f"{source}: payload {attr!r} is not a JSON object")
        missing = sorted(payload_keys - set(pinned))
        if missing:
            raise LockError(f"{source}: payload {attr!r} is missing {missing}")
        extra = sorted(set(pinned) - payload_keys)
        if extra:
            raise LockError(
                f"{source}: payload {attr!r} has unrecognised field(s) {extra}. Same "
                "reason as above: an ignored field is a pin that is not a pin. "
                f"Known fields are {sorted(payload_keys)}."
            )
        if pinned["tier"] not in TIERS:
            raise LockError(
                f"{source}: payload {attr!r} declares tier {pinned['tier']!r}, which "
                f"is not one of {list(TIERS)}. An unknown tier would quietly excuse "
                "the payload from every tier's required set."
            )
        if not is_wide and pinned["tier"] == TIER_WIDE:
            raise LockError(
                f"{source}: canonical lock payload {attr!r} declares tier 'wide'. "
                "Wide paths belong only to a wide_closure lock; otherwise fast/full "
                "would silently require neither the path nor its bytes."
            )
        if is_wide:
            if pinned["tier"] != TIER_WIDE:
                raise LockError(
                    f"{source}: wide payload {attr!r} has tier {pinned['tier']!r}, "
                    f"expected {TIER_WIDE!r}"
                )
            for key in (
                "nar_size",
                "file_size",
                "cache_apparent_size",
                "cache_allocated_size",
            ):
                if (
                    isinstance(pinned[key], bool)
                    or not isinstance(pinned[key], int)
                    or pinned[key] < 0
                ):
                    raise LockError(
                        f"{source}: payload {attr!r} field {key!r} must be a "
                        "non-negative integer"
                    )
            if pinned["role"] not in ("member", "root"):
                raise LockError(
                    f"{source}: payload {attr!r} has invalid role {pinned['role']!r}"
                )
            if not isinstance(pinned["references"], list) or not all(
                isinstance(reference, str) for reference in pinned["references"]
            ):
                raise LockError(
                    f"{source}: payload {attr!r} references must be a string list"
                )

    if is_wide:
        _validate_exact_int_object(
            lock["cardinality"], WIDE_CARDINALITY_KEYS, source, "cardinality"
        )
        _validate_exact_int_object(lock["totals"], WIDE_TOTAL_KEYS, source, "totals")
        _validate_exact_int_object(
            lock["budgets"], frozenset(WIDE_BUDGETS), source, "budgets"
        )
        if lock["budgets"] != WIDE_BUDGETS:
            raise LockError(
                f"{source}: budgets are {lock['budgets']}, expected frozen integer "
                f"budgets {WIDE_BUDGETS}"
            )
        _validate_exact_int_object(
            lock["disk_accounting"],
            WIDE_DISK_ACCOUNTING_KEYS - {"scope"},
            source,
            "disk_accounting",
            allowed_extra=frozenset({"scope"}),
        )
        if lock["disk_accounting"].get("scope") != "cache_regular_files_v1":
            raise LockError(
                f"{source}: disk accounting scope must be 'cache_regular_files_v1'"
            )
        # Validate the ORIGINAL local accounting before any portable comparison
        # neutralises allocated-byte observations.  Converting the lock's keyed
        # payloads to the manifest shape lets one production semantic oracle own
        # totals, integer budgets, cardinality, and fanout for both forms.
        semantic_lock = copy.deepcopy(lock)
        semantic_lock["tier"] = TIER_WIDE
        semantic_lock["paths"] = [
            {"attr": attr, **pinned} for attr, pinned in lock["paths"].items()
        ]
        semantic_problems = wide_contract_problems(semantic_lock)
        if semantic_problems:
            raise LockError(
                f"{source}: wide semantic contract failed:\n  - "
                + "\n  - ".join(semantic_problems)
            )
    return lock


def load_generation_lock(generation: Path) -> dict:
    """The AUTHORITATIVE lock: `<generation>/lock.json`, the runtime source of
    truth for what workload the published tree IS.

    This is what every runtime/gate/consistency reader resolves - via
    `current -> gen-<sha>/lock.json`. Because the lock lives inside the
    generation, the single symlink flip that publishes the tree commits its
    lock in the same syscall: there are no longer two authoritative sources to
    reconcile, and so publish() has nothing to roll back and nothing to read
    back (the round-8 redesign). The git-tracked file below is NOT consulted
    here.

    Read relative to a descriptor on the generation dir, O_NOFOLLOW at the leaf,
    consistent with the zero-symlink rule a generation is validated against.
    """
    lock_json = generation / GEN_LOCK_NAME
    try:
        gen_fd = open_dir(generation)
    except OSError as exc:
        raise LockError(f"cannot open generation {generation}: {exc}") from exc
    try:
        raw = read_at(gen_fd, GEN_LOCK_NAME)
    except OSError as exc:
        raise LockError(f"cannot read {lock_json}: {exc}") from exc
    finally:
        os.close(gen_fd)
    try:
        lock = json.loads(raw)
    except ValueError as exc:
        raise LockError(f"{lock_json} is not valid JSON: {exc}") from exc
    return validate_lock(lock, str(lock_json))


def load_baseline(repo: Path, tier: str = TIER_FULL) -> dict:
    """The selected DEMOTED git baseline (canonical or independent wide).

    A review / version-control artifact, NOT a runtime source of truth. It is
    read only by the generator's freeze path - the fresh-build drift check and
    `--write-lock` reconciliation - and written only at `--write-lock` time, so
    the frozen baseline still lives in git and shows in `git diff`. No
    runtime/gate/consistency code opens it; that is asserted by
    scripts/check-lock-sources.py.
    """
    path = lock_path(repo, tier)
    try:
        with anchored_fixtures_dir(repo) as fixtures_fd:
            lock = json.loads(read_at(fixtures_fd, path.name))
    except OSError as exc:
        raise LockError(f"cannot read {path}: {exc}") from exc
    except ValueError as exc:
        raise LockError(f"{path} is not valid JSON: {exc}") from exc
    return validate_lock(lock, str(path))


def expected_attrs(lock: dict, tier: str) -> set[str]:
    """Payload names a tree of `tier` must contain - no more, no fewer.

    Full owes fast+full, while the independent wide family owes only wide.
    Making that relation explicit prevents a wide cache from satisfying a
    canonical request merely because somebody placed the word after `full`.
    """
    if tier not in TIERS:
        raise ValueError(f"unknown tier {tier!r}")
    included = TIER_INCLUDES[tier]
    return {a for a, p in lock["paths"].items() if p["tier"] in included}


def tier_satisfies(actual: str, required: str) -> bool:
    """Whether an actual fixture tier satisfies an explicitly required tier."""
    if actual not in TIERS or required not in TIERS:
        raise ValueError(
            f"unknown tier relation: actual={actual!r}, required={required!r}"
        )
    return required in TIER_INCLUDES[actual]


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

    is_wide = lock.get("fixture_class") == FIXTURE_CLASS_WIDE
    for entry in manifest.get("paths", []):
        pinned = lock["paths"].get(entry["attr"])
        if pinned is None:
            continue  # already reported as an extra
        compared = ["store_path", "compression", "nar_hash", "file_hash"]
        if is_wide:
            compared.extend(
                [
                    "nar_size",
                    "file_size",
                    "url",
                    "references",
                    "role",
                    "cache_apparent_size",
                    "cache_allocated_size",
                ]
            )
        for key in compared:
            if pinned[key] != entry.get(key):
                problems.append(
                    f"payload {entry['attr']!r}: {key} is {entry.get(key)!r}, lock "
                    f"pins {pinned[key]!r}"
                )
    if is_wide:
        for key in (
            "fixture_class",
            "root_attr",
            "cardinality",
            "totals",
            "budgets",
            "disk_accounting",
        ):
            if lock[key] != manifest.get(key):
                problems.append(
                    f"wide metadata {key!r} is {manifest.get(key)!r}, lock pins "
                    f"{lock[key]!r}"
                )
        problems.extend(wide_contract_problems(manifest))
    return problems


def portable_fixture_document(document: dict) -> dict:
    """Copy a manifest/lock with local allocated-byte observations neutralised."""
    result = copy.deepcopy(document)
    if result.get("fixture_class") != FIXTURE_CLASS_WIDE:
        return result
    paths = result.get("paths", {})
    values = paths.values() if isinstance(paths, dict) else paths
    for entry in values:
        entry["cache_allocated_size"] = 0
    result["totals"]["cache_allocated_size"] = 0
    result["disk_accounting"]["nix_cache_info_allocated_size"] = 0
    return result


def portable_lock_problems(manifest: dict, lock: dict) -> list[str]:
    """Lock comparison excluding filesystem-local allocated-byte evidence.

    Each generation's own lock still pins and verifies its observed st_blocks.
    A tracked baseline or independently generated tree may live on a different
    filesystem/extent layout, so portable equality replaces only those values
    with a common sentinel before applying the otherwise exact lock oracle.
    """
    # This is deliberately before portable_fixture_document: otherwise a bad
    # allocated total can be replaced by the same zero sentinel on both sides
    # and disappear.  The manifest is not a lock-shaped document, so it uses
    # the same wide semantic oracle directly.
    try:
        validate_lock(lock, "portable comparison lock")
    except LockError as error:
        return [str(error)]
    if manifest.get("fixture_class") == FIXTURE_CLASS_WIDE:
        semantic_problems = wide_contract_problems(manifest)
        if semantic_problems:
            return semantic_problems
    return lock_problems(
        portable_fixture_document(manifest), portable_fixture_document(lock)
    )


def wide_count_problems(
    member_count: int, closure_path_count: int, root_reference_count: int | None
) -> list[str]:
    """Judge observed wide shape against frozen budgets and direct fanout.

    This deliberately takes observations, not a manifest and not the nominal
    WIDE_MEMBER_COUNT.  The budget bite can therefore exercise the independent
    lower bound without mutating module state or manufacturing a second fixture.
    """
    problems = []
    if not (
        WIDE_BUDGETS["member_count_min"]
        <= member_count
        <= WIDE_BUDGETS["member_count_max"]
    ):
        problems.append(
            f"wide member count {member_count} is outside the frozen budget"
        )
    if not (
        WIDE_BUDGETS["closure_path_count_min"]
        <= closure_path_count
        <= WIDE_BUDGETS["closure_path_count_max"]
    ):
        problems.append(
            f"wide closure path count {closure_path_count} is outside the frozen budget"
        )
    if root_reference_count is not None and root_reference_count != member_count:
        problems.append(
            f"wide root has {root_reference_count} direct references, expected one "
            f"per {member_count} members"
        )
    return problems


def wide_contract_problems(manifest: dict) -> list[str]:
    """Semantic, independently recomputed contract for `wide_closure`."""
    problems = []
    if manifest.get("fixture_class") != FIXTURE_CLASS_WIDE:
        return [
            f"fixture_class is {manifest.get('fixture_class')!r}, expected "
            f"{FIXTURE_CLASS_WIDE!r}"
        ]
    if manifest.get("tier") != TIER_WIDE:
        problems.append(
            f"wide fixture tier is {manifest.get('tier')!r}, expected 'wide'"
        )
    if manifest.get("root_attr") != WIDE_ROOT_ATTR:
        problems.append(
            f"wide root_attr is {manifest.get('root_attr')!r}, expected {WIDE_ROOT_ATTR!r}"
        )
    if manifest.get("budgets") != WIDE_BUDGETS:
        problems.append(
            f"wide budgets are {manifest.get('budgets')!r}, expected {WIDE_BUDGETS!r}"
        )

    entries = manifest.get("paths")
    if not isinstance(entries, list):
        return problems + ["wide paths is not a list"]
    roots = [entry for entry in entries if entry.get("role") == "root"]
    members = [entry for entry in entries if entry.get("role") == "member"]
    expected_member_attrs = {
        f"{WIDE_MEMBER_PREFIX}{index:03d}" for index in range(WIDE_MEMBER_COUNT)
    }
    actual_member_attrs = {entry.get("attr") for entry in members}
    if actual_member_attrs != expected_member_attrs:
        missing = sorted(expected_member_attrs - actual_member_attrs)
        extra = sorted(actual_member_attrs - expected_member_attrs, key=str)
        problems.append(f"wide member attrs differ: missing={missing}, extra={extra}")
    if len(roots) != 1 or not roots or roots[0].get("attr") != WIDE_ROOT_ATTR:
        problems.append(
            f"wide fixture needs exactly one {WIDE_ROOT_ATTR!r} root; found "
            f"{[entry.get('attr') for entry in roots]}"
        )

    cardinality = {
        "member_count": len(members),
        "root_count": len(roots),
        "closure_path_count": len(entries),
    }
    if manifest.get("cardinality") != cardinality:
        problems.append(
            f"wide cardinality is {manifest.get('cardinality')!r}, recomputed "
            f"{cardinality!r}"
        )

    store_paths = [entry.get("store_path") for entry in entries]
    urls = [entry.get("url") for entry in entries]
    if len(set(store_paths)) != len(store_paths):
        problems.append("wide store paths are not all distinct")
    if len(set(urls)) != len(urls):
        problems.append("wide NAR URLs are not all distinct")

    member_basenames = {
        PurePosixPath(entry.get("store_path", "")).name for entry in members
    }
    for member in members:
        if member.get("references") != []:
            problems.append(
                f"wide member {member.get('attr')!r} unexpectedly references "
                f"{member.get('references')!r}"
            )
    if len(roots) == 1 and set(roots[0].get("references", [])) != member_basenames:
        missing = sorted(member_basenames - set(roots[0].get("references", [])))
        extra = sorted(set(roots[0].get("references", [])) - member_basenames)
        problems.append(f"wide root fanout differs: missing={missing}, extra={extra}")
    if len(roots) == 1 and len(roots[0].get("references", [])) != len(member_basenames):
        problems.append("wide root fanout contains duplicate references")

    total_keys = {
        "nar_size": "nar_size",
        "file_size": "file_size",
        "cache_apparent_size": "cache_apparent_size",
        "cache_allocated_size": "cache_allocated_size",
    }
    recomputed_totals = {}
    for total_key, entry_key in total_keys.items():
        values = [entry.get(entry_key) for entry in entries]
        if not all(
            isinstance(value, int) and not isinstance(value, bool) for value in values
        ):
            problems.append(f"wide per-path {entry_key} values are not all integers")
            continue
        recomputed_totals[total_key] = sum(values)
    accounting = manifest.get("disk_accounting") or {}
    for total_key, accounting_key in (
        ("cache_apparent_size", "nix_cache_info_apparent_size"),
        ("cache_allocated_size", "nix_cache_info_allocated_size"),
    ):
        if total_key in recomputed_totals:
            extra = accounting.get(accounting_key)
            if isinstance(extra, int) and not isinstance(extra, bool):
                recomputed_totals[total_key] += extra
            else:
                problems.append(f"wide disk_accounting.{accounting_key} is not integer")
    if manifest.get("totals") != recomputed_totals:
        problems.append(
            f"wide totals are {manifest.get('totals')!r}, recomputed "
            f"{recomputed_totals!r}"
        )
    total_nar = recomputed_totals.get("nar_size")
    if isinstance(total_nar, int) and not (
        WIDE_BUDGETS["total_nar_size_min"]
        <= total_nar
        <= WIDE_BUDGETS["total_nar_size_max"]
    ):
        problems.append(f"wide total NarSize {total_nar} is outside the frozen budget")
    member_count = len(members)
    root_reference_count = (
        len(roots[0].get("references", [])) if len(roots) == 1 else None
    )
    problems.extend(
        wide_count_problems(member_count, len(entries), root_reference_count)
    )
    for total_key, budget_key in (
        ("cache_apparent_size", "cache_apparent_size_max"),
        ("cache_allocated_size", "cache_allocated_size_max"),
    ):
        value = recomputed_totals.get(total_key)
        if isinstance(value, int) and value > WIDE_BUDGETS[budget_key]:
            problems.append(f"wide {total_key} {value} exceeds {budget_key}")
    if accounting.get("scope") != "cache_regular_files_v1":
        problems.append("wide disk accounting scope is not cache_regular_files_v1")
    if accounting.get("block_unit_bytes") != 512:
        problems.append("wide disk accounting block unit is not 512 bytes")
    return problems


def wide_cache_file_set_problems(manifest: dict, actual_files: set[Path]) -> list[str]:
    """Compare an observed cache regular-file set with the manifest's exact set."""
    expected_files = {Path("nix-cache-info")}
    for entry in manifest.get("paths", []):
        expected_files.add(Path(narinfo_name(entry.get("store_path", ""))))
        expected_files.add(Path(entry.get("url", "")))
    problems = []
    missing_files = sorted(str(path) for path in expected_files - actual_files)
    extra_files = sorted(str(path) for path in actual_files - expected_files)
    if missing_files:
        problems.append(
            f"cache accounting scope is missing regular files {missing_files}"
        )
    if extra_files:
        problems.append(
            f"cache accounting scope has unexpected regular files {extra_files}"
        )
    return problems


def wide_disk_problems(cache: Path, manifest: dict) -> list[str]:
    """Recompute cache-only apparent/allocated evidence from filesystem truth."""
    if manifest.get("fixture_class") != FIXTURE_CLASS_WIDE:
        return []
    problems = []

    actual_files = {
        path.relative_to(cache)
        for path in cache.rglob("*")
        if stat.S_ISREG(path.lstat().st_mode)
    }
    problems.extend(wide_cache_file_set_problems(manifest, actual_files))

    def sizes(path: Path) -> tuple[int, int]:
        info = path.stat()
        return info.st_size, info.st_blocks * 512

    apparent_total = 0
    allocated_total = 0
    for entry in manifest.get("paths", []):
        narinfo = cache / narinfo_name(entry.get("store_path", ""))
        blob, refusal = confined_blob(cache, entry.get("url"))
        if (
            refusal is not None
            or not narinfo.is_file()
            or blob is None
            or not blob.is_file()
        ):
            continue  # completeness/blob checks report the concrete absence
        narinfo_sizes = sizes(narinfo)
        blob_sizes = sizes(blob)
        apparent = narinfo_sizes[0] + blob_sizes[0]
        allocated = narinfo_sizes[1] + blob_sizes[1]
        apparent_total += apparent
        allocated_total += allocated
        if entry.get("cache_apparent_size") != apparent:
            problems.append(
                f"payload {entry.get('attr')!r}: cache_apparent_size is "
                f"{entry.get('cache_apparent_size')!r}, filesystem says {apparent}"
            )
        if entry.get("cache_allocated_size") != allocated:
            problems.append(
                f"payload {entry.get('attr')!r}: cache_allocated_size is "
                f"{entry.get('cache_allocated_size')!r}, filesystem says {allocated}"
            )
    cache_info = cache / "nix-cache-info"
    if cache_info.is_file():
        info_apparent, info_allocated = sizes(cache_info)
        apparent_total += info_apparent
        allocated_total += info_allocated
        accounting = manifest.get("disk_accounting") or {}
        if accounting.get("nix_cache_info_apparent_size") != info_apparent:
            problems.append("nix-cache-info apparent size differs from manifest")
        if accounting.get("nix_cache_info_allocated_size") != info_allocated:
            problems.append("nix-cache-info allocated size differs from manifest")
    totals = manifest.get("totals") or {}
    if totals.get("cache_apparent_size") != apparent_total:
        problems.append(
            f"cache apparent total is {apparent_total}, manifest says "
            f"{totals.get('cache_apparent_size')!r}"
        )
    if totals.get("cache_allocated_size") != allocated_total:
        problems.append(
            f"cache allocated total is {allocated_total}, manifest says "
            f"{totals.get('cache_allocated_size')!r}"
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


def symlink_problems(root: Path) -> list[str]:
    """A generation tree must contain ZERO symlinks. Reports every one found.

    Not a stylistic rule - it is the anchor that makes every other confinement
    check sufficient. `confined_blob` walks the components BELOW `cache/`, so
    replacing `cache` itself with a symlink to an external tree slipped past
    it: the gate hashed, verified and served someone else's directory and
    exited 0. Rather than teach each check to re-derive containment from a
    different starting point, the tree is required to have no symlinks at all,
    which is trivially true of anything this generator produces
    (`normalise_tree` refuses to create one) and makes "resolved path stays
    inside" hold by construction.

    `current` and `previous` are symlinks, and they live OUTSIDE the
    generation, in the publication root - which is exactly why this rule can be
    absolute in here.
    """
    problems = []
    if root.is_symlink():
        problems.append(
            f"{root.name} is a symlink; a generation must be a real directory"
        )
        return problems
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            problems.append(
                f"{path.relative_to(root)} is a symlink (-> {os.readlink(path)}); a "
                "generation must contain none, so that every path inside it is "
                "provably inside it"
            )
    return problems


def narinfo_name(store_path: str) -> str:
    """`<hash>.narinfo`, the filename a client asks for. Defined once."""
    return f"{PurePosixPath(store_path).name.split('-')[0]}.narinfo"


# Fields the fixture's own checks read out of a narinfo. Deriver and friends
# are optional; these are not, and an absent one means the file cannot do its
# job even though it exists.
REQUIRED_NARINFO_FIELDS = (
    "StorePath",
    "URL",
    "Compression",
    "FileHash",
    "FileSize",
    "NarHash",
    "NarSize",
    "References",
    "Sig",
)


def completeness_problems(cache: Path, manifest: dict) -> list[str]:
    """Everything about a served cache that is cheap to check without hashing.

    Presence AND structure: `nix-cache-info` parses and says what the manifest
    says it says, and every payload's narinfo exists, is non-empty, parses,
    carries the fields the fixture depends on, describes the right store path,
    and bears a signature that verifies against the manifest's public key.

    The scope grew because the previous version's scope was the defect. Reuse
    and the gate are supposed to share one definition of "is this the pinned
    workload"; when reuse checked strictly less, a tree the gate rejected was
    reported as reusable, `just fixtures` became a no-op, and the gate's own
    advice ("regenerate") could not fix what it had just detected. Every class
    the gate can reject a TREE for has to be visible here, or the repair loop
    does not terminate.

    Signature verification lives here rather than in the gate alone for the
    same reason: it is the one remaining thing a damaged narinfo could fail
    that hashing the NAR blobs would not catch.
    """
    problems = []
    info = cache / "nix-cache-info"
    if not info.is_file():
        problems.append("nix-cache-info is missing; the cache advertises nothing")
    else:
        declared = {k: str(v) for k, v in (manifest.get("cache_info") or {}).items()}
        try:
            served = {}
            for line in info.read_text().splitlines():
                if not line.strip():
                    continue
                key, separator, value = line.partition(": ")
                if not separator:
                    raise ValueError(f"malformed line {line!r}")
                if key in served:
                    raise ValueError(f"repeated key {key!r}")
                served[key] = value
        except (OSError, ValueError, UnicodeDecodeError) as error:
            problems.append(f"nix-cache-info cannot be parsed: {error}")
        else:
            if served != declared:
                problems.append(
                    f"nix-cache-info on disk is {served}, but manifest.json declares "
                    f"{declared}; the cache does not advertise what it claims to"
                )

    public_line = manifest.get("public_key")
    for entry in manifest.get("paths", []):
        attr = entry.get("attr")
        store_path = entry.get("store_path")
        if not isinstance(store_path, str) or not store_path:
            problems.append(f"payload {attr!r} has no store_path")
            continue
        name = narinfo_name(store_path)
        narinfo, refusal = confined_blob(cache, name)
        if refusal is not None:
            problems.append(f"payload {attr!r}: {refusal}")
            continue
        if not narinfo.is_file():
            problems.append(
                f"payload {attr!r}: {name} is missing, so the path it describes "
                "cannot be substituted"
            )
            continue
        try:
            text = narinfo.read_text()
        except (OSError, UnicodeDecodeError) as error:
            problems.append(f"payload {attr!r}: {name} cannot be read: {error}")
            continue
        if not text.strip():
            problems.append(
                f"payload {attr!r}: {name} is empty; a zero-byte narinfo is served "
                "as a valid answer and substitutes nothing"
            )
            continue
        try:
            pairs = parse_narinfo(text)
        except ValueError as error:
            problems.append(f"payload {attr!r}: {name} does not parse: {error}")
            continue
        missing = [
            f for f in REQUIRED_NARINFO_FIELDS if not any(k == f for k, _ in pairs)
        ]
        if missing:
            problems.append(f"payload {attr!r}: {name} is missing field(s) {missing}")
            continue
        if field(pairs, "StorePath") != store_path:
            problems.append(
                f"payload {attr!r}: {name} describes "
                f"{field(pairs, 'StorePath')!r}, manifest says {store_path!r}"
            )
            continue
        declared_fields = {
            "URL": entry.get("url"),
            "Compression": entry.get("compression"),
            "FileHash": entry.get("file_hash"),
            "FileSize": str(entry.get("file_size")),
            "NarHash": entry.get("nar_hash"),
            "NarSize": str(entry.get("nar_size")),
            "References": " ".join(entry.get("references") or []),
        }
        for key, declared_value in declared_fields.items():
            served_value = field(pairs, key)
            if served_value != declared_value:
                problems.append(
                    f"payload {attr!r}: narinfo {key} is {served_value!r}, "
                    f"manifest says {declared_value!r}"
                )
        if isinstance(public_line, str) and public_line:
            if not verify_narinfo(pairs, public_line):
                problems.append(
                    f"payload {attr!r}: {name} carries a Sig that does not verify "
                    "against the manifest's public key"
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


@contextmanager
def recording_static_server(directory: Path, overrides: dict[str, bytes] | None = None):
    """Serve a cache while recording response status for every GET/HEAD.

    `overrides` is deliberately in-memory.  The wide fanout mutation can serve
    one re-signed narinfo without copying a 256 MiB cache or mutating the
    immutable published generation.
    """
    records: list[tuple[str, str, int]] = []
    record_lock = threading.Lock()
    response_overrides = overrides or {}

    class RecordingHandler(_QuietHandler):
        def _request_path(self) -> str:
            return self.path.partition("?")[0]

        def send_response(self, code, message=None):
            with record_lock:
                records.append((self.command, self._request_path(), code))
            return super().send_response(code, message)

        def _send_override(self, include_body: bool) -> bool:
            body = response_overrides.get(self._request_path())
            if body is None:
                return False
            self.send_response(200)
            self.send_header("Content-Type", "text/x-nix-narinfo")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if include_body:
                self.wfile.write(body)
            return True

        def do_GET(self):  # noqa: N802 - stdlib handler API
            if not self._send_override(include_body=True):
                super().do_GET()

        def do_HEAD(self):  # noqa: N802 - stdlib handler API
            if not self._send_override(include_body=False):
                super().do_HEAD()

    handler = functools.partial(RecordingHandler, directory=str(directory))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", records
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
