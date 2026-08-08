#!/usr/bin/env python3
"""Generate the signed binary-cache fixture the mock upstream serves.

Output is a plain Nix binary cache directory - `nix-cache-info`, one
`<hash>.narinfo` per path, and `nar/` blobs - so ANY static file server is a
sufficient mock upstream (`just fixtures-serve`, a container's httpd, or the
in-process server the gate uses). Nothing here knows about the daemon or the
testproxy; task-2's caching and fault-injection logic is not this file's
business.

Determinism is the point of the `irreversible` label on task-3, so be exact
about which of three different claims each check earns:

  * EXPORT repeatability - re-serialising, recompressing and re-signing
    already-realised store paths gives identical bytes. `just test` proves
    this by regenerating and diffing.
  * BUILD determinism - the derivations themselves produce the same output
    twice. NOT covered above: regeneration finds the payloads already in the
    store and never rebuilds them, so a nondeterministic payload would be
    realised once and pass forever. `just fixtures-verify-rebuild` covers it,
    and is required before the J2 baseline is recorded.
  * Cross-host / cross-nixpkgs reproducibility - NOT verified anywhere, and
    not claimed. fixtures/workload.lock.json is the instrument for that case:
    it fails loudly when the workload moves for any reason.

Every assertion below is fatal rather than a warning, because a fixture that
is subtly wrong is worse than no fixture: the J2 egress baseline is frozen
against this workload and a silent change makes every cross-wave comparison
meaningless without anything looking broken.

Why payloads are built locally, and the other design rationale: see
fixtures/README.md, which is canonical. The short version, because it governs
the code immediately below: `nix copy` propagates the signatures a path
already carries, so anything substituted from cache.nixos.org would land here
with two Sig lines - hence the `signatures == []` / `ultimate == true`
assertion before every copy.

Exit codes: 0 generated, 1 an assertion about the produced fixture failed,
2 the environment is wrong and nothing was proven.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import shutil
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path

import fixturelib as fx

# Copy plan, in execution order. `compression` is a copy-time parameter (it is
# not a property of the derivation), so it lives here rather than in
# fixtures/workload.nix, which owns content. Order is load-bearing: `app`
# references `lib`, and `nix copy` copies closures, so `lib` must already be
# present with its own compression before `app` is copied - otherwise `lib`
# would inherit xz. The post-copy Compression assertion makes any reordering a
# hard failure instead of a silent workload change - and because EVERY entry is
# asserted, any compression-inheritance mistake surfaces at the victim's own
# assertion, not only at a reversal. That breadth rests on Nix's skip-existing
# copy semantics, which is why it is stated rather than assumed.
FAST_PLAN = [
    ("lib", "none"),
    ("app", "xz"),
    ("zstd", "zstd"),
]
LARGE_PLAN = [
    ("big", "none"),
]


def plan_for(include_large: bool):
    return FAST_PLAN + (LARGE_PLAN if include_large else [])


def tier_of(attr: str) -> str:
    """Derived from the plans, never restated. The plans decide what a tier is."""
    return fx.TIER_FULL if attr in {a for a, _ in LARGE_PLAN} else fx.TIER_FAST


# Loud enough that nobody mistakes it for real key material, and named once so
# the normaliser and the writer cannot disagree about which file stays 0600.
SECRET_KEY_NAME = "test-key.UNSAFE-TEST-ONLY.sec"


# nix-cache-info values are written EXPLICITLY. A file:// store initialised by
# Nix emits StoreDir only (verified), and both omitted fields then fall back to
# client defaults - which would leave every substituter-ordering scenario
# resting on an implicit value nobody chose. 40/1 mirror what cache.nixos.org
# advertises, because this fixture stands in for it; scenarios that need a
# different order use the client-side `?priority=N` override (TESTING.md).
CACHE_INFO_PRIORITY = 40
CACHE_INFO_WANT_MASS_QUERY = 1

# Guards the >=100 MB acceptance criterion at generation time rather than
# trusting the derivation's arithmetic.
LARGE_NAR_MIN_BYTES = 100_000_000


def fail(message: str, code: int = 1) -> None:
    sys.stdout.flush()
    print(f"gen-fixtures: FAIL - {message}", file=sys.stderr)
    raise SystemExit(code)


def pinned_nix() -> str:
    """Path to the `nix` from flake.lock, or a hard error.

    The host's `nix` would do the compression, making the fixture bytes a
    function of whatever Nix the developer happens to run - the one thing a
    pinned workload cannot tolerate. Mirrors the Justfile's `_toolchain`
    guard for cargo.
    """
    root = os.environ.get("NIX_P2P_NIX")
    if not root:
        fail("NIX_P2P_NIX not set - run inside: nix develop -c just fixtures", code=2)
    binary = Path(root) / "bin" / "nix"
    if not binary.is_file():
        fail(f"NIX_P2P_NIX={root} has no bin/nix", code=2)
    return str(binary)


def nix(*args: str, capture: bool = True) -> str:
    cmd = [pinned_nix(), "--extra-experimental-features", "nix-command flakes", *args]
    result = subprocess.run(cmd, capture_output=capture, text=True)
    if result.returncode != 0:
        detail = result.stderr.strip() if capture else "(output above)"
        fail(f"`{' '.join(cmd)}` failed:\n{detail}")
    return result.stdout if capture else ""


def build_payload(repo: Path, attr: str) -> str:
    """Realise one workload derivation and return its store path."""
    out = nix(
        "build",
        "--no-link",
        "--print-out-paths",
        f"{repo}#fixture-{attr}",
    ).strip()
    if not out:
        fail(f"nix build of fixture-{attr} printed no store path")
    return out


def write_cache_info(cache: Path) -> str:
    """Write nix-cache-info before any copy, so Nix validates instead of writing it."""
    text = (
        f"StoreDir: {fx.STORE_DIR}\n"
        f"WantMassQuery: {CACHE_INFO_WANT_MASS_QUERY}\n"
        f"Priority: {CACHE_INFO_PRIORITY}\n"
    )
    (cache / "nix-cache-info").write_text(text)
    return text


def copy_into_cache(cache: Path, secret_key: Path, store_path: str, compression: str):
    nix(
        "copy",
        "--to",
        f"file://{cache}?compression={compression}&secret-key={secret_key}",
        store_path,
        capture=False,
    )


def narinfo_path(cache: Path, store_path: str) -> Path:
    return cache / f"{Path(store_path).name.split('-')[0]}.narinfo"


def assert_fixture_narinfo(
    cache: Path, store_path: str, compression: str, public_line: str
) -> list[tuple[str, str]]:
    """Every assertion AC#2 makes about one produced narinfo."""
    path = narinfo_path(cache, store_path)
    if not path.is_file():
        fail(f"expected narinfo {path} was not produced")
    pairs = fx.parse_narinfo(path.read_text())

    sigs = [v for k, v in pairs if k == "Sig"]
    if len(sigs) != 1:
        fail(f"{path.name}: expected exactly one Sig line, found {len(sigs)}: {sigs}")
    if not sigs[0].startswith(f"{fx.KEY_NAME}:"):
        fail(f"{path.name}: foreign signature {sigs[0].split(':')[0]!r}")
    if not fx.verify_narinfo(pairs, public_line):
        fail(f"{path.name}: Sig does not verify against the test public key")

    actual = fx.field(pairs, "Compression")
    if actual != compression:
        fail(
            f"{path.name}: Compression is {actual!r}, expected {compression!r}. "
            "Copy order or the copy plan changed - the pinned workload is no longer "
            "the one the J2 baseline was measured against."
        )
    return pairs


def closure_of(store_paths) -> dict:
    """Every path `nix copy` will actually transfer, keyed by store path.

    `nix copy` copies CLOSURES, not the roots it is given. Checking provenance
    on the roots alone would leave any unexpected closure member to be signed
    into the fixture without ever appearing in the manifest - the same
    two-signature hazard the root check exists to prevent, one level down. The
    fixture's payloads are constructed to have no references outside the plan,
    so this is expected to return exactly the roots; asserting it is what makes
    that a fact rather than an assumption.
    """
    raw = nix("path-info", "--recursive", "--json", "--json-format", "1", *store_paths)
    return json.loads(raw)


def assert_closure_is_planned(store_paths: dict) -> None:
    planned = set(store_paths.values())
    closure = closure_of(sorted(planned))
    unexpected = sorted(set(closure) - planned)
    if unexpected:
        fail(
            "the closure of the planned payloads contains paths the workload does "
            f"not describe: {unexpected}.\n`nix copy` transfers whole closures, so "
            "these would be signed into the fixture and served without appearing in "
            "manifest.json or the lock. Give the payload no such reference, or add "
            "it to the plan deliberately."
        )
    for store_path, info in closure.items():
        if info["signatures"]:
            fail(
                f"closure member {store_path} carries signatures "
                f"{info['signatures']} - it was substituted, not built here."
            )
        if not info.get("ultimate"):
            fail(f"closure member {store_path} is not marked ultimate (locally built)")


def assert_no_unplanned_narinfos(cache: Path, store_paths: dict) -> None:
    """The served tree must describe the planned payloads and nothing else."""
    emitted = sorted(p.name for p in cache.glob("*.narinfo"))
    planned = sorted(
        f"{Path(p).name.split('-')[0]}.narinfo" for p in store_paths.values()
    )
    if emitted != planned:
        fail(
            f"the cache holds {len(emitted)} narinfo(s) but the plan has "
            f"{len(planned)}.\nemitted: {emitted}\nplanned: {planned}\n"
            "A narinfo nobody planned is a path the fixture serves and the "
            "manifest does not describe."
        )


def build_into(
    staging: Path, repo: Path, secret_line: str, public_line: str, include_large: bool
):
    """Realise, sign and copy every planned payload into `staging`."""
    staging.mkdir(parents=True)
    # Written before anything else, so the directory is claimed from its first
    # moment: a run that dies mid-build still leaves a tree the next run is
    # allowed to clean up.
    (staging / fx.OUT_MARKER).write_text(
        "Generated by scripts/gen-fixtures.py. Safe to delete; it is what marks "
        "this directory as ours, so --out cannot destroy anything else.\n"
    )
    cache = staging / "cache"
    cache.mkdir()

    secret_key = staging / SECRET_KEY_NAME
    secret_key.write_text(secret_line + "\n")
    secret_key.chmod(0o600)
    (staging / "test-key.pub").write_text(public_line + "\n")

    cache_info = write_cache_info(cache)

    plan = plan_for(include_large)
    store_paths = {}
    for attr, _compression in plan:
        store_paths[attr] = build_payload(repo, attr)
    # Checked over the whole closure before anything is signed, not per root
    # after each copy: the point is to know what will be transferred.
    assert_closure_is_planned(store_paths)
    for attr, compression in plan:
        copy_into_cache(cache, secret_key, store_paths[attr], compression)
    assert_no_unplanned_narinfos(cache, store_paths)

    # Re-read every narinfo from disk AFTER the whole plan has run, and build
    # both the assertions and the manifest from those re-reads. Asserting on
    # state captured at copy time would miss a later copy rewriting an earlier
    # path's narinfo - exactly the failure mode the ordering rule exists to
    # prevent, and one a future Nix could reintroduce.
    entries = [
        (
            attr,
            compression,
            store_paths[attr],
            assert_fixture_narinfo(cache, store_paths[attr], compression, public_line),
        )
        for attr, compression in plan
    ]

    if (cache / "nix-cache-info").read_text() != cache_info:
        fail(
            "nix-cache-info was rewritten by `nix copy`. The explicit Priority / "
            "WantMassQuery this fixture advertises are gone; ordering scenarios "
            "would silently fall back to client defaults."
        )

    if include_large:
        nar_size = int(
            fx.field(next(e for e in entries if e[0] == "big")[3], "NarSize")
        )
        if nar_size < LARGE_NAR_MIN_BYTES:
            fail(
                f"large payload NAR is {nar_size} bytes, below the "
                f"{LARGE_NAR_MIN_BYTES} the byte-volume fault modes need"
            )
    return entries


def read_workload_version(repo: Path) -> str:
    """Read WORKLOAD_VERSION, insisting it needs no normalisation.

    flake.nix strips only a newline while this strips all whitespace, so a
    trailing space would give Nix `"...-v1 "` - baked into every payload's
    seed - and Python `"...-v1"`, recorded in the manifest and the lock. The
    payload bytes would then derive from a string no artifact records.
    Rejecting anything but exactly one clean line makes the two normalisations
    provably equivalent instead of coincidentally so.
    """
    raw = (repo / "fixtures" / "WORKLOAD_VERSION").read_text()
    version = raw.strip()
    if raw != version + "\n" or not version:
        fail(
            f"fixtures/WORKLOAD_VERSION must be exactly one line with no leading or "
            f"trailing whitespace; got {raw!r}",
            code=2,
        )
    return version


def reusable(
    out_dir: Path, repo: Path, version: str, public_line: str, include_large: bool
) -> bool:
    """True when the tree on disk already IS the requested workload.

    Without this, `just test` (which depends on the fast tier) would delete a
    110 MiB full-tier tree that a container or measurement run had just spent
    minutes building. Reuse is safe only because the decision is made against
    the committed lock rather than against a timestamp: anything stale, from a
    different workload version, or signed by a different key regenerates.
    A full tree satisfies a request for the fast tier - it is a superset - but
    never the other way round.
    """
    manifest_file = out_dir / "manifest.json"
    if not manifest_file.is_file():
        return False
    try:
        manifest = json.loads(manifest_file.read_text())
    except (OSError, ValueError):
        return False
    if manifest.get("workload_version") != version:
        return False
    if manifest.get("public_key") != public_line:
        return False
    if include_large and manifest.get("tier") != fx.TIER_FULL:
        return False
    # Same definition of "is the pinned workload" the gate uses, including the
    # tier's required payload set - so reuse can never keep a tree the gate
    # would reject. Blob sizes are checked; blob hashes are not, because
    # re-hashing 110 MiB on every `just test` would cost more than it protects
    # (the gate hashes them, and generation is what this decides to skip).
    lock = fx.load_lock(repo)
    if fx.lock_problems(manifest, lock):
        return False
    for entry in manifest.get("paths", []):
        blob = out_dir / "cache" / entry["url"]
        if not blob.is_file() or blob.stat().st_size != entry["file_size"]:
            return False
    return True


def assert_safe_out_dir(out_dir: Path, repo: Path) -> None:
    """Refuse to take ownership of a directory that is not ours to destroy.

    `--out` publishes by renaming the old tree aside and deleting it. Pointed
    at a home directory or a source tree by a typo (or a stale shell variable),
    that is unrecoverable. Anything this script created carries OUT_MARKER; a
    non-empty directory without it is someone else's.
    """
    if out_dir == repo or (out_dir / ".git").exists():
        fail(f"--out {out_dir} looks like a source tree; refusing", code=2)
    if out_dir.exists():
        if not out_dir.is_dir():
            fail(f"--out {out_dir} exists and is not a directory", code=2)
        if any(out_dir.iterdir()) and not (out_dir / fx.OUT_MARKER).exists():
            fail(
                f"--out {out_dir} is not empty and has no {fx.OUT_MARKER} marker, so "
                "this script cannot show it created it. Refusing to delete it.\n"
                "If it IS an old fixture tree from before the marker existed, "
                f"remove it once by hand: rm -rf {out_dir}",
                code=2,
            )


@contextmanager
def publication_lock(out_dir: Path):
    """Serialise generators publishing to the same tree.

    Staging plus rename keeps a READER from seeing a half-written tree, but two
    WRITERS still race: both stage, both rename, and the loser's rename can
    land after the winner's while its `retired` cleanup deletes the winner's
    bytes. Observed as a spurious "signature is not valid" during review, which
    is exactly the kind of failure that gets blamed on the code under test.
    """
    out_dir.parent.mkdir(parents=True, exist_ok=True)
    lock_file = out_dir.parent / f".{out_dir.name}.publish.lock"
    # os.open with O_NOFOLLOW and WITHOUT O_TRUNC, not Path.open("w"). The lock
    # path is predictable, and "w" both follows symlinks and truncates: a
    # symlink planted there truncated its target the moment the lock was taken.
    # The lock needs no contents at all, so there is nothing to truncate for.
    try:
        descriptor = os.open(
            lock_file, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644
        )
    except OSError as error:
        # ELOOP here means the lock path is a symlink. Named explicitly,
        # because "Too many levels of symbolic links" on a path the caller
        # never mentioned is otherwise baffling.
        fail(
            f"cannot take the publication lock at {lock_file}: {error}. "
            "If it is a symlink, remove it - this script refuses to follow it, "
            "because opening it for writing would truncate whatever it points at.",
            code=2,
        )
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def generate(
    out_dir: Path,
    include_large: bool,
    write_lock: bool = False,
    retire_baseline: bool = False,
) -> None:
    repo = fx.repo_root()
    _name, _private, secret_line, public_line = fx.keypair()
    version = read_workload_version(repo)
    assert_safe_out_dir(out_dir, repo)
    warn_about_stranded_trees(out_dir)

    # Checked against the committed lock, not against a constant living beside
    # the seed phrase: an external pin is the only kind a coordinated edit
    # cannot walk past. Skipped only while bootstrapping a new lock.
    lock_file = fx.lock_path(repo)
    if not write_lock or lock_file.is_file():
        pinned = json.loads(lock_file.read_text())["public_key"]
        if public_line != pinned:
            fail(
                f"derived public key {public_line} != the key pinned in "
                f"{lock_file.name} ({pinned}). Every narinfo signed by the old key "
                "is now unverifiable against this one."
            )

    with publication_lock(out_dir):
        if not write_lock and reusable(
            out_dir, repo, version, public_line, include_large
        ):
            print(f"gen-fixtures: {version} already present at {out_dir} - reused")
            return

        # Built in a private staging directory, VALIDATED there, and only then
        # published with a rename. Order matters and was wrong once: publishing
        # first meant a drifted tree replaced a good one and the process still
        # exited 0, because the comparison against the lock happened afterwards
        # in a different program. A tree that does not match the pin must never
        # become the tree on disk.
        staging = out_dir.parent / f".{out_dir.name}.staging.{os.getpid()}"
        # The staging path is derived from a pid, so it is predictable and
        # could already exist as something that is not ours. Same ownership
        # discipline as --out: nothing without our marker is ever deleted.
        safe_rmtree(staging, "staging directory")
        try:
            entries = build_into(staging, repo, secret_line, public_line, include_large)
            manifest = write_manifest(
                staging, version, public_line, include_large, entries
            )
            fx.normalise_tree(staging, secret_names=frozenset({SECRET_KEY_NAME}))

            # One transaction, in the only safe order. The lock is the record
            # of what is on disk, so it must never describe a tree that was
            # not published: previously --write-lock replaced the tracked lock
            # BEFORE publishing, and a publication failure restored the old
            # tree while leaving the new lock behind - a repository whose lock
            # and tree disagreed, with the disagreement committed.
            #
            # Anything that can REFUSE runs before publication; only the file
            # write happens after it.
            if write_lock:
                pending = prepare_lock(repo, manifest, retire_baseline)
            else:
                pending = None
                assert_matches_lock(staging, repo, manifest)
            publish(staging, out_dir)
            if pending is not None:
                commit_lock(repo, pending)
        finally:
            # A no-op on success (publish renamed it away); on any failure it
            # keeps a half-built tree from being mistaken for a fixture later.
            if staging.exists():
                shutil.rmtree(staging)
    tier = "full" if include_large else "fast"
    print(f"gen-fixtures: {version} tier={tier} paths={len(entries)} -> {out_dir}")


def safe_rmtree(path: Path, what: str) -> None:
    """Delete a directory only if this script can show it created it."""
    if not path.exists():
        return
    if path.is_symlink() or not path.is_dir():
        fail(f"{what} {path} exists and is not a plain directory; refusing", code=2)
    if any(path.iterdir()) and not (path / fx.OUT_MARKER).exists():
        fail(
            f"{what} {path} is not empty and has no {fx.OUT_MARKER} marker, so this "
            f"script cannot show it created it. Refusing to delete it.",
            code=2,
        )
    shutil.rmtree(path)


def assert_matches_lock(staging: Path, repo: Path, manifest: dict) -> None:
    """The staged tree must be the pinned workload, or it is not published."""
    problems = fx.lock_problems(manifest, fx.load_lock(repo)) + fx.blob_problems(
        staging / "cache", manifest
    )
    if problems:
        fail(
            "the tree just built is NOT the workload pinned in "
            "fixtures/workload.lock.json, so it was discarded and the previous "
            "tree (if any) is untouched:\n  - "
            + "\n  - ".join(problems)
            + "\n\nMost likely flake.lock moved. Changing the pinned workload "
            "RETIRES the J2 measurement baseline - every number recorded against "
            "the old workload becomes incomparable. If that is what you intend: "
            "bump fixtures/WORKLOAD_VERSION, run `gen-fixtures.py --large "
            "--write-lock`, update the TESTING.md fixture section, and mark the "
            "existing baseline retired wherever it is quoted."
        )


def publish(staging: Path, out_dir: Path) -> None:
    """Swap the validated tree into place, then drop the old one.

    Not atomic in the POSIX sense - two directories cannot be exchanged in one
    call - but the caller holds the publication lock, the window where
    `out_dir` does not exist is a rename rather than the length of a 110 MiB
    copy, and a reader never sees a partly written tree.

    Two accepted residuals, recorded rather than fixed. A reader that opens a
    path during the swap gets ENOENT - loud and retryable, never a silently
    wrong byte; task-5's harness is told to expect it. And a process killed
    between the two renames strands the old tree under `.<name>.retired.<pid>`
    with no `out_dir`; nothing is lost, and warn_about_stranded_trees() names
    the directory and the one command that restores it.
    """
    retired = out_dir.parent / f".{out_dir.name}.retired.{os.getpid()}"
    if out_dir.exists():
        out_dir.rename(retired)
    try:
        staging.rename(out_dir)
    except OSError:
        if retired.exists():
            retired.rename(out_dir)
        raise
    if retired.exists():
        shutil.rmtree(retired)


def warn_about_stranded_trees(out_dir: Path) -> None:
    """Name any tree a crash stranded, and say how to get it back.

    Accepted residual: a process killed between the two renames in publish()
    leaves the previous tree under `.<name>.retired.<pid>` and no `out_dir`.
    Nothing is lost, but only if the operator is told where it went - an
    unexplained `.retired.12345` directory reads as junk and gets deleted.
    """
    stranded = sorted(out_dir.parent.glob(f".{out_dir.name}.retired.*"))
    if not stranded:
        return
    print(
        "gen-fixtures: NOTE - a previous run was interrupted mid-publication and "
        f"left {[str(p) for p in stranded]}.\n"
        "  Nothing is lost. This run rebuilds the tree from scratch, after which "
        "they are safe to delete;\n"
        f"  to restore one instead, stop and run: mv {stranded[0]} {out_dir}",
        flush=True,
    )


# The fields that say what a payload IS, for the purpose of deciding whether
# rewriting the lock retires a measurement baseline.
#
# `tier` is in this list, and that was contested. The round-2 reading treated
# it as schema bookkeeping - it does not change a single byte the fixture
# serves, so a tier edit is not "different bytes". The round-3 reading, adopted
# here, is that tier decides which payloads a given tier's gate must contain,
# so moving `big` from full to fast silently changes what a fast-tier
# measurement covered while the version string stands still. That is the exact
# class of silent redefinition the lock exists to prevent, and the cost of
# being wrong is asymmetric: a spurious version bump is an annoyance, a
# silently redefined baseline is a wrong decision about the kill criterion.
MATERIAL_KEYS = ("store_path", "compression", "nar_hash", "file_hash", "tier")


def material(entry) -> dict:
    return {k: (entry or {}).get(k) for k in MATERIAL_KEYS}


def prepare_lock(repo: Path, manifest: dict, retire_baseline: bool) -> dict:
    """Build the new lock and decide whether writing it is allowed.

    Everything that can REFUSE lives here, and this runs BEFORE publication;
    commit_lock() only writes. Splitting them is what stops the tracked lock
    from being replaced for a tree that then failed to publish - a repository
    whose committed lock described a tree that never existed.

    The fixture tree is generated and gitignored, so without this file nothing
    in the repository records what the workload version actually denotes, and
    the frozen workload the J2 baseline is measured against would be
    unreviewable. It also catches the drift WORKLOAD_VERSION alone cannot:
    bumping flake.lock changes stdenv, hence every store path, while the
    version string sits still.

    That last property is only real if the version cannot be REBOUND. Writing
    a new lock under an unchanged version silently redefines what every
    recorded measurement was taken against - the precise failure the lock
    exists to prevent - so it takes an explicit flag whose name says what it
    costs.
    """
    lock_file = fx.lock_path(repo)
    new = {
        "workload_version": manifest["workload_version"],
        "public_key": manifest["public_key"],
        "paths": {
            entry["attr"]: {
                "store_path": entry["store_path"],
                "compression": entry["compression"],
                "nar_hash": entry["nar_hash"],
                "file_hash": entry["file_hash"],
                # Tier lives in the lock so the gate can demand a complete tree
                # instead of verifying whatever it happens to find. Derived
                # from LARGE_PLAN rather than restated, so the plans stay the
                # single place that decides what belongs to which tier.
                "tier": tier_of(entry["attr"]),
            }
            for entry in manifest["paths"]
        },
    }
    if lock_file.is_file():
        old = json.loads(lock_file.read_text())
        same_version = old.get("workload_version") == new["workload_version"]
        # Compared on MATERIAL fields only - the bytes a measurement was taken
        # against. Adding a field to this file's schema is not a baseline
        # event and must not demand a version bump; changing what a payload
        # IS very much is.
        changed = sorted(
            attr
            for attr in set(old.get("paths", {})) | set(new["paths"])
            if material(old.get("paths", {}).get(attr))
            != material(new["paths"].get(attr))
        )
        rebinding = bool(changed) or old.get("public_key") != new["public_key"]
        if same_version and rebinding and not retire_baseline:
            fail(
                f"refusing to rebind workload version {new['workload_version']!r} to "
                f"different bytes (changed: {changed or ['metadata']}).\n"
                "Doing so RETIRES the J2 measurement baseline while leaving the "
                "version string that identifies it unchanged, so old and new numbers "
                "would look comparable and would not be.\n"
                "Either bump fixtures/WORKLOAD_VERSION (the documented path), or pass "
                "--retire-baseline to say deliberately that every measurement recorded "
                "against this version is now void.",
                code=2,
            )
        if same_version and rebinding:
            print(
                "gen-fixtures: WARNING - rebinding workload version "
                f"{new['workload_version']!r} (changed: {changed}); every measurement "
                "recorded against it is now RETIRED and must be marked so where it "
                "is quoted."
            )
    return new


def commit_lock(repo: Path, new: dict) -> None:
    """Write the prepared lock. Runs only after the tree it describes exists.

    Atomic: a lock truncated by an interrupted run would leave the repository
    with no valid record of the frozen workload at all.
    """
    lock_file = fx.lock_path(repo)
    temporary = lock_file.with_suffix(f".tmp.{os.getpid()}")
    temporary.write_text(json.dumps(new, indent=2, sort_keys=True) + "\n")
    os.replace(temporary, lock_file)
    print(f"gen-fixtures: rewrote {lock_file} - commit it as a reviewed diff")


def write_manifest(
    out_dir: Path, version: str, public_line: str, include_large: bool, entries
) -> dict:
    """Machine-readable description of what was generated.

    Consumers (the gate, task-9's measurement runs, task-5's containers) read
    this instead of globbing the cache. It describes the tree; it does not
    DEFINE it - the lock does. That distinction is load-bearing: a manifest
    that lists three payloads when the tier owes four is a red tree, not a
    smaller workload, and fixturelib.lock_problems() is where that is decided.
    """
    manifest = {
        "workload_version": version,
        "tier": "full" if include_large else "fast",
        "public_key": public_line,
        "cache_info": {
            "StoreDir": fx.STORE_DIR,
            "WantMassQuery": CACHE_INFO_WANT_MASS_QUERY,
            "Priority": CACHE_INFO_PRIORITY,
        },
        "paths": [
            {
                "attr": attr,
                "compression": compression,
                "store_path": store_path,
                "nar_hash": fx.field(pairs, "NarHash"),
                "nar_size": int(fx.field(pairs, "NarSize")),
                # The compressed body is what crosses the wire, so the egress
                # counting rule (TESTING.md) needs its size, and its hash is
                # the only thing that moves when a compressor changes but the
                # content does not.
                "file_hash": fx.field(pairs, "FileHash"),
                "file_size": int(fx.field(pairs, "FileSize")),
                "url": fx.field(pairs, "URL"),
                "references": fx.field(pairs, "References").split(),
            }
            for attr, compression, store_path, pairs in entries
        ],
    }
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        type=Path,
        default=fx.repo_root() / "fixtures" / "out",
        help="directory to (re)generate; wiped first",
    )
    parser.add_argument(
        "--large",
        action="store_true",
        help="also build the 110 MiB uncompressed payload (slow; kept out of "
        "`just test` and out of `nix flake check`)",
    )
    parser.add_argument(
        "--write-lock",
        action="store_true",
        help="rewrite fixtures/workload.lock.json from what was just built - "
        "do this only when the workload is meant to change, and bump "
        "fixtures/WORKLOAD_VERSION in the same commit",
    )
    parser.add_argument(
        "--retire-baseline",
        action="store_true",
        help="allow --write-lock to rebind the CURRENT workload version to "
        "different bytes. Every measurement recorded against that version "
        "becomes void; say so wherever it is quoted",
    )
    args = parser.parse_args()
    # Validated before any work: rejecting the combination after building and
    # publishing a whole tree would waste the run and, worse, leave a fast-tier
    # tree behind as if the command had partly succeeded.
    if args.write_lock and not args.large:
        fail(
            "--write-lock requires --large: a lock covering three of four payloads "
            "would pin nothing about the fourth.",
            code=2,
        )
    if args.retire_baseline and not args.write_lock:
        fail("--retire-baseline only means anything with --write-lock", code=2)
    # Tested BEFORE resolve(), which dereferences symlinks - checking the
    # resolved path would have been dead code. Publishing through a symlink
    # would replace it with a real directory and orphan whatever it pointed at.
    if args.out.is_symlink():
        fail(f"--out {args.out} is a symlink; refusing to publish through it", code=2)
    try:
        generate(args.out.resolve(), args.large, args.write_lock, args.retire_baseline)
    except OSError as error:
        # A read-only parent, a full disk or a vanished directory is an
        # environment failure, not a verdict about the workload. Reported as
        # exit 2 with a legible message rather than a raw traceback, so it is
        # never mistaken for the fixture being wrong.
        fail(f"filesystem error while generating: {error}", code=2)
    return 0


if __name__ == "__main__":
    # A malformed or unrecognisable lock is an environment failure, not a
    # verdict about the fixture: nothing can be proven against a definition
    # that cannot be read, so it exits 2 rather than 1.
    try:
        sys.exit(main())
    except fx.LockError as error:
        print(f"gen-fixtures: FAIL - {error}", file=sys.stderr)
        sys.exit(2)
