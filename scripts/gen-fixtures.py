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

PUBLICATION is immutable generations plus one atomic symlink flip:

    <out>/generations/gen-<manifest-sha>/   built, validated, then never touched
    <out>/current -> generations/gen-<...>  swapped with a single os.replace

Every consumer resolves through `current` (fixturelib.resolve_current), so a
publication is one syscall with no intermediate state. The previous design
renamed whole trees aside on publish and back again on rollback, with a
quarantine directory for the failed-lock case; four review rounds each found a
new hole in it (a rollback that fired on a failed `print`, a marker check
racing its own delete, a quarantine collision that abandoned the rollback
half-done, a cleanup failure reported as a failed publication). None of those
states exist here: a generation is either complete and named, or it is not
`current`. A failed run leaves its generation on disk, named and inspectable,
and the next successful publication collects it.

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
import contextlib
import fcntl
import hashlib
import json
import os
import stat
import subprocess
import sys
import time
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
    """Derived from the plans, never restated. The plans decide what a tier is.

    An attr in neither plan is a hard error rather than a default. Falling back
    to `fast` is the same fail-open species already fixed twice in this file
    (an unknown tier excusing a payload from every required set): a payload
    nobody planned would be silently pinned into the fast tier, and the tier
    whose gate is supposed to cover it would never know it existed.
    """
    if attr in {a for a, _ in LARGE_PLAN}:
        return fx.TIER_FULL
    if attr in {a for a, _ in FAST_PLAN}:
        return fx.TIER_FAST
    fail(
        f"payload {attr!r} is in neither FAST_PLAN nor LARGE_PLAN, so which tier "
        "must contain it is undefined. Add it to a plan; do not let it default."
    )


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


def note(message: str, stream=None) -> None:
    """Report something that must NEVER change the outcome.

    Used only once the publication is committed. Writing to a stream can fail
    on its own - EPIPE when the caller closed the pipe (`gen-fixtures | head`),
    ENOSPC on a full disk - and at that point the generation and the lock are
    both on disk. Letting a message that could not be delivered turn a
    completed publication into a non-zero exit reports a state that did not
    happen, which is the same class of lie as the rollback that used to fire
    when commit_lock's own success line failed to print. This is the one place
    in this file where suppressing an OSError is the correct thing to do.

    Suppressing the write is not enough on its own. The failed write leaves the
    message in the stream's buffer, and CPython exits 120 when its own flush at
    interpreter shutdown fails - so `gen-fixtures | head -1` still returned
    non-zero after a completed publication, by a second route. The underlying
    descriptor is therefore redirected to /dev/null, which makes that final
    flush succeed and leaves the exit status saying what actually happened.
    """
    target = stream or sys.stdout
    try:
        print(message, file=target, flush=True)
    except (OSError, ValueError):
        # ValueError too: writing to a closed stream raises "I/O operation on
        # closed file", which is not an OSError and would otherwise escape and
        # flip a committed publication to a failure.
        #
        # Best-effort by definition: a stream with no descriptor (a test
        # double, a StringIO) has nothing to redirect and needs nothing.
        with contextlib.suppress(Exception):
            devnull = os.open(os.devnull, os.O_WRONLY)
            try:
                os.dup2(devnull, target.fileno())
            finally:
                os.close(devnull)


def warn(message: str) -> None:
    """Report a problem on a PRE-commit path without letting it become one.

    Deliberately NOT note(). note() redirects the failing stream to /dev/null
    so the interpreter's shutdown flush cannot fail, and that redirect outlives
    the call: used on the unwind path it put /dev/null over fd 2 for the rest
    of the process, so the fail() or LockError handler that runs afterwards
    printed the real failure into the void and the run exited non-zero with no
    message at all. Pre-commit, the message that MUST survive is the one that
    comes later, so this suppresses the write and changes nothing else.
    """
    with contextlib.suppress(OSError, ValueError):
        print(message, file=sys.stderr, flush=True)


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
    built: Path, repo: Path, secret_line: str, public_line: str, include_large: bool
):
    """Realise, sign and copy every planned payload into `built`.

    `built.mkdir` is deliberately NOT exist_ok: the build directory carries a
    nanosecond timestamp, so anything already sitting there was put there by
    something else, and refusing is the only safe answer.
    """
    built.mkdir(parents=True)
    # Written before anything else, so the directory is claimed from its first
    # moment: a run that dies mid-build still leaves a tree the next run is
    # allowed to clean up.
    (built / fx.OUT_MARKER).write_text(
        "Generated by scripts/gen-fixtures.py. Safe to delete; it is what marks "
        "this directory as ours, so --out cannot destroy anything else.\n"
    )
    cache = built / "cache"
    cache.mkdir()

    secret_key = built / SECRET_KEY_NAME
    secret_key.write_text(secret_line + "\n")
    secret_key.chmod(0o600)
    (built / "test-key.pub").write_text(public_line + "\n")

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
    # Read through the anchored fixtures descriptor for the same reason the
    # lock is: it is the other file that defines the frozen workload, and it is
    # embedded in every payload's seed.
    with fx.anchored_fixtures_dir(repo) as fixtures_fd:
        raw = fx.read_at(fixtures_fd, "WORKLOAD_VERSION")
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
    """True when the PUBLISHED generation already IS the requested workload.

    Without this, `just test` (which depends on the fast tier) would republish
    over a 110 MiB full-tier tree that a container or measurement run had just
    spent minutes building. Reuse is safe only because the decision is made
    against the committed lock rather than against a timestamp: anything stale,
    from a different workload version, or signed by a different key
    regenerates. A full tree satisfies a request for the fast tier - it is a
    superset - but never the other way round.
    """
    current = fx.resolve_current(out_dir)
    if current is None or not current.is_dir():
        return False
    manifest_file = current / "manifest.json"
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
    # EVERY class of tree defect the gate can reject, checked here too - blob
    # hashes included. The old rationale for skipping them ("re-hashing 110 MiB
    # on every `just test` would cost more than it protects") was simply wrong:
    # measured, all four blobs total 116 MB and hash in 0.12 s, which is far
    # below the cost of the `nix build` calls this shortcut skips. It was also
    # the last thing keeping reuse weaker than the gate, and a reuse check
    # weaker than the gate does not merely miss defects - it makes them
    # UNREPAIRABLE, because `just fixtures` becomes a no-op on exactly the
    # trees the gate is refusing.
    #
    # With this, every rejection class terminates: reuse refuses, the tree is
    # rebuilt, and install_generation publishes it (superseding the damaged
    # generation if the content-derived name collides). What remains gate-only
    # is nothing about the TREE - only assertions about the environment
    # (TESTING.md naming the version, the client's trusted-keys) and about
    # Nix's behaviour (the positive controls and tamper bites), none of which a
    # damaged fixture tree can cause and none of which regeneration can fix.
    cache = current / "cache"
    lock = fx.load_lock(repo)
    try:
        if (
            fx.symlink_problems(current)
            or fx.lock_problems(manifest, lock)
            or fx.completeness_problems(cache, manifest)
            or fx.blob_problems(cache, manifest)
        ):
            return False
    except OSError:
        # A published generation that cannot even be READ is not reusable, and
        # saying so is the whole job of this function. Letting the error escape
        # aborted the run with "filesystem error while generating" and left the
        # unreadable generation in place - so an unreadable tree could not be
        # repaired at all, which is the same dead-end shape as the reuse loop.
        # The rebuild that follows supersedes it.
        return False
    return True


def assert_safe_out_dir(out_dir: Path, repo: Path) -> None:
    """Refuse to take ownership of a directory that is not ours to write into.

    Pointed at a home directory or a source tree by a typo (or a stale shell
    variable), publication would scatter generations into it and later collect
    them. Anything this script created carries OUT_MARKER; a non-empty
    directory without it is someone else's.
    """
    if out_dir == repo or (out_dir / ".git").exists():
        fail(f"--out {out_dir} looks like a source tree; refusing", code=2)
    if not out_dir.exists():
        return
    if not out_dir.is_dir():
        fail(f"--out {out_dir} exists and is not a directory", code=2)
    # is_file() on the un-followed path: .exists() follows symlinks, so a
    # symlink named like the marker and pointing at any existing file let --out
    # claim a non-empty foreign directory. purge_marked_dir already verifies
    # this marker with O_NOFOLLOW; one ownership question deserves one answer.
    marker = out_dir / fx.OUT_MARKER
    if any(out_dir.iterdir()) and (marker.is_symlink() or not marker.is_file()):
        fail(
            f"--out {out_dir} is not empty and has no {fx.OUT_MARKER} marker, so "
            "this script cannot show it created it. Refusing to write into it.\n"
            "If it IS an old fixture tree from before the marker existed, "
            f"remove it once by hand: rm -rf {out_dir}",
            code=2,
        )
    # Pre-generations layout: the tree used to be published AS the --out
    # directory (manifest.json and cache/ directly inside it). Refused rather
    # than migrated: the tree is gitignored and rebuilt in seconds, so a
    # one-time manual removal is cheaper and far more honest than a migration
    # path that would live in this file forever for a single transition.
    if (out_dir / "manifest.json").exists() and not (
        out_dir / fx.GENERATIONS_DIR
    ).is_dir():
        fail(
            f"{out_dir} holds a fixture tree in the old layout (manifest.json at the "
            "top level). Publication is now an immutable generation plus a `current` "
            f"symlink, so this directory cannot be reused.\n"
            f"  Remove it once and regenerate: rm -rf {out_dir}",
            code=2,
        )
    # Both publication links, checked the same way: os.replace cannot swap a
    # symlink in over a directory, and `previous` is flipped by exactly the
    # same primitive as `current`.
    for link_name in (fx.CURRENT_LINK, fx.PREVIOUS_LINK):
        link = out_dir / link_name
        if not link.is_symlink() and link.exists():
            fail(
                f"{link} exists and is not a symlink. Publication replaces it with "
                "one atomic os.replace, which cannot swap a symlink for a "
                f"directory.\n  Inspect it, then remove it: rm -rf {link}",
                code=2,
            )


def ensure_out_root(out_dir: Path) -> Path:
    """Create the publication root and claim it. Returns the generations dir.

    The marker goes down before anything else, exactly as it does inside a
    generation: a run that dies immediately after must still leave a directory
    the next run can recognise as its own.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    marker = out_dir / fx.OUT_MARKER
    if not marker.exists():
        marker.write_text(
            "Generated by scripts/gen-fixtures.py. Safe to delete; it is what marks "
            "this directory as ours, so --out cannot destroy anything else.\n"
        )
    generations = out_dir / fx.GENERATIONS_DIR
    generations.mkdir(exist_ok=True)
    # Every deletion happens under this directory, so prove it is really inside
    # the publication root before anything uses it. With `generations` a
    # symlink, the collector followed it and deleted marked directories
    # elsewhere on the filesystem.
    anchored = fx.anchored_generations(out_dir)
    if anchored is None:
        fail(
            f"{generations} is not a plain directory inside {out_dir} (a symlink, or "
            "not a directory at all). Everything this script deletes lives under it, "
            "so it will not act through it.\n"
            f"  Inspect it, then remove it: rm -rf {generations}",
            code=2,
        )
    return anchored


@contextmanager
def publication_lock(out_dir: Path):
    """Serialise generators publishing to the same root.

    The symlink flip protects READERS - each sees one complete generation or
    another - but two WRITERS still need ordering: both would build, both would
    flip, and the loser's `collect_generations` could delete the generation the
    winner had just published. Observed as a spurious "signature is not valid"
    during review, which is exactly the kind of failure that gets blamed on the
    code under test.

    Also what makes build-directory names safe to collect: nothing else is
    mid-build under generations/ while this is held.
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


@contextmanager
def anchored_publication(out_dir: Path):
    """Resolve the publication root ONCE and hold descriptors on it.

    Yields (generations_path, generations_fd). Everything destructive is done
    relative to the descriptor; the path is carried for messages and for the
    two places a real path must be handed to another process, each guarded by
    assert_anchor_intact.

    This is the sweep, not a patch: O_NOFOLLOW only ever guarded the FINAL
    component of a path, so every ancestor was still followed on every call.
    Swapping `out` for a symlink after `anchored_generations` had validated it
    redirected the collector, which then deleted a marked generation outside
    the root. Opening once and descending by descriptor removes the ancestors
    from the question entirely - `openat` does not consult them.
    """
    generations = ensure_out_root(out_dir)
    out_fd = fx.open_dir(out_dir)
    try:
        generations_fd = fx.open_dir(fx.GENERATIONS_DIR, dir_fd=out_fd)
        try:
            yield generations, generations_fd
        finally:
            os.close(generations_fd)
    finally:
        os.close(out_fd)


def assert_anchor_intact(anchor_fd: int, path: Path) -> None:
    """A real path is about to be used; prove it still names the anchor.

    Descriptors are immune to ancestor swaps, but `nix copy` and the HTTP
    server need paths. Comparing (dev, ino) back to the held descriptor is what
    makes handing a path out safe - without it the anchoring would stop at the
    boundary of this process.
    """
    if not fx.same_inode(anchor_fd, path):
        fail(
            f"{path} no longer names the directory this run anchored at startup - "
            "something replaced a directory above it mid-run. Nothing further will "
            "be written or deleted through that path.",
            code=2,
        )


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

    # Checked against the committed lock, not against a constant living beside
    # the seed phrase: an external pin is the only kind a coordinated edit
    # cannot walk past. Skipped only while bootstrapping a new lock, and read
    # through load_lock so a lock with a schema this code does not understand
    # is an error here too, not just at the comparison sites.
    lock_file = fx.lock_path(repo)
    if not write_lock or lock_file.is_file():
        pinned = fx.load_lock(repo)["public_key"]
        if public_line != pinned:
            fail(
                f"derived public key {public_line} != the key pinned in "
                f"{lock_file.name} ({pinned}). Every narinfo signed by the old key "
                "is now unverifiable against this one."
            )

    with (
        publication_lock(out_dir),
        anchored_publication(out_dir) as (
            generations,
            generations_fd,
        ),
    ):
        if not write_lock and reusable(
            out_dir, repo, version, public_line, include_large
        ):
            current = fx.resolve_current(out_dir)
            # Collect here too. collect_generations used to run only from
            # publish(), so on a warm tree - the common case, since `just test`
            # reuses - a generation stranded by a failed flip and a .building.*
            # left by a SIGKILL accumulated forever at 110 MiB each, silently,
            # because the warning lives in publish() as well.
            collect_generations(generations_fd, generations, retained(out_dir, current))
            # note(), not print(): reuse changed nothing and the published tree
            # is valid, so a stream this cannot be written to must not turn a
            # correct state into a non-zero exit.
            note(f"gen-fixtures: {version} already published at {current} - reused")
            return

        stamp = f"{time.time_ns()}-{os.getpid()}"
        building = generations / f".building.{stamp}"
        try:
            # STEP 1: build into a private directory under generations/.
            # `nix copy` needs a real path, so the anchor is re-checked here -
            # the one place a path leaves this process during publication.
            assert_anchor_intact(generations_fd, generations)
            entries = build_into(
                building, repo, secret_line, public_line, include_large
            )
            manifest = write_manifest(
                building, version, public_line, include_large, entries
            )
            fx.normalise_tree(building, secret_names=frozenset({SECRET_KEY_NAME}))

            # STEP 2: validate it FULLY, before it becomes a generation. Blob
            # self-consistency is checked in both modes - it compares the tree
            # against its own manifest and says nothing about the lock - while
            # the lock comparison applies only when the lock is meant to stay
            # put. With --write-lock the workload is deliberately changing, so
            # the equivalent refusal logic lives in step 3.
            assert_blobs_consistent(building, manifest)
            if not write_lock:
                assert_matches_lock(building, repo, manifest)

            # STEP 3: every remaining way this can REFUSE, still before
            # anything is published. prepare_lock decides; it does not write.
            pending = (
                prepare_lock(repo, manifest, retire_baseline) if write_lock else None
            )

            # STEPS 4-7.
            name = install_generation(building, generations, generations_fd, stamp)
            published = publish(
                out_dir, generations, generations_fd, name, repo, pending
            )
        except BaseException:
            # Catches EVERYTHING, including the SystemExit that fail() raises
            # and a KeyboardInterrupt: this is the unwinding path, and a
            # refusal or an error while cleaning up must never replace the
            # failure that caused the unwind.
            remove_build_directory(generations_fd, generations, building.name)
            raise
    tier = "full" if include_large else "fast"
    note(f"gen-fixtures: {version} tier={tier} paths={len(entries)} -> {published}")


def remove_build_directory(generations_fd: int, generations: Path, name: str) -> None:
    """Best-effort removal of the private build directory. Never raises.

    Catches Exception rather than BaseException on purpose: a KeyboardInterrupt
    arriving DURING cleanup is the operator asking again, and swallowing it
    would make the run unkillable. Everything an unwind can realistically hit
    here - a refusal, EACCES, EIO - is an Exception and is turned into a
    warning, so the failure that caused the unwind is what gets reported.
    """
    try:
        refusal = purge_marked_dir(generations_fd, generations, name)
    except Exception as error:  # noqa: BLE001 - unwinding path, see docstring
        refusal = f"{error}"
    if refusal is not None:
        # warn(), not note(): this runs while unwinding, and note()'s /dev/null
        # redirect would swallow the failure report that follows it.
        warn(f"gen-fixtures: WARNING - left {generations / name} in place: {refusal}")


def purge_marked_dir(parent_fd: int, parent: Path, name: str) -> str | None:
    """Delete `parent/name` iff it is a directory of ours. Returns a refusal.

    This is the ONLY deletion primitive in this file, and every step of it is
    done through an open file descriptor rather than by path. The previous
    version checked for the ownership marker by path and then called
    shutil.rmtree by path, so a directory swapped in between those two moments
    was deleted on the strength of a marker it never had - a real
    time-of-check/time-of-use hole, since generation and build-directory names
    are derivable. Here the directory is opened once with O_NOFOLLOW |
    O_DIRECTORY, the marker is verified with openat ON THAT DESCRIPTOR, and the
    contents are unlinked relative to it. Whatever the name refers to
    afterwards, the bytes removed are the ones whose marker was seen.

    An UNMARKED directory is never deleted, empty or not. Emptiness used to be
    treated as consent, which quietly made `mkdir` at a predictable path a way
    to have it removed.

    Returns None when the directory is gone, or a human-readable reason when it
    was left alone. Refusing is never fatal here: nothing this deletes is
    load-bearing (a generation is immutable and inspectable; a build directory
    is scratch), so the only right response to "cannot delete" is to say so.
    """
    # The caller HOLDS `parent_fd`, opened once by descent from the anchored
    # publication root; `parent` is carried only for messages. Re-opening the
    # parent by path here was the remaining ancestor hole: O_NOFOLLOW guards
    # only the final component, so swapping `out` for a symlink after the root
    # was resolved redirected this and it deleted a marked generation outside
    # the root entirely. Resolution that begins at a held descriptor never
    # consults an ancestor, so there is nothing left to swap.
    try:
        dir_fd = os.open(
            name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY | os.O_CLOEXEC,
            dir_fd=parent_fd,
        )
    except FileNotFoundError:
        return None
    except OSError as error:
        # ELOOP (a symlink, refused by O_NOFOLLOW) or ENOTDIR (a plain
        # file). Either way it is not a directory this script created.
        return f"{error}"
    try:
        try:
            os.close(
                os.open(
                    fx.OUT_MARKER,
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=dir_fd,
                )
            )
        except OSError:
            return (
                f"it carries no {fx.OUT_MARKER} marker, so this script cannot "
                "show it created it"
            )
        try:
            unlink_contents(dir_fd)
        except OSError as error:
            # Everything this can raise - EACCES on an unwritable
            # subdirectory, EIO, or the descent's own identity refusal -
            # means "left alone", which is what this function returns
            # rather than raises. The callers catch broadly anyway; going
            # through the documented channel is what keeps the contract
            # ("returns a refusal") true instead of nearly true.
            return f"{error}"
        # The final rmdir is unavoidably by name - POSIX has no rmdir(fd) -
        # so the inode the name refers to is compared against the one that
        # was just emptied. Without this, a directory swapped in after the
        # contents were removed could be rmdir'd instead. The residual is
        # the instant between this stat and the rmdir, and it can only
        # remove an EMPTY directory; it is stated rather than hidden.
        here = os.fstat(dir_fd)
        there = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (here.st_dev, here.st_ino) != (there.st_dev, there.st_ino):
            return "it was replaced by a different directory while being removed"
        os.rmdir(name, dir_fd=parent_fd)
        return None
    finally:
        os.close(dir_fd)


def unlink_contents(dir_fd: int) -> None:
    """Empty an open directory, depth first, never following a symlink.

    The descent re-verifies identity at every level, not just at the top. The
    top-level marker check plus O_NOFOLLOW does not protect a CHILD: stat a
    subdirectory, then open it by name, and a real directory swapped in between
    those two calls would be recursed into and emptied - the same
    check-then-act shape as the round-4 marker race, one level down. Comparing
    the stat's (dev, ino) against fstat on the descriptor that was actually
    opened closes it: whatever the name means afterwards, the bytes removed
    belong to the inode that was examined.
    """
    for entry in os.listdir(dir_fd):
        info = os.stat(entry, dir_fd=dir_fd, follow_symlinks=False)
        if not stat.S_ISDIR(info.st_mode):
            os.unlink(entry, dir_fd=dir_fd)
            continue
        child_fd = os.open(
            entry,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY | os.O_CLOEXEC,
            dir_fd=dir_fd,
        )
        try:
            opened = os.fstat(child_fd)
            if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                raise OSError(
                    f"{entry!r} was replaced between being examined and being "
                    "opened; refusing to delete its contents"
                )
            unlink_contents(child_fd)
        finally:
            os.close(child_fd)
        os.rmdir(entry, dir_fd=dir_fd)


def assert_blobs_consistent(built: Path, manifest: dict) -> None:
    """The staged tree must contain the bytes its own manifest describes.

    Independent of the lock, so it runs in --write-lock mode too: a manifest
    that disagrees with the blobs beside it is broken whether or not the
    workload is deliberately changing.
    """
    problems = fx.blob_problems(built / "cache", manifest)
    if problems:
        fail(
            "the tree just built does not match its own manifest, so it was "
            "discarded and the previous tree (if any) is untouched:\n  - "
            + "\n  - ".join(problems)
        )


def assert_matches_lock(built: Path, repo: Path, manifest: dict) -> None:
    """The staged tree must be the pinned workload, or it is not published."""
    problems = fx.lock_problems(manifest, fx.load_lock(repo))
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


def generation_name(built: Path) -> str:
    """A generation is named by the SHA-256 of the manifest it published.

    Content-derived rather than sequential, so the name says what the directory
    is: two runs of the same workload at the same tier produce the same name,
    and a run at a different tier produces a different one (the tier is a
    manifest field). That is what lets a fast and a full generation coexist
    instead of overwriting each other.
    """
    digest = hashlib.sha256((built / "manifest.json").read_bytes()).hexdigest()
    return f"gen-{digest[:16]}"


def install_generation(
    built: Path, generations: Path, generations_fd: int, stamp: str
) -> str:
    """Turn the validated build directory into an IMMUTABLE generation.

    One rename, and from that moment the directory is never written to, renamed
    or mutated again - only read, and eventually collected. Everything that
    could refuse has already run, so this is the last step that can touch a
    tree at all.

    The name is content-derived, so the target can legitimately already exist:
    `--write-lock` bypasses the reuse shortcut, so running it twice rebuilds a
    byte-identical tree. That case is compared with the same metadata-aware
    digest the gate uses and ADOPTED, which is what "immutable and
    content-named" predicts.

    When the name is taken by anything else - a generation something mutated
    after publication, a foreign file, a symlink - this publishes under a
    disambiguated name instead of refusing. Refusing was the obvious choice and
    it was wrong: the occupant of a content-derived name is usually the very
    tree being repaired, so `just fixtures` dead-ended on "remove it and rerun"
    naming the directory `current` still pointed at. One stray deletion inside
    a published generation made the tool unable to fix itself, which is the
    same unrecoverable shape as the reuse loop this round already closed.

    Publishing beside it keeps every rule intact: the occupant is never
    written to, renamed or deleted here (immutability is not conditional on the
    occupant being ours), the flip still publishes a fully validated tree, and
    the displaced directory is collected by a later run once it is no longer
    `current` or its predecessor. The disambiguated name is the loud part - it
    says in `ls` that something violated the contract.
    """
    name = generation_name(built)
    target = generations / name
    # lexists, not exists: a DANGLING symlink at a generation's name is
    # invisible to exists(), so the rename would fail with a bare ENOTDIR.
    if not os.path.lexists(target):
        # A concurrent creator would make this raise ENOTEMPTY rather than
        # merge two trees; the publication flock makes that a non-event, and
        # the error is handled as a filesystem failure either way.
        # Renamed relative to the held descriptor, so no ancestor is walked.
        os.rename(
            built.name, name, src_dir_fd=generations_fd, dst_dir_fd=generations_fd
        )
        return name

    reason = None
    if target.is_symlink() or not target.is_dir():
        reason = "it is not a directory"
    else:
        try:
            occupant = fx.tree_digest(target)
        except Exception as error:  # noqa: BLE001 - see below
            # ANY failure to read the occupant means the same thing: it cannot
            # be shown to be the generation its name claims. Letting this raise
            # made the repair path unreachable in exactly the case that needs
            # it most - an unreadable generation is damage, and damage is what
            # superseding exists to route around. Catching broadly is correct
            # here precisely because the response does not depend on which
            # error it was.
            reason = f"it could not be read ({error})"
        else:
            if occupant != fx.tree_digest(built):
                reason = (
                    "its contents differ from the tree just built, so it was mutated "
                    "or truncated after publication"
                )
    if reason is None:
        return name

    superseded = f"{name}.superseded-{stamp}"
    os.rename(
        built.name, superseded, src_dir_fd=generations_fd, dst_dir_fd=generations_fd
    )
    warn(
        f"gen-fixtures: WARNING - {target} already exists and {reason}. A generation "
        "is immutable by contract, so it was NOT modified or deleted.\n"
        f"  The freshly built tree was published as {superseded} instead; the old "
        "directory is inert and a later run collects it.\n"
        f"  If you want the plain name back, remove {target} once nothing is using "
        "it and regenerate."
    )
    return superseded


def publish(
    out_dir: Path,
    generations: Path,
    generations_fd: int,
    name: str,
    repo: Path,
    pending,
) -> Path:
    """Steps 4-7: flip the symlink, record the lock, collect what is superseded.

    The ordering and every failure's end state are specified here rather than
    inferred from the code, because the previous design - rename the old tree
    aside, rename the new one in, roll both back on failure - grew a new hole
    in each of three review rounds. Publication is now a single atomic
    operation, so there is no half-published state left to describe:

      4. os.replace(tmp symlink, current)   ONE syscall; the flip
      5. commit_lock                        ONE atomic os.replace of the lock
      6. on 5 failing: flip `current` back  ONE syscall; exit 2
      7. collect superseded generations     never touches `current`'s target

    Failures:
      * at 4  nothing has changed. `current`, the old generation and the old
              lock all stand. The validated new generation stays on disk under
              generations/, named and inspectable.
      * at 5  `current` is flipped back to the generation it pointed at (or
              removed, if nothing was published before). The old lock is
              intact, the new generation stays on disk. Exit 2, naming it.
      * at 7  the tree AND the lock are committed, so this REPORTS SUCCESS with
              a warning naming the residue. A failure to delete something
              superseded is not a reason to call a completed publication
              failed - the previous code did exactly that.

    The invariant behind all of it: the tracked lock must never describe a tree
    that is not the published one, in either direction.
    """
    previous = fx.resolve_current(out_dir)
    stamp = f"{time.time_ns()}-{os.getpid()}"

    # STEP 4a - record the predecessor BEFORE the flip, so the retention claim
    # ("the published generation and the one before it") is implemented rather
    # than asserted. A crash between 4a and 4b leaves previous == current,
    # which over-retains by nothing and under-retains nothing.
    if previous is not None:
        try:
            point_link_at(out_dir, fx.PREVIOUS_LINK, previous.name, f"{stamp}-prev")
        except OSError as error:
            fail(
                f"could not record the predecessor ({error}). Nothing changed: "
                f"{out_dir / fx.CURRENT_LINK} and the lock are as they were. The "
                f"validated new generation is on disk at {generations / name}.",
                code=2,
            )

    # STEPS 4b-6 - the flip and the lock write, as ONE guarded region.
    #
    # The flip is INSIDE the try. Round 6 opened the guard one statement after
    # it, and an ordinary Ctrl-C landing between os.replace and entering the
    # try left the new generation published against the OLD lock. There is no
    # placement of a guard that "starts after" an effect and still covers it;
    # the effect has to happen inside.
    #
    # The unwind decision is made from the DISK, not from a flag. That is the
    # second half of the same lesson: an interrupt can land between the lock's
    # os.replace and any assignment that would record it, so no flag can be set
    # closely enough. A flag-based rollback undid the flip after the lock had
    # already been written and produced the opposite split state from the one
    # it was guarding - old current, new lock. Asking the file system "is the
    # lock the new one?" has no window at all.
    #
    # commit_lock deliberately prints nothing: an earlier version printed its
    # success line inside the guarded block, so an EPIPE on stdout was caught
    # as "the lock could not be written" and triggered a rollback that reported
    # the opposite of what had actually happened.
    committed = False
    reported = False
    try:
        try:
            point_link_at(out_dir, fx.CURRENT_LINK, name, f"{stamp}-publish")
        except OSError as error:
            reported = True
            fail(
                f"could not publish ({error}). Nothing changed: "
                f"{out_dir / fx.CURRENT_LINK} and the lock are as they were. The "
                f"validated new generation is on disk at {generations / name}.",
                code=2,
            )
        if pending is not None:
            try:
                commit_lock(repo, pending)
            except OSError as error:
                rolled_back = safe_restore_current(out_dir, previous, name, stamp)
                reported = True
                fail(
                    f"the tree was published but the lock could not be written "
                    f"({error}), which would leave a published tree no committed "
                    f"lock describes.\n"
                    f"  {rolled_back}\n"
                    f"  The committed lock is unchanged. The new generation is on "
                    f"disk at {generations / name}.\n"
                    f"  Fix the permissions on {fx.lock_path(repo)} and rerun.",
                    code=2,
                )
        committed = True
    finally:
        if not committed and not reported:
            # Reached only by something the handlers above do not name -
            # KeyboardInterrupt, MemoryError, a bug in this file - at any point
            # from before the flip to just after the lock was replaced.
            if pending is not None and lock_on_disk_is(repo, pending):
                # The lock DID land. Rolling the flip back now would create the
                # split state instead of preventing it, so the publication is
                # left complete and said so.
                warn(
                    "gen-fixtures: interrupted, but the tree and the lock were both "
                    f"committed; {name} is published and the lock describes it."
                )
            else:
                undone = safe_restore_current(out_dir, previous, name, stamp)
                warn(f"gen-fixtures: interrupted after publishing. {undone}")

    note(
        f"gen-fixtures: rewrote {fx.lock_path(repo)} - commit it as a reviewed diff"
        if pending is not None
        else f"gen-fixtures: published {name}"
    )

    # STEP 7 - published; from here nothing may turn this into a failure.
    collect_generations(
        generations_fd, generations, retained(out_dir, generations / name)
    )
    return generations / name


def safe_restore_current(
    out_dir: Path, previous: Path | None, name: str, stamp: str
) -> str:
    """restore_current that never raises. Returns what actually happened.

    Used from both the error handler and the finally guard, where raising would
    replace the failure being reported with a second, less useful one.
    """
    try:
        return restore_current(out_dir, previous, name, f"{stamp}-rollback")
    except OSError as error:
        return (
            f"the rollback ALSO failed ({error}), so {out_dir / fx.CURRENT_LINK} may "
            "still point at the new generation while the lock does not describe it - "
            "fix this by hand"
        )


def point_link_at(out_dir: Path, link_name: str, name: str, stamp: str) -> None:
    """Make `<link_name>` name `generations/<name>` in one atomic step.

    A symlink cannot be retargeted in place, so a uniquely named one is created
    beside it and os.replace'd over it. os.replace on a symlink replaces the
    LINK, never what it points at, and is atomic - which is the whole reason
    the publication model changed: readers see the old generation or the new
    one, never a directory mid-rename and never a missing one.
    """
    link = out_dir / link_name
    temporary = out_dir / f".{link_name}.{stamp}"
    os.symlink(fx.generation_link_target(name), temporary)
    try:
        os.replace(temporary, link)
    except OSError:
        # Nothing collects the publication root itself (collect_generations
        # only scans generations/), so a leaked temporary would sit there
        # forever contradicting the caller's "nothing changed" message.
        with contextlib.suppress(OSError):
            os.unlink(temporary)
        raise


def restore_current(out_dir: Path, previous: Path | None, name: str, stamp: str) -> str:
    """Undo a flip. Returns what it ACTUALLY did, for the caller's message.

    The caller must not describe the end state itself: the claim "the new
    generation is inert" is only true if this returned, and stitching it into
    the message unconditionally is how a rollback that failed still gets
    reported as one that worked.

    `name` is needed for the case the adopt path makes routine: rebuilding an
    unchanged workload produces the generation that is ALREADY current, so
    `previous.name == name` and the flip was a no-op. Rolling back then leaves
    that generation published, and calling it inert - as this did - describes
    the opposite of the disk. Nothing is wrong in that state; the report was.
    """
    link = out_dir / fx.CURRENT_LINK
    if previous is None:
        os.unlink(link)
        return (
            f"Rolled back: nothing had been published before, so {link} was removed "
            "and the new generation is inert."
        )
    point_link_at(out_dir, fx.CURRENT_LINK, previous.name, stamp)
    if previous.name == name:
        return (
            f"Nothing to roll back: {link} already pointed at {previous.name}, which "
            "is the generation this run rebuilt, so it was and still is the published "
            "one. Only the lock write failed."
        )
    return (
        f"Rolled back: {link} points at {previous.name} again, so the new generation "
        "is inert."
    )


def retained(out_dir: Path, current: Path) -> set[str]:
    """The generations retention protects: the published one and its predecessor.

    Read from the two symlinks rather than remembered, so it is the same answer
    on the publish path and the warm-reuse path. Reuse used to keep only
    `current`, which deleted the predecessor on the very next `just test` and
    made the stated one-publication grace period false for any reader that
    resolves a PATH rather than holding a descriptor open.
    """
    previous = fx.resolve_previous(out_dir)
    return {current.name} | ({previous.name} if previous is not None else set())


def collect_generations(generations_fd: int, generations: Path, keep: set[str]) -> None:
    """Delete superseded generations. Never fatal, never touches `keep`.

    Two are kept: the one just published and the one it replaced. That buys a
    reader ONE generation of lag - it goes on reading a complete, immutable
    tree across a republication rather than racing a rename - and it makes
    reverting a publication a single symlink flip. Be exact about the limit:
    this is not a lease. A reader that resolved `current` and then idled
    through TWO further publications has its generation collected underneath
    it. Unbounded retention would be the worse trade for a 110 MiB fixture, so
    the contract for long-lived consumers is stated instead (TESTING.md): hold
    the directory open and re-resolve `current` on ENOENT.

    Anything else under generations/ is collectable: an older generation, or a
    build directory a killed run left behind. Deletion goes through
    purge_marked_dir, so an unmarked directory that appears here is left alone
    and named instead of removed.
    """
    left = []
    try:
        # Listed through the held descriptor, like every other step: iterdir()
        # would walk the path again and could be redirected by an ancestor
        # swapped after the root was anchored.
        candidates = sorted(os.listdir(generations_fd))
    except OSError as error:  # pragma: no cover - the directory just worked
        note(
            f"gen-fixtures: WARNING - published, but could not list {generations} "
            f"to collect superseded generations: {error}",
            sys.stderr,
        )
        return
    for candidate in candidates:
        if candidate in keep:
            continue
        try:
            refusal = purge_marked_dir(generations_fd, generations, candidate)
        except Exception as error:  # noqa: BLE001 - post-commit, see docstring
            refusal = f"{error}"
        if refusal is not None:
            left.append(f"{generations / candidate} ({refusal})")
    if left:
        # SUCCESS with a warning, deliberately. The tree and the lock are both
        # committed at this point; reporting failure because some superseded
        # bytes could not be removed would describe a state that did not happen.
        note(
            "gen-fixtures: WARNING - published successfully, but these superseded "
            "directories could not be removed:\n  - "
            + "\n  - ".join(left)
            + "\n  They are inert. Note that a partial removal can strip the "
            f"{fx.OUT_MARKER} marker before failing, after which this script will "
            "never delete the remainder itself - reclaim it with:\n"
            + "\n".join(f"    rm -rf {path.split(' (')[0]}" for path in left),
            sys.stderr,
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
        # Read through load_lock, not json.loads: a lock whose schema this code
        # does not understand must not be silently compared field-by-field and
        # then overwritten. It is an environment error (LockError -> exit 2).
        old = fx.load_lock(repo)
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

    Prints NOTHING, and that is load-bearing rather than a style choice. This
    function is called inside the caller's `except OSError` guard, so anything
    here that can raise OSError after the os.replace has already succeeded gets
    reported as "the lock could not be written" and rolled back - which is the
    exact opposite of the truth. Writing to stdout can raise OSError (EPIPE,
    ENOSPC), so the success line belongs to the caller, after the guard.
    """
    lock_file = fx.lock_path(repo)
    # Every step relative to a descriptor on `fixtures/`, not to a path.
    # O_NOFOLLOW only ever guarded the FINAL component, so with `fixtures`
    # itself a symlink this wrote an unrelated file outside the repository and
    # reported success. Resolution that starts at a held descriptor cannot
    # consult an ancestor at all, so there is no ancestor to swap or to have
    # been a symlink all along.
    #
    # O_CREAT|O_EXCL with an unguessable name replaces the old pid-derived temp
    # path: predictable and unanchored, it let a planted symlink both overwrite
    # an unrelated file and become the tracked lock itself.
    with fx.anchored_fixtures_dir(repo) as fixtures_fd:
        temporary_name = f".{lock_file.name}.{os.urandom(8).hex()}.tmp"
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o644,
            dir_fd=fixtures_fd,
        )
        try:
            with os.fdopen(descriptor, "w") as handle:
                handle.write(json.dumps(new, indent=2, sort_keys=True) + "\n")
            os.replace(
                temporary_name,
                lock_file.name,
                src_dir_fd=fixtures_fd,
                dst_dir_fd=fixtures_fd,
            )
        except BaseException:
            # BaseException, not OSError: a KeyboardInterrupt here must not
            # leave a stray temporary beside the tracked lock either. The
            # original failure is re-raised untouched.
            with contextlib.suppress(OSError):
                os.unlink(temporary_name, dir_fd=fixtures_fd)
            raise


def lock_on_disk_is(repo: Path, pending: dict) -> bool:
    """Has `pending` actually reached the tracked lock? Never raises.

    Asked on the unwind path INSTEAD of consulting a flag. An interrupt can
    land between the lock's os.replace and any assignment that would record
    it, so no flag can be set closely enough; reading the file back has no
    window at all. Getting this wrong is not academic - a flag-based rollback
    undid the symlink flip after the lock had already been written, producing
    the opposite split state from the one it was guarding against.
    """
    try:
        with fx.anchored_fixtures_dir(repo) as fixtures_fd:
            return (
                json.loads(fx.read_at(fixtures_fd, fx.lock_path(repo).name)) == pending
            )
    except (OSError, ValueError, fx.LockError):
        return False


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
        help="publication root: generations land in <dir>/generations and "
        "<dir>/current is flipped to the new one",
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
