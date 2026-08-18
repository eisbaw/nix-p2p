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
    already-realised store paths gives identical portable fixture identity.
    `just test` proves this for the canonical family; `just fixtures-wide`
    proves it for the independent wide family while treating only local
    allocated-byte observations as filesystem-specific.
  * BUILD determinism - the derivations themselves produce the same output
    twice. NOT covered above: regeneration finds the payloads already in the
    store and never rebuilds them, so a nondeterministic payload would be
    realised once and pass forever. `just fixtures-verify-rebuild` covers the
    canonical family and is required before the J2 baseline is recorded;
    `just fixtures-wide-verify-rebuild` covers the wide family.
  * Cross-host / cross-nixpkgs reproducibility - NOT verified anywhere, and
    not claimed. The selected family's tracked review baseline
    (`fixtures/workload.lock.json` or `fixtures/wide_closure.lock.json`) is the
    instrument for that case: it fails loudly when the workload moves.

Every assertion below is fatal rather than a warning, because a fixture that
is subtly wrong is worse than no fixture. The canonical J2 egress baseline is
frozen against its four-path workload; the independent wide baseline is frozen
against `wide_closure`. Silent drift invalidates results tied to the affected
family without anything looking broken.

PUBLICATION is immutable generations plus one atomic symlink flip, and the
AUTHORITATIVE lock lives INSIDE the generation:

    <out>/generations/gen-<manifest-sha>/lock.json   the runtime source of truth
    <out>/current -> generations/gen-<...>           swapped with one os.replace

Because the lock lives inside what `current` points at, that single os.replace
commits the tree AND its lock in one syscall. There is no second authoritative
source to reconcile, so publish() has NO rollback and NO read-back. Rounds 2-7
all failed on machinery that reconciled the `current` symlink against the
git-tracked lock to decide a rollback - a rollback that fired on a failed
`print`, a read-back that returned False on a read error and destroyed a good
publish, an interrupt that split the two writes. The fix was not a better
reconciliation but DELETING the second source. Crash consistency is therefore
not "windowless via a clever read-back"; it is that there is nothing to split:
kill before the flip -> old-complete, kill after -> new-complete.

The selected git-tracked baseline (`fixtures/workload.lock.json` for canonical,
`fixtures/wide_closure.lock.json` for wide) is DEMOTED to a review artifact.
It is read only by the freeze/--write-lock path (assert_matches_baseline,
prepare_baseline) and written only at --write-lock, AFTER publication. Its lag
is fine and visible in git. Every runtime/gate reader resolves the lock through
`current -> gen-<sha>/lock.json`; that boundary is enforced by
scripts/check-lock-sources.py.

A failed run leaves its generation on disk, named and inspectable, and the next
successful publication collects it.

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
from pathlib import Path, PurePosixPath

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
WIDE_MEMBER_ATTRS = tuple(
    f"{fx.WIDE_MEMBER_PREFIX}{index:03d}" for index in range(fx.WIDE_MEMBER_COUNT)
)
WIDE_PLAN = [(attr, "none") for attr in WIDE_MEMBER_ATTRS] + [
    (fx.WIDE_ROOT_ATTR, "none")
]


def plan_for(tier: str):
    if tier == fx.TIER_FAST:
        return FAST_PLAN
    if tier == fx.TIER_FULL:
        return FAST_PLAN + LARGE_PLAN
    if tier == fx.TIER_WIDE:
        return WIDE_PLAN
    fail(f"unknown fixture tier {tier!r}", code=2)


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
    if attr in {a for a, _ in WIDE_PLAN}:
        return fx.TIER_WIDE
    fail(
        f"payload {attr!r} is in no fixture plan, so which tier "
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
    """Report a diagnostic whose output failure must NEVER poison success.

    Used after publication is committed and on non-fatal pre-flip paths that
    continue toward a possible successful publication or return. Writing to a
    stream can fail on its own - EPIPE when the caller closed the pipe
    (`gen-fixtures | head`), ENOSPC on a full disk. Letting that diagnostic turn
    an existing or later committed publication into a non-zero exit reports a
    state that did not happen, which is the same class of lie as the rollback
    that used to fire when commit_lock's own success line failed to print. This
    is the one place in this file where suppressing an OSError is correct. It is
    deliberately not used while a real failure unwinds; unwind_warning preserves
    that later failure channel instead of redirecting it.

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


def unwind_warning(message: str) -> None:
    """Report cleanup trouble while an earlier pre-commit failure unwinds.

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


def copy_many_into_cache(
    cache: Path, secret_key: Path, store_paths: list[str], compression: str
):
    """Copy same-compression independent members in one pinned-Nix invocation."""
    nix(
        "copy",
        "--to",
        f"file://{cache}?compression={compression}&secret-key={secret_key}",
        *store_paths,
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


def wide_store_paths(repo: Path) -> dict[str, str]:
    """Realise the root once and map its store-truth closure to planned attrs."""
    root_path = build_payload(repo, fx.WIDE_ROOT_ATTR)
    closure = closure_of([root_path])
    mapped = {}
    for attr, _compression in WIDE_PLAN:
        suffix = f"-nix-p2p-fixture-{attr}"
        matches = [path for path in closure if Path(path).name.endswith(suffix)]
        if len(matches) != 1:
            fail(
                f"wide closure maps attr {attr!r} to {len(matches)} store paths: "
                f"{matches}. The Nix definition and generator plan drifted."
            )
        mapped[attr] = matches[0]
    planned = set(mapped.values())
    if set(closure) != planned:
        fail(
            "wide root closure contains unplanned store paths: "
            f"{sorted(set(closure) - planned)}"
        )
    return mapped


def assert_wide_store_contract(store_paths: dict[str, str]) -> None:
    """Prove the fanout from Nix store truth before any cache metadata exists."""
    closure = closure_of([store_paths[fx.WIDE_ROOT_ATTR]])
    root_info = closure[store_paths[fx.WIDE_ROOT_ATTR]]
    member_paths = {store_paths[attr] for attr in WIDE_MEMBER_ATTRS}
    root_references = set(root_info.get("references", []))
    if root_references != member_paths:
        fail(
            "wide root direct references differ from its 128 members: "
            f"missing={sorted(member_paths - root_references)}, "
            f"extra={sorted(root_references - member_paths)}"
        )
    if set(closure) != member_paths | {store_paths[fx.WIDE_ROOT_ATTR]}:
        fail("wide recursive closure is not exactly root plus all members")
    for attr in WIDE_MEMBER_ATTRS:
        references = closure[store_paths[attr]].get("references", [])
        if references:
            fail(f"wide member {attr!r} unexpectedly references {references}")


def build_into(built: Path, repo: Path, secret_line: str, public_line: str, tier: str):
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

    plan = plan_for(tier)
    if tier == fx.TIER_WIDE:
        store_paths = wide_store_paths(repo)
        assert_wide_store_contract(store_paths)
    else:
        store_paths = {}
        for attr, _compression in plan:
            store_paths[attr] = build_payload(repo, attr)
    # Checked over the whole closure before anything is signed, not per root
    # after each copy: the point is to know what will be transferred.
    assert_closure_is_planned(store_paths)
    if tier == fx.TIER_WIDE:
        copy_many_into_cache(
            cache,
            secret_key,
            [store_paths[attr] for attr in WIDE_MEMBER_ATTRS],
            "none",
        )
        # Root last: a closure copy before the members exist would choose the
        # root's compression for every member.
        copy_into_cache(cache, secret_key, store_paths[fx.WIDE_ROOT_ATTR], "none")
    else:
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

    if tier == fx.TIER_FULL:
        nar_size = int(
            fx.field(next(e for e in entries if e[0] == "big")[3], "NarSize")
        )
        if nar_size < LARGE_NAR_MIN_BYTES:
            fail(
                f"large payload NAR is {nar_size} bytes, below the "
                f"{LARGE_NAR_MIN_BYTES} the byte-volume fault modes need"
            )
    return entries


def read_workload_version(repo: Path, tier: str) -> str:
    """Read the selected family's version, insisting on one clean line.

    flake.nix strips only a newline while this strips all whitespace, so a
    trailing space would give Nix `"...-v1 "` - baked into every payload's
    seed - and Python `"...-v1"`, recorded in the manifest and the lock. The
    payload bytes would then derive from a string no artifact records.
    Rejecting anything but exactly one clean line makes the two normalisations
    provably equivalent instead of coincidentally so.
    """
    if tier == fx.TIER_WIDE:
        version_file = "WIDE_WORKLOAD_VERSION"
    elif tier in (fx.TIER_FAST, fx.TIER_FULL):
        version_file = "WORKLOAD_VERSION"
    else:
        raise ValueError(f"unknown fixture tier {tier!r}")
    # Read through the anchored fixtures descriptor for the same reason the
    # lock is: this file defines the frozen workload and is embedded in every
    # payload's seed.
    with fx.anchored_fixtures_dir(repo) as fixtures_fd:
        raw = fx.read_at(fixtures_fd, version_file)
    version = raw.strip()
    if raw != version + "\n" or not version:
        fail(
            f"fixtures/{version_file} must be exactly one line with no leading or "
            f"trailing whitespace; got {raw!r}",
            code=2,
        )
    return version


def reusable(
    out_dir: Path, repo: Path, version: str, public_line: str, tier: str
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
    actual_tier = manifest.get("tier")
    if actual_tier not in fx.TIERS or not fx.tier_satisfies(actual_tier, tier):
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
    try:
        # Against the generation's OWN authoritative lock, exactly as the gate
        # does at runtime - not the git baseline. A published generation was
        # validated against the baseline at build time; the runtime question is
        # only whether the tree still matches the lock committed alongside it.
        lock = fx.load_generation_lock(current)
        if (
            fx.symlink_problems(current)
            or fx.lock_problems(manifest, lock)
            or fx.completeness_problems(cache, manifest)
            or fx.blob_problems(cache, manifest)
            or fx.wide_disk_problems(cache, manifest)
        ):
            return False
    except (OSError, fx.LockError):
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

    Yields (out_fd, generations_path, generations_fd). Everything destructive
    is done relative to those descriptors; the path is carried for messages and
    for the two places a real path must be handed to another process, each
    guarded by assert_anchor_intact.

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
            yield out_fd, generations, generations_fd
        finally:
            os.close(generations_fd)
    finally:
        os.close(out_fd)


def ownership_marker_problem(directory_fd: int, display: Path) -> str | None:
    """Return why an anchored directory lacks a plain ownership marker."""
    try:
        marker_fd = os.open(
            fx.OUT_MARKER,
            os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=directory_fd,
        )
    except OSError as error:
        return f"{display} has no plain {fx.OUT_MARKER} ownership marker ({error})"
    try:
        if not stat.S_ISREG(os.fstat(marker_fd).st_mode):
            return f"{display / fx.OUT_MARKER} is not a regular file"
    finally:
        os.close(marker_fd)
    return None


def require_ownership_marker(directory_fd: int, display: Path) -> None:
    """Require a plain marker in an already-open directory, without following it."""
    problem = ownership_marker_problem(directory_fd, display)
    if problem is not None:
        fail(
            f"{problem}; refusing to collect anything from a foreign directory",
            code=2,
        )


@contextmanager
def anchored_existing_publication(out_dir: Path):
    """Anchor an existing owned publication without creating or repairing it."""
    try:
        out_fd = fx.open_dir(out_dir)
    except OSError as error:
        fail(f"cannot anchor existing fixture publication {out_dir}: {error}", code=2)
    try:
        require_ownership_marker(out_fd, out_dir)
        try:
            generations_fd = fx.open_dir(fx.GENERATIONS_DIR, dir_fd=out_fd)
        except OSError as error:
            fail(
                f"{out_dir / fx.GENERATIONS_DIR} is missing, is not a plain "
                f"directory, or is a symlink ({error}); refusing collection",
                code=2,
            )
        try:
            yield out_fd, out_dir / fx.GENERATIONS_DIR, generations_fd
        finally:
            os.close(generations_fd)
    finally:
        os.close(out_fd)


def retained_generation_at(
    out_fd: int,
    generations_fd: int,
    out_dir: Path,
    link_name: str,
    *,
    strict: bool = True,
) -> str | None:
    """Resolve one publication link relative to held descriptors.

    Collection is strict because a bad anchor must stop every deletion. Generation
    is tolerant because a bad link is precisely what publishing a new `current`
    repairs; it uses the same descriptor parser with ``strict=False`` and retains
    only names this function could prove safe before the atomic flip.
    """

    def refuse(message: str) -> None:
        if strict:
            fail(message, code=2)

    try:
        link_info = os.stat(link_name, dir_fd=out_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as error:
        refuse(f"cannot inspect {out_dir / link_name}: {error}")
        return None
    if not stat.S_ISLNK(link_info.st_mode):
        refuse(f"{out_dir / link_name} exists and is not a symlink")
        return None
    try:
        target_text = os.readlink(link_name, dir_fd=out_fd)
    except OSError as error:
        refuse(f"cannot read {out_dir / link_name}: {error}")
        return None
    target = PurePosixPath(target_text)
    if (
        target.as_posix() != target_text
        or len(target.parts) != 2
        or target.parts[0] != fx.GENERATIONS_DIR
        or not target.parts[1].startswith("gen-")
    ):
        refuse(
            f"{out_dir / link_name} has malformed or unconfined target "
            f"{target_text!r}; expected generations/gen-..."
        )
        return None
    name = target.parts[1]
    try:
        generation_fd = fx.open_dir(name, dir_fd=generations_fd)
    except OSError as error:
        refuse(
            f"{out_dir / link_name} points at missing, symlinked, or non-directory "
            f"generation {name!r} ({error})"
        )
        return None
    try:
        marker_problem = ownership_marker_problem(
            generation_fd, out_dir / fx.GENERATIONS_DIR / name
        )
        if marker_problem is not None:
            refuse(f"{marker_problem}; refusing to retain an unowned generation")
            return None
    finally:
        os.close(generation_fd)
    return name


def retained_generations_at(
    out_fd: int,
    generations_fd: int,
    out_dir: Path,
) -> set[str]:
    """Resolve strict current+previous anchors for deletion-capable collection."""
    current = retained_generation_at(out_fd, generations_fd, out_dir, fx.CURRENT_LINK)
    previous = retained_generation_at(out_fd, generations_fd, out_dir, fx.PREVIOUS_LINK)
    if current is None:
        fail(
            f"{out_dir} exists but has no {fx.CURRENT_LINK} publication link; "
            "refusing to collect without an active-generation anchor",
            code=2,
        )
    return {current} | ({previous} if previous is not None else set())


def generator_retention_at(
    out_fd: int,
    generations_fd: int,
    out_dir: Path,
) -> tuple[str | None, str | None, bool]:
    """Snapshot tolerant anchors and whether an existing previous needs repair.

    ``None`` is a valid result for an absent ``previous`` link, but an existing
    malformed/dangling link must not collapse to that same state: warm reuse
    otherwise returns success while leaving strict collection inoperable. The
    third result distinguishes that invalid-link case without weakening the
    collector's fail-closed resolver.
    """
    try:
        os.stat(fx.PREVIOUS_LINK, dir_fd=out_fd, follow_symlinks=False)
    except FileNotFoundError:
        previous_present = False
    except OSError:
        # An entry that cannot be inspected is not safely equivalent to an
        # absent optional link. Let the generator's atomic repair either replace
        # it or fail before reporting warm reuse as successful.
        previous_present = True
    else:
        previous_present = True

    current = retained_generation_at(
        out_fd,
        generations_fd,
        out_dir,
        fx.CURRENT_LINK,
        strict=False,
    )
    previous = retained_generation_at(
        out_fd,
        generations_fd,
        out_dir,
        fx.PREVIOUS_LINK,
        strict=False,
    )
    return current, previous, previous_present and previous is None


def collect_only(out_dir: Path) -> None:
    """Collect one existing fixture root under the normal publication lock."""
    if out_dir.is_symlink():
        fail(f"--out {out_dir} is a symlink; refusing collection through it", code=2)
    if not os.path.lexists(out_dir):
        note(f"gen-fixtures: no publication root at {out_dir}; nothing to collect")
        return
    with publication_lock(out_dir):
        # The root may disappear while this process waits for a publisher. That
        # is still an absent-root no-op, and must not recreate it.
        if not os.path.lexists(out_dir):
            note(f"gen-fixtures: no publication root at {out_dir}; nothing to collect")
            return
        if out_dir.is_symlink():
            fail(
                f"--out {out_dir} became a symlink while waiting for the publication "
                "lock; refusing collection",
                code=2,
            )
        with anchored_existing_publication(out_dir) as (
            out_fd,
            generations,
            generations_fd,
        ):
            keep = retained_generations_at(out_fd, generations_fd, out_dir)
            refusals = collect_generations(generations_fd, generations, keep)
            if refusals:
                fail(
                    "fixture collection was incomplete; inspect the refused "
                    "directories before retrying:\n  - " + "\n  - ".join(refusals),
                    code=2,
                )
    note(
        f"gen-fixtures: collected unreferenced generations under {out_dir}; "
        f"retained {sorted(keep)}"
    )


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
    tier: str,
    write_lock: bool = False,
    retire_baseline: bool = False,
) -> None:
    repo = fx.repo_root()
    _name, _private, secret_line, public_line = fx.keypair()
    version = read_workload_version(repo, tier)
    assert_safe_out_dir(out_dir, repo)

    # No git-baseline read here any more. The derived public key is compared
    # against the baseline where the baseline is legitimately consulted - the
    # fresh-build freeze check (assert_matches_baseline) and --write-lock
    # reconciliation (prepare_baseline) - both of which run below AFTER the
    # tree is built. Removing the standalone pre-check keeps the git file out of
    # every runtime path; the cost is that a seed/key mismatch surfaces after
    # the build rather than before it, with the same clear message.
    with (
        publication_lock(out_dir),
        anchored_publication(out_dir) as (
            out_fd,
            generations,
            generations_fd,
        ),
    ):
        current_before, previous_before, previous_invalid = generator_retention_at(
            out_fd, generations_fd, out_dir
        )
        if (
            not write_lock
            and current_before is not None
            and reusable(out_dir, repo, version, public_line, tier)
        ):
            if previous_invalid:
                # Missing previous is a valid one-generation state. An existing
                # malformed/dangling previous is not: repair it before collection
                # and before claiming this warm publication was successfully
                # reused, so strict collect-only can immediately operate on it.
                stamp = f"{time.time_ns()}-{os.getpid()}"
                assert_anchor_intact(out_fd, out_dir)
                try:
                    point_link_at(
                        out_dir,
                        fx.PREVIOUS_LINK,
                        current_before,
                        f"{stamp}-reuse-prev",
                    )
                except OSError as error:
                    fail(
                        "could not repair the malformed previous retention link "
                        f"({error}). {out_dir / fx.CURRENT_LINK} remains published "
                        f"as {current_before!r}, but warm reuse was not completed.",
                        code=2,
                    )
                previous_before = current_before
            retained_before = {
                name for name in (current_before, previous_before) if name is not None
            }
            current = fx.resolve_current(out_dir)
            # Collect here too. collect_generations used to run only from
            # publish(), so on a warm tree - the common case, since `just test`
            # reuses - a generation stranded by a failed flip and a .building.*
            # left by a SIGKILL accumulated forever at 110 MiB each, silently,
            # because the warning lives in publish() as well.
            report_collection_refusals(
                collect_generations(
                    generations_fd,
                    generations,
                    retained_before,
                )
            )
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
            entries = build_into(building, repo, secret_line, public_line, tier)
            # st_blocks can settle when freshly-created cache files receive
            # their canonical metadata.  Wide disk evidence is sampled only
            # after that operation; the later whole-tree normalisation is then
            # idempotent for cache/ and cannot invalidate its own manifest.
            if tier == fx.TIER_WIDE:
                fx.normalise_tree(building, secret_names=frozenset({SECRET_KEY_NAME}))
            manifest = write_manifest(building, version, public_line, tier, entries)
            # STEP 1b: write the AUTHORITATIVE lock INSIDE the generation. This
            # is the round-8 change: the lock the runtime and the gate resolve
            # is gen-<sha>/lock.json, committed atomically with the tree by the
            # publish flip. Written from the manifest, so it is a deterministic
            # function of the build and the generation stays content-addressed.
            (building / fx.GEN_LOCK_NAME).write_text(
                json.dumps(lock_dict_from_manifest(manifest), indent=2, sort_keys=True)
                + "\n"
            )
            if tier == fx.TIER_WIDE:
                # cache/ was normalised before its filesystem-local st_blocks
                # evidence was sampled. Touching it again can legitimately
                # change extent accounting, so normalise only the two files
                # created since then and the root directory they entered.
                for metadata_file in (
                    building / "manifest.json",
                    building / fx.GEN_LOCK_NAME,
                ):
                    metadata_file.chmod(fx.TREE_FILE_MODE)
                    os.utime(metadata_file, (fx.TREE_MTIME, fx.TREE_MTIME))
                building.chmod(fx.TREE_DIR_MODE)
                os.utime(building, (fx.TREE_MTIME, fx.TREE_MTIME))
            else:
                fx.normalise_tree(building, secret_names=frozenset({SECRET_KEY_NAME}))

            # STEP 2: validate it FULLY, before it becomes a generation. Blob
            # self-consistency is checked in both modes - it compares the tree
            # against its own manifest and says nothing about the baseline -
            # while the freeze check against the git baseline applies only on a
            # plain build. With --write-lock the workload is deliberately
            # changing, so the equivalent refusal logic lives below.
            assert_blobs_consistent(building, manifest)
            assert_matches_generation_lock(building, manifest)
            if not write_lock:
                assert_matches_baseline(building, repo, manifest)

            # STEP 3: at --write-lock, decide whether rewriting the demoted git
            # baseline is allowed (may refuse). Still before anything published.
            baseline = (
                prepare_baseline(repo, manifest, retire_baseline)
                if write_lock
                else None
            )

            # STEP 4: publish - ONE symlink flip, no rollback, no read-back.
            name = install_generation(building, generations, generations_fd, stamp)
            published = publish(
                out_dir,
                generations,
                generations_fd,
                name,
                current_before,
                previous_before,
            )

            # STEP 5: reconcile the DEMOTED git baseline, AFTER publication and
            # only at --write-lock. Publication is already committed; a failure
            # here is SUCCESS-with-a-warning, never a rollback - the git file is
            # a review artifact whose lag is visible in git.
            if baseline is not None:
                try:
                    write_baseline(repo, baseline)
                    note(
                        f"gen-fixtures: rewrote {fx.lock_path(repo, tier)} - commit it as a "
                        "reviewed diff"
                    )
                except (OSError, fx.LockError) as error:
                    note(
                        f"gen-fixtures: {published.name} is PUBLISHED and authoritative, "
                        f"but the git baseline {fx.lock_path(repo, tier)} could not be "
                        f"updated ({error}). The baseline now lags the published "
                        "workload; this is visible in git status and reconciled by "
                        "re-running with --write-lock. Nothing was rolled back.",
                        sys.stderr,
                    )
        except BaseException:
            # Catches EVERYTHING, including the SystemExit that fail() raises
            # and a KeyboardInterrupt: this is the unwinding path, and a
            # refusal or an error while cleaning up must never replace the
            # failure that caused the unwind.
            remove_build_directory(generations_fd, generations, building.name)
            raise
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
        # unwind_warning(), not note(): this runs while unwinding, and note()'s
        # /dev/null redirect would swallow the failure report that follows it.
        unwind_warning(
            f"gen-fixtures: WARNING - left {generations / name} in place: {refusal}"
        )


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
            marker_fd = os.open(
                fx.OUT_MARKER,
                os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=dir_fd,
            )
        except OSError:
            return (
                f"it carries no {fx.OUT_MARKER} marker, so this script cannot "
                "show it created it"
            )
        try:
            if not stat.S_ISREG(os.fstat(marker_fd).st_mode):
                return (
                    f"its {fx.OUT_MARKER} marker is not a regular file, so this "
                    "script cannot show it created the directory"
                )
        finally:
            os.close(marker_fd)
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
    problems = fx.blob_problems(built / "cache", manifest) + fx.wide_disk_problems(
        built / "cache", manifest
    )
    if problems:
        fail(
            "the tree just built does not match its own manifest, so it was "
            "discarded and the previous tree (if any) is untouched:\n  - "
            + "\n  - ".join(problems)
        )


def assert_matches_generation_lock(built: Path, manifest: dict) -> None:
    """The tree must match the AUTHORITATIVE lock just written inside it.

    Cheap and self-referential on a fresh build (the lock is derived from this
    manifest), but it is the check that GIVES the embedded lock its meaning: it
    is the same comparison the gate runs at runtime, so the thing the gate will
    later hold the served tree to is proven satisfiable at build time. Runs in
    both modes - it says nothing about the git baseline.
    """
    problems = fx.lock_problems(manifest, fx.load_generation_lock(built))
    if problems:
        fail(
            "the tree just built does not match its own authoritative lock.json, so "
            "it was discarded and nothing was published:\n  - "
            + "\n  - ".join(problems)
        )


def assert_matches_baseline(built: Path, repo: Path, manifest: dict) -> None:
    """FREEZE CHECK: a fresh build must match the git-tracked baseline.

    This is the one place a plain build reads the demoted git baseline, and it
    is read-only - the freeze gate that catches a flake.lock bump (new stdenv ->
    new store paths) while WORKLOAD_VERSION stands still. It decides whether to
    publish AT ALL; it is NOT the runtime consistency reconciliation that rounds
    2-7 kept breaking (that lived in publish() and is gone). Skipped under
    --write-lock, where the workload is deliberately changing and prepare_baseline
    owns the equivalent refusal.
    """
    tier = manifest["tier"]
    baseline = fx.load_baseline(repo, tier)
    problems = (
        fx.portable_lock_problems(manifest, baseline)
        if tier == fx.TIER_WIDE
        else fx.lock_problems(manifest, baseline)
    )
    if problems:
        baseline_path = fx.lock_path(repo, tier)
        remediation = (
            "bump fixtures/WIDE_WORKLOAD_VERSION, run `gen-fixtures.py --wide "
            "--write-lock`, and review fixtures/wide_closure.lock.json plus the "
            "dedicated wide fixture documentation"
            if tier == fx.TIER_WIDE
            else "bump fixtures/WORKLOAD_VERSION, run `gen-fixtures.py --large "
            "--write-lock`, update the TESTING.md fixture section, and mark the "
            "existing baseline retired wherever it is quoted"
        )
        fail(
            "the tree just built is NOT the workload recorded in the git baseline "
            f"{baseline_path}, so it was discarded and nothing was "
            "published:\n  - "
            + "\n  - ".join(problems)
            + "\n\nMost likely flake.lock or a fixture definition moved. If that "
            f"is intentional, {remediation}."
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
    # This warning is pre-flip, but success continues into publication. It must
    # therefore use the same poison-safe output as a post-commit diagnostic: a
    # failed flush here must not lurk in stderr until interpreter shutdown and
    # turn the later committed publication into exit 120.
    note(
        f"gen-fixtures: WARNING - {target} already exists and {reason}. A generation "
        "is immutable by contract, so it was NOT modified or deleted.\n"
        f"  The freshly built tree was published as {superseded} instead; the old "
        "directory is inert and a later run collects it.\n"
        f"  If you want the plain name back, remove {target} once nothing is using "
        "it and regenerate.",
        sys.stderr,
    )
    return superseded


def publish(
    out_dir: Path,
    generations: Path,
    generations_fd: int,
    name: str,
    predecessor: str | None,
    retained_previous: str | None,
) -> Path:
    """Publish a generation with ONE symlink flip. No rollback, no read-back.

    This is the round-8 redesign, and the whole point is what is ABSENT. The
    authoritative lock now lives INSIDE the generation (gen-<sha>/lock.json), so
    `current -> gen-<sha>` is the only thing that has to move, and that single
    os.replace atomically commits BOTH the tree and its lock. There is no second
    authoritative source to reconcile, so there is nothing to roll back and
    nothing to read back.

    Rounds 2-7 all failed HERE, each on machinery that reconciled the `current`
    symlink against the git-tracked lock to decide a rollback: a rollback fired
    on a failed print (r4/5), a read-back returned False on a read error and
    destroyed a good publish (r7), an interrupt split the two writes (r6/7). The
    fix is not a better reconciliation - it is deleting the second source. The
    git baseline is written, if at all, AFTER this returns, as a demoted review
    artifact whose lag is fine and visible in git.

    Crash consistency, by seam (there is no split to prevent):
      * before the flip           -> `current` is unchanged: OLD-complete.
      * mid os.replace            -> os.replace is atomic: OLD- or NEW-complete.
      * after the flip            -> `current` names the new generation, whose
                                     lock.json is inside it: NEW-complete.

    `previous` is made valid BEFORE the flip: it names the descriptor-validated
    outgoing `current` when one exists, otherwise a separately valid old
    `previous`, otherwise the installed new generation. Thus a malformed pair is
    repaired as one state transition and every successful publication is
    immediately operable by the strict collector. If the `current` flip never
    happens, `previous` may already name a valid retained/new generation; it is a
    collector hint, not a second publication commit.
    """
    stamp = f"{time.time_ns()}-{os.getpid()}"

    # Establish a valid collector anchor first. Prefer the outgoing publication,
    # then a separately valid old predecessor. On first publication or repair of
    # a wholly malformed pair, pointing previous at the installed new generation
    # means the later current flip leaves two valid links without any post-commit
    # resolution or repair step. Failure is still before the publication flip.
    previous_target = predecessor or retained_previous or name
    try:
        point_link_at(out_dir, fx.PREVIOUS_LINK, previous_target, f"{stamp}-prev")
    except OSError as error:
        fail(
            f"could not establish the previous retention anchor ({error}). "
            f"{out_dir / fx.CURRENT_LINK} is as it was, and the new generation is "
            f"on disk at {generations / name}.",
            code=2,
        )

    # THE publication: one flip. Failure here changes nothing (point_link_at
    # cleans up its own temporary), so this is a plain OSError -> exit 2 with no
    # rollback to attempt.
    try:
        point_link_at(out_dir, fx.CURRENT_LINK, name, f"{stamp}-publish")
    except OSError as error:
        fail(
            f"could not publish ({error}). {out_dir / fx.CURRENT_LINK} is as it was; "
            f"{out_dir / fx.PREVIOUS_LINK} already names the valid retained generation "
            f"{previous_target!r}, and the validated new generation is on disk at "
            f"{generations / name}.",
            code=2,
        )

    note(f"gen-fixtures: published {name}")

    # Published; from here nothing may turn this into a failure. In particular,
    # DO NOT re-read either retention link: malformed links were classified
    # before the flip, when refusal was still safe. The known new name plus the
    # precomputed predecessor are sufficient and cannot fail after commit.
    keep = {name, previous_target}
    report_collection_refusals(collect_generations(generations_fd, generations, keep))
    return generations / name


def point_link_at(out_dir: Path, link_name: str, name: str, stamp: str) -> None:
    """Make `<link_name>` name `generations/<name>` in one atomic step.

    A symlink cannot be retargeted in place, so a uniquely named one is created
    beside it and os.replace'd over it. os.replace on a symlink replaces the
    LINK, never what it points at, and is atomic - which is the whole reason the
    publication model is a flip: readers see the old generation or the new one,
    never a directory mid-rename and never a missing one.
    """
    link = out_dir / link_name
    temporary = out_dir / f".{link_name}.{stamp}"
    os.symlink(fx.generation_link_target(name), temporary)
    try:
        os.replace(temporary, link)
    except OSError:
        # Nothing collects the publication root itself (collect_generations only
        # scans generations/), so a leaked temporary would sit there forever
        # contradicting the caller's "nothing changed" message.
        with contextlib.suppress(OSError):
            os.unlink(temporary)
        raise


def collect_generations(
    generations_fd: int, generations: Path, keep: set[str]
) -> list[str]:
    """Delete marked superseded generations and return every refusal.

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
        return [f"{generations} (could not list directory: {error})"]
    for candidate in candidates:
        if candidate in keep:
            continue
        try:
            refusal = purge_marked_dir(generations_fd, generations, candidate)
        except Exception as error:  # noqa: BLE001 - post-commit, see docstring
            refusal = f"{error}"
        if refusal is not None:
            left.append(f"{generations / candidate} ({refusal})")
    return left


def report_collection_refusals(left: list[str]) -> None:
    """Report post-publication collection refusals without changing success."""
    if not left:
        return
    # SUCCESS with a warning, deliberately. The tree and the lock are both
    # committed (or a valid warm generation was reused); reporting failure
    # because superseded bytes remain would describe a state that did not happen.
    note(
        "gen-fixtures: WARNING - the fixture remains valid, but these superseded "
        "directories could not be removed:\n  - "
        + "\n  - ".join(left)
        + "\n  They are inert. A partial removal can strip the ownership marker; "
        "the collector will continue to refuse that remainder until an operator "
        "inspects it.",
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
MATERIAL_KEYS = (
    "store_path",
    "compression",
    "nar_hash",
    "file_hash",
    "tier",
    "nar_size",
    "file_size",
    "url",
    "references",
    "role",
    "cache_apparent_size",
)


def material(entry) -> dict:
    return {k: (entry or {}).get(k) for k in MATERIAL_KEYS}


def lock_dict_from_manifest(manifest: dict) -> dict:
    """The authoritative lock content, derived deterministically from a manifest.

    The SAME dict is written two places: `gen-<sha>/lock.json` inside every
    generation (authoritative, always), and - only at `--write-lock` - the
    git-tracked baseline. "The same content relocated", so the git file stays
    byte-identical to what it always was while the runtime source of truth moves
    inside the generation.
    """
    is_wide = manifest["tier"] == fx.TIER_WIDE
    lock = {
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
                **(
                    {
                        "nar_size": entry["nar_size"],
                        "file_size": entry["file_size"],
                        "url": entry["url"],
                        "references": entry["references"],
                        "role": entry["role"],
                        "cache_apparent_size": entry["cache_apparent_size"],
                        "cache_allocated_size": entry["cache_allocated_size"],
                    }
                    if is_wide
                    else {}
                ),
            }
            for entry in manifest["paths"]
        },
    }
    if is_wide:
        lock.update(
            {
                key: manifest[key]
                for key in (
                    "fixture_class",
                    "root_attr",
                    "cardinality",
                    "totals",
                    "budgets",
                    "disk_accounting",
                )
            }
        )
    return lock


def prepare_baseline(repo: Path, manifest: dict, retire_baseline: bool) -> dict:
    """Decide whether rewriting the DEMOTED git baseline is allowed, at
    `--write-lock` time only.

    Everything that can REFUSE lives here, and it runs BEFORE publication;
    write_baseline() only writes. The git baseline is no longer authoritative at
    runtime (the generation carries its own lock.json), but it remains the
    reviewable, version-controlled record of the frozen workload, so rebinding a
    version to different bytes still has to be a deliberate, flagged act.

    It catches the drift WORKLOAD_VERSION alone cannot: bumping flake.lock
    changes stdenv, hence every store path, while the version string sits still.
    Writing a new baseline under an unchanged version silently redefines what
    every recorded measurement was taken against, so it takes an explicit flag
    whose name says what it costs.
    """
    tier = manifest["tier"]
    lock_file = fx.lock_path(repo, tier)
    new = lock_dict_from_manifest(manifest)
    if lock_file.is_file():
        # Read through load_baseline, not json.loads: a baseline whose schema
        # this code does not understand must not be silently compared
        # field-by-field and then overwritten. LockError -> exit 2.
        old = fx.load_baseline(repo, tier)
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
        portable_old = fx.portable_fixture_document(old)
        portable_new = fx.portable_fixture_document(new)
        wide_metadata_changed = tier == fx.TIER_WIDE and any(
            portable_old.get(key) != portable_new.get(key)
            for key in (
                "fixture_class",
                "root_attr",
                "cardinality",
                "totals",
                "budgets",
                "disk_accounting",
            )
        )
        rebinding = (
            bool(changed)
            or old.get("public_key") != new["public_key"]
            or wide_metadata_changed
        )
        if same_version and rebinding and not retire_baseline:
            consequence = (
                "the frozen wide_closure class"
                if tier == fx.TIER_WIDE
                else "the J2 measurement baseline"
            )
            version_remediation = (
                "bump fixtures/WIDE_WORKLOAD_VERSION"
                if tier == fx.TIER_WIDE
                else "bump fixtures/WORKLOAD_VERSION"
            )
            fail(
                f"refusing to rebind workload version {new['workload_version']!r} to "
                f"different bytes (changed: {changed or ['metadata']}).\n"
                f"Doing so RETIRES {consequence} while leaving the "
                "version string that identifies it unchanged, so old and new numbers "
                "would look comparable and would not be.\n"
                f"Either {version_remediation} (the documented path), or pass "
                "--retire-baseline to say deliberately that every measurement recorded "
                "against this version is now void.",
                code=2,
            )
        if same_version and rebinding:
            # Success continues from here into publication. Buffering a plain
            # print against a poisoned stdout can defer ENOSPC/EPIPE until
            # interpreter shutdown, after `current` has committed, and lie with
            # exit 120. Use the success-path helper even though this is pre-flip.
            note(
                "gen-fixtures: WARNING - rebinding workload version "
                f"{new['workload_version']!r} (changed: {changed}); every measurement "
                "recorded against it is now RETIRED and must be marked so where it "
                "is quoted."
            )
    return new


def write_baseline(repo: Path, new: dict) -> None:
    """Write the DEMOTED git baseline. Runs AFTER publication, at `--write-lock`.

    Publication is already complete and authoritative before this is called -
    the generation and its embedded lock.json were committed by the symlink
    flip. This only updates the reviewable git record. If it fails, the caller
    reports SUCCESS-with-a-warning: the published tree is correct and
    self-describing; the git baseline merely lags, which is visible in `git
    status` and reconciled by re-running `--write-lock`. There is nothing to
    roll back, because this file is no longer authoritative.

    Atomic all the same: a baseline truncated by an interrupted run would leave
    a confusing half-written review artifact.
    """
    lock_file = fx.lock_path(repo, new["paths"][next(iter(new["paths"]))]["tier"])
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


def write_manifest(
    out_dir: Path, version: str, public_line: str, tier: str, entries
) -> dict:
    """Machine-readable description of what was generated.

    Consumers (the gate, task-9's measurement runs, task-5's containers) read
    this instead of globbing the cache. It describes the tree; it does not
    DEFINE it - the lock does. That distinction is load-bearing: a manifest
    that lists three payloads when the tier owes four is a red tree, not a
    smaller workload, and fixturelib.lock_problems() is where that is decided.
    """
    paths = [
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
    ]
    manifest = {
        "workload_version": version,
        "tier": tier,
        "public_key": public_line,
        "cache_info": {
            "StoreDir": fx.STORE_DIR,
            "WantMassQuery": CACHE_INFO_WANT_MASS_QUERY,
            "Priority": CACHE_INFO_PRIORITY,
        },
        "paths": paths,
    }
    if tier == fx.TIER_WIDE:
        cache = out_dir / "cache"

        # ext4/XFS may report delayed-allocation st_blocks until data is
        # flushed.  The allocated-byte budget is evidence, so sample it only
        # after every served regular file has reached stable backing blocks.
        for cache_file in sorted(cache.rglob("*")):
            if cache_file.is_file():
                with cache_file.open("rb") as handle:
                    os.fsync(handle.fileno())

        def disk_sizes(path: Path) -> tuple[int, int]:
            info = path.stat()
            return info.st_size, info.st_blocks * 512

        for entry in paths:
            entry["role"] = "root" if entry["attr"] == fx.WIDE_ROOT_ATTR else "member"
            narinfo_sizes = disk_sizes(narinfo_path(cache, entry["store_path"]))
            blob_sizes = disk_sizes(cache / entry["url"])
            entry["cache_apparent_size"] = narinfo_sizes[0] + blob_sizes[0]
            entry["cache_allocated_size"] = narinfo_sizes[1] + blob_sizes[1]
        cache_info_apparent, cache_info_allocated = disk_sizes(cache / "nix-cache-info")
        manifest.update(
            {
                "fixture_class": fx.FIXTURE_CLASS_WIDE,
                "root_attr": fx.WIDE_ROOT_ATTR,
                "cardinality": {
                    "member_count": len(paths) - 1,
                    "root_count": 1,
                    "closure_path_count": len(paths),
                },
                "budgets": dict(fx.WIDE_BUDGETS),
                "disk_accounting": {
                    "scope": "cache_regular_files_v1",
                    "block_unit_bytes": 512,
                    "nix_cache_info_apparent_size": cache_info_apparent,
                    "nix_cache_info_allocated_size": cache_info_allocated,
                },
                "totals": {
                    "nar_size": sum(entry["nar_size"] for entry in paths),
                    "file_size": sum(entry["file_size"] for entry in paths),
                    "cache_apparent_size": cache_info_apparent
                    + sum(entry["cache_apparent_size"] for entry in paths),
                    "cache_allocated_size": cache_info_allocated
                    + sum(entry["cache_allocated_size"] for entry in paths),
                },
            }
        )
        problems = fx.wide_contract_problems(manifest) + fx.wide_disk_problems(
            cache, manifest
        )
        if problems:
            fail(
                "wide fixture contract failed before publication:\n  - "
                + "\n  - ".join(problems)
            )
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="publication root: generations land in <dir>/generations and "
        "<dir>/current is flipped to the new one. Defaults to fixtures/out, "
        "or fixtures/out-wide with --wide",
    )
    parser.add_argument(
        "--large",
        action="store_true",
        help="also build the 110 MiB uncompressed payload (slow; kept out of "
        "`just test` and out of `nix flake check`)",
    )
    parser.add_argument(
        "--wide",
        action="store_true",
        help="build the independent 128-member wide_closure fixture family; "
        "publishes to fixtures/out-wide by default and never changes fixtures/out",
    )
    parser.add_argument(
        "--collect-only",
        action="store_true",
        help="collect unreferenced generations from the selected existing fixture "
        "root without building, publishing, repairing, or creating an absent root",
    )
    parser.add_argument(
        "--write-lock",
        action="store_true",
        help="rewrite the selected family's tracked baseline from what was just "
        "built. Do this only when that workload is meant to change; bump "
        "fixtures/WORKLOAD_VERSION for canonical changes or "
        "fixtures/WIDE_WORKLOAD_VERSION for wide changes in the same commit",
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
    if args.large and args.wide:
        fail("--large and --wide select different fixture families", code=2)
    if args.collect_only and (args.large or args.write_lock or args.retire_baseline):
        fail(
            "--collect-only may be combined only with --wide and/or --out; build "
            "tier, baseline-write, and retirement flags are meaningless for collection",
            code=2,
        )
    if args.write_lock and not (args.large or args.wide):
        fail(
            "--write-lock requires --large (canonical) or --wide: a partial "
            "canonical lock would pin nothing about its fourth payload.",
            code=2,
        )
    if args.retire_baseline and not args.write_lock:
        fail("--retire-baseline only means anything with --write-lock", code=2)
    # Tested BEFORE resolve(), which dereferences symlinks - checking the
    # resolved path would have been dead code. Publishing through a symlink
    # would replace it with a real directory and orphan whatever it pointed at.
    tier = fx.TIER_WIDE if args.wide else fx.TIER_FULL if args.large else fx.TIER_FAST
    out = args.out or (
        fx.repo_root() / "fixtures" / ("out-wide" if args.wide else "out")
    )
    if out.is_symlink():
        action = "collect" if args.collect_only else "publish"
        fail(f"--out {out} is a symlink; refusing to {action} through it", code=2)
    resolved_out = out.resolve()
    canonical_root = (fx.repo_root() / "fixtures" / "out").resolve()
    wide_root = (fx.repo_root() / "fixtures" / "out-wide").resolve()
    lexical_out = Path(os.path.abspath(out))

    def reaches_subtree(candidate: Path, root: Path) -> bool:
        return candidate == root or candidate.is_relative_to(root)

    reaches_canonical = reaches_subtree(lexical_out, canonical_root) or reaches_subtree(
        resolved_out, canonical_root
    )
    reaches_wide = reaches_subtree(lexical_out, wide_root) or reaches_subtree(
        resolved_out, wide_root
    )
    exact_canonical = lexical_out == canonical_root and resolved_out == canonical_root
    exact_wide = lexical_out == wide_root and resolved_out == wide_root
    if reaches_canonical and not (not args.wide and exact_canonical):
        message = (
            "--wide cannot publish into the reserved canonical fixtures/out"
            if args.wide and exact_canonical
            else "--wide cannot publish inside the reserved canonical fixtures/out "
            "subtree"
            if args.wide
            else "canonical fixtures may publish at reserved fixtures/out, not "
            "inside its subtree"
        )
        fail(message, code=2)
    if reaches_wide and not (args.wide and exact_wide):
        message = (
            "canonical fixtures cannot publish into reserved fixtures/out-wide"
            if not args.wide and exact_wide
            else "canonical fixtures cannot publish inside the reserved "
            "fixtures/out-wide subtree"
            if not args.wide
            else "wide fixtures may publish at reserved fixtures/out-wide, not "
            "inside its subtree"
        )
        fail(message, code=2)
    try:
        if args.collect_only:
            collect_only(resolved_out)
        else:
            generate(resolved_out, tier, args.write_lock, args.retire_baseline)
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
