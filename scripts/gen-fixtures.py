#!/usr/bin/env python3
"""Generate the signed binary-cache fixture the mock upstream serves.

Output is a plain Nix binary cache directory - `nix-cache-info`, one
`<hash>.narinfo` per path, and `nar/` blobs - so ANY static file server is a
sufficient mock upstream (`just fixtures-serve`, a container's httpd, or the
in-process server the gate uses). Nothing here knows about the daemon or the
testproxy; task-2's caching and fault-injection logic is not this file's
business.

Determinism (the point of the `irreversible` label on task-3): payload bytes
come from a seeded XOF, Nix canonicalises metadata on store entry, and the
compressors are the ones in the pinned `nix` from flake.lock. Scope that claim
honestly - what is verified is REPEATABILITY: back-to-back regeneration on one
machine with one flake.lock is byte-identical. Reproducibility across hosts and
across nixpkgs revisions is NOT verified and is not claimed;
fixtures/workload.lock.json is the instrument for that case, because it fails
loudly when the workload moves.

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
import json
import os
import shutil
import subprocess
import sys
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


def assert_locally_built(store_path: str) -> None:
    info = json.loads(nix("path-info", "--json", "--json-format", "1", store_path))
    entry = info[store_path]
    if entry["signatures"]:
        fail(
            f"{store_path} already carries signatures {entry['signatures']} - it was "
            "substituted, not built here. Copying it would put a foreign Sig line in "
            "the fixture and make the tamper bites pass for the wrong reason."
        )
    if not entry.get("ultimate"):
        fail(
            f"{store_path} is not marked ultimate (locally built). Refusing to sign a "
            "path whose provenance this script cannot vouch for."
        )


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


def build_into(
    staging: Path, repo: Path, secret_line: str, public_line: str, include_large: bool
):
    """Realise, sign and copy every planned payload into `staging`."""
    cache = staging / "cache"
    cache.mkdir(parents=True)

    secret_key = staging / "test-key.UNSAFE-TEST-ONLY.sec"
    secret_key.write_text(secret_line + "\n")
    secret_key.chmod(0o600)
    (staging / "test-key.pub").write_text(public_line + "\n")

    cache_info = write_cache_info(cache)

    plan = FAST_PLAN + (LARGE_PLAN if include_large else [])
    store_paths = {}
    for attr, compression in plan:
        store_paths[attr] = build_payload(repo, attr)
        assert_locally_built(store_paths[attr])
        copy_into_cache(cache, secret_key, store_paths[attr], compression)

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
    if include_large and manifest.get("tier") != "full":
        return False
    lock = json.loads(lock_path(repo).read_text())
    for entry in manifest.get("paths", []):
        pinned = lock["paths"].get(entry["attr"])
        if pinned is None:
            return False
        if any(
            pinned[k] != entry[k] for k in ("store_path", "compression", "nar_hash")
        ):
            return False
        # A manifest describing files that are gone is not a usable fixture.
        if not (out_dir / "cache" / entry["url"]).is_file():
            return False
    return True


def generate(out_dir: Path, include_large: bool, write_lock: bool = False) -> None:
    repo = fx.repo_root()
    _name, _private, secret_line, public_line = fx.keypair()
    version = read_workload_version(repo)

    # Checked against the committed lock, not against a constant living beside
    # the seed phrase: an external pin is the only kind a coordinated edit
    # cannot walk past. Skipped only while bootstrapping a new lock.
    lock_file = lock_path(repo)
    if not write_lock or lock_file.is_file():
        pinned = json.loads(lock_file.read_text())["public_key"]
        if public_line != pinned:
            fail(
                f"derived public key {public_line} != the key pinned in "
                f"{lock_file.name} ({pinned}). Every narinfo signed by the old key "
                "is now unverifiable against this one."
            )

    # Built in a private staging directory and published with a rename, never
    # written into out_dir in place. Two reasons, both observed: a run that
    # fails halfway would otherwise leave a wiped or half-written tree that
    # the gate then reports as a corrupt fixture, and a concurrent reader
    # (a second `just test`, a running `just fixtures-serve`) would see the
    # tree mid-rewrite - which surfaces as "signature is not valid" against a
    # perfectly good fixture. Regenerating from scratch rather than
    # incrementally is deliberate too: `nix copy` skips paths that are already
    # present, so a tree left from an older workload would keep its narinfos.
    if not write_lock and reusable(out_dir, repo, version, public_line, include_large):
        print(f"gen-fixtures: {version} already present at {out_dir} - reused")
        return

    staging = out_dir.parent / f".{out_dir.name}.staging.{os.getpid()}"
    if staging.exists():
        shutil.rmtree(staging)
    try:
        entries = build_into(staging, repo, secret_line, public_line, include_large)
        write_manifest(staging, version, public_line, include_large, entries)
        publish(staging, out_dir)
    finally:
        # A no-op on success (publish renamed it away); on any failure it
        # keeps a half-built tree from being mistaken for a fixture later.
        if staging.exists():
            shutil.rmtree(staging)
    if write_lock:
        update_lock(repo, version, public_line, entries)
    tier = "full" if include_large else "fast"
    print(f"gen-fixtures: {version} tier={tier} paths={len(entries)} -> {out_dir}")


def publish(staging: Path, out_dir: Path) -> None:
    """Swap the finished tree into place, then drop the old one.

    Not atomic in the POSIX sense - two directories cannot be exchanged in one
    call - but the window where `out_dir` does not exist is a rename rather
    than the length of a 110 MiB copy, and a reader never sees a partly
    written tree.
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


def lock_path(repo: Path) -> Path:
    return repo / "fixtures" / "workload.lock.json"


def update_lock(repo: Path, version: str, public_line: str, entries) -> None:
    """Rewrite the committed lock. Deliberate action, never automatic.

    The fixture tree is generated and gitignored, so without this file nothing
    in the repository records what `nix-p2p-fixture-workload-v1` actually
    denotes - and the frozen workload the J2 baseline is measured against
    would be unreviewable. It also catches the drift that WORKLOAD_VERSION
    alone cannot: bumping flake.lock changes stdenv, which changes every store
    path, which silently changes the workload while the version string stays
    put. Regenerating this file must therefore appear in a diff.
    """
    lock = {
        "workload_version": version,
        "public_key": public_line,
        "paths": {
            attr: {
                "store_path": store_path,
                "compression": compression,
                "nar_hash": fx.field(pairs, "NarHash"),
                "file_hash": fx.field(pairs, "FileHash"),
            }
            for attr, compression, store_path, pairs in entries
        },
    }
    lock_path(repo).write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n")
    print(f"gen-fixtures: rewrote {lock_path(repo)} - commit it as a reviewed diff")


def write_manifest(
    out_dir: Path, version: str, public_line: str, include_large: bool, entries
) -> None:
    """Machine-readable description of what was generated.

    Consumers (the gate, task-9's measurement runs, task-5's containers) read
    this instead of globbing the cache: the gate asserts exactly what the
    manifest declares, so a partially generated tree fails loudly rather than
    verifying a subset and reporting green.
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
    generate(args.out.resolve(), args.large, args.write_lock)
    return 0


if __name__ == "__main__":
    sys.exit(main())
