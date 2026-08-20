#!/usr/bin/env python3
"""Prove the fixture cache is trustworthy AND that its verification bites.

Runs the real `nix` CLI as the client against the fixture served over HTTP by
an in-process static server - no containers, so it belongs to the fast tier
(TESTING.md). The chain under test is Nix's own: `require-sigs` stays on and
`trusted-public-keys` holds exactly the test key, never a
`require-sigs = false` shortcut (explicitly forbidden by TESTING.md).

Why the real CLI rather than verifying signatures in-process with a Rust
crate: what needs proving is that a stock Nix client REJECTS a bad fixture,
not that some library agrees with our own fingerprint arithmetic. Re-deriving
the check would test this repository against itself. nix-compat was the
alternative and was rejected for that reason (it would also have added a
crate that the daemon must never share - PRD round 5).

The three bites are paired with a POSITIVE CONTROL: an untampered path must
copy successfully under the same options. Without it, a typo in the URL would
make all three rejections pass while proving nothing.

Bite 3 is the interesting one. Mutating NarHash alone only re-triggers the
signature check, so the fixture's own key is used to RE-SIGN the tampered
narinfo: the signature is then valid and Nix must still reject on the NAR's
actual content hash. That is the only version of the test that proves content
integrity rather than proving the signature check twice.

SCOPE - read before reusing any of this in the container or VM harness. What
is proven here is enforcement in Nix's DIRECT store mode: the CLI does the
verifying, and `--option trusted-public-keys` is a client-side setting. Under
a real `nix-daemon`, a non-trusted user's `trusted-public-keys` is IGNORED and
`require-sigs` is enforced daemon-side from /etc/nix/nix.conf. So
`nix_client_options()` below must NOT be copy-pasted into task-5's containers
or task-10's VM test; those must re-assert the three bites through the DAEMON
enforcement path, which this script structurally cannot reach. Same three
tampered inputs, different enforcement point - that is the comparison, not a
repeat.

Exit codes: 0 all assertions held, 1 an assertion failed, 2 the environment or
the fixture tree is missing and nothing was proven.
"""

from __future__ import annotations

import argparse
import copy
import contextlib
import fcntl
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import urllib.request
from pathlib import Path

import fixturelib as fx

# Bites target the path with a non-empty References field: it exercises the
# reference part of the signed fingerprint, which an empty-reference path
# cannot.
BITE_ATTR = "app"

# Independently stated here, NOT read from the manifest. The manifest and the
# served nix-cache-info are both written by gen-fixtures.py from one pair of
# constants, so comparing them to each other can only detect Nix rewriting the
# file - it can never catch a wrong Priority. A second witness with its own
# copy of the expected values is what gives this check any power. Changing the
# advertised values therefore has to be a deliberate edit in two files.
EXPECTED_CACHE_INFO = {"StoreDir": "/nix/store", "WantMassQuery": "1", "Priority": "40"}


def fail(message: str, code: int = 1) -> None:
    # Flushing first keeps the failure adjacent to the checks that preceded it;
    # stdout is block-buffered when piped and would otherwise arrive last.
    sys.stdout.flush()
    print(f"check-fixtures: FAIL - {message}", file=sys.stderr)
    raise SystemExit(code)


def ok(message: str) -> None:
    """Report a passing check without letting the report change the verdict.

    `check-fixtures | head` used to exit 120: the write raises EPIPE, the
    message stays buffered, and CPython exits 120 when its own flush at
    interpreter shutdown fails - a FAIL verdict for a pipe problem, on a run
    where every assertion held. Same defect that was just fixed in
    gen-fixtures' note(); this is its sibling. Redirecting the dead descriptor
    to /dev/null makes the shutdown flush succeed so the exit status reports
    the checks, not the pipe. fail() is deliberately NOT wrapped: a failure
    that cannot be printed must still exit non-zero.
    """
    try:
        print(f"check-fixtures: ok - {message}", flush=True)
    except (OSError, ValueError):
        with contextlib.suppress(Exception):
            devnull = os.open(os.devnull, os.O_WRONLY)
            try:
                os.dup2(devnull, sys.stdout.fileno())
            finally:
                os.close(devnull)


def pinned_nix() -> str:
    root = os.environ.get("NIX_P2P_NIX")
    if not root:
        fail("NIX_P2P_NIX not set - run inside: nix develop -c just test", code=2)
    binary = Path(root) / "bin" / "nix"
    if not binary.is_file():
        fail(f"NIX_P2P_NIX={root} has no bin/nix", code=2)
    return str(binary)


def published_generation(out_root: Path) -> Path:
    """Resolve `<out_root>/current`, or say why there is nothing to verify.

    `--out` names the publication ROOT, the same thing gen-fixtures' `--out`
    names, and the generation is reached through the `current` symlink. One
    meaning of `--out` across both scripts is deliberate: the alternative -
    this script pointing at a generation directly - is how a run ends up
    verifying a generation that is not the published one.
    """
    recipe = "just fixtures-wide" if out_root.name == "out-wide" else "just fixtures"
    if not out_root.is_dir():
        fail(
            f"no fixture publication root at {out_root} - generate it first:\n"
            f"  nix develop -c {recipe}",
            code=2,
        )
    generation = fx.resolve_current(out_root)
    if generation is None:
        fail(
            f"{out_root / fx.CURRENT_LINK} is missing, is not a symlink, or does not "
            f"point at a generation under {fx.GENERATIONS_DIR}/, so nothing "
            f"verifiable is published there. Regenerate with `{recipe}`.",
            code=2,
        )
    if not (generation / "manifest.json").is_file():
        fail(
            f"{out_root / fx.CURRENT_LINK} points at {generation}, which has no "
            "manifest.json. The publication root is corrupt; regenerate it.",
            code=2,
        )
    return generation


def load_manifest(generation: Path) -> dict:
    return json.loads((generation / "manifest.json").read_text())


def check_workload_version_documented(repo: Path, manifest: dict) -> None:
    """TESTING.md must name the version the fixture actually has.

    The measurement baseline is quoted against a workload version; a bumped
    fixture with a stale document would let two incomparable numbers be
    compared as if they were the same experiment.
    """
    version = manifest["workload_version"]
    # Delimited, not a plain substring: "...-workload-v1" occurs inside
    # "...-workload-v11", so a v1 fixture would otherwise pass against a
    # document that only describes v11.
    delimited = rf"(?<![\w.-]){re.escape(version)}(?![\w.-])"
    if not re.search(delimited, (repo / "TESTING.md").read_text()):
        version_source = (
            "fixtures/WIDE_WORKLOAD_VERSION"
            if manifest.get("tier") == fx.TIER_WIDE
            else "fixtures/WORKLOAD_VERSION"
        )
        fail(
            f"TESTING.md does not mention workload version {version!r}. "
            f"Bumping {version_source} means the recorded baseline no longer "
            "describes this workload."
        )
    ok(f"TESTING.md records workload version {version}")


def check_matches_lock(repo: Path, generation: Path, manifest: dict) -> None:
    """The served tree must match its OWN authoritative lock - metadata and bytes.

    The runtime source of truth is `current -> gen-<sha>/lock.json`, committed
    with the tree by the publish flip. This gate holds the served tree to that
    immutable lock: it catches any post-publish tampering of the manifest, the
    narinfos, the cache-info, or the NAR blobs. Detecting a flake.lock BASELINE
    drift is a separate, build-time concern (gen-fixtures' assert_matches_baseline
    reads the git baseline); the git file is not consulted here.

    Two things this deliberately does NOT do, both because they failed open in
    review. It does not accept a subset ("3 of 4 pinned payloads" used to be a
    printed note, so deleting a payload from manifest.json still exited 0); the
    tier's required set is checked for EQUALITY. And it does not stop at
    metadata: the NAR blobs are re-hashed, because a manifest and a lock agree
    perfectly about a file that has been deleted, which is how a missing
    110 MiB payload passed under --skip-determinism.
    """
    # The AUTHORITATIVE lock is INSIDE the generation, resolved via
    # current -> gen-<sha>/lock.json. The selected family's git-tracked baseline
    # is NOT read here - it is a demoted review artifact, and this gate has one
    # runtime source of truth (asserted by scripts/check-lock-sources.py).
    lock = fx.load_generation_lock(generation)
    cache = generation / "cache"
    problems = (
        fx.symlink_problems(generation)
        + fx.lock_problems(manifest, lock)
        + fx.completeness_problems(cache, manifest)
        + fx.blob_problems(cache, manifest)
        + fx.wide_disk_problems(cache, manifest)
    )
    if problems:
        repair_recipe = (
            "just fixtures-wide"
            if manifest.get("tier") == fx.TIER_WIDE
            else "just fixtures / just fixtures-large"
        )
        workload_change = (
            "run `gen-fixtures.py --wide --write-lock` and review "
            "the dedicated tracked wide baseline diff"
            if manifest.get("tier") == fx.TIER_WIDE
            else "bump fixtures/WORKLOAD_VERSION and run `gen-fixtures.py --large "
            "--write-lock`"
        )
        fail(
            "the served tree does NOT match its own authoritative "
            f"{generation / fx.GEN_LOCK_NAME}:\n  - "
            + "\n  - ".join(problems)
            + f"\n\nIf the tree is merely damaged, regenerate it "
            f"(`{repair_recipe}`): the generator checks the "
            "same things this does, so it will rebuild rather than reuse, and it "
            "publishes beside a damaged generation rather than refusing. If it "
            f"still reports 'reused', remove the generation and rerun: rm -rf "
            f"{generation}\nIf the pinned workload "
            f"itself is meant to change, {workload_change}."
        )
    tier = manifest["tier"]
    ok(
        f"is the pinned workload for tier={tier}: "
        f"{len(manifest['paths'])} payload(s), metadata and NAR bytes verified "
        f"against the generation's own {fx.GEN_LOCK_NAME}"
    )
    if tier == fx.TIER_FAST:
        # Not a failure - the fast tier is a legitimate thing to run - but said
        # as its own line rather than buried in an ok(), because the payloads
        # outside this tier were checked by NOTHING in this run.
        outside = sorted(set(lock["paths"]) - fx.expected_attrs(lock, tier))
        print(
            f"check-fixtures: PARTIAL - tier={tier} does not cover "
            + ", ".join(outside)
            + "; run `just fixtures-large` to gate the full workload",
            flush=True,
        )
    elif tier == fx.TIER_WIDE:
        ok(
            "wide_closure is isolated from the canonical four-path cache; this "
            "verdict makes no claim about the canonical full tier"
        )


def check_cache_info(base_url: str, manifest: dict) -> None:
    """AC#4: the served nix-cache-info carries explicit Priority/WantMassQuery."""
    try:
        with urllib.request.urlopen(f"{base_url}/nix-cache-info", timeout=10) as body:
            text = body.read().decode()
    except OSError as exc:
        fail(f"could not fetch nix-cache-info over HTTP: {exc}")
    # Strict: every non-blank line must parse, and a repeated key is a
    # conflict rather than a last-one-wins. Dropping unparseable lines let junk
    # appended to the served file pass unnoticed, which is the same
    # unrecognised-input-widens shape fixed elsewhere in this round - and it is
    # inconsistent with fx.parse_narinfo, which raises on a malformed line.
    served = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        key, separator, value = line.partition(": ")
        if not separator:
            fail(f"served nix-cache-info has a malformed line: {line!r}")
        if key in served:
            fail(f"served nix-cache-info repeats the key {key!r}")
        served[key] = value
    if served != EXPECTED_CACHE_INFO:
        fail(
            f"served nix-cache-info is {served}, expected exactly "
            f"{EXPECTED_CACHE_INFO}. These values are stated independently in "
            "this file precisely so a wrong Priority cannot agree with itself."
        )
    # Weaker than the check above and kept anyway: it catches a manifest that
    # disagrees with the file it claims to describe, which downstream consumers
    # read instead of the file.
    #
    # Compared as a WHOLE, against the expected keys - not by iterating the
    # manifest's own keys. Iterating what was supplied made the check's strength
    # a function of its input: `"cache_info": {}` iterated nothing and passed,
    # so a manifest that described no cache-info at all was indistinguishable
    # from a correct one. Same fail-open species as an unknown tier excusing a
    # payload; the fix is that the EXPECTATION drives the comparison.
    declared = {k: str(v) for k, v in (manifest.get("cache_info") or {}).items()}
    if declared != EXPECTED_CACHE_INFO:
        fail(
            f"manifest cache_info is {declared}, expected exactly "
            f"{EXPECTED_CACHE_INFO}. Consumers read the manifest instead of the "
            "served file, so a manifest that omits or renames a field describes a "
            "cache that is not the one being served."
        )
    ok(f"nix-cache-info served with explicit {served}")


def nix_client_options(public_line: str) -> list[str]:
    """The harness client's Nix options - one definition, used by every check."""
    return [
        # `--option` REPLACES the default (which contains cache.nixos.org-1);
        # `--extra-...` would have appended to it and left the real cache key
        # trusted, so a foreign-signed narinfo could have passed.
        "--option",
        "trusted-public-keys",
        public_line,
        "--option",
        "require-sigs",
        "true",
        # Nix caches narinfos in binary-cache-v6.sqlite for 30 days. Each
        # invocation also gets a private XDG_CACHE_HOME, but zeroing the TTLs
        # too means a tampered narinfo can never be answered from a cached
        # pristine one (TESTING.md oracle-pairing rule).
        "--option",
        "narinfo-cache-positive-ttl",
        "0",
        "--option",
        "narinfo-cache-negative-ttl",
        "0",
    ]


def check_trusted_keys_exactly_test_key(public_line: str) -> None:
    """AC#2: the harness trusts the test key and nothing else."""
    result = subprocess.run(
        [
            pinned_nix(),
            "--extra-experimental-features",
            "nix-command",
            "config",
            "show",
            "trusted-public-keys",
            *nix_client_options(public_line),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        fail(f"`nix config show` failed: {result.stderr.strip()}")
    keys = result.stdout.split()
    if keys != [public_line]:
        fail(f"harness trusts {keys}, expected exactly [{public_line}]")
    ok(f"client trusted-public-keys is exactly [{public_line}]")


def copy_to_store(
    base_url: str,
    store_path: str,
    public_line: str,
    destination: Path,
    xdg_cache: Path,
):
    env = dict(os.environ, XDG_CACHE_HOME=str(xdg_cache))
    return subprocess.run(
        [
            pinned_nix(),
            "--extra-experimental-features",
            "nix-command",
            "copy",
            "--from",
            base_url,
            "--to",
            str(destination),
            *nix_client_options(public_line),
            store_path,
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


def copy_from_fixture(base_url: str, store_path: str, public_line: str):
    """Copy one path from the served fixture into a throwaway chroot store."""
    with tempfile.TemporaryDirectory(prefix="nix-p2p-client-") as tmp:
        root = Path(tmp)
        return copy_to_store(
            base_url, store_path, public_line, root / "store", root / "cache"
        )


def expect_accept(base_url: str, store_path: str, public_line: str, what: str) -> None:
    result = copy_from_fixture(base_url, store_path, public_line)
    if result.returncode != 0:
        fail(f"POSITIVE CONTROL failed ({what}): {result.stderr.strip()}")
    ok(f"positive control - {what}")


def expect_reject(
    base_url: str, store_path: str, public_line: str, what: str, needle: str
) -> None:
    result = copy_from_fixture(base_url, store_path, public_line)
    if result.returncode == 0:
        fail(f"BITE DID NOT BITE ({what}): nix accepted a tampered narinfo")
    if needle not in result.stderr:
        fail(
            f"{what}: nix rejected, but not for the expected reason.\n"
            f"expected to see {needle!r} in:\n{result.stderr.strip()}"
        )
    ok(f"bite - {what} (nix: {needle!r})")


def minimal_cache(src_cache: Path, dst_cache: Path, manifest: dict, attrs) -> None:
    """Copy just the files needed to serve `attrs`, so tampering stays cheap.

    Copying the whole tree would mean duplicating the 110 MiB payload once per
    bite for no benefit.
    """
    dst_cache.mkdir(parents=True)
    by_attr = {entry["attr"]: entry for entry in manifest["paths"]}
    wanted = ["nix-cache-info"]
    for attr in attrs:
        entry = by_attr[attr]
        wanted.append(f"{Path(entry['store_path']).name.split('-')[0]}.narinfo")
        wanted.append(entry["url"])
    for relative in wanted:
        source = src_cache / relative
        if not source.is_file():
            # An incomplete cache would make the tamper bites reject for a
            # missing file rather than for the tampering - the classic
            # passes-for-the-wrong-reason failure.
            fail(
                f"fixture is incomplete: {source} is listed in manifest.json but "
                "absent. Regenerate with "
                + (
                    "`just fixtures-wide`."
                    if manifest.get("tier") == fx.TIER_WIDE
                    else "`just fixtures` / `just fixtures-large`."
                )
            )
        destination = dst_cache / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def narinfo_file(cache: Path, entry: dict) -> Path:
    return cache / f"{Path(entry['store_path']).name.split('-')[0]}.narinfo"


def store_path_info(destination: Path, recursive: bool, store_path: str):
    result = subprocess.run(
        [
            pinned_nix(),
            "--extra-experimental-features",
            "nix-command",
            "path-info",
            "--store",
            str(destination),
            *(["--recursive"] if recursive else []),
            "--json",
            "--json-format",
            "1",
            store_path,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return None, result.stderr.strip()
    try:
        return json.loads(result.stdout), None
    except ValueError as error:
        return None, f"path-info returned invalid JSON: {error}"


def wide_copy_problems(
    base_url: str,
    records: list[tuple[str, str, int]],
    destination: Path,
    xdg_cache: Path,
    manifest: dict,
    public_line: str,
):
    """Copy only the wide root, then judge fanout from destination-store truth."""
    problems = []
    if destination.exists():
        problems.append("destination store was not cold before the root copy")
    by_attr = {entry["attr"]: entry for entry in manifest["paths"]}
    root = by_attr[fx.WIDE_ROOT_ATTR]
    members = [entry for entry in manifest["paths"] if entry["role"] == "member"]
    expected_paths = {entry["store_path"] for entry in manifest["paths"]}
    result = copy_to_store(
        base_url,
        root["store_path"],
        public_line,
        destination,
        xdg_cache,
    )
    if result.returncode != 0:
        problems.append(f"root copy failed: {result.stderr.strip()}")
        return result, problems

    recursive, error = store_path_info(destination, True, root["store_path"])
    if error is not None:
        problems.append(f"cannot query copied wide closure: {error}")
    elif set(recursive) != expected_paths:
        problems.append(
            f"copied wide closure differs from all {len(expected_paths)} pinned paths: "
            f"missing={sorted(expected_paths - set(recursive))}, "
            f"extra={sorted(set(recursive) - expected_paths)}"
        )
    direct, error = store_path_info(destination, False, root["store_path"])
    if error is not None:
        problems.append(f"cannot query copied wide root: {error}")
    else:
        root_info = direct.get(root["store_path"], {})
        expected_members = {entry["store_path"] for entry in members}
        references = set(root_info.get("references", []))
        if references != expected_members:
            problems.append(
                "copied root direct fanout differs: "
                f"missing={sorted(expected_members - references)}, "
                f"extra={sorted(references - expected_members)}"
            )

    successful_gets = {
        path for method, path, status in records if method == "GET" and status == 200
    }
    expected_nars = {f"/{entry['url']}" for entry in manifest["paths"]}
    missing_nars = sorted(expected_nars - successful_gets)
    if missing_nars:
        problems.append(
            f"cold root substitution did not request {len(missing_nars)} NAR(s): "
            f"{missing_nars}"
        )
    return result, problems


def check_reserved_publication_root_isolation(repo: Path) -> None:
    """Wrong-family commands must refuse before touching either publication."""
    canonical_root = repo / "fixtures" / "out"
    wide_root = repo / "fixtures" / "out-wide"
    current_links = [
        canonical_root / fx.CURRENT_LINK,
        wide_root / fx.CURRENT_LINK,
    ]

    def link_snapshot(link: Path):
        if not os.path.lexists(link):
            return ("absent",)
        info = link.lstat()
        if link.is_symlink():
            return (
                "symlink",
                os.readlink(link),
                info.st_dev,
                info.st_ino,
                info.st_mode,
                info.st_size,
                info.st_mtime_ns,
            )
        return (
            "other",
            info.st_dev,
            info.st_ino,
            info.st_mode,
            info.st_size,
            info.st_mtime_ns,
        )

    generator = Path(__file__).resolve().parent / "gen-fixtures.py"
    canonical_descendant = canonical_root / ".fixture-root-isolation-bite"
    wide_descendant = wide_root / ".fixture-root-isolation-bite"
    canonical_current_descendant = (
        canonical_root / fx.CURRENT_LINK / ".fixture-root-isolation-bite"
    )
    wide_current_descendant = (
        wide_root / fx.CURRENT_LINK / ".fixture-root-isolation-bite"
    )
    probes = {
        canonical_descendant,
        wide_descendant,
        canonical_current_descendant,
        wide_current_descendant,
    }
    occupied = sorted(str(path) for path in probes if os.path.lexists(path))
    if occupied:
        fail(
            "reserved-root control needs absent descendant probes, but these exist: "
            f"{occupied}"
        )
    cases = [
        (
            ["--wide", "--out", str(canonical_root)],
            "--wide cannot publish into the reserved canonical fixtures/out",
        ),
        (
            ["--out", str(wide_root)],
            "canonical fixtures cannot publish into reserved fixtures/out-wide",
        ),
        (
            ["--wide", "--out", str(canonical_descendant)],
            "--wide cannot publish inside the reserved canonical fixtures/out subtree",
        ),
        (
            ["--out", str(canonical_descendant)],
            "canonical fixtures may publish at reserved fixtures/out, not inside its "
            "subtree",
        ),
        (
            ["--out", str(wide_descendant)],
            "canonical fixtures cannot publish inside the reserved "
            "fixtures/out-wide subtree",
        ),
        (
            ["--wide", "--out", str(wide_descendant)],
            "wide fixtures may publish at reserved fixtures/out-wide, not inside its "
            "subtree",
        ),
        (
            ["--wide", "--out", str(canonical_current_descendant)],
            "--wide cannot publish inside the reserved canonical fixtures/out subtree",
        ),
        (
            ["--out", str(wide_current_descendant)],
            "canonical fixtures cannot publish inside the reserved "
            "fixtures/out-wide subtree",
        ),
    ]
    for arguments, expected_message in cases:
        before = {str(link): link_snapshot(link) for link in current_links}
        result = subprocess.run(
            [sys.executable, str(generator), *arguments],
            capture_output=True,
            text=True,
            check=False,
        )
        expected_stderr = f"gen-fixtures: FAIL - {expected_message}"
        if result.returncode != 2 or result.stderr.strip() != expected_stderr:
            fail(
                "reserved-root control failed for "
                f"{arguments}: expected exit 2 and {expected_stderr!r}, got exit "
                f"{result.returncode}, stdout={result.stdout!r}, stderr={result.stderr!r}"
            )
        after = {str(link): link_snapshot(link) for link in current_links}
        if after != before:
            fail(
                "BITE DID NOT BITE (reserved fixture root): wrong-family command "
                f"changed a current link; before={before}, after={after}"
            )
        created = sorted(str(path) for path in probes if os.path.lexists(path))
        if created:
            fail(
                "BITE DID NOT BITE (reserved fixture subtree): rejected command "
                f"created descendant probe(s) {created}"
            )
    ok("bite - wrong-family generators refuse both reserved roots before publication")


def check_collect_only_controls(repo: Path) -> None:
    """Prove reclaim uses the generator's locked, confined deletion path."""
    generator = repo / "scripts" / "gen-fixtures.py"

    def mark(directory: Path) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        (directory / fx.OUT_MARKER).write_text("fixture collector control\n")

    def publication(
        root: Path,
        *,
        current: str = "gen-current",
        previous: str | None = "gen-previous",
        stale: tuple[str, ...] = (),
    ) -> Path:
        mark(root)
        generations = root / fx.GENERATIONS_DIR
        generations.mkdir()
        names = {current, *stale}
        if previous is not None:
            names.add(previous)
        for name in names:
            mark(generations / name)
        (root / fx.CURRENT_LINK).symlink_to(fx.generation_link_target(current))
        if previous is not None:
            (root / fx.PREVIOUS_LINK).symlink_to(fx.generation_link_target(previous))
        return generations

    def run_collect(root: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(generator),
                "--collect-only",
                "--out",
                str(root),
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    def require_refusal(
        result: subprocess.CompletedProcess[str],
        needle: str,
        survivors: tuple[Path, ...],
    ) -> None:
        if result.returncode != 2 or needle not in result.stderr:
            fail(
                "collector refusal control failed: expected exit 2 containing "
                f"{needle!r}, got exit {result.returncode}, stdout={result.stdout!r}, "
                f"stderr={result.stderr!r}"
            )
        missing = [str(path) for path in survivors if not os.path.lexists(path)]
        if missing:
            fail(
                "BITE DID NOT BITE (collector refusal): refusing malformed/foreign "
                f"input deleted sentinel(s) {missing}"
            )

    with tempfile.TemporaryDirectory(prefix="nix-p2p-collector-bites-") as tmp:
        scratch = Path(tmp)

        absent = scratch / "absent"
        absent_lock = absent.parent / f".{absent.name}.publish.lock"
        result = run_collect(absent)
        if result.returncode != 0 or absent.exists() or absent_lock.exists():
            fail(
                "BITE DID NOT BITE (absent collector root): expected a no-op with "
                f"no root or lock creation, got exit {result.returncode}, "
                f"root={absent.exists()}, lock={absent_lock.exists()}, "
                f"stderr={result.stderr!r}"
            )

        retained_root = scratch / "retained"
        retained_generations = publication(retained_root, stale=("gen-stale",))
        result = run_collect(retained_root)
        if result.returncode != 0:
            fail(
                "collector retention positive control failed: "
                f"exit {result.returncode}, stderr={result.stderr!r}"
            )
        if not all(
            (retained_generations / name).is_dir()
            for name in ("gen-current", "gen-previous")
        ) or os.path.lexists(retained_generations / "gen-stale"):
            fail(
                "BITE DID NOT BITE (collector retention): current+previous were not "
                "both retained or the marked stale generation was not removed"
            )

        unmarked_root = scratch / "unmarked"
        unmarked_generations = publication(unmarked_root)
        unmarked = unmarked_generations / "gen-unmarked"
        unmarked.mkdir()
        result = run_collect(unmarked_root)
        require_refusal(
            result,
            f"carries no {fx.OUT_MARKER} marker",
            (unmarked, unmarked_generations / "gen-current"),
        )

        foreign_root = scratch / "foreign"
        foreign_generations = foreign_root / fx.GENERATIONS_DIR
        foreign_generations.mkdir(parents=True)
        foreign_sentinel = foreign_generations / "gen-sentinel"
        mark(foreign_sentinel)
        result = run_collect(foreign_root)
        require_refusal(
            result,
            f"has no plain {fx.OUT_MARKER} ownership marker",
            (foreign_sentinel,),
        )

        external_generations = scratch / "external-generations"
        external_sentinel = external_generations / "gen-sentinel"
        mark(external_sentinel)
        generations_link_root = scratch / "generations-link"
        mark(generations_link_root)
        (generations_link_root / fx.GENERATIONS_DIR).symlink_to(
            external_generations, target_is_directory=True
        )
        (generations_link_root / fx.CURRENT_LINK).symlink_to(
            fx.generation_link_target("gen-sentinel")
        )
        result = run_collect(generations_link_root)
        require_refusal(
            result,
            "refusing collection",
            (external_sentinel,),
        )

        external_root = scratch / "external-root"
        external_root_generations = publication(
            external_root, previous=None, stale=("gen-sentinel",)
        )
        root_link = scratch / "root-link"
        root_link.symlink_to(external_root, target_is_directory=True)
        result = run_collect(root_link)
        require_refusal(
            result,
            "is a symlink; refusing to collect through it",
            (external_root_generations / "gen-sentinel",),
        )

        malformed_root = scratch / "malformed-current"
        mark(malformed_root)
        malformed_generations = malformed_root / fx.GENERATIONS_DIR
        malformed_generations.mkdir()
        malformed_sentinel = malformed_generations / "gen-sentinel"
        mark(malformed_sentinel)
        (malformed_root / fx.CURRENT_LINK).symlink_to("../../outside")
        result = run_collect(malformed_root)
        require_refusal(
            result,
            "malformed or unconfined target",
            (malformed_sentinel,),
        )

        missing_current_root = scratch / "missing-current"
        mark(missing_current_root)
        missing_current_generations = missing_current_root / fx.GENERATIONS_DIR
        missing_current_generations.mkdir()
        missing_current_sentinel = missing_current_generations / "gen-sentinel"
        mark(missing_current_sentinel)
        result = run_collect(missing_current_root)
        require_refusal(
            result,
            "has no current publication link",
            (missing_current_sentinel,),
        )

        lock_root = scratch / "locked"
        lock_generations = publication(lock_root, stale=("gen-stale",))
        spec = importlib.util.spec_from_file_location(
            "nix_p2p_fixture_collector_control", generator
        )
        if spec is None or spec.loader is None:
            fail(f"could not import collector implementation from {generator}")
        collector = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(collector)
        expected_lock = lock_root.parent / f".{lock_root.name}.publish.lock"
        lock_checks = []

        def require_lock_held(stage: str) -> None:
            descriptor = os.open(expected_lock, os.O_RDWR | os.O_CLOEXEC)
            try:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    lock_checks.append(stage)
                else:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                    fail(
                        "BITE DID NOT BITE (collector serialization): the shared "
                        f"publication lock was free during {stage}"
                    )
            finally:
                os.close(descriptor)

        original_retained = collector.retained_generation_at
        original_collect = collector.collect_generations

        def retained_spy(*args, **kwargs):
            require_lock_held("retention resolution")
            return original_retained(*args, **kwargs)

        def collect_spy(*args, **kwargs):
            require_lock_held("generation collection")
            return original_collect(*args, **kwargs)

        collector.retained_generation_at = retained_spy
        collector.collect_generations = collect_spy
        collector.collect_only(lock_root)
        if (
            lock_checks.count("retention resolution") != 2
            or lock_checks.count("generation collection") != 1
        ):
            fail(
                "collector lock control did not observe both retention-link reads and "
                f"collection under the shared lock: {lock_checks}"
            )
        if os.path.lexists(lock_generations / "gen-stale"):
            fail("collector lock positive control did not remove its stale generation")

    ok(
        "collector shares publication locking, retains current+previous, and refuses "
        "absent-anchor, unowned, malformed, or symlink-redirected roots"
    )


def check_generator_repair_controls(repo: Path) -> None:
    """Prove generator retention stays tolerant and cannot fail after its flip."""
    generator_path = repo / "scripts" / "gen-fixtures.py"
    spec = importlib.util.spec_from_file_location(
        "nix_p2p_fixture_generator_repair_control", generator_path
    )
    if spec is None or spec.loader is None:
        fail(f"could not import generator implementation from {generator_path}")
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)

    def mark(directory: Path) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        (directory / fx.OUT_MARKER).write_text("fixture generator repair control\n")

    def fake_build(building: Path, *_args) -> list:
        mark(building)
        return []

    def fake_manifest(
        building: Path,
        version: str,
        public_line: str,
        tier: str,
        _entries: list,
    ) -> dict:
        manifest = {
            "workload_version": version,
            "public_key": public_line,
            "tier": tier,
            "paths": [],
        }
        (building / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        )
        return manifest

    generator.read_workload_version = lambda _repo, _tier: "repair-control-v1"
    generator.reusable = lambda *_args: False
    generator.build_into = fake_build
    generator.write_manifest = fake_manifest
    generator.lock_dict_from_manifest = lambda _manifest: {}
    generator.assert_blobs_consistent = lambda *_args: None
    generator.assert_matches_generation_lock = lambda *_args: None
    generator.assert_matches_baseline = lambda *_args: None

    original_keypair = generator.fx.keypair
    generator.fx.keypair = lambda: ("control", None, "secret", "public")
    try:
        with tempfile.TemporaryDirectory(
            prefix="nix-p2p-generator-repair-bites-"
        ) as tmp:
            scratch = Path(tmp)
            for case, target in (
                ("malformed", "../../outside"),
                ("dangling", fx.generation_link_target("gen-missing")),
            ):
                root = scratch / case
                mark(root)
                (root / fx.GENERATIONS_DIR).mkdir()
                (root / fx.CURRENT_LINK).symlink_to(target)
                try:
                    generator.generate(root, fx.TIER_FAST)
                except BaseException as error:  # noqa: BLE001 - bite captures fail()
                    fail(
                        f"BITE DID NOT BITE (generator repairs {case} current): "
                        f"generation refused instead of publishing over it: {error}"
                    )
                published = fx.resolve_current(root)
                if published is None or not (published / fx.OUT_MARKER).is_file():
                    fail(
                        f"BITE DID NOT BITE (generator repairs {case} current): "
                        f"no owned generation was published at {root}"
                    )

            both_invalid_root = scratch / "both-invalid"
            mark(both_invalid_root)
            both_invalid_generations = both_invalid_root / fx.GENERATIONS_DIR
            both_invalid_generations.mkdir()
            (both_invalid_root / fx.CURRENT_LINK).symlink_to("../../bad-current")
            (both_invalid_root / fx.PREVIOUS_LINK).symlink_to("../../bad-previous")
            try:
                generator.generate(both_invalid_root, fx.TIER_FAST)
            except BaseException as error:  # noqa: BLE001 - bite captures fail()
                fail(
                    "BITE DID NOT BITE (generator repairs both retention links): "
                    f"generation refused malformed current+previous: {error}"
                )
            published = fx.resolve_current(both_invalid_root)
            retained = fx.resolve_previous(both_invalid_root)
            if published is None or retained != published:
                fail(
                    "BITE DID NOT BITE (generator repairs both retention links): "
                    f"current={published}, previous={retained}"
                )
            post_repair_stale = both_invalid_generations / "gen-post-repair-stale"
            mark(post_repair_stale)
            try:
                generator.collect_only(both_invalid_root)
            except BaseException as error:  # noqa: BLE001 - bite captures fail()
                fail(
                    "BITE DID NOT BITE (strict collector after pair repair): "
                    f"collector refused the generated state: {error}"
                )
            if os.path.lexists(post_repair_stale):
                fail(
                    "BITE DID NOT BITE (strict collector after pair repair): marked "
                    "stale generation was not collected"
                )

            warm_root = scratch / "warm-malformed-previous"
            mark(warm_root)
            warm_generations = warm_root / fx.GENERATIONS_DIR
            warm_generations.mkdir()
            warm_current = warm_generations / "gen-warm-current"
            mark(warm_current)
            (warm_root / fx.CURRENT_LINK).symlink_to(
                fx.generation_link_target(warm_current.name)
            )
            (warm_root / fx.PREVIOUS_LINK).symlink_to("../../bad-previous")
            warm_stale = warm_generations / "gen-warm-stale"
            mark(warm_stale)

            original_reusable = generator.reusable
            original_build_into = generator.build_into

            def forbid_warm_rebuild(*_args):
                raise AssertionError("warm-reuse repair unexpectedly rebuilt fixtures")

            generator.reusable = lambda *_args: True
            generator.build_into = forbid_warm_rebuild
            try:
                generator.generate(warm_root, fx.TIER_FAST)
            except BaseException as error:  # noqa: BLE001 - bite captures fail()
                fail(
                    "BITE DID NOT BITE (warm reuse repairs malformed previous): "
                    f"real reusable path failed or rebuilt instead of repairing: {error}"
                )
            finally:
                generator.reusable = original_reusable
                generator.build_into = original_build_into

            published = fx.resolve_current(warm_root)
            retained = fx.resolve_previous(warm_root)
            if published != warm_current or retained != warm_current:
                fail(
                    "BITE DID NOT BITE (warm reuse repairs malformed previous): "
                    f"current={published}, previous={retained}, expected={warm_current}"
                )
            if os.path.lexists(warm_stale):
                fail(
                    "BITE DID NOT BITE (warm reuse repairs malformed previous): "
                    "warm-path collection left a marked stale generation"
                )

            strict_stale = warm_generations / "gen-strict-after-warm-repair"
            mark(strict_stale)
            try:
                generator.collect_only(warm_root)
            except BaseException as error:  # noqa: BLE001 - bite captures fail()
                fail(
                    "BITE DID NOT BITE (strict collector after warm repair): "
                    f"collector refused the reused state: {error}"
                )
            if os.path.lexists(strict_stale):
                fail(
                    "BITE DID NOT BITE (strict collector after warm repair): marked "
                    "stale generation was not collected"
                )

            previous_root = scratch / "malformed-previous"
            mark(previous_root)
            previous_generations = previous_root / fx.GENERATIONS_DIR
            previous_generations.mkdir()
            old = previous_generations / "gen-old"
            mark(old)
            (previous_root / fx.CURRENT_LINK).symlink_to(
                fx.generation_link_target(old.name)
            )
            (previous_root / fx.PREVIOUS_LINK).symlink_to("../../malformed")

            original_resolver = generator.retained_generation_at
            original_point_link = generator.point_link_at
            current_flipped = False

            def resolver_spy(*args, **kwargs):
                if current_flipped:
                    raise AssertionError(
                        "retention link was re-read after current committed"
                    )
                return original_resolver(*args, **kwargs)

            def point_link_spy(*args, **kwargs):
                nonlocal current_flipped
                result = original_point_link(*args, **kwargs)
                if args[1] == fx.CURRENT_LINK:
                    current_flipped = True
                return result

            generator.retained_generation_at = resolver_spy
            generator.point_link_at = point_link_spy
            try:
                generator.generate(previous_root, fx.TIER_FAST)
            except BaseException as error:  # noqa: BLE001 - bite captures fail()
                fail(
                    "BITE DID NOT BITE (post-commit retention): malformed previous "
                    f"or a post-flip resolver turned committed publication into failure: {error}"
                )
            if not current_flipped:
                fail("post-commit retention control never observed the current flip")
            published = fx.resolve_current(previous_root)
            retained = fx.resolve_previous(previous_root)
            if published is None or published == old or retained != old:
                fail(
                    "BITE DID NOT BITE (post-commit retention): publication/retention "
                    f"state is current={published}, previous={retained}, old={old}"
                )
    finally:
        generator.fx.keypair = original_keypair

    ok(
        "generator repairs malformed/dangling current, repairs a fully malformed "
        "retention pair, repairs malformed previous on real warm reuse for strict "
        "collection, and never re-reads anchors after flip"
    )


def check_post_commit_output_control(repo: Path) -> None:
    """A poisoned warning stream must not falsify a committed publication."""
    child = textwrap.dedent(
        """
        import importlib.util
        import json
        import sys
        from pathlib import Path

        repo = Path(sys.argv[1])
        out = Path(sys.argv[2])
        attempted = Path(sys.argv[3])
        generator_path = repo / "scripts" / "gen-fixtures.py"
        sys.path.insert(0, str(generator_path.parent))
        spec = importlib.util.spec_from_file_location(
            "nix_p2p_post_commit_output_child", generator_path
        )
        if spec is None or spec.loader is None:
            raise RuntimeError(f"cannot import {generator_path}")
        generator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(generator)

        def mark(directory):
            directory.mkdir(parents=True, exist_ok=True)
            (directory / generator.fx.OUT_MARKER).write_text(
                "post-commit output control\\n"
            )

        def fake_build(building, *_args):
            mark(building)
            return []

        def fake_manifest(building, version, public_line, tier, _entries):
            manifest = {
                "workload_version": version,
                "public_key": public_line,
                "tier": tier,
                "paths": [],
            }
            (building / "manifest.json").write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\\n"
            )
            return manifest

        generator.fx.keypair = lambda: ("control", None, "secret", "public")
        generator.read_workload_version = (
            lambda _repo, _tier: "post-commit-output-control-v1"
        )
        generator.build_into = fake_build
        generator.write_manifest = fake_manifest
        generator.lock_dict_from_manifest = lambda manifest: {
            "workload_version": manifest["workload_version"],
            "public_key": manifest["public_key"],
            "paths": {},
        }
        generator.assert_blobs_consistent = lambda *_args: None
        generator.assert_matches_generation_lock = lambda *_args: None
        generator.prepare_baseline = lambda *_args: {"injected": "baseline-lag"}

        def injected_write_failure(*_args):
            attempted.write_text("baseline write attempted\\n")
            raise OSError("injected baseline write failure")

        generator.write_baseline = injected_write_failure
        generator.generate(out, generator.fx.TIER_FAST, write_lock=True)
        """
    )

    with tempfile.TemporaryDirectory(prefix="nix-p2p-post-commit-output-bite-") as tmp:
        scratch = Path(tmp)
        out = scratch / "out"
        baseline_path = scratch / "review-baseline.json"
        baseline_path.write_text(
            json.dumps({"workload_version": "older-reviewed-v1"}) + "\n"
        )
        baseline_before = baseline_path.read_bytes()
        attempted = scratch / "baseline-write-attempted"
        with Path("/dev/full").open("wb", buffering=0) as poisoned_stderr:
            result = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    child,
                    str(repo),
                    str(out),
                    str(attempted),
                ],
                stdout=subprocess.PIPE,
                stderr=poisoned_stderr,
                text=True,
                check=False,
                timeout=20,
            )
        generation = fx.resolve_current(out)
        if result.returncode != 0:
            fail(
                "BITE DID NOT BITE (post-commit output poison): baseline-write "
                "failure plus stderr=/dev/full changed committed publication to "
                f"exit {result.returncode}; stdout={result.stdout!r}"
            )
        if generation is None:
            fail(
                "BITE DID NOT BITE (post-commit output poison): child exited 0 but "
                "published no current generation"
            )
        manifest = json.loads((generation / "manifest.json").read_text())
        authoritative_lock = json.loads((generation / fx.GEN_LOCK_NAME).read_text())
        if (
            manifest.get("workload_version") != "post-commit-output-control-v1"
            or authoritative_lock.get("workload_version")
            != manifest["workload_version"]
            or not (generation / fx.OUT_MARKER).is_file()
        ):
            fail(
                "BITE DID NOT BITE (post-commit output poison): current does not "
                "contain the fake publication and its authoritative lock"
            )
        if not attempted.is_file():
            fail("post-commit output bite never attempted the injected baseline write")
        if baseline_path.read_bytes() != baseline_before:
            fail(
                "BITE DID NOT BITE (post-commit output poison): injected failed write "
                f"changed the lagging review baseline {baseline_path}"
            )
        baseline_version = json.loads(baseline_before)["workload_version"]
        if baseline_version == "post-commit-output-control-v1":
            fail(
                "post-commit output bite setup did not create an observable baseline lag"
            )
    ok(
        "baseline-write failure with stderr=/dev/full exits 0 after publication; "
        "current stays authoritative and the review baseline visibly lags"
    )


def check_reclaim_direct_execution_control(repo: Path) -> None:
    """Unset pinned Python skips fixture GC without aborting later reclaim work."""
    reclaim = repo / "scripts" / "reclaim.sh"
    with tempfile.TemporaryDirectory(prefix="nix-p2p-reclaim-direct-bite-") as tmp:
        scratch = Path(tmp)
        fake_bin = scratch / "bin"
        fake_bin.mkdir()
        calls = scratch / "calls.log"
        fake_tool = (
            "#!/usr/bin/env bash\n"
            'printf \'%s\' "$0" >> "${RECLAIM_CONTROL_LOG}"\n'
            'printf \' %s\' "$@" >> "${RECLAIM_CONTROL_LOG}"\n'
            "printf '\\n' >> \"${RECLAIM_CONTROL_LOG}\"\n"
        )
        for name in ("podman", "git", "rm"):
            tool = fake_bin / name
            tool.write_text(fake_tool)
            tool.chmod(0o755)

        later_target = scratch / "later-cargo-target"
        (later_target / "debug").mkdir(parents=True)
        env = os.environ.copy()
        env.pop("NIX_P2P_PYTHON", None)
        env.pop("NIX_P2P_NIX", None)
        env.update(
            {
                "PATH": f"{fake_bin}:{env['PATH']}",
                "CARGO_TARGET_DIR": str(later_target),
                "RECLAIM_CONTROL_LOG": str(calls),
            }
        )
        result = subprocess.run(
            [str(reclaim)],
            cwd=repo,
            env=env,
            capture_output=True,
            text=True,
            check=False,
            timeout=20,
        )
        if result.returncode != 0 or "unbound variable" in result.stderr:
            fail(
                "BITE DID NOT BITE (direct reclaim without devshell): expected a "
                f"complete run, got exit {result.returncode}, stdout={result.stdout!r}, "
                f"stderr={result.stderr!r}"
            )
        for label in ("canonical", "wide"):
            expected = (
                f"reclaim: {label} fixture collection skipped: NIX_P2P_PYTHON is unset"
            )
            if result.stderr.count(expected) != 1:
                fail(
                    "direct reclaim did not emit exactly one contextual missing-Python "
                    f"message for {label}: stderr={result.stderr!r}"
                )
        resolved_target = later_target.resolve()
        # reclaim.sh stage 4 now prunes STALE cargo artifacts with cargo-sweep
        # (keeping the current dep cache) instead of `rm -rf <target>`, so this
        # oracle no longer looks for a wipe. Its JOB is unchanged: prove the
        # skipped fixture stage did NOT abort reclaim, so the LATER cargo stage is
        # still REACHED. Accept any stage-4 marker (a sweep, or a documented skip),
        # and bite only if NONE appear (== the run aborted before stage 4). The
        # sweep line goes to stdout; the skip variants go to stderr.
        reached_markers = (
            f"sweeping cargo target {later_target}",
            f"sweeping cargo target {resolved_target}",
            "is not a cargo target dir, skipping cargo cleanup",
            "cargo-sweep not on PATH",
        )
        if not any(m in result.stdout or m in result.stderr for m in reached_markers):
            fail(
                "BITE DID NOT BITE (direct reclaim continuation): unset pinned Python "
                "prevented the later cargo-sweep cleanup stage; "
                f"stdout={result.stdout!r} stderr={result.stderr!r}"
            )
    ok(
        "direct reclaim with pinned Python unset reports both skipped collectors and "
        "continues through the later cargo cleanup stage"
    )


def run_wide_closure_controls(
    generation: Path, manifest: dict, public_line: str
) -> None:
    """Positive cold-store oracle plus two controls proving it can fail."""
    cache = generation / "cache"
    by_attr = {entry["attr"]: entry for entry in manifest["paths"]}
    root_entry = by_attr[fx.WIDE_ROOT_ATTR]
    member_entries = sorted(
        (entry for entry in manifest["paths"] if entry["role"] == "member"),
        key=lambda entry: entry["attr"],
    )

    check_reserved_publication_root_isolation(fx.repo_root())

    # Schema mutation: stripping the wide class metadata must not turn these
    # tier=wide pins into a canonical lock whose fast/full required sets ignore
    # them. Canonical locks accept only canonical tiers.
    wide_lock = fx.load_generation_lock(generation)
    clean_contract_problems = fx.wide_contract_problems(manifest)
    if clean_contract_problems:
        fail(
            "wide budget bite setup is not a clean production-oracle control: "
            f"{clean_contract_problems}"
        )
    clean_portable_problems = fx.portable_lock_problems(manifest, wide_lock)
    if clean_portable_problems:
        fail(
            "portable wide-lock bite setup is not a clean production-oracle "
            f"control: {clean_portable_problems}"
        )

    first_entry = next(
        entry for entry in manifest["paths"] if entry["role"] == "member"
    )
    below_nar_minimum = copy.deepcopy(manifest)
    nar_total = fx.WIDE_BUDGETS["total_nar_size_min"] - 1
    nar_delta = below_nar_minimum["totals"]["nar_size"] - nar_total
    mutated_nar_entry = next(
        entry
        for entry in below_nar_minimum["paths"]
        if entry["attr"] == first_entry["attr"]
    )
    if nar_delta <= 0 or mutated_nar_entry["nar_size"] < nar_delta:
        fail(
            "NarSize budget bite setup cannot isolate the lower bound: "
            f"delta={nar_delta}, entry={mutated_nar_entry['nar_size']}"
        )
    mutated_nar_entry["nar_size"] -= nar_delta
    below_nar_minimum["totals"]["nar_size"] = nar_total
    nar_problems = fx.wide_contract_problems(below_nar_minimum)
    expected_nar_problem = (
        f"wide total NarSize {nar_total} is outside the frozen budget"
    )
    if nar_problems != [expected_nar_problem]:
        fail(
            "BITE DID NOT BITE (wide NarSize minimum): expected only "
            f"{expected_nar_problem!r}, got {nar_problems}"
        )
    ok("bite - isolated NarSize minimum mutation fails the production oracle")

    above_apparent_maximum = copy.deepcopy(manifest)
    apparent_total = fx.WIDE_BUDGETS["cache_apparent_size_max"] + 1
    apparent_delta = (
        apparent_total - above_apparent_maximum["totals"]["cache_apparent_size"]
    )
    mutated_apparent_entry = next(
        entry
        for entry in above_apparent_maximum["paths"]
        if entry["attr"] == first_entry["attr"]
    )
    mutated_apparent_entry["cache_apparent_size"] += apparent_delta
    above_apparent_maximum["totals"]["cache_apparent_size"] = apparent_total
    apparent_problems = fx.wide_contract_problems(above_apparent_maximum)
    expected_apparent_problem = (
        f"wide cache_apparent_size {apparent_total} exceeds cache_apparent_size_max"
    )
    if apparent_problems != [expected_apparent_problem]:
        fail(
            "BITE DID NOT BITE (wide apparent-size maximum): expected only "
            f"{expected_apparent_problem!r}, got {apparent_problems}"
        )
    ok("bite - isolated apparent-size maximum mutation fails the production oracle")

    inconsistent_allocated_lock = copy.deepcopy(wide_lock)
    inconsistent_allocated_lock["totals"]["cache_allocated_size"] += 1
    inconsistent_allocated_problems = fx.portable_lock_problems(
        manifest, inconsistent_allocated_lock
    )
    if (
        len(inconsistent_allocated_problems) != 1
        or "wide totals are" not in (inconsistent_allocated_problems[0])
    ):
        fail(
            "BITE DID NOT BITE (wide allocated total consistency): portable "
            "comparison masked an inconsistent local observation; "
            f"problems={inconsistent_allocated_problems}"
        )
    ok(
        "bite - portable comparison rejects inconsistent allocated totals before masking"
    )

    above_allocated_maximum = copy.deepcopy(wide_lock)
    allocated_total = fx.WIDE_BUDGETS["cache_allocated_size_max"] + 1
    allocated_delta = (
        allocated_total - above_allocated_maximum["totals"]["cache_allocated_size"]
    )
    first_locked_entry = above_allocated_maximum["paths"][first_entry["attr"]]
    first_locked_entry["cache_allocated_size"] += allocated_delta
    above_allocated_maximum["totals"]["cache_allocated_size"] = allocated_total
    allocated_problems = fx.portable_lock_problems(manifest, above_allocated_maximum)
    expected_allocated_problem = (
        f"wide cache_allocated_size {allocated_total} exceeds cache_allocated_size_max"
    )
    if (
        len(allocated_problems) != 1
        or expected_allocated_problem not in (allocated_problems[0])
    ):
        fail(
            "BITE DID NOT BITE (wide allocated-size maximum): portable comparison "
            f"masked the local budget violation; problems={allocated_problems}"
        )
    ok("bite - portable comparison rejects allocated-size overflow before masking")

    disguised_canonical = {
        "workload_version": wide_lock["workload_version"],
        "public_key": wide_lock["public_key"],
        "paths": {
            attr: {key: copy.deepcopy(pinned[key]) for key in fx.LOCK_PAYLOAD_KEYS}
            for attr, pinned in wide_lock["paths"].items()
        },
    }
    try:
        fx.validate_lock(disguised_canonical, "wide-disguised-as-canonical mutation")
    except fx.LockError as error:
        if "canonical lock payload" not in str(
            error
        ) or "declares tier 'wide'" not in str(error):
            fail(
                "wide-tier canonical-lock mutation failed for the wrong reason: "
                f"{error}"
            )
    else:
        fail(
            "BITE DID NOT BITE (wide tier in canonical lock): schema accepted "
            "pinned paths that fast/full would never require"
        )
    ok("bite - canonical lock rejects every tier=wide payload")

    # Semantic mutation: make a self-consistent 127-member/128-path document.
    # The nominal v1 attr oracle will also complain, but the specific budget
    # needle proves wide_contract_problems still wires in the independent >=128
    # member bound without mutating module state.
    undersized = copy.deepcopy(manifest)
    removed_entry = next(
        entry
        for entry in undersized["paths"]
        if entry["attr"] == f"{fx.WIDE_MEMBER_PREFIX}127"
    )
    undersized["paths"].remove(removed_entry)
    undersized_root = next(
        entry for entry in undersized["paths"] if entry["role"] == "root"
    )
    undersized_root["references"].remove(Path(removed_entry["store_path"]).name)
    undersized["cardinality"] = {
        "member_count": 127,
        "root_count": 1,
        "closure_path_count": 128,
    }
    for key in (
        "nar_size",
        "file_size",
        "cache_apparent_size",
        "cache_allocated_size",
    ):
        undersized["totals"][key] -= removed_entry[key]
    undersized_problems = fx.wide_contract_problems(undersized)
    if not any("member count 127" in problem for problem in undersized_problems):
        fail(
            "BITE DID NOT BITE (127-member wide closure): independent member-count "
            f"budget did not reject it; problems={undersized_problems}"
        )
    ok("bite - self-consistent 127-member closure fails independent member budget")

    # Disk-scope mutation uses a tiny synthetic cache, not a 256 MiB copy. The
    # clean precondition and dirty trial both call production wide_disk_problems,
    # so removing its exact-file-set wiring makes this bite fail rather than
    # leaving a helper-only test green.
    with tempfile.TemporaryDirectory(prefix="nix-p2p-wide-disk-bite-") as tmp:
        tiny_cache = Path(tmp) / "cache"
        (tiny_cache / "nar").mkdir(parents=True)
        cache_info = tiny_cache / "nix-cache-info"
        narinfo = tiny_cache / "00000000000000000000000000000000.narinfo"
        blob = tiny_cache / "nar" / "tiny.nar"
        cache_info.write_bytes(b"StoreDir: /nix/store\n")
        narinfo.write_bytes(b"tiny narinfo\n")
        blob.write_bytes(b"tiny nar\n")
        for path in (cache_info, narinfo, blob):
            with path.open("rb") as handle:
                os.fsync(handle.fileno())

        def disk_sizes(path: Path) -> tuple[int, int]:
            info = path.stat()
            return info.st_size, info.st_blocks * 512

        info_apparent, info_allocated = disk_sizes(cache_info)
        narinfo_apparent, narinfo_allocated = disk_sizes(narinfo)
        blob_apparent, blob_allocated = disk_sizes(blob)
        tiny_manifest = {
            "fixture_class": fx.FIXTURE_CLASS_WIDE,
            "paths": [
                {
                    "attr": "tiny",
                    "store_path": "/nix/store/00000000000000000000000000000000-tiny",
                    "url": "nar/tiny.nar",
                    "cache_apparent_size": narinfo_apparent + blob_apparent,
                    "cache_allocated_size": narinfo_allocated + blob_allocated,
                }
            ],
            "disk_accounting": {
                "nix_cache_info_apparent_size": info_apparent,
                "nix_cache_info_allocated_size": info_allocated,
            },
            "totals": {
                "cache_apparent_size": (
                    info_apparent + narinfo_apparent + blob_apparent
                ),
                "cache_allocated_size": (
                    info_allocated + narinfo_allocated + blob_allocated
                ),
            },
        }
        clean_disk_problems = fx.wide_disk_problems(tiny_cache, tiny_manifest)
        if clean_disk_problems:
            fail(
                "disk-scope bite setup is not a clean production-oracle control: "
                f"{clean_disk_problems}"
            )
        (tiny_cache / "nar" / "unexpected-junk").write_bytes(b"junk")
        disk_problems = fx.wide_disk_problems(tiny_cache, tiny_manifest)
    if not any("unexpected regular files" in problem for problem in disk_problems):
        fail(
            "BITE DID NOT BITE (unaccounted cache file): exact regular-file-set "
            f"oracle accepted junk; problems={disk_problems}"
        )
    ok("bite - unaccounted regular cache file fails disk-scope oracle")

    with tempfile.TemporaryDirectory(prefix="nix-p2p-wide-cold-") as tmp:
        scratch = Path(tmp)
        with fx.recording_static_server(cache) as (base_url, records):
            check_cache_info(base_url, manifest)
            result, problems = wide_copy_problems(
                base_url,
                records,
                scratch / "store",
                scratch / "xdg",
                manifest,
                public_line,
            )
        if result.returncode != 0 or problems:
            fail(
                "wide cold-store positive control failed:\n  - "
                + "\n  - ".join(problems)
            )
    ok(
        "wide cold root copy requested and realised every one of "
        f"{len(manifest['paths'])} closure paths"
    )

    # Mutation 1: remove one direct root reference and re-sign. The root NAR
    # bytes remain valid, so Nix can import the deliberately shrunken closure;
    # only the fanout/request oracle should reject it.
    pairs = fx.parse_narinfo(narinfo_file(cache, root_entry).read_text())
    references = fx.field(pairs, "References").split()
    removed = references[0]
    pairs = fx.replace_field(pairs, "References", " ".join(references[1:]))
    _name, private, _secret, _public = fx.keypair()
    mutated = fx.format_narinfo(fx.sign_narinfo(pairs, private, fx.KEY_NAME)).encode()
    override_path = f"/{fx.narinfo_name(root_entry['store_path'])}"
    with tempfile.TemporaryDirectory(prefix="nix-p2p-wide-fanout-bite-") as tmp:
        scratch = Path(tmp)
        with fx.recording_static_server(cache, {override_path: mutated}) as (
            base_url,
            records,
        ):
            result, problems = wide_copy_problems(
                base_url,
                records,
                scratch / "store",
                scratch / "xdg",
                manifest,
                public_line,
            )
        if result.returncode != 0:
            fail(
                "removed-fanout control was rejected by Nix before the closure "
                f"oracle could judge it: {result.stderr.strip()}"
            )
        if not problems or not any(removed in problem for problem in problems):
            fail(
                "BITE DID NOT BITE (removed root fanout): the oracle did not name "
                f"the omitted member {removed!r}; problems={problems}"
            )
    ok("bite - re-signed root with one removed fanout fails closure/request oracle")

    # Mutation 2: warm one member in the destination, then request only root.
    # Nix legitimately skips that NAR; the coldness and request-set assertions
    # must make the supposedly cold trial red.
    pre_realised = member_entries[0]
    with tempfile.TemporaryDirectory(prefix="nix-p2p-wide-warm-bite-") as tmp:
        scratch = Path(tmp)
        destination = scratch / "store"
        with fx.static_server(cache) as base_url:
            warm = copy_to_store(
                base_url,
                pre_realised["store_path"],
                public_line,
                destination,
                scratch / "warm-xdg",
            )
        if warm.returncode != 0:
            fail(f"pre-realisation setup failed: {warm.stderr.strip()}")
        with fx.recording_static_server(cache) as (base_url, records):
            result, problems = wide_copy_problems(
                base_url,
                records,
                destination,
                scratch / "cold-xdg",
                manifest,
                public_line,
            )
        missing_url = f"/{pre_realised['url']}"
        if result.returncode != 0:
            fail(f"pre-realised control root copy unexpectedly failed: {result.stderr}")
        if not any("not cold" in problem for problem in problems) or not any(
            missing_url in problem for problem in problems
        ):
            fail(
                "BITE DID NOT BITE (pre-realised member): coldness/request oracle "
                f"did not reject {pre_realised['attr']}; problems={problems}"
            )
    ok("bite - pre-realised member makes the cold-store request oracle fail")


def run_bites(generation: Path, manifest: dict, public_line: str) -> None:
    src_cache = generation / "cache"
    by_attr = {entry["attr"]: entry for entry in manifest["paths"]}
    if manifest["tier"] == fx.TIER_WIDE:
        run_wide_closure_controls(generation, manifest, public_line)
        bite_attr = f"{fx.WIDE_MEMBER_PREFIX}000"
    else:
        bite_attr = BITE_ATTR
    target = by_attr[bite_attr]
    # `app` references `lib`; the closure must be servable or the bite would
    # fail on a missing dependency instead of on the tampering. A reference
    # the manifest does not describe is asserted rather than quietly dropped:
    # silently serving an incomplete closure is how a bite starts rejecting
    # for the wrong reason.
    known = {Path(e["store_path"]).name: attr for attr, e in by_attr.items()}
    unknown = sorted(set(target["references"]) - set(known))
    if unknown:
        fail(
            f"payload {bite_attr!r} references paths the manifest does not "
            f"describe: {unknown}. The bites would run against an incomplete cache."
        )
    needed = [bite_attr] + [known[r] for r in target["references"]]

    with tempfile.TemporaryDirectory(prefix="nix-p2p-bites-") as tmp:
        root = Path(tmp)

        # The positive control covers EVERY payload in the tier, not just the
        # bite target. Importing only app+lib left zstd decompression and the
        # 110 MiB NAR never once handled by a real client: a corrupt zstd frame
        # or an unreadable large blob would have sailed through every check
        # here while breaking the first scenario that actually used them.
        if manifest["tier"] != fx.TIER_WIDE:
            pristine = root / "pristine"
            minimal_cache(src_cache, pristine, manifest, sorted(by_attr))
            with fx.static_server(pristine) as base_url:
                check_cache_info(base_url, manifest)
                for attr in sorted(by_attr):
                    entry = by_attr[attr]
                    expect_accept(
                        base_url,
                        entry["store_path"],
                        public_line,
                        f"{attr} ({entry['compression']}, {entry['file_size']} B on the "
                        "wire) imports with only the test key trusted",
                    )

        # Bite 1: the signature bytes are corrupted.
        corrupt = root / "corrupt-sig"
        minimal_cache(src_cache, corrupt, manifest, needed)
        path = narinfo_file(corrupt, target)
        pairs = fx.parse_narinfo(path.read_text())
        name, _, b64 = fx.field(pairs, "Sig").partition(":")
        flipped = ("B" if b64[0] != "B" else "C") + b64[1:]
        path.write_text(
            fx.format_narinfo(fx.replace_field(pairs, "Sig", f"{name}:{flipped}"))
        )
        with fx.static_server(corrupt) as base_url:
            expect_reject(
                base_url,
                target["store_path"],
                public_line,
                "corrupted Sig",
                "lacks a signature by a trusted key",
            )

        # Bite 2: a well-formed signature from a key the client does not trust
        # - a hostile mirror that signs its own tampering.
        foreign = root / "foreign-key"
        minimal_cache(src_cache, foreign, manifest, needed)
        path = narinfo_file(foreign, target)
        _n, foreign_private, _s, _p = fx.keypair(
            fx.FOREIGN_SEED_PHRASE, fx.FOREIGN_KEY_NAME
        )
        pairs = fx.parse_narinfo(path.read_text())
        path.write_text(
            fx.format_narinfo(
                fx.sign_narinfo(pairs, foreign_private, fx.FOREIGN_KEY_NAME)
            )
        )
        with fx.static_server(foreign) as base_url:
            expect_reject(
                base_url,
                target["store_path"],
                public_line,
                "valid signature by an untrusted key",
                "lacks a signature by a trusted key",
            )

        # Bite 3: NarHash mutated AND re-signed with the trusted test key, so
        # the signature check passes and only content verification can catch
        # it. Reaching a hash error is itself proof the signature was valid.
        tampered = root / "tampered-narhash"
        minimal_cache(src_cache, tampered, manifest, needed)
        path = narinfo_file(tampered, target)
        pairs = fx.parse_narinfo(path.read_text())
        _n, private, _s, _p = fx.keypair()
        alg, _, digest = fx.field(pairs, "NarHash").partition(":")
        # Mutating a middle character keeps the value a well-formed 52-char
        # nix-base32 digest; the leading character encodes only the top bits
        # and is not freely choosable.
        chars = list(digest)
        chars[25] = "z" if chars[25] != "z" else "y"
        pairs = fx.replace_field(pairs, "NarHash", f"{alg}:{''.join(chars)}")
        path.write_text(fx.format_narinfo(fx.sign_narinfo(pairs, private, fx.KEY_NAME)))
        with fx.static_server(tampered) as base_url:
            expect_reject(
                base_url,
                target["store_path"],
                public_line,
                "NarHash mutated and re-signed by the trusted key",
                "hash mismatch importing path",
            )


def check_determinism(generation: Path, manifest: dict) -> None:
    """Regenerating yields the same portable fixture identity.

    Be exact about what this earns, because the obvious reading is wrong.
    Regeneration re-EXPORTS store paths that are already realised: `nix build`
    finds them in the store and returns them without building anything. So
    what is proven is that EXPORT is repeatable - NAR serialisation,
    compression, signing and manifest writing - on one host with one
    flake.lock, minutes apart. It says nothing about whether the DERIVATIONS
    build deterministically: a payload that produced different bytes on every
    build would be realised once and then pass this check forever.

    Build determinism is a separate question with a separate check,
    `just fixtures-verify-rebuild` or `just fixtures-wide-verify-rebuild`
    (nix build --rebuild, which rebuilds and compares against the realised
    output). It is slow, so it is not in the
    fast loop - and it is a REQUIRED step before the J2 baseline is recorded,
    noted on task-9 and task-12.

    Neither check proves reproducibility across machines or nixpkgs revisions.
    The wide family records local st_blocks evidence in each generation; that
    one filesystem-dependent field is budget-checked independently on both
    trees and excluded from portable equality. Every content/hash/reference,
    apparent-size and metadata field remains exact.
    """
    with tempfile.TemporaryDirectory(prefix="nix-p2p-determinism-") as tmp:
        replica_root = Path(tmp) / "out"
        cmd = [
            sys.executable,
            str(Path(__file__).resolve().parent / "gen-fixtures.py"),
            "--out",
            str(replica_root),
        ]
        if manifest["tier"] == fx.TIER_FULL:
            cmd.append("--large")
        elif manifest["tier"] == fx.TIER_WIDE:
            cmd.append("--wide")
        # `--out` points at an empty scratch root, so the reuse shortcut in
        # gen-fixtures cannot fire and this always regenerates for real.
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            fail(f"regeneration failed:\n{result.stderr.strip()}")
        replica = fx.resolve_current(replica_root)
        if replica is None:
            fail(f"regeneration published nothing at {replica_root}", code=2)

        def repeatability_digest(tree: Path) -> dict[str, str]:
            digest = fx.tree_digest(tree)
            if manifest["tier"] != fx.TIER_WIDE:
                return digest
            for name in ("manifest.json", fx.GEN_LOCK_NAME):
                document = fx.portable_fixture_document(
                    json.loads((tree / name).read_text())
                )
                portable_bytes = json.dumps(
                    document, sort_keys=True, separators=(",", ":")
                ).encode()
                _content, separator, metadata = digest[name].partition(" mode=")
                digest[name] = (
                    "portable-json:"
                    + hashlib.sha256(portable_bytes).hexdigest()
                    + separator
                    + metadata
                )
            return digest

        original, regenerated = (
            repeatability_digest(generation),
            repeatability_digest(replica),
        )
        if original != regenerated:
            differing = sorted(
                set(original) ^ set(regenerated)
                | {
                    k
                    for k in set(original) & set(regenerated)
                    if original[k] != regenerated[k]
                }
            )
            fail(
                "regeneration is NOT byte-stable; differing entries: "
                + ", ".join(differing)
                + "\nThe workload is not reproducible, so no measurement taken "
                "against it can be compared across waves."
            )
    if manifest["tier"] == fx.TIER_WIDE:
        ok(
            f"PORTABLE EXPORT identity repeatable across {len(original)} files "
            "(tier=wide): every portable byte/field is exact; each tree's local "
            "allocated-byte observation was independently verified and bounded. "
            "Build determinism is NOT covered here - see "
            "`just fixtures-wide-verify-rebuild`"
        )
    else:
        ok(
            f"EXPORT repeatable across {len(original)} files (tier={manifest['tier']}): "
            "re-serialising, recompressing and re-signing already-realised store "
            "paths is byte-identical. Build determinism is NOT covered here - see "
            "`just fixtures-verify-rebuild`"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="fixture publication root; the generation under <dir>/current is "
        "what gets verified. Defaults to fixtures/out-wide when requiring wide, "
        "otherwise fixtures/out",
    )
    parser.add_argument(
        "--skip-determinism",
        action="store_true",
        help="skip the regenerate-and-diff check. The verdict then prints "
        "PARTIAL: blob presence and hashes are still verified (that check is "
        "not optional), but repeatability is not",
    )
    parser.add_argument(
        "--require-tier",
        choices=fx.TIERS,
        help="fail unless the tree satisfies this tier. `just fixtures-large` "
        "selects full; `just fixtures-wide` selects the independent wide family",
    )
    args = parser.parse_args()

    repo = fx.repo_root()
    out_root = (
        args.out
        or repo
        / "fixtures"
        / ("out-wide" if args.require_tier == fx.TIER_WIDE else "out")
    ).resolve()

    generation = published_generation(out_root)
    manifest = load_manifest(generation)
    tier = manifest.get("tier")
    # Checked before anything indexes on it. An unrecognised tier reaching the
    # rank comparison below would be a KeyError traceback at best and, if the
    # comparison were written the other way round, a silently satisfied
    # requirement - the same fail-open shape load_lock rejects on the lock side.
    if tier not in fx.TIERS:
        fail(f"manifest declares tier {tier!r}, which is not one of {list(fx.TIERS)}")
    print(
        f"check-fixtures: verifying {manifest['workload_version']} tier={tier} "
        f"paths={len(manifest['paths'])} at {generation}"
    )
    if args.require_tier and not fx.tier_satisfies(tier, args.require_tier):
        fail(
            f"--require-tier {args.require_tier}, but the published tree is tier "
            f"{tier!r}. Regenerate with the matching dedicated fixture recipe; "
            "the wide family is intentionally incomparable with fast/full."
        )
    check_workload_version_documented(repo, manifest)
    check_matches_lock(repo, generation, manifest)

    # The key is not re-derived here: check_matches_lock already tied the
    # manifest to the committed pin, and re-deriving it from the same seed
    # would only prove this file can call the same function gen-fixtures did.
    public_line = manifest["public_key"]
    check_trusted_keys_exactly_test_key(public_line)
    check_collect_only_controls(repo)
    check_generator_repair_controls(repo)
    check_post_commit_output_control(repo)
    check_reclaim_direct_execution_control(repo)
    run_bites(generation, manifest, public_line)
    if args.skip_determinism:
        print(
            "check-fixtures: PARTIAL - repeatability NOT checked "
            "(--skip-determinism); this run does not license any claim that "
            "regeneration is byte-stable",
            flush=True,
        )
    else:
        check_determinism(generation, manifest)
    return 0


if __name__ == "__main__":
    # A malformed or unrecognisable lock is an environment failure, not a
    # verdict about the fixture: nothing can be proven against a definition
    # that cannot be read, so it exits 2 rather than 1.
    try:
        sys.exit(main())
    except fx.LockError as error:
        print(f"check-fixtures: FAIL - {error}", file=sys.stderr)
        sys.exit(2)
