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
import contextlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
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
    if not out_root.is_dir():
        fail(
            f"no fixture publication root at {out_root} - generate it first:\n"
            "  nix develop -c just fixtures        (fast tier)\n"
            "  nix develop -c just fixtures-large  (adds the 110 MiB payload)",
            code=2,
        )
    generation = fx.resolve_current(out_root)
    if generation is None:
        fail(
            f"{out_root / fx.CURRENT_LINK} is missing, is not a symlink, or does not "
            f"point at a generation under {fx.GENERATIONS_DIR}/, so nothing "
            "verifiable is published there. Regenerate with `just fixtures` / "
            "`just fixtures-large`.",
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
        fail(
            f"TESTING.md does not mention workload version {version!r}. "
            "Bumping fixtures/WORKLOAD_VERSION means the recorded baseline no "
            "longer describes this workload."
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
    # current -> gen-<sha>/lock.json. The git-tracked fixtures/workload.lock.json
    # is NOT read here - it is a demoted review artifact, and this gate has one
    # runtime source of truth (asserted by scripts/check-lock-sources.py).
    lock = fx.load_generation_lock(generation)
    cache = generation / "cache"
    problems = (
        fx.symlink_problems(generation)
        + fx.lock_problems(manifest, lock)
        + fx.completeness_problems(cache, manifest)
        + fx.blob_problems(cache, manifest)
    )
    if problems:
        fail(
            "the served tree does NOT match its own authoritative "
            f"{generation / fx.GEN_LOCK_NAME}:\n  - "
            + "\n  - ".join(problems)
            + f"\n\nIf the tree is merely damaged, regenerate it "
            "(`just fixtures` / `just fixtures-large`): the generator checks the "
            "same things this does, so it will rebuild rather than reuse, and it "
            "publishes beside a damaged generation rather than refusing. If it "
            f"still reports 'reused', remove the generation and rerun: rm -rf "
            f"{generation}\nIf the pinned workload "
            "itself is meant to change, note that doing so RETIRES the J2 "
            "measurement baseline: bump fixtures/WORKLOAD_VERSION, run "
            "`gen-fixtures.py --large --write-lock`, update the TESTING.md "
            "fixture section, and mark the old baseline retired where it is quoted."
        )
    tier = manifest["tier"]
    ok(
        f"is the pinned workload for tier={tier}: "
        f"{len(manifest['paths'])} payload(s), metadata and NAR bytes verified "
        f"against the generation's own {fx.GEN_LOCK_NAME}"
    )
    if tier != fx.TIER_FULL:
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


def copy_from_fixture(base_url: str, store_path: str, public_line: str):
    """Copy one path from the served fixture into a throwaway chroot store."""
    with tempfile.TemporaryDirectory(prefix="nix-p2p-client-") as tmp:
        env = dict(os.environ, XDG_CACHE_HOME=str(Path(tmp) / "cache"))
        return subprocess.run(
            [
                pinned_nix(),
                "--extra-experimental-features",
                "nix-command",
                "copy",
                "--from",
                base_url,
                "--to",
                str(Path(tmp) / "store"),
                *nix_client_options(public_line),
                store_path,
            ],
            capture_output=True,
            text=True,
            env=env,
            check=False,
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
                "absent. Regenerate with `just fixtures` / `just fixtures-large`."
            )
        destination = dst_cache / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def narinfo_file(cache: Path, entry: dict) -> Path:
    return cache / f"{Path(entry['store_path']).name.split('-')[0]}.narinfo"


def run_bites(generation: Path, manifest: dict, public_line: str) -> None:
    src_cache = generation / "cache"
    by_attr = {entry["attr"]: entry for entry in manifest["paths"]}
    target = by_attr[BITE_ATTR]
    # `app` references `lib`; the closure must be servable or the bite would
    # fail on a missing dependency instead of on the tampering. A reference
    # the manifest does not describe is asserted rather than quietly dropped:
    # silently serving an incomplete closure is how a bite starts rejecting
    # for the wrong reason.
    known = {Path(e["store_path"]).name: attr for attr, e in by_attr.items()}
    unknown = sorted(set(target["references"]) - set(known))
    if unknown:
        fail(
            f"payload {BITE_ATTR!r} references paths the manifest does not "
            f"describe: {unknown}. The bites would run against an incomplete cache."
        )
    needed = [BITE_ATTR] + [known[r] for r in target["references"]]

    with tempfile.TemporaryDirectory(prefix="nix-p2p-bites-") as tmp:
        root = Path(tmp)

        # The positive control covers EVERY payload in the tier, not just the
        # bite target. Importing only app+lib left zstd decompression and the
        # 110 MiB NAR never once handled by a real client: a corrupt zstd frame
        # or an unreadable large blob would have sailed through every check
        # here while breaking the first scenario that actually used them.
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
    """Regenerating the same workload yields a byte-identical tree.

    Be exact about what this earns, because the obvious reading is wrong.
    Regeneration re-EXPORTS store paths that are already realised: `nix build`
    finds them in the store and returns them without building anything. So
    what is proven is that EXPORT is repeatable - NAR serialisation,
    compression, signing and manifest writing - on one host with one
    flake.lock, minutes apart. It says nothing about whether the DERIVATIONS
    build deterministically: a payload that produced different bytes on every
    build would be realised once and then pass this check forever.

    Build determinism is a separate question with a separate check,
    `just fixtures-verify-rebuild` (nix build --rebuild, which rebuilds and
    compares against the realised output). It is slow, so it is not in the
    fast loop - and it is a REQUIRED step before the J2 baseline is recorded,
    noted on task-9 and task-12.

    Neither check proves reproducibility across machines or nixpkgs revisions.
    fixtures/workload.lock.json is the instrument for that case.
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
        # `--out` points at an empty scratch root, so the reuse shortcut in
        # gen-fixtures cannot fire and this always regenerates for real.
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            fail(f"regeneration failed:\n{result.stderr.strip()}")
        replica = fx.resolve_current(replica_root)
        if replica is None:
            fail(f"regeneration published nothing at {replica_root}", code=2)

        original, regenerated = fx.tree_digest(generation), fx.tree_digest(replica)
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
        default=fx.repo_root() / "fixtures" / "out",
        help="fixture publication root; the generation under <dir>/current is "
        "what gets verified",
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
        help="fail unless the tree is at least this tier. `just fixtures-large` "
        "passes full, so it cannot silently pass by verifying a fast tree",
    )
    args = parser.parse_args()

    repo = fx.repo_root()
    out_root = args.out.resolve()

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
    # A rank comparison, not a test for the one tier somebody happened to pass:
    # `--require-tier fast` satisfied by a full tree is correct BECAUSE full
    # outranks fast, and a tier added later inherits that rather than defaulting
    # to "no requirement".
    if args.require_tier and fx.TIER_RANK[tier] < fx.TIER_RANK[args.require_tier]:
        fail(
            f"--require-tier {args.require_tier}, but the published tree is tier "
            f"{tier!r}. Regenerate with `just fixtures-large`; verifying a fast tree "
            "here would report the full workload green without ever touching the "
            "110 MiB payload."
        )
    check_workload_version_documented(repo, manifest)
    check_matches_lock(repo, generation, manifest)

    # The key is not re-derived here: check_matches_lock already tied the
    # manifest to the committed pin, and re-deriving it from the same seed
    # would only prove this file can call the same function gen-fixtures did.
    public_line = manifest["public_key"]
    check_trusted_keys_exactly_test_key(public_line)
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
