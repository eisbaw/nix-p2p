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
import hashlib
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
    print(f"check-fixtures: ok - {message}", flush=True)


def pinned_nix() -> str:
    root = os.environ.get("NIX_P2P_NIX")
    if not root:
        fail("NIX_P2P_NIX not set - run inside: nix develop -c just test", code=2)
    binary = Path(root) / "bin" / "nix"
    if not binary.is_file():
        fail(f"NIX_P2P_NIX={root} has no bin/nix", code=2)
    return str(binary)


def load_manifest(out_dir: Path) -> dict:
    manifest = out_dir / "manifest.json"
    if not manifest.is_file():
        fail(
            f"no fixture at {out_dir} - generate it first:\n"
            "  nix develop -c just fixtures        (fast tier)\n"
            "  nix develop -c just fixtures-large  (adds the 110 MiB payload)",
            code=2,
        )
    return json.loads(manifest.read_text())


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


def check_matches_lock(repo: Path, out_dir: Path, manifest: dict) -> None:
    """The tree must BE the pinned workload for its tier - metadata and bytes.

    WORKLOAD_VERSION alone cannot catch the drift that matters most: bumping
    flake.lock changes stdenv, hence every derivation, hence every store path
    and NarHash - while the version string sits still and the J2 baseline
    silently stops describing the workload it was measured against.

    Two things this deliberately does NOT do, both because they failed open in
    review. It does not accept a subset ("3 of 4 pinned payloads" used to be a
    printed note, so deleting a payload from manifest.json still exited 0); the
    tier's required set is checked for EQUALITY. And it does not stop at
    metadata: the NAR blobs are re-hashed, because a manifest and a lock agree
    perfectly about a file that has been deleted, which is how a missing
    110 MiB payload passed under --skip-determinism.
    """
    lock = fx.load_lock(repo)
    problems = fx.lock_problems(manifest, lock) + fx.blob_problems(
        out_dir / "cache", manifest
    )
    if problems:
        fail(
            "the fixture is NOT the workload pinned in "
            "fixtures/workload.lock.json:\n  - "
            + "\n  - ".join(problems)
            + "\n\nIf the tree is merely incomplete, regenerate it "
            "(`just fixtures` / `just fixtures-large`). If the pinned workload "
            "itself is meant to change, note that doing so RETIRES the J2 "
            "measurement baseline: bump fixtures/WORKLOAD_VERSION, run "
            "`gen-fixtures.py --large --write-lock`, update the TESTING.md "
            "fixture section, and mark the old baseline retired where it is quoted."
        )
    tier = manifest["tier"]
    ok(
        f"is the pinned workload for tier={tier}: "
        f"{len(manifest['paths'])} payload(s), metadata and NAR bytes verified "
        f"against fixtures/workload.lock.json"
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
    served = dict(line.split(": ", 1) for line in text.splitlines() if ": " in line)
    if served != EXPECTED_CACHE_INFO:
        fail(
            f"served nix-cache-info is {served}, expected exactly "
            f"{EXPECTED_CACHE_INFO}. These values are stated independently in "
            "this file precisely so a wrong Priority cannot agree with itself."
        )
    # Weaker than the check above and kept anyway: it catches a manifest that
    # disagrees with the file it claims to describe, which downstream
    # consumers read instead of the file.
    for key, expected in manifest["cache_info"].items():
        if served.get(key) != str(expected):
            fail(
                f"manifest says nix-cache-info {key}={expected!r} but the served "
                f"file says {served.get(key)!r}"
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


def run_bites(out_dir: Path, manifest: dict, public_line: str) -> None:
    src_cache = out_dir / "cache"
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


def tree_digest(root: Path) -> dict[str, str]:
    """Contents AND metadata, per entry - directories included.

    Contents alone were compared before, so two trees generated under
    different umasks (022 -> 644/755, 077 -> 600/700) were reported identical
    while being materially different to rsync, tar, an image build, or a
    server deciding a file is unreadable. gen-fixtures now normalises modes
    and mtimes; including them here is what proves the normalisation happened
    rather than assuming it.
    """
    digest = {}
    for path in sorted(root.rglob("*")):
        stat = path.lstat()
        if path.is_symlink():
            body = f"symlink:{os.readlink(path)}"
        elif path.is_dir():
            body = "dir"
        else:
            body = hashlib.sha256(path.read_bytes()).hexdigest()
        digest[str(path.relative_to(root))] = (
            f"{body} mode={stat.st_mode & 0o7777:04o} mtime={int(stat.st_mtime)}"
        )
    return digest


def check_determinism(out_dir: Path, manifest: dict) -> None:
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
        replica = Path(tmp) / "out"
        cmd = [
            sys.executable,
            str(Path(__file__).resolve().parent / "gen-fixtures.py"),
            "--out",
            str(replica),
        ]
        if manifest["tier"] == "full":
            cmd.append("--large")
        # `--out` points at a scratch tree, so the reuse shortcut in
        # gen-fixtures cannot fire and this always regenerates for real.
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            fail(f"regeneration failed:\n{result.stderr.strip()}")

        original, regenerated = tree_digest(out_dir), tree_digest(replica)
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
        help="fixture tree to verify",
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
    out_dir = args.out.resolve()

    manifest = load_manifest(out_dir)
    print(
        f"check-fixtures: verifying {manifest['workload_version']} "
        f"tier={manifest['tier']} paths={len(manifest['paths'])}"
    )
    if args.require_tier == fx.TIER_FULL and manifest["tier"] != fx.TIER_FULL:
        fail(
            f"--require-tier full, but the tree at {out_dir} is tier "
            f"{manifest['tier']!r}. Regenerate with `just fixtures-large`; "
            "verifying a fast tree here would report the full workload green "
            "without ever touching the 110 MiB payload."
        )
    check_workload_version_documented(repo, manifest)
    check_matches_lock(repo, out_dir, manifest)

    # The key is not re-derived here: check_matches_lock already tied the
    # manifest to the committed pin, and re-deriving it from the same seed
    # would only prove this file can call the same function gen-fixtures did.
    public_line = manifest["public_key"]
    check_trusted_keys_exactly_test_key(public_line)
    run_bites(out_dir, manifest, public_line)
    if args.skip_determinism:
        print(
            "check-fixtures: PARTIAL - repeatability NOT checked "
            "(--skip-determinism); this run does not license any claim that "
            "regeneration is byte-stable",
            flush=True,
        )
    else:
        check_determinism(out_dir, manifest)
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
