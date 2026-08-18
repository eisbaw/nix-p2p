#!/usr/bin/env python3
"""Prove the fixture payloads BUILD deterministically, not merely export so.

scripts/check-fixtures.py regenerates the cache and diffs it, which is a real
check but a narrower one than its name suggests: `nix build` finds the payloads
already realised in the store and hands back the existing paths, so nothing is
rebuilt. It therefore proves that NAR serialisation, compression and signing
are repeatable - not that the derivations produce the same bytes twice. A
payload that built nondeterministically would be realised once and then pass
that check forever, and the frozen workload would rest on whichever bytes
happened to land first.

`nix build --rebuild` closes exactly that gap: it rebuilds each derivation and
compares the result against the output already in the store, failing on any
difference. That is slow by construction, so each fixture family has a
dedicated recipe rather than putting it in the fast loop. For the canonical
family it is a REQUIRED step before the J2 measurement baseline is recorded;
for the wide family it separately grounds the frozen workload's build
repeatability.

Limits worth stating, because task-9 will reuse this:

  * --rebuild compares against THIS store's copy, so it proves determinism
    here and now, on one machine. Cross-machine reproducibility is proven by
    nothing in this repository.
  * It rebuilds each payload's OWN derivation, not an arbitrary transitive
    closure. The canonical lock exposes app, big, lib, and zstd; the wide lock
    exposes all 128 members plus its root. Thus every first-party derivation
    currently defined by either fixture family is explicitly rebuilt. If an
    unpinned first-party dependency is added later, the lock and this coverage
    claim must be extended.
  * It checks that the payloads the LOCK pins rebuild identically. It does not
    re-derive the fixture cache; scripts/check-fixtures.py owns that.

Exit codes: 0 all payloads rebuilt identically and match the lock, 1 a payload
is nondeterministic or is not the pinned one, 2 the environment is wrong and
nothing was proven (including a store where a payload was never realised).
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

import fixturelib as fx


# Every payload the lock pins, regardless of tier: build determinism of the
# large payload is exactly what a measurement baseline depends on. The lock is
# the AUTHORITATIVE one INSIDE the published generation (current -> gen/lock.json),
# not the demoted git baseline - check-rebuild is runtime/consistency code.
def published_lock(repo: Path, wide: bool = False) -> dict:
    out_root = repo / "fixtures" / ("out-wide" if wide else "out")
    generation = fx.resolve_current(out_root)
    if generation is None:
        recipe = "just fixtures-wide" if wide else "just fixtures-large"
        fail(
            f"nothing published at {out_root / fx.CURRENT_LINK} - generate first with "
            f"`{recipe}`",
            code=2,
        )
    return fx.load_generation_lock(generation)


def fail(message: str, code: int = 1) -> int:
    print(f"check-rebuild: FAIL - {message}", file=sys.stderr)
    raise SystemExit(code)


def pinned_nix() -> str:
    root = os.environ.get("NIX_P2P_NIX")
    if not root:
        fail("NIX_P2P_NIX not set - run inside: nix develop -c just ...", code=2)
    binary = Path(root) / "bin" / "nix"
    if not binary.is_file():
        fail(f"NIX_P2P_NIX={root} has no bin/nix", code=2)
    return str(binary)


def nix_build(repo: Path, attr: str, rebuild: bool):
    return subprocess.run(
        [
            pinned_nix(),
            "--extra-experimental-features",
            "nix-command flakes",
            "build",
            *(["--rebuild"] if rebuild else ["--print-out-paths"]),
            "--no-link",
            f"{repo}#fixture-{attr}",
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--wide",
        action="store_true",
        help="rebuild the independent wide_closure fixture family",
    )
    args = parser.parse_args()
    repo = fx.repo_root()
    lock = published_lock(repo, args.wide)
    pinned_tiers = {payload["tier"] for payload in lock["paths"].values()}
    is_wide_lock = lock.get("fixture_class") == fx.FIXTURE_CLASS_WIDE
    if args.wide and (not is_wide_lock or pinned_tiers != {fx.TIER_WIDE}):
        fail(
            "--wide selected fixtures/out-wide, but its published lock is not an "
            "all-wide wide_closure lock; regenerate with `just fixtures-wide`",
            code=2,
        )
    if not args.wide and (
        is_wide_lock or not pinned_tiers <= {fx.TIER_FAST, fx.TIER_FULL}
    ):
        fail(
            "canonical rebuild selected fixtures/out, but its published lock is "
            "not canonical fast/full; regenerate with `just fixtures-large`",
            code=2,
        )
    attrs = sorted(lock["paths"])
    expected_attrs = (
        {fx.WIDE_ROOT_ATTR}
        | {
            f"{fx.WIDE_MEMBER_PREFIX}{index:03d}"
            for index in range(fx.WIDE_MEMBER_COUNT)
        }
        if args.wide
        else {"app", "big", "lib", "zstd"}
    )
    if set(attrs) != expected_attrs:
        fail(
            f"the selected {'wide_closure' if args.wide else 'canonical full'} lock "
            "does not pin the exact frozen rebuild set: "
            f"missing={sorted(expected_attrs - set(attrs))}, "
            f"extra={sorted(set(attrs) - expected_attrs)}. Regenerate with "
            f"`{'just fixtures-wide' if args.wide else 'just fixtures-large'}`",
            code=2,
        )

    for attr in attrs:
        # REALISE FIRST. `nix build --rebuild` on a store where the output was
        # never realised fails with "outputs are not valid, so checking is not
        # possible" - which is an empty store, not a nondeterministic payload.
        # Reporting that as nondeterminism accused every fresh clone and CI
        # runner of a defect in the workload (task-20). Realising first turns
        # the cold-store case into a normal build, and any failure HERE is an
        # environment problem (exit 2), keeping exit 1 for the real thing.
        print(f"check-rebuild: realising fixture-{attr} ...", flush=True)
        realise = nix_build(repo, attr, rebuild=False)
        if realise.returncode != 0:
            fail(
                f"fixture-{attr} could not be built at all:\n"
                f"{realise.stderr.strip()}\n\n"
                "This is an environment or expression failure, NOT evidence about "
                "determinism - nothing was proven either way.",
                code=2,
            )
        out_path = realise.stdout.strip()

        # Rebuilding "the current flake attr" proves nothing about the FROZEN
        # workload unless it is the same path the lock pins: an edited
        # workload.nix rebuilds perfectly deterministically into a store path
        # no measurement was ever taken against, and would have reported green.
        pinned = lock["paths"][attr]["store_path"]
        if out_path != pinned:
            fail(
                f"fixture-{attr} builds to {out_path}, but the lock pins {pinned}.\n"
                "Rebuild determinism of a path the frozen workload does not contain "
                "says nothing about the workload. Regenerate the fixture and the "
                "lock together, or check out the revision the lock belongs to."
            )

        print(f"check-rebuild: rebuilding fixture-{attr} ...", flush=True)
        result = nix_build(repo, attr, rebuild=True)
        if result.returncode != 0:
            consequence = (
                "the frozen wide_closure workload would not be repeatable"
                if args.wide
                else "the J2 baseline would be unreproducible"
            )
            fail(
                f"fixture-{attr} did not rebuild to the same output:\n"
                f"{result.stderr.strip()}\n\n"
                "The payload is NONDETERMINISTIC. The frozen workload currently "
                f"rests on whichever bytes were realised first, so {consequence}. "
                "Fix the derivation before relying on this workload."
            )
    family = "wide_closure" if args.wide else "canonical"
    print(
        f"check-rebuild: ok - {len(attrs)} payload(s) rebuilt to identical outputs "
        f"and match the store paths pinned in the {family} lock "
        f"({', '.join(attrs)}). "
        "Proven on THIS machine; cross-machine reproducibility remains unverified."
    )
    return 0


if __name__ == "__main__":
    # A malformed or unrecognisable lock is an environment failure, not a
    # verdict about the fixture: nothing can be proven against a definition
    # that cannot be read, so it exits 2 rather than 1.
    try:
        sys.exit(main())
    except fx.LockError as error:
        print(f"check-rebuild: FAIL - {error}", file=sys.stderr)
        sys.exit(2)
