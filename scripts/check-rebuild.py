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
difference. That is slow by construction (it rebuilds the 110 MiB payload), so
it is a dedicated recipe rather than part of the fast loop - and it is a
REQUIRED step before the J2 measurement baseline is recorded, because a
baseline taken against accidentally-unique bytes cannot be reproduced by
anyone, including its author.

Limits worth stating: --rebuild compares against THIS store's copy, so it
proves determinism here and now, on one machine. It does not prove
cross-machine reproducibility, which nothing in this repository does.

Exit codes: 0 all payloads rebuilt identically, 1 a payload is
nondeterministic, 2 the environment is wrong and nothing was proven.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import fixturelib as fx


# Every payload the lock pins, regardless of tier: build determinism of the
# large payload is exactly what a measurement baseline depends on.
def payload_attrs(repo: Path) -> list[str]:
    return sorted(fx.load_lock(repo)["paths"])


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


def main() -> int:
    repo = fx.repo_root()
    attrs = payload_attrs(repo)
    if not attrs:
        fail("the lock pins no payloads; nothing to rebuild", code=2)

    for attr in attrs:
        print(f"check-rebuild: rebuilding fixture-{attr} ...", flush=True)
        result = subprocess.run(
            [
                pinned_nix(),
                "--extra-experimental-features",
                "nix-command flakes",
                "build",
                "--rebuild",
                "--no-link",
                f"{repo}#fixture-{attr}",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            fail(
                f"fixture-{attr} did not rebuild to the same output:\n"
                f"{result.stderr.strip()}\n\n"
                "The payload is NONDETERMINISTIC. The frozen workload currently "
                "rests on whichever bytes were realised first, so the J2 baseline "
                "would be unreproducible. Fix the derivation before recording any "
                "measurement against this workload."
            )
    print(
        f"check-rebuild: ok - {len(attrs)} payload(s) rebuilt to identical outputs "
        f"({', '.join(attrs)}). Proven on THIS machine; cross-machine "
        "reproducibility remains unverified."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
