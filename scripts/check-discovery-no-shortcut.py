#!/usr/bin/env python3
"""AC#9 (TASK-103): the SHIPPED libp2p discovery path must be kad-EXCLUSIVE.

The s7-libp2p decentralized-discovery proof is only worth something if the
consumer can reach the provider ONLY through the libp2p-kad DHT. If the shipped
node also ran a LAN/broadcast or central-tracker discovery behaviour, a
"discovered" peer could have been found by that shortcut instead - and the
proof's attribution (0 upstream egress => DHT-mediated peer serve) would be a
lie. So the node's `NetworkBehaviour` composition must contain kad + identify
ONLY: no mDNS (LAN multicast), no rendezvous (a central meeting-point tracker),
no gossipsub/floodsub (pubsub flooding), no autonat.

This is the SOURCE half of AC#9 (the runtime half is s7-libp2p's no-injection
oracle: the consumer's REAL container argv carries no `--libp2p-provider-addr`
and no bootstrap to the provider, so no out-of-band address is injected). It is
modelled on `check-source-guard.py`: a dependency-free substring scan over the
first-party discovery source, run in `just lint` and as evidence for TASK-103.

THE BITE (AC#9's "a mutation enabling any substitute makes the proof fail"):
`--self-test` synthesises a source file that adds `mdns::Behaviour` to the
composition and asserts this guard REPORTS it. A guard that cannot be shown to
fail is not a guard.

Limits, stated plainly: this is a substring scan (like its sibling), so it
catches an accidental or straightforward re-enablement, not a determined
obfuscation (an aliased import, a macro). The behavioural no-injection oracle in
the e2e is the complementary check that observes the running boundary.

Usage: check-discovery-no-shortcut.py [--self-test] [ROOT ...]
Exit codes: 0 clean, 1 a forbidden discovery substrate is present, 2 nothing
was scanned so nothing was proven.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

# The first-party crates that DEFINE the shipped libp2p discovery behaviour. The
# node's `NetworkBehaviour` composition lives entirely in `fabric-libp2p/src`
# (swarm.rs); `daemon-libp2p/src` is the thin binary over it. The composite
# `daemon` crate is deliberately NOT scanned: it also links the iroh backend
# (whose relay code legitimately mentions "rendezvous"), and it cannot add a
# behaviour to the fabric's sealed `Behaviour` struct - it only calls the fabric's
# kad API. Scoping here keeps the guard precise (no iroh false positives) while
# still covering the ONLY place a libp2p LAN/tracker behaviour could be enabled.
DISCOVERY_ROOTS = ("fabric-libp2p/src", "daemon-libp2p/src")

SKIP_DIRS = {".git", "target", "result", "fixtures", "backlog", ".direnv", "tests"}

# libp2p discovery behaviours that would give a node a NON-kad route to a peer -
# each a "tracker / LAN / broadcast substitute" AC#9 forbids. Kept as the libp2p
# module tokens (not bare English words like "broadcast", which appears in an
# unrelated comment) so the scan does not false-positive on prose.
FORBIDDEN = {
    "mdns": "mDNS is LAN multicast peer discovery - a non-kad shortcut",
    "rendezvous": "rendezvous is a central meeting-point tracker - a non-kad shortcut",
    "gossipsub": "gossipsub is pubsub flooding - a non-kad discovery/broadcast path",
    "floodsub": "floodsub is pubsub flooding - a non-kad discovery/broadcast path",
    "autonat": "autonat is address-discovery signalling outside the kad proof",
}


def scan(roots: list[Path]) -> tuple[list[str], int]:
    violations: list[str] = []
    scanned = 0
    for root in roots:
        if not root.exists():
            continue
        for source in sorted(root.rglob("*.rs")):
            rel_parts = set(source.relative_to(root).parts)
            if SKIP_DIRS & rel_parts:
                continue
            scanned += 1
            try:
                text = source.read_text()
            except (UnicodeDecodeError, OSError) as exc:
                violations.append(f"{source}: cannot be scanned ({exc})")
                continue
            for needle, reason in FORBIDDEN.items():
                if needle in text:
                    violations.append(f"{source}: contains {needle!r} - {reason}")
    return violations, scanned


def self_test() -> int:
    """Prove the scan BITES: a synthetic composition adding mDNS must be flagged."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "fabric-libp2p" / "src"
        root.mkdir(parents=True)
        # A clean file must NOT trip the guard.
        (root / "clean.rs").write_text(
            "pub struct Behaviour {\n"
            "    pub kad: kad::Behaviour<MemoryStore>,\n"
            "    pub identify: identify::Behaviour,\n"
            "}\n"
        )
        clean_violations, clean_scanned = scan([Path(tmp) / "fabric-libp2p" / "src"])
        if clean_violations or clean_scanned == 0:
            print(
                f"self-test FAILED: a kad+identify composition was flagged "
                f"({clean_violations}) or nothing scanned ({clean_scanned})",
                file=sys.stderr,
            )
            return 1
        # The MUTATION: re-enable a LAN discovery substitute. The guard MUST bite.
        (root / "mutated.rs").write_text(
            "pub struct Behaviour {\n"
            "    pub kad: kad::Behaviour<MemoryStore>,\n"
            "    pub identify: identify::Behaviour,\n"
            "    pub mdns: mdns::Behaviour,\n"
            "}\n"
        )
        mutated_violations, _ = scan([Path(tmp) / "fabric-libp2p" / "src"])
        if not any("mdns" in v for v in mutated_violations):
            print(
                "self-test FAILED: adding mdns::Behaviour did NOT trip the guard - "
                "the guard does not bite, so it proves nothing",
                file=sys.stderr,
            )
            return 1
        print(
            "check-discovery-no-shortcut: self-test OK - clean composition passes, "
            "adding mdns::Behaviour BITES (AC#9 mutation caught)"
        )
        return 0


def main(argv: list[str]) -> int:
    args = list(argv)
    if "--self-test" in args:
        args.remove("--self-test")
        rc = self_test()
        if rc != 0:
            return rc
        if not args:
            return 0
    roots = [Path(a) for a in args] if args else [Path(r) for r in DISCOVERY_ROOTS]
    violations, scanned = scan(roots)
    if scanned == 0:
        print(
            "check-discovery-no-shortcut: NOTHING scanned - nothing proven "
            f"(roots={[str(r) for r in roots]})",
            file=sys.stderr,
        )
        return 2
    if violations:
        print(
            "check-discovery-no-shortcut: FORBIDDEN non-kad discovery substrate found:",
            file=sys.stderr,
        )
        for v in violations:
            print(f"  {v}", file=sys.stderr)
        return 1
    print(
        f"check-discovery-no-shortcut: OK - {scanned} shipped discovery source file(s) "
        "scanned; kad-exclusive (no mdns/rendezvous/gossipsub/floodsub/autonat)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
