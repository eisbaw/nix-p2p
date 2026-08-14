#!/usr/bin/env python3
"""AC#3 (TASK-154): the shipped kad path stays OFF the public IPFS DHT and admits
no default-bootstrap / implicit-public-preset / out-of-band public-entrypoint.

This is the SOURCE half of the sybil/eclipse/amplification story that TASK-154's
resource bounds are the other half of. Bounds cap what a hostile peer's records
COST us; this guard pins the qualification INVARIANT that makes those bounds
meaningful: the node participates ONLY in the private, scope-namespaced
`/nix-p2p/<scope>/kad/1.0.0` DHT, never the global `/ipfs/kad/1.0.0` one, and it
carries NO hardcoded well-known bootstrap. If the shipped node silently rejoined
the public IPFS DHT (a `kad::Config::default()` / `kad::Behaviour::new` preset
whose protocol is `/ipfs/kad/1.0.0`) or shipped a baked-in
`bootstrap.libp2p.io` entrypoint, the whole adversarial-bounds argument would be
about the wrong network - an open global DHT the node was never meant to touch,
where the sybil/eclipse surface is unbounded and out of our hands.

This is a SIBLING to `check-discovery-no-shortcut.py`. That guard forbids non-kad
DISCOVERY substitutes (mdns/rendezvous/gossipsub/floodsub - a peer LEARNS of a
provider off-DHT). THIS guard governs the kad path itself: which DHT it joins and
how it bootstraps. Two disjoint invariants, two disjoint guards.

The guard has TWO arms over the shipped first-party source
(`fabric-libp2p/src`, `daemon-libp2p/src` - where the `NetworkBehaviour` and the
node config live):

  FORBIDDEN (a mutation ADDING any of these BITES): a public-IPFS-DHT protocol
  name or a hardcoded well-known bootstrap entrypoint. These are the concrete
  strings a re-enablement would introduce; none appears in the shipped source
  today, and any one of them means the node reaches out to the global network.

  POSITIVE INVARIANT (removing it BITES): at least one private, scope-namespaced
  `/nix-p2p/.../kad` protocol construction MUST be present. This is what catches
  the QUIET regression the forbidden-list cannot: swapping the explicit
  `kad::Behaviour::with_config(.., custom_protocol_config)` for the default
  `kad::Behaviour::new(..)` drops NO forbidden string into OUR source (the
  `/ipfs/kad/1.0.0` default lives inside the library), yet silently rejoins the
  public DHT. Requiring the private marker to survive turns "the custom protocol
  keeps us off the public IPFS DHT" from a comment into a guarded invariant.

THE BITE (AC#3's "a mutation enabling any substitute makes the proof fail"):
`--self-test` synthesises (1) a clean private-DHT composition and asserts it
PASSES; (2) a mutation adding `/ipfs/kad/1.0.0` and asserts it FAILS; (3) a
mutation adding `bootstrap.libp2p.io` and asserts it FAILS; (4) a source with
the private marker REMOVED and asserts it FAILS. A guard that cannot be shown to
fail is not a guard.

Limits, stated plainly: like its sibling this is a dependency-free substring
scan, so it catches an accidental or straightforward re-enablement, not a
determined obfuscation (an aliased import, a runtime-computed protocol string).
It also does NOT prove the node cannot be TOLD (via explicit config) to dial a
public peer - `join_bootstraps` takes caller-supplied addresses by design
(TASK-168's explicit-peers model); this guard's job is only that no PUBLIC
entrypoint is BAKED IN and no PUBLIC DHT protocol is joined by default. And a
source-level invariant is not an adversarial FIELD proof: whether the private
DHT actually resists a determined eclipse is deferred to TASK-205's multi-node
harness.

Usage: check-public-dht-isolation.py [--self-test] [ROOT ...]
Exit codes: 0 clean, 1 a public-DHT / default-bootstrap enabler is present OR the
private-kad invariant is missing, 2 nothing was scanned so nothing was proven.
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

# The first-party crates that DEFINE the shipped kad path: the `NetworkBehaviour`
# composition (`fabric-libp2p/src/swarm.rs`) and the node config over it
# (`daemon-libp2p/src`). Same scope as the discovery sibling and for the same
# reason: the composite `daemon` crate also links the iroh backend and cannot add
# to the fabric's sealed behaviour, so scanning it would only invite false
# positives.
DHT_ROOTS = ("fabric-libp2p/src", "daemon-libp2p/src")

SKIP_DIRS = {".git", "target", "result", "fixtures", "backlog", ".direnv", "tests"}

# Public-IPFS-DHT protocol names and hardcoded well-known bootstrap entrypoints. Each
# is a string that would only appear if the node were wired to the GLOBAL network the
# private `/nix-p2p` DHT deliberately avoids. Kept as concrete path/host tokens (not
# bare words) so the scan does not false-positive on prose.
FORBIDDEN = {
    "/ipfs/kad/1.0.0": (
        "the DEFAULT public IPFS DHT protocol - joining it puts the node on the global "
        "DHT where the sybil/eclipse surface is unbounded (implicit-public preset)"
    ),
    "/ipfs/lan/kad": (
        "the IPFS LAN-DHT protocol preset - a non-scoped DHT the private node must not run"
    ),
    "bootstrap.libp2p.io": (
        "a hardcoded well-known public bootstrap host - a baked-in public entrypoint "
        "(default-IPFS-bootstrap / out-of-band injection of a global-network peer)"
    ),
    "dnsaddr/bootstrap": (
        "the dnsaddr form of the well-known public bootstrap list - a baked-in public "
        "entrypoint the private node must not carry"
    ),
}

# The POSITIVE invariant: a private, scope-namespaced kad protocol construction. The
# `<scope>` is a runtime value (a `{...}` format placeholder or any non-quote run), so
# match the surrounding literal, not a fixed scope. At least one match must survive in
# the shipped source, or the node has no proven-private DHT protocol.
PRIVATE_KAD_MARKER = re.compile(r"/nix-p2p/[^\"]*?/kad")


def scan(roots: list[Path]) -> tuple[list[str], int, int]:
    """Return (violations, files_scanned, private_marker_hits)."""
    violations: list[str] = []
    scanned = 0
    private_hits = 0
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
            private_hits += len(PRIVATE_KAD_MARKER.findall(text))
    return violations, scanned, private_hits


def _evaluate(roots: list[Path]) -> tuple[list[str], int]:
    """Full verdict: forbidden-token violations PLUS the missing-invariant check."""
    violations, scanned, private_hits = scan(roots)
    if scanned > 0 and private_hits == 0:
        violations.append(
            "no private /nix-p2p/<scope>/kad protocol marker found - the shipped kad "
            "path has no proven-private DHT protocol; a default `/ipfs/kad/1.0.0` preset "
            "would silently rejoin the PUBLIC IPFS DHT (invariant lost)"
        )
    return violations, scanned


def self_test() -> int:
    """Prove the guard BITES on each substitute and on a dropped invariant."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "fabric-libp2p" / "src"
        root.mkdir(parents=True)
        roots = [Path(tmp) / "fabric-libp2p" / "src"]

        clean = (
            "let kad_protocol = StreamProtocol::try_from_owned(\n"
            '    format!("/nix-p2p/{scope}/kad/1.0.0"))?;\n'
            "let kad = kad::Behaviour::with_config(peer_id, store, kad_config);\n"
        )
        # (1) A clean private-DHT composition must PASS both arms.
        (root / "clean.rs").write_text(clean)
        violations, scanned = _evaluate(roots)
        if violations or scanned == 0:
            print(
                f"self-test FAILED: a clean private-DHT composition was flagged "
                f"({violations}) or nothing scanned ({scanned})",
                file=sys.stderr,
            )
            return 1

        # (2) MUTATION: join the public IPFS DHT protocol. MUST bite.
        (root / "mut_ipfs.rs").write_text(
            'let kad_protocol = StreamProtocol::new("/ipfs/kad/1.0.0");\n'
        )
        violations, _ = _evaluate(roots)
        if not any("/ipfs/kad/1.0.0" in v for v in violations):
            print(
                "self-test FAILED: adding the public '/ipfs/kad/1.0.0' protocol did NOT "
                "trip the guard - it does not bite",
                file=sys.stderr,
            )
            return 1
        (root / "mut_ipfs.rs").unlink()

        # (3) MUTATION: bake in a well-known public bootstrap. MUST bite.
        (root / "mut_boot.rs").write_text(
            'let boot = "/dnsaddr/bootstrap.libp2p.io/p2p/QmSoLnSGccFuZQJzRadHn95W2C'
            'rSFmZuTdDWP8HXaHca9".parse();\n'
        )
        violations, _ = _evaluate(roots)
        if not any("bootstrap.libp2p.io" in v for v in violations):
            print(
                "self-test FAILED: baking in 'bootstrap.libp2p.io' did NOT trip the "
                "guard - it does not bite",
                file=sys.stderr,
            )
            return 1
        (root / "mut_boot.rs").unlink()

        # (4) MUTATION: drop the private-kad invariant (swap with_config for the default
        # `Behaviour::new` preset). No forbidden string enters OUR source, yet the node
        # silently rejoins the public DHT - the missing-invariant arm MUST bite.
        (root / "clean.rs").write_text(
            "let kad = kad::Behaviour::new(peer_id, store);\n"
        )
        violations, _ = _evaluate(roots)
        if not any("no private /nix-p2p" in v for v in violations):
            print(
                "self-test FAILED: removing the private /nix-p2p kad marker did NOT trip "
                "the guard - the invariant is not enforced",
                file=sys.stderr,
            )
            return 1

        print(
            "check-public-dht-isolation: self-test OK - a private-DHT composition passes; "
            "adding '/ipfs/kad/1.0.0' BITES; baking in 'bootstrap.libp2p.io' BITES; "
            "dropping the private /nix-p2p kad marker BITES (AC#3 mutations caught)"
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
    roots = [Path(a) for a in args] if args else [Path(r) for r in DHT_ROOTS]
    violations, scanned = _evaluate(roots)
    if scanned == 0:
        print(
            "check-public-dht-isolation: NOTHING scanned - nothing proven "
            f"(roots={[str(r) for r in roots]})",
            file=sys.stderr,
        )
        return 2
    if violations:
        print(
            "check-public-dht-isolation: the shipped kad path is NOT isolated from the "
            "public DHT:",
            file=sys.stderr,
        )
        for v in violations:
            print(f"  {v}", file=sys.stderr)
        return 1
    print(
        f"check-public-dht-isolation: OK - {scanned} shipped kad-path source file(s) "
        "scanned; the private /nix-p2p/<scope>/kad protocol is present and no public "
        "IPFS-DHT protocol / hardcoded well-known bootstrap is baked in"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
