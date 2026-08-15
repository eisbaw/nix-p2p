#!/usr/bin/env python3
"""AC#9 (TASK-103): the SHIPPED libp2p discovery path must be kad-EXCLUSIVE.

The s7-libp2p decentralized-discovery proof is only worth something if the
consumer can reach the provider ONLY through the libp2p-kad DHT. If the shipped
node also ran a LAN/broadcast or central-tracker discovery behaviour, a
"discovered" peer could have been found by that shortcut instead - and the
proof's attribution (0 upstream egress => DHT-mediated peer serve) would be a
lie. So the node's `NetworkBehaviour` composition must run NO peer-DISCOVERY
substitute: no mDNS (LAN multicast), no rendezvous (a central meeting-point
tracker), no gossipsub/floodsub (pubsub flooding).

DISCOVERY vs DIAL-ASSISTANCE (TASK-168). The NAT-traversal trio - autonat
(reachability detection), dcutr (hole punching), relay (circuit-v2 client+server)
- is EXPLICITLY PERMITTED. These are dial-assistance / CONNECTIVITY, not discovery:
they change HOW you REACH a peer you have ALREADY discovered via kad, never HOW you
find WHO holds content. None of them enumerates providers, floods content
announcements, or offers a non-kad route to LEARN of a peer - autonat only tells YOU
whether YOUR OWN address is dialable, relay carries bytes to an
already-known-PeerId destination, dcutr upgrades an existing relayed connection to a
direct one. Discovery stays kad-EXCLUSIVE; the no-injection oracle (0 upstream
egress => DHT-mediated serve) is undisturbed because the consumer still LEARNS of the
provider only through kad. So the guard forbids the discovery substitutes below and
PERMITS the dial-assistance trio (asserted by the second self-test arm).

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

import re
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

# libp2p peer-DISCOVERY behaviours that would give a node a NON-kad route to LEARN
# OF a peer - each a "tracker / LAN / broadcast substitute" AC#9 forbids. Kept as the
# libp2p module tokens (not bare English words like "broadcast", which appears in an
# unrelated comment) so the scan does not false-positive on prose.
#
# NOTE (TASK-168): `autonat` was REMOVED from this set. It was originally forbidden as
# "address-discovery signalling outside the kad proof", but autonat discovers only
# whether OUR OWN address is publicly dialable - it never discovers OTHER peers or
# content, so it is dial-assistance, not a discovery substitute (see the module
# docstring). dcutr/relay were never forbidden and stay permitted for the same reason.
FORBIDDEN = {
    "mdns": "mDNS is LAN multicast peer discovery - a non-kad shortcut",
    "rendezvous": "rendezvous is a central meeting-point tracker - a non-kad shortcut",
    "gossipsub": "gossipsub is pubsub flooding - a non-kad discovery/broadcast path",
    "floodsub": "floodsub is pubsub flooding - a non-kad discovery/broadcast path",
}

# The NAT-traversal trio explicitly PERMITTED (TASK-168): dial-assistance, not
# discovery. Documented here so a future reader sees the boundary is deliberate, and
# asserted by the second self-test arm (a composition adding these must NOT trip).
PERMITTED_DIAL_ASSISTANCE = ("autonat", "dcutr", "relay")

# TASK-218 (mped-architect must-fix #3, tightened per codex finding #4): the relay-circuit
# dial-address the locator COMPOSES for a NAT'd provider must come from a CONFIG-LEVEL,
# provider-INDEPENDENT relay set (`known_relays`), never from a per-provider / per-content
# channel. A per-provider relay association is "the relay THIS provider is on", i.e. address
# injection under another name - reintroducing exactly what the kad-exclusive discovery
# guarantee forbids. We enforce it STRUCTURALLY against THREE shapes:
#   (A) `known_relays` declared as anything other than a flat `Vec<...>` (a map keyed by an
#       identity) - the original check;
#   (B) `known_relays: Vec<(NodeId|ContentKey|Provider..., ...)>` - a Vec whose element is
#       KEYED by a provider/content identity (the legit form's first element is the RELAY's
#       transport `PeerId`, never the provider's `NodeId`); and
#   (C) ANY field whose name mentions `relay`/`circuit` declared as a map keyed by a
#       provider/content identity (`relay_by_provider: BTreeMap<NodeId, _>`, etc). The
#       legitimate `peer_address_book: BTreeMap<NodeId, Vec<Multiaddr>>` is NOT flagged - its
#       name carries no relay/circuit token and it is the zero-disclosure ExplicitPeers book.
# Prose/doc mentions (comment lines) are ignored. A NodeId/ContentKey identifies the
# CONTENT/PROVIDER; a PeerId identifies the RELAY transport - only the former keying is forbidden.
# A NodeId/ContentKey/Provider* identifies the CONTENT/PROVIDER; a PeerId identifies the RELAY
# transport. Keying a relay set by the FORMER is per-provider injection; by the latter is fine.
IDENTITY_KEY = r"(?:NodeId|ContentKey|Provider\w*)"
# Any binding whose NAME mentions relay/circuit (case-insensitive: snake_case fields AND
# PascalCase type aliases) that is a MAP/SET keyed by a provider/content identity, OR a
# tuple-`Vec`/array whose FIRST element is that identity. Matches `field: Type` AND
# `type Alias = Type`, and tolerates MULTILINE declarations (`\s*` spans newlines) because
# comments are stripped first. The legit `known_relays: Vec<(PeerId, Multiaddr)>` (keyed by the
# relay's PeerId) and `peer_address_book: BTreeMap<NodeId, ...>` (name has no relay/circuit
# token) are NOT matched.
RELAY_KEYED_BY_IDENTITY = re.compile(
    r"\b(?i:[A-Za-z_]*(?:relay|circuit)[A-Za-z0-9_]*)\s*[:=]\s*"
    r"(?:&\s*(?:'[A-Za-z_]\w*\s+)?)?"  # tolerate a borrowed / lifetime-qualified type
    r"(?:"
    r"(?:BTreeMap|HashMap|BTreeSet|HashSet|IndexMap|IndexSet)\s*<\s*"
    + IDENTITY_KEY
    + r"|(?:Vec|VecDeque|\[)\s*<?\s*\(\s*"
    + IDENTITY_KEY
    + r")"
)


def _strip_line_comments(text: str) -> str:
    """Drop `// ...` (and `/// ...`) tails so prose mentioning a forbidden shape never trips the
    scan, while KEEPING newlines so a multiline declaration stays contiguous for the regex."""
    return "\n".join(re.sub(r"//.*", "", line) for line in text.splitlines())


def scan_relay_provider_independence(roots: list[Path]) -> list[str]:
    """No relay/circuit set may be keyed by a provider/content identity - as a map, set,
    tuple-Vec, or type alias, on one line or across several (TASK-218, codex #4). The relay set
    the locator composes circuit addresses from must be provider-INDEPENDENT."""
    violations: list[str] = []
    for root in roots:
        if not root.exists():
            continue
        for source in sorted(root.rglob("*.rs")):
            rel_parts = set(source.relative_to(root).parts)
            if SKIP_DIRS & rel_parts:
                continue
            try:
                text = source.read_text()
            except (UnicodeDecodeError, OSError):
                continue
            code = _strip_line_comments(text)
            for m in RELAY_KEYED_BY_IDENTITY.finditer(code):
                snippet = " ".join(m.group(0).split())[:90]
                violations.append(
                    f"{source}: a relay/circuit set keyed by a provider/content identity "
                    f"({snippet!r}) - associating relays with a provider/content is per-provider "
                    "circuit-address injection under another name (TASK-218). The relay set MUST "
                    "be provider-INDEPENDENT (e.g. Vec<(PeerId, Multiaddr)>)."
                )
    return violations


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
        # A composition carrying the PERMITTED NAT-traversal trio (TASK-168) must NOT
        # trip: dial-assistance is not a discovery substitute. This arm proves the guard
        # still PASSES the exact behaviours the shipped node now runs, so a green scan is
        # meaningful (the guard did not merely stop scanning).
        (root / "dial_assistance.rs").write_text(
            "pub struct Behaviour {\n"
            "    pub kad: kad::Behaviour<MemoryStore>,\n"
            "    pub identify: identify::Behaviour,\n"
            "    pub autonat: autonat::Behaviour,\n"
            "    pub relay: relay::Behaviour,\n"
            "    pub relay_client: relay::client::Behaviour,\n"
            "    pub dcutr: dcutr::Behaviour,\n"
            "}\n"
        )
        permitted_violations, _ = scan([Path(tmp) / "fabric-libp2p" / "src"])
        if permitted_violations:
            print(
                "self-test FAILED: the permitted NAT-traversal trio "
                f"({', '.join(PERMITTED_DIAL_ASSISTANCE)}) was flagged as a discovery "
                f"substitute ({permitted_violations}) - dial-assistance must be allowed",
                file=sys.stderr,
            )
            return 1
        (root / "dial_assistance.rs").unlink()
        # TASK-218 provider-independence: the shipped provider-INDEPENDENT forms MUST pass;
        # EVERY provider-keyed relay association (map, Vec-keyed, or a *relay* map) MUST bite.
        # ALLOWED: the flat known_relays Vec AND the legit NodeId-keyed peer_address_book
        # (its name carries no relay/circuit token, so it is NOT a relay association).
        (root / "relay_ok.rs").write_text(
            "pub struct Cfg {\n"
            "    pub known_relays: Vec<(PeerId, Multiaddr)>,\n"
            "    pub peer_address_book: BTreeMap<NodeId, Vec<Multiaddr>>,\n"
            "    /// doc prose: a known_relays: BTreeMap<NodeId, _> would be forbidden (comment)\n"
            "    pub relay: Toggle<relay::Behaviour>,\n"
            "}\n"
        )
        relay_ok = scan_relay_provider_independence([Path(tmp) / "fabric-libp2p" / "src"])
        if relay_ok:
            print(
                "self-test FAILED: a legit shape (flat known_relays Vec, NodeId-keyed "
                "peer_address_book, a relay Toggle, or a comment mention) was flagged as "
                f"per-provider injection ({relay_ok})",
                file=sys.stderr,
            )
            return 1
        (root / "relay_ok.rs").unlink()
        # Each mutation must trip the guard; INCLUDING the tuple-Vec, multiline, and type-alias
        # forms codex flagged as slipping through the earlier line-oriented / map-only check.
        mutations = {
            "known_relays_map": "    pub known_relays: BTreeMap<NodeId, Multiaddr>,",
            "known_relays_vec_keyed": "    pub known_relays: Vec<(NodeId, Multiaddr)>,",
            "relay_by_provider_map": "    pub relay_by_provider: BTreeMap<NodeId, Multiaddr>,",
            # codex #4: the tuple-Vec form (a map keyed by provider under a Vec of pairs).
            "relay_by_provider_vec": "    pub relay_by_provider: Vec<(NodeId, Multiaddr)>,",
            "provider_circuit_map": "    pub provider_circuits: HashMap<ContentKey, Multiaddr>,",
            # codex #4: a MULTILINE declaration (name and type on different lines).
            "relay_multiline": "    pub provider_relays:\n        BTreeMap<NodeId, Multiaddr>,",
            # codex #4: a type ALIAS whose name mentions relay and is identity-keyed.
            "relay_type_alias": "pub type ProviderRelays = BTreeMap<NodeId, Multiaddr>;",
        }
        for name, decl in mutations.items():
            bad = root / f"{name}.rs"
            bad.write_text("pub struct Cfg {\n" + decl + "\n}\n")
            hits = scan_relay_provider_independence([Path(tmp) / "fabric-libp2p" / "src"])
            bad.unlink()
            if not hits:
                print(
                    f"self-test FAILED: the provider-keyed relay shape `{decl.strip()}` did NOT "
                    "trip the guard - per-provider circuit injection would slip through",
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
            "check-discovery-no-shortcut: self-test OK - clean composition passes, the "
            "permitted NAT-traversal trio (autonat/dcutr/relay) is ALLOWED, and adding "
            "mdns::Behaviour BITES (AC#9 mutation caught)"
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
    # TASK-218: also enforce that the relay-circuit composition input is provider-independent.
    violations = violations + scan_relay_provider_independence(roots)
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
        "scanned; discovery is kad-EXCLUSIVE (no mdns/rendezvous/gossipsub/floodsub); "
        "the NAT-traversal trio (autonat/dcutr/relay) is permitted dial-assistance"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
