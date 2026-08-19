#!/usr/bin/env python3
"""AC#9 (TASK-103) + TASK-257: CONTENT discovery must stay kad-EXCLUSIVE.

The invariant this guard protects: the SHIPPED node learns WHO HOLDS content ("who
has hash X?") ONLY through the libp2p-kad DHT (`get_providers` / the fabric's
`find_providers`). If a "discovered" provider could have been found by a
LAN/broadcast or central-tracker CONTENT path instead, the s7-libp2p proof's
attribution (0 upstream egress => DHT-mediated peer serve) would be a lie. So no
peer-DISCOVERY substitute may feed the content-resolution path: no
gossipsub/floodsub (pubsub content flooding), no rendezvous (a central
meeting-point tracker).

THE mDNS BOUNDARY (TASK-257). mDNS is now SHIPPED, but ONLY in the peer-ADDRESS
BOOTSTRAP role: it supplies a LAN neighbour's dial ADDRESS into the SAME kad
routing/bootstrap path an explicit `--libp2p-bootstrap` (or identify) feeds
(`kad.add_address`), so a node with no configured bootstrap can still CONVERGE its
DHT. That is address bootstrap, NOT content discovery - the node still learns WHO
holds hash X only through kad. This guard therefore:
  * PERMITS mDNS wired to the address/bootstrap path (`add_address`/`dial`/
    bootstrap) - the shipped wiring; and
  * STILL FORBIDS mDNS wired into CONTENT discovery: if an mDNS event ever feeds
    `find_providers`/`get_providers` (a non-kad answer to "who has hash X?"), a
    bite fires. The distinction is made STRUCTURALLY - by which call the mDNS
    EVENT-HANDLER (or an mDNS-named function) feeds (see `scan_mdns_wiring`).

THE MAINLINE-RENDEZVOUS BOUNDARY (TASK-258 SPIKE). The Mainline (BitTorrent DHT)
rendezvous is the SAME address-bootstrap shape as mDNS, just over a different
substrate: a node `get_peers` a well-known infohash to learn member ADDRESSES and
hands the bare IP:port into the libp2p dial/bootstrap path. BEP5 carries IP:port
ONLY (no PeerId, no arbitrary payload), so it structurally CANNOT answer "who holds
hash X?". So the plain-substring `rendezvous` outright-ban is REFINED exactly like
mDNS was: a mainline/rendezvous-named region may feed the ADDRESS/dial/bootstrap
path but BITES if it feeds `find_providers`/`get_providers` (see
`scan_rendezvous_wiring`). What STAYS forbidden outright is the libp2p RENDEZVOUS
PROTOCOL behaviour itself (`libp2p::rendezvous` / `rendezvous::{client,server,
Behaviour,...}`) - a central meeting-point registration tracker we do NOT use; the
Mainline rendezvous is the `mainline` crate on its OWN UDP socket, never a libp2p
behaviour. The precise pattern (see `FORBIDDEN_PROTOCOL_RE`) matches the libp2p
protocol path but NOT the `mainline_rendezvous` crate/flag naming.
gossipsub/floodsub remain forbidden OUTRIGHT (their mere presence is a violation);
mDNS and the Mainline rendezvous are judged by their WIRING, not their presence.

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

THE BITE (AC#9's "a mutation enabling a content-discovery substitute makes the
proof fail"): `--self-test` proves BOTH directions of the mDNS boundary - a
composition wiring an mDNS event to `add_address` (bootstrap) PASSES, and one
wiring an mDNS event to `get_providers`/`find_providers` (content discovery)
FAILS - and that adding `gossipsub`/`floodsub`/`rendezvous` still bites. A guard
that cannot be shown to fail is not a guard.

Limits, stated plainly: this is a source scan (like its sibling), so it catches an
accidental or straightforward mis-wiring, not a determined obfuscation (routing an
mDNS peer through an unnamed helper several hops away, an aliased import, a macro).
The mDNS-wiring check reasons about the mDNS EVENT-HANDLER body and mDNS-named
functions; a content sink reached through an intermediate un-named helper is the
acknowledged gap. The behavioural no-injection oracle in the e2e (content served
with 0 upstream egress and NO injected provider address) is the complementary
check that observes the running boundary.

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

# libp2p peer-DISCOVERY behaviours whose mere PRESENCE gives a node a NON-kad route to
# a CONTENT holder - each a "tracker / broadcast substitute" the invariant forbids
# OUTRIGHT. Kept as the libp2p module tokens (not bare English words like "broadcast",
# which appears in an unrelated comment) so the scan does not false-positive on prose.
#
# NOTE (TASK-168): `autonat` was REMOVED - it discovers only whether OUR OWN address is
# publicly dialable, never OTHER peers or content (dial-assistance, not a substitute).
# NOTE (TASK-257): `mdns` was REMOVED from this OUTRIGHT set. mDNS is now SHIPPED in the
# peer-ADDRESS BOOTSTRAP role (it feeds `kad.add_address`, never content discovery), so
# its PRESENCE is permitted; its WIRING is judged by `scan_mdns_wiring`.
# NOTE (TASK-258): the bare `rendezvous` SUBSTRING was REMOVED from this OUTRIGHT set. The
# Mainline rendezvous is the SAME address-bootstrap shape as mDNS over a different
# substrate (BEP5 `get_peers` -> IP:port -> the libp2p dial path); its WIRING is judged by
# `scan_rendezvous_wiring`, which still forbids a mainline/rendezvous region feeding
# `find_providers`/`get_providers`. What stays forbidden OUTRIGHT is the libp2p RENDEZVOUS
# PROTOCOL behaviour (`FORBIDDEN_PROTOCOL_RE`) - a genuine central meeting-point
# registration tracker we do NOT use. The precise regex matches the libp2p protocol path
# but NOT the `mainline_rendezvous` crate/flag naming (whose `rendezvous` is preceded by
# `_`, so a `\b`-anchored match never fires inside it).
FORBIDDEN = {
    "gossipsub": "gossipsub is pubsub flooding - a non-kad discovery/broadcast path",
    "floodsub": "floodsub is pubsub flooding - a non-kad discovery/broadcast path",
}

# The libp2p RENDEZVOUS PROTOCOL behaviour stays forbidden outright (TASK-258): installing
# `libp2p::rendezvous` / a `rendezvous::{client,server,Behaviour,Event,Config,register,
# Registration,Namespace}` is a central meeting-point registration tracker - a non-kad
# discovery substrate. These patterns are `\b`-anchored so they match the libp2p protocol
# path (`libp2p::rendezvous`, `rendezvous::Behaviour`) but NEVER the `mainline_rendezvous`
# crate/flag identifiers (there `rendezvous` follows `_`, a word char, so `\b` fails) and
# NEVER a prose comment mentioning the word (comments are stripped first).
FORBIDDEN_PROTOCOL_RE = (
    re.compile(r"\blibp2p[_:]{1,2}rendezvous\b"),
    re.compile(
        r"\brendezvous::(?:client|server|Behaviour|Event|Config|register|"
        r"Registration|Namespace)\b"
    ),
)

# TASK-257: the CONTENT-DISCOVERY sinks an mDNS event must NEVER feed - the "who holds
# hash X?" query entry points. `find_providers` is the fabric directory API; `get_providers`
# is the raw kad query. If either appears inside an mDNS event-handler body (or an
# mDNS-named function), mDNS has been wired as a second content-discovery mechanism and the
# guard bites. These calls are LEGITIMATE elsewhere in the file (they ARE the kad-exclusive
# content path); the violation is specifically an mDNS EVENT feeding one of them.
MDNS_CONTENT_SINKS = ("find_providers", "get_providers")

# TASK-258: the SAME content-discovery sinks a mainline/rendezvous region must NEVER feed.
# Shared with the mDNS check: whatever answers "who holds hash X?" must stay kad-exclusive.
RENDEZVOUS_CONTENT_SINKS = ("find_providers", "get_providers")

# A mainline/rendezvous-named function: its WHOLE body is a rendezvous wiring region. The
# Mainline rendezvous is a side task (its own UDP socket), NOT a libp2p behaviour, so unlike
# mDNS there is no `SwarmEvent` arm to anchor on - the anchor is the FUNCTION NAME. This
# catches `fn spawn_mainline_rendezvous(){...}`, `fn on_rendezvous_addr(){...}`, etc. The
# `mainline`/`rendezvous` tokens here are plain substrings of the fn NAME (not `\b`-anchored),
# so `mainline_rendezvous`-derived helper names are covered too.
RENDEZVOUS_NAMED_FN = re.compile(
    r"\bfn\s+[A-Za-z0-9_]*(?:rendezvous|mainline)[A-Za-z0-9_]*\s*(?:<[^>]*>)?\s*\("
)

# Anchors that mark an mDNS EVENT-HANDLER (as opposed to the struct field, the behaviour
# constructor `mdns::tokio::Behaviour::new`, or a config). Only these begin an mDNS wiring
# region; a bare `mdns` token (e.g. the `pub mdns:` field) does NOT, so the struct
# declaration cannot false-anchor onto an unrelated later match arm.
MDNS_EVENT_ANCHORS = (
    re.compile(r"mdns::Event\b"),
    re.compile(r"BehaviourEvent::Mdns\s*\("),
)
# An mDNS-named function: its whole body is an mDNS wiring region, so routing an mDNS peer
# into `on_mdns_discovered() { ... get_providers ... }` is caught even though the content
# sink is one call away from the event arm.
MDNS_NAMED_FN = re.compile(r"\bfn\s+[A-Za-z0-9_]*mdns[A-Za-z0-9_]*\s*(?:<[^>]*>)?\s*\(")

# The NAT-traversal trio explicitly PERMITTED (TASK-168): dial-assistance, not
# discovery. Documented here so a future reader sees the boundary is deliberate, and
# asserted by the second self-test arm (a composition adding these must NOT trip).
PERMITTED_DIAL_ASSISTANCE = ("autonat", "dcutr", "relay")

# TASK-218/TASK-219: the legacy relay-circuit input must remain the CONFIG-LEVEL,
# provider-INDEPENDENT `known_relays`. TASK-219 adds one deliberate provider->relay association:
# `TransportOffer::Libp2p { relay_hints: RelayHints }` inside the exact-key DHT record. That typed
# value is bounded/canonical and covered by the provider's signature; it is the discovery proof,
# not out-of-band injection. What remains forbidden is an AUXILIARY mutable provider/content-keyed
# relay map/cache or untyped address channel alongside the record. We enforce that structurally:
#   (A) `known_relays` declared as anything other than a flat `Vec<...>` (a map keyed by an
#       identity) - the original check;
#   (B) `known_relays: Vec<(NodeId|ContentKey|Provider..., ...)>` - a Vec whose element is
#       KEYED by a provider/content identity (the legit form's first element is the RELAY's
#       transport `PeerId`, never the provider's `NodeId`); and
#   (C) ANY field whose name mentions `relay`/`circuit` declared as a map keyed by a
#       provider/content identity (`relay_by_provider: BTreeMap<NodeId, _>`, etc). The
#       legitimate `peer_address_book: BTreeMap<NodeId, Vec<Multiaddr>>` is NOT flagged - its
#       name carries no relay/circuit token and it is the zero-disclosure ExplicitPeers book.
# Prose/doc mentions (comment lines) are ignored. A NodeId/ContentKey/Provider* identifies the
# CONTENT/PROVIDER; a PeerId identifies the RELAY
# transport. Keying a relay set by the FORMER is per-provider injection; by the latter is fine.
IDENTITY_KEY = r"(?:NodeId|ContentKey|Provider\w*)"
# An IDENTITY-KEYED CONTAINER: a map/set keyed by a provider/content identity, OR a tuple
# Vec/array whose FIRST element is that identity. Tolerates a borrowed / lifetime-qualified type.
IDENTITY_KEYED_CONTAINER = (
    r"(?:&\s*(?:'[A-Za-z_]\w*\s+)?)?"
    r"(?:(?:BTreeMap|HashMap|BTreeSet|HashSet|IndexMap|IndexSet)\s*<\s*"
    + IDENTITY_KEY
    + r"|(?:Vec|VecDeque|\[)\s*<?\s*\(\s*"
    + IDENTITY_KEY
    + r")"
)
# A binding NAME that mentions relay/circuit (case-insensitive; snake_case fields AND PascalCase
# type aliases). `\s*[:=]\s*` handles both `field: T` and `type Alias = T`, MULTILINE (comments
# are stripped first, so `\s*` spans newlines).
RELAY_NAME = r"[A-Za-z_]*(?:relay|circuit)[A-Za-z0-9_]*"
# (A) a relay/circuit-named binding whose type is a LITERAL identity-keyed container.
RELAY_KEYED_BY_IDENTITY = re.compile(
    r"\b(?i:" + RELAY_NAME + r")\s*[:=]\s*" + IDENTITY_KEYED_CONTAINER
)
# (B) a `type Alias = <identity-keyed container>` - captures the alias NAME so a relay/circuit
# field that uses it (however innocuously the alias is named) can still be caught (codex #2).
TYPE_ALIAS_TO_IDENTITY_KEYED = re.compile(
    r"\btype\s+([A-Za-z_]\w*)\s*=\s*" + IDENTITY_KEYED_CONTAINER
)
# (C) a relay/circuit-named binding whose type is a bare NAMED type (the first identifier after
# `:`/`=`) - so we can check it against the tainted-alias set. `Vec<...>` etc are literals, not
# bare names, and are already covered by (A).
RELAY_FIELD_TYPE_NAME = re.compile(
    r"\b(?i:"
    + RELAY_NAME
    + r")\s*[:=]\s*(?:&\s*(?:'[A-Za-z_]\w*\s+)?)?([A-Za-z_]\w*)\b"
)


def _strip_line_comments(text: str) -> str:
    """Drop `// ...` (and `/// ...`) tails so prose mentioning a forbidden shape never trips the
    scan, while KEEPING newlines so a multiline declaration stays contiguous for the regex."""
    return "\n".join(re.sub(r"//.*", "", line) for line in text.splitlines())


def scan_relay_provider_independence(roots: list[Path]) -> list[str]:
    """No AUXILIARY relay/circuit collection may be keyed by provider/content identity.

    The exact signed record's typed, bounded `RelayHints` value is deliberately allowed; it is
    the authority, not a map/cache. Literal or aliased maps, sets, and tuple-Vec side channels
    remain forbidden (TASK-218/TASK-219, codex #2/#4). The legacy config relay set must remain
    provider-independent.
    """
    # Pass 1: collect every file's comment-stripped source AND the set of type-alias names that
    # resolve to an identity-keyed container (so alias INDIRECTION cannot launder the injection).
    files: list[tuple[Path, str]] = []
    tainted_aliases: set[str] = set()
    for root in roots:
        if not root.exists():
            continue
        for source in sorted(root.rglob("*.rs")):
            if SKIP_DIRS & set(source.relative_to(root).parts):
                continue
            try:
                code = _strip_line_comments(source.read_text())
            except (UnicodeDecodeError, OSError):
                continue
            files.append((source, code))
            for m in TYPE_ALIAS_TO_IDENTITY_KEYED.finditer(code):
                tainted_aliases.add(m.group(1))

    # Pass 2: flag literal identity-keyed relay sets AND relay/circuit fields that reach an
    # identity-keyed container THROUGH a tainted alias.
    violations: list[str] = []
    for source, code in files:
        for m in RELAY_KEYED_BY_IDENTITY.finditer(code):
            snippet = " ".join(m.group(0).split())[:90]
            violations.append(
                f"{source}: a relay/circuit set keyed by a provider/content identity "
                f"({snippet!r}) - associating relays with a provider/content is per-provider "
                "circuit-address injection under another name (TASK-218/TASK-219). Use the "
                "bounded signature-bound RelayHints value, or keep config provider-INDEPENDENT "
                "(e.g. Vec<(PeerId, Multiaddr)>)."
            )
        for m in RELAY_FIELD_TYPE_NAME.finditer(code):
            if m.group(1) in tainted_aliases:
                snippet = " ".join(m.group(0).split())[:90]
                violations.append(
                    f"{source}: a relay/circuit field uses the type alias {m.group(1)!r} which "
                    f"resolves to a provider/content-keyed container ({snippet!r}) - alias "
                    "indirection cannot launder per-provider circuit injection (TASK-218)."
                )
    return violations


def _balanced_block(code: str, open_idx: int) -> str:
    """Return the substring from the `{` at `open_idx` through its matching `}` (inclusive).
    If unbalanced (truncated source), returns to end-of-string - a conservative over-capture
    that can only make the scan STRICTER, never miss a sink."""
    depth = 0
    k = open_idx
    while k < len(code):
        c = code[k]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return code[open_idx : k + 1]
        k += 1
    return code[open_idx:]


def _arm_body_after(code: str, anchor_idx: int) -> str:
    """Given an anchor at an mDNS event pattern, return the match-arm BODY that its `=>`
    introduces: a balanced `{ ... }` block, or - for a brace-less single-expression arm
    (`=> self.foo(x),`) - the expression up to the arm-terminating top-level comma. This is
    the exact code the mDNS event feeds, so a content sink INSIDE it is an mDNS->content
    wiring, while the file's OTHER (legitimate, kad-exclusive) `get_providers` calls are
    outside any arm body and never inspected."""
    arrow = code.find("=>", anchor_idx)
    if arrow == -1:
        return ""
    j = arrow + 2
    while j < len(code) and code[j].isspace():
        j += 1
    if j >= len(code):
        return ""
    if code[j] == "{":
        return _balanced_block(code, j)
    # Brace-less arm: capture to the terminating comma at paren/bracket/brace depth 0 (or
    # the enclosing match's closing brace, whichever comes first).
    depth = 0
    k = j
    while k < len(code):
        c = code[k]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                break
            depth -= 1
        elif c == "," and depth == 0:
            break
        k += 1
    return code[j:k]


def scan_mdns_wiring(roots: list[Path]) -> list[str]:
    """TASK-257: mDNS is PERMITTED in the peer-address bootstrap role but FORBIDDEN as a
    content-discovery mechanism. For every mDNS EVENT-HANDLER body and every mDNS-named
    function body, flag a content-discovery sink (`find_providers`/`get_providers`) - that is
    an mDNS event answering "who holds hash X?", which must stay kad-EXCLUSIVE. mDNS wired to
    the address/bootstrap path (`add_address`/`dial`) is NOT a sink and passes.

    Only mDNS EVENT/handler regions are inspected, so the file's legitimate kad content path
    (its own `get_providers`, the struct field, the behaviour constructor) never trips."""
    violations: list[str] = []
    for root in roots:
        if not root.exists():
            continue
        for source in sorted(root.rglob("*.rs")):
            if SKIP_DIRS & set(source.relative_to(root).parts):
                continue
            try:
                code = _strip_line_comments(source.read_text())
            except (UnicodeDecodeError, OSError):
                continue
            if "mdns" not in code:
                continue
            regions: list[str] = []
            # (a) event-handler arms: capture the body the `=>` introduces.
            for anchor in MDNS_EVENT_ANCHORS:
                for m in anchor.finditer(code):
                    regions.append(_arm_body_after(code, m.start()))
            # (b) mDNS-named functions: capture the whole `{ ... }` body.
            for m in MDNS_NAMED_FN.finditer(code):
                brace = code.find("{", m.end())
                if brace != -1:
                    regions.append(_balanced_block(code, brace))
            for body in regions:
                for sink in MDNS_CONTENT_SINKS:
                    if sink in body:
                        snippet = " ".join(body.split())[:90]
                        violations.append(
                            f"{source}: an mDNS event/handler feeds the content-discovery sink "
                            f"{sink!r} ({snippet!r}) - mDNS may supply peer ADDRESSES to the kad "
                            "bootstrap path (add_address/dial) ONLY, never answer 'who holds hash "
                            "X?'. Content discovery must stay kad-EXCLUSIVE (TASK-257)."
                        )
    return violations


def scan_forbidden_protocols(roots: list[Path]) -> list[str]:
    """TASK-258: the libp2p RENDEZVOUS PROTOCOL behaviour stays forbidden OUTRIGHT.

    `FORBIDDEN_PROTOCOL_RE` matches the libp2p protocol path (`libp2p::rendezvous`,
    `rendezvous::Behaviour`, ...) but NOT the `mainline_rendezvous` crate/flag identifiers
    (there `rendezvous` follows `_`, so the `\\b` anchor never fires). Comments are stripped
    first, so a prose mention of the word never trips."""
    violations: list[str] = []
    for root in roots:
        if not root.exists():
            continue
        for source in sorted(root.rglob("*.rs")):
            if SKIP_DIRS & set(source.relative_to(root).parts):
                continue
            try:
                code = _strip_line_comments(source.read_text())
            except (UnicodeDecodeError, OSError):
                continue
            for pattern in FORBIDDEN_PROTOCOL_RE:
                m = pattern.search(code)
                if m:
                    violations.append(
                        f"{source}: contains the libp2p rendezvous PROTOCOL token "
                        f"{m.group(0)!r} - a central meeting-point registration tracker is a "
                        "non-kad discovery substrate, forbidden outright (TASK-258). The Mainline "
                        "rendezvous is the `mainline` crate on its own UDP socket, never a libp2p "
                        "behaviour."
                    )
    return violations


def scan_rendezvous_wiring(roots: list[Path]) -> list[str]:
    """TASK-258: the Mainline rendezvous is PERMITTED in the peer-address bootstrap role but
    FORBIDDEN as a content-discovery mechanism. For every mainline/rendezvous-named function
    body, flag a content-discovery sink (`find_providers`/`get_providers`) - that would be a
    rendezvous answering "who holds hash X?", which must stay kad-EXCLUSIVE. A rendezvous
    region wired to the address/dial/bootstrap path (`dial`/`add_address`/`join_bootstraps`)
    is NOT a sink and passes - exactly the mDNS boundary, over a different substrate."""
    violations: list[str] = []
    for root in roots:
        if not root.exists():
            continue
        for source in sorted(root.rglob("*.rs")):
            if SKIP_DIRS & set(source.relative_to(root).parts):
                continue
            try:
                code = _strip_line_comments(source.read_text())
            except (UnicodeDecodeError, OSError):
                continue
            if "rendezvous" not in code and "mainline" not in code:
                continue
            for m in RENDEZVOUS_NAMED_FN.finditer(code):
                brace = code.find("{", m.end())
                if brace == -1:
                    continue
                body = _balanced_block(code, brace)
                for sink in RENDEZVOUS_CONTENT_SINKS:
                    if sink in body:
                        snippet = " ".join(body.split())[:90]
                        violations.append(
                            f"{source}: a mainline/rendezvous-named function feeds the "
                            f"content-discovery sink {sink!r} ({snippet!r}) - the Mainline "
                            "rendezvous may supply peer ADDRESSES to the dial/bootstrap path "
                            "ONLY, never answer 'who holds hash X?'. Content discovery must stay "
                            "kad-EXCLUSIVE (TASK-258)."
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
        # TASK-218/TASK-219: allowed forms MUST pass: flat provider-independent known_relays,
        # the explicit-peer book, and the bounded signature-bound RelayHints VALUE. Every
        # auxiliary provider-keyed relay map/cache must still bite.
        (root / "relay_ok.rs").write_text(
            "pub struct Cfg {\n"
            "    pub known_relays: Vec<(PeerId, Multiaddr)>,\n"
            "    pub peer_address_book: BTreeMap<NodeId, Vec<Multiaddr>>,\n"
            "    pub relay_hints: RelayHints,\n"
            "    /// doc prose: a known_relays: BTreeMap<NodeId, _> would be forbidden (comment)\n"
            "    pub relay: Toggle<relay::Behaviour>,\n"
            "}\n"
        )
        relay_ok = scan_relay_provider_independence(
            [Path(tmp) / "fabric-libp2p" / "src"]
        )
        if relay_ok:
            print(
                "self-test FAILED: a legit shape (flat known_relays Vec, signed RelayHints, "
                "NodeId-keyed peer_address_book, a relay Toggle, or a comment mention) was flagged as "
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
            "relay_hint_cache": "    pub relay_hint_cache: HashMap<NodeId, RelayHints>,",
            # codex #4: a MULTILINE declaration (name and type on different lines).
            "relay_multiline": "    pub provider_relays:\n        BTreeMap<NodeId, Multiaddr>,",
            # codex #4: a type ALIAS whose name mentions relay and is identity-keyed.
            "relay_type_alias": "pub type ProviderRelays = BTreeMap<NodeId, Multiaddr>;",
        }
        for name, decl in mutations.items():
            bad = root / f"{name}.rs"
            bad.write_text("pub struct Cfg {\n" + decl + "\n}\n")
            hits = scan_relay_provider_independence(
                [Path(tmp) / "fabric-libp2p" / "src"]
            )
            bad.unlink()
            if not hits:
                print(
                    f"self-test FAILED: the provider-keyed relay shape `{decl.strip()}` did NOT "
                    "trip the guard - per-provider circuit injection would slip through",
                    file=sys.stderr,
                )
                return 1
        # codex #2: ALIAS INDIRECTION - a relay field whose type is a SEPARATELY-declared,
        # innocuously-named identity-keyed alias must STILL bite (the alias is resolved).
        alias_file = root / "relay_alias_indirection.rs"
        alias_file.write_text(
            "type ProviderMap = BTreeMap<NodeId, Multiaddr>;\n"
            "pub struct Cfg {\n    pub relay_by_provider: ProviderMap,\n}\n"
        )
        alias_hits = scan_relay_provider_independence(
            [Path(tmp) / "fabric-libp2p" / "src"]
        )
        alias_file.unlink()
        if not any("alias" in v.lower() for v in alias_hits):
            print(
                "self-test FAILED: a relay field using an identity-keyed type ALIAS "
                "(relay_by_provider: ProviderMap) did NOT trip the guard - alias indirection "
                "would launder per-provider circuit injection",
                file=sys.stderr,
            )
            return 1
        # TASK-257 DIRECTION (a): mDNS in the peer-ADDRESS BOOTSTRAP role must PASS. A
        # composition that installs the mDNS behaviour AND wires its Discovered event to
        # `kad.add_address` (the bootstrap/address path) is the SHIPPED wiring and must not trip
        # either the outright-forbidden scan (mdns is no longer in FORBIDDEN) or the wiring scan
        # (add_address is not a content sink).
        (root / "mdns_bootstrap_ok.rs").write_text(
            "pub struct Behaviour {\n"
            "    pub kad: kad::Behaviour<MemoryStore>,\n"
            "    pub identify: identify::Behaviour,\n"
            "    pub mdns: Toggle<mdns::tokio::Behaviour>,\n"
            "}\n"
            "fn on_event(&mut self, event: SwarmEvent<BehaviourEvent>) {\n"
            "    match event {\n"
            "        SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Discovered(peers))) => {\n"
            "            let kad = &mut self.swarm.behaviour_mut().kad;\n"
            "            for (peer_id, addr) in peers { kad.add_address(&peer_id, addr); }\n"
            "        }\n"
            "        _ => {}\n"
            "    }\n"
            "}\n"
        )
        boot_violations, _ = scan([Path(tmp) / "fabric-libp2p" / "src"])
        boot_wiring = scan_mdns_wiring([Path(tmp) / "fabric-libp2p" / "src"])
        (root / "mdns_bootstrap_ok.rs").unlink()
        if boot_violations or boot_wiring:
            print(
                "self-test FAILED: mDNS wired to the ADDRESS/bootstrap path (add_address) was "
                f"flagged (outright={boot_violations}, wiring={boot_wiring}) - the permitted "
                "peer-address bootstrap role must PASS (TASK-257)",
                file=sys.stderr,
            )
            return 1
        # TASK-257 DIRECTION (b): mDNS wired into CONTENT discovery must FAIL. The ONLY change
        # from (a) is the sink the Discovered event feeds: `get_providers`/`find_providers`
        # instead of `add_address`. Both the event-arm form AND the mDNS-named-helper form must
        # bite (a content sink one call away, inside `on_mdns_*`, is still caught).
        for label, body in (
            (
                "event-arm get_providers",
                "        SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Discovered(peers))) => {\n"
                "            for (peer_id, _addr) in peers {\n"
                "                self.swarm.behaviour_mut().kad.get_providers(some_key);\n"
                "            }\n"
                "        }\n",
            ),
            (
                "mdns-named-fn find_providers",
                "        SwarmEvent::Behaviour(BehaviourEvent::Mdns(ev)) => self.on_mdns_discovered(ev),\n",
            ),
        ):
            extra = ""
            if "on_mdns_discovered" in body:
                extra = (
                    "fn on_mdns_discovered(&mut self, ev: mdns::Event) {\n"
                    "    self.directory.find_providers(&key, &budget);\n"
                    "}\n"
                )
            (root / "mdns_content.rs").write_text(
                "fn on_event(&mut self, event: SwarmEvent<BehaviourEvent>) {\n"
                "    match event {\n" + body + "        _ => {}\n    }\n}\n" + extra
            )
            content_wiring = scan_mdns_wiring([Path(tmp) / "fabric-libp2p" / "src"])
            (root / "mdns_content.rs").unlink()
            if not any("content-discovery sink" in v for v in content_wiring):
                print(
                    f"self-test FAILED: mDNS wired into CONTENT discovery ({label}) did NOT trip "
                    "the guard - mDNS must never answer 'who holds hash X?' (TASK-257)",
                    file=sys.stderr,
                )
                return 1
        # The pubsub substitutes must STILL bite by mere presence (via `scan`): gossipsub,
        # floodsub. (mDNS and the bare `rendezvous` substring are deliberately NOT in this
        # set anymore - mDNS/rendezvous are judged by WIRING.)
        for token in ("gossipsub", "floodsub"):
            (root / "forbidden.rs").write_text(
                "pub struct Behaviour {\n"
                "    pub kad: kad::Behaviour<MemoryStore>,\n"
                f"    pub sub: {token}::Behaviour,\n"
                "}\n"
            )
            forbid_violations, _ = scan([Path(tmp) / "fabric-libp2p" / "src"])
            (root / "forbidden.rs").unlink()
            if not any(token in v for v in forbid_violations):
                print(
                    f"self-test FAILED: adding {token}::Behaviour did NOT trip the guard - the "
                    "outright-forbidden pubsub content-discovery substitutes must still bite",
                    file=sys.stderr,
                )
                return 1
        # TASK-258 OUTRIGHT: the libp2p RENDEZVOUS PROTOCOL behaviour must still bite (via
        # `scan_forbidden_protocols`), while the `mainline_rendezvous` crate/flag identifier
        # must NOT (the `\b`-anchored regex never fires inside `mainline_rendezvous`).
        for label, decl, want_bite in (
            ("rendezvous::Behaviour", "    pub rzv: rendezvous::Behaviour,", True),
            (
                "libp2p::rendezvous",
                "    pub rzv: libp2p::rendezvous::client::Behaviour,",
                True,
            ),
            (
                "mainline_rendezvous flag",
                "    pub libp2p_mainline_rendezvous: bool,",
                False,
            ),
        ):
            (root / "proto.rs").write_text("pub struct S {\n" + decl + "\n}\n")
            proto_hits = scan_forbidden_protocols([Path(tmp) / "fabric-libp2p" / "src"])
            (root / "proto.rs").unlink()
            if want_bite and not proto_hits:
                print(
                    f"self-test FAILED: the libp2p rendezvous PROTOCOL ({label}) did NOT bite - a "
                    "central meeting-point tracker must be forbidden outright (TASK-258)",
                    file=sys.stderr,
                )
                return 1
            if not want_bite and proto_hits:
                print(
                    f"self-test FAILED: the `mainline_rendezvous` identifier ({label}) tripped the "
                    f"libp2p-protocol ban ({proto_hits}) - the crate/flag naming must be allowed",
                    file=sys.stderr,
                )
                return 1
        # TASK-258 DIRECTION (a): the Mainline rendezvous in the ADDRESS/dial role must PASS. A
        # mainline/rendezvous-named function that hands the recovered bare IP:port to the dial
        # path is the permitted wiring.
        (root / "rzv_addr_ok.rs").write_text(
            "async fn spawn_mainline_rendezvous(&self) {\n"
            "    let addrs = self.discover().await;\n"
            "    for addr in addrs { let _ = self.swarm.dial(addr).await; }\n"
            "}\n"
        )
        rzv_ok = scan_rendezvous_wiring([Path(tmp) / "fabric-libp2p" / "src"])
        (root / "rzv_addr_ok.rs").unlink()
        if rzv_ok:
            print(
                "self-test FAILED: the Mainline rendezvous wired to the dial/ADDRESS path was "
                f"flagged ({rzv_ok}) - the permitted peer-address bootstrap role must PASS (TASK-258)",
                file=sys.stderr,
            )
            return 1
        # TASK-258 DIRECTION (b): the Mainline rendezvous wired into CONTENT discovery must FAIL.
        # The ONLY change is the sink the rendezvous-named function feeds.
        for label, sink in (
            ("get_providers", "get_providers"),
            ("find_providers", "find_providers"),
        ):
            (root / "rzv_content.rs").write_text(
                "async fn on_rendezvous_discovered(&self, key: Key) {\n"
                f"    let _ = self.swarm.behaviour_mut().kad.{sink}(key);\n"
                "}\n"
            )
            rzv_bad = scan_rendezvous_wiring([Path(tmp) / "fabric-libp2p" / "src"])
            (root / "rzv_content.rs").unlink()
            if not any("content-discovery sink" in v for v in rzv_bad):
                print(
                    f"self-test FAILED: the Mainline rendezvous wired into CONTENT discovery "
                    f"({label}) did NOT trip the guard - it must never answer 'who holds hash X?' "
                    "(TASK-258)",
                    file=sys.stderr,
                )
                return 1
        print(
            "check-discovery-no-shortcut: self-test OK - clean composition passes, the permitted "
            "NAT-traversal trio (autonat/dcutr/relay) is ALLOWED, mDNS AND the Mainline rendezvous "
            "in the ADDRESS/bootstrap role (add_address/dial) PASS while either wired into content "
            "discovery (find_providers/get_providers) BITES, gossipsub/floodsub AND the libp2p "
            "rendezvous PROTOCOL behaviour still BITE (but the `mainline_rendezvous` flag naming "
            "does not), and an auxiliary provider-keyed relay cache BITES"
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
    # TASK-218/219: allow signed RelayHints, forbid auxiliary provider-keyed relay state.
    violations = violations + scan_relay_provider_independence(roots)
    # TASK-257: mDNS is permitted for address bootstrap, forbidden for content discovery.
    violations = violations + scan_mdns_wiring(roots)
    # TASK-258: the libp2p rendezvous PROTOCOL behaviour is forbidden outright; the Mainline
    # rendezvous is permitted for address bootstrap, forbidden for content discovery.
    violations = violations + scan_forbidden_protocols(roots)
    violations = violations + scan_rendezvous_wiring(roots)
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
        "scanned; CONTENT discovery is kad-EXCLUSIVE (no gossipsub/floodsub, no libp2p rendezvous "
        "PROTOCOL behaviour, and no mDNS/mainline-rendezvous region feeds "
        "find_providers/get_providers); mDNS and the Mainline rendezvous are permitted in the "
        "peer-ADDRESS bootstrap role; signed RelayHints and the NAT-traversal trio are permitted "
        "dial-assistance; auxiliary provider-keyed relay maps/caches remain forbidden"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
