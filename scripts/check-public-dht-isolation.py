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

  POSITIVE INVARIANT (removing it BITES): the EXECUTABLE private-DHT wiring must
  be present in CODE, not merely mentioned in a comment, and the marker and the
  constructor must be CO-LOCATED IN THE SAME FILE. Concretely, over the
  COMMENT-STRIPPED source there must be ONE file that holds BOTH (a) a private,
  scope-namespaced `/nix-p2p/.../kad` protocol string literal AND (b) the explicit
  fully-qualified `kad::Behaviour::with_config(..)` constructor that pins a custom
  `kad::Config` (the only construction that can carry the private protocol). This is
  what catches the QUIET regression the forbidden-list cannot: swapping the explicit
  `kad::Behaviour::with_config(.., custom_protocol_config)` for the default
  `kad::Behaviour::new(..)` drops NO forbidden string into OUR source (the
  `/ipfs/kad/1.0.0` default lives inside the library), yet silently rejoins the
  public DHT.

  WHY CO-LOCATION is load-bearing (TASK-154 F2): an intermediate version aggregated
  the marker hits and the `with_config` presence GLOBALLY and checked them
  INDEPENDENTLY, so the invariant held merely because SOME file had a marker and SOME
  file had a `with_config`. That is bypassable: add a second, UNRELATED
  `kad::Behaviour::with_config` (a future behaviour, a test/probe helper) in any
  scanned file and swap the REAL kad ctor to `kad::Behaviour::new` - the marker
  lingers in its file, the unrelated `with_config` satisfies the global check, and
  the swap to the public DHT sails through. We now require the marker and the
  constructor to be found TOGETHER in one file, and match the constructor as the
  fully module-qualified `kad::Behaviour::with_config` specifically (not a bare
  `with_config` nor a bare `Behaviour::with_config`), so neither `MemoryStore::with_config`
  nor an unrelated behaviour's `with_config` can stand in for it.

  WHY comment-stripping is load-bearing (TASK-154 B4): an EARLIER version of this
  guard scanned the RAW text for the private marker, so the marker lingering in a
  `//` comment or `///` doc satisfied it even after the executable construction was
  swapped for `Behaviour::new` - the guard was theater ("oracle must bite by
  mutation" failure). We now strip comments BEFORE the positive scan so only a
  marker in real CODE counts, and we additionally require `with_config` so a lone
  unused marker literal cannot satisfy the invariant either. (The FORBIDDEN scan
  still runs over RAW text - a public protocol name is a violation wherever it
  appears, comment or not.)

THE BITE (AC#3's "a mutation enabling any substitute makes the proof fail"):
`--self-test` synthesises (1) a clean private-DHT composition and asserts it
PASSES; (2) a mutation adding `/ipfs/kad/1.0.0` and asserts it FAILS; (3) a
mutation adding `bootstrap.libp2p.io` and asserts it FAILS; (4) a source with the
executable construction swapped for `Behaviour::new` and asserts it FAILS; (5) the
TASK-154 B4 mutation - the private marker swapped for `Behaviour::new` but LEFT
LINGERING IN A COMMENT - and asserts it STILL FAILS (proving the comment-strip
bites); (6) the executable marker present in code but wired via `Behaviour::new`
instead of `with_config` and asserts it FAILS (proving the wiring, not just the
marker, is required); (7) the TASK-154 F2 global-noise bypass - the private marker
in one file with the kad ctor swapped to `Behaviour::new`, plus an UNRELATED
`kad::Behaviour::with_config` in a DIFFERENT file - and asserts it FAILS (proving
co-location, not mere global presence, is required). A guard that cannot be shown to
fail is not a guard.

PRIMARY vs SECONDARY (TASK-154 F2): this SOURCE scan is the CHEAP SECONDARY lint. The
PRIMARY, unbypassable AC#3 oracle is now a SEMANTIC Rust test,
`kad_speaks_only_the_private_scoped_protocol_never_the_public_ipfs_dht` in
`fabric-libp2p/src/swarm.rs`. That test calls the SINGLE production kad constructor
(`build_kad_behaviour`) and inspects `kad::Behaviour::protocol_names()` on the RUNTIME object,
asserting the private `/nix-p2p/<scope>/kad` protocol IS advertised and the public
`/ipfs/kad/1.0.0` is NOT. Because it binds to the constructed behaviour, not the source text,
the `Behaviour::with_config` -> `Behaviour::new` / `Config::default()` regression BITES there
regardless of any same-file source decoy (the bypass that defeated this text scan THREE times:
global -> file -> same-file). This scan remains only to catch the ACCIDENTAL / straightforward
re-enablement cheaply at lint time; it is NOT, and never was, an adversarial-proof oracle.

Limits, stated plainly: like its sibling this is a dependency-free substring
scan over comment-stripped source, so it catches an accidental or straightforward
re-enablement, not a determined obfuscation (an aliased import, a runtime-computed
protocol string, a raw-string-encoded marker); a determined developer defeats any source
lint (or simply deletes the guard) — that is what the semantic test above exists to catch.
The comment stripper handles line
/ block comments and ordinary string literals; it does not parse Rust.
It also does NOT prove the node cannot be TOLD (via explicit config) to dial a
public peer - `join_bootstraps` takes caller-supplied addresses by design
(TASK-168's explicit-peers model); this guard's job is only that no PUBLIC
entrypoint is BAKED IN and no PUBLIC DHT protocol is joined by default. And a
source-level invariant is not an adversarial FIELD proof: whether the private
DHT actually resists a determined eclipse is deferred to TASK-205's multi-node
harness.

Usage: check-public-dht-isolation.py [--self-test] [ROOT ...]
Exit codes: 0 clean, 1 a public-DHT / default-bootstrap enabler is present OR the
executable private-kad wiring (marker + `with_config`) is missing, 2 nothing was
scanned so nothing was proven.
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
# match the surrounding literal, not a fixed scope. At least one match must survive - IN
# COMMENT-STRIPPED CODE, not a comment - or the node has no proven-private DHT protocol.
PRIVATE_KAD_MARKER = re.compile(r"/nix-p2p/[^\"]*?/kad")

# The EXECUTABLE constructor that pins a CUSTOM kad::Config (and thus our private protocol).
# `kad::Behaviour::with_config(..)` is the ONLY construction that carries a non-default
# protocol; the default `kad::Behaviour::new(..)` silently uses `/ipfs/kad/1.0.0`. Requiring
# this in code means a swap to `Behaviour::new` fails the invariant even if a marker literal
# lingers (TASK-154 B4). Matched as `kad::Behaviour::with_config(..)` SPECIFICALLY - fully
# module-qualified, NOT a bare `with_config` nor a bare `Behaviour::with_config`, so neither the
# unrelated `MemoryStore::with_config(..)` (always present) NOR a future/unrelated OTHER
# behaviour's `with_config` can satisfy it and mask a swapped-out kad Behaviour constructor
# (TASK-154 F2). This pairs with the CO-LOCATION requirement in `scan` (marker and ctor must
# live in the SAME file), so a stray `kad::Behaviour::with_config` in a different file cannot
# vouch for a private marker stranded next to a swapped-in `Behaviour::new`.
KAD_WITH_CONFIG_MARKER = re.compile(r"kad::Behaviour::with_config\s*\(")


def strip_comments(text: str) -> str:
    """Return `text` with Rust line (`//`, `///`, `//!`) and block (`/* */`) comments removed,
    PRESERVING string literals (so a marker in a real string still counts) and replacing each
    stripped comment with a single space (so tokens on either side do not fuse).

    A small hand state machine, not a Rust parser: it tracks ordinary `"..."` strings (with
    `\\` escapes), raw strings (`r"..."`, `r#"..."#`), and char literals (`'x'`, `'\\n'`) just
    enough that a `//` or `/*` inside them is NOT treated as a comment, and a `"` inside a
    comment does NOT open a string. This covers the shipped source; it is deliberately not a
    full lexer (the guard's stated limit). Nested block comments are handled (Rust allows them).
    """
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        # Raw string: r"..." or r#..."...#  (skip verbatim, no escapes, may contain // and ")
        if c == "r" and (nxt == '"' or nxt == "#"):
            j = i + 1
            hashes = 0
            while j < n and text[j] == "#":
                hashes += 1
                j += 1
            if j < n and text[j] == '"':
                j += 1
                closer = '"' + "#" * hashes
                end = text.find(closer, j)
                end = n if end == -1 else end + len(closer)
                out.append(text[i:end])
                i = end
                continue
            # a bare `r` not opening a raw string
            out.append(c)
            i += 1
            continue
        # Ordinary string literal
        if c == '"':
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == '"':
                    j += 1
                    break
                j += 1
            out.append(text[i:j])
            i = j
            continue
        # Char literal: '\'' or 'a' or '\n'. Only treat as a char literal when it closes
        # quickly, so a lifetime tick (`'a` with no closing quote soon) is left alone.
        if c == "'":
            if nxt == "\\" and i + 3 < n and text[i + 3] == "'":
                out.append(text[i : i + 4])
                i += 4
                continue
            if nxt != "\\" and i + 2 < n and text[i + 2] == "'":
                out.append(text[i : i + 3])
                i += 3
                continue
            out.append(c)
            i += 1
            continue
        # Line comment
        if c == "/" and nxt == "/":
            j = text.find("\n", i)
            j = n if j == -1 else j
            out.append(" ")
            i = j
            continue
        # Block comment (nested-aware)
        if c == "/" and nxt == "*":
            depth = 1
            j = i + 2
            while j < n and depth > 0:
                if text[j] == "/" and j + 1 < n and text[j + 1] == "*":
                    depth += 1
                    j += 2
                elif text[j] == "*" and j + 1 < n and text[j + 1] == "/":
                    depth -= 1
                    j += 2
                else:
                    j += 1
            out.append(" ")
            i = j
            continue
        out.append(c)
        i += 1
    return "".join(out)


def scan(roots: list[Path]) -> tuple[list[str], int, bool, bool, bool]:
    """Return (violations, files_scanned, any_code_marker, any_kad_with_config, colocated).

    FORBIDDEN tokens are matched over RAW text (a public protocol string is a violation
    wherever it appears). The POSITIVE invariant (private marker + `kad::Behaviour::with_config`)
    is matched over COMMENT-STRIPPED code only - a marker in a comment does NOT count (TASK-154
    B4). Critically (TASK-154 F2) the marker and the constructor are tracked PER FILE and the
    invariant demands they be CO-LOCATED (both present in the SAME file, `colocated`), not merely
    both present SOMEWHERE in the scanned tree: aggregating them globally let an UNRELATED second
    `kad::Behaviour::with_config` in one file vouch for a private marker stranded in a DIFFERENT
    file whose real kad ctor had been swapped to `Behaviour::new`, so the AC#3 oracle did not bite
    that global-noise bypass. `any_code_marker` / `any_kad_with_config` are still returned so the
    verdict can name WHICH half is missing vs. merely un-colocated.
    """
    violations: list[str] = []
    scanned = 0
    any_code_marker = False
    any_kad_with_config = False
    colocated = False
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
            code = strip_comments(text)
            file_has_marker = PRIVATE_KAD_MARKER.search(code) is not None
            file_has_ctor = KAD_WITH_CONFIG_MARKER.search(code) is not None
            any_code_marker = any_code_marker or file_has_marker
            any_kad_with_config = any_kad_with_config or file_has_ctor
            if file_has_marker and file_has_ctor:
                colocated = True
    return violations, scanned, any_code_marker, any_kad_with_config, colocated


def _evaluate(roots: list[Path]) -> tuple[list[str], int]:
    """Full verdict: forbidden-token violations PLUS the missing / un-colocated-invariant checks."""
    violations, scanned, any_code_marker, any_kad_with_config, colocated = scan(roots)
    if scanned > 0 and not any_code_marker:
        violations.append(
            "no private /nix-p2p/<scope>/kad protocol marker found IN CODE (a marker only in "
            "a comment does not count) - the shipped kad path has no proven-private DHT "
            "protocol; a default `/ipfs/kad/1.0.0` preset would silently rejoin the PUBLIC "
            "IPFS DHT (invariant lost)"
        )
    elif scanned > 0 and not any_kad_with_config:
        violations.append(
            "the private /nix-p2p/<scope>/kad marker is present but NOT wired through an "
            "executable `kad::Behaviour::with_config(..)` - a swap to the default "
            "`Behaviour::new(..)` would rejoin the PUBLIC IPFS DHT while the marker literal "
            "lingers unused (the executable-wiring invariant is lost)"
        )
    elif scanned > 0 and not colocated:
        violations.append(
            "the private /nix-p2p/<scope>/kad marker and the executable "
            "`kad::Behaviour::with_config(..)` both appear in the scanned tree but are NOT "
            "CO-LOCATED in the SAME file - the marker sits in one file while the only "
            "private-kad constructor is in another, so the file that actually builds the kad "
            "Behaviour may have been swapped to the default `Behaviour::new(..)` (PUBLIC IPFS "
            "DHT) while an UNRELATED `kad::Behaviour::with_config` elsewhere masks the swap "
            "(TASK-154 F2 global-noise bypass)"
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

        # (5) TASK-154 B4 MUTATION: swap the construction for `Behaviour::new` but LEAVE the
        # private marker LINGERING IN A COMMENT. The OLD guard scanned raw text, so the comment
        # marker satisfied it and this PASSED (oracle theater). With comment-stripping the code
        # has no marker, so the missing-invariant arm MUST bite - this is the proof the strip
        # is load-bearing.
        (root / "clean.rs").write_text(
            "// builds the private /nix-p2p/v1/kad/1.0.0 protocol (do NOT use the ipfs default)\n"
            "/// The private /nix-p2p/<scope>/kad DHT this node joins.\n"
            "let kad = kad::Behaviour::new(peer_id, store);\n"
        )
        violations, _ = _evaluate(roots)
        if not any("no private /nix-p2p" in v for v in violations):
            print(
                "self-test FAILED: a private marker left ONLY in a comment (construction "
                "swapped to Behaviour::new) did NOT trip the guard - the comment-strip is not "
                "load-bearing and the oracle is theater (TASK-154 B4)",
                file=sys.stderr,
            )
            return 1

        # (6) TASK-154 B4 MUTATION: keep the EXECUTABLE marker literal in code AND the unrelated
        # `MemoryStore::with_config(..)` (as the shipped file has), but wire the kad Behaviour
        # through the default `Behaviour::new` instead of `Behaviour::with_config`. The
        # marker-in-code arm passes and a BARE-`with_config` matcher would be fooled by the
        # MemoryStore call - so this proves the wiring arm matches `Behaviour::with_config`
        # SPECIFICALLY and still bites (the marker + a MemoryStore::with_config are not enough).
        (root / "clean.rs").write_text(
            "let kad_protocol = StreamProtocol::try_from_owned(\n"
            '    format!("/nix-p2p/{scope}/kad/1.0.0"))?;\n'
            "let store = MemoryStore::with_config(peer_id, content_store_config());\n"
            "let kad = kad::Behaviour::new(peer_id, store);\n"
        )
        violations, _ = _evaluate(roots)
        if not any("executable `kad::Behaviour::with_config" in v for v in violations):
            print(
                "self-test FAILED: an in-code marker NOT wired through Behaviour::with_config "
                "(kad swapped to Behaviour::new, only MemoryStore::with_config left) did NOT "
                "trip the guard - the executable-wiring invariant is not enforced (TASK-154 B4)",
                file=sys.stderr,
            )
            return 1

        # (7) TASK-154 F2 GLOBAL-NOISE MUTATION: the AC#3 bypass the earlier guard missed. The
        # marker and the constructor were aggregated GLOBALLY and checked INDEPENDENTLY, so a
        # SECOND, UNRELATED `kad::Behaviour::with_config` ANYWHERE in a scanned path vouched for a
        # private marker stranded in a DIFFERENT file whose real kad ctor had been swapped to
        # `Behaviour::new` (PUBLIC IPFS DHT). Synthesise exactly that: file A carries the private
        # marker but builds kad via `Behaviour::new`; file B carries an UNRELATED
        # `kad::Behaviour::with_config` (a test/probe helper) with NO private marker. Under the OLD
        # global aggregation BOTH halves were independently satisfied and this PASSED (the bypass);
        # co-location requires the marker and the constructor IN THE SAME file, so it MUST bite.
        for stale in root.glob("*.rs"):
            stale.unlink()
        (root / "node.rs").write_text(
            "let kad_protocol = StreamProtocol::try_from_owned(\n"
            '    format!("/nix-p2p/{scope}/kad/1.0.0"))?;\n'
            "let store = MemoryStore::with_config(peer_id, content_store_config());\n"
            "let kad = kad::Behaviour::new(peer_id, store);\n"
        )
        (root / "probe_helper.rs").write_text(
            "fn make_probe_kad(peer: PeerId, store: MemoryStore) -> kad::Behaviour<MemoryStore> {\n"
            '    let cfg = kad::Config::new(StreamProtocol::new("/probe/kad/1.0.0"));\n'
            "    kad::Behaviour::with_config(peer, store, cfg)\n"
            "}\n"
        )
        violations, _ = _evaluate(roots)
        if not any("CO-LOCATED" in v for v in violations):
            print(
                "self-test FAILED: a private marker in one file with the kad ctor swapped to "
                "`Behaviour::new`, plus an UNRELATED `kad::Behaviour::with_config` in ANOTHER "
                "file, did NOT trip the guard - the global-noise bypass survives and AC#3 is "
                "bypassable (TASK-154 F2)",
                file=sys.stderr,
            )
            return 1

        print(
            "check-public-dht-isolation: self-test OK - a private-DHT composition passes; "
            "adding '/ipfs/kad/1.0.0' BITES; baking in 'bootstrap.libp2p.io' BITES; "
            "dropping the private /nix-p2p kad marker BITES; a marker left only in a COMMENT "
            "BITES (comment-strip proven); an in-code marker not wired through with_config "
            "BITES (executable-wiring proven); a private marker and an UNRELATED "
            "kad::Behaviour::with_config split across DIFFERENT files (kad ctor swapped to "
            "Behaviour::new) BITES (co-location proven) - AC#3 + TASK-154 B4 + F2 mutations caught"
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
