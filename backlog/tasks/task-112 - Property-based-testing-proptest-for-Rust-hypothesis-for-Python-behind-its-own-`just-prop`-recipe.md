---
id: TASK-112
title: >-
  Property-based testing (proptest for Rust, hypothesis for Python) behind its
  own `just prop` recipe
status: To Do
assignee: []
created_date: '2026-08-10 21:39'
updated_date: '2026-08-17 17:39'
labels: []
dependencies:
  - TASK-46
  - TASK-55
  - TASK-119
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The suite is entirely example-based: every test names the inputs it tries. That finds the cases someone thought of. The parsers, encoders and round-trips in this repo are exactly the shape where property testing finds the ones nobody thought of - NAR framing, narinfo parse/rewrite, the claim wire format, safe_key, HTTP framing.

WHAT EXISTS TODAY. Nothing property-based. daemon/src/narinfo_cache.rs:715 says so deliberately: 'reproducible - no rand/proptest dependency, no Date/entropy flakiness'. That instinct was RIGHT and must be preserved, not overruled - see the determinism constraint below.

CANDIDATE PROPERTIES, chosen because each is a round-trip or an invariant rather than a restatement of the implementation:
  RUST (proptest)
  * synth/parse NAR: parse(render(x)) == x for arbitrary file contents, and parse REJECTS arbitrary byte strings that are not valid NARs (both directions, or the first is vacuous).
  * narinfo: rewrite(rewrite(x)) == rewrite(x) (idempotence), and unknown fields survive a rewrite+frame round-trip byte-identically. task-13 already fuzzes this with a hand-rolled 5k loop - a property test states the claim instead of sampling it.
  * claim wire: decode(encode(c)) == c across arbitrary claims, and decode fails closed on arbitrary bytes. Note task-110 is about a MISSING COUNT CAP on Have.offers - a generator that produces large offer vectors is exactly how that class is found.
  * safe_key: the nix-base32 alphabet + length-32 rule holds for arbitrary input, and no input escapes the cache root (task-13 fuzzes containment with a 20k loop; the property is 'resolved path is always under root').
  * HTTP framing: for arbitrary header sets, the servable predicate never accepts a response whose framing is ambiguous (TE + conflicting Content-Length is already a fixed bug - a property would have found it).
  PYTHON (hypothesis)
  * scalefit: fitting a known law recovers its class; a permuted/labelless report is REJECTED.
  * the measurement counting rule: egress accounting is additive over arbitrary run splits.
  * flake_rate.classify: arbitrary (exit code, output) never yields PASS unless exit==0 - the 127-as-green trap, stated as a property.

THE DETERMINISM CONSTRAINT - the whole reason this needs its OWN recipe. task-109 has just brought the gate from a 45% failure rate to 0/20 under load, and TESTING.md now forbids certifying 'test 0' from a non-deterministic gate. Dropping randomized tests into `just test` would reintroduce exactly what was removed. So:
  * `just test` runs property tests with a FIXED seed and a small case count - deterministic, fast, still a real bite.
  * `just prop` runs many cases with a free seed - the exploration mode, run deliberately, not on every cycle.
  * Any failure MUST print a reproducer (proptest's .proptest-regressions file, hypothesis's @example), and the shrunk counterexample gets committed as a NAMED example test. A property failure that cannot be replayed is a rumour.

PREREQUISITES, both real:
  * proptest is a new workspace dev-dependency; check it against scripts/check-independence.py's convergence denylist before adding.
  * pythonEnv in flake.nix currently has ONLY cryptography and blake3, so hypothesis must be added there. hypothesis does NOT require pytest - it can be driven from the existing '--self-test' convention the scripts already use, so this does not drag a test framework into the repo.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A `just prop` recipe exists, is documented in the Justfile with a one-line summary, and is listed in README/TESTING.md alongside the other gates
- [ ] #2 `just test` runs property tests with a FIXED seed and bounded cases, and the full-suite flake rate re-measured with scripts/flake_rate.py is unchanged (still 0 failures at N>=20 under the task-109 load)
- [ ] #3 At least 3 Rust properties and 2 Python properties are implemented, each proven to BITE by mutation (break the invariant, show the property catches it) - a property that cannot fail is decoration
- [ ] #4 Every property failure prints a reproducer, and the shrunk counterexample is committed as a named example test
- [ ] #5 proptest checked against check-independence.py's denylist; hypothesis added to flake.nix pythonEnv without pulling in pytest
- [ ] #6 STATED HONESTLY: which properties were considered and REJECTED as restatements of the implementation rather than independent claims
- [ ] #7 Cross-backend properties generate claims/discovery outcomes/offers containing Iroh and BitTorrent kinds and assert bounded round-trip, at-most-one-offer-per-frozen-kind, explicit registry dispatch and unknown-kind behavior.
- [ ] #8 BitTorrent properties cover NarHash/RawNar-to-metainfo/infohash determinism, piece partition boundaries and malformed/oversized metadata; Iroh properties cover codec negotiation/raw fallback and decompressed-size bounds.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
RE-SCOPED (COMPASS 2026-08-17, post-TASK-202). AC#7 (Iroh+BitTorrent cross-backend properties) and AC#8 (BitTorrent metainfo/infohash + Iroh codec) are DEFERRED-PENDING-202 (iroh OPTIONAL, BT tournament deferred) — do NOT implement now; Done is Done-with-#7/#8-residual, re-file when iroh/BT un-parks. This task now targets the SHIPPED surfaces only: AC#3 (>=3 Rust + 2 Python properties, each mutation-proven) should cover the FROZEN CLAIM WIRE round-trip (decode(encode(claim))==claim; decode FAILS-CLOSED on arbitrary/truncated/oversized bytes; the MAX_OFFERS_PER_ANSWER count cap + the MAX_OFFER_WIRE_BYTES per-offer byte cap hold for generated offer vectors; unknown-kind tolerate-but-inert), RawNarV1/NAR, narinfo parse, safe_key, and the hand-rolled HTTP framing. This property class would STRUCTURALLY close the 110->223->224->227 enumeration family that has cost ~9 cumulative codex NO-GO rounds by hand. AC#1-#6 unchanged.
<!-- SECTION:NOTES:END -->
