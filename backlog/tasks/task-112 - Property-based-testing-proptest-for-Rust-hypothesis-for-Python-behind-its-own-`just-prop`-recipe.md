---
id: TASK-112
title: >-
  Property-based testing (proptest for Rust, hypothesis for Python) behind its
  own `just prop` recipe
status: Done
assignee:
  - '@claude'
created_date: '2026-08-10 21:39'
updated_date: '2026-08-17 20:02'
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
- [x] #1 A `just prop` recipe exists, is documented in the Justfile with a one-line summary, and is listed in README/TESTING.md alongside the other gates
- [ ] #2 `just test` runs property tests with a FIXED seed and bounded cases, and the full-suite flake rate re-measured with scripts/flake_rate.py is unchanged (still 0 failures at N>=20 under the task-109 load)
- [x] #3 At least 3 Rust properties and 2 Python properties are implemented, each proven to BITE by mutation (break the invariant, show the property catches it) - a property that cannot fail is decoration
- [x] #4 Every property failure prints a reproducer, and the shrunk counterexample is committed as a named example test
- [x] #5 proptest checked against check-independence.py's denylist; hypothesis added to flake.nix pythonEnv without pulling in pytest
- [x] #6 STATED HONESTLY: which properties were considered and REJECTED as restatements of the implementation rather than independent claims
- [ ] #7 Cross-backend properties generate claims/discovery outcomes/offers containing Iroh and BitTorrent kinds and assert bounded round-trip, at-most-one-offer-per-frozen-kind, explicit registry dispatch and unknown-kind behavior.
- [ ] #8 BitTorrent properties cover NarHash/RawNar-to-metainfo/infohash determinism, piece partition boundaries and malformed/oversized metadata; Iroh properties cover codec negotiation/raw fallback and decompressed-size bounds.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
RE-SCOPED (COMPASS 2026-08-17, post-TASK-202). AC#7 (Iroh+BitTorrent cross-backend properties) and AC#8 (BitTorrent metainfo/infohash + Iroh codec) are DEFERRED-PENDING-202 (iroh OPTIONAL, BT tournament deferred) — do NOT implement now; Done is Done-with-#7/#8-residual, re-file when iroh/BT un-parks. This task now targets the SHIPPED surfaces only: AC#3 (>=3 Rust + 2 Python properties, each mutation-proven) should cover the FROZEN CLAIM WIRE round-trip (decode(encode(claim))==claim; decode FAILS-CLOSED on arbitrary/truncated/oversized bytes; the MAX_OFFERS_PER_ANSWER count cap + the MAX_OFFER_WIRE_BYTES per-offer byte cap hold for generated offer vectors; unknown-kind tolerate-but-inert), RawNarV1/NAR, narinfo parse, safe_key, and the hand-rolled HTTP framing. This property class would STRUCTURALLY close the 110->223->224->227 enumeration family that has cost ~9 cumulative codex NO-GO rounds by hand. AC#1-#6 unchanged.

IMPLEMENTED (RE-SCOPED, shipped surfaces only; AC#7/#8 left unchecked, deferred-pending-202).

WHAT LANDED
- just prop recipe (free seed + many cases), documented in Justfile + README + TESTING.md (AC#1).
- just test now also runs the SAME properties at a FIXED seed + bounded cases: Rust proptest via daemon-core prop_support::runner (deterministic ChaCha seed, 64 cases default); Python via scripts/prop_tests.py --check (derandomize, database=None). Determinism knobs use the PROPTEST_ prefix (PROPTEST_FREE_SEED / PROPTEST_CASES) because check-source-guard bans dev-shell NIX_P2P_ vars from shipped src (unset in the Nix sandbox).
- 5 Rust properties (daemon-core, proptest) + 3 Python properties (hypothesis), each MUTATION-PROVEN to bite (AC#3).
- proptest added as daemon-core DEV-dependency (out of every shipped closure); hypothesis added to flake.nix pythonEnv, NO pytest (driven by --check/--explore like the other scripts) (AC#5).
- Cargo.lock delta is MINIMAL: proptest + 7 transitive deps ADDED, ZERO existing crate versions bumped (an earlier cargo generate-lockfile bumped 42 unrelated crates; reverted to a plain cargo resolve).

RUST PROPERTIES + their MUTATION (red under mutation / green restored):
1. prop_claim_wire_roundtrips: decode(encode(claim))==claim over generated valid claims. MUT: deserialize_optional_known_payload always returns None -> RED.
2. prop_hold_response_roundtrips: decode(encode(response))==response. MUT: keep_known_offers drops one offer (.skip(1)) -> RED.
3. prop_oversize_valid_claim_is_rejected_by_the_size_cap + prop_decoders_never_panic_on_arbitrary_bytes (fail-closed): a padded-but-VALID claim over MAX_CLAIM_WIRE_BYTES is refused; arbitrary bytes never panic. MUT: remove check_size from decode_claim -> RED.
4. prop_over_count_offers_are_rejected: over-MAX_OFFERS_PER_ANSWER offer count rejected. MUT: MAX_OFFERS_PER_ANSWER 4->4096 -> RED. prop_over_byte_cap_offer_is_rejected: over-MAX_OFFER_WIRE_BYTES per-offer rejected. MUT: offer_within_byte_cap comparison disabled -> RED. (This pair STRUCTURALLY closes the 110->223->224->227 enumeration-family caps.)
5. prop_safe_key_containment_and_acceptance (narinfo_cache): an ACCEPTED cache key can never contain / . or NUL (path-containment), and acceptance <=> exact STORE_HASH_LEN + all nix-base32. MUT: len guard != 32 changed to == 0 -> RED (accepted a 33-byte key).
Named example_* tests committed for each shrunk counterexample (AC#4).

PYTHON PROPERTIES + MUTATION:
1. prop_classify_pass_iff_exit_zero: flake_rate.classify never returns PASS unless exit==0 (the 127-as-green trap). MUT: classify returns PASS on 127 -> Falsifying example.
2. prop_narinfo_parse_after_format_is_identity: parse_narinfo(format_narinfo(pairs))==pairs. MUT: parse reverses order -> Falsifying example.
3. prop_narinfo_rejects_a_line_without_a_separator: a non-blank line with no ": " must raise ValueError (fail-closed). MUT: raise -> continue -> Falsifying example.

AC#6 REJECTED as mere restatements (not independent claims):
- NarHashKey::from_raw_nar(b) == sha256(b): re-runs the implementation (it IS sha256).
- KnownTransport::to_offer / wire_tag equalities: restate the match arms (already covered by an existing assertion test).
- Python fixturelib.nix_base32 length == (len*8-1)//5+1: copies the impl formula; used the narinfo round-trip (an independent claim) instead.
- format_narinfo == "".join(...): restatement; the round-trip THROUGH parse is the real claim.
- classify(0,out)==PASS direction: the impl's first line; kept only the CONVERSE (PASS => exit 0) as the load-bearing fail-closed claim.

GATE (nix dev shell, final minimal lock):
- just prop: GREEN (7 Rust props at free seed + 1024 cases; hypothesis explore 2000 examples).
- just test: GREEN (7 prop_ + 4 example_ tests; golden vectors BYTE-IDENTICAL blake3:95f49df0... / sha256:06rgb4...; prop_tests --check green).
- just lint: GREEN (clippy -D warnings incl. test code; fmt; ruff; check-independence; check-no-floats; check_shaping; source-guard; discovery/dht guards).
- just audit: GREEN (advisories/bans/licenses/sources ok - proptest tree clean).
- check-golden-vectors: BYTE-IDENTICAL (frozen wire untouched).
- Property-tests-only flake_rate.py N=20, 14 workers: 20/20 PASS, 0 failures (deterministic under load).
- just e2e NOT run: no runtime/serving-path change (property tests + recipes only); the fixed-seed suite is deterministic and e2e oracles are unaffected.

AC#2 - HONEST STATUS (left UNCHECKED): the FIXED-seed + bounded-cases half is DONE and the property tests themselves are 0/20 under the 14-worker load (deterministic, proven). BUT the full-suite flake_rate.py N=20 measured 10/20 FAILURES - and EVERY failure is a PRE-EXISTING load-sensitive iroh/daemon timing test (iroh_publication_authority clock-rollback x3, provider_reachable_only_via_relay_circuit x2, forced_shutdown/shutdown/dropping fixed-port-release x3, serve_deadline, discovery-only), NONE of them property tests, ALL in crates this task did not touch (daemon/fabric-iroh), and the lock is version-identical to HEAD apart from the additive proptest dep - so this change did NOT regress them. The rate reflects the SHARED host running at load ~31-33 (other tenants ~17 ambient + 14 burners = ~2.3x oversubscription), ABOVE TASK-109's idle-host 2x baseline. A clean full-suite 0/20 needs an OTHERWISE-IDLE host, which this shared box was not; re-confirm the TASK-109 baseline on an idle host before checking #2. Orchestrator owns that call.

DONE-with-residual (LIGHT gate). Commit 57dcdf7. 5 Rust + 3 Python properties, all mutation-proven; the enumeration-family caps (prop_over_count_offers + prop_over_byte_cap) now STRUCTURALLY covered (structural net over the 110->223->224 hand-hardening). AC#1/#3/#4/#5/#6 met; AC#2 property-half done (0/20 deterministic) - full-suite idle-host re-confirmation deferred (full-suite 10/20 is PRE-EXISTING load-sensitive iroh/daemon timing, NOT property tests, NOT a 112 regression: version-identical lock + untouched crates); AC#7/#8 deferred-pending-202. Cargo.lock minimal (0 bumped); golden byte-identical; just prop/test/lint/audit green.
<!-- SECTION:NOTES:END -->
