---
id: TASK-279
title: libp2p additive-supply edge-case hardening (post-278 codex NO-GO residuals)
status: Done
assignee: []
created_date: '2026-08-20 03:49'
updated_date: '2026-08-20 18:27'
labels:
  - hardening
  - follow-up
dependencies:
  - TASK-278
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Deferred edge-case findings from the codex DEEP re-review of TASK-278 Part A (Mark-emulator arbitrated: none reintroduces the silent-drop, none puts a bad byte/store path on the wire, worst peer cost is a TTL-bounded retry -> inside TCB, filed as hardening while the normal additive path ships).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 codex #2 (public mixed-allowlist non-atomic publish; TRANSACTION): on public-share, authorize EVERY leg (seeds AND provisions) against the TASK-103 allowlist BEFORE announcing ANY record; on any refusal no record is published (or every published record is withdrawn before Err). Biting test: after the induced P-refusal, a kad get_providers for the allowlisted seed S returns nothing; mutation restoring announce-before-full-authz => S lingers to TTL
- [x] #2 codex #7 (S10 e2e coverage): add a daemon-libp2p variant (thin binary additive path e2e-covered, not unit-only); drive the provider to SELF-FETCH the static seed through its own daemon (seed proven SERVED from the union under real fetch, not merely announced); assert the additive REPORT LINE in the provider log; correct the S10 docstring + SEED-PRESENCE comment to state the mutation reddens the SERVE oracle (0 upstream), not the announce-presence oracle
- [x] #3 codex #1 (seed/hook shared-key GC tombstone; STATE MACHINE): a node with a static seed for NarHash H that ALSO self-realizes+announces H via announce-after-fetch, then GCs that store path, MUST NOT tombstone the durable seed leg's announce -- discoverability for H holds WITHIN the signed record TTL (until the record expires or is re-announced). Fix (option a): the announce-after-fetch hook refuses to grow/track/withdraw a seed-owned NarHash (Begin::SeedOwned, checked first+total in begin). Biting unit tests: seed-owned key classified SeedOwned + never withdrawn after store-GC, RED under pre-fix code. SCOPE NOTE: periodic seed-record re-sign BEFORE signed-TTL expiry is a separate pre-existing seed-durability gap -> TASK-285 (HIGH).
- [x] #4 codex #5 (profile-native parse ordering; NORTH-STAR path): --profile lan-share --libp2p-seed-nar S --libp2p-announce-after-fetch with NO explicit --libp2p-provider MUST succeed on the THIN daemon-libp2p (zero-config NORTH-STAR) binary -- the lan-share provider back-fill runs BEFORE the announce-after-fetch companion check. The composite daemon is flag-authoritative BY DESIGN (requires explicit --libp2p-provider + --libp2p-listen; daemon/src/main.rs:1188,1245) and loud-rejects the combo; composite zero-config parity -> TASK-286 (LOW). Biting test on the thin binary: parse this exact argv => provider with announce_after_fetch on; mutation restoring the old ordering => Err.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
IN PROGRESS (implementer): AC#1/#2/#3 committed edb5cf2, each mutation-proven RED. AC#1 state machine: announce-after-fetch hook now refuses to grow/track/withdraw a NarHash owned by the durable memory-resident seed leg (Begin::SeedOwned checked first in begin), closing the GC-tombstone-over-seed-leg-announce defect. AC#2 transaction: authorize_public_supply authorizes seeds+provisions before any announce (all-or-nothing); both binaries route the public plan through announce_public_supply. AC#3 parse: lan-share provider back-fill moved before the announce-after-fetch companion check. Gate: cargo test 4 crates green; fmt/ruff/nix-parse clean. AC#4 (e2e) harness edits done (oracle-honesty corrections + full report-line assert + thin-binary s10 variant registered); s10 composite+thin container run in progress.

DELIVERED (implementer; orchestrator owns Done + DEEP re-gate). Commits: edb5cf2 (AC#1/#2/#3), 14d2ee1 (AC#4). All 4 ACs implemented+verified; 3 mutation-RED proofs done+restored. s10 composite 15/15 PASS + s10-thin 15/15 PASS. PREMISE NOTES: AC#1/#2 premises REAL (defects existed on the shipped path). AC#3 REAL for the THIN binary; for the COMPOSITE daemon the premise is N/A - it has NO lan-share zero-config back-fill at all (requires explicit --libp2p-provider + --libp2p-listen at parse by design), so there is no back-fill to reorder; the fix+test target the thin NORTH-STAR binary. AC#4 self-fetch phrasing reconciled: a node cannot libp2p-fetch its OWN announced content, so the seed serve-proof is B cross-node fetch (STEP1, 0 upstream). FINDING: LIBP2P-PROVIDER-ADDR marker drift (composite listen= vs thin addrs=); harness now accepts both, but the binaries should be unified (follow-up).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
DELIVERED (DEEP-gated: qa + mped-architect + codex cross-model + Mark-emulator arbitration; GO on the honesty-corrected tree). Two real defects fixed and mutation-proven: AC#1 GC-tombstone (SeedOwned guard, checked first+total in begin, so a store-GC can never withdraw the durable seed leg's announce) and AC#3 thin-binary parse ordering (lan-share provider back-fill before the announce-after-fetch companion check). AC#2 authorize-all-before-announce atomicity holds + the empty-leg fallible-readiness footgun fixed (empty approved leg skips phase-2 capture, biting test empty_legs_skip_the_fallible_phase2_readiness_capture RED-without/GREEN-with). AC#4 e2e on BOTH binaries: s10 composite 15/15 + thin 15/15, oracles firing under kill-A controls (additive report line, seed-serve 0-egress cross-node fetch, growth-serve 0-egress). Comment honesty fixed (phase-2 failures are not 'only network errors'). Commits: edb5cf2 (AC#1/2/3) + 14d2ee1 (AC#4 e2e) + c4c1a2a (empty-leg guard + comment + clippy unblock) + ffeb1d1 (ruff-format 4 pre-existing-drifted scripts to reach just lint green). Gate at HEAD ffeb1d1: just lint exit=0 (independently re-derived; ruff-format-check + clippy both cleared), libp2p e2e subset s7/s8/s9/s10/s10-thin all PASS. SCOPE NARROWED (Mark-emulator, out-of-279): AC#1 seed-record TTL re-sign before signed-TTL expiry (pre-existing north-star durability gap) -> TASK-285 (HIGH); AC#3 composite zero-config parity (composite is flag-authoritative by design) -> TASK-286 (LOW). FILED residuals: phase-2 general post-publish non-atomicity (TTL-bounded, in-TCB) -> TASK-287 (LOW); gate-integrity (just lint shipped RED masked by clippy short-circuit; TASK-283 LIGHT-gate escape) -> TASK-288 (LOW). AC texts corrected to the guarantee the code actually delivers (no 'for H'/'both binaries' overclaim).
<!-- SECTION:FINAL_SUMMARY:END -->
