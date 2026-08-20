---
id: TASK-278
title: >-
  Bare --profile lan-share complete supply + reachability defaults (additive
  supply; default-listen decision)
status: Done
assignee: []
created_date: '2026-08-20 00:25'
updated_date: '2026-08-20 04:33'
labels:
  - usability
  - cornerstone
  - follow-up
dependencies:
  - TASK-273
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Root-causes codex finding #1 and completes the zero-config supply story that TASK-273 (narrowed to discovery-only) deliberately deferred. Absorbs TASK-276 (cross-host serving / lan-isolation).

Why: forcing announce-after-fetch selected an EXCLUSIVE store-supply mode that silently bypassed --libp2p-seed-nar and falsely reported seeded NARs. The fix is additive supply, not a default flip on a broken seam.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 install_provider is ADDITIVE: unions --libp2p-seed-nar + --libp2p-provide-store + announce-after-fetch dynamic supply; the startup report reflects the ACTUAL served set (no false count)
- [x] #2 INTERIM until additive lands: seed-nar together with announce-after-fetch FAILS CLOSED (never silently drops the seed)
- [x] #3 Biting test: (unit) a Config with --libp2p-seed-nar S + --libp2p-announce-after-fetch builds a union whose plan() answers for BOTH S and a provide-store P, report counts both; MUTATION restoring mode-select makes plan(S)=None -> RED. (e2e, in the DEFAULT just e2e set) one provider with BOTH seed-nar S AND announce-after-fetch: consumer-1 fetches S peer-served (upstream.nar==0), provider self-fetches P' -> announces -> consumer-2 fetches P'; MUTATION restoring mode-select -> the SEED fetch falls to upstream (attributable)
- [x] #4 Remove the interim seed+announce fail-closed (daemon-libp2p:651, daemon:1259) once additive lands; fix codex-LOW-#2 ordering so seed+announce reaches the additive install (not an earlier no-provider error)
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Part A only (Part B = listen relax -> TASK-276). Mark-emulator spec: the two supply modes are NOT structurally exclusive - Libp2pNarSupplier::plan returns Option (fabric-libp2p/src/nar.rs:1744). Union at the fabric supplier seam, NO AvailabilityIndex refactor (index only accepts StorePath, availability.rs:1434 - do NOT push seeds into it).
Add UnionNarSupplier(Vec<Arc<dyn Libp2pNarSupplier>>) in fabric-libp2p/src/nar.rs (plan = find_map over legs). Rewrite install_provider (daemon-libp2p/src/main.rs:1075 AND composite daemon/src/main.rs:1905) from mode-select to ADDITIVE: seed leg iff !seed_nar.is_empty() (MemoryNarSupplier + seed-size guard); store leg iff !provide_store.is_empty() || announce_after_fetch (AvailabilityIndex + provision-size guard + CatalogNarSupplier); supplier = UnionNarSupplier(legs); build fabric ONCE; one serve gate under one serve_budget; announce BOTH lists against the one fabric+readiness (seeds via announce_provider_seeds/public, provisions via announce_store_provisions/public - distinct content keys, no seq collision); announce-after-fetch hook over the store leg index. Both legs empty -> existing nothing-to-serve fail-closed. Fix BOTH report sites (daemon-libp2p:1672, daemon:2364) to count S seeds + P store paths + hook independently (no false count). Remove interim fail-closed. Wrinkles: both size-guards run; seed+store-in-one-boot durable-seq path is new (test must serve both); one node identity.
Gate: qa+mped+codex + FULL just e2e (cross-cutting supply change).
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
codex re-review confirmed finding #1 persists on the EXPLICIT announce-after-fetch path (main.rs:1059 store/grow mode reads only provide_store, bypasses seed_nar; false report main.rs:1650; composite daemon/src/main.rs:1891/2110/2350). Doing the INTERIM fail-closed now (seed_nar + announce-after-fetch together -> error, both binaries) as a 278 down-payment; full additive supply remains.

codex v3 LOW #2: when both --libp2p-seed-nar and --libp2p-announce-after-fetch are passed WITHOUT an explicit --libp2p-provider, an earlier validation (daemon-libp2p:640 / composite:1191) fails-closed FIRST, so the hazard-specific TASK-278 message is not shown (still safely fail-closed, just a less specific error). Fold into the additive-supply work.

TASK-278 Part A landed (commit caf735d). Additive union supply on both binaries: UnionNarSupplier in fabric-libp2p; install_provider/install_libp2p_provider rewritten from mode-select to a synchronous build_provider_supply (seed leg + store/announce leg) -> ONE fabric, ONE serve gate, both lists announced (distinct content keys). Both report sites count S+P+hook independently (no false count). Interim fail-closed removed on both binaries (seed+announce and seed+provide-store now valid); dead const removed; codex-LOW-#2 resolved. Unit tests (both binaries) + e2e scenario s10-libp2p-seed-and-grow added to the DEFAULT just e2e set. Unit MUTATION (restore mode-select) proven RED on daemon-libp2p union test, then reverted. Gate so far: cargo test 4 crates GREEN, cargo fmt GREEN, ruff GREEN, nix-instantiate GREEN. e2e honest run + mutation-attribution run in progress (long image build).

TASK-278 Part A VERIFIED. Gate results (actual): cargo test -p daemon-core -p daemon-libp2p -p daemon -p fabric-libp2p = ALL GREEN (composite daemon 55 incl 2 new additive tests + parse test flipped to accept; daemon-libp2p 47 incl 2 new additive tests + parse test flipped; fabric-libp2p union exported). cargo fmt --all --check GREEN; ruff check scripts GREEN; nix-instantiate --parse nixos/nix-p2p.nix GREEN. UNIT MUTATION (restore mode-select): daemon-libp2p union test RED at the seed oracle ("the union must serve the seeded NAR S"), reverted GREEN; composite mutation ALSO caught IN the e2e image build gate (daemon unit tests 2 failed, build aborted) - the unit oracle is load-bearing in the shipped build. E2E s10-libp2p-seed-and-grow (in DEFAULT just e2e set): HONEST run PASS 15/15 (37.6s) - B fetches static seed S peer-served upstream.nar==0 byte-identical AND A grows a distinct P that B fetches peer-served upstream.nar==0. E2E MUTATION (restore mode-select on composite, unit tests temporarily #[ignore]d to let the image build): FAIL 14/15 - the ONLY reddened check is "S10 SEED oracle: 0 upstream NAR egress" [upstream.nar=1] while ALL growth-leg checks stay GREEN => attributable to the SEED leg exactly as finding #1. Mutation + ignore markers reverted; git diff clean vs commit caf735d. Disk 30G free at end. NOT marking Done - orchestrator owns Done after qa+mped+codex + full-e2e re-gate.

codex DEEP re-review VERDICT_NO_GO: normal unique-input additive path CONFIRMED working both binaries + both size-guards + no seq collision, BUT edge-case contract violations. #1 HIGH: seed key also realized-through-self + GC-d -> reconcile withdraws held not announced -> discovery tombstoned (served-but-not-announced); #2 HIGH: public-share allowlisted-seed + non-allowlisted-provision publishes seed then aborts -> stale authz record (non-atomic cross-leg publish); #3 HIGH: duplicate CLI seed/NarHash over-counts report (supplier dedups) + double-announces; #4 HIGH: announce-after-fetch + budget 0 + no static supply reports "grows on demand" but never grows; #5 MED: profile-native lan-share+seed+announce fails without redundant --libp2p-provider (parse ordering); #6 LOW: UnionNarSupplier pub field; #7 LOW: S10 gaps (runs /bin/daemon not daemon-libp2p; never self-fetches the seed; announce assertion from log not report line). Routing arbitration to Mark-emulator.

TASK-278 codex parse-layer round landed (commit b5dc7e7 on HEAD caf735d). Applied on BOTH binaries: #3 reject duplicate NarHash fail-loud (within seed list, within provide-store list, or across the two) - makes report count honest by construction and ENFORCES the no-seq-collision claim; #4 reject --libp2p-announce-after-fetch with --libp2p-announce-budget 0 (grows nothing while report says "grows on demand"), keyed on the growth budget the hook consumes so a static-only provider with budget 0 is NOT caught; #6 UnionNarSupplier field made private + ::new() constructor (type-enforces no-enumeration; call sites updated). Corrected the "distinct content keys" comments to say the guarantee is now enforced by #3. Biting tests per binary (dup-across-lists -> Err naming hash; announce-after-fetch+budget0 -> Err; static+budget0 -> Ok precision). UNIT MUTATION (neutralize both guards on daemon-libp2p): the 2 reject tests RED, precision test stays green; reverted. Gate: cargo test -p daemon-core -p daemon-libp2p -p daemon -p fabric-libp2p GREEN (daemon-libp2p 58, daemon 50 incl new parse tests); cargo fmt GREEN; ruff GREEN; nix-instantiate GREEN. e2e s10-libp2p-seed-and-grow regression PASS 15/15 (37.5s) - unique inputs, guards do not fire. Did NOT touch TASK-279 items (#1/#2/#5/#7). Not marking Done - orchestrator owns Done after re-gate.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
DELIVERED (Part A: additive libp2p provider supply). UnionNarSupplier (fabric-libp2p/src/nar.rs, plan=find_map over legs, private field) lets a static seed leg + a store/announce-after-fetch leg COEXIST under one fabric/serve-gate on both binaries - root-causing the silent seed-drop where mode-select read only provide_store and falsely reported the seed count. Both report sites now count the ACTUAL served set (S seeds + P paths + hook) independently. Interim seed+announce fail-closed removed. Parse-layer fail-loud guards (codex must-fix): duplicate NarHash across seed/store REJECTED (honest count by construction); announce-after-fetch + zero growth budget REJECTED (never a silent 'grows nothing'); union field private (compile-time no-enumeration).

Gate: full just e2e 13/13 PASS (s10-libp2p-seed-and-grow 15/15, mutation-attributable to the seed oracle); cargo test all crates 0 failed; fmt/ruff/nix-parse clean. DEEP-gated qa+mped+codex; codex (cross-model) NO-GO caught real edge-cases mped GO'd past -> arbitrated: 3 cheap honesty must-fixes landed, 4 narrow state-machine/transaction/test items deferred to TASK-279 (none reintroduces the silent-drop; worst peer cost a TTL-bounded retry, inside TCB).

DEFERRED: TASK-279 (seed+announce same-key GC tombstone; public mixed-allowlist atomic publish; profile-native parse ordering; S10 daemon-libp2p coverage). Part B (private-LAN listen relax for cross-host serving) = TASK-276.

Commits: caf735d (additive union) + b5dc7e7 (parse-layer reject guards).
<!-- SECTION:FINAL_SUMMARY:END -->
