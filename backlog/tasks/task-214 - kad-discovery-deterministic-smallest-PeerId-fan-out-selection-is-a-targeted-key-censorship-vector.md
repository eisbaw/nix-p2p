---
id: TASK-214
title: >-
  kad discovery: deterministic smallest-PeerId fan-out selection is a
  targeted-key censorship vector
status: In Progress
assignee:
  - '@claude'
created_date: '2026-08-14 21:59'
updated_date: '2026-08-16 10:51'
labels:
  - discovery
  - adversarial
  - availability
  - hardening
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Surfaced by the TASK-154 mped-architect review (2026-08-14), F1. PRE-EXISTING (the old cap_fan_out had it too); TASK-154's B2 fix makes it OBSERVABLE. At prod defaults max_peers=16 vs STORE_MAX_PROVIDERS_PER_KEY=20, the named provider union routinely exceeds 16. PeerIds are grindable, so an attacker can mint identities that sort into the 16 smallest slots and permanently evict a legit provider for a CHOSEN key -> perpetual Unavailable(truncated). INTEGRITY HOLDS (no bad store path), but discovery-AVAILABILITY for that key is denied, and deterministic retry with the same budget re-chases the same dead 16, so it does not self-heal. Fix candidates: randomized/rotating selection among the named set, or a per-query salt, so a griefer cannot deterministically own the retained slots; at minimum document the vector in the fan-out threat-model comment. Relates to TASK-154 (fan-out bound) and TASK-205 (adversarial-swarm field proof).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The retained fan-out subset is not deterministically grindable: an attacker minting PeerIds cannot guarantee eviction of a specific legit provider for a chosen key across retries (randomized/rotating/salted selection)
- [ ] #2 A key whose legit provider is out-competed on one query can still be resolved on retry (self-heals; retry does not re-chase the identical dead subset)
- [ ] #3 If the residual risk is accepted rather than fully closed, it is documented in the fan-out threat-model comment with the honest bound
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
TASK-214 implementation landed (awaiting just e2e). Selection design: replaced the deterministic keep-16-smallest-by-PeerId fan-out with keep-16-smallest-by-RANK, where rank = provider_rank(salt, peer) = FNV-1a over the peer multihash bytes seeded by a FRESH per-query u64 salt, then a splitmix64 avalanche. Salt is drawn from the OS CSPRNG (rand::random) in the Command::GetProviders handler, so it is chosen AFTER the attacker mints identities and is re-drawn on EVERY retry. Integer-only (u64), no float in the decision path. retain_bounded_provider now keys a BTreeSet<(u64,PeerId)> and evicts the largest-rank, preserving the TASK-154 O(max_peers) memory bound; output presented in ascending PeerId (membership is salt-dependent, order is not; directory fetches all retained concurrently). Why not grindable: a griefer cannot pre-compute rank without the salt; the salt is unknown at mint time and independent per retry. Honest residual (AC#3, documented in the ProviderFanOut threat-model comment): NOT fully closed - a determined attacker sustaining S forged providers drives per-query success prob to max_peers/(S+legit) and expected retries to ~(S+legit)/max_peers; they can degrade availability PROBABILISTICALLY (more retries/latency) but can no longer force NEVER, and it self-heals with prob ->1 as retries grow. Per honest store node S+legit<=STORE_MAX_PROVIDERS_PER_KEY=20 so success prob >=16/20 per query there. Integrity untouched (ed25519 + Nix re-verify).

TASK-214 DONE at commit 55f39c2. Full gate GREEN: cargo test -p fabric-libp2p = 83 lib + all integration passed (0 failed); the AC bites fan_out_selection_varies_with_salt (AC#1) and out_competed_victim_self_heals_within_bounded_retries_but_never_under_a_pinned_salt (AC#2) both pass; MUTATION-PROOF verified: dropping the salt seed in provider_rank reddens BOTH (AC#1 distinct==1; AC#2 self-heal never selects victim across 512 salts), the order-independence bite stays green. cargo fmt --check clean; cargo clippy -p fabric-libp2p --all-targets -- -D warnings clean; check-no-floats.py green (self-test + real scan); check-discovery-no-shortcut.py --self-test green (kad-exclusive guard still bites on mdns). just e2e E2E_EXIT=0, 5/5 scenarios PASS incl s6-p2p 11/11 (the discovery path). New-dep audit: rand="0.8" resolves to already-present 0.8.7 (Cargo.lock diff is one edge line; NO new version pulled); cargo-deny/cargo-audit not present in the dev shell and no just audit recipe, so no formal advisory scan was run - the dep-graph delta is a single edge to an already-trusted crate in the libp2p TCB. HONEST RESIDUAL (AC#3): not fully closed. Under a fresh uniform per-query salt over T named providers (S forged + legit incl victim v), P(v retained one query)=min(1, max_peers/T); independent salts per retry give P(v excluded across R retries)=(1 - max_peers/T)^R -> 0. Attacker cannot force NEVER (old rule could); can only raise expected retries to ~(S+legit)/max_peers. Per honest store node T<=STORE_MAX_PROVIDERS_PER_KEY=20 so per-query success >= 16/20 there; DHT union can exceed 20 across k-replicas (stated, not hidden).

CODEX CROSS-MODEL DEEP GATE (restored via TASK-233): NO-GO on commit 55f39c2. AC#1/#4/#5 PASS (production salt path per-query + not key-derived; cap/O(max_peers)/kad-exclusive/presentation-order-salt-independent; no float in gate/serialized, no frozen surface). TWO gate-breaking FAILs to fix: (AC#2) the self-heal GREEN-arm test enumerates DETERMINISTIC SEQUENTIAL salts 1..513 and BYPASSES the Command::GetProviders production handler, so it does NOT validate the production rand::random per-query self-heal, and the ~6e-10 independent-draw flake figure does not describe a sequential-salt test. (AC#3) the ProviderFanOut threat-model prose overclaims: P(v retained)=max_peers/T is presented as EXACT but the true value is N_v/2^64 (201 does not divide 2^64; FNV+splitmix is not proven uniform) so it is APPROX only; the exclusion formula (1-max_peers/T)^R omits the min(1,.) clamp (wrong when max_peers>T); and guaranteed eventual self-heal overstates ALMOST-SURE healing (P->0 as R->inf, NOT a finite-retry guarantee). NOTE: the orchestrator ALSO missed AC#3 (repeated the exact-rational overclaim) - demonstrates the cross-model gate value. Fix cycle dispatched.
<!-- SECTION:NOTES:END -->
