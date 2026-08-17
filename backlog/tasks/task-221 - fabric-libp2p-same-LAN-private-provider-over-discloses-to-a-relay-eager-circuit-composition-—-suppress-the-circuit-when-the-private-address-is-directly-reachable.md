---
id: TASK-221
title: >-
  fabric-libp2p: same-LAN private provider over-discloses to a relay (eager
  circuit composition) — suppress the circuit when the private address is
  directly reachable
status: Done
assignee:
  - '@claude'
created_date: '2026-08-15 19:08'
updated_date: '2026-08-17 17:36'
labels:
  - libp2p
  - fabric
  - nat
  - privacy
  - hardening
dependencies:
  - TASK-218
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-218 composes a relay /p2p-circuit dial-candidate (and records a Relay disclosure to the relay operator) whenever kad can only place a provider at a PRIVATE (RFC1918)/link-local address. A provider on the consumers OWN LAN is ALSO directly reachable at that private address, so composing a circuit + disclosing to a relay for it is unnecessary over-disclosure (lookup-leakage is a tracked PRD privacy axis). Root: the consumer cannot distinguish a same-LAN private address (directly reachable) from a cross-NAT private address (needs a relay) from the address alone. TASK-218 deliberately accepts this (the real-NAT cornerstone, nat-vm-test 192.168.x provider, depends on composing for private addresses) and documents it in fabric-libp2p/src/locator.rs. Candidate resolutions: probe the direct private dial first and only compose/disclose the circuit on direct-dial failure (fallback, not eager); or scope by observed local subnet. Do NOT weaken kad-exclusive discovery or the no-injection guard. Distinct from TASK-219 (which is about discovering an UNKNOWN relay in multi-relay deployments); this is about SUPPRESSING an unnecessary circuit for a directly-reachable private provider.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A provider reachable directly at a same-LAN private address does NOT compose a relay circuit and records NO Relay disclosure, while a cross-NAT private provider (nat-vm-test 192.168.x) STILL composes; proven by a test that distinguishes the two
- [ ] #2 kad-exclusive discovery and check-discovery-no-shortcut.py are not weakened
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
TASK-221 IMPLEMENTED (commit 2ee2b2b, NOT pushed; In Progress - DEEP gate pending, orchestrator owns AC/Done).

RESOLUTION CHOSEN: (a) direct-dial-first / bounded probe, over (b) subnet-scoping. Why: (a) decides reachability by OBSERVATION, so it has NO RFC1918-collision hazard (two NATs numbering LANs identically) that a subnet heuristic would - and (b) would need per-interface netmasks and still be ambiguous for a cross-NAT provider numbered in the consumer subnet, a cornerstone-breaking direction codex would rightly flag. Tradeoff (honest): (a) adds a bounded direct-dial-probe latency (integer 2000ms) to a genuinely cross-NAT LOCATE; negligible vs the nat-vm 600s convergence budget; public/loopback/addressless providers never pay it; a too-short budget only forgoes the privacy win (falls back to composing), never the cornerstone.

CHANGED: fabric-libp2p/src/swarm.rs adds SwarmHandle::probe_direct_reachable(peer, targets, budget) - fast-path if already ConnPath::Direct, else dial each target and poll connection_path until Direct or budget; dials ONLY direct targets (a relayed conn reads as ConnPath::Relay, never a false positive). fabric-libp2p/src/locator.rs: a private-only provider is now PROBED; compose+record folded into one compose_and_record_circuit so NO circuit composed <=> NO Relay disclosure. transport.rs + B2 oracle UNTOUCHED.

BITES (mutation-proven):
1 (privacy, ledger-asserted): directly_reachable_provider_records_no_relay_disclosure - reachable => empty circuit + ZERO Recipient::Relay entries. MUTATION revert-to-eager-compose => reddens (only that test).
2 (cornerstone): probe_returns_false_bounded_for_an_unreachable_provider - unreachable => false, and the decision test composes+records one Relay. MUTATION over-suppress (return true on timeout) => reddens. nat-vm AC#1 byte-fetch + B2 still green.
3 (bounded): probe honours integer budget; unreachable elapsed in [budget, budget+3s].

GATE (actual, nix dev shell): cargo test --workspace exit 0 (fabric-libp2p 88 lib incl 4 new disclosure + 2 new probe tests; nat_dht_resolve/nat_traversal green). fmt --check OK; clippy --workspace --all-targets -D warnings clean. no-floats rc0; golden-vectors BYTE-IDENTICAL rc0; discovery-no-shortcut rc0 (kad-EXCLUSIVE + no-injection intact). just audit rc0. just e2e ALL 9 scenarios PASS incl s6-p2p 11/11 (HIT=MISS+1 preserved; loopback records no Relay) - one prior run hit a FLAKY iroh fixed-port TOCTOU (iroh_node_lookup shutdown_..._releases_its_fixed_iroh_port, port bind race, unrelated to this libp2p change), green on retry. nat-vm-test PASSED (KVM): AC#1 nodeb fetched byte-identical THROUGH the relay (probe of 192.168.2.3 fails since the direct path is B1-blocked, so the circuit still composes - resolved set carries BOTH the direct private addr and the /p2p-circuit); B2 POSITIVE + LOAD-BEARING with relay-down attribution (NAR fetch UNREACHABLE, no DCUtR upgrade, provider MainPID unchanged).

HONEST LIMITS: same-LAN suppression (probe TRUE for a reachable private addr) is proven by the ledger unit bite + the probe-reachable swarm test, NOT end-to-end in the VM (an in-process/VM host cannot bind a reachable RFC1918 addr hermetically); the nat-vm proves only the cross-NAT NON-suppression (probe FALSE). A same-LAN VM subtest is the fuller proof and could be added under nat-vm if a same-vlan provider is wired. Justfile e2e-nat-vm recipe comment is stale (pre-218 wording) - left untouched (TASK-218 surface, not this task).

TASK-221 DEEP-gate F1-F5 ADDRESSED (commit 6a17b8e on top of 2ee2b2b; NOT pushed; still In Progress - orchestrator owns AC/Done). codex NOGO + mped GO both agreed safety-by-construction is sound; NOGO was test-coupling + invariant-completeness + edges.

F1 (PRIMARY - coupling): provenance 2 is now ONE method Libp2pNodeLocator::circuit_provenance (probe -> reachability verdict -> compose? -> record?). New locator::circuit_provenance_tests drive it over a LIVE consumer swarm: an UNREACHABLE private provider (192.0.2.9 TEST-NET-1) makes the REAL probe return false -> composes circuit + records Relay. MUTATION in the CALLER (force verdict true / skip probe -> suppress) => the unreachable provider gets NO circuit + NO disclosure => the F1 test REDDENS (shown), and ONLY that test. The old test fed a literal false and could not catch caller suppression.

F2 (completeness - HANDLED + assessed): "circuit <=> disclosure" is now END-TO-END. The single Relay record is taken over the UNION of the resolved dial set (dht_addrs + composed), and addr_is_directly_reachable now returns false for ANY /p2p-circuit (a public-relay circuit can no longer skip the probe/compose and dodge disclosure). Assessment vs the FROZEN schema: a DHT-provided circuit locator is STRUCTURALLY IMPOSSIBLE today - ProviderRecord carries NO dial address (only provider NodeId + TransportOffer, whose only variants are Iroh{node} / BitTorrent{infohash}), and kad peer-routing drops the /p2p-circuit addr (TASK-218 diagnosis). So this is defense-in-depth that keeps the invariant true if kad address handling or the offer schema changes; not overstated (the code comment says exactly this). Coupled test: a DHT-provided circuit records a disclosure even when we compose nothing; MUTATION (record only over composed, not union) => reddens.

F3 (dcutr edge - documented, chose MINIMUM): circuit_provenance carries a precise comment - a relay circuit hole-punched to ConnPath::Direct reads as directly reachable and its circuit is suppressed; SAFE because a hole-punched link IS direct, the fabric reuses the live connection by PeerId, and a drop before the fetch only costs a RETRY, never a bad store path. NOT distinguished from a native Direct (would need new per-connection provenance in the swarm, and a hole-punched direct is arguably right to prefer over the relay). nat-vm does not exercise it (DCUtR fails there, link stays relayed - confirmed in the run).

F4 (budget strictness): the probe deadline is taken BEFORE issuing the dials (swarm.rs), so command round-trips + N addresses are INSIDE the bound; corrected the swarm doc overclaim "dials ONLY direct targets" (verdict is robust regardless since only ConnPath::Direct returns true).

F5 (test integration): documented that the loopback swarm test exercises the probe MECHANISM (production classifies loopback before the probe); the reachable->suppress->no-disclosure chain through the real locator is the by-address suppress bite in circuit_provenance_tests.

GATE (actual, nix dev shell): cargo test --workspace exit 0 (90 test blocks; fabric-libp2p lib +7 new, incl 3 live-swarm coupled bites). One pre-existing FLAKY iroh test blocked two runs (daemon iroh_node_lookup::shutdown_..._releases_its_fixed_iroh_port - a fixed-port re-bind TOCTOU: binds UDP port 0, drops it, re-binds the same port after endpoint shutdown; iroh UDP teardown is not synchronous). Added in 001d452 / last touched TASK-190 db0cc5b - PRE-DATES TASK-221 and is iroh-only (unrelated to this fabric-libp2p change); green isolated (0.8s) and on retry. RECOMMEND filing a task to make the re-bind robust (retry-on-bind or await teardown). fmt --check OK; clippy --workspace --all-targets -D warnings clean; no-floats rc0; golden-vectors BYTE-IDENTICAL rc0; discovery-no-shortcut rc0 (kad-EXCLUSIVE + no-injection intact). just audit rc0. just e2e ALL 9 scenarios PASS incl s6-p2p 11/11 (HIT=MISS+1 preserved). nat-vm-test PASSED on the F1-F5 code (forced --rebuild, FRESH VM boot, provider MainPID 825): AC#1 byte-identical relay fetch + B2 POSITIVE + B2 relay-attribution + B2 LOAD-BEARING all green; DCUtR never upgraded (F3 edge not hit). F1 + F2 mutations shown red/green.

TASK-221 DEEP-gate ROUND 3 (F2-wording, F5-positive-coupling, F4-strict-bound) ADDRESSED (commit 8e1864b on top of 6a17b8e; NOT pushed; In Progress - orchestrator owns AC/Done). codex round-2 confirmed F1/F3 resolved and the F2 IMPLEMENTATION correct; these are the 3 remaining items.

F2-wording (CORRECTED): removed the overstated "structurally impossible". kad PEER-ROUTING (separate from the ProviderRecord, which carries no dial address) feeds a target identify listen addresses into the routing table UNFILTERED (swarm.rs identify->kad add_address) and returns them from get_closest_peers (info.addrs), so a provider advertising a /p2p-circuit listen addr CAN surface one in dht_addrs. The current non-propagation is OBSERVED, not a frozen guarantee. The union-record (now record_relay_if_circuit_dialed) + addr_is_directly_reachable refusing to classify a circuit as directly reachable is therefore LOAD-BEARING on that reachable path. Comment rewritten to say exactly this.

F5 (POSITIVE-DIRECTION COUPLING - the gap): split the locator USE of the verdict into circuit_from_verdict(peer, dht_addrs, reachable_directly) so BOTH directions are couplable with an INJECTED verdict (a reachable private addr cannot be bound hermetically). New tests: reachable_private_verdict_suppresses_circuit_and_discloses_nothing (verdict=true, PRIVATE 192.168.3.9 -> suppress + ZERO disclosure) and unreachable_private_verdict_composes_circuit_and_discloses_once (verdict=false -> 1 circuit + 1 disclosure). BOTH mutation directions shown: locator ignoring the verdict to ALWAYS-COMPOSE reddens the positive/suppress tests ONLY (reachable_private_verdict + the loopback by-address suppress); ALWAYS-SUPPRESS reddens the negative/compose tests ONLY (unreachable_private_verdict + the F1 real-probe unreachable). So a mutation that suppresses for a genuinely-reachable provider (restoring the over-disclosure) now reddens.

F4 (STRICT BOUND - chose the HARD bound): the whole probe (fast-path + sequential dials + poll) now runs inside one tokio::time::timeout(budget, ..), so channel congestion / many targets cannot overrun 2000ms; fixed the doc that implied only the poll loop was bounded. probe_returns_false_bounded still asserts elapsed in [budget, budget+3s].

GATE (actual): cargo test --workspace exit 0 (90 blocks; fabric-libp2p lib +2 directional coupling tests, total 11 circuit tests + 2 probe tests). fmt --check OK; clippy --workspace --all-targets -D warnings clean; no-floats rc0; golden-vectors BYTE-IDENTICAL rc0; discovery-no-shortcut rc0. just audit rc0. just e2e ALL 9 scenarios PASS incl s6-p2p 11/11 (clean first try). nat-vm-test PASSED on the F2/F4/F5 code (FRESH build+boot, new .drv v7hjhgj, provider MainPID 730): AC#1 byte-identical relay fetch + B2 POSITIVE + B2 relay-attribution + B2 LOAD-BEARING all green; F4 hard-bounded probe still fails 192.168.2.3 (cross-NAT) -> circuit composed and carries bytes. F5 both-direction mutations red/green shown. Ran e2e + nat-vm because F4 touched the probe runtime path (swarm.rs); F2/F5 are locator/test refactors with byte-identical runtime behaviour.

DEEP GATE PASSED (2026-08-17). Commits 2ee2b2b + 6a17b8e + 8e1864b. qa GREEN (1065/0, e2e 9/9, KVM nat-vm PASSED), mped GO, codex NOGO->3 rounds->GO-VERDICT-221R2. Resolution (a) direct-dial-first probe (2000ms hard-bounded), safety by construction (with_peer_id Noise check -> cross-NAT never mis-classified Direct), circuit<=>disclosure end-to-end (union record + P2pCircuit non-reachable), both verdict directions coupled+mutation-proven, dcutr edge documented (costs-a-retry). nat-vm cornerstone preserved. Iroh e2e flake = pre-existing TASK-177.
<!-- SECTION:NOTES:END -->
