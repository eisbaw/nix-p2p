---
id: TASK-15
title: 'RE-PLAN: wave 2 planning via phase2-backlog-snowball (not feature code)'
status: To Do
assignee: []
created_date: '2026-08-07 21:56'
updated_date: '2026-08-08 20:09'
labels:
  - replan
dependencies:
  - TASK-14
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Re-plan task - not feature code. Re-invoke phase2-backlog-snowball with: the PRD (PRD.md), the current TESTING.md grounding doc, and the lessons/notes wave 1 produced (J2 baseline: egress, p95, narinfo-to-nar gap histogram; journey findings; hardening results). Plan wave 2 to the depth the new knowledge supports. Wave 2 candidates the PRD already names: DHT mechanism spike (mainline vs BEP44 vs iroh-tracker - first freeze surface, will need irreversible labels), iroh-blobs whole-NAR NarSource, peer yes/no probe protocol + rate-limiting design, hedge with throughput abort, figure revision to DHT-authoritative. TESTING.md wave-scoping checklist lists the not-yet-grounded oracles wave 2 must pull in. Write no implementation in this task. Shallow-ahead planning is deliberate: this project is experimental (PRD field), and planning past current knowledge manufactures false certainty.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Wave-2 tasks exist in the tracker, grounded in J2 baseline data
- [ ] #2 New wave ends with its own re-plan task UNLESS project reclassified firm (then full breakdown; PRD field updated)
- [ ] #3 TESTING.md updated with what wave 1 taught (baseline section + pulled-in oracles for wave 2)
- [ ] #4 Irreversible labels applied to wave-2 freeze-surface tasks per PRD map (claim schema, DHT key derivation, addressed-unit encoding)
- [ ] #5 Wave exit gate: just e2e AND just e2e-vm both green at the moment of re-planning (a gate that vanished cannot be required - task-1 stubs must be long gone)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Owner requirement added post-review: wave-2 planning must include peer-count scale sweeps using the task-18 S5 machinery - real sweeps at 1..30 peers, regression-fit extrapolation to 100s/1000s for latency and RAM, with S5 honesty limits (resource laws only, not emergent DHT/gossip effects). See TESTING.md S5 and the not-grounded list.

Owner standing goal (2026-08-08): implement the entire backlog; modular crates composed together; first simple full-NAR decentralized solution, then ca-chunked (Candidate C); iroh is first-priority transport, and wave-2 planning should design the NarSource/transport seam so OTHER protocols (e.g. BitTorrent) can slot in later without a network fork - transport pluggability joins the claim-schema freeze discussion.

forward-carried from task-4 seam fix: the NarSource seam is NarKey{SignedNarHash,UpstreamPath} with a token->NarHash correlation catalog populated at narinfo-serve time. Wave-2 iroh NarSource keys on NarKey::SignedNarHash via the claims index; the correlation catalog is the seed of the PRD 'learn NarHash at narinfo time' prefetch. Plan the claims-index lookup to consume NarKey::SignedNarHash.

J2 baseline recorded (task-12, TESTING.md 'J2 measurement baseline', 2026-08-08). Wave-2 re-plan inputs: (a) pre-p2p reference = payload NAR egress 115,934,829 B/workload (workload nix-p2p-fixture-workload-v1, gen-d2ab43402b88715a), offload 0.0 by construction - the number wave-2 offload is measured against by this same instrument. (b) PREFETCH-WINDOW FINDING: the narinfo->nar gap is sub-millisecond on the LOOPBACK harness (~0.5ms median, <2ms max), so a 1-4s DHT resolve cannot be masked by prefetch on these numbers - hedge (not prefetch) would carry offload. BUT this is loopback with a local mock, NOT a verdict on the real cache.nixos.org gap (which carries real RTT and may open a larger window). Filed task-35 to re-measure the gap on a real upstream BEFORE the hedge/prefetch design is committed. (c) S4 latency axis is UNUSABLE on the container tier (A/A noise floor >10%, task-32) - wave-2 latency claims need task-32's inner-realise timing or the VM tier.

Forward-carry from task-13 (hardening pt1) - wave-2 p2p relevant findings:
1) The per-hop upstream header timeout does NOT compose across hops (task-33, now documented+configurable+boundary-pinned, but NOT fixed). A p2p multi-hop resolve path needs a BUDGET-AWARE deadline or it will 502 at depth exactly as the daemon chain does - this is a wave-2 design input, not just a daemon tweak.
2) The depth-composition term is WAN-scale (sub-ms on loopback), so wave-2 must re-validate depth/timeout behaviour against REAL RTT (ties to task-35's real-upstream gap re-measure).
3) HTTP/2 + TLS gap (task-24): the daemon+testproxy are h1.1-plaintext only; fronting real cache.nixos.org or peers over TLS/h2 is unbuilt. h2-only upstream currently fails CLOSED (proven), which is safe but blocks real-upstream fronting.
4) Unsigned-narinfo caching (task-30) blocks caching private/unsigned p2p peers - the narinfo cache requires a Sig line as its truncation signal.
5) The seeded fuzz harness pattern (path-traversal containment + unknown-field identity) should be reused for the wave-2 claim-schema/DHT-key fuzz.

WAVE-2 GOAL (owner, 2026-08-08) - drives this re-plan. See PRD 'Wave 2 scope'. Key: (1) iroh whole-NAR NarSource FIRST, BitTorrent as a 2nd pluggable transport (interface + claim schema must admit it); (2) DHT-authoritative discovery spike (mainline/BEP44/iroh-native) + gossip accelerant + no-enumeration probes, keyed on the frozen NarKey::SignedNarHash; (3) SCENARIO MODELING & PROFILING (reuse/extend task-18 S5): typical + pathological cases estimating RAM/disk/latency/throughput/speedup-over-cache, extrapolated to 1000s of peers; pathological set incl slow-peer-on-HIT, dead-holder-after-claim, DHT-timeout/cold-start, NAT-relay, thundering-herd, lying-claim, seeder-churn; (4) POLICY DERIVATION: file a policy task per decision the scenarios expose - archetype: slow-HIT -> abort-to-cache vs delayed-race/hedge vs adaptive-by-throughput. Do NOT hardcode a policy the data hasn't justified. Grounding: net-upstream-egress-v2 = speedup yardstick; task-35 real-gap = prefetch-vs-hedge input. When I invoke phase2-backlog-snowball for wave-2, design-for-test FIRST (the scenario models ARE the test grounding), then the backlog.
<!-- SECTION:NOTES:END -->
