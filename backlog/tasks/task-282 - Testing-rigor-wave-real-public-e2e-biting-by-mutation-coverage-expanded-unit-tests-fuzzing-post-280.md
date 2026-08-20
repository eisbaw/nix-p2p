---
id: TASK-282
title: >-
  Testing-rigor wave: real-public e2e + biting-by-mutation coverage + expanded
  unit tests + fuzzing (post-280)
status: To Do
assignee: []
created_date: '2026-08-20 13:42'
updated_date: '2026-08-20 14:34'
labels:
  - hardening
  - testing
dependencies:
  - TASK-280
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Owner-requested hardening wave to run RIGHT AFTER TASK-280 (the isolation guarantee) lands. Grounded in the coverage audit 2026-08-20: LAN/mDNS/DHT-discovery/transfer-integrity are well-covered with biting oracles, but three real gaps remain — (1) PUBLIC/real-network is untested (containerized NAT only, needs KVM; no real cache.nixos.org / real-uplink test; the value thesis is unmeasured on a real link); (2) the 280 isolation guarantee is proven only at unit level and codex found some unit "mutation proofs" DO NOT BITE the production path (they hand-populate the ledger / call a helper, so deleting the real check stays green); (3) security-critical code is thin on unit tests (provenance ~4, identify ~4, confinement ~3).

COORDINATES existing tasks (do not duplicate; fold/supersede as appropriate): 113 (fuzz), 43/79 (pathological suite), 205 (adversarial), 254 (real-upstream tier), 168/207/247 (NAT/public chain), 14 (concurrency soak + docs-truthfulness).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 MUTATION-BITE AUDIT: every security/isolation e2e + unit oracle must be proven to bite by mutating the PRODUCTION path (revert the real guard/check -> RED), not a hand-populated helper. Sweep and fix the decoration-test class codex flagged on 280 (serve-provenance, identify-gate); make it a standing gate discipline
- [ ] #2 EXPANDED UNIT COVERAGE on the thin security-critical areas: multiaddr LAN-provenance grammar (compound/relay/dns/mapped-v6 edge cases), per-connection serve provenance, identify scope receive-gate + cache, dial veto (kad-autonomous by-PeerId path), scope-as-audience derivation across every role; property tests where the input space is large
- [ ] #3 REAL-PUBLIC e2e tier (coordinate 254/168/207/247): a real-network path — fetch/serve against the real cache.nixos.org over verified TLS AND a real (or KVM-NAT) multi-host peer link (not just container netns) — measuring the value thesis (peer vs CDN incl. discovery latency) with float-free magnitude-bounded provenance-labelled deltas. Gate it as an opt-in slow/BROAD tier, not the fast loop
- [ ] #4 FUZZING (coordinate/expand 113): fuzz the wire/parse surfaces — the multiaddr grammar classifier, NAR/bao leaf+proof decode, narinfo parse, signed kad provider/value records, and the /nar protocol framing; wire fuzz targets into the BROAD-cadence gate (never the fast loop), with a corpus + a crash-triage path
- [ ] #5 BROADEN the e2e negative-control set: adversarial peers (sybil/eclipse/amplification per 154/205), pathological inputs (43/79), and a concurrency soak (14); each with an attributable oracle
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
codex 280-core GO residuals -> mutation-bite-audit AC: (a) removing identify .with_cache_size(0) is NOT caught by the identify helper test (swarm.rs); (b) the e2e identify assertion DUPLICATES the DIAL log predicate (e2e_harness.py:7992) — not an independent identify bite; (c) SERVE leg is an unconditional placeholder (e2e:8027); (d) pcap-SYN non-vacuity open (e2e:7968). So the isolation-bridge '11/11' is NOT 11 independent system bites — the DIAL/identify single-mitigation system RED needs a multi-mitigation revert + rebuild. ALSO: (e) an aggregate MIXED-MODE profile can suppress the lan-share scope warning even when the libp2p leg is consumer-only (daemon/src/main.rs:2746); (f) source_config accepts a free lan_share bool not type-enforced against PublicationPlan (daemon-libp2p/src/main.rs:962) — type-enforce the invariant to kill the drift edge.
<!-- SECTION:NOTES:END -->
