---
id: TASK-155
title: >-
  fabric-libp2p: decentralized-content-discovery-v1 evidence artifact (bound to
  TASK-126 freeze)
status: To Do
assignee: []
created_date: '2026-08-12 07:55'
updated_date: '2026-08-14 18:01'
labels:
  - libp2p
  - fabric
  - evidence
  - decentralized
  - wave-2c
dependencies:
  - TASK-103
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Follow-up to TASK-103 (AC#10). Emit a decentralized-content-discovery-v1 verdict=pass artifact bound to the TASK-126 final tree, with manifests, timings, packet evidence and the mutation set, from a cold run-unique multi-node discovery (harness insertion / prior rendezvous / named candidates / tracker / LAN invalidate the evidence). TASK-132 accepts no unsupported tracker-backed or fabricated substitute. Mirror the existing iroh evidence harness+finalizer shape (scripts/*_evidence.py + finalize_*.py + Justfile recipes).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 a cold, run-unique multi-node run emits decentralized-content-discovery-v1 verdict=pass bound to the TASK-126 tree with manifests/timings/packet evidence/mutations
- [ ] #2 harness insertion, prior rendezvous, named candidates, tracker or LAN invalidate the evidence (bite by mutation)
- [ ] #3 an evidence finalizer binds a passing raw run to its reviewed implementation commit, like the iroh artifacts
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
TASK-103 landed an MVP-minimal decentralized-content-discovery-v1 artifact (scripts/decentralized_discovery_evidence.py + artifacts/decentralized-content-discovery-v1.json): re-derives verdict from raw e2e + AC#9 captures, fails closed on missing raw. This task remains the FULL mutation-rich artifact (bound to the TASK-126 freeze: richer tree manifests, packet-level pcaps, the full mutation matrix). Extend the MVP finalizer rather than replace it.

DEP CORRECTION 2026-08-14 (COMPASS): dropped the stale iroh-framed TASK-132 dep — decentralized discovery was PROVEN on libp2p-kad (TASK-103/159/179), not iroh; the discovery-v1 artifact this task fully-hardens is the libp2p one. Dep now TASK-103 (Done). NOTE: the TASK-103 MVP already landed a MINIMAL fail-closed decentralized-content-discovery-v1 artifact that re-derives from raw + records raw-log hashes + fails closed (verdict=pass ok/fail, checks_fail==0 required, both s7 arms required, live tree manifest). This task's REMAINING scope is the FULLER lock-in over that: (a) packet-level evidence (pcap capture in the s7/s8 pod so the no-injection + kad-only claims are backed at the wire, not just harness stdout); (b) a fuller mutation set; (c) binding to the TASK-126 frozen tree. If pcap-in-container proves env-heavy, scope it / BLOCK the pcap arm precisely and still deliver the fuller-mutation + tree-binding hardening — do not fake packet evidence.
<!-- SECTION:NOTES:END -->
