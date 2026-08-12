---
id: TASK-142
title: >-
  Iroh relay-capability routed evidence harness + artifact
  (iroh-relay-capability-v1)
status: In Progress
assignee:
  - '@claude'
created_date: '2026-08-11 22:55'
updated_date: '2026-08-12 14:14'
labels:
  - iroh
  - discovery
  - relay
  - transport
  - evidence
  - wave-2c
dependencies:
  - TASK-139
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Build the routed podman evidence harness that produces artifacts/iroh-relay-capability-v1.json with verdict=pass bound to a REAL routed run, completing TASK-139's AC#2/#5/#6 and the evidence-binding of AC#1/#3/#4. Deferred from TASK-139, which landed the deterministic Rust relay-transport capability cornerstone (daemon/src/iroh_relay.rs: typed default-off RelayTransportConfig building RelayMode::Custom, external-authorization gate, typed RelayTransportUnavailable taxonomy, 10000ms deadline + 1000ms grace, privacy preflight, pure connection-path classifier) but could not honestly produce a real routed relay artifact in one session (the two template harnesses -- scripts/iroh_node_lookup_evidence.py ~2000 lines + finalize ~95KB, plus the node-publication pair -- are each a multi-file infrastructure with a nix docker image and new binaries). A hand-written verdict=pass with no real routed run is forbidden.

Scope (mirror TASK-137/138 exactly):
- New daemon binaries for the image: a local iroh relay SERVER runner and a relay CLIENT that connects a peer addressed relay-only across routed namespaces where the direct path is L3-blocked, emitting a canonical JSON outcome (path attribution via daemon::classify_connection_path / IncomingAddr).
- scripts/iroh_relay_capability_evidence.py: routed rootless-podman topology (two internal networks + tiny L3 router, direct path deliberately blocked), tcpdump capture proving zero relay packets when disabled/offline and relay attribution when forced; a direct-positive control that stays direct and is NOT credited to relay; the typed-failure matrix (relay outage / wrong URL / wrong cert / wrong identity / half-open stream / forced-direct-failure) as distinct typed outcomes within the 10000ms deadline; source + packet mutation bites; --self-test hook.
- scripts/finalize_iroh_relay_capability.py: assemble artifacts/iroh-relay-capability-v1.json bound to tree/evidence/config hashes; --self-test mutation bites.
- docs/iroh-relay-capability-artifact-v1.schema.json + docs/iroh-relay-capability-v1.md.
- flake.nix docker image for the relay evidence; Justfile recipes (iroh-relay-evidence / finalize) + wire the two --self-test hooks into 'just test' next to task-137/138.
- Label evidence production-shaped (locally operated routed relay only); do NOT reach n0 default relays; external/public relay requires a named owner + explicit authorization.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 artifacts/iroh-relay-capability-v1.json exists with verdict=pass bound to a REAL routed run (direct L3-blocked -> relay success, direct-positive control stays direct, full typed-failure matrix within the 10000ms deadline)
- [ ] #2 The two new scripts' --self-test hooks are wired into 'just test' and are green
- [ ] #3 Evidence is labelled production-shaped; no n0/public relay is contacted
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
inc1: feature-gated relay evidence binaries (server+peer) DONE, committed 99376b9. inc2: python harness+finalize+schema+doc+flake image+Justfile self-test wiring. inc3: routed run producing artifacts/iroh-relay-capability-v1.json verdict=pass (or honest blocker).
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
DEEP gate returned: core relay-attribution proof CONFIRMED genuine + non-circular (mped-architect). One gate-breaking finding F1 = TASK-166 (elapsed_ms measures container wall-clock + is clamped, so the deadline oracle cannot bite). F1 is an evidence-instrument honesty defect, NOT a relay-transport bug. Follow-ups F2=TASK-165, F3=TASK-167. Decision: TASK-142 stays In Progress (not falsely Done) on the timing axis; F1 (TASK-166) is deferred and gates TASK-89's use of the artifact, so it lands when the iroh relay evidence is finalized rather than being hardened now while the core path is the priority.
<!-- SECTION:NOTES:END -->
