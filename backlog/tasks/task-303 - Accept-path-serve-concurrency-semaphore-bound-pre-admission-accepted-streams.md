---
id: TASK-303
title: Accept-path serve concurrency semaphore (bound pre-admission accepted streams)
status: Done
assignee:
  - '@claude'
created_date: '2026-08-22 12:09'
updated_date: '2026-08-22 19:24'
labels:
  - production
  - operator
  - hardening
  - wave-2c
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-120 AC#3 hardening (codex): the concurrent_serves_count bound is enforced at serve ADMISSION (a CAS in fabric_libp2p ServeGate::admit_plan, after the request digest is read), so it bounds parsed+admitted serves. The libp2p accept loop (fabric-libp2p/src/swarm.rs ~run_accept_loop) still spawns every accepted inbound /nar stream unconditionally, so a peer that connects and opens streams but does not send an admissible request can create >N pre-admission serve tasks, bounded only by transport connection/substream (yamux) limits. This task adds a true accept-path admission gate (a permit acquired BEFORE spawning the per-stream serve task, released on completion/drop) so the concurrent-serve ceiling also bounds pre-admission accepted streams. Until then the operator marker honestly scopes the bound to 'parsed+admitted serves' and does not claim an accept-path semaphore. Prereq: keep the shared server-owned counter (already added) as the accounting SSOT.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The libp2p /nar serve accept loop acquires an admission permit (N = active profile concurrent_serves_count) BEFORE spawning a per-stream serve task; the N+1th accepted stream is bounded (queued/declined) rather than spawned unconditionally
- [x] #2 A biting test drives >N concurrent PRE-ADMISSION accepted streams (connect + open stream, no admissible request) and proves at most N serve tasks are live; reverting the accept-path gate reddens it
- [x] #3 The daemon-core operator marker for concurrent_serves_count is upgraded from 'parsed+admitted serves' to cover accepted streams, matching the new mechanism
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
TASK-303 Implementation Plan (accept-path serve-concurrency permit):

Design (single ceiling, permit acquired at ACCEPT, held through admission+serve):
1. nar.rs: extract the concurrent-serve COUNT reservation OUT of ServeGate::admit_plan into a new
   ServeGate::try_acquire_serve_count(&Arc<Self>) -> ServeCountAcquire {Unbounded|Admitted(ServeCountPermit)|Full}.
   ServeCountPermit is a Drop guard that fetch_subs the SHARED inflight_serves counter on drop.
   admit_plan keeps ONLY the inflight-BYTE reserve; InflightReservation loses its serves field
   (count no longer double-reserved at admit). This removes the second ceiling per the AC.
2. swarm.rs accept_loop_core: snapshot the gate per-stream (moved in from run_accept_loop closure),
   call ServeGate::admit_accepted_stream(&gate) -> StreamAdmission {Spawn{permit}|Decline} BEFORE the
   spawn. Decline => drop the stream (bounded, not spawned). Spawn => serve(...) receives gate+permit.
   serve_stream gains a permit: Option<ServeCountPermit> param, held for the whole task (releases on
   drop, incl pre-first-poll) — same discipline as InflightReservation.
3. AC#2 bite: swarm.rs test drives accept_loop_core (generic-over-ITEM seam) with a REAL gate wired
   .with_serve_concurrency(N, shared), N+K sentinel items, sink STORES permits so they stay reserved;
   assert exactly N reach the sink. Mutation: make admit_accepted_stream always Spawn -> N+K reach
   sink -> reddens.
4. Rewrite the two nar.rs admit_plan-driven concurrency tests to drive try_acquire_serve_count (the
   mechanism moved); keep bite + attribution(declined_concurrency) + negative-control + handoff.
5. AC#3: upgrade ENFORCED_SEMAPHORE_MARKER + module doc (profile_budget.rs) + operator.rs consumer
   docs/test from "parsed+admitted serves (admit ADMISSION CAS)" to "accepted + admitted serves
   (accept-path permit)". Keep profile-sensitive (non-serving still NOT-INSTALLED). Keep marker
   mutually non-substring. Do NOT touch other TASK-120 AC#3 surfaces (announce/disk/rustdoc/nixos).

HONEST SCOPE: transport (yamux) already bounds pre-admission streams today; this TIGHTENS them to the
operator-declared N. NOT a fix for an unbounded DoS. Single production spawn site = run_accept_loop.

TASK-303 progress + gotchas (pre-commit):
- Count reservation MOVED out of ServeGate::admit_plan into ServeGate::try_acquire_serve_count,
  acquired at the ACCEPT loop (accept_loop_core -> admit_accepted_stream) BEFORE spawning the
  per-stream serve task, held through the whole serve via a ServeCountPermit guard moved into the
  spawn wrapper. admit_plan now reserves ONLY the in-flight BYTE ceiling (no more double-count).
  InflightReservation lost its serves field. SSOT counter unchanged (server-owned, shared across
  handoff).
- WIRE-BEHAVIOR CHANGE (honest, intentional): at the ceiling the accept loop DROPS the over-ceiling
  substream rather than writing a protocol Declined(Busy). A spawned decline-writer would NOT bound
  pre-admission task count (the whole point), so dropping is the only design that genuinely bounds to
  N. Fetcher observes Unavailable (timing-dependent surface: "failed to send the NAR request ...
  connection is closed" OR "closed/stalled before its status byte"), costing a bounded retry (in TCB).
  Updated daemon-libp2p/tests/serve_upload_wiring.rs production_wiring test to assert the Unavailable
  VARIANT (not sub-message) + kept the unbounded negative control for attribution.
- AC#2 mutation PROVEN: swarm::tests::accept_loop_count_gate_bounds_pre_admission_streams GREEN with
  gate (1 passed); RED with admit_accepted_stream neutered to always-Spawn (left==right 7!=3).
- Rewrote the two nar.rs admit_plan-driven concurrency unit tests to drive try_acquire_serve_count.
- AC#3 marker upgraded: "enforced at serve ADMISSION - CAS bound on parsed+admitted serves" ->
  "enforced at stream ACCEPT - permit bound on accepted + admitted serves". Non-serving profile still
  renders NOT-INSTALLED (machinery untouched). Only touched the concurrent_serves_count marker surface.
- clippy type_complexity on the AC#2 sink fixed via a local PermitSink type alias.
- GATES: targeted cargo test (4 crates) all ok; clippy green; rustfmt --check green after cargo fmt;
  e2e pending.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Delivered (commits a25354c mechanism+tests, 3acf700 AC#3 marker). AC#1: accept_loop_core acquires a ServeCountPermit via ServeGate::admit_accepted_stream/try_acquire_serve_count BEFORE spawning each per-stream serve task, against the SAME server-owned shared inflight_serves counter (count reservation REMOVED from admit_plan to avoid double-count; InflightReservation is byte-only). Permit held through the whole serve; n+1th accepted stream DROPPED pre-admission. Wired in the production run_accept_loop (shared swarm loop covers both daemon and daemon-libp2p). AC#2: swarm::tests::accept_loop_count_gate_bounds_pre_admission_streams drives the generic accept_loop_core seam with N+K pre-admission sentinel streams (no request) + a real gate; mutation-proven GREEN with gate / RED (7!=3) when admit_accepted_stream neutered to always-Spawn; negative control with unbounded gate admits all N+K. AC#3: marker upgraded serve ADMISSION/parsed+admitted -> stream ACCEPT/accepted+admitted, profile-sensitive (non-serving still NOT-INSTALLED). GATES: just lint exit 0; cargo test -p fabric-libp2p -p daemon-core -p daemon-libp2p -p daemon all ok; just e2e 16/16 PASS. HONEST LIMIT: this is a TIGHTENING (yamux already bounded pre-admission streams) not an unbounded-DoS fix; and at the ceiling the provider now DROPS the substream (fetcher sees Unavailable + retries, within TCB) rather than emitting a protocol Declined(Busy) — a decline-writer would not bound the pre-admission task count. Updated the production_wiring concurrency e2e test to assert the Unavailable variant accordingly. Left for DEEP gate: codex+qa+mped (security/resource surface).
<!-- SECTION:FINAL_SUMMARY:END -->
