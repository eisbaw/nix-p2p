---
id: TASK-190
title: >-
  gate BLOCKER: daemon iroh_node_lookup
  'hanging_authority_is_cancelled_at_the_single_absolute_ten_second_deadline'
  hangs >5min in isolation, blocking full 'just test'
status: In Progress
assignee:
  - '@claude'
created_date: '2026-08-13 09:08'
updated_date: '2026-08-13 16:02'
labels:
  - infra
  - daemon
  - fabric-iroh
  - flaky
  - gate-blocker
  - verification
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The daemon crate test iroh_node_lookup::hanging_authority_is_cancelled_at_the_single_absolute_ten_second_deadline (#[tokio::test(start_paused = true)] standing up a REAL Iroh endpoint) hangs indefinitely (>5min even in isolation, no contention; qa observed 30min+ under load). Its own comment flags the paused-tokio-time vs real-socket-readiness fragility: with time paused, the Iroh network/socket never becomes ready so the 10s absolute deadline (in virtual time) does not advance to fire. Effect: 'just test' (cargo test --locked --workspace) CANNOT run to completion, so the phase3 FAST gate cannot be closed end-to-end on this host — a rung-1 verification-infra blocker. This is DISTINCT from TASK-143 (publication_authority restart flake) and TASK-177 (shutdown_cancels_an_active_lookup under pathological load): this one hangs in isolation and is a hard gate stopper. FIX options: drive the deadline off a mock/injected clock decoupled from socket readiness; or don't pause tokio time while awaiting a real endpoint (use a real short timeout); or gate the real-Iroh-endpoint test behind a feature/ignore so the workspace gate completes and run it in a dedicated networked lane. Oracle must still bite (a never-cancelled hang must fail, not hang). Found during TASK-185 re-gate.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Root cause: daemon/tests/iroh_node_lookup.rs hanging_authority test uses #[tokio::test(start_paused=true)] (virtual clock) while runtime(authority) stands up a REAL iroh endpoint doing real socket I/O. Paused time freezes real socket/iroh maintenance -> hang. Fix (root cause, injectable deadline): add pub NodeLookupHandle::resolve_before(node_id, absolute_deadline) in fabric-iroh; resolve() delegates with Instant::now()+NODE_LOOKUP_DEADLINE. Rewrite the daemon test to REAL time (drop start_paused) with a SHORT injected deadline (~500ms) so real iroh works and deadline still fires deterministically; wrap in OUTER tokio::time::timeout(deadline+2s) so a never-cancelled hang FAILS not hangs (oracle bites). Sweep: fabric-iroh:1266 start_paused test uses NodeLookupCore directly (NO iroh endpoint, blocks on held state lock) -> SAFE, not hazardous; verify it stays fast. TASK-143/177 are distinct load flakes. Gate: fmt/build/clippy daemon, isolated timed run + bite proof (neuter cancel->fails), then FULL just test to completion with disk watch.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
READY FOR GATE (DEEP qa+codex to confirm oracle bites + gate completes; not self-certifying Done).

FIX (root cause, injectable deadline; NOT a workaround):
- fabric-iroh/src/iroh_node_lookup.rs: split NodeLookupHandle::resolve into a thin default-policy wrapper + new pub resolve_before(node_id, absolute_deadline: tokio::time::Instant). Deadline policy now lives at the call site (composable).
- daemon/tests/iroh_node_lookup.rs: hanging_authority test dropped #[tokio::test(start_paused=true)] -> real-time #[tokio::test] with a SHORT 500ms injected deadline via resolve_before, wrapped in an OUTER tokio::time::timeout(deadline+2s) so a never-cancelled hang FAILS (bounded) instead of hanging.

EVIDENCE:
- Isolated: passes in 0.53s (was >5min hang).
- Oracle bites: neutering the deadline (add +3600s) -> test FAILS via outer timeout at 2.52s (Elapsed), not hang.
- Full 'cargo test --locked --workspace --no-fail-fast' RUNS TO COMPLETION in 56s; hanging_authority passes inside the full run. Plain fail-fast 'just test' also completes (exit 101, finite) - no hang.

DEFECT-SPECIES SWEEP: only 2 start_paused sites. fabric-iroh/src/iroh_node_lookup.rs:1266 (held_replay_state_expires...) uses NodeLookupCore directly with a held state lock, NO real iroh endpoint, no real socket wait -> SAFE under paused time (verified 0.00s). Not hazardous; left as-is. TASK-143/177 are DISTINCT load flakes, not this hazard.

GOTCHAS: (1) paused tokio time is INCOMPATIBLE with a real iroh endpoint - iroh maintenance timers + real socket readiness need wall-clock; start_paused freezes them -> hang. Never combine start_paused with a real endpoint; inject a short REAL deadline instead. (2) integration-test crate boundary: #[cfg(test)] in fabric-iroh does NOT reach daemon/tests, so the seam is a real (pub) API, not a cfg(test) hook.

NEW FINDINGS (pre-existing, unrelated, now UNMASKED by the completing gate; both block a GREEN fail-fast just test): TASK-195 (doc_citations dangling nar_size_uncompressed_nar) and TASK-196 (no_enumeration plural-holdings rule misses load()). Not fixed here (scope; daemon-core guards). PRE-EXISTING unrelated fmt defect also noted: fabric-libp2p/tests/nar_transport.rs fails 'cargo fmt --all --check' at HEAD.
<!-- SECTION:NOTES:END -->
