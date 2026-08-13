---
id: TASK-193
title: >-
  fabric-libp2p: off-worker async serve production reachable from the swarm
  serve loop (unblocks store-dump serve)
status: In Progress
assignee:
  - '@claude'
created_date: '2026-08-13 13:15'
updated_date: '2026-08-13 14:50'
labels:
  - libp2p
  - fabric
  - transport
  - serve
  - wave-2c
dependencies:
  - TASK-158
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Carve-out from TASK-157 (which bundles the request-response->libp2p-stream rewrite + mid-stream size abort + body-idle bound + off-worker production). ONLY the off-worker async production sub-part blocks serving a real /nix/store path, and it does NOT require the stream rewrite.

ROOT CAUSE (verified): the shipped libp2p serve loop is synchronous + Memory-only. fabric-libp2p/src/swarm.rs on_nar_event (sync &mut self poll-loop handler) -> ServeGate::respond(&digest) -> NarSupplyPlan::produce(). produce() (nar.rs ~310-321) handles ONLY NarSource::Memory; a NarSource::Process (the nix-store --dump store-dump source) returns a loud typed Err -> respond -> Declined(SupplyFailed). The async produce_supervised() (which runs --dump under a supervised process group with the serve-time BLAKE3 recheck) has ZERO non-test callers. on_nar_event cannot .await it (sync poll loop; the request-response ResponseChannel is consumed inline).

CONSEQUENCE: any CatalogNarSupplier/Process-backed provider announces store paths correctly but DECLINES every serve (SupplyFailed) - a small 4 KB path included, not just large NARs. So this is a PREREQUISITE FOR ANY store-dump serve, not a large-NAR optimisation. It blocks TASK-191 (serve from real /nix/store) and its container e2e.

SCOPE: within request-response (no stream rewrite), make async supervised production reachable from the serve loop: ServeGate yields a produce-future (or the plan) instead of inline bytes; a spawned tokio task OWNS the ResponseChannel across the await; NarSource::Process is served via produce_supervised(&TaskSupervisorHandle, &content) with its len==declared_size AND BLAKE3(RawNarV1)==content serve-time recheck kept. The daemon owns a TaskSupervisor and passes its handle in. Mind the poll-loop borrow split (the existing &self.serve / &mut self.swarm invariant in on_nar_event) and the backchannel to send the response once produced. Leave mid-stream abort + idle bound + full stream rewrite as TASK-157 proper (which then depends on this seam).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 async supervised production (produce_supervised) is reachable from the swarm serve loop: a NarSource::Process (store-dump) inbound request is served with correct bytes, NOT Declined(SupplyFailed)
- [ ] #2 production runs OFF the poll loop (spawned task owns the ResponseChannel) so a serve does not block kad/identify; proven by a bite test that discovery still answers during an in-flight serve
- [ ] #3 the serve-time BLAKE3(RawNarV1)==announced content recheck + len==declared_size guard (TASK-158) fire on the wired path; a rebuilt/mismatched source fails the serve loud, never ships wrong bytes
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
## Implementation Plan (inc1)

Mechanism: off-loop async supervised production reachable from the sync poll loop, via a backchannel.

1. fabric-libp2p/src/nar.rs — ServeGate seam
   - ServeGate holds a `TaskSupervisorHandle` (new ctor arg).
   - Split admission into `admit_plan` (shared policy: stop/unknown/too-large/in-flight
     CAS-reserve). `respond()` kept (Memory inline + the RED path: a Process source is
     Declined via sync `produce()`), now built on `admit_plan`.
   - New `admit()` (poll-loop entry): Memory -> Serve::Now(inline bytes); Process ->
     Serve::OffLoop{plan,content,declared} with the reservation HELD.
   - New async `produce_admitted(self: Arc<Self>, ...)`: runs `produce_supervised` (keeps
     len==declared AND BLAKE3 recheck), releases the reservation via an `InflightReservation`
     RAII guard (drop-safe => cancellation never leaks the reservation).
   - CAS reserve replaces the pre-193 load-then-add TOCTOU (production now off-loop).

2. fabric-libp2p/src/swarm.rs — the worker
   - Worker gets a backchannel mpsc `(ResponseChannel<NarResponse>, NarResponse)`; run()
     selects it as a 3rd arm and calls send_response on the poll loop (owns &mut Behaviour).
   - on_nar_event Request arm: `gate.admit()`; Now -> send_response inline; OffLoop -> spawn
     an off-loop task that OWNS the ResponseChannel across the await, races produce_admitted
     against `is_open()` closing (drop => reap), then delivers via the backchannel.
   - Borrow-split preserved: admit uses `&self.serve`; the spawned task holds owned clones
     (Arc<ServeGate>, backchannel tx) + the moved channel — never &mut self / the swarm.

3. Ownership: the fabric OWNS a TaskSupervisor when built with a supplier (RAII reap on
   fabric drop) and passes its handle to Libp2pServer->ServeGate. This keeps the seam the
   task describes (handle threaded into serve wiring) WITHOUT changing start_with_supplier's
   public signature (zero daemon churn); TASK-191 can later thread the daemon's own handle.

4. Tests (fabric-libp2p): RED respond(Process)=Declined vs GREEN admit+produce_admitted served;
   two-node integration serving a Process (cat) source; reap-on-cancel through the gate;
   poll-loop liveness (a slow in-flight serve does not block a concurrent request).

Gate: bounded (build/clippy/fmt/check-independence/test -p fabric-libp2p). Leave In Progress.

## Ready for gate (inc1 complete) — DEEP review pending (qa + codex)

Implemented off-loop async supervised production reachable from the swarm serve loop.
Left In Progress per brief; NOT self-certified Done.

### Files
- fabric-libp2p/src/nar.rs — ServeGate seam: `admit_plan` (shared policy + CAS reserve),
  `finish_inline`, kept `respond` (Memory inline + the RED path), new `admit` -> `Serve`,
  new async `produce_admitted(self: Arc<Self>)`, `Serve` enum, `InflightReservation` RAII
  guard, `NarSupplyPlan::requires_supervised_production`. Module honest-scope note updated.
- fabric-libp2p/src/swarm.rs — Worker backchannel mpsc (ResponseChannel, NarResponse);
  run() 3rd select arm -> `deliver_nar_response`; on_nar_event Request arm: admit -> Now
  (inline) | OffLoop (spawn owns the channel across the await, races is_open() close vs
  produce_admitted, delivers via backchannel); `wait_response_channel_closed` helper.
- fabric-libp2p/src/server.rs — Libp2pServer carries a TaskSupervisorHandle -> ServeGate.
- fabric-libp2p/src/fabric.rs — a SERVING fabric OWNS a TaskSupervisor (RAII reap on drop)
  and threads its handle to Libp2pServer. NOTE deviation from brief: brief said "daemon
  owns the supervisor and passes the handle in"; owning it in the fabric keeps
  start_with_supplier's public signature unchanged (ZERO daemon/daemon-libp2p churn — the
  gate is bounded to fabric-libp2p) while still realizing the handle-threaded seam. TASK-191
  may instead thread the daemon's own handle for a unified capacity ceiling; the
  Libp2pServer/ServeGate seam already takes a handle so that is a drop-in.

### Async-response mechanism (the crux)
send_response needs &mut Behaviour which ONLY the poll loop owns. So: on_nar_event admits
on the loop; for a Process source it spawns a task that MOVES the ResponseChannel across
the produce_supervised .await, then hands (channel, response) back over an mpsc backchannel;
the run() loop selects that backchannel and calls send_response on the next poll. Borrow-
split preserved: admit uses `&self.serve` (borrow ends before any &mut swarm); the spawned
task holds only OWNED clones (Arc<ServeGate>, backchannel tx) + the moved channel — never
&mut self / the swarm.

### Cancellation/reap wiring + bite
produce_admitted holds an InflightReservation RAII guard; the spawned task races
produce_admitted against wait_response_channel_closed (polls ResponseChannel::is_open). A
dropped/closed channel drops the produce future -> (a) reservation released via guard drop,
(b) the inner produce_supervised future drop signals caller-abandonment -> supervisor
SIGKILL-reaps the process group. Node/supervisor shutdown reaps identically. Fabric drop
drops its TaskSupervisor -> cancel_now -> reaps in-flight groups.
BITE proven (bounded, one spawn+reap): off_loop_serve_is_reaped_and_reservation_released_on_cancel
asserts /proc/<pid> gone + registry active_len==0 + inflight==0 after supervisor.cancel_now.
Mutation-verified: neutering InflightReservation::drop -> the inflight==0 assertion FAILS.

### Concurrency + recheck
- Multiple in-flight: each OffLoop gets its own spawned task + reservation (pending-map is
  the set of spawned tasks); actual dumps are bounded by the TaskSupervisor's MAX_OWNED_TASKS
  (execute_process -> Capacity -> Declined(SupplyFailed)); the in-flight ceiling now BINDS
  via a CAS reserve (replaced the pre-193 serialized load-then-add).
- Recheck NOT bypassed: produce_admitted goes through produce_supervised, which enforces
  len==declared_size AND BLAKE3(RawNarV1)==content; a mismatch -> Declined, never wrong bytes.

### Tests (all green)
- nar.rs unit: process_source_is_declined_inline_but_served_off_loop (RED respond vs GREEN
  admit+produce_admitted; BLAKE3 of served == announced); off_loop_serve_is_reaped_and_
  reservation_released_on_cancel.
- nar_transport.rs (two real swarms): process_source_is_served_across_two_nodes (the unblock
  end to end — Process served, was Declined pre-193); a_slow_process_serve_does_not_block_
  the_poll_loop (deterministic: waits process_jobs.active_len()>=1 in flight, then a
  concurrent listen_addrs() on the serving node must return <500ms; inline would block ~2s).

### BOUNDED GATE (inside nix develop, disk 114G >30G floor; no orphans, no leftover pids)
- cargo fmt --all --check: OK
- cargo clippy -p fabric-libp2p --all-targets --locked -- -D warnings: clean
- python3 scripts/check-independence.py: green (no new edges; HTTP denylist green)
- cargo test -p fabric-libp2p --locked: 53 passed / 0 failed
  (lib 35, bootstrap_independence 2, decentralized_discovery 1, nar_transport 8,
   near_key_routing_bar 1, node_locator_discovery 1, record_lifecycle 5, doctests 0)

### Honest limits
- Per-request channel-drop cancellation (is_open poll, 250ms) can't be unit-bitten in
  isolation (ResponseChannel is un-constructable outside libp2p); its reap path shares
  produce_supervised's caller-abandonment mechanism, which IS bitten via supervisor shutdown.
- Serve time is bounded only by the request-response inbound timeout (~10s default); a true
  serve deadline + mid-stream size abort + raw-stream transfer remain TASK-157.
- Still buffers the whole NAR (TASK-157). Memory sources still produce inline on the loop
  (instant clone); only Process goes off-loop.
- NOTE: README.md is being modified by a CONCURRENT session (TLS/supply-integrity, unrelated
  to TASK-193); NOT staged in this commit.

## DEEP-gate fix applied (inc2) — READY FOR RE-GATE (codex)

Codex NO-GO was one real concurrency defect: pre-first-poll cancellation LEAKED the
in-flight reservation (the InflightReservation guard was built INSIDE produce_admitted's
async body, which only runs on first poll; a future dropped before first poll never built
the guard, so the admit-time CAS increment was never decremented -> repeated leaks wedge
the serve gate: an availability/DoS hole). Fixed.

### Guard-ownership restructuring (reserve and guard are now atomic at ADMIT)
- nar.rs: `inflight_bytes` is now `Arc<AtomicU64>`. `InflightReservation` holds a direct
  `Arc<AtomicU64>` handle to that counter (NOT a back-ref to the gate) + declared; its Drop
  does the single fetch_sub. `admit_plan` constructs the guard SYNCHRONOUSLY the instant the
  CAS reserve succeeds and returns `(NarSupplyPlan, InflightReservation)`. `admit` hands the
  guard out inside `Serve::OffLoop { plan, content, reservation }` (was `declared`).
  `produce_admitted(&self, plan, content)` no longer touches the reservation (guard removed
  from its body; `self: Arc<Self>` -> `&self`). `respond` binds `_reservation` for the call
  (inline release). `Serve`/`InflightReservation` are `pub(crate)` so the enum can carry it.
- swarm.rs worker OffLoop arm: `let _reservation = reservation;` is the FIRST line of the
  spawned task's async block, so the guard is OWNED BY the future from creation. Dropping the
  task at ANY point - including BEFORE its first poll (peer abandons instantly), mid-await
  (channel closes), or on completion - runs the guard's Drop exactly once and releases. The
  select still races wait_response_channel_closed vs produce_admitted (reap on channel drop).
  Invariant now holds: reserve (admit) and release (guard Drop) are paired across every path.

### Two new bites (both mutation-verified RED without their fix; reverted)
1. dropping_an_unpolled_off_loop_future_releases_the_reservation (nar.rs unit, NO
   ResponseChannel): admit an OffLoop, build the exact future the worker builds, DROP IT
   UNPOLLED, assert inflight_bytes == 0 (and no process spawned). BITE: neutering
   InflightReservation::Drop -> inflight stays == declared -> RED (this observably reproduces
   the pre-fix in-body-guard leak: an unpolled future built pre-fix contained no guard, i.e.
   equivalent to a no-op Drop). GREEN with the guard owned-from-admit.
2. process_source_with_wrong_declared_length_is_declined (nar.rs unit): a Process dump that
   emits FEWER bytes than declared_size (but whose bytes DO hash to the announced content, so
   the BLAKE3 arm passes) must be Declined(SupplyFailed) via the exact-length arm. BITE:
   removing the `bytes.len() != declared` check in produce_supervised -> the short dump is
   served as Nar(...) -> RED.

### Kept (codex-confirmed sound, unchanged): reap-after-poll, borrow-split, poll-loop
off-loading, response pairing, backchannel awaits-not-drops, CAS ceiling logic, len+BLAKE3
recheck ordering, fabric-owned supervisor.

### BOUNDED GATE (nix develop; disk 114G > floor; no orphans, no leftover pids)
- cargo fmt --all --check: OK
- cargo build -p fabric-libp2p --locked: OK
- cargo clippy -p fabric-libp2p --all-targets --locked -- -D warnings: clean
- python3 scripts/check-independence.py: green
- cargo test -p fabric-libp2p --locked: 55 passed / 0 failed
  (lib 37 [+2 new bites], bootstrap_independence 2, decentralized_discovery 1,
   nar_transport 8, near_key_routing_bar 1, node_locator_discovery 1, record_lifecycle 5,
   doctests 0)

Left In Progress for the codex re-gate. README.md remains modified-uncommitted by the
orchestrator (unrelated); NOT staged.
<!-- SECTION:NOTES:END -->
