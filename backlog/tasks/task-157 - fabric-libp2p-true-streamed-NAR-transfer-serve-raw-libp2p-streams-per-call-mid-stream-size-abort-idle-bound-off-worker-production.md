---
id: TASK-157
title: >-
  fabric-libp2p: true streamed NAR transfer/serve (raw libp2p streams) -
  per-call mid-stream size abort + idle bound + off-worker production
status: Done
assignee:
  - '@claude'
created_date: '2026-08-12 08:38'
updated_date: '2026-08-13 18:02'
labels:
  - libp2p
  - fabric
  - transport
  - serve
  - streaming
  - wave-2c
dependencies:
  - TASK-151
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-151's libp2p transport uses request-response, which BUFFERS the whole NAR. Consequences it documents honestly and defers here: (1) the fetch side reads the response into a Vec capped at MAX_NAR_RESPONSE_BYTES (256 MiB) - bounded, never unbounded - and the per-call expected_size TooLarge check fires POST-receive on that bounded buffer, NOT mid-stream at exactly expected_size; (2) the SafetyEnvelope dial/body-idle bounds are not enforced separately (only total_timeout is, via tokio::timeout) because request-response exposes a single request_timeout, not a raw stream; (3) the SERVE side produces bytes INLINE on the swarm worker (blocking the poll loop) - fine for small NARs, not for real store-dumps. Replace request-response with libp2p-stream (raw AsyncRead/AsyncWrite) so: the fetcher aborts the instant cumulative bytes exceed expected_size (true streaming size abort) and enforces a real body-idle bound; the server streams produced bytes off the worker (spawned task, the iroh model) so a large serve does not stall kad. Mirror fabric-iroh's bao streaming decode contract for gate-1.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 the fetch side aborts a transfer the instant cumulative bytes exceed the per-call expected_size (mid-stream), proven by a bite test
- [x] #2 the SafetyEnvelope body_idle_timeout is enforced as a real inter-chunk stall guard (not just total_timeout)
- [x] #3 serve production runs OFF the swarm worker so a large serve does not block kad/discovery
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
COMPASS 2026-08-13: this is a VALUE-THESIS PRECONDITION, not streaming polish. request-response buffers the whole NAR and caps a single NAR at 256 MiB; TASK-72 admission also declines >256 MiB. The byte-dominant tail (the largest store paths hold the majority of bytes) is therefore STRUCTURALLY UNSERVABLE by the primary transport, so peers could only supply the small-NAR head while the CDN keeps the byte tail. TASK-193 (off-loop async serve seam) is now landed as this task's prerequisite; what remains here is the request-response->stream rewrite + mid-stream size abort + a serve deadline. Must land before any honest break-even measurement over the real size distribution.

IMPL PLAN (2026-08-13, streaming rewrite via libp2p-stream):

TRANSPORT SWAP: add libp2p-stream 0.2.0-alpha (direct dep; libp2p 0.54 meta-crate has no 'stream' feature; version matches locked swarm 0.45/core 0.42). Replace request_response::Behaviour<NarCodec> in swarm Behaviour with stream::Behaviour. Control::open_stream auto-dials (bounded by dial_timeout); Control::accept yields inbound (PeerId, Stream) handled in spawned tasks OFF the poll loop (AC#3 structural). Stream = libp2p::Stream (AsyncRead+AsyncWrite).

WIRE (raw stream, transport layer only; RawNarV1 bytes + claim/ContentKey/ProviderRecord/golden UNCHANGED): request=32 digest bytes. response=1 status byte then NotHeld(none)/Declined(1 reason byte)/Nar(raw NAR bytes streamed to EOF, no length prefix — mirrors iroh; server half-closes write). Protocol bumped /nar/1 -> /nar/2 (framing changed; name is not a frozen surface).

AC#1 mid-stream size abort: fetcher reads status then loops 64KiB reads accumulating; cap = expected_size (else MAX_NAR_RESPONSE_BYTES floor); abort the INSTANT cumulative > cap -> TooLarge{limit,streamed}, drop stream. Core read logic = pure async fn read_response_streamed<R:AsyncRead>() in nar.rs, unit-tested with bites.
AC#2 body-idle: each read wrapped in timeout(body_idle_timeout); a stalled inter-chunk read -> Unavailable(stall), distinct from transport-level total_timeout. Unit-bitten with a controllable pending reader (no wall-clock race).
AC#3 off-worker: inbound serve fully on spawned per-stream tasks; gate in a shared Arc<Mutex<Option<Arc<ServeGate>>>> slot (install/uninstall update it directly, identity-checked). produce_admitted stays off-loop; reservation guard moved into the task (pre-first-poll leak safe). Reap-on-disconnect preserved: race produce_admitted vs a peer-hung-up read detector (client keeps write half open as still-interested signal). max_serve_duration now enforced (timeout around production; drop reaps process).

GATE-1 verify: size-abort is truly mid-stream; byte-integrity via frozen Blake3Digest::from_raw_nar at stream completion (single pass, memory bounded to cap+chunk). HONEST LIMIT: per-CHUNK byte-corruption detection needs a bao outboard on the wire (wire addition) -> follow-up; corrupt peer still fails the fetch (gate-1 preserved). Serve-side keeps buffer-then-verify-then-ship (integrity recheck before shipping requires it) -> full stdout passthrough streaming = same bao follow-up.

Tests: keep nar_transport.rs two-node suite green (happy/corrupt/oversize/budget/teardown/stale-successor/process/liveness/rebuilt). Add nar.rs unit bites (mid-stream abort on a large body, body-idle stall, corrupt-at-eof, notheld, declined). Add a two-node large-NAR mid-stream-abort bite. Gate: fmt/build/clippy/independence/test bounded per cycle; full just test once before final commit.

READY-FOR-GATE (2026-08-13, streaming rewrite landed; leaving In Progress for the codex DEEP gate).

DONE: replaced request_response::Behaviour<NarCodec> with a raw libp2p-stream protocol (/nix-p2p/<scope>/nar/2). AC#1 mid-stream size abort, AC#2 body-idle inter-chunk guard, AC#3 off-worker serve - all landed and BITE-verified.

MECHANISMS:
- Fetch: SwarmHandle::fetch_nar_streaming opens a stream via libp2p_stream::Control (auto-dials, bounded by dial_timeout), writes the 32-byte digest, then nar::read_response_streamed streams the body: cap = expected_size (else 256 MiB floor), abort the INSTANT cumulative > cap (TooLarge), each read bounded by body_idle_timeout (stall guard), gate-1 BLAKE3 verify (frozen from_raw_nar) at completion. Transport wraps in total_timeout.
- Serve: run_accept_loop pulls inbound streams off the poll loop and spawns nar::serve_stream per stream. Gate lives in a shared Arc<Mutex<Option<Arc<ServeGate>>>> slot (install/uninstall = synchronous identity-checked slot writes, replacing the worker commands; stale-teardown-vs-successor preserved). serve_stream: EVERY phase deadline-bound by ServeBudget::max_serve_duration (else UNSERVED_STREAM_DEADLINE=30s) - request read, production (produce_admitted now enforces max_serve_duration + reaps on timeout), AND the response write. Off-loop production raced against consumer_hung_up (dropped stream reaps the nix-store --dump group). InflightReservation held at serve_stream scope through production AND the write (pre-first-poll leak safe; ceiling accounts for the resident NAR during the write).

NO FROZEN WIRE CHANGED: RawNarV1 bytes, claim/ContentKey/ProviderRecord, golden vectors untouched - only the transport framing (protocol name bumped /nar/1->/nar/2). libp2p-stream 0.2.0-alpha added as a direct dep, stays on the libp2p side (check-independence green).

GATE NUMBERS (all inside nix develop): cargo fmt --all --check = 0; cargo clippy -p fabric-libp2p --all-targets -D warnings = 0; cargo test -p fabric-libp2p --locked = 62 passed / 0 failed (43 lib incl. the new streaming + serve-deadline bites, 10 nar_transport incl. the two-node large mid-stream-abort, + 9 others); check-independence = green. Full just test: the workspace cargo suite + golden-vectors + content-key + measure self-test all pass; the tail python self-tests (scalefit/scale_sweep/iroh evidence/profile/rewrite-realnix) confirmed pass separately (the shared-box harness time-capped the single full run mid-tail; an earlier full run was green exit 0).

BITES PROVEN BY MUTATION: AC#1 (defeat mid-stream check -> read_aborts_mid_stream... FAILS); AC#2 (drop body-read timeout -> read_aborts_on_inter_chunk_stall... hangs >60s); serve-deadline (drop write timeout -> serve_releases_the_reservation... hangs, 5s guard trips).

MPED-ARCHITECT DEEP REVIEW (done): found + FIXED the headline - the raw-stream rewrite had dropped request-response's whole-exchange timeout, so the serve-side request-read and response-write were unbounded (a non-reading consumer could park the serve task on yamux backpressure). Fixed: all serve phases deadline-bound; new bite serve_releases_the_reservation_when_the_consumer_never_reads_the_response. Corrected mped's premise that the reservation was pinned THROUGH the write (it was scoped to the OffLoop arm, released at production-end); now deliberately held through the write for correct in-flight accounting. Also fixed doc-drift (/nar/1->/nar/2 headers; stale worker-command comment). Accepted-with-note: Memory-path reservation releases at admit (inline/instant, finding 5); global concurrent-serve semaphore is possible future hardening (finding 3, mitigated by per-task deadlines + yamux cap).

HONEST LIMITS -> TASK-197 (filed): (a) gate-1 byte-corruption caught at stream COMPLETION not per-chunk (per-chunk needs a bao outboard on the wire); (b) serve side still BUFFERS the produced NAR before shipping (the serve-time integrity recheck must complete before any byte ships). Both resolved by adding a bao outboard to the transport wire.

REMAINING FOR THE GATE: codex review of streaming size-abort correctness, body-idle, off-worker non-blocking, cancellation/reap, gate-1 streaming verify, no frozen-wire change. NOT self-certifying Done.

REGATE-2 (2026-08-13): addressed codex NO-GO from the first DEEP gate. Bounded gate re-run green; leaving In Progress for the codex re-gate.

DECISIVE FIX (Memory-path in-flight ceiling was bypassable): the serve-deadline fix had held the InflightReservation THROUGH the write only on the Process path (Serve::OffLoop); the MEMORY path (Serve::Now) dropped its reservation inside admit() BEFORE the socket write, so a never-reading consumer parked a blocked reservation-free Memory write and run_accept_loop could spawn unbounded such writes -> the in-flight byte ceiling was defeated for memory-backed content. FIX: Serve::Now now carries reservation: Option<InflightReservation> (Some for an inline Memory serve, None for a non-admit that reserved nothing); admit() hands the Memory reserve back instead of dropping it; serve_stream holds it (Memory OR Process) through production AND the response write, released exactly once on every path (completion / consumer-hung-up / deadline / drop / abort). The ceiling now bounds ALL concurrent in-flight serve writes regardless of NarSource. (Also fixed a doc-comment mis-attachment: the produce_admitted doc had merged onto the max_serve_duration accessor.)

STRENGTHENED BITES:
- Body-idle: StatusThenStall -> StatusChunkThenStall (status + ONE real body chunk + stall). read_aborts_on_inter_chunk_stall_within_the_idle_bound now proves the idle timer is RE-ARMED per chunk (the stall it catches happens AFTER a chunk already streamed), not just guarded on the first body read.
- Never-reader ceiling (the DECISIVE oracle): new a_never_reading_memory_consumer_holds_the_inflight_ceiling_against_a_second_serve - a Memory never-reader charges the ceiling; the test OBSERVES inflight == NAR size while its write is blocked, asserts a SECOND serve is Declined(Busy) (ceiling held), then that it releases to zero after the blocked serve is dropped. PROVEN TO BITE: with the pre-fix Memory-drop-before-write behavior it FAILS at 3s ('never-reader #1 never charged the in-flight ceiling - the ceiling is bypassable'). Kept serve_releases... (Process deadline-termination) too.

total_timeout SCOPE (codex Medium - FIXED here, small change): NarTransfer::fetch now wraps the WHOLE remote operation (DHT resolution/locate + add_address + dial + stream) in tokio::time::timeout(total_timeout, ...), not just the transfer. A hanging kad resolution is now bounded by the envelope total (previously only kad's own query timeout bounded it, so fetch could run resolution + total_timeout). dial_timeout / body_idle_timeout remain the finer bounds inside.

KEPT ALL codex-confirmed-sound properties (mid-stream abort genuine, Process reservation exactly-once, cancellation/reap, no bad store path, frozen wire unchanged, independence green).

BOUNDED GATE (inside nix develop, NOT full just test - orchestrator runs that): cargo fmt --all --check = 0; cargo build -p fabric-libp2p --locked = 0; cargo clippy -p fabric-libp2p --all-targets -D warnings = 0; python3 scripts/check-independence.py = 0; cargo test -p fabric-libp2p --locked = 64 passed / 0 failed (44 lib, 10 nar_transport, 10 others). Files: fabric-libp2p/src/nar.rs, fabric-libp2p/src/transport.rs.

RE-GATE: codex re-checks the Memory-path reservation-through-write (exactly-once release on all paths), the two strengthened bites, and the total_timeout scope.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Replaced the libp2p request-response NAR carrier (buffered whole NAR, 256 MiB cap, post-receive size check, inline serve on the poll thread) with a raw libp2p-stream protocol /nix-p2p/<scope>/nar/2. AC#1 the fetcher aborts MID-STREAM the instant cumulative bytes exceed the per-call expected_size (<= one 64KiB overshoot; two-node 1MiB-served/4KiB-bound bite). AC#2 a real inter-chunk body_idle_timeout (fresh per-read timeout, re-armed each chunk), distinct from total_timeout. AC#3 serve production streams off the swarm worker (per-stream tasks; kad stays responsive during a slow serve). The in-flight byte ceiling is a CAS reserve whose InflightReservation guard is held THROUGH the write for BOTH Memory and Process serves (released exactly once on every path), so a never-reading consumer cannot bypass it (mutation-proven ceiling bite). total_timeout now bounds the WHOLE fetch (resolution+dial+request+response). Gate-1 BLAKE3(RawNarV1) verified at stream completion (no bad store path); the serve side still rechecks len+BLAKE3 before shipping. Frozen wire untouched (only the transport protocol name /nar/1->/nar/2). DEEP-gated: codex NO-GO (Memory-path reservation dropped before write -> ceiling bypass) -> held-through-write on both paths -> codex GO; full just test 677/0. Honest limits (TASK-197): per-chunk verify (currently at completion) + serve-side buffer-before-ship both need a bao outboard on the stream wire. libp2p-stream stays disjoint from testproxy (independence green).
<!-- SECTION:FINAL_SUMMARY:END -->
