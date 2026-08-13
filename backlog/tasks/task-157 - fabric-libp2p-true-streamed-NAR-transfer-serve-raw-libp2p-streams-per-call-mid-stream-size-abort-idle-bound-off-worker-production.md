---
id: TASK-157
title: >-
  fabric-libp2p: true streamed NAR transfer/serve (raw libp2p streams) -
  per-call mid-stream size abort + idle bound + off-worker production
status: In Progress
assignee:
  - '@claude'
created_date: '2026-08-12 08:38'
updated_date: '2026-08-13 16:31'
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
- [ ] #1 the fetch side aborts a transfer the instant cumulative bytes exceed the per-call expected_size (mid-stream), proven by a bite test
- [ ] #2 the SafetyEnvelope body_idle_timeout is enforced as a real inter-chunk stall guard (not just total_timeout)
- [ ] #3 serve production runs OFF the swarm worker so a large serve does not block kad/discovery
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
<!-- SECTION:NOTES:END -->
