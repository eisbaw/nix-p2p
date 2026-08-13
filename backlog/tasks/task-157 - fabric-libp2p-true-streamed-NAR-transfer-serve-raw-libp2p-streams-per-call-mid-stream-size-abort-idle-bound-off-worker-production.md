---
id: TASK-157
title: >-
  fabric-libp2p: true streamed NAR transfer/serve (raw libp2p streams) -
  per-call mid-stream size abort + idle bound + off-worker production
status: To Do
assignee: []
created_date: '2026-08-12 08:38'
updated_date: '2026-08-13 14:56'
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
<!-- SECTION:NOTES:END -->
