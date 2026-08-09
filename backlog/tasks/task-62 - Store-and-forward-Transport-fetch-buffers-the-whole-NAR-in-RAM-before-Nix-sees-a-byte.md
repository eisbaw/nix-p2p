---
id: TASK-62
title: >-
  Store-and-forward: Transport::fetch buffers the whole NAR in RAM before Nix
  sees a byte
status: To Do
assignee: []
created_date: '2026-08-09 13:24'
updated_date: '2026-08-09 13:33'
labels: []
dependencies:
  - TASK-65
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found by TASK-42. daemon/src/transport_fetch.rs:295 - 'async fn fetch(..) -> Result<Vec<u8>, TransportError>' - the p2p path materializes the ENTIRE NAR in memory, verifies it, then serves it to Nix.

CORRECTED JUSTIFICATION (Mark-emulator review, supersedes the original filing): this is NOT a latency fix. The measured 3.5x peer-path latency penalty is explained, to within noise, by iroh's throughput deficit alone (110 MiB / 758 MB/s = 0.152 s vs / 210 MB/s = 0.549 s; measured 0.159 vs 0.562; latency ratio 3.53 vs throughput ratio 3.61 - see TASK-64). Store-and-forward overlaps only the CHEAP daemon->Nix loopback leg, so expect wall clock ~0.562 -> ~0.55 s. If this ships claiming a latency win it will not deliver one.

The three real reasons to do it:
(1) FETCHER RSS decouples from NAR size (measured 1.23x today).
(2) It RESTRICTS THE ADMISSIBLE POLICY SET, which is why it must land before TASK-44. Once the 200 and the first body byte are committed to Nix, abort-to-cache is no longer invisible. 'Abort after T' and 'hedge' become fundamentally different mechanisms than under buffering - hedge becomes 'hold the response head until first-past-the-gate, then commit and stream' with a bounded-buffer cost, rather than 'run both to completion, double the memory, pick a winner'. Modeling three candidates in a world with no commit deadline and then implementing them in a world with one is wasted modeling.
(3) It creates a NEW BYTE-CROSSING CLASS (peer stream committed, aborted mid-body, Nix refetches upstream) that the frozen counting rule must be able to express - hence TASK-52 (counting-rule v3 freeze) comes AFTER this, not before. Freezing an irreversible rule before landing the change that creates a new provenance case is how a frozen surface gets burned.

Streaming is safe on trust grounds: iroh-blobs uses bao verified streaming so gate-1 is incremental per chunk, Nix independently re-verifies sha256==NarHash over the whole stream (gate-2), and the daemon and peers sit outside the trust base. daemon/src/transport_iroh.rs:480 (dial_and_stream) already loops leaf-by-leaf for the NarSize abort, and NarBody is already a BoxBody stream - the seam exists.

WHAT IT COSTS (do not merge without these): the INVISIBLE FALLBACK is lost. Today TransportNarSource::resolve (transport_fetch.rs:423-489) fails BEFORE any response head is written, so FallbackNarSource turns a peer failure into a silent upstream fetch (S2). After streaming, a mid-body peer failure is client-visible, and the build's survival depends on Nix's retry behavior across substituters after a partial NAR - an empirical question about NIX, not about our code, and it is the PRD's headline additive invariant.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 TTFB oracle: time-to-first-byte measured AT THE HTTP CLIENT, with a pinned TTFB/total ratio; it must BITE - revert to buffering and the check fails. Inspection is not an oracle, and streaming into an unbounded channel that flushes at the end must not pass
- [ ] #2 BACKPRESSURE: with a deliberately slow-reading client, daemon RSS stays bounded and independent of NAR size. Without this the buffer has moved, not gone
- [ ] #3 FAILURE SEMANTICS at the new boundary: after a mid-body peer abort or corruption (kill a peer at ~50% of a 110 MiB NAR), the BUILD STILL SUCCEEDS via fallback and the store path is absent-or-correct, never wrong. The daemon can no longer prevent partial delivery, so the guarantee moves to gate-2 plus Nix's retry - extend TASK-7's killed-mid-NAR suite and prove by mutation
- [ ] #4 FRAMING: Content-Length from the signed NarSize on the correlated path, chunked framing on the cold-start None path - both tested (transport_fetch.rs:481 currently sets it from bytes.len()). Peer stream torn down on HEAD and on client disconnect (server.rs:137 notes a HEAD NAR opens the stream)
- [ ] #5 RSS decouples from NAR size, GATED on a fitted slope over >=5 sizes with CI (needs TASK-65's axis; a single-point check is unfalsifiable). Wall-clock is predicted UNCHANGED - record that prediction up front so 'no latency win' reads as confirmation, not failure
<!-- AC:END -->
