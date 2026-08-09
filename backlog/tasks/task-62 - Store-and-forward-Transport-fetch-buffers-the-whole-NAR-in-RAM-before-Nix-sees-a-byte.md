---
id: TASK-62
title: >-
  Store-and-forward: Transport::fetch buffers the whole NAR in RAM before Nix
  sees a byte
status: To Do
assignee: []
created_date: '2026-08-09 13:24'
labels: []
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found by task-42 profiling. daemon/src/transport_fetch.rs:295 - 'async fn fetch(..) -> Result<Vec<u8>, TransportError>' - the p2p path materializes the ENTIRE NAR in memory, verifies it, and only then serves it to Nix. Consequences measured on the 110 MiB fixture: fetcher peak RSS 1.23x the NAR size (node-a 135.9 MiB vs 10.7 MiB with peers off), and client realise 0.562 s peers-on vs 0.159 s peers-off - a 3.5x LATENCY PENALTY, because time-to-first-byte for Nix is the whole peer transfer. (Caveat: that arm's upstream is a loopback testproxy, so 0.283 is not a product speedup number - but the store-and-forward component of it is ours, not the network's.) Streaming is SAFE here and not a trust compromise: iroh-blobs uses bao verified streaming, so each chunk is BLAKE3-verified on arrival (gate-1 is incremental, not whole-blob), and Nix independently re-verifies sha256==NarHash over the full stream (gate-2). daemon/src/transport_iroh.rs already streams leaf-by-leaf for the NarSize abort, so the streaming seam exists. This confounds TASK-44's slow-HIT policy model: thresholds fitted against our own buffering latency would be tuned to an artifact.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The p2p NAR path streams: bytes reach the HTTP client as bao-verified chunks arrive, rather than after the whole blob is buffered
- [ ] #2 A hash-mismatch or truncated stream still FAILS - prove by mutation that a corrupt/short peer stream does not leave Nix with a successful partial (the corrupt-bite oracle must still bite once bytes are streamed)
- [ ] #3 Re-run just profile: fetcher peak RSS is no longer proportional to NAR size, and the peers-on vs peers-off realise gap is re-measured (before-numbers: 1.23x RSS, 0.562s vs 0.159s)
<!-- AC:END -->
