---
id: TASK-203
title: >-
  fabric-libp2p: pipelined streaming zstd compress on the NAR serve path
  (cancellation-preemptible + removes the LAN serial penalty)
status: To Do
assignee: []
created_date: '2026-08-14 08:28'
labels:
  - wave-2c
  - libp2p
  - transport
  - streaming
dependencies:
  - TASK-99
  - TASK-157
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-99 landed negotiated zstd link compression, but the serve side compresses the WHOLE produced NAR in a single synchronous peer_fabric::compress_zstd call (fabric-libp2p/src/nar.rs write_response, codec.rs compress_zstd) and the fetch side likewise feeds the decoder synchronously (BoundedZstdDecoder::push). Two coupled consequences codex flagged at the TASK-99 DEEP gate: (1) CANCELLATION-PREEMPTION GAP - the synchronous whole-buffer compress at write_response and the decoder.push at read_zstd_body cannot be preempted by the surrounding tokio serve/fetch deadline mid-call; a very large NAR compresses for seconds inside one .await point that the timeout cannot interrupt (the timeout only fires at the next await boundary). The integrity/OOM bounds are unaffected (still fail closed, still memory-bounded); this is a RESPONSIVENESS/preemption gap, not a safety gap. (2) LAN SERIAL PENALTY - because the whole NAR is compressed before the first byte ships (serial compress->send->decompress), even zstd-3 marginally net-LOSES on a ~204 MB/s LAN in the TASK-99 measurement (evidence/task-99, net_lan zstd_beats_raw=false). Pipelined streaming compression (compress-and-send in blocks, off the serve worker, chunked so the deadline can preempt between blocks) removes BOTH: the compressor overlaps the link instead of preceding it, and each block is an await boundary the deadline bounds. Wire-compatible with /nar/3 (a zstd frame is a zstd frame; streaming just changes HOW the serve produces it). Adaptive level/disable-on-fast-link is the cheaper complementary lever already noted in the codec DEFAULT_ZSTD_LEVEL doc. NOTE: churnable transport layer only; the frozen RawNarV1/ContentKey/claim surfaces are untouched.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Serve-side zstd compression streams the produced NAR in blocks (pipelined compress-and-send), so the first compressed bytes ship before the whole NAR is compressed, and a serve deadline can PREEMPT it between blocks (a large NAR no longer compresses inside one un-preemptible synchronous call)
- [ ] #2 The fetch-side bounded streaming decode remains fail-closed with the same integrity/OOM/window bounds (bomb/corruption/truncation/trailing still rejected, memory still cap + one block + window)
- [ ] #3 The LAN serial penalty is re-measured with pipelining ON: the net_lan verdict from TASK-99 (zstd-3 marginally loses under the serial whole-nar-compress model) is re-evaluated, or the honest 'raw on a fast LAN' fallback is documented
<!-- AC:END -->
