---
id: TASK-197
title: 'fabric-libp2p: Bao-authenticated /nar/4 with bounded two-pass regeneration'
status: Done
assignee: []
created_date: '2026-08-13 16:53'
updated_date: '2026-08-18 19:31'
labels:
  - libp2p
  - fabric
  - transport
  - streaming
  - wave-2c
dependencies:
  - TASK-157
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-157 replaced the request-response NAR carrier with a raw libp2p-stream protocol (/nar/2) that carries the raw NAR bytes ALONE. Two honest residuals from that cycle, both rooted in the same missing wire element - a bao outboard tree interleaved with the NAR bytes (as iroh-blobs' bao stream carries): (1) FETCH per-chunk verify - the SIZE abort is truly mid-stream, but per-CHUNK byte-corruption detection (catching a flipped byte before EOF) is not possible without the bao tree; today gate-1 BLAKE3 (frozen from_raw_nar) verifies at stream completion (single pass, memory bounded to cap+chunk). The trust property holds - a corrupt peer fails the fetch - only the detection is at EOF, not per chunk. (2) SERVE stdout passthrough - the serve side still BUFFERS the produced NAR before streaming it out, because the serve-time integrity recheck (len==declared_size AND BLAKE3(RawNarV1)==content, 'never ship the wrong bytes under the right name', exercised by a_rebuilt_store_source_is_declined_and_never_ships_wrong_bytes) must complete BEFORE any byte ships. Piping nix-store --dump stdout straight to the socket needs the bao outboard so the recheck can be incremental. Adding a bao outboard to /nar/2 (or a /nar/3) resolves both. NOTE: this changes the transport wire (churnable), not the frozen RawNarV1/claim/ContentKey/ProviderRecord surfaces.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A wholesale /nar/4 wire carries Bao full-range preorder proofs for fixed 64-KiB raw leaves. A fetcher exposes a leaf only after it authenticates against the requested BLAKE3; corrupt proof or content fails before that leaf reaches the consumer.
- [x] #2 Process-backed supply uses two bounded regeneration passes without retaining RawNarV1 as a whole: proof preparation, then authenticated delivery. Each pass consumes exactly declared NarSize, reaches EOF, exits successfully, and pass-1 root equals the request.
- [x] #3 Provider authenticates every pass-2 leaf before socket write. Fetch success requires an explicit COMPLETE marker followed by clean FIN and no trailing bytes; final consumer completion, preferably the final leaf, is withheld until this terminal sequence succeeds.
- [x] #4 One absolute serve deadline covers request parsing, both passes, socket backpressure, COMPLETE and FIN, cancellation, and a separately bounded measured reap tail. Slow readers backpressure pass 2 and drop or timeout reaps producers and releases reservations.
- [x] #5 Raw and per-leaf zstd codecs produce identical RawNarV1. Encoded leaf length, decoder window, and exact geometry-derived output are bounded before allocation; zstd bombs, trailing frames, and oversized leaves fail closed.
- [x] #6 A real two-node test observes the first authenticated leaf while the provider is blocked before later EOF. Corruption, proof mutation, truncation, duplication or reordering, wrong raw_size, oversized encoded leaf, zstd bomb or trailing frame, missing COMPLETE, post-COMPLETE data, and nonzero exit after exact stdout are mutation-proven failures.
- [x] #7 The transport Bao pipeline buffers at most one encoded leaf, one raw leaf, bounded process/codec chunks, and O(tree depth), plus a declared-size-derived ephemeral provider outboard; it exposes a bounded streaming primitive for TASK-62. The existing NarTransfer compatibility collector remains explicitly O(N) until TASK-62 connects that primitive to HTTP, and memory-backed test supply may own its input Vec.
- [x] #8 Only /nar/4 is registered. A /nar/3-only peer is classified as protocol-incompatible or not-opened and no /nar/3 stream is attempted; normal offer fallback may try another peer or upstream.
- [x] #9 Evidence reports proof-preparation time, authenticated-first-leaf time, total serve time, both pass byte counts, and per-leaf-zstd wire regression versus the prior single-frame codec. Claims explicitly state that the design removes process-path whole-NAR buffering but does not improve absolute TTFB.
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Introduce the versioned Bao wire and bounded verified-leaf primitive; add replayable supervised stdout with cancellation and exact completion; implement two-pass serve and bounded fetch decode; wholesale-bump the swarm to /nar/4; update shaped-wire accounting and documentation; mutation-test unit and real two-node paths; run the full e2e and review gates.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-08-18 critical-path audit for TASK-62: /nar/3 can size-abort mid-stream but cannot authenticate a chunk against the requested BLAKE3 before EOF. TASK-62 AC#6 therefore depends on this task. Required implementation shape: a versioned bao-capable wire; bounded fetch and serve memory; backpressure and drop cancellation; explicit mixed-version behavior; a real two-node oracle where the first authenticated chunk is released while the provider is blocked before EOF; corruption/truncation/reordering mutations must fail before the corrupt/crossing chunk reaches the consumer. Do not claim streaming from socket-to-HTTP until this transport proof exists.

2026-08-18 Compass design gate: GO for wholesale /nar/4 and two-pass bounded streaming regeneration. Do not offer or fall back to /nar/3 because that silently drops this task guarantee. Use response-global codec, fixed 64-KiB leaves, raw proof pairs, independently framed bounded zstd leaves, and COMPLETE plus clean FIN. Both process invocations must prove exact size, EOF, and exit 0 under one absolute deadline. This is no-whole-NAR-buffer authenticated delivery, not literal one-pass stdout passthrough; it preserves roughly the existing pre-first-byte preparation cost and adds a second dump, so measure that and frame-reset compression overhead honestly. Persisted outboards remain out of scope, but measurements may justify revisiting the PRD decision later.

2026-08-18 Compass acceptance audit corrected the memory truth boundary: TASK-197 owns an O(leaf)+O(tree-depth) authenticated transport primitive and process-path bounded serving; NarTransfer still intentionally collects to Vec for compatibility. TASK-62 remains responsible for removing that O(N) collector and proving bounded socket-to-HTTP memory. This clarification does not waive the end-to-end requirement.

2026-08-18 CLOSED after independent QA, MPED, and Compass acceptance gates. Implementation is commit 8d4ec41. Clean detached-worktree evidence is evidence/task-197/8d4ec414ebe1/measurement.json: provenance binds full HEAD 8d4ec414ebe106d20ee0c55efad814dc8d9d21e7, git_worktree_dirty=false, unchanged-after-run=true, and all load-bearing flags true. Across three alternating shaped runs over a 16,777,216-byte synthetic compressible NAR, every raw and zstd pass1/pass2 count was exactly 16,777,216 bytes; proof preparation was 280,553,369..285,351,406 ns; authenticated first leaf was 368,913,940..424,332,157 ns from request origin; provider total serve was 7,400,623,720..7,863,436,876 ns raw and 2,135,802,578..2,182,196,307 ns zstd. Per-leaf zstd cost 4,270,133 encoded bytes versus the prior single-frame 4,219,763 (+50,370), or 4,287,491 versus 4,219,765 including response protocol (+67,726). This removes process-path whole-NAR buffering; it does not claim lower absolute TTFB. NarTransfer still has the named O(N) compatibility collector owned by TASK-62.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Shipped wholesale /nar/4: fixed 64-KiB Bao-authenticated leaves, bounded raw/per-leaf-zstd codecs, exact two-pass process regeneration, one absolute serve deadline with measured reap tail, COMPLETE plus clean-FIN completion, and no /nar/3 downgrade. A real two-Node blocked-pass2 oracle proves early authenticated leaf delivery; the mutation matrix fails corrupt, reordered, truncated, oversized, bomb, trailing, terminal, and nonzero-exit cases closed. Clean shaped evidence quantifies preparation, first-leaf, total-serve, exact pass bytes, and frame-reset overhead without claiming an absolute-TTFB win. TASK-62 now owns lifting the bounded verified-leaf primitive through PeerFabric to HTTP and removing the final O(N) collector.
<!-- SECTION:FINAL_SUMMARY:END -->
