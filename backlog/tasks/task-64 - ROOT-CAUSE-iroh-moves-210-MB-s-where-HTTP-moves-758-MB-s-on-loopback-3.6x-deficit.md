---
id: TASK-64
title: >-
  ROOT-CAUSE: iroh moves 210 MB/s where HTTP moves 758 MB/s on loopback (3.6x
  deficit)
status: To Do
assignee: []
created_date: '2026-08-09 13:31'
labels: []
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-42 measured, on the same host, same 110 MiB NAR: HTTP/testproxy 758 MB/s vs iroh-blobs 210 MB/s. This single ratio explains essentially ALL of the observed peer-path latency penalty (110 MiB / 758 = 0.152 s vs / 210 = 0.549 s; measured 0.159 vs 0.562 - latency ratio 3.53 against throughput ratio 3.61). It is therefore the DOMINANT term in every latency, speedup and policy conclusion wave-2a draws, and it is currently unexplained. Candidate causes to discriminate, not guess between: BLAKE3/bao verification cost on the receive path; a single QUIC stream with no parallelism; userspace copies (see the to_vec() at transport_iroh.rs:350); 16 KiB chunk-group granularity; loopback MTU/GSO effects. FIRST STEP is the cheap disambiguation: measure iroh throughput PEER-TO-PEER with no HTTP client and no daemon in the path. If it is still ~210 MB/s the deficit is transport-side; if it jumps, our own pipeline is implicated and TASK-62's priority changes. Root-cause it - do NOT paper over it with a workaround or a policy that avoids the peer path.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Peer-to-peer iroh throughput measured with the daemon and HTTP client OUT of the path, on the same host and fixture: reported next to the 210 MB/s in-daemon number and the 758 MB/s HTTP number
- [ ] #2 The deficit is attributed to a NAMED cause with evidence (a measurement or a profile that discriminates between the candidates), not a plausible story
- [ ] #3 If the cause is fixable, the fix is measured and the before/after throughput pinned; if it is inherent to bao/QUIC, that is stated as a measured property of the transport and carried into the PRD's honest-limits
<!-- AC:END -->
