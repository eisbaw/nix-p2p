---
id: TASK-270
title: >-
  Consider negotiated light-compression (zstd-3) on the peer link for
  home-bandwidth swarm peers
status: To Do
assignee: []
created_date: '2026-08-19 19:15'
labels:
  - measurement-followup
  - deferred
  - Low
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
From TASK-269 crossover sweep: link compression helps ONLY in the ~100 Mbit home-bandwidth WAN-swarm regime, and only with a LIGHT codec (zstd-1..3). Heavy codecs (zstd-19/xz/brotli-11) NEVER beat the CDN because on-the-fly per-serve compress CPU exceeds the transfer savings (python3 xz-9 = 51s compress CPU per serve). At LAN/datacenter speeds raw wins outright, so the org/LAN-first product needs NO link compression. Evidence: evidence/task-269/crossover_map.json + docs/profiling.md sweep section. Scope IF a home-bandwidth swarm becomes a target: a negotiated zstd-3 link-compression OPTION (peer advertises capability, requester opts in), never a fixed high-ratio codec. Deliberately DEFERRED behind discovery + LAN-first per the North Star; do not implement pre-emptively.
<!-- SECTION:DESCRIPTION:END -->
