---
id: TASK-226
title: >-
  End-to-end narinfo->catalog->server->UpstreamHttp anti-trap test
  (defense-in-depth for the NarSize/FileSize unit determinant)
status: To Do
assignee: []
created_date: '2026-08-15 23:10'
labels:
  - daemon
  - hardening
  - test-coverage
dependencies:
  - TASK-25
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
codex DEEP-gate (TASK-25 re-gate) MEDIUM non-gating finding: the NarSize/FileSize anti-trap is tested at TWO layers separately - catalog::compression_is_authoritative_not_the_url_suffix (parse layer) and an upstream streaming test that supplies Compressed directly - but there is NO single end-to-end narinfo -> catalog -> server (NarKey::SignedNarHash.transport) -> UpstreamHttp::fetch_streaming anti-trap test. So a mutation at server.rs:211 that injected Compression=Raw for a compressed body could evade BOTH existing tests while breaking production. Current wiring is CORRECT (codex confirmed Compression flows through all layers; reverting cap computation to URL-suffix makes the streaming test RED). This task: add ONE end-to-end test that drives a narinfo with Compression:xz through the real catalog+server+UpstreamHttp path and asserts the on-wire compressed body is NOT capped by the uncompressed NarSize - defense-in-depth so no single-layer mutation can smuggle Raw. Hardening-wave rigor, not gate-breaking. Relates: TASK-25 (source), and the [[nar-size-vs-file-size-unit-trap]] 6th-recurrence memory.
<!-- SECTION:DESCRIPTION:END -->
