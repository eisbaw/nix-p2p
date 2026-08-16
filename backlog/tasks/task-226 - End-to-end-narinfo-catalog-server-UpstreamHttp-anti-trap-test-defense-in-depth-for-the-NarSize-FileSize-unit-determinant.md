---
id: TASK-226
title: >-
  End-to-end narinfo->catalog->server->UpstreamHttp anti-trap test
  (defense-in-depth for the NarSize/FileSize unit determinant)
status: Done
assignee:
  - '@claude'
created_date: '2026-08-15 23:10'
updated_date: '2026-08-16 01:48'
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

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Plan: add ONE integration test in daemon/tests spanning parse(catalog)->server Route::Nar (transport threading, server.rs L211)->upstream fetch_streaming/compute_transport_cap, via the common spawn_daemon+MockUpstream harness. Narinfo uses .nar URL suffix + Compression: xz + NarSize < on-wire FileSize, so the compressed body (FileSize>NarSize) must stream to completion (cap = on-wire Content-Length, never NarSize). The .nar suffix makes it bite parse OR server OR upstream single-layer Raw-smuggle mutations. Mutation-proof: temporarily inject Raw at server.rs L211 -> expect RED, restore -> green. Report actual gate numbers.

Done. Added daemon/tests/nar_size_filesize_e2e_anti_trap.rs::compressed_body_over_uncompressed_narsize_streams_end_to_end - ONE integration test spanning parse(catalog parse_correlation) -> catalog.record -> server Route::Nar (threads meta.transport into NarKey::SignedNarHash) -> upstream resolve_within/fetch_streaming/compute_transport_cap, driven through the REAL daemon over a MockUpstream. Narinfo: URL nar/<t>.nar (suffix says raw) + Compression: xz (authoritative compressed) + NarSize 1000 < on-wire FileSize/Content-Length 3072. Positive path: the compressed body streams to completion byte-verbatim (3072B, complete), bounded by Content-Length not NarSize. Mutation proof at SERVER layer (server.rs Route::Nar: transport meta.transport -> NarinfoTransport{Raw}): RED (daemon log: streamed 3072 on-wire body bytes, over the 1000-byte transport bound; aborting mid-stream; client got a reset, status None) -> restored server.rs byte-identical to HEAD -> green. The .nar-suffix+xz design also bites a Raw-smuggle at the parse or upstream layer, giving 3-layer defense-in-depth. Gate (nix dev shell): cargo test -p daemon-core -p daemon = 452 passed / 0 failed (daemon-core lib 203 ok, 1 ignored; new test ok); cargo fmt --check clean; cargo clippy -p daemon-core -p daemon --all-targets -- -D warnings clean; scripts/check-no-floats.py clean (compile-time const _ assert, integer byte counts only). No production code changed (test-only). e2e (just e2e) NOT run - in-process end-to-end test is the anti-trap oracle; noted as nice-to-have.
<!-- SECTION:NOTES:END -->
