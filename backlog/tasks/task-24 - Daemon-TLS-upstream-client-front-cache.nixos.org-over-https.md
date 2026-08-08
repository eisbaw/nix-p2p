---
id: TASK-24
title: Daemon TLS upstream client (front cache.nixos.org over https)
status: To Do
assignee: []
created_date: '2026-08-08 08:16'
labels:
  - wave1-followup
  - daemon
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-4 shipped the daemon upstream client (UpstreamHttp) as plain HTTP only (daemon/src/upstream.rs parse_authority rejects https). Fronting the real cache.nixos.org needs TLS. Wave-1 tests all use the loopback mock/testproxy over HTTP, so this is out of wave-1 scope but required before the daemon is useful against the real CDN. Sibling of task-22 (testproxy TLS). Add a TLS-capable connector (rustls) behind the same UpstreamHttp::send path; keep auto-decompression OFF.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 https:// upstream base is accepted and connects over TLS
- [ ] #2 verbatim byte forwarding + no auto-decompression preserved over TLS (AC#6 property holds)
<!-- AC:END -->
