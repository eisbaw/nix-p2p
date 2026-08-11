---
id: TASK-130
title: 'Iroh LAN node discovery: address-free local connection component'
status: To Do
assignee: []
created_date: '2026-08-11 03:30'
updated_date: '2026-08-11 03:34'
labels:
  - iroh
  - discovery
  - lan
  - wave-2c
dependencies:
  - TASK-114
  - TASK-115
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Add explicitly enabled LAN-local NodeId/address discovery to the shared TASK-115 runtime. This component discovers candidates and establishes a real Iroh connection within a local network without peer-address, claim or content-locator injection. It publishes no content inventory and contacts no DNS/pkarr, relay, Mainline, tracker or other public infrastructure. Full zero-content-injection Nix substitution is deliberately owned by TASK-100 plus TASK-116, which consume these recorded LAN candidates.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Offline-test remains the default and is network-silent. LAN discovery is opt-in and packet-capture evidence shows only the declared LAN-local multicast/direct traffic: no DNS/pkarr, n0 relay, Mainline, tracker or public bootstrap contact.
- [ ] #2 The mechanism documents and reports exactly which NodeId/address/service fields it advertises, recipients, TTL and withdrawal behavior. It advertises no NarHash, StorePath, closure membership or content inventory.
- [ ] #3 Startup, duplicate announcements, stale withdrawal, malformed/spoofed records, interface churn and restart are bounded by named deadlines; failures remain typed node-discovery unavailable outcomes and never become content MISS or bypass Iroh identity checks.
- [ ] #4 The evidence is explicitly component-level, records discovery source and confirmed network path, and cannot be labelled a zero-injection Nix build. TASK-116 must use TASK-130 LAN candidates with public discovery disabled to prove that full vertical slice.
- [ ] #5 Two daemon runtimes in separate network namespaces on the same LAN discover both stable NodeIds and dialable addresses through the explicitly enabled local mechanism, then establish a real bidirectional Iroh connection with no peer address, claim or content locator supplied by the harness.
<!-- AC:END -->
