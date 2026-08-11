---
id: TASK-116
title: 'Iroh BatchHoldQuery ALPN: networked bounded discovery of unannounced NARs'
status: To Do
assignee: []
created_date: '2026-08-10 22:23'
updated_date: '2026-08-11 03:31'
labels:
  - iroh
  - discovery
  - privacy
  - wave-2c
dependencies:
  - TASK-83
  - TASK-100
  - TASK-104
  - TASK-106
  - TASK-107
  - TASK-110
  - TASK-115
  - TASK-130
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Put the existing batched yes/no hold-query protocol on the real shared Iroh endpoint so a node can ask an already-known set of candidate NodeIds about NarHash keys that were never globally announced. This is privacy-preserving whole-store probing, not global peer discovery or an identity census: candidate NodeIds must come from a named source such as LAN discovery, prior rendezvous, tracker/DHT results or explicit operator configuration. A caller names keys; a responder never lists holdings. Use the shared ContentDiscovery outcomes, total deadlines and responder work budgets.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The shared Iroh router serves a versioned BatchHoldQuery ALPN and a remote node resolves multiple holders/offers for a closure over a real network namespace, not an in-process trait fake.
- [ ] #2 The wire path preserves structural no-enumeration, caps keys/offers/work, enforces one total caller deadline, abandons the remainder after a peer fault, and exposes miss separately from unavailable.
- [ ] #3 Unknown protocol versions and malformed/oversized requests fail closed without killing the router; a supported older version continues to interoperate.
- [ ] #4 Bites prove that removing the total deadline, offer cap, or named-key restriction makes a test fail; provider-side bytes plus Nix gate-2 prove the success path is non-vacuous.
- [ ] #5 A store-backed unannounced NAR is found through candidate NodeIds supplied only by TASK-130 LAN discovery while DNS/pkarr, relay, Mainline and tracker mechanisms are disabled. With no peer address, p2p claim or content locator injected, a real Nix substitution completes over Iroh; provider bytes and Nix gate-2 make the vertical slice non-vacuous. The report names LAN candidate coverage and never calls bounded probing global discovery.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
This is bounded direct content probing over Iroh. Global announced-content lookup remains in TASK-101/TASK-103.
<!-- SECTION:NOTES:END -->
