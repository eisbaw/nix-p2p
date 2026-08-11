---
id: TASK-115
title: >-
  Iroh node runtime: persistent identity, one shared endpoint/router, explicit
  endpoint scopes
status: To Do
assignee: []
created_date: '2026-08-10 22:23'
updated_date: '2026-08-11 03:30'
labels:
  - iroh
  - production
  - wave-2c
dependencies:
  - TASK-39
  - TASK-69
  - TASK-114
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Replace the current test-shaped endpoint lifecycle with one deployment-capable Iroh node runtime. The daemon currently creates separate ephemeral endpoints for serving and fetching. A real node needs one persisted identity and one long-lived Endpoint/Router that serves iroh-blobs and can register additional ALPN handlers. This task owns identity persistence, endpoint/router lifetime, lower-level bind scopes and explicit relay/address-lookup capability inputs, plus a hermetic offline-test configuration. It does not activate LAN-local discovery (TASK-130), DNS/pkarr or relay discovery (TASK-89), conditional Mainline address lookup (TASK-131), choose content lookup policy (TASK-100/101/103/116), or define operator participation modes (TASK-120). No Iroh public-network default may be inherited implicitly.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A daemon state directory stores a versioned, integrity-checked Iroh secret-key record under restrictive directory and file permissions. Restart preserves the NodeId. Missing state initializes durably and atomically without clobbering an identity created concurrently. Existing unreadable, malformed, permission-unsafe, version-unknown, checksum-mismatched, symlink or non-regular state fails without rewrite or key regeneration.
- [ ] #2 One runtime builds one Endpoint and one Router after rejecting duplicate ALPN registrations. Provider, fetch transport and registered application handlers share that endpoint, NodeId and socket set. Provider and fetch handles cannot independently create or close endpoints.
- [ ] #3 Shutdown has a named numeric deadline. It stops new accepts, drains or cancels inbound and outbound streams and owned tasks, shuts down handlers and the Router, and closes the Endpoint. On deadline expiry it force-closes and aborts remaining owned tasks. A test immediately restarts on the same state directory and fixed port, observes the same NodeId, and detects no surviving task or socket.
- [ ] #4 Daemon and benchmark call the same endpoint constructor. The benchmark test selector is guarded equal to the daemon test selector, and a one-sided selector or constructor mutation fails. Persistent versus ephemeral identity is an explicit constructor input, not a duplicated builder.
- [ ] #5 One closed lower-level endpoint configuration represents offline-test, LAN-bind and global-bind scopes plus explicit relay and address-lookup capability inputs. Offline-test is the test default: it clears default IP transports, adds only explicit loopback binds, disables port mapping, relay, network-report probes and every AddressLookup service, and rejects injected network capabilities. Selecting LAN-bind or global-bind alone enables no discovery or public service; TASK-130, TASK-89 and TASK-131 activate and test their separate mechanisms. No path uses presets::N0.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Foundation for operational Iroh discovery. TASK-115 owns identity, endpoint/router lifetime, lower-level network scopes and capability inputs only. TASK-130 owns LAN address discovery; TASK-89 owns DNS/pkarr and relay discovery; TASK-131 owns conditional Mainline address lookup; TASK-100/101/103/116 own content lookup; TASK-120 owns operator participation modes. Pinned iroh Minimal is not offline: true offline-test must clear default IPv4/IPv6 transports, re-add loopback explicitly, disable portmapper, relay, net-report probes and all AddressLookup services.
<!-- SECTION:NOTES:END -->
