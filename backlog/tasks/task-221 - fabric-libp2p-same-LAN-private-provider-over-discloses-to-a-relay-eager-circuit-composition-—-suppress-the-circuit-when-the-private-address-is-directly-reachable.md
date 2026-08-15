---
id: TASK-221
title: >-
  fabric-libp2p: same-LAN private provider over-discloses to a relay (eager
  circuit composition) — suppress the circuit when the private address is
  directly reachable
status: To Do
assignee: []
created_date: '2026-08-15 19:08'
labels:
  - libp2p
  - fabric
  - nat
  - privacy
  - hardening
dependencies:
  - TASK-218
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-218 composes a relay /p2p-circuit dial-candidate (and records a Relay disclosure to the relay operator) whenever kad can only place a provider at a PRIVATE (RFC1918)/link-local address. A provider on the consumers OWN LAN is ALSO directly reachable at that private address, so composing a circuit + disclosing to a relay for it is unnecessary over-disclosure (lookup-leakage is a tracked PRD privacy axis). Root: the consumer cannot distinguish a same-LAN private address (directly reachable) from a cross-NAT private address (needs a relay) from the address alone. TASK-218 deliberately accepts this (the real-NAT cornerstone, nat-vm-test 192.168.x provider, depends on composing for private addresses) and documents it in fabric-libp2p/src/locator.rs. Candidate resolutions: probe the direct private dial first and only compose/disclose the circuit on direct-dial failure (fallback, not eager); or scope by observed local subnet. Do NOT weaken kad-exclusive discovery or the no-injection guard. Distinct from TASK-219 (which is about discovering an UNKNOWN relay in multi-relay deployments); this is about SUPPRESSING an unnecessary circuit for a directly-reachable private provider.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A provider reachable directly at a same-LAN private address does NOT compose a relay circuit and records NO Relay disclosure, while a cross-NAT private provider (nat-vm-test 192.168.x) STILL composes; proven by a test that distinguishes the two
- [ ] #2 kad-exclusive discovery and check-discovery-no-shortcut.py are not weakened
<!-- AC:END -->
