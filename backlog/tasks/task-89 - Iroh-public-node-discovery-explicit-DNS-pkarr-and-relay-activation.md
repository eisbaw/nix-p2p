---
id: TASK-89
title: 'Iroh public node discovery: explicit DNS/pkarr and relay activation'
status: To Do
assignee: []
created_date: '2026-08-10 07:09'
updated_date: '2026-08-11 03:41'
labels:
  - wave-2b
  - discovery
  - iroh
dependencies:
  - TASK-114
  - TASK-115
  - TASK-116
  - TASK-130
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Wire public-capable DNS/pkarr address discovery and relay selection into TASK-115 shared runtime through explicit capability inputs, after TASK-130 proves the LAN-local component. This is NODE discovery (NodeId to relay URL plus direct addresses), not content discovery (TASK-100/101/103/116). The default iroh DNS server and relay are n0-run third-party dependencies and must be deliberate, switchable choices. TASK-115 bind scopes alone activate nothing. Mainline address lookup is entirely deferred to TASK-131 behind TASK-96. The hermetic offline-test and LAN-only paths remain free of public infrastructure, and no n0/public default is inherited.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Two daemons with public-capable discovery explicitly enabled resolve stable NodeId to dialable direct/relay addresses and establish a real Iroh connection with no peer address supplied on the command line. The trace distinguishes direct, hole-punched and relay paths plus discovery source.
- [ ] #2 Any reliance on an n0-run DNS server or relay is a deliberate documented switchable choice, stated in README honest limits and runtime preflight rather than inherited from an Iroh preset or builder default.
- [ ] #3 DNS/pkarr address lookup and relay use are independently registered through TASK-115 capabilities and remain OFF in offline-test and LAN-only configurations. This task has no Mainline dependency or implementation; TASK-131 alone may add it after TASK-96.
- [ ] #4 Documentation and status state exactly what each enabled mechanism publishes and queries about this node, its recipients/third-party dependencies, TTL/republish behavior and whether client-only operation still leaks lookups. Node/address publication is distinguished from bounded content yes/no queries.
- [ ] #5 NodeId remains stable across restart via TASK-115; a no-address-flags restart reconnects within a numeric deadline, while DNS/relay outage is visible and bounded rather than misreported as a content MISS.
- [ ] #6 Bites prove that disabling each selected DNS/relay mechanism restores failure or the named alternate path, injecting an address invalidates the proof, and offline-test or LAN-only packet capture observes no DNS/pkarr/relay contact.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Scope split before TASK-115 implementation: TASK-130 owns LAN-local address discovery; TASK-89 owns deliberate DNS/pkarr and relay activation only; TASK-131 owns conditional Mainline address lookup. TASK-89 consumes TASK-115 lower-level capabilities and does not own identity/endpoint lifetime, content discovery or operator-mode policy.
<!-- SECTION:NOTES:END -->
