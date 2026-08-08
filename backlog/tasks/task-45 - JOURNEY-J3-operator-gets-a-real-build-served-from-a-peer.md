---
id: TASK-45
title: 'JOURNEY J3: operator gets a real build served from a peer'
status: To Do
assignee: []
created_date: '2026-08-08 20:13'
labels:
  - journey
dependencies:
  - TASK-41
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Interspersed journey (wave-2a). Act as an operator with two machines (two daemon nodes): prime node B with a closure, then on node A run a real nix build and SEE it served from the peer (comprehensible logs: source=peer NodeId, bytes, duration), with cache.nixos.org untouched. Then take node B offline mid-build and watch fallback feel invisible. File friction as tasks; this is the human-facing proof the decentralization works.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Executable journey (just journey-p2p or extend just journey): the operator steps + asserted log events (one line per peer substitution: NarHash, source NodeId, bytes, duration - grep-asserted)
- [ ] #2 S6 experienced end-to-end (peer-served) AND S2 (peer offline mid-build -> fallback) - both asserted, not narrated
- [ ] #3 Friction filed as tasks or an explicit none-found emitted by the run
<!-- AC:END -->
