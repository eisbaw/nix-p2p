---
id: TASK-77
title: Announce-after-fetch with an explicit announce budget
status: To Do
assignee: []
created_date: '2026-08-09 21:01'
updated_date: '2026-08-09 21:02'
labels:
  - wave-2b
dependencies:
  - TASK-72
  - TASK-61
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
PRD MVP scope names 'announce-after-fetch with an explicit announce budget'. Neither exists. Today a node announces only what the harness told it to (--p2p-claim), and the availability index answers hold-queries derived on demand - nothing publishes new availability after a successful fetch.

Announce-after-fetch is what makes the swarm GROW: a node that just fetched a NAR becomes a holder for it, so popular paths acquire holders naturally instead of depending on a few seeders. The BUDGET is the guardrail - unbounded announcing is a self-DoS (every announce invites dials, and dials cost RAM at 2.0 B/B per serve, see TASK-72's unbounded-serve problem) and it is also a privacy surface: what you announce reveals what you fetched.

Interacts with TASK-72 (a node must not announce what it cannot serve) and TASK-61 (the supply model decides whether a fetched NAR is retained at all, or regenerated from /nix/store on demand - which changes what announce-after-fetch even means, since after nix realises the path the store IS the copy).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 After a successful peer or upstream fetch, the node becomes a discoverable holder for that content, and a second node can fetch it FROM the first - shown end to end
- [ ] #2 The announce budget is explicit, configurable and ENFORCED: past the budget, announcing stops rather than degrading. Bite by mutation - remove the budget and the count grows unbounded
- [ ] #3 A node never announces content it cannot serve (consistency with TASK-72's index-coverage == provider-coverage requirement)
- [ ] #4 The privacy cost is stated: announcing reveals what you fetched. Interacts with the leech-mode flag (TASK-78)
<!-- AC:END -->
