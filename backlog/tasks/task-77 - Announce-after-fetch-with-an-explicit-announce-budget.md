---
id: TASK-77
title: Announce-after-fetch with an explicit announce budget
status: To Do
assignee: []
created_date: '2026-08-09 21:01'
updated_date: '2026-08-09 22:09'
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

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
## Forward-carried from TASK-61/TASK-72: what the supply model retains, and what it costs to announce

TASK-61 decided: nothing is retained. A node holds a NAR only while a serve of it
is in flight. So an announce budget is NOT a storage budget - announcing costs no
bytes at rest at all.

WHAT ANNOUNCING DOES COST, measured: one streamed BLAKE3 pass over the NAR
(`Blake3Digest::stream_raw_nar`, 64 KiB peak allocation whatever the size) plus
the `nix-store --dump` that feeds it. On the owner's store that is a full read of
the path off disk - the dominant cost, not the hash (task-64: the peer path is
CPU-bound at ~204 MB/s with 72% of the work below our code). So your budget's
real unit is DUMPS PER INTERVAL / bytes read, not bytes stored. Sizing it as a
storage budget would be sizing the wrong quantity.

SECOND COST, and it is the one that will bite: every announce also creates a
promise this node must be able to keep. Task-72's rule is that a positive
hold-answer implies a servable blob. `setup_iroh_provider` already refuses at
STARTUP to announce a NAR larger than `--iroh-max-serve-nar-bytes`, because a
claim the node would then decline is the same defect in a different disguise.
Announce-after-fetch must apply the same check: never publish a claim for
something the serve budget would refuse.

THIRD: the announce is only durable while the process is. The digest -> path
binding is in memory (task-82 would persist it). An announce budget that assumes
announcements survive a restart is assuming something false today.
<!-- SECTION:NOTES:END -->
