---
id: TASK-78
title: Leech-mode flag (consume without serving)
status: To Do
assignee: []
created_date: '2026-08-09 21:02'
updated_date: '2026-08-09 21:02'
labels:
  - wave-2b
dependencies:
  - TASK-77
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
PRD MVP scope names a 'leech-mode flag'. Nothing exists. A node in leech mode fetches from peers but does not serve or announce - the opt-out for users who cannot or will not contribute uplink (metered connections, laptops on cellular, corporate networks, or simply an unwillingness to reveal what they hold).

This is also an honest-limits item the PRD already acknowledges under non-goals: 'incentives/economics; long-tail availability guarantees... The long tail is where a CDN is strong and swarms are weak'. Leech mode makes the free-rider case explicit rather than pretending it away - and the profiling harness should be able to MODEL a swarm with a given leech fraction, because a swarm that is 90% leeches behaves very differently from one that is 10%.

Cheap to implement, and it is the privacy answer to TASK-77's 'announcing reveals what you fetched'.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A leech-mode flag disables serving AND announcing; a leech node still fetches from peers successfully, and peers cannot obtain content from it (verified from the peer side, not the leech's self-report)
- [ ] #2 Leech mode is observable in the profiling report, and the harness can run a swarm with a configurable leech FRACTION so the effect on offload can be modelled
- [ ] #3 Honest statement of what a high leech fraction does to the value thesis, measured on the testbed rather than asserted
<!-- AC:END -->
