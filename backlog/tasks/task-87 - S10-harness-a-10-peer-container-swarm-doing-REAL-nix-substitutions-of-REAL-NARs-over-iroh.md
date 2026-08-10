---
id: TASK-87
title: >-
  S10 harness: a 10+ peer container swarm doing REAL nix substitutions of REAL
  NARs over iroh
status: To Do
assignee: []
created_date: '2026-08-10 05:55'
updated_date: '2026-08-10 05:55'
labels:
  - wave-2b
dependencies:
  - TASK-83
  - TASK-57
  - TASK-58
  - TASK-54
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Owner request 2026-08-10. Everything measured so far is either 2 nodes (S6) or a swarm of daemon PROCESSES with synthetic payloads and a host-side HTTP reader standing in for nix (task-65 honest limits 1 and 2: 'the consumer is a host-side HTTP reader, not real nix' and 'payloads are synthetic - real framing, real NarHash, really signed, but never realised by nix'). This task builds the missing thing: >=10 CONTAINERS, each a real nix client plus a daemon, substituting a real closure, with the NAR bytes actually crossing iroh between them.

Why it is not just 'turn the swarm knob up':
- REAL NIX, not an HTTP reader. The consumer must be / so gate-2 (sig + NarHash) is exercised on every transfer and a wrong byte fails a build rather than a comparison.
- REAL NARS FROM THE STORE. Needs TASK-83 (the AvailabilityIndex wired into the daemon) so a node supplies by dumping a store path on demand, not from an --iroh-seed-nar file list. Hand-seeding 10 nodes is not the system under test.
- ENOUGH DISTINCT CONTENT. The fixture closure offers 4 attrs (ALL_ATTRS in scripts/e2e_harness.py:108). With 10 peers holding the same 4 paths there is no distribution to observe. Needs TASK-57's wide-fanout fixture (>=128 tiny substitutable paths).
- PEER WIRING AT N=10. Today peers are wired by --iroh-peer/--p2p-claim, which is O(n^2) flags at this size and models nothing real. Either a static full mesh built by the harness (acceptable interim, SAY SO) or real discovery (TASK-73). State which, because it determines whether cold-start numbers mean anything.
- INSTRUMENT COLLISION. TASK-58: the container instruments share one podman label and tear each other down. At 10+ containers this stops being theoretical.
- DISK. TASK-54. 10+ containers with a real closure each; add a fail-fast headroom precondition rather than a mid-run ENOSPC.

Scope this task to the HARNESS being able to run the topology and produce a trustworthy trace. The measurement it feeds is TASK-88.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 N>=10 containers, each running a real nix client and a daemon, complete real substitutions of a real closure with NAR bytes crossing iroh; N is a parameter, not a constant
- [ ] #2 Peer-served bytes are counted at the PROVIDER (the receiving daemon's self-report is untrusted narration, per the S6 rule), and every transfer passes gate-2 - a wrong byte must fail a build, shown by a corrupt-peer bite at this scale
- [ ] #3 The trace records, per transfer: which peer served it, which requested it, byte count in uncompressed-NAR units, wall-clock, and whether it fell back to upstream - enough for TASK-88 to compute offload over time without re-running
- [ ] #4 Concurrency is MEASURED not assumed (the task-18 rule): a run whose observed overlap does not match the intended fan-out is INVALID, not a data point
- [ ] #5 Honest limits: state whether peers were wired statically or discovered, and what that does to the realism of the result
<!-- AC:END -->
