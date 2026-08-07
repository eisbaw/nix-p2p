---
id: TASK-12
title: 'JOURNEY J2: measurement journey - read the baseline like a decision-maker'
status: To Do
assignee: []
created_date: '2026-08-07 21:56'
updated_date: '2026-08-07 23:57'
labels:
  - journey
dependencies:
  - TASK-9
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Second interspersed journey. As the project owner: run the measurement workload (two realistic package closures, warm and cold), read the report, and answer in writing: what narinfo-to-nar gap does real traffic show (is the prefetch window real, PRD risk 3)? What would p2p have to beat? Baseline numbers land in TESTING.md and feed the re-plan task directly. If the report cannot answer these questions, that is the finding.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Baseline in TESTING.md: egress, p95 (with N and variance), gap-histogram summary; dated + fixture-workload version; report regenerated twice with agreeing results (run-to-run agreement asserted, not assumed)
- [ ] #2 Written answers committed: is the prefetch window real (gap data vs 1-4s DHT lookups, PRD risk 3)? what must p2p beat? - these feed the go/no-go checkpoint directly
- [ ] #3 Report gaps/friction filed as tasks
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
forward-carried from task-3 (119cbb7): the J2 baseline you write freezes against workload nix-p2p-fixture-workload-v1 (pinned in fixtures/workload.lock.json, described in TESTING.md 'Fixture workload'). Quote the version string next to every number in the baseline - a number without it cannot be compared to anything later.

Two honesty caveats to carry into how the baseline is read: (a) payloads are incompressible seeded bytes, so compression ratios are unrepresentative of real nixpkgs closures; (b) the workload is 4 paths totalling ~111 MiB, dominated by one 110 MiB uncompressed NAR - it exercises byte volume, not closure breadth or narinfo count. If the decision-maker's question is about many-small-paths behaviour, this workload does not answer it and the baseline should say so rather than imply otherwise.

If the lock ever forces a WORKLOAD_VERSION bump (e.g. a flake.lock update), the existing baseline is RETIRED, not adjusted - mark it so wherever it is quoted.
<!-- SECTION:NOTES:END -->
