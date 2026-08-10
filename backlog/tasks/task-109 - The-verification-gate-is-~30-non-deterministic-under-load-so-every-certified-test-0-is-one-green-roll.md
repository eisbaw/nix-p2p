---
id: TASK-109
title: >-
  The verification gate is ~30% non-deterministic under load, so every certified
  "test 0" is one green roll
status: To Do
assignee: []
created_date: '2026-08-10 16:00'
updated_date: '2026-08-10 19:34'
labels:
  - hardening
dependencies:
  - TASK-9
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
FOUND BY THE TASK-91 RE-GATE, 2026-08-10, and it undermines every 'gate green' claim this project has made.

daemon/tests/fault_loop.rs::fault_mode_loop failed 3 of 10 full `cargo test --locked --workspace` runs under machine load (502 instead of 200; 'no response headers from 127.0.0.1:37601') and passed 3/3 in isolation. It is a pre-existing test from task-4, untouched by task-91.

THIS IS THE FOURTH MEMBER OF A FAMILY, and the family is the point:
  TASK-105  store_residency_oracle      13/64 under 8 concurrent processes, 0/125 sequential
  TASK-108  testproxy truncated_nar_fault_short_reads   1 failure under the first full parallel run
  TASK-84   cargo test --workspace flaked once under load after task-72 added a heavier binary
  THIS      daemon fault_loop::fault_mode_loop          3/10 under load

Unlike TASK-108 this one is in the DAEMON crate, so the 'crate-independent, not mine' defence does not apply to it.

WHY THIS IS ITS OWN TASK RATHER THAN A FOURTH FLAKE TICKET: the individual flakes have individual causes (whole-process /proc reads under libtest parallelism; port/timing races under load). The SYSTEMIC fact is that `just test` fails roughly 30% of the time under load, which means every 'test 0' this project has certified - in task notes, in Final Summaries, in git notes, and in the README's implied gate-green status - is ONE GREEN ROLL of a non-deterministic gate. The honest-failure discipline this project runs on assumes the gate is a truth oracle. It is not, and nobody knew the rate until now.

DO NOT FIX BY RETRYING OR BY SERIALIZING EVERYTHING. --test-threads=1 diagnoses; it is not a fix, and buying determinism by deleting parallel coverage is the anti-pattern. The question to answer first is WHICH tests are load-sensitive and WHY - the two known mechanisms are (a) whole-process measurements read while siblings allocate, (b) fixed/ephemeral port and timing assumptions under CPU contention.

Reference: TASK-105's reproduction method (N concurrent processes x M rounds) is the harness that found the rate; reuse it rather than reinventing it.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The flake RATE is measured, not guessed: run the full suite N>=20 times under a defined load and report failures per test, so 'the gate is green' has a known confidence rather than an assumed one
- [ ] #2 Each load-sensitive test is classified by MECHANISM (whole-process measurement vs port/timing race vs something else) and fixed at that mechanism - no blanket --test-threads=1, no retry-until-green
- [ ] #3 After the fixes, the same N>=20 run reports ZERO failures; a single green run is explicitly NOT accepted as evidence (that is what created this problem)
- [ ] #4 The project's honesty convention is updated: a cycle may not certify 'test 0' from one run while a known flake rate is outstanding - state the rate or state that it is unmeasured
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
DEPENDENCY CORRECTED 2026-08-10: this task previously depended on TASK-105/108/84, i.e. on the very flake instances it exists to fix - the umbrella was blocked behind its own instances. They are now handled AS PART OF this task (same defect family, batched deliberately), not as prerequisites.

DISK NOTE for whoever runs this: a prior review filled the filesystem to 0 MB by building inside a /tmp worktree, which killed all shell access. 20+ full suite runs is disk-heavy. There is 53 GB free as of this correction; clean scratch dirs as you go and check headroom before starting.
<!-- SECTION:NOTES:END -->
