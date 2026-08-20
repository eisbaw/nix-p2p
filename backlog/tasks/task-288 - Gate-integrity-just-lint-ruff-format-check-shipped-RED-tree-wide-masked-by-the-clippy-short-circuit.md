---
id: TASK-288
title: >-
  Gate integrity: just lint ruff-format-check shipped RED tree-wide, masked by
  the clippy short-circuit
status: Done
assignee: []
created_date: '2026-08-20 18:27'
updated_date: '2026-08-20 18:40'
labels:
  - gate
  - infra
dependencies: []
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
During the TASK-279 DEEP gate, qa found just lint deterministically RED at HEAD: ruff format --check failed on 4 scripts (e2e_harness.py 902-line drift, task269_compression_sweep.py, task269_crossover.py, check-fixtures.py) that were never ruff-format-clean, AND 2 clippy doc_lazy_continuation errors in fabric-libp2p/src/swarm.rs (from TASK-283, whose LIGHT gate self-report claimed green). The clippy failure short-circuited just lint before the ruff stage in recent runs, but the ruff-format RED predates that -- meaning just lint's full completion has been RED across multiple 'lint green' Done claims. TASK-279's honesty-pass reformatted the 4 scripts to reach green (commit ffeb1d1), but the ROOT CAUSE (how did unformatted scripts + a clippy RED ship past LIGHT gates repeatedly?) is untriaged. Fixing the symptom without this is the workaround the standards forbid.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Root-cause the gate escape: determine whether (a) the just lint recipe's stage ordering lets an early failure mask later stages (clippy short-circuits ruff), (b) LIGHT-cycle implementer self-reports skipped/misread just lint, and/or (c) a devshell ruff-version bump silently re-drifted the format. Report findings.
- [x] #2 Make the lint gate non-maskable: the recipe runs ALL stages and reports each stage's captured exit code (a later-stage RED cannot be hidden by an earlier-stage RED), OR an equivalent guarantee that just lint green means every stage passed. Add a pre-commit/CI check or an orchestrator-gate rule that requires the captured just lint exit=0 (not a self-reported claim) before any Done.
- [x] #3 Confirm no other currently-Done task is sitting on a red gate: run the full just lint at HEAD and record the captured exit code; if RED, file the specific stage failures.
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
DONE (LIGHT gate; orchestrator independently re-derived just lint exit=0). Commit fb1f33d (Justfile only, +90/-18). Root cause (AC#1): (a) recipe masking ACTIVE -- just halts at the first failing recipe line, so a clippy RED short-circuited before the ruff-format stage + source/discovery/dht guards ran; (b) LIGHT self-report escape ACTIVE -- an aborted-early recipe looks green up to where it stopped; (c) ruff version-drift NOT the cause (pinned ruff 0.15.14, format stable). Fix (AC#2): lint + independence are now bash blocks with set +e + a run() helper that runs EVERY stage, records per-stage PASS/FAIL, prints a summary, and exits 1 iff any failed -- a later-stage RED can no longer hide behind an earlier one; ordering + self-test-before-scan preserved; no check weakened. Mutation-proven: injecting an early-stage failure leaves all 14 real stages still running and the recipe exits 1 (old behavior aborted silently). AC#3 audit: just lint at HEAD = all 14 stages PASS, exit 0 (independently re-run by orchestrator, not self-reported). CI already blocks on just lint (.github/workflows/ci.yml:97) and that captured exit is now trustworthy. Process note carried to memory: require the captured just lint exit=0 before any Done, never a self-report. Minor: the ~10-line run()/summary harness is duplicated in lint + independence (recipes can't share bash fns without a sourced helper) -- judged acceptable, filed as no follow-up.
<!-- SECTION:FINAL_SUMMARY:END -->
