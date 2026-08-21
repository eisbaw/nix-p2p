---
id: TASK-296
title: >-
  Nightly cargo-fuzz coverage-guided tier + /nar async framing fuzz target (282
  AC#4 residual)
status: To Do
assignee: []
created_date: '2026-08-21 06:31'
labels:
  - hardening
  - testing
  - follow-up
dependencies:
  - TASK-282
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-282 AC#4 delivered structured proptest fuzzing (bounded random). Deferred: (1) a coverage-guided libFuzzer/cargo-fuzz tier with ASan - blocked on the no-nightly constraint (pinned stable toolchain + 113 AC#9); would need an opt-in nightly fuzz-only toolchain isolated from the crane build. (2) a fuzz target for the /nar async request/response FRAMING loop (tokio + idle timeouts) - only decode_verified (the body verifier) is covered now.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Either a nightly-isolated cargo-fuzz coverage-guided tier is wired as an opt-in BROAD job (not in the stable devshell/crane build), OR a decision is recorded that proptest structured fuzzing is sufficient and cargo-fuzz is rejected with rationale.
- [ ] #2 A bounded fuzz target exercises the /nar async framing loop (malformed length prefixes, truncation, idle-timeout) without hanging the harness.
<!-- AC:END -->
