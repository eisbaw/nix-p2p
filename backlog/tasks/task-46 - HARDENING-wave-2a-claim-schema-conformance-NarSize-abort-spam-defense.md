---
id: TASK-46
title: 'HARDENING (wave-2a): claim-schema conformance + NarSize-abort spam defense'
status: To Do
assignee: []
created_date: '2026-08-08 20:13'
labels:
  - hardening
dependencies:
  - TASK-41
  - TASK-44
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Wave-2a hardening block, deep-gated (runs against stabilized wave-2a surfaces). Claim-schema conformance/versioning fuzz (unknown variants, version skew, malformed claims - forward-compat holds, malformed rejected fail-closed); the NarSize/FileSize abort against claim-spam (PRD risk 6: a lying claim pointing at an attacker-chosen huge blob must be aborted at the signed NarSize, not downloaded in full before the gate - the daemon is outside the TCB but wasted-dial DoS is real); wasted-dial bounding on lying claims. Plus deferred findings wave-2a filed along the way.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Claim-schema fuzz: malformed/version-skewed/unknown-variant claims handled per spec (forward-compat parses, malformed fail-closed) - each bite shown
- [ ] #2 NarSize-abort: a claim pointing at a blob exceeding the signed NarSize is aborted before full download (bite: without the abort, the huge blob downloads; with it, aborted early)
- [ ] #3 deferred-finding label for wave-2a is empty (closed or converted to explicit tasks)
<!-- AC:END -->
