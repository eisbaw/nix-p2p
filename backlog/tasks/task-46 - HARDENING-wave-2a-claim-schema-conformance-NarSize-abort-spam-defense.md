---
id: TASK-46
title: 'HARDENING (wave-2a): claim-schema conformance + NarSize-abort spam defense'
status: To Do
assignee: []
created_date: '2026-08-08 20:13'
updated_date: '2026-08-08 20:30'
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

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
REVIEW REVISION (qa#6/codex#5): (1) task-51 owns the DEFAULT NarSize abort; task-46 HARDENS/fuzzes it + adds the HOSTILE-provider fixture (a peer that claims NarHash X but serves an oversized/wrong blob - no task owned this; task-41's bite is only corrupted bytes). (2) State the TRUST PRECONDITION: the NarSize-abort is valid ONLY because the narinfo (hence signed NarSize) comes from cache.nixos.org in wave-2a; the claim schema carries NO size field; v2 signed-narinfo-relay would break this - document it. (3) Claim-schema conformance fuzz stays.
<!-- SECTION:NOTES:END -->
