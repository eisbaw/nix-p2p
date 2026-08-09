---
id: TASK-81
title: Verify the Candidate C (chunked castore) seam is still open
status: To Do
assignee: []
created_date: '2026-08-09 21:02'
labels:
  - wave-2b
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Chunk-level dedup is an explicit PRD NON-GOAL for the MVP - but the PRD commits to keeping the seam open ('Chunk-level dedup (Candidate C; seam kept open)'), and the whole reason Candidate B was chosen over C was that B could be built first WITHOUT foreclosing C. That commitment is currently unverified, and it decays silently: every wave-2a decision that assumed whole-NAR addressing is a chance to have closed it without noticing.

This is a design REVIEW, not a feature. Concretely, check that: the frozen claim schema still admits a CastoreRoot payload variant beside WholeNar{blake3} (daemon/src/claim.rs); NarKey::SignedNarHash still keys resolution independently of how bytes are supplied; the Transport trait's fetch-by-content-id shape does not assume whole-blob (it currently returns Vec<u8> and takes an expected_size - see TASK-62, whose streaming work may improve or worsen this); the availability index and the narinfo rewrite path do not bake in whole-NAR assumptions.

Do NOT implement Candidate C. The deliverable is a verdict plus, if the seam has narrowed, the specific tasks needed to reopen it - filed while reopening is still cheap.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A written verdict per seam point (claim schema, NarKey, Transport trait, availability index, narinfo rewrite): still open / narrowed / closed, each with the specific code reference that justifies the verdict
- [ ] #2 Anywhere the seam narrowed, a task is filed to reopen it, with the cost of reopening now vs later stated
- [ ] #3 No Candidate C implementation is written in this task
<!-- AC:END -->
