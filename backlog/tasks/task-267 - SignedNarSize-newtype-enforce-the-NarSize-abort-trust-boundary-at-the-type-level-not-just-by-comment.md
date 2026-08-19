---
id: TASK-267
title: >-
  SignedNarSize newtype: enforce the NarSize-abort trust boundary at the type
  level (not just by comment)
status: To Do
assignee: []
created_date: '2026-08-19 17:22'
labels:
  - hardening
dependencies: []
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-46 follow-up (mped-architect Finding 4). The risk-6 NarSize abort in fabric-libp2p (read_response_streamed_since: raw_size > cap) is only sound because expected_size is the SIGNED NarSize from a trusted narinfo. Today that provenance is carried by a bare Option<u64> (daemon-core/src/server.rs threads Some(meta.nar_size)) and enforced ONLY by a doc comment. Per MPED make-illegal-states-unrepresentable: introduce a SignedNarSize(u64) newtype minted at the narinfo trust boundary (server.rs) and threaded to the abort site, so a non-signed size cannot be passed as the ceiling. Fail-fast here becomes enforcement, not documentation. No wire change; internal type-safety only. LOW: the current comment-documented precondition is correct and holds on the shipped path; this hardens it against a future refactor silently passing an untrusted size.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A SignedNarSize newtype is minted only at the trusted-narinfo boundary and threaded to the fetch abort ceiling; passing an unsigned/peer-supplied size as the ceiling is a compile error
<!-- AC:END -->
