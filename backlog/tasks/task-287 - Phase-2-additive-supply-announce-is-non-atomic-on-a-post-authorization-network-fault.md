---
id: TASK-287
title: >-
  Phase-2 additive-supply announce is non-atomic on a post-authorization network
  fault
status: To Do
assignee: []
created_date: '2026-08-20 18:27'
labels:
  - hardening
  - transaction
dependencies:
  - TASK-279
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-279 AC#2 delivered the AUTHORIZATION-granularity atomicity (authorize_public_supply ?-short-circuits ALL legs against the allowlist before phase-2 announces ANY record) and the specific empty-leg footgun was fixed (empty approved leg skips its fallible readiness capture). But the GENERAL phase-2 is still not atomic: after seed leg S is announced (on the wire), a second leg's announce can fail on a non-authorization error (relay-readiness capture, TASK-56 seed re-verification, TASK-231 eligibility re-check, save-before-publish persistence, unreachable/network, or a deadline -- see the corrected comment at daemon-libp2p/src/lib.rs ~L2479) and there is NO rollback, so S lingers to its TTL. This is WITHIN the TCB: TTL-bounded, self-healing, integrity untouched (no bad bytes, no wrong store path). Found by codex in the TASK-279 DEEP gate; Mark-emulator ruled it file-not-fold. LOW.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 On any phase-2 announce failure after one leg is already on the wire, either every already-published record from this supply batch is withdrawn before returning Err (all-or-nothing publish), or the residual is explicitly documented+bounded as acceptable TTL-linger with a rationale. Biting test: induce a second-leg phase-2 failure after the first leg announces; assert a kad get_providers for the first leg returns nothing (if rollback chosen) within the withdrawal window.
<!-- AC:END -->
