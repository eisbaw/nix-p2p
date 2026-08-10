---
id: TASK-56
title: >-
  Availability index: verify sha256(dump)==NarHash at register (not caller's
  word)
status: To Do
assignee: []
created_date: '2026-08-09 00:10'
updated_date: '2026-08-10 22:36'
labels:
  - wave-2
dependencies:
  - TASK-50
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
task-50 honest limit: register() binds NarHashKey->store_path on the CALLER's word; blake3_for computes only BLAKE3, never asserts sha256(nix-store --dump path)==the registered NarHash. Nix gate 2 backstops a bad INSTALL (no wrong bytes reach a store), but a MIS-registration produces a FALSE CLAIM - the node advertises holding X but would serve Y, which a consumer fetches then rejects at its NarHash gate = a wasted dial. This directly feeds the pathological lying-claim/wasted-dial cost (task-43/46) and honest offload accounting. Fix: at register (or first blake3_for), compute sha256 of the --dump stream and assert == the registered NarHash; reject/quarantine a mismatch. Needs a sha256 pass over --dump (daemon-side; sha2 is daemon-only, independence denylist is HTTP-only).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 register/first-serve asserts sha256(--dump)==NarHash; a mis-registered path is rejected/quarantined, never announced as a valid claim (bite: register key X for a path whose real NarHash is Y -> rejected)
<!-- AC:END -->
