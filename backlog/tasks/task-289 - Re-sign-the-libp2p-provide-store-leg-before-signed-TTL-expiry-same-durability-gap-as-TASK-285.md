---
id: TASK-289
title: >-
  Re-sign the --libp2p-provide-store leg before signed-TTL expiry (same
  durability gap as TASK-285)
status: To Do
assignee: []
created_date: '2026-08-20 23:58'
labels:
  - hardening
  - durability
  - follow-up
dependencies:
  - TASK-285
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-285 added periodic re-sign for the static-SEED leg (--libp2p-seed-nar). The --libp2p-provide-store leg (regenerate-on-demand store provisions) has the IDENTICAL absolute-signed-TTL lapse: its provider records are announced once and never re-signed, so a node offering store paths goes undiscoverable for them within <=24h until restart. Out of TASK-285's scope by its ACs (seed-only), flagged by mped + codex as same-class. Apply the same SeedResignAuthority/run_resign_supervised mechanism (or generalize it) to the store-provision announce leg.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The store-provision announce leg re-signs its records before signed-TTL expiry via the same anti-rollback + save-before-publish + supervised-loop mechanism as the seed leg; a --libp2p-provide-store node stays discoverable for its offered paths indefinitely. Biting test past one TTL window; mutation removing re-sign => undiscoverable after TTL.
<!-- AC:END -->
