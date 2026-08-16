---
id: TASK-235
title: >-
  Optional: salt-keyed cryptographic PRF for fan-out rank (single-query grind
  hardening)
status: To Do
assignee: []
created_date: '2026-08-16 10:20'
labels:
  - discovery
  - adversarial
  - hardening
dependencies: []
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-214 residual (self-flagged). provider_rank uses a non-cryptographic FNV-1a+splitmix64 seeded by a fresh per-query CSPRNG salt. Cross-retry targeting is already prevented (the salt is fresh per query and never on the wire). The only residual: IF an attacker learned a specific query's salt (side channel), they could grind PeerIds to occupy that ONE query's retained subset. Since the salt is never transmitted this is defense-in-depth, hence Low. AC (if pursued): replace the FNV+splitmix rank with a keyed cryptographic PRF (e.g. keyed BLAKE3, blake3 is already a dep) keyed by the salt, so even a known-salt single query is not grindable; keep it integer-only (no float in the decision path) and preserve the TASK-154 O(max_peers) bound + salt-independent presentation order. Do NOT pursue before higher-rung discovery work unless a concrete salt-leak vector is found.
<!-- SECTION:DESCRIPTION:END -->
