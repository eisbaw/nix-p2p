---
id: TASK-205
title: >-
  TASK-103 residual: container partition/rejoin (AC#6) + Sybil/eclipse/resource
  bounds (AC#8) adversarial-resilience proof
status: To Do
assignee: []
created_date: '2026-08-14 16:24'
labels:
  - discovery
  - resilience
  - hardening
  - adversarial
dependencies:
  - TASK-103
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Deferred from the TASK-103 discovery MVP (which proved discover->fetch->serve works + is secure on the shipped binary). The remaining adversarial-RESILIENCE layer: AC#6 CONTAINER partition/rejoin (the in-process record_lifecycle.rs proves the core lifecycle — concurrent/withdrawal/expiry/restart/replay/anti-rollback/corruption — but NOT a real network partition + rejoin without lost updates / expired-record resurrection); AC#8 resource tests enforcing record/provider/request/response/storage/concurrency/rate/work bounds PLUS poisoning/amplification/Sybil/eclipse assumptions without compromising integrity. Needs an adversarial multi-node harness (heavy, netns-class, shared-box grind — see TASK-179). This is 'robust connectivity' hardening beyond the honest-case discovery proof; do after the discovery trunk MVP + store-dump e2e (194) land.
<!-- SECTION:DESCRIPTION:END -->
