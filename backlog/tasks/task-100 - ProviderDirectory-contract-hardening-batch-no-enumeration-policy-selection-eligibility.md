---
id: TASK-100
title: >-
  ProviderDirectory contract hardening: batch, no-enumeration, policy-selection,
  eligibility
status: To Do
assignee: []
created_date: '2026-08-10 09:26'
updated_date: '2026-08-11 21:22'
labels:
  - wave-2b
dependencies:
  - TASK-66
  - TASK-91
  - TASK-102
  - TASK-104
  - TASK-106
  - TASK-107
  - TASK-110
  - TASK-114
  - TASK-140
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Replace the insufficient single-key/single-holder seam with a mechanism-neutral discovery domain boundary. Adapters batch named keys, return multiple holders and typed MISS versus UNAVAILABLE outcomes, enforce caller deadlines and publication eligibility, and report measured latency/control cost/capabilities. A separate resolver execution plan—explicit configuration now, frozen policy artifact later—chooses ordering, parallelism, racing and stop conditions. The seam/registry must not hardcode cheapest-first, Iroh-first or any production preference before holdout. Mechanisms include in-process/direct probe, LAN/node discovery, tracker and TASK-103's selected global-DHT implementation.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The seam batch-resolves named keys to multiple holders, with single-key compatibility; in-process and direct-probe adapters preserve existing behavior.
- [ ] #2 MISS, UNAVAILABLE(reason), deadline expiry and partial results are typed and observable; a dead mechanism cannot silently read as nobody-has-it.
- [ ] #3 Every adapter enforces the caller's total deadline and reports capabilities plus observed latency/control bytes/resource outcome; these are measurements, not a timeless cheap/expensive class.
- [ ] #4 No-enumeration is structural: no listing method exists, batches contain only asker-named keys, and a negative mutation proves inventory cannot be requested.
- [ ] #5 Ordering, parallelism/racing and stop conditions come from an explicit versioned execution plan. A named fixed baseline is testable, but neither the seam nor registry selects a production default before TASK-123.
- [ ] #6 Every publish-capable adapter consumes the single TASK-102 eligibility decision, preserves transport offers, and emits mechanism-neutral publication outcomes; bypassing the filter makes a test fail.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Re-scoped 2026-08-11: the SEAM itself is now TASK-140 (ProviderDirectory trait). This task is no longer a duplicate seam - it is the contract/policy hardening ON that seam: positional batch, structural no-enumeration, typed MISS/UNAVAILABLE, explicit versioned execution plan (policy selects, no default before TASK-123), and single TASK-102 eligibility consumption. Depends on TASK-140.
<!-- SECTION:NOTES:END -->
