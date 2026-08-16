---
id: TASK-228
title: >-
  AC#5 measurement campaign: >=100 authenticated-HTTPS idle/loaded/WAN
  observations to validate the TASK-111 connect/header timeout defaults
status: To Do
assignee: []
created_date: '2026-08-16 02:00'
updated_date: '2026-08-16 02:23'
labels:
  - measurement
dependencies:
  - TASK-111
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Carved off from TASK-111 (which shipped the minimal honest core: connect/header timeout split, WAN-sane 15s header default anchored to Nix's stalled-download-timeout=300s / connect-timeout=0, a with_connect_timeout setter + --connect-timeout-ms flag, and a lock-in bite). This is the rung-6 MEASUREMENT campaign that TASK-111 deliberately did NOT gate the product-default fix on (gating a default on a 100-observation campaign is ossification). Validate/refine the chosen defaults against real distributions.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 At least 100 authenticated-HTTPS observations in EACH of idle, loaded, and WAN/RTT profiles record connect and header latency distributions (integer ms; no floats)
- [ ] #2 The chosen numeric defaults (connect 1000ms, header 15000ms) are recorded against those distributions and refined if the data warrants; any change re-derives the e2e boundary pins
- [ ] #3 Replay of the healthy observations yields ZERO timeout-induced 502s at the chosen defaults
- [ ] #4 A response delayed beyond the configured bound fails within 10% of that bound (fast-fail-against-dead preserved), measured on the authenticated-HTTPS path via the #[ignore]d tls_real_cache_nixos_org_over_https smoke
- [ ] #5 Header-ARRIVAL latency (time-to-first-header AFTER connect) is measured and characterised as its OWN distribution, kept DISTINCT from the body-idle segment (BODY_IDLE_TIMEOUT_MS=30s, the analog of Nix stalled-download-timeout); the campaign must NOT lump header TTFB with body-idle (unit-conflation guard)
<!-- AC:END -->
