---
id: TASK-286
title: >-
  Composite daemon binary: zero-config --profile lan-share parity (provider
  back-fill + mDNS + listen defaults)
status: To Do
assignee: []
created_date: '2026-08-20 18:26'
labels:
  - follow-up
dependencies:
  - TASK-279
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-279 AC#3 was ruled satisfied on the THIN daemon-libp2p binary (the zero-config NORTH-STAR vehicle). The composite /bin/daemon is flag-authoritative BY DESIGN: no --profile lan-share provider back-fill, and it requires explicit --libp2p-provider (daemon/src/main.rs:1188), explicit --libp2p-listen (:1245), and explicit mDNS/bootstrap (:1294). If we ever want the composite binary to be a zero-config lan-share vehicle too, it needs the provider back-fill + a listen default + an mDNS default under --profile lan-share -- a whole feature, not a reorder. Related to but distinct from TASK-277 (mirror the fail-loud guard into composite). LOW: composite is the explicit-config/advanced binary; nobody reaches zero-config through it today. Reasonable to keep as tracked divergence or Won't-do-for-now.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Decide (adopt / adopt-with-conditions / won't-do): whether composite /bin/daemon should support zero-config --profile lan-share. If adopt: --profile lan-share --libp2p-seed-nar S --libp2p-announce-after-fetch with NO explicit provider/listen/mdns flags succeeds on the composite binary identically to the thin binary, with a biting parse test. If won't-do: record the deliberate divergence in docs + a fail-loud message pointing lan-share users at the thin binary.
<!-- AC:END -->
