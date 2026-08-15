---
id: TASK-217
title: >-
  shaped_libp2p.py oracle-arm shape mismatch: builds {rtt_ms,mbit} but
  assert_shaping reads {rtt_ns,rate_bytes_per_s} — runtime KeyError in measure()
  (TASK-206 latent)
status: To Do
assignee: []
created_date: '2026-08-15 10:26'
labels:
  - bug
  - measurement
  - shaped-link
  - libp2p
  - latent
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found during TASK-198 (not touched there — out of scope). scripts/shaped_libp2p.py (from TASK-206) constructs the shaping-oracle arms as {"rtt_ms", "mbit"}, but shaped_link.assert_shaping consumes {"rtt_ns", "rate_bytes_per_s"}. The measure() path would raise KeyError at runtime; TASK-206's --self-test does NOT exercise that path, so it passed green with the latent mismatch. TASK-198's new scripts/shaped_compress.py feeds the correct rtt_ns/rate_bytes_per_s shape (reference for the fix). Fix: align shaped_libp2p.py's arm construction to the rtt_ns/rate_bytes_per_s contract assert_shaping expects, AND extend its --self-test to exercise the measure()/assert_shaping path so the mismatch would bite. Integer/rational only (no-floats). Relates: TASK-206 (source), TASK-198 (found + correct-shape reference).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 shaped_libp2p.py builds oracle arms in the {rtt_ns, rate_bytes_per_s} shape assert_shaping consumes; no runtime KeyError on the measure() path
- [ ] #2 shaped_libp2p.py --self-test exercises the assert_shaping/measure() path so the arm-shape mismatch BITES (mutation-proven)
<!-- AC:END -->
