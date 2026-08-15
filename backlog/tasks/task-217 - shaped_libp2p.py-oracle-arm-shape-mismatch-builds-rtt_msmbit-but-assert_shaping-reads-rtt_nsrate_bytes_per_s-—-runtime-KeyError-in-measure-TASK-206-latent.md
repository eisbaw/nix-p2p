---
id: TASK-217
title: >-
  shaped_libp2p.py oracle-arm shape mismatch: builds {rtt_ms,mbit} but
  assert_shaping reads {rtt_ns,rate_bytes_per_s} — runtime KeyError in measure()
  (TASK-206 latent)
status: Done
assignee:
  - '@claude'
created_date: '2026-08-15 10:26'
updated_date: '2026-08-15 20:59'
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
- [x] #1 shaped_libp2p.py builds oracle arms in the {rtt_ns, rate_bytes_per_s} shape assert_shaping consumes; no runtime KeyError on the measure() path
- [x] #2 shaped_libp2p.py --self-test exercises the assert_shaping/measure() path so the arm-shape mismatch BITES (mutation-proven)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
PLAN (TASK-217): shaped_libp2p.py measure() builds oracle arms as {rtt_ms,mbit} at L216-217 but shaped_link.assert_shaping reads {rtt_ns,rate_bytes_per_s} so the real measure() path raises KeyError. Fix mirrors shaped_compress._arm_for_oracle: exact integer rtt_ns (ping decimal STRING to ns via Fraction) plus integer rate_bytes_per_s, with float rtt_ms/mbit as display-only fields the gate never reads. Extend --self-test to EXERCISE assert_shaping via the SAME _arm_for_oracle: honest pair ACCEPTED, shaping-removed arm REJECTED; reverting to {rtt_ms,mbit} then makes assert_shaping raise KeyError -> self-test RED (mutation proof). Gate: shaped_libp2p --self-test + red/green mutation, check-no-floats, ruff on shaped_libp2p.py only. Python-only oracle fix: NOT running the netns VM e2e.

DONE (TASK-217). AC#1: measure() now builds oracle arms via new _arm_for_oracle() in the exact {rtt_ns, rate_bytes_per_s} shape assert_shaping consumes (plus display-only rtt_ms/mbit the gate never reads); parse_arm now stores exact integer rtt_ns from the ping decimal STRING via Fraction (removed the float round() helper). No more KeyError on the measure() path. AC#2: --self-test now EXERCISES the assert_shaping path with arms from the SAME _arm_for_oracle (honest pair ACCEPTED, shaping-removed arm REJECTED, decision fields asserted integer). MUTATION PROOF: reverting _arm_for_oracle to the buggy {rtt_ms,mbit} -> self-test RED, 4 named SELF-TEST FAIL lines (missing rtt_ns), RC=1; restoring -> RC=0. GATE (nix shell, all green): shaped_libp2p --self-test RC=0; check-no-floats RC=0 (13 scripts clean); ruff check + ruff format --check on shaped_libp2p.py RC=0. NOT RUN (out of scope, stated): the netns VM/e2e shaped_probe measure() run (needs unshare -Urn userns caps + cargo-built probe); the measure() netns plumbing is structurally unchanged, only arm construction/display moved to integer fields. Did NOT touch the 3 TASK-222 pre-existing ruff-drift scripts. LIMIT: the hermetic self-test proves the arm-shape contract and that the oracle bites; it does not execute the real two-node shaped fetch.
<!-- SECTION:NOTES:END -->
