---
id: TASK-200
title: >-
  No-floats sweep: convert ratios to rational num/denom, bandwidth to bytes/sec,
  latency to ns across measurement code
status: To Do
assignee: []
created_date: '2026-08-14 06:42'
labels:
  - hardening
  - tech-debt
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Standing owner design rule (memory: no-floats-integers-or-rationals): NO floats/NaN in any gate, bound, admission, decision, or serialized-integrity field — ratios as an EXACT rational num/denom (compare by cross-multiplication a*d vs b*c), bandwidth as whole integer BYTES/SEC, latency/durations as whole integer NANOSECONDS. Floats permitted only as terminal display, and even then prefer the integer form. SCOPE (audit + convert): (1) GATE/DECISION path first — any float used in a comparison/threshold/admission across the codebase is a defect: grep for float ratios/tolerances in gates. TASK-94's peer_wire_baseline.py trust path is already integer-exact (good reference); the span gate is already integer (TASK-199). (2) DISPLAY/measurement floats: scripts/shaped_link*.py (prints mbit/MB floats), scripts/profile_p2p.py, scripts/measure.py, scripts/scale_sweep.py, and peer_wire_baseline.py display ratios — convert reported ratios to rational (fractions.Fraction / integer pair), rates to integer bytes/sec, latencies to integer ns; keep comparisons on the (bytes,ns) pair / cross-multiplied. (3) Rust side: any (rare) float in fabric/daemon/transport — replace with integers or num-rational. Statistical fits (scalefit regression) are the one allowed float, but must never gate/decide. Prove: a grep-based guard (like check-independence/check-shaping) that fails if a float appears in a gate/serialized-integrity context is a good addition. NON-BLOCKING for the value-thesis on-ramp; this is hardening/consistency, do after the on-ramp lands or opportunistically.
<!-- SECTION:DESCRIPTION:END -->
