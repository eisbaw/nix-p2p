---
id: TASK-199
title: >-
  Rename misnamed nar_size_span_orders_of_magnitude field (holds a linear
  multiple, not OOM)
status: Done
assignee: []
created_date: '2026-08-14 05:37'
updated_date: '2026-08-14 06:33'
labels:
  - hardening
  - measurement
  - finding
dependencies:
  - TASK-94
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
DEEP-gate residual honestly flagged by the TASK-94 fix implementer. In scripts/peer_wire_baseline.py the field nar_size_span_orders_of_magnitude holds a LINEAR multiple (max/min NarSize ~55806), not orders of magnitude (log10 ~4.7). This is the project's recurring 'unit label != valid derivation' trap (a name asserting a derivation the value doesn't match). The sample_gate min_span check compares against the same linear multiple consistently, so the GATE IS SOUND — this is a naming smell, not a correctness bug. But it lives in the CANONICAL committed baseline artifact (evidence/task-94/<rev>/sample.json) that TASK-99/198 read. FIX: rename to nar_size_span_multiple (or compute a true log10 OOM if that's the intended semantics), update sample_gate + docstrings, and regenerate the committed evidence artifact with the corrected schema (a fresh live sample — the number is a convenience-sample snapshot and will shift slightly, which is expected/acceptable). Low blast radius (99/198 consume the ratio, not the span field). Low priority hardening.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
DONE in TASK-94's final hardening cycle (code @ 59e7d3b, evidence @ e03ed53). Renamed nar_size_span_orders_of_magnitude -> nar_size_span_multiple (the value is a LINEAR multiple, ~55806x) and additionally emit an honest nar_size_span_log10 (~4.75 OOM). More than a rename: the span GATE is now INTEGER -- sample_gate compares max_nar >= min_nar * MIN_SPAN_MULTIPLE (int), removing the last float from the admission trust path (a float max/min rounds max=min*k-1 up to k.0 at large sizes and admitted a too-narrow sample; the integer form rejects it exactly). Updated _aggregate_from_records, sample_gate, _DERIVED_DISPLAY_FLOATS, docstrings and the CLI --min-span (now int). Committed evidence artifact regenerated with the corrected schema; consumers (99/198) read the ratio, not the span field, so blast radius nil.
<!-- SECTION:NOTES:END -->
