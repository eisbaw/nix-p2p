---
id: TASK-200
title: >-
  No-floats sweep: convert ratios to rational num/denom, bandwidth to bytes/sec,
  latency to ns across measurement code
status: Done
assignee: []
created_date: '2026-08-14 06:42'
updated_date: '2026-08-14 20:29'
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

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
IMPLEMENTED (scoped per mped-architect ruling):

GUARD scripts/check-no-floats.py wired into 'just lint' via the independence recipe. Non-vacuous: --self-test has 6 bite cases + 4 clean cases + ALLOW-suppression proof.
AST rules (not regex):
- Rule A: a comparison whose operand subtree holds a float literal OR references a float-tainted local name, inside a gate/verdict function. Gate detection = name tokens (assert_/gate/bite/oracle/verdict/admit/decide/judge/earn) OR VERDICT_FUNCS include-list OR a verdict-named assignment target (faster/trips/_ok/_flag/...) OR a verdict-named dict key holding a float comparison.
- Intra-function float-TAINT pass: names assigned a float-yielding expr (float literal / float() / '/' true-div) are tracked, so a computed decision-float is caught even with NO literal in the comparison. This is load-bearing: break_even's gate is 'denom > 0' where denom=ratio/up-1.0/peer -- a pure name-based guard is BLIND to it (mped's vacuity-trap finding). VERDICT_FUNCS lists (peer_wire_baseline.py, break_even) because its name carries no gate token. Self-test has a break_even-shaped positive control + an exact cross-multiplied negative control.
- Rule B: float written to a *_ns/*_num/*_denom serialized-integrity field (never legitimately float). Narrow on purpose: *_bytes/*_per_s carry measurement means, left to review.

CONVERTED (clean, isolated, verdict-identical): shaped_link.assert_shaping -> integer-ns RTT + exact-rational bytes/sec throughput, tolerances as Fraction cross-multiplication (0.7 -> 10*x<7*want etc). parse_inner_output now returns exact rtt_ns/rate_bytes_per_s (the gate) PLUS float rtt_ms/mbit (terminal display, from the SAME decimal string -> peer_wire_baseline reads them unchanged, zero perturbation). RTT ms-decimal*1e6 is an exact integer; throughput parses the already-rounded mbit_per_s STRING to Fraction (NOT recomputed from bytes/elapsed, which would be a different number). self-test green, all 6 mutations + 4 truncations still bite.

ALLOWLISTED with per-site (i)threshold (ii)observand (iii)why-not-here reasons, two honest sub-classes:
- PERMANENT (irreducible physical/statistical float; needs wall-time re-plumbed to ns end-to-end = measurement-plumbing, not representation): measure.bite_gap_oracle (median of wall ms), measure.bite_latency_p95 (p95 of wall seconds), profile_p2p.bite_applicability (Monte-Carlo rate+std-err), profile_p2p.cross_condition_block (mean speedup vs 1.0).
- DEFERRED to TASK-211 (convertible byte-ratio/spine, but coupled to proven peer_wire_baseline trust spine + measure.py finalizer + committed evidence schema; break_even needs a boundary self-test-vector re-bless audit): peer_wire_baseline.break_even, peer_wire_baseline.assert_link_label, measure.bite_product_narinfo_cache, measure.bite_magnitude_and_self_counter. Created TASK-211 for these.
scalefit.py statistical internals need NO allowlist entry: their names carry no gate token so Rule A never fires (sanctioned float is out of scope by construction, not by rubber-stamp).

COVERAGE BOUNDARY (honest): scans 11 listed scripts, not the whole tree, not the Rust trust path (already integer-by-type). Rule A is name+taint driven, not a general float-taint analyzer.

GATE: check-no-floats --self-test bites + real scan green; shaped_link + peer_wire_baseline self-tests green (verdicts unchanged); ruff check scripts green; my files ruff-format clean; just independence green (with the new guard).
PRE-EXISTING BLOCKER (NOT TASK-200): ruff 0.15.14 flags committed format drift in scripts/e2e_harness.py (TASK-194) and scripts/task99_link_compression_measure.py (TASK-99) -- HEAD content fails 'ruff format --check' as named files, unrelated to this task and proven e2e/finalizer code the brief says NOT to touch. Left for orchestrator triage (likely a separate hygiene commit or a ruff pin bump); it blocks the whole-dir 'ruff format --check scripts' step of 'just lint'.

DONE 2026-08-14. No-floats enforcement landed where it matters: (1) scripts/check-no-floats.py AST guard (wired into just lint) - flags float-in-gate comparisons (Rule A, with an intra-function float-TAINT pass that catches computed-float gates like break_even's denom=ratio/up-1.0/peer that a literal-only guard misses) + float in _ns/_num/_denom serialized fields (Rule B); 8 sanctioned floats allowlisted-with-reason (permanent physical/statistical vs deferred-to-TASK-211); --self-test bites 6 cases + 4 clean-pass + ALLOW-suppression proof (non-vacuous). (2) shaped_link.assert_shaping converted to integer-ns RTT + exact-rational bytes/sec (Fraction cross-multiplication), verdict-IDENTICAL (parses the same decimal strings; zero evidence-schema perturbation) - self-test 6+4 still bite. Orchestrator-verified: guard bites + real scan clean + both finalizer self-tests unchanged. Also fixed a latent pre-existing ruff-bump drift (e2e_harness.py + task99_link_compression_measure.py failed ruff 0.15.14 whole-dir check with empty git diff, blocking just lint) - pure reformat, self-tests green (ac228f6). DEFERRED -> TASK-211: the peer_wire_baseline break_even/assert_link_label Fraction conversion (convertible but COUPLED to the 3-codex-gated finalizer + committed evidence schema; break_even's denom==0 boundary self-test vectors need a re-bless audit since exact Fraction removes float cancellation error near the boundary - must not be done silently). HONEST: guard scans 11 listed scripts not the whole tree, Rule A is name+taint driven not a general analyzer (extend VERDICT_FUNCS include-list, don't weaken the taint pass).
<!-- SECTION:NOTES:END -->
