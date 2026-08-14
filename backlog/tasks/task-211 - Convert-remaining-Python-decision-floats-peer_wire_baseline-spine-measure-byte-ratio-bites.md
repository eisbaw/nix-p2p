---
id: TASK-211
title: >-
  Convert remaining Python decision-floats (peer_wire_baseline spine + measure
  byte-ratio bites)
status: To Do
assignee: []
created_date: '2026-08-14 20:20'
labels:
  - hardening
  - tech-debt
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Successor to TASK-200. TASK-200 added the check-no-floats.py guard and converted the self-contained shaped_link.assert_shaping oracle to integer-ns/rational-bytes-per-sec, then ALLOWLISTED (with reasons) the float-in-gate sites it could not safely convert within a representation-only, don't-touch-proven-code remit. This task converts the CONVERTIBLE-BUT-DEFERRED subset the guard's allowlist names.
(1) peer_wire_baseline.py TRUST SPINE, converted as ONE coherent unit (per mped ruling: the half-measure is the worst option): aggregate_file_over_nar_ratio = sum_file/sum_nar -> Fraction(sum_file,sum_nar); break_even denom/numer sign-tests -> all-Fraction/int with cross-multiplied sign comparisons; peer_bw -> exact bytes/sec; assert_link_label rtt/throughput label gate -> integer-ns/rational. Serialized evidence fields (rtt_ms, throughput_mbit_per_s, throughput_bytes_uncompressed_nar_per_s, aggregate_file_over_nar_ratio, per_byte_saving_s_per_nar_byte) MUST stay byte-identical via terminal float() projection reproducing the historical float ops.
(2) measure.py byte-ratio bites: bite_product_narinfo_cache (on[1]<0.5*on[0], off[1]>=0.8*off[0] on integer egress bytes) and bite_magnitude_and_self_counter (|a-b|/b<=SELF_COUNTER_TOL on integer byte counts) -> cross-multiplied integer/rational; make SELF_COUNTER_TOL a Fraction.
CRITICAL PITFALL (mped): break_even's own self-test constructs denom==0/numer boundary vectors assuming FLOAT semantics; exact Fraction removes float cancellation error near denom~=0, which COULD change a stated self-test conclusion at the boundary. Audit and re-bless those boundary vectors BEFORE converting -- surface it, do not do it silently. On live data the real shaped-arm peer_bw (~11 MiB/s) sits a mile inside NO_THRESHOLD so no live-data flip; risk is confined to synthetic boundary vectors.
NOT in scope (permanent guard allowlist -- irreducible physical/statistical floats needing wall-time re-plumbed to integer ns end-to-end, a measurement-plumbing change): bite_gap_oracle (median of wall-clock ms), bite_latency_p95 (p95 of wall-seconds), bite_applicability (Monte-Carlo rate+std-error), cross_condition_block (mean speedup vs 1.0).
When this task converts a site, remove its entry from check-no-floats.py ALLOW_FUNCS so the guard enforces it.
<!-- SECTION:DESCRIPTION:END -->
