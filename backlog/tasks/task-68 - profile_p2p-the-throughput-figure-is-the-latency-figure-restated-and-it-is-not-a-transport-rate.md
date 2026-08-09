---
id: TASK-68
title: >-
  profile_p2p: the 'throughput' figure is the latency figure restated, and it is
  not a transport rate
status: To Do
assignee: []
created_date: '2026-08-09 14:01'
labels:
  - honesty
  - measurement
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
FOUND BY TASK-64. scripts/profile_p2p.py:745 computes throughput as `workload_bytes_uncompressed_nar / realise_s` per run, per arm. The numerator is the SAME CONSTANT in both arms, so throughput_ratio == 1/latency_ratio ALGEBRAICALLY. The task-42 report nevertheless presents 'throughput ratio 3.61' beside 'latency ratio 3.53' as if they were two agreeing observations - they are one observation counted twice, and the 3.61-vs-3.53 gap is nothing but mean-of-reciprocals vs reciprocal-of-mean (Jensen), not independent corroboration. That double-count is what made TASK-64's deficit look like it had two witnesses. SECOND defect, same key: the denominator is the whole in-container `nix-store --realise` - substituter query, NAR unpack, sha256 NarHash, store registration - so 758 MB/s and 210 MB/s are END-TO-END REALISE RATES, not transport throughputs, and quoting them as 'HTTP moves X, iroh moves Y' misattributes nix's own costs to the transport. TASK-64 measured the transport alone (daemon/examples/iroh_throughput.rs): the product's fetch is 187 MB/s and iroh-blobs alone 255 MB/s on the same host at 110 MiB, so the in-daemon 210 is roughly the transport plus nix, as expected. NOTE the UNIT rule itself is FINE and did NOT recur: assert_unit_coincidence proves file_size == nar_size for the speedup attrs, so both arms count the same NarSize bytes. This is a DERIVED-QUANTITY honesty defect, not a unit defect - which is exactly why the existing unit gate did not catch it.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The report no longer presents throughput and latency as independent corroboration: either the derived throughput key is removed, or it is structurally labelled as a restatement of realise_s with the identity spelled out
- [ ] #2 Any figure derived by dividing a CONSTANT by a measured quantity is labelled as such, and the honesty machinery gates on it - proven by mutation (a report that presents such a pair as two observations must be REJECTED by the self-test)
- [ ] #3 The realise-rate figures are renamed so they cannot be read as transport throughput (they carry nix unpack + NarHash + store registration), with the task-64 transport-only numbers cited as the contrast
<!-- AC:END -->
