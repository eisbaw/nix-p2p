---
id: TASK-68
title: >-
  profile_p2p: the 'throughput' figure is the latency figure restated, and it is
  not a transport rate
status: To Do
assignee: []
created_date: '2026-08-09 14:01'
updated_date: '2026-08-09 15:47'
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

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
## PARTLY DONE by TASK-63 - what landed, and what is still open

LANDED (scripts/profile_p2p.py, commit "task-63: race the peer path against a
real upstream, not a fiction"):
  * AC#3 is MET for the upstream side. `throughput_bytes_uncompressed_nar_per_s`
    is renamed `realise_rate_bytes_uncompressed_nar_per_s`, and the arm carries
    `realise_rate_is_not_a_transport_rate` spelling out the identity: constant
    numerator over a whole `nix-store --realise`, hence 1/realise_s rescaled,
    with unpack + sha256 NarHash + store registration in the denominator. The
    printed summary tags the line "(NarSize; NOT a transport rate - TASK-68)".
  * A REAL transport rate now sits beside it:
    `upstream_nar_transport_bytes_compressed_wire_per_s`, from the testproxy's
    own per-record `bytes_sent` / `duration_ms` at the cache boundary. It is a
    link rate, not a realise rate: measured 977.8 MB/s against the unshaped
    loopback upstream and 19.9 MB/s against the WAN-shaped one, i.e. it tracks
    the link while the realise rate does not.
  * `cross_condition_block` reports the upstream link rate next to each
    condition's speedup, and states in `peer_side_link_rate` that the peer side
    is NOT measured here, citing TASK-64's 187/255 MB/s bench as the contrast.
  * --self-test check: the realise-rate key exists, the old throughput key does
    NOT, and the transport-rate key is present.

STILL OPEN, and it is the harder half:
  * AC#1/AC#2 are only partly served. The realise rate is now labelled, but the
    honesty machinery does NOT yet MECHANICALLY gate "any figure derived by
    dividing a CONSTANT by a measured quantity". A future key of that shape
    could be added and nothing would reject it. AC#2 asks for a gate proven by
    mutation, and that does not exist - the current protection is a name and a
    note, which is the editorial protection this project keeps finding
    insufficient. Suggested shape, matching the existing gates: a
    `derived_quantity_violations()` that requires any `*_rate_*` / `*_per_s` key
    whose numerator is a report CONSTANT to carry an explicit
    `..._is_not_a_transport_rate`-style sibling, mutation-proven in --self-test.
  * There is still NO peer-side transport rate. The comparison "peer link vs
    upstream link" is only closable when the daemon (or its iroh provider)
    reports bytes served over the time it was actually serving. Until then the
    honest contrast is TASK-64's separate bench, and that is what the report
    says. TASK-65 may be able to produce this as a side effect of its axis.
<!-- SECTION:NOTES:END -->
