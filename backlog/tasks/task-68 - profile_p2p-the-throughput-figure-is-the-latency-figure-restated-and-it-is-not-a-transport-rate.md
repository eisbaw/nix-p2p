---
id: TASK-68
title: >-
  profile_p2p: the 'throughput' figure is the latency figure restated, and it is
  not a transport rate
status: Done
assignee:
  - '@claude'
created_date: '2026-08-09 14:01'
updated_date: '2026-08-17 13:08'
labels:
  - honesty
  - measurement
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
FOUND BY TASK-64. scripts/profile_p2p.py:745 computes throughput as `workload_bytes_uncompressed_nar / realise_s` per run, per arm. The numerator is the SAME CONSTANT in both arms, so throughput_ratio == 1/latency_ratio ALGEBRAICALLY. The task-42 report nevertheless presents 'throughput ratio 3.61' beside 'latency ratio 3.53' as if they were two agreeing observations - they are one observation counted twice, and the 3.61-vs-3.53 gap is nothing but mean-of-reciprocals vs reciprocal-of-mean (Jensen), not independent corroboration. That double-count is what made TASK-64's deficit look like it had two witnesses. SECOND defect, same key: the denominator is the whole in-container `nix-store --realise` - substituter query, NAR unpack, sha256 NarHash, store registration - so 758 MB/s and 210 MB/s are END-TO-END REALISE RATES, not transport throughputs, and quoting them as 'HTTP moves X, iroh moves Y' misattributes nix's own costs to the transport. TASK-64 measured the transport alone (daemon/examples/iroh_throughput.rs): the product's fetch is 187 MB/s and iroh-blobs alone 255 MB/s on the same host at 110 MiB, so the in-daemon 210 is roughly the transport plus nix, as expected. NOTE the UNIT rule itself is FINE and did NOT recur: assert_unit_coincidence proves file_size == nar_size for the speedup attrs, so both arms count the same NarSize bytes. This is a DERIVED-QUANTITY honesty defect, not a unit defect - which is exactly why the existing unit gate did not catch it.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The report no longer presents throughput and latency as independent corroboration: either the derived throughput key is removed, or it is structurally labelled as a restatement of realise_s with the identity spelled out
- [x] #2 Any figure derived by dividing a CONSTANT by a measured quantity is labelled as such, and the honesty machinery gates on it - proven by mutation (a report that presents such a pair as two observations must be REJECTED by the self-test)
- [x] #3 The realise-rate figures are renamed so they cannot be read as transport throughput (they carry nix unpack + NarHash + store registration), with the task-64 transport-only numbers cited as the contrast
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

## TASK-68 completed the harder half (commit 033b180)

TASK-63 had done AC#3's data-key rename + a real transport link rate beside it,
but AC#1/#2 lacked the MECHANICAL, mutation-proven gate. Landed now in
scripts/profile_p2p.py:

- derived_quantity_violations(report): pure structural gate, wired into the
  honesty block (compliant now ANDs it) alongside unit/qualifier gates. Two rules:
  (1) every registered constant-numerator rate key
  (realise_rate_bytes_uncompressed_nar_per_s) must carry a disclaimer sibling
  that SPELLS the identity (must contain 'constant' AND '1/latency'); bare or
  vague is rejected. (2) no key may pair a constant-numerator rate stem
  (throughput|realise_rate) with a corroboration stem (ratio|speedup|corrobor) -
  the double-count reborn. Honest latency_speedup_* keys carry no rate stem and
  pass; the measured transport link rate (numerator = measured bytes_sent, not a
  constant) passes too.
- Relabelled the stale counting_rule 'throughput' doc key to 'realise_rate' with
  the identity + TASK-64 transport-alone contrast (fetch 187, iroh-blobs 255 MB/s
  at 110 MiB).

BITE (mutation red/green), all in --self-test:
  * strip the disclaimer sibling -> gate RED, names the bare rate.
  * disclaimer present but no longer names the identity -> RED.
  * inject throughput_speedup_<cond> into the speedup block, rebuild report ->
    honesty.compliant is False end-to-end.
  * CONTROLS: latency_speedup_* and the measured link rate are NOT caught.
  * Load-bearing proof: neutering derived_quantity_violations to `return []`
    turns all three mutation checks RED (self-test exit 1); reverted -> green.

GATES (nix devshell): profile_p2p.py --self-test exit 0 (ALL PASS incl.
assert_unit_coincidence and the unit gate, both untouched); ruff check clean;
ruff format --check clean on profile_p2p.py; check-no-floats.py rc 0 (no float in
any gated comparison - the gate is string/set-membership only). Full e2e not run:
the change is confined to the pure Python report/self-test layer, touches no Rust
or container path.

HONEST LIMITS / still open:
  * The peer-SIDE transport rate: sizeaxis.peer_serve_rate (holder_send_*) closes
    it on the size axis; the speedup arm still cites TASK-64's separate bench for
    the peer side rather than measuring it in-arm. Not regressed here.
  * The gate's rate registry is explicit (one key today). A future
    constant-numerator rate must be added to CONSTANT_NUMERATOR_RATE_KEYS or it
    escapes rule (1) - rule (2)'s stem match is the backstop, but a novel rate
    name with no throughput/realise_rate stem would need registration. Documented
    at the constant.
  * Pre-existing repo-wide ruff-format drift (4 other scripts) keeps `just lint`
    exit 1 independent of this change - folded into TASK-222 (duplicate TASK-244
    archived). profile_p2p.py itself is now ruff-format clean.

DONE (LIGHT gate). Commit 033b180. Landed the mutation-proven derived_quantity_violations gate for AC#1/#2 (AC#3 relabel was TASK-63). Self-test rc0; neutering the gate -> rc1 (load-bearing, orchestrator-verified); check-no-floats rc0; assert_unit_coincidence untouched. Pre-existing ruff-format red on 4 OTHER scripts -> TASK-222.
<!-- SECTION:NOTES:END -->
