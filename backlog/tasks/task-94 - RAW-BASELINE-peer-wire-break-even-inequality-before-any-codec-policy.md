---
id: TASK-94
title: 'RAW BASELINE: peer-wire break-even inequality before any codec policy'
status: In Progress
assignee:
  - '@mped'
created_date: '2026-08-10 08:43'
updated_date: '2026-08-13 22:14'
labels:
  - wave-2b
dependencies:
  - TASK-64
  - TASK-70
  - TASK-114
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Establish the raw/uncompressed peer-wire economics used by Stage A. Measure cache.nixos.org FileSize/NarSize over a reproducible signed-path sample, measure raw peer socket throughput under validated controlled link conditions, and compute the break-even inequality without smuggling compression or policy conclusions into the result. This is diagnostic evidence: raw WAN losing at every size is a valid outcome, but it cannot decide the compressed Stage-B policy. Compression implementation and re-evaluation belong to TASK-99.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 FileSize/NarSize is measured over at least 200 cache.nixos.org-signed paths spanning all size deciles, with Compression recorded; an uncompressed fixture sample is classified and excluded from the compressed-upstream aggregate.
- [x] #2 Raw peer socket throughput is measured at at least three NAR sizes under TASK-70's externally verified link profiles; loopback results are labelled loopback and the harness refuses to label them WAN.
- [x] #3 The report computes the break-even size from measured ratio, upstream bandwidth, peer bandwidth and discovery/dial latency; when the denominator is non-positive it prints NO SIZE THRESHOLD EXISTS, proven by a pinned negative-denominator bite.
- [x] #4 Wire bytes, uncompressed NarSize, discovery/control bytes and protocol overhead stay in distinct fields, and provider-side counters plus shaping controls make each arm non-vacuous.
- [x] #5 The artifact is structurally tagged diagnostic_uncompressed and cannot select a production policy; TASK-99 owns codec implementation and the compressed re-evaluation.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
IMPL PLAN + DEP-GUARD (task-94, In Progress)

DEP-GUARD CONFIRMED = NO. task-94 does NOT route bytes through net-upstream-egress-v2/v3.
Evidence: measure.classify_run(records, url_sizes, delivered_by_url, stats_bytes_sent,
client_exit, wall_s) consumes the TESTPROXY per-request log + stats endpoint for the
daemon-on/off arms. task-94 produces none of those inputs: it fetches cache.nixos.org
narinfo METADATA over HTTP (FileSize/NarSize/Compression) and runs a raw TCP transfer
over a tc-netem-shaped netns link (scripts/shaped_link.py), then does arithmetic. No
testproxy, no classify_run, no hedge/winner accounting. => task-52 dep correctly pruned;
proceeding without re-adding it.

DELIVERABLE: scripts/peer_wire_baseline.py (mirrors measure.py/shaped_link.py discipline:
one script, --self-test proving every oracle bites by mutation).
 AC#1 real cache.nixos.org narinfo BFS over closure References (metadata only, no NARs),
      >=200 signed compressed paths; Compression:none classified + EXCLUDED from the
      compressed aggregate (project fixtures manifest supplies deliberate none entries);
      per-decile ratios + span gate (refuses a narrow-band sample -> the prior 0.278 flaw).
 AC#2 raw peer socket throughput at 3 NAR sizes over shaped_link.py's netns+tc primitive;
      loopback labelled loopback; assert_link_label REFUSES a wan_shaped label on a
      loopback/unshaped run (red-green bitten).
 AC#3 break_even(): denom = ratio/B_up - 1/B_peer (sec saved per NAR byte); denom<=0 ->
      NO SIZE THRESHOLD EXISTS (red-green bitten). Break-even needs B_peer > B_up/ratio
      (~75 MB/s for ratio 0.278, 21 MB/s CDN).
 AC#4 distinct unit-suffixed fields (_bytes_compressed_wire / _bytes_uncompressed_nar /
      _bytes_control); unit_violations gate + self-test bite.
 AC#5 diagnostic_uncompressed tag + assert_cannot_select_policy (bitten).

GATE so far: ruff check + format clean; py_compile OK; --self-test OK; 3 mutations
(neg-denominator, loopback-label, compression-exclusion) each proven RED then reverted.
Real cache sample + shaped-link runs in progress.

RESULTS (measured 2026-08-14, nix-shell):
 AC#1: 220 cache.nixos.org-signed COMPRESSED paths, closure BFS from gcc/python3/ffmpeg/git
   (nixpkgs rev 044bfe75), metadata-only (no NARs, 0 drops). Aggregate FileSize/NarSize=
   0.3256 (byte-weighted) => peer moves 3.07x the CDN wire bytes; per-path median 0.340.
   NarSize 4968 B .. 277 MB (55,805x span), all 10 deciles populated (22 paths each).
   Per-decile ratio stable 0.30-0.43 => compression is NOT a big-file artifact. 2
   Compression:none fixtures classified + EXCLUDED. NOTE: the wider decile-spanning
   sample gives 3.07x, LOWER than the legacy 3.6x/0.278 which was taken over 20 large
   (>10 MiB) paths only -- the honest broad number is the point of this task.
 AC#2: raw TCP over shaped_link.py netns+tc (100mbit/20ms): 8/20/40 MiB -> 9.2/10.7/11.3
   MB/s shaped (RTT ~48ms), loopback control ~45-61 Gbit @ 0.05ms; every shaped arm earned
   wan_shaped only after assert_shaping fired; loopback arm REFUSED wan_shaped (bitten).
 AC#3: peer must sustain >67.6 MB/s (=CDN 21MB/s / ratio 0.3256) to break even. home
   uplink 5 MB/s and the measured shaped peer ~11 MB/s => NO SIZE THRESHOLD EXISTS (raw
   WAN loses at every size, expected). 125 MB/s LAN peer => break-even at 21 MB NarSize.
 AC#4: distinct unit-suffixed fields (_bytes_compressed_wire / _bytes_uncompressed_nar /
   _bytes_control); unit_violations gate clean on the real merged report.
 AC#5: report tagged diagnostic_uncompressed; assert_cannot_select_policy passes; no
   policy field. finalize() PASSED end-to-end on the merged real report.

RED-GREEN proof: 3 mutations (neg-denominator guard, loopback-label refusal, compression
exclusion) each driven RED via sed then reverted; self-test green after. ruff check+format
clean, py_compile OK. Shared-box: no orphan netns/procs after shaped runs (verified).

GOTCHA fed forward: the 3.6x/0.278 legacy asymmetry is a NARROW-SAMPLE artifact (large
paths only). The honest decile-spanning ratio is ~0.326 (3.07x). Anyone re-deriving the
"peer must sustain X MB/s" threshold must use the broad ratio, not 0.278, or they overstate
the peer deficit by ~18%.
<!-- SECTION:NOTES:END -->
