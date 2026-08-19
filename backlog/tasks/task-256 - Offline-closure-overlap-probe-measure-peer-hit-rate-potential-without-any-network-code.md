---
id: TASK-256
title: >-
  Offline closure-overlap probe: measure peer hit-rate potential without any
  network code
status: Done
assignee: []
created_date: '2026-08-18 20:35'
updated_date: '2026-08-19 10:33'
labels:
  - measurement
  - value-thesis
  - cheap
  - decision-input
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
THE CHEAP VALUE-THESIS PROBE. Roughly one day, no protocol code, no network, no containers. Surfaced by COMPASS (F6).

THE INSIGHT: the value thesis is not a networking measurement. Offload is approximately hit-rate times bytes-per-hit. Bytes-per-hit is ALREADY MEASURED (TASK-94/198/203: a peers raw NAR loses at every size; fast negotiated link compression restores near-parity). The unmeasured half is HIT-RATE, which is a SUPPLY/DEMAND OVERLAP property -- what fraction of a cold builds closure is already resident on a reachable peer -- and it can be computed OFFLINE from nix path-info across k machines plus a request trace.

WHY NOW: TASK-237 costs weeks, needs shaped multi-node topology, and its own ACs forbid its result from meaning anything (policy_training_eligible=false, topology_class=development_shaped_3_node, never PRD success). This probe answers the actual product question -- is there enough overlap for peers to serve a meaningful fraction of demand -- at a small fraction of the cost, and it can be run before committing to any of that apparatus.

RUN IT FOR TWO POPULATIONS, because the answer is expected to differ sharply and that difference IS the finding:
  (a) same-org / same-pinned-flake machines (the LAN/org case);
  (b) unrelated machines on different nixpkgs revisions (the global permissionless swarm case).

WHAT IT DECIDES:
  * Whether the org/LAN deployment or the global swarm is the honest first product.
  * Whether TASK-255 (whole-store supply coverage) is worth building, or whether announce-after-fetch already suffices for the target case.
  * It prices PRD risk 4 (supply lags demand) with data instead of argument.

DISCIPLINE: obey the no-floats rule -- overlap as exact integer numerator/denominator, byte totals as integers; floats only as terminal display. Keep NarSize (uncompressed NAR) and compressed-wire bytes as separate, unit-suffixed fields; do NOT compare them (that conflation has recurred three times). Report cold-start and steady-state separately. An honest low-overlap result is a valid and valuable outcome -- it is the cheap kill signal, and it should surface BEFORE weeks of further work, not after.

NOT: policy training material, holdout material, or a PRD success claim. TASK-95 and TASK-127 are the nearest existing tasks; both are Low and both are over-specified (127 wants 14 days of longitudinal churn and a running swarm). This is deliberately smaller.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Overlap computed OFFLINE from nix path-info closures across k>=2 stores + a request/build trace — NO protocol code, NO network, NO containers
- [x] #2 Run for BOTH populations: (a) same-org / same-pinned-flake stores; (b) unrelated stores on DIFFERENT nixpkgs revisions. The DIFFERENCE between (a) and (b) is reported as the finding
- [x] #3 Overlap reported as EXACT integer numerator/denominator (path counts AND byte totals); floats only as terminal display. NarSize (uncompressed) vs compressed-wire bytes kept as separate unit-suffixed fields, NEVER compared
- [x] #4 Cold-start and steady-state hit-rate reported SEPARATELY
- [x] #5 VACUITY BITE (mutation): the measurement RE-DERIVES overlap from raw path-info; a run handed a fabricated/injected overlap or the wrong closure set FAILS the check (demonstrated by mutation)
- [x] #6 Written finding: whether org/LAN or global-swarm is the honest first product, whether TASK-255 (whole-store supply) is worth building, and PRD risk 4 (supply lags demand) priced with data. An honest LOW-overlap result is an explicitly VALID outcome (the cheap kill signal)
- [x] #7 Labeled decision-input ONLY — NOT policy-training, NOT holdout, NOT a PRD success claim
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
TASK-256 DONE in commit 7ec27e9. Offline closure-overlap probe scripts/task256_closure_overlap.py + evidence/task-256/. Data: nix path-info --recursive closures for 9 pkgs x 2 nixpkgs pins (A=445d861c nixos-26.05 flake pin = same-pin; B=50ab7937 nixos-24.11 = cross-rev), via cache narinfo (narSize, no NAR download). DEMAND=curl@A (21 paths). FINDING (exact int num/den): (a) same-pin cold 4/21 paths (55.45% NAR bytes 37730224/68039832) -> steady 20/21 (99.44% bytes 67657296/68039832); (b) cross-rev 0/21 in BOTH cold and steady, 0 NAR bytes. Cross-rev overlap is STRUCTURALLY 0 (input-addressed store paths rehash across revs) -> bytes-per-hit irrelevant when hit-rate=0. RECOMMENDATION: org/LAN same-pin is the honest first product (95%+ warm); global permissionless swarm across arbitrary revs is a kill unless segmented into same-pin cohorts. PRD risk 4 = bounded cold-start transient on same-pin only. Defer TASK-255 (no cross-rev hits to announce; same-pin warms to 95% via announce-on-fetch). VACUITY BITE (AC#5) demonstrated on real results: --verify green unmutated, RED (rc1) when b_cross_rev__steady_state paths_num injected 0->21; --self-test green (fabrication+tamper fire, overlap(D,D)!=overlap(D,S_real), empty=nothing-proven). GATES: check-no-floats self+real green (task256 added to SCANNED); check-discovery-no-shortcut self+real green (no discovery code added); ruff check+format green (flake pin ruff). Did NOT run just e2e (no e2e surface). Label: decision-input ONLY (AC#7).

ORCHESTRATOR VERIFICATION 2026-08-19 (escalated past LIGHT because the finding is product-direction-bearing). Independently RE-DERIVED from the raw captures (not the implementer self-report): same-pin steady overlap 39/40 (97.5%), cross-rev steady 0/40; decisively, A_curl vs B_curl share 6 package NAMES but 0 exact store paths — confirming the cross-rev 0 is genuine input-addressed rehashing, NOT an empty-operand or failed-build artifact (B closures are all non-empty: B_curl 36, B_git 154, ...). Oracle BITE run by the orchestrator: injecting a fabricated cross-rev numerator (0->21) drove --verify to exit 1 (RED); real --verify exit 0; --self-test exit 0. Guards: check-no-floats green, check-discovery-no-shortcut green. VERDICT: finding CONFIRMED. IMPLICATION for TASK-258: the global public pool across arbitrary nixpkgs revs offloads NOTHING (0 overlap) — 258 BEP5 rendezvous is valuable only for bootstrapping SAME-PIN cohorts (which is the org/LAN case at global scale). Does not invalidate 258; reframes its value.
<!-- SECTION:NOTES:END -->
