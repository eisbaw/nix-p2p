---
id: TASK-256
title: >-
  Offline closure-overlap probe: measure peer hit-rate potential without any
  network code
status: To Do
assignee: []
created_date: '2026-08-18 20:35'
updated_date: '2026-08-19 10:18'
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
- [ ] #1 Overlap computed OFFLINE from nix path-info closures across k>=2 stores + a request/build trace — NO protocol code, NO network, NO containers
- [ ] #2 Run for BOTH populations: (a) same-org / same-pinned-flake stores; (b) unrelated stores on DIFFERENT nixpkgs revisions. The DIFFERENCE between (a) and (b) is reported as the finding
- [ ] #3 Overlap reported as EXACT integer numerator/denominator (path counts AND byte totals); floats only as terminal display. NarSize (uncompressed) vs compressed-wire bytes kept as separate unit-suffixed fields, NEVER compared
- [ ] #4 Cold-start and steady-state hit-rate reported SEPARATELY
- [ ] #5 VACUITY BITE (mutation): the measurement RE-DERIVES overlap from raw path-info; a run handed a fabricated/injected overlap or the wrong closure set FAILS the check (demonstrated by mutation)
- [ ] #6 Written finding: whether org/LAN or global-swarm is the honest first product, whether TASK-255 (whole-store supply) is worth building, and PRD risk 4 (supply lags demand) priced with data. An honest LOW-overlap result is an explicitly VALID outcome (the cheap kill signal)
- [ ] #7 Labeled decision-input ONLY — NOT policy-training, NOT holdout, NOT a PRD success claim
<!-- AC:END -->
