---
id: TASK-252
title: >-
  Guard the backend-isolation claim: daemon-core links no p2p stack, each binary
  links exactly one
status: Done
assignee: []
created_date: '2026-08-18 20:25'
updated_date: '2026-08-18 20:27'
labels:
  - architecture
  - guard
  - seam
  - hygiene
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The README leads with "daemon-libp2p links one backend and nothing of the other, proven by its dependency graph", and the PRD seam argument rests on daemon-core being stack-neutral. At HEAD this is TRUE but UNGUARDED: daemon-core/Cargo.toml has no iroh dep (verified 2026-08-18), yet scripts/check-independence.py only enforces the daemon-vs-testproxy separation (PRD round 5/6), not backend isolation. Nothing fails if someone adds iroh or libp2p to daemon-core tomorrow.

Extracted from TASK-141 AC#1 / TASK-144 AC#6 / TASK-145 (all parked as iroh work) because the GUARD is stack-neutral hygiene that survives the iroh deprioritization -- it protects a claim the README makes to users.

Scope is deliberately small: a source/manifest policy check in the existing guard family, wired into just lint next to independence. Assert (a) daemon-core depends on no p2p stack crate, (b) each daemon binary links exactly one backend. Frozen claim-wire tag strings such as "transport":"iroh" are stack-neutral and must NOT trip the guard -- daemon-core legitimately holds 124 of them.

Per the repo rule, the guard must BITE: prove it by mutation (add the dep, watch it fail) before claiming it works.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
CLOSED NOT-NEEDED 2026-08-18, same day it was filed. I filed this on a WRONG PREMISE: I checked only scripts/check-independence.py (which covers daemon-vs-testproxy) and concluded the backend-isolation claim was unguarded. It is not. daemon-libp2p/tests/no_iroh_closure_guard.rs (TASK-146) walks the NORMAL-edge cargo tree for daemon-libp2p and asserts no iroh crate appears, with an explicit non-vacuity assertion so an empty or wrong graph cannot pass. It runs under just test.

It also covers daemon-core transitively: daemon-core is IN daemon-libp2p closure, so if daemon-core ever linked a p2p stack it would appear in that tree and the guard would bite. The only uncovered direction is the reverse (a daemon-iroh binary linking no libp2p), which is TASK-145 and is parked Low under the iroh deprioritization.

Lesson recorded rather than repeated: verify a guard premise against the actual test tree, not against one guard script.
<!-- SECTION:NOTES:END -->
