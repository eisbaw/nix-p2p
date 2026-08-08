---
id: TASK-51
title: >-
  Conservative safety envelope: dial + body-idle + NarSize abort (default before
  policy)
status: To Do
assignee: []
created_date: '2026-08-08 20:28'
updated_date: '2026-08-08 20:29'
labels: []
dependencies:
  - TASK-39
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Mid-transfer fallback + bounded slow-HIT behavior are required BEFORE any policy is chosen (codex#5, arch#3, qa#4) - otherwise task-43 has nothing safe to assert and a slow peer just stalls. A conservative default: bounded dial timeout, body-idle timeout (subsumes/uses task-25), and a size abort keyed on the SIGNED raw NarSize (NEVER the compressed unsigned FileSize - unit trap). This is the provisional safety net that task-43 asserts (weak invariant: never unbounded-hang, never wrong bytes); task-44 later MODELS the real policy on top; a still-later task implements the chosen optimization. Explicitly labeled provisional.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A slow/stalled peer on a HIT triggers the default bounded abort within a PINNED time bound, then falls back to upstream; build succeeds (bite: remove the envelope -> stall)
- [ ] #2 Size abort uses signed NarSize (bite: a peer serving > NarSize is aborted early, not downloaded in full); dial timeout bounds a dead holder
- [ ] #3 Labeled PROVISIONAL: task-44 may replace the policy; this is the safety floor, not the tuned answer
<!-- AC:END -->
