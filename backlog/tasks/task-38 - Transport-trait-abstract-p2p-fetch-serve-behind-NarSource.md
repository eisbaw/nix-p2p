---
id: TASK-38
title: 'Transport trait: abstract p2p fetch/serve behind NarSource'
status: To Do
assignee: []
created_date: '2026-08-08 20:12'
labels: []
dependencies:
  - TASK-37
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
A Transport interface so iroh is one impl and BitTorrent a future one, sitting under the frozen NarKey::SignedNarHash NarSource seam. resolve(NarHash) via a transport = fetch the addressed-unit (raw-NAR BLAKE3) and verify. The claim transport tag selects the impl. Keeps the p2p layer swappable per PRD wave-2 scope.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Trait defined; a fake in-memory transport satisfies NarSource and passes the NarHash gate in a unit test (URL-less, keyed on NarHash)
- [ ] #2 The claim transport tag maps to a transport impl; an unknown tag is skipped, not a crash
<!-- AC:END -->
