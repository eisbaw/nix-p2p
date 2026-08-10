---
id: TASK-121
title: >-
  BitTorrent compressed arm: canonical representation, bounded decode and raw
  coexistence
status: To Do
assignee: []
created_date: '2026-08-10 22:24'
updated_date: '2026-08-10 22:53'
labels:
  - bittorrent
  - compression
  - tournament
  - wave-2c
dependencies:
  - TASK-62
  - TASK-75
  - TASK-117
  - TASK-125
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
After raw Stage A, resolve whether a compressed BitTorrent representation can satisfy TASK-117's frozen supply, interoperability and offer-cardinality contract. Declare one of two branches before work: SUPPORTED implements a canonical representation as a separate tournament arm; UNSUPPORTED records an evidenced no-go. Standard BitTorrent integrity addresses representation bytes, so raw and compressed arms need distinct explicit locators, but no claim may violate TASK-110's bounded offer rule and the registry never chooses between arms implicitly.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A versioned branch artifact selects SUPPORTED or UNSUPPORTED from TASK-117/Stage-A evidence before Stage-B data is run, with supply, storage, schema, security and independent-client constraints enumerated.
- [ ] #2 If SUPPORTED, canonical codec/version/settings/framing/decompressed length have stable golden vectors and distinct transport locators while RawNarV1/NarHash remains the universal verified identity.
- [ ] #3 If SUPPORTED, raw and compressed are separate configured tournament arms and each claim obeys TASK-110's at-most-one-offer-per-transport-kind rule using TASK-117's frozen representation model; registry dispatch is explicit and preference-free.
- [ ] #4 If SUPPORTED, streaming decode is backpressured and bounded by signed NarSize, zstd window, CPU/time and memory; corruption, truncation, oversized output and decompression bombs fail closed.
- [ ] #5 If SUPPORTED, socket bytes, CPU/RSS/disk/metadata/seed startup/end-to-end throughput and independent-client interoperability are measured against Iroh compression in identical units.
- [ ] #6 If UNSUPPORTED, the artifact records attempted alternatives and the exact violated constraint, marks implementation criteria not-applicable, and forces TASK-122 to emit the compressed-BitTorrent cell as evidenced unsupported rather than omit or impute it.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Conditional completion: supported criteria are checked with evidence when supported and marked not-applicable by the frozen branch when unsupported; the no-go criterion is mandatory for the unsupported branch.
<!-- SECTION:NOTES:END -->
