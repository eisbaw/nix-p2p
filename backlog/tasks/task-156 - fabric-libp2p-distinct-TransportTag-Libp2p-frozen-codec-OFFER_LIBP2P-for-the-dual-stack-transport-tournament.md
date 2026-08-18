---
id: TASK-156
title: >-
  fabric-libp2p: distinct TransportTag::Libp2p + frozen-codec OFFER_LIBP2P for
  the dual-stack transport tournament
status: Done
assignee:
  - claude
created_date: '2026-08-12 08:38'
updated_date: '2026-08-18 00:55'
labels:
  - libp2p
  - fabric
  - transport
  - frozen-seam
  - wave-2c
dependencies:
  - TASK-151
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-151 intentionally reused TransportOffer::Iroh for the first pure-libp2p product, which blocks a real iroh + libp2p transfer registry and leaves no signed place for TASK-219 relay identities. Deliver the final deliberate frozen-seam evolution once: add TransportTag::Libp2p and TransportOffer::Libp2p { node, relay_hints }, with OFFER_LIBP2P=2 as a typed additive variant inside the existing schema-v1 offer union. The hints are bounded signed relay NodeIds, not addresses or opaque bytes. Preserve every pre-existing v1 ProviderRecord/withdrawal byte and rejection exactly, including the version-2 negative vector; add separate tag-2 goldens and an independent oracle. Switch the pure-libp2p product to the distinct tag, retain an explicit non-colliding legacy-read path for old Iroh-tag libp2p records, and prove Iroh + Libp2p registry entries coexist.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A distinct TransportTag::Libp2p and TransportOffer::Libp2p { node, relay_hints } exist; relay_hints is a typed bounded value with at most two NodeIds, and Libp2pTransport::tag() returns Libp2p
- [x] #2 The existing schema-v1 tagged union gains OFFER_LIBP2P=2 without changing any pre-existing v1 ProviderRecord/withdrawal bytes or reject result, including reject_wrong_version(found=2, expected=1); old readers fail closed on tag 2 and upgraded readers retain v1 decode
- [x] #3 A separate byte-pinned tag-2 golden plus independent decoder/signature oracle covers zero, one, and two relay hints and bites tamper, truncation, over-cap, duplicate/descending hints, invalid relay identity, self-relay, and Libp2p node != provider
- [x] #4 The libp2p product publishes the Libp2p offer and dispatches it through the Libp2p tag; any legacy Iroh-tag compatibility is explicit and cannot collide with a real Iroh backend
- [x] #5 The runtime TransferRegistry can hold Iroh and Libp2p transfers simultaneously under distinct keys without overwrite, proven by a biting test
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Compass wire ruling (2026-08-17): TASK-156 is the immediate wire prerequisite of TASK-219 and must define the final tag-2 shape now, including bounded signed relay identities; do not first freeze a narrower Libp2p { node } offer. Use OFFER_LIBP2P=2 inside the existing schema-v1 tagged union. Do not bump the record version: the frozen v1 negative vector intentionally burns version 2, and all old v1 bytes/rejections must remain production-decoder truths. Rollout is reader-first/coordinated; old readers reject tag 2 as UnknownOffer.

Implementation evidence (2026-08-18): code commit 619300a adds TransportTag::Libp2p, bounded RelayHints, additive schema-v1 OFFER_LIBP2P=2, exact typed encode/decode guards, native dispatch, and a separate legacy-Iroh compatibility fallback where native Iroh always wins. The original v1 golden and independent oracle remain byte-identical (SHA256 1590b4e2a8da12221e50670c68e3356326e365ddaf233dabe048dd630640ee04 and 45a0116514cb82d94460f51119ff07cd3fd9398f355f1dfe0371a2f9f10eeaa2). New Rust and pure-Python oracles cover four positive wires and eleven exact rejects; the duplicate-hint guard was mutation-proven by changing >= to >, observing exit 101, then restoring it. Mandatory qa-test-runner and mped-architect reviews both returned GO after the stale TASK-219 schema-v2 note was corrected. nix develop -c just build lint test passed. Exact pre-commit nix develop -c just e2e passed 9/9 scenarios and 107/107 checks in 254.9 seconds. TASK-219 intentionally owns live reservation-derived hints and their runtime consumption.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Delivered the distinct native Libp2p ProviderRecord transport and dispatch key without changing historical schema-v1 bytes or widening daemon-core. Relay hints are signed, typed, strict, canonical, non-self, and capped at two. Old readers fail closed on tag 2; upgraded readers retain old v1 support, and pure-libp2p readers have an explicit non-colliding legacy-Iroh fallback. All acceptance criteria, independent reviews, build/lint/test, mutation bite, and exact E2E gate passed.
<!-- SECTION:FINAL_SUMMARY:END -->
