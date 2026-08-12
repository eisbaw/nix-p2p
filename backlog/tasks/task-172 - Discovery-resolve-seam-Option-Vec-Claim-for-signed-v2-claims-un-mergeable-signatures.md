---
id: TASK-172
title: >-
  Discovery resolve seam: Option<Vec<Claim>> for signed v2 claims (un-mergeable
  signatures)
status: To Do
assignee: []
created_date: '2026-08-12 18:12'
labels:
  - discovery
  - wave-2b
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Forward-carried from TASK-66 (mped review). resolve() returns Option<Claim>, so multi-holder is expressed by MERGING accumulated claims into one synthetic Claim (union of holders/transports/signatures, payload/relay from the first that carries one). This is a value NO holder ever asserted. Fine while offers are fungible under one blake3 and signatures/relay are empty (v1). The moment claim signatures become real (the reason those fields are RESERVED), the merged singleton is UN-VERIFIABLE: a ClaimSignature signs its OWN holder's claim bytes, not the union, so no holder signed the merged claim. The honest v2 seam is resolve -> Option<Vec<Claim>> with the fetch driver iterating claims and verifying EACH, not a merged singleton.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 when claim signatures/relay become load-bearing (v2), resolve yields the per-holder claims (Option<Vec<Claim>> or equivalent) and the fetch driver verifies each claim's signature before using its offers
- [ ] #2 no synthetic merged claim is signature-checked as if a holder asserted it
- [ ] #3 single-holder path is unchanged (a one-element set behaves exactly as today)
<!-- AC:END -->
