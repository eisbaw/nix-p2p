---
id: TASK-244
title: >-
  draft-codec claim-wire whitespace/escape frame-inflation residual (wire
  amplification stays ~744x within the frame; disclosed at TASK-223)
status: To Do
assignee: []
created_date: '2026-08-17 14:19'
labels:
  - daemon-core
  - claim-wire
  - hardening
  - security
dependencies: []
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Disclosed at TASK-223. The per-offer byte cap (MAX_OFFER_WIRE_BYTES=2 KiB) bounds DECODED offer-CONTENT (<=4 offers x 2 KiB = 8 KiB) but NOT raw-wire bytes: whitespace/escape padding around <=4 tiny offers still fills the claim frame to ~64 KiB (MAX_CLAIM_WIRE_BYTES), so worst-case WIRE amplification stays ~744x vs an ~88 B query, unchanged by TASK-223. This is a DISTINCT channel from the offer-body one: UNIVERSAL (works on any message incl Absent and queries), CONTENT-FREE, and DRAFT-CODEC-ONLY (the JSON draft codec normalizes whitespace away on decode; it vanishes under the planned binary codec where whitespace is not on the wire). It is FRAME-BOUNDED (<=64 KiB always) so it sits WITHIN the README/PRD guarantee (frame-bounded resource use; a hostile peer costs a bounded retry) and is NOT a guarantee break. DECISION: either (a) resolve-under-binary-codec — accept the frame cap as the only bound until the binary codec lands, then VERIFY the whitespace channel is gone (measure-then-close); or (b) add a canonical-form / whitespace-normalization frame gate on the draft codec now. Low priority: frame-bounded + codec-transient. Owning this per the repo standard that a disclosed residual must be owned, not hand-waved (cf TASK-227). Relates TASK-223 (offer-content cap), TASK-227 (identity-text residual), TASK-224 (structural unknown-kind).
<!-- SECTION:DESCRIPTION:END -->
