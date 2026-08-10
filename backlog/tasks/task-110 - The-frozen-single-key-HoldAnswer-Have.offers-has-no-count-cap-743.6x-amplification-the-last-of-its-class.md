---
id: TASK-110
title: >-
  The frozen single-key HoldAnswer::Have.offers has no count cap: 743.6x
  amplification, the last of its class
status: To Do
assignee: []
created_date: '2026-08-10 17:11'
updated_date: '2026-08-10 17:11'
labels:
  - irreversible
dependencies:
  - TASK-91
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Deferred from TASK-91 round 7, and it is the LAST member of the amplification class.

TASK-91 fixed the batched path: the offer dictionary is now bounded against ANSWERED keys (<= MAX_OFFERS_PER_ANSWER=4 per answer, and at most one per transport KIND, since the content behind a key has one identity per transport). Amplification fell 613.8x -> 4.0x; a 91 B query now elicits at most 366 B carrying at most one content identity.

THE FROZEN SINGLE-KEY PATH WAS NOT FIXED AND IS NOW THE WORST REMAINING CASE. HoldAnswer::Have.offers has no count cap at all. Measured by two independent reviewers: 622 offers = 65,440 B against an 88 B query = 743.6x amplification, bounded only by the pre-existing 64 KiB MAX_CLAIM_WIRE_BYTES gate. A BitTorrent infohash is a CONTENT identity, so this is both an amplification vector and a no-enumeration vector: a peer asked about ONE key may volunteer hundreds of content identities the asker never named.

WHY IT WAS DEFERRED, correctly: capping it narrows what a FROZEN type ACCEPTS. That is the same decoder-acceptance decision the orchestrator ruled on for deny_unknown_fields at KnownTransport/KnownPayload (see TASK-91 notes, ruling recorded 2026-08-10) - approved there because it aligned the code with the file's own documented 'malformed-known errors' rule, preserved unknown-kind forward compatibility, and costs nothing while no peers are deployed. The same four arguments apply here and should be re-examined, not assumed.

THE SEMANTIC ARGUMENT TO REUSE: the batch fix succeeded because it replaced an ARITHMETIC bound with a SEMANTIC one. 'offers.len() <= have_count * 4' became a theorem rather than a check, because the content behind a key genuinely has one identity per transport kind. The single-key Have answers about exactly one key, so the same reasoning gives a tighter bound directly - one offer per transport kind, full stop.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 HoldAnswer::Have.offers is bounded by the same SEMANTIC rule as the batch path (at most one offer per transport kind for the single key being answered), not by an arbitrary count
- [ ] #2 Amplification for the single-key path is MEASURED before and after; the 743.6x figure (622 offers, 65,440 B against an 88 B query) is the pinned before-number and the after-number is reported with its query/response byte sizes
- [ ] #3 The decoder-acceptance narrowing is recorded as a DELIBERATE freeze amendment with its rationale, the way the KnownTransport/KnownPayload one was - an auditor must find a decision, not infer a slip
- [ ] #4 Unknown transport KINDS still decode inertly afterwards (forward compatibility preserved), proven by test
- [ ] #5 Bites by mutation: removing the cap restores an over-cap response being accepted, and the check is proven to have applied before the result is trusted
<!-- AC:END -->
