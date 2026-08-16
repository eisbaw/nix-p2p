---
id: TASK-227
title: >-
  Full text-enumeration closure for unknown-KIND offers (tag/field-name/value
  channels; the TASK-224 residual)
status: To Do
assignee: []
created_date: '2026-08-16 00:25'
labels:
  - irreversible
dependencies: []
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-224 closed the STRUCTURAL/list half of the unknown-KIND no-enumeration gap (arrays, nested objects, and multiple fields are rejected, on all three tolerate-drop routes: Claim.transports + single-key HoldAnswer::Have.offers + batch BatchHoldResponse.offers, via the shared reject_enumeration_shaped_unknown_offer). A TEXT residual REMAINS: a single opaque scalar of identity-shaped text can still be carried in an ACCEPTED unknown offer across THREE channels - (1) the transport TAG itself (any string kind not in KNOWN_TRANSPORT_TAGS, e.g. {"transport":"blake3:<64hex>"}), (2) an extra FIELD NAME (e.g. {"transport":"future","blake3:<64hex>":"x"}), and (3) the single scalar string VALUE (e.g. {"transport":"future","loc":"blake3:a,blake3:b,..."}). Each is accepted-then-dropped, and even ONE accepted unasked identity is a claim.rs:332 defect (an accepted-but-dropped also_held naming an unasked key IS an enumeration defect).

THREAT MODEL (orchestrator arbitration, 2026-08-16): this is a FORMAT-CLEANLINESS gap per the repo self-imposed claim.rs:332 rule, NOT a violation of the actual privacy invariant. The privacy invariant is that an honest peer secret holdings are never enumerated; a hostile RESPONDER naming FAKE identities to an asker leaks nothing about any honest peer. So this is Low-urgency correctness/cleanliness, not a live privacy leak. It is nonetheless a real defect by the repo own standard and must be owned, not hand-waved.

NOT OWNED BY TASK-223: TASK-223 is byte-VOLUME only (a per-offer byte cap bounds how MANY bytes/identities fit); it does NOT ELIMINATE identity naming - a byte cap still admits one (or a few short) identities per slot, and one accepted unasked identity is already the defect. This task owns ELIMINATION.

GENUINE CLOSURE CRITERION: eliminate identity NAMING in an accepted unknown offer across all three channels and all three routes - not merely bound its bytes. A test that pins the criterion should show that NO identity-shaped text survives on an accepted wire via tag, field-name, or value.

ARCHITECTURAL FORK (forward-compat vs enumeration - decide deliberately, DEEP/irreversible, this is the crux): the residual exists ONLY because the current forward-compat contract admits an ARBITRARY string kind + an arbitrary single string locator. Literal closure IS possible (the frozen golden pins just one carrier_pigeon input; it is the arbitrary-string CONTRACT, not the golden, that admits the residual), but at a real forward-compat cost. Options, each with its cost: (A) identity-SHAPE rejection - reject any tag/field-name/value that parses as a content identity (blake3:/sha256: shaped); brittle blocklist, must track identity encodings. (B) length cap short enough to preclude even ONE identity (< ~59 bytes so a sha256:/blake3: id cannot fit); rejects legitimate large future locators (URLs, multiaddrs) and collides with the recorded large-locator concern. (C) tag-only / registered-kinds - tolerate an unknown kind only as a bare {"transport":"<short registered-ish token>"} with NO locator and a bounded tag charset; tightest, but a future transport ships no inline locator until its build lands. Pick with rationale; mutation-prove; record as a deliberate freeze amendment like TASK-110/224.

SCOPE: all three routes (Claim.transports + single-key + batch) and all three channels (tag, field-name, value). Reference this task id in code at the reject_enumeration_shaped_unknown_offer guard site. FROZEN-SURFACE: a further decoder-acceptance narrowing -> DEEP-gate it.
<!-- SECTION:DESCRIPTION:END -->
