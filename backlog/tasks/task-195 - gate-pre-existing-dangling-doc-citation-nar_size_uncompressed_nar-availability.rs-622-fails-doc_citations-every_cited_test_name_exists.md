---
id: TASK-195
title: >-
  gate: pre-existing dangling doc-citation nar_size_uncompressed_nar
  (availability.rs:622) fails doc_citations::every_cited_test_name_exists
status: Done
assignee: []
created_date: '2026-08-13 16:01'
updated_date: '2026-08-13 16:08'
labels:
  - infra
  - verification
  - gate-blocker
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Unmasked once TASK-190 fixed the hang that stopped 'just test' completing. daemon-core/src/availability.rs:622 backticks the STRUCT FIELD `nar_size_uncompressed_nar` in a /// comment; doc_citations.rs treats any backtick snake_case identifier with >=MIN_UNDERSCORES underscores as a test citation and reports it dangling because it is a field, not a fn/const/type. This is exactly the scanner's STATED LIMIT (doc_citations.rs:21-23): fix by adding the identifier to NOT_ITEMS with a reason, or rephrase the comment so the field name is not backticked. Pre-existing at HEAD 0c71e66, unrelated to the iroh test hang. Blocks a GREEN fail-fast 'just test'.
<!-- SECTION:DESCRIPTION:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
doc_citations guard flagged the backticked snake_case 'nar_size_uncompressed_nar' (>=3 underscores) as a citation needing a matching test/item, but it is a persisted StoreProvision/registration FIELD name in prose (the TASK-82 NarSize-vs-FileSize unit-trap doc). Added it to the guard's NOT_ITEMS allowlist with the reason (keeps the exception visible). doc_citations 3/3 green. Pre-existing; unmasked by the TASK-190 gate un-hang.
<!-- SECTION:FINAL_SUMMARY:END -->
