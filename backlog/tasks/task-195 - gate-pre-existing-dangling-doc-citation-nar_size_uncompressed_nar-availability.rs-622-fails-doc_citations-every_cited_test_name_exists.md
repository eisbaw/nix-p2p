---
id: TASK-195
title: >-
  gate: pre-existing dangling doc-citation nar_size_uncompressed_nar
  (availability.rs:622) fails doc_citations::every_cited_test_name_exists
status: To Do
assignee: []
created_date: '2026-08-13 16:01'
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
