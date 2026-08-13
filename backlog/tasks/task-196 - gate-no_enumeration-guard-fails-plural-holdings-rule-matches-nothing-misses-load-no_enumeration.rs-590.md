---
id: TASK-196
title: >-
  gate: no_enumeration guard fails - plural-holdings rule matches nothing,
  misses load() (no_enumeration.rs:590)
status: In Progress
assignee:
  - '@claude'
created_date: '2026-08-13 16:01'
updated_date: '2026-08-13 16:14'
labels:
  - infra
  - verification
  - gate-blocker
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Unmasked once TASK-190 fixed the hang that stopped 'just test' completing. daemon/tests/no_enumeration.rs:590 no_function_returns_plural_holdings_it_was_not_given fails: 'the rule did not even notice load, which does return plural holdings; it is matching nothing. Saw: [decode_batch_hold_response, answer_batch, resolve_many, query_batch, query_batch, resolve_many]'. The plural-holdings detection rule has drifted and no longer matches load(); either the rule regex/heuristic or the scanned surface changed. Pre-existing at HEAD 0c71e66, unrelated to the iroh test hang (scans daemon-core source my change did not touch). Blocks a GREEN fail-fast 'just test'.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Ready for gate (commit 2b7578f). Root cause: task-82 changed IndexStore::load return to Result<Vec<PersistedRegistration>, PersistError>; PersistedRegistration was absent from IDENTITY_TYPES, so Vec<PersistedRegistration> was not seen as plural holdings and load was never classified -> self-test 'saw everything but load'. Fix: added PersistedRegistration to IDENTITY_TYPES (+doc sync); the 3 IndexStore::load impls stay exempt (local-startup, non-wire). Guard proven to still bite BY MUTATION: removing the exemptions makes all 3 real load impls FAIL as enumeration APIs. Added the_guard_bites_on_an_enumeration_of_the_persisted_registration_set (new arm fail-closed). Gate: cargo test no_enumeration 11 passed; doc_citations 3 passed; fmt/build --locked/clippy -D warnings all clean. Reviewer to confirm the guard still catches real enumeration.
<!-- SECTION:NOTES:END -->
