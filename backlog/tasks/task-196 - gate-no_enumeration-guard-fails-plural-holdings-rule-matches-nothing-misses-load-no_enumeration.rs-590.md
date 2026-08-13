---
id: TASK-196
title: >-
  gate: no_enumeration guard fails - plural-holdings rule matches nothing,
  misses load() (no_enumeration.rs:590)
status: Done
assignee:
  - '@claude'
created_date: '2026-08-13 16:01'
updated_date: '2026-08-13 16:15'
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

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
no_enumeration meta-guard was blind to IndexStore::load: TASK-82 changed load()'s return to Result<Vec<PersistedRegistration>,PersistError> (a Vec of {key,store_path,derived} records = a holdings listing), but PersistedRegistration was not in the guard's IDENTITY_TYPES, so returns_plural_container() didn't classify load as plural and the guard silently stopped protecting the local-persistence surface. Fix: added PersistedRegistration to IDENTITY_TYPES (+ synced the module doc); the three IndexStore::load impls stay in ALLOWED (local-startup reads of this node's own file, not wire-reachable - confirmed not an enumeration leak); added the_guard_bites_on_an_enumeration_of_the_persisted_registration_set. Demonstrated the guard STILL BITES by mutation (removing the load exemptions flags all 3 impls; reverted). no_enumeration 11/0, doc_citations 3/0, fmt/build/clippy clean. Inherent limit (documented): a text-shape guard needs each new holdings-bearing type hand-listed. Pre-existing; unmasked by the TASK-190 gate un-hang.
<!-- SECTION:FINAL_SUMMARY:END -->
