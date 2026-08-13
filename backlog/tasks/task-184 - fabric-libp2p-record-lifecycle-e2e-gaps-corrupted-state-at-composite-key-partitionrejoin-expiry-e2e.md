---
id: TASK-184
title: >-
  fabric-libp2p record-lifecycle e2e gaps: corrupted-state-at-composite-key,
  partition+rejoin, expiry e2e
status: To Do
assignee: []
created_date: '2026-08-13 03:22'
labels:
  - libp2p
  - fabric
  - dht
  - hardening
  - testing
  - wave-2c
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Follow-up to TASK-176 #4. TASK-176 landed a mutation-biting multi-node PROVIDER-RESTART e2e (a_restarted_provider_withdrawal_blocks_resurrection: durable announce-seq -> seq-6 tombstone blocks resurrection of a re-served seq-5 record; the non-durable mutation lets it resurrect). Three dedicated e2e remain, deferred to keep TASK-176 honest (each must BITE by mutation, not be decorative):
1. Corrupted-state-at-the-composite-key: put garbage bytes at provider_value_key and assert the consumer fail-closes (skips, never serves, never crashes). Needs a crate-internal put helper on Libp2pFabric (a test-only surface on the production API - decide whether to gate behind a feature). NOTE: the fail-closed DECODE itself is already exhaustively unit-tested in the frozen record_codec (every RecordDecodeError variant bites) + the directory Err-skip arm; the e2e adds end-to-end realism with a soft bite.
2. Partition+rejoin lifecycle: beyond bootstrap_independence's bootstrap-loss. Hard to make deterministic/non-flaky with in-process kad (no clean connection-cut primitive); needs a topology-control approach.
3. Expiry e2e: announce short-TTL, resolve Found, wait past TTL, resolve -> Miss. Bite is on the frozen decode Stale check (already unit-tested), so low marginal value; include only if it can bite a BACKEND behavior (e.g. the put_record kad-expires reconciliation).
DURABILITY is proven by biting UNIT oracles (FloorStore restart round-trip through a real file; persist.rs round-trips; announcer re-seed via load_seqs) + the provider-restart e2e; these three are additional coverage, not a capability gap.
<!-- SECTION:DESCRIPTION:END -->
