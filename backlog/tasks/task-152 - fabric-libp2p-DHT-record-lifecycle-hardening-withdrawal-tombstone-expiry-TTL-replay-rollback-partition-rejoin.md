---
id: TASK-152
title: >-
  fabric-libp2p: DHT record-lifecycle hardening (withdrawal tombstone,
  expiry/TTL, replay/rollback, partition/rejoin)
status: To Do
assignee: []
created_date: '2026-08-12 07:55'
labels:
  - libp2p
  - fabric
  - dht
  - discovery
  - hardening
  - wave-2c
dependencies:
  - TASK-103
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Follow-up to TASK-103 (cornerstone landed the crate + directory + announcer + multi-node decentralized test). Harden the record lifecycle against AC#6: propagate a SIGNED ProviderWithdrawal tombstone (announcer.withdraw currently only stop_providing's the local index + lets the value expire on TTL; other nodes' cached value records are not actively retracted). Reconcile ProviderRecord.expiry with the kad record/provider TTL (effective = MIN). Enforce monotonic sequence / idempotent refresh / reject replayed-old and rolled-back records and no expired-or-withdrawn resurrection at the value-store boundary (peer_fabric::record_store has the frozen validation oracle - wire it into the get_record decode path). Bind the discovered PeerId to the record.provider ed25519 so a peer cannot re-store a third party's record under its own composite value key. Cover concurrent providers, restart, corrupted state, partition+rejoin without lost updates.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A signed ProviderWithdrawal is published and other nodes stop returning the record before its natural TTL
- [ ] #2 expiry reconciles with the substrate TTL (effective = MIN) and an expired/withdrawn record is never resurrected
- [ ] #3 monotonic sequence + idempotent refresh enforced; replayed-old, rolled-back and stale records rejected at the get_record decode boundary via peer_fabric::record_store
- [ ] #4 the discovered PeerId is bound to record.provider so a re-stored third-party record under a foreign composite key is rejected
- [ ] #5 multi-node tests: concurrent providers, explicit withdrawal, expiry, restart, replay, rollback, corrupted state, partition+rejoin - no lost updates, no resurrection
<!-- AC:END -->
