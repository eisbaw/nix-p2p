---
id: TASK-170
title: 'Discovery multimap: partition merge by content_id under untrusted announces'
status: To Do
assignee: []
created_date: '2026-08-12 18:12'
labels:
  - discovery
  - wave-2b
  - security
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Forward-carried from TASK-66 (mped review). InMemoryDiscovery::merge takes the merged content id from the first holder that carries a payload and unions ALL holders' offers under it. Sound for TRUSTED wave-2a seeds (announces are local config, and DirectDiscovery — the network path — is first-Have-wins single-holder, no merge). It becomes a griefing vector the instant a push/gossip layer feeds the multimap UNTRUSTED announces: a malicious FIRST announce carrying a wrong blake3 poisons the merged content_id, so every honest holder's offer is dialed for the wrong content, fails gate-1, and the whole key collapses to a discovery-exhausted miss -> forced upstream for that key.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 merge partitions accumulated claims by content_id and only unions offers WITHIN a content-id group (a disagreeing/minority blake3 cannot mask the honest majority's content id)
- [ ] #2 a test drives >=2 content-id groups under one key and proves the honest group still resolves+fetches while a wrong-blake3 announce is segregated, not merged
- [ ] #3 honest limit named: this only matters once untrusted announces reach the in-process index (push/gossip); until then it is latent
<!-- AC:END -->
