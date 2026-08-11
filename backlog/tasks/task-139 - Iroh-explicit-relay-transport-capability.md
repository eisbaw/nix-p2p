---
id: TASK-139
title: Iroh explicit relay transport capability
status: To Do
assignee: []
created_date: '2026-08-11 06:01'
updated_date: '2026-08-11 20:08'
labels:
  - iroh
  - discovery
  - node
  - relay
  - transport
  - privacy
  - wave-2c
dependencies:
  - TASK-114
  - TASK-115
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Implement the explicit default-off relay transport capability for the shared TASK-115 endpoint. Configure a deliberate relay URL or map and expose direct hole-punched or relayed connection provenance. Do not publish or look up NodeId records discover content use LAN or select operator policy. This mandatory Iroh component must emit a passing iroh-relay-capability-v1 artifact for TASK-89; unsupported relay does not complete the task.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Relay is a separate typed default-off capability and no Iroh preset/default relay is inherited. Enabling it performs no DNS/pkarr publication, NodeId lookup or content lookup; disabling it produces zero relay packets. Source and packet mutations prove the boundary.
- [ ] #2 A configured local relay carries a real Iroh connection across routed namespaces where the direct path is deliberately blocked; the trace proves relay attribution. A direct-positive control stays direct and is not falsely credited to relay.
- [ ] #3 Relay connect has a 10000 ms total deadline. Relay outage, wrong URL/certificate/identity, half-open stream and forced direct-path failure remain distinct typed unavailable/path outcomes within the bound; monotonic tests allow at most 1000 ms scheduler grace.
- [ ] #4 Status/preflight records configured relay recipients, NodeId/IP exposure, authentication/trust, health and bytes without full NodeId/IP labels by default. Relay use never implies serving, node publication or a production default.
- [ ] #5 External n0/public relay contact, accounts, credentials, cost or infrastructure require a named owner and explicit authorization. Otherwise only a locally operated routed relay is used and evidence is labelled production-shaped.
- [ ] #6 Emit iroh-relay-capability-v1 verdict=pass with final tree evidence and configuration hashes plus all required direct forced-relay outage deadline privacy and mutation results. Unsupported no-go or ordinary defects keep TASK-89 and global qualification blocked.
<!-- AC:END -->
