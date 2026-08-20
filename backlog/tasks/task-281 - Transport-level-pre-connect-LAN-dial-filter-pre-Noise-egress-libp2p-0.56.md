---
id: TASK-281
title: Transport-level pre-connect LAN dial filter (pre-Noise egress; libp2p 0.56)
status: To Do
assignee: []
created_date: '2026-08-20 11:55'
labels:
  - hardening
  - follow-up
  - security
dependencies:
  - TASK-280
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Split out of TASK-280 (Mark-emulator + COMPASS: non-converging over-investment against the org/LAN-first threat model). The TASK-280 LanDialGuard behaviour veto fires at handle_established_outbound_connection, i.e. AFTER transport upgrade + Noise/QUIC-TLS auth, so a non-LAN dial completes a session (peer-id + source-addr exposed) before rejection -- though NO kad/identify/nar app substream opens (guard-first), so no content-key/membership/byte crosses. That residual is honestly DISCLOSED (operator line + PRD #13) and inside the stated trust boundary.

codex (280-v2) DISPUTES the "phased SwarmBuilder has no transport-wrap hook -> infeasible" conclusion: an enclosing NetworkBehaviour can delegate pending resolution and FILTER the combined Kademlia/Identify address result before returning it to Swarm; a lower-level wrapped-transport is another option. Investigate a pre-Noise egress filter so a confined lan-share node NEVER completes a session to a non-LAN peer.

LOW: default-safe at HEAD (no public swarm; DHT cannot self-bootstrap) and the leak is disclosed; the structural isolation is the distinct lan-share.v1 Kad scope, not this.
<!-- SECTION:DESCRIPTION:END -->
