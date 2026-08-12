---
id: TASK-165
title: >-
  Evidence finalizers re-derive packet counts from bound pcaps (not
  self-reported run.json)
status: To Do
assignee: []
created_date: '2026-08-12 14:12'
updated_date: '2026-08-12 14:13'
labels:
  - iroh
  - evidence
  - hardening
  - integrity
  - wave-2c
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
F2 from TASK-142 DEEP gate (mped-architect, MEDIUM). The iroh evidence finalizers (relay-capability, node-lookup, node-publication) read captured_relay_packets/captured_direct_peer_packets from run.json and only sha256-hash the pcaps into the manifest; they never re-parse the pcap bytes to re-derive the counts. So a buggy or hand-authored run.json with plausible numbers + arbitrary attached pcaps would pass the zero-direct guard. The git-blob binding proves the harness SOURCE is reviewed, not that THIS run.json was produced by executing it. Root fix: each finalizer re-parses every bound pcap (parse_pcap_flows/count_endpoint_packets) and re-derives counts, failing if they disagree with run.json. Systemic across all three evidence families.
<!-- SECTION:DESCRIPTION:END -->
