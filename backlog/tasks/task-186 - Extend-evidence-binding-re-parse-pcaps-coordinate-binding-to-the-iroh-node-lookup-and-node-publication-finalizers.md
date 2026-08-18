---
id: TASK-186
title: >-
  Extend evidence-binding (re-parse pcaps + coordinate binding) to the iroh
  node-lookup and node-publication finalizers
status: To Do
assignee: []
created_date: '2026-08-13 05:17'
updated_date: '2026-08-18 20:25'
labels:
  - iroh
  - evidence
  - hardening
  - integrity
  - wave-2c
  - deferred-pending-202
dependencies: []
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Follow-up from TASK-165/B1 (done for relay-capability only). scripts/finalize_iroh_node_lookup.py and finalize_iroh_node_publication.py still read captured packet counts from run.json and only sha256-hash the pcaps; they never re-parse the pcap bytes to re-derive the counts, and (where applicable) they trust attribution coordinates from run.json. Apply the pattern proven in finalize_iroh_relay_capability.py: (1) REQUIRE the exact expected pcap set + capture logs, (2) re-parse each pcap (parse_pcap_flows/count_endpoint_packets/count_pcap_records) and re-derive counts, rejecting disagreement/truncation, (3) re-check tcpdump captured/received/dropped completeness, (4) bind any attribution coordinate to the deterministic topology (not free text), (5) require records==IPv4-flow count. Wire mutation bites into each --self-test. The relay-capability finalizer at HEAD is the reference implementation.
<!-- SECTION:DESCRIPTION:END -->
