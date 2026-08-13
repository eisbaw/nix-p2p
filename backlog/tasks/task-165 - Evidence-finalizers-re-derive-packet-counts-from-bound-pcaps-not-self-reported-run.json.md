---
id: TASK-165
title: >-
  Evidence finalizers re-derive packet counts from bound pcaps (not
  self-reported run.json)
status: In Progress
assignee:
  - '@claude'
created_date: '2026-08-12 14:12'
updated_date: '2026-08-13 04:25'
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

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
F2 plan (relay-capability first): (1) harness run_arm: after INT-stopping the capture, read the capture container logs BEFORE cleanup, parse tcpdump captured/received/dropped, write {scenario}.capture.log into the raw tree, and record captured_packets/received_by_filter/dropped_by_kernel/captured_pcap_records into the arm; add acceptor_ip to run.json topology. (2) finalizer: REQUIRE the exact 8-pcap set + per-arm capture.log; RE-PARSE each pcap (parse_pcap_flows/count_endpoint_packets) and re-derive relay/direct counts, reject mismatch; check dropped==0, captured==received, pcap-records==captured (rejects truncation/text-as-pcap). (3) preserve raw tree: commit the bound pcaps+logs+run.json so counts are re-derivable. (4) schema: arm gains the capture-completeness fields, topology gains acceptor_ip. Prove bite: drop a pcap / tamper a count / inject a kernel drop -> finalizer REJECTS (offline self-test with a synthetic raw tree).
<!-- SECTION:NOTES:END -->
