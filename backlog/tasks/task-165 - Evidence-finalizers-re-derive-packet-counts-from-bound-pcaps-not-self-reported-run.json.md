---
id: TASK-165
title: >-
  Evidence finalizers re-derive packet counts from bound pcaps (not
  self-reported run.json)
status: In Progress
assignee:
  - '@claude'
created_date: '2026-08-12 14:12'
updated_date: '2026-08-13 05:54'
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
F2 DONE (incl DEEP-gate B1). Root cause: finalizer read packet counts from a self-reported run.json and only sha256-hashed the pcaps; codex got verdict=pass from a hand-authored run.json with zero pcaps and accepted a text file as a pcap.
Fix (009b26b): harness run_arm reads tcpdump captured/received/dropped from the capture container logs BEFORE cleanup, writes {scenario}.capture.log into the raw tree, gates capture-completeness, records the counters + acceptor_ip into run.json. Finalizer rederive_and_bind_captures REQUIRES the exact 8 {scenario}.pcap + {scenario}.capture.log, RE-PARSES each pcap (parse_pcap_flows/count_endpoint_packets/count_pcap_records), re-derives relay/direct counts from topology.relay_ip:44380 + topology.acceptor_ip:44330, rejects disagreement; re-checks dropped==0/captured==received/records==captured. Raw evidence committed under artifacts/iroh-relay-capability-v1.evidence/ (17 files) so counts are re-derivable.
B1 (blocker, 1c3cd41): F2 bound the COUNTS but trusted the attribution COORDINATE (acceptor_ip) from run.json - mped forged a real direct leak to the true acceptor while relocating acceptor_ip to a decoy -> masked. Fix: assert_topology_coordinates re-derives relay_ip/acceptor_ip from the STRICT canonical acceptor_subnet at the harness's deterministic host offsets (acceptor=hosts[9], relay=hosts[39]) and requires relay_url host==relay_ip; relay_ip is independently pinned by relay-success relay>0, so binding acceptor_ip to the same subnet transitively pins it to the true peer (hosts[39]-hosts[9]=30 for any prefix<=30, no aliasing). Also capture-gate direct-positive (captured_direct_peer_packets>0). S2: require records==IPv4-flow count (non-IPv4 leak can't escape). S3: finalizer imports DEADLINE/GRACE/CONNECT_ARMS/offsets from the harness (no drift). Scope note (76ae1e7): the coordinate binding assumes a genuine capture; a wholly fabricated pcap is out of scope (anchored by the podman sandbox + git-blob-pinned binaries).
GOTCHA content-tag/load: build .#iroh-relay-evidence-image; tag=store-hash prefix of the tarball name; podman load then retag localhost/nix-p2p-iroh-relay-evidence:<hash>; harness refuses :latest. Image label implementation-revision=self.rev ONLY when the git tree is CLEAN -> commit code first. Regen requires the implementation-commit to NOT track the artifact path -> drop the artifact in the code commit, finalize, then commit the artifact.
Oracle bites (wired self-tests + demonstrated on the real tree/forge): wrong count vs pcap -> FATAL; missing pcap -> FATAL; kernel-drop capture.log -> FATAL; text-file-as-pcap -> FATAL; acceptor_ip relocated (the forge) -> FATAL; relay_ip off-offset / relay_url mismatch / non-canonical subnet -> FATAL; direct-positive 0 direct -> FATAL; non-IPv4 record -> FATAL.
Gate: just lint green; both self-tests PASS; deterministic reproduce of the artifact (44c0ac94...). qa green; mped: B1 CLOSED (ship it). Genuine verdict=pass artifact bound to 76ae1e7. Systemic note: the lookup/publication finalizers still only hash pcaps (not re-parsed) - a follow-up task should extend this pattern to them.
<!-- SECTION:NOTES:END -->
