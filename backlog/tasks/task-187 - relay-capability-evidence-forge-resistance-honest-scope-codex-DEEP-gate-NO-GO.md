---
id: TASK-187
title: >-
  relay-capability evidence: forge-resistance + honest scope (codex DEEP-gate
  NO-GO)
status: To Do
assignee: []
created_date: '2026-08-13 05:54'
labels:
  - iroh
  - evidence
  - relay
  - integrity
  - security
  - wave-2c
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Codex adversarially attacked the TASK-166/165-hardened relay finalizer and DEMONSTRATED (verified forges under /tmp) that verdict=pass is still forgeable + claims properties the finalizer does not enforce. Blockers: (1) the pcap re-parse checks packet COUNTS only, never that packets represent a real relay connection (no handshake/QUIC/TLS/ALPN/identity/payload validation) -> a fabricated pcap with matching counts + hand-written capture logs finalizes pass with no podman/network. (2) captures carry no run-id/scenario/outcome/peer-identity binding -> a genuine FAILURE pcap replays as relay-success. (3) B1 binds the attribution COORDINATE (relay_ip/acceptor_ip offsets) but not semantic attribution: a pcap to the decoy relay + a direct packet to a DIFFERENT 'true peer' passes; route-blocking is emitted unconditionally (no route/network-inspect retained). (4) REAL BUG: the relay_url host regex (finalize:371) reads URL userinfo as host + ignores port, and the public-relay marker check is case-sensitive -> a run using the PUBLIC n0 relay (https://10.x:pw@USE1-1.RELAY.IROH.NETWORK:44380) passes as no_public_relay=true. FIX: strict canonical URL equality (host==relay_ip, port==RELAY_HTTPS_PORT). (5) REAL BUG/OVERCLAIM: validate_raw_run never uses implementation_commit (finalize:470); no image digest/OCI-label/binary-hash in run.json (relay server gets hard-coded '1'*40 rev); a local podman tag is retargetable -> the same raw tree finalizes against ANY commit, so 'bound to <commit>' is not machine-enforced. FIX: bind the image DIGEST + record binary hashes + verify the implementation_commit. (6) manifest TOCTOU (finalize:222): evidence validated then re-read for hashing -> atomic-replace makes the manifest hash bytes never validated; validate the immutable snapshot whose exact bytes become the manifest. (7) connect_ms is a peer self-report (over-deadline can report a smaller number); document + the F1 numeric oracle is otherwise sound. (8) schema doesn't require connect_ms / permits dup scenarios / allows pass with non-empty failed_constraints. HONEST SCOPE: full forge-resistance vs a malicious evidence author needs cryptographic capture attestation (out of scope); at minimum fix the real bugs (4/5/6), tighten semantics where cheap, and PROMINENTLY document that the verdict is trustworthy only given a genuine sandboxed producer + git-blob-pinned binaries, NOT forge-proof. Blocks TASK-89 using the relay artifact as a passing gate.
<!-- SECTION:DESCRIPTION:END -->
