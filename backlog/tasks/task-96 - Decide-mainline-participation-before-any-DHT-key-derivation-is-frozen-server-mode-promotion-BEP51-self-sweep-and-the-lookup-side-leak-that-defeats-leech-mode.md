---
id: TASK-96
title: >-
  Decide mainline participation before any DHT key derivation is frozen:
  server-mode promotion, BEP51 self-sweep, and the lookup-side leak that defeats
  leech mode
status: To Do
assignee: []
created_date: '2026-08-10 08:43'
labels:
  - wave-2b
dependencies:
  - TASK-73
  - TASK-78
  - TASK-89
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
This is the irreversibility gate in front of TASK-73's frozen key-derivation surface. It does not duplicate TASK-73's evaluation of iroh-mainline-content-discovery 0.6.0 / iroh-dht-experiment; it answers three questions that must be settled BEFORE a key derivation is committed, two of which are owner decisions rather than engineering defaults.

FACT 1 — THE DEPENDENCY IS NEW, AND ITS DEFAULT ENROLLS USERS IN BITTORRENT INFRASTRUCTURE. `grep -c 'pkarr\|mainline' Cargo.lock` returns 0. We are on iroh 1.0.3, whose iroh-dns pulls hickory-resolver + simple-dns; iroh's mainline usage lives in a separate crate (n0-mainline). So adding the `mainline` crate (pubky/mainline, 8.x) is a new ~6.6k-LOC DHT dependency, and running two mainline implementations in one process if iroh's own DHT discovery is later enabled (TASK-89). Critically, pubky/mainline's DEFAULT is Adaptive mode: client-only, then automatic promotion to SERVER after 15 minutes with a publicly reachable address, at which point the node stores and serves peer records for arbitrary third-party torrent infohashes. Shipped in a NixOS module that is opt-out-only enrollment of every reachable nix-p2p user as BitTorrent DHT infrastructure — an incident on a corporate, university or CI network, and an owner decision.

FACT 2 — ANY PER-PATH KEY SET WE PUBLISH IS ENUMERABLE BY DESIGN. BEP51 sample_infohashes is a first-class, libtorrent-default RPC returning a random sample of a node's stored infohashes plus a total count, with the interval capped at 21,600 s and the spec's stated goal being that a single node can survey the entire DHT within a few hours. Restricting publication to upstream-signed NarHashes does not help — it GUARANTEES the crawler can invert every key by computing NarHash -> key over any nixpkgs revision, yielding a per-IP, per-package software inventory refreshed multiple times a day, in a namespace under continuous commercial crawling.

FACT 3 — THE LOOKUP SIDE LEAKS UNCONDITIONALLY, AND NO PUBLICATION RESTRICTION TOUCHES IT. BEP51's own rationale notes that DHT indexing is already possible by passively observing get_peers queries. So every lookup broadcasts, from the operator's IP to the ~8 strangers nearest each key, a timestamped want-list of what they are about to install. TASK-78 leech mode protects the announce side only; a leech that publishes nothing still leaks its entire fetch history. The PRD's residual-leak acceptance (PRD.md, privacy invariant) was priced against targeted online probing, not against this.

FACT 4 — CORRECT THE RECORD ON NodeId RECOVERY. BEP5 announce_peer stores only the querying node's source IP and the supplied port; implied_port merely selects which port, it is not a value field, so a 32-byte iroh NodeId cannot go in. iroh requires a NodeId to connect — the ed25519 key IS the TLS identity, there is no anonymous connect-by-address. The claim that 'n0 used identify-on-announced-port' is a misattribution: n0-mainline does BEP44 pubkey-keyed NodeId->address (forward direction only), and iroh-mainline-content-discovery announced TRACKER locations, not peers. So addr->NodeId reverse lookup has no upstream precedent and building one publishes a content-key -> IP -> long-term-NodeId reverse index that does not exist today.

OUTPUT is a decision record with measurements attached, not code we keep.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A two-host experiment where host A announces N keys via the `mainline` crate and host B runs a BEP51 sample_infohashes sweep, reporting the fraction of A's key set recovered and the wall-clock time to recover it. BITE: A must derive its keys from a seed B does not have, and the harness must self-check that B had no prior knowledge — a run where B is handed the key list is vacuous and must fail its own assertion.
- [ ] #2 Client-only mode is verified by OBSERVATION, not configuration: run for >=30 minutes with a publicly reachable address and assert zero inbound DHT queries were served, counted at the request handler. BITE: flip the same node to adaptive mode and confirm the identical assertion FAILS after the 15-minute promotion window — if the assertion passes in both modes it is not observing the promotion boundary and proves nothing.
- [ ] #3 Announced-endpoint reachability measured over >=20 trials across two different ISPs, reporting the fraction of announced IP:port endpoints dialable by a THIRD host on a third network. BITE: the probing host must not be on the announcer's LAN or NAT — demonstrate that a same-LAN probe reports a materially higher success rate, so the number being trusted is the off-net one.
- [ ] #4 A written decision record answering, with the above measurements attached: (a) do we ship a mainline dependency in the NixOS module at all; (b) client-only or server, and how is that enforced rather than defaulted; (c) does the get_peers lookup-side leak change TASK-78's leech-mode privacy claim, and if so what text in PRD.md's privacy invariant changes. BITE: TASK-73's key-derivation freeze carries a tracker dependency on this record; verify the edge exists and that TASK-73 cannot be marked done without it.
- [ ] #5 The task's notes correct three factual claims currently circulating in the backlog: that `mainline`/`pkarr` are already in our dependency graph (they are not — Cargo.lock has zero occurrences), that n0 solved NodeId recovery with identify-on-announced-port (they did not), and that iroh-mainline-content-discovery 0.6.0 is recent and actively developed (crates.io dates it 2025-04-04 and upstream deleted its mainline layer weeks later). BITE: grep the backlog for those three claims and confirm each surviving occurrence is annotated.
<!-- AC:END -->
