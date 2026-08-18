---
id: TASK-257
title: >-
  libp2p mDNS LAN peer discovery behind --libp2p-mdns (zero-config bootstrap for
  the org pool)
status: To Do
assignee: []
created_date: '2026-08-18 20:53'
updated_date: '2026-08-18 20:56'
labels:
  - libp2p
  - mdns
  - discovery
  - bootstrap
  - lan
  - user-value
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
OWNER DIRECTION 2026-08-18, FIRST PRIORITY of the three bootstrap mechanisms.

THE PROBLEM: a DHT cannot bootstrap itself. Kademlia routes once you are IN; joining needs one live members address learned out of band. Verified at HEAD: there are NO default bootstrap nodes anywhere in the codebase, and consume-only REFUSES TO START without an explicit --libp2p-bootstrap PeerId@multiaddr (daemon-libp2p/src/main.rs:664). So today every user must be handed peers by someone they know.

WHY mDNS IS FIRST: it removes bootstrap ENTIRELY for the LAN/org case -- zero configuration, zero DNS, zero hardcoded peers, and no infrastructure anyone has to run or pay for. It is also the ONLY one of the three mechanisms compatible with lan-share: the Wave-2c privacy contract requires lan_share to emit ZERO packets/records to public tracker, DNS discovery, relay, DHT or Mainline infrastructure, which rules out both DNSADDR and Mainline there. mDNS is link-local multicast and emits nothing off-LAN. Combined with the existing scope mechanism (protocol names are /nix-p2p/<scope>/kad/1.0.0, so a distinct scope is ALREADY a disjoint network) this makes the private org pool work with no new architecture.

SCOPE:
  * Add the libp2p mdns feature (tokio variant) to fabric-libp2p and wire the behaviour into the existing swarm alongside kad/identify/autonat/dcutr/relay.
  * New CLI flag --libp2p-mdns, DEFAULT OFF, mirrored as a NixOS module option under services.nix-p2p.libp2p (match the existing naming: provider/leech/router/listen/bootstrap/scope).
  * Discovered peers feed the SAME NodeLocator/bootstrap path as an explicit --libp2p-bootstrap entry; mDNS supplies peer addresses, it does NOT become a second content-discovery mechanism.
  * Honour the scope: a peer discovered by mDNS but running a different /nix-p2p/<scope>/kad protocol name must not join. mDNS discovery and scope isolation are independent and must compose correctly.

OPERATOR-CONTRACT MAPPING (TASK-120 axes -- enabling one axis NEVER implies another):
  * This is axis 1, LOCAL DISCOVERY, only. It must not imply serving, announcing, publication, or public participation.
  * upstream_only MUST remain zero-P2P: with the profile set to upstream-only, --libp2p-mdns must be refused or inert, and the node must emit ZERO multicast packets.
  * Permitted under consume_only, lan_share and public_share as an explicit opt-in.
  * Exposure: mDNS discloses this hosts presence and NodeId to every device on the LAN. That is a real disclosure and must be recorded in the exposure ledger and surfaced by preflight/--status, not silently accepted because it is local.

TESTING IS REQUIRED (owner: "we need to test both"). The oracle must BITE by mutation, not by inspection:
  * Two daemons on one LAN segment with NO --libp2p-bootstrap discover each other and complete a real fetch. Disable mDNS on one and the same scenario must FAIL to discover -- that is the bite proving mDNS is load-bearing and no other path leaked the address in.
  * Packet-level proof that upstream-only emits zero multicast; mutate the guard and watch it go red.
  * Scope-mismatch negative control: same LAN, different --libp2p-scope, must NOT form a network.
  * Prefer the existing rootless-podman container topology over adding a new harness family.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The libp2p mdns behaviour is wired into the shipped swarm behind a default-OFF --libp2p-mdns flag, mirrored as a NixOS module option under services.nix-p2p.libp2p
- [ ] #2 Two daemons on one LAN segment with NO --libp2p-bootstrap discover each other and complete a real byte-identical NAR fetch
- [ ] #3 BITE: disabling mDNS on one node makes that same scenario fail to discover, proving mDNS was load-bearing and no address leaked in by another path
- [ ] #4 upstream-only emits ZERO multicast packets with --libp2p-mdns requested; proven at packet level and the guard bites under mutation
- [ ] #5 Negative control: two nodes on the same LAN with different --libp2p-scope do NOT form a network (mDNS discovery and scope isolation compose)
- [ ] #6 mDNS presence/NodeId disclosure to the LAN is recorded in the exposure ledger and surfaced by preflight and --status
- [ ] #7 mDNS supplies peer ADDRESSES into the existing bootstrap/NodeLocator path only; it does not become a second content-discovery mechanism and no holdings enumeration is possible
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Sequence (owner 2026-08-18): mDNS FIRST, then TASK-258 Mainline rendezvous, then TASK-259 DNSADDR. Owner will NOT run public server infra, so there are no public bootstrap nodes: TASK-258 is the only path to a global public pool, TASK-259 is enterprise/internal only, and this task (mDNS) is the zero-infrastructure answer for the LAN/org pool. All three are default-OFF CLI flags plus mirrored NixOS options; all three need tests whose oracles bite by mutation.
<!-- SECTION:NOTES:END -->
