---
id: TASK-259
title: >-
  DNSADDR bootstrap for enterprise/internal fleets (--libp2p-bootstrap accepts
  /dnsaddr, no public default)
status: To Do
assignee: []
created_date: '2026-08-18 20:55'
updated_date: '2026-08-18 20:56'
labels:
  - libp2p
  - dnsaddr
  - bootstrap
  - enterprise
  - operator
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
OWNER DIRECTION 2026-08-18, THIRD of the three bootstrap mechanisms, and DELIBERATELY SCOPED TO ENTERPRISE/INTERNAL ONLY.

THE OWNER CONSTRAINT THAT DEFINES THIS TASK: "i wont run public server infra, so i wont provide public bootstrap nodes -- hence the need for bittorrent, but for enterprise i may run internal nodes."

So this is NOT the public-pool front door. The public pool depends entirely on TASK-258 (Mainline rendezvous), because DNSADDR requires someone to operate the named machines and nobody will for the public case. What DNSADDR IS good for is the enterprise deployment, where an org runs its own routers inside its own network and wants to point its fleet at them without hardcoding addresses into every machine.

WHAT DNSADDR ACTUALLY IS. A multiaddr is libp2ps self-describing address format (/ip4/10.0.0.5/tcp/4001/p2p/12D3KooW...). /dns4/host/tcp/4001 uses DNS to resolve only the HOST -- transport, port and peer id stay hardcoded in the shipped string. /dnsaddr/name instead makes the resolver query TXT at _dnsaddr.<name>, and each record returns a COMPLETE multiaddr including the peer id, with recursive indirection allowed. Live example (IPFS):
  _dnsaddr.bootstrap.libp2p.io TXT -> dnsaddr=/dnsaddr/am6.bootstrap.libp2p.io/p2p/QmbLHAnMoJ...
  _dnsaddr.am6.bootstrap.libp2p.io TXT -> dnsaddr=/dns/am6.bootstrap.libp2p.io/tcp/4001/p2p/QmbLHAnMoJ...
                                          dnsaddr=/dns/am6.bootstrap.libp2p.io/udp/4001/quic-v1/p2p/...

WHY THAT MATTERS FOR AN ORG: the fleet hardcodes only the NAME. Rotating a routers IP, retiring or adding a router, rolling an identity key, or adding QUIC alongside TCP all become a TXT-record edit instead of a fleet-wide redeploy. Without it, an org bakes 12D3KooW...@/ip4/10.0.0.5/tcp/4001 into every machine and the day that host moves the whole internal P2P path silently degrades to upstream-only.

THE ROUTER ROLE ALREADY EXISTS: SharingProfile::Router (TASK-241) is kad-server + relay carrying no content. That IS an internal bootstrap node. This task supplies the addressing indirection in front of it.

SCOPE:
  * Enable the libp2p dns transport/resolver so /dnsaddr and /dns multiaddrs resolve (the dns feature is referenced already; confirm and wire the DNSADDR TXT path specifically, which is distinct from plain /dns4 A-record resolution).
  * --libp2p-bootstrap must accept a /dnsaddr/... multiaddr alongside the existing PeerId@multiaddr form; resolution yields peer ids from the records rather than requiring one up front.
  * Mirror as a NixOS module option so an org sets one name fleet-wide.
  * Support recursive dnsaddr indirection and multiple records per name (several routers, several transports).
  * Ship NO default name. There is no public bootstrap domain and none is planned; a compiled-in default would be a promise the project cannot keep.

OPERATOR-CONTRACT MAPPING (TASK-120):
  * Axis 2 (node/address discovery) plus axis 6 (lookup leakage): resolving _dnsaddr.<name> discloses to the DNS resolver that this host runs nix-p2p. Preflight must say so even for an internal name, since an internal name may still be resolved by a corporate resolver that logs.
  * upstream_only must not resolve anything at all.
  * lan_share: the Wave-2c contract forbids packets to public DNS discovery infrastructure. An INTERNAL resolver is not public infrastructure, so lan_share may permit an internal /dnsaddr name -- but that distinction must be enforced and evidenced, not assumed. Getting this boundary right is the subtle part of the task.

TESTING: an org-shaped container topology where a router-profile node is reachable only via a /dnsaddr name served by a local resolver; consumers get the name and nothing else, and complete a real fetch. BITE: break the TXT record and discovery must fail, proving the name was load-bearing. Prove upstream_only issues zero DNS queries, and prove the lan_share internal-versus-public resolver boundary holds under mutation.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 --libp2p-bootstrap accepts a /dnsaddr/<name> multiaddr and resolves peer ids from the TXT records, including recursive indirection and multiple records per name
- [ ] #2 Mirrored as a NixOS module option so an org points a whole fleet at one name
- [ ] #3 NO default bootstrap name ships; there is no public bootstrap domain and a compiled-in default would be a promise the project cannot keep
- [ ] #4 Org-shaped container topology: a router-profile node reachable only via a /dnsaddr name from a local resolver, consumers given the name and nothing else, real byte-identical fetch completes
- [ ] #5 BITE: breaking the TXT record makes discovery fail, proving the name was load-bearing and no address arrived another way
- [ ] #6 upstream_only issues ZERO DNS queries for bootstrap; guard bites under mutation
- [ ] #7 The lan_share boundary is enforced and evidenced: an internal resolver is permitted, public DNS discovery infrastructure is refused fail-closed
- [ ] #8 Preflight and --status record the DNS resolver as a lookup-exposure recipient even for an internal name
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Sequence (owner 2026-08-18): TASK-257 mDNS first, then TASK-258 Mainline rendezvous, then this. Scoped to enterprise/internal because the owner will not run public server infra.
<!-- SECTION:NOTES:END -->
