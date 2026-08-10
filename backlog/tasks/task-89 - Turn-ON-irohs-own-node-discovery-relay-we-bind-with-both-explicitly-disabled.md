---
id: TASK-89
title: >-
  Turn ON iroh's own node discovery + relay (we bind with both explicitly
  disabled)
status: To Do
assignee: []
created_date: '2026-08-10 07:09'
updated_date: '2026-08-10 23:06'
labels:
  - wave-2b
dependencies:
  - TASK-96
  - TASK-114
  - TASK-115
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Cheapest real step toward peers finding each other, and it is currently switched OFF by our own code. daemon/src/transport_iroh.rs bind_loopback_endpoint binds 'on loopback with the relay DISABLED and NO discovery' - correct for deterministic tests, useless for deployment.

This is NODE discovery (EndpointId -> relay URL + direct addrs), NOT content discovery (TASK-73). It is what turns a NodeId in a claim into something dialable across a real network, and without it a claim's NodeId is only usable if the address was also passed on the command line.

iroh ships three, per docs.iroh.computer/concepts/discovery:
  * DNS/pkarr - DEFAULT ON upstream; signed records to an iroh-dns-server resolved over DNS. The
    default server is RUN BY n0. That is a third-party runtime dependency and must be a declared,
    switchable choice, not something we inherit by accident.
  * Local/mDNS-like address lookup - default OFF, no infrastructure, LAN only. This is the highest
    value-per-effort item in the whole discovery area: the LAN/office/CI/home-lab case is exactly
    where a peer plausibly beats a CDN (a gigabit peer vs a ~21 MB/s cache), whereas a residential
    uplink probably loses. Do this one first.
  * DHT address lookup - default OFF; publishes the same signed pkarr records to the BitTorrent
    Mainline DHT via iroh-mainline-address-lookup (0.4+), wired through Endpoint::builder.
    Fully distributed; documented cost is slower lookups than DNS.

Keep the current no-discovery/no-relay mode as an explicit TEST profile - the e2e determinism depends on it, and a test that silently starts using the public network is worse than one that cannot reach it.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 LAN case demonstrated: two daemons on the same network find each other and complete a peer-served nix build with NO address passed on the command line (only mDNS-like local discovery enabled)
- [ ] #2 Any reliance on n0-run infrastructure (the default iroh-dns-server) is a deliberate, documented, switchable choice - stated in the README's honest-limits, not inherited silently
- [ ] #3 Node discovery and relay are configurable per-profile: the deterministic test profile keeps them OFF by default; deployment profiles can independently enable mDNS-local and DNS/pkarr, and can enable Mainline address lookup only if TASK-96 approves it. If TASK-96 rejects Mainline, status/capability output records evidenced unsupported and the build has no Mainline dependency.
- [ ] #4 For every enabled mechanism, documentation states exactly what it publishes about this node; announcing is distinguished from answering a bounded content yes/no query.
- [ ] #5 NodeId remains stable across restart via TASK-115, and direct/hole-punched/relay selection plus discovery source is operator-visible; a no-address-flags restart scenario still reconnects.
<!-- AC:END -->
