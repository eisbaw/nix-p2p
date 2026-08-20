---
id: TASK-274
title: Decide whether public-share should also default mDNS-on for LAN reachability
status: Done
assignee: []
created_date: '2026-08-19 21:52'
updated_date: '2026-08-20 12:00'
labels:
  - usability
  - follow-up
dependencies:
  - TASK-273
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-273 defaults mDNS-on for lan-share ONLY (default_lan_mdns matches LanShare). A public-share node on a LAN with no bootstrap now correctly FAILS LOUD (273's new guard) instead of running dark. Open question: should public-share ALSO default mDNS-on for LAN reachability? Leans yes, but public-share implies global-DHT semantics + broader presence disclosure, so it needs its own privacy call. Out of scope for 273.
<!-- SECTION:DESCRIPTION:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
DECISION: public-share does NOT auto-default mDNS-on; mDNS stays OPT-IN (--libp2p-mdns / services.nix-p2p.libp2p.mdns=true) for public-share. Rationale: (a) public-share is the global-DHT / allowlist-gated profile with EXPLICIT entry paths (bootstrap, provider-addr) and does not depend on mDNS as its sole entry the way a bare lan-share does (lan-share defaults mDNS-on precisely because mDNS is its only zero-config entry); (b) auto-multicasting LAN presence + NodeId + listen-multiaddrs for a public-share node adds a LAN presence disclosure with no clear zero-config NEED, since public-share operators configure their entry explicitly; (c) conservative privacy default (least surprise). A public-share operator who ALSO wants zero-config LAN reachability passes --libp2p-mdns explicitly and gets the same presence-disclosure startup line. No code change; the current default-off-for-public-share behavior is correct and now documented as the decided contract. (If a same-pin org runs public-share nodes on a LAN and wants them to also form the LAN pool, the honest path is --profile lan-share for the LAN role or explicit --libp2p-mdns.)
<!-- SECTION:FINAL_SUMMARY:END -->
