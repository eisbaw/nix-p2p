---
id: TASK-274
title: Decide whether public-share should also default mDNS-on for LAN reachability
status: To Do
assignee: []
created_date: '2026-08-19 21:52'
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
