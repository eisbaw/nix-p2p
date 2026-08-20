---
id: TASK-276
title: >-
  Relax lan-isolation guard to admit private-LAN ranges for zero-config same-pin
  SERVING
status: To Do
assignee: []
created_date: '2026-08-19 22:18'
updated_date: '2026-08-20 00:25'
labels:
  - usability
  - privacy
  - follow-up
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-273 defaults a LOOPBACK libp2p listen under a bare --profile lan-share because lan_isolation_or_refuse (TASK-102 stopgap) refuses any non-loopback/non-link-local listen for a no-allowlist lan-share (a routable/wildcard listen is treated as 'reachable by strangers'). Consequence: a zero-config lan-share node can DISCOVER same-pin peers over mDNS and FETCH from them, but can only SERVE to loopback/same-host peers. Genuine cross-HOST same-pin serving currently requires the trusted-key allowlist door (public-announce) or an explicit routable --libp2p-listen paired with that allowlist. Decide whether lan-share should admit private-LAN ranges (is_private: 10/8, 172.16/12, 192.168/16) as LAN-isolated for SERVING, given org/LAN same-pin is the honest first product. This is privacy-sensitive (a routable listen without allowlist authorization serves unauthorized content to the LAN), so it needs an explicit call and likely couples to the announce-authorization model. Out of scope for TASK-273.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Folded into TASK-278 (its default-listen / cross-host-serving AC). Keep for the lan-isolation-relaxation detail; sequence under the supply task.
<!-- SECTION:NOTES:END -->
