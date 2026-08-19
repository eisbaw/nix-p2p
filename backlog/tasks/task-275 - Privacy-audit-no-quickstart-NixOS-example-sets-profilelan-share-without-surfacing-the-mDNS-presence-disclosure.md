---
id: TASK-275
title: >-
  Privacy audit: no quickstart/NixOS example sets profile=lan-share without
  surfacing the mDNS presence-disclosure
status: To Do
assignee: []
created_date: '2026-08-19 21:52'
labels:
  - docs
  - privacy
  - follow-up
dependencies:
  - TASK-273
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-273 flips the mDNS default off->on under lan-share (the node multicasts presence/NodeId/listen multiaddrs to the local link). That off->on default flip is the sensitive change. Audit README quickstart, docs/, and nixos examples so none silently enable lan-share without showing the user the presence-disclosure consequence + the --libp2p-no-mdns opt-out.
<!-- SECTION:DESCRIPTION:END -->
