---
id: TASK-275
title: >-
  Privacy audit: no quickstart/NixOS example sets profile=lan-share without
  surfacing the mDNS presence-disclosure
status: Done
assignee: []
created_date: '2026-08-19 21:52'
updated_date: '2026-08-20 11:59'
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

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Docs-only: the runtime mDNS presence-disclosure line is correct on both binaries; the gap was static docs. Fixed README (the bootstrapping mDNS clause stated stale 'off by default' + framed mDNS as inbound-only, hiding the outbound presence disclosure; and the module quickstart offered lan-share with no disclosure) + the NixOS profile-option lan-share bullet (omitted the mDNS consequence + overclaimed 'isolated'). NixOS mdns option, PRD, docs/ were already honest. Commit surfaces the presence disclosure + --libp2p-no-mdns/mdns=false opt-out at every lan-share touchpoint.
<!-- SECTION:FINAL_SUMMARY:END -->
