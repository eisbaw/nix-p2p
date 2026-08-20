---
id: TASK-279
title: >-
  Zero-config lan-share SUPPLY + REACHABILITY auto-defaults
  (announce-after-fetch + loopback listen)
status: To Do
assignee: []
created_date: '2026-08-20 00:40'
labels:
  - usability
  - follow-up
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-273 was re-scoped to DISCOVERY-ONLY (Option B): a bare --profile lan-share defaults mDNS ON (zero-config discovery) + back-fills the provider axis, but SUPPLY (seed/store/announce-after-fetch) and a listen stay the operator's explicit choice — so a bare lan-share fails LOUD on missing supply/listen (honest 'saw your intent, here's what's missing'). This task revisits whether to auto-default a loopback listen + announce-after-fetch under lan-share so a bare --profile lan-share is a complete zero-config participant. It was reverted from 273 because codex NO-GO flagged (a) forcing announce-after-fetch is a silent second exposure, (b) a loopback default only serves same-host so 'complete participant' overclaimed, (c) the honesty of failing loud is preferable as the first step. If pursued: the default listen MUST be loopback (the TASK-102 lan_isolation_or_refuse guard refuses a routable listen for a no-allowlist lan-share); pair with TASK-276 (relax isolation for private-LAN serving) for genuine cross-host value; disclose the announce-after-fetch exposure (already wired in 273's startup line when the flag is on).
<!-- SECTION:DESCRIPTION:END -->
