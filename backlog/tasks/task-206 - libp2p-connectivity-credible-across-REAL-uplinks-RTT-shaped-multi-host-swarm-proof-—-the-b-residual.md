---
id: TASK-206
title: >-
  libp2p connectivity credible across REAL uplinks/RTT (shaped/multi-host swarm
  proof) — the (b) residual
status: To Do
assignee: []
created_date: '2026-08-14 16:46'
labels:
  - connectivity
  - measurement
  - libp2p
  - credibility
dependencies:
  - TASK-103
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
COMPASS 2026-08-14 credibility gap. The decentralized-DISCOVERY claim is now credibly proven on a genuine routed topology (TASK-179 netns, minimal-pair control). But 'robust CONNECTIVITY works' has TWO honest residuals: (a) zero NAT — TASK-168 closes it (hole-punch/relay/AutoNAT); (b) single physical host + UNSHAPED routing — every connectivity proof runs on one host with no real RTT/loss/asymmetric home-uplink conditions, so the fetch-over-a-realistic-link half is not shown for the libp2p-primary path the way TASK-94/99's shaped links showed it for compression. TASK-80 exists but is iroh/BitTorrent-tournament-framed + parked, so it does NOT cover this. SCOPE: prove a libp2p peer fetch (discover->fetch->serve byte-identical) over a SHAPED link (reuse TASK-70's shaped-link primitive: netns+veth+tc-netem, RTT + bandwidth cap, host-side asserted with a negative control) and/or a genuine multi-host swarm, so the connectivity claim is earned under real link conditions, not just unshaped one-host routing. Complements TASK-168 (NAT) — 168 is 'can they connect at all behind NAT', this is 'does the connection perform honestly under real RTT/bandwidth'. Do after 168 (or interleave). Owner steer: robust connectivity is a basics-first priority.
<!-- SECTION:DESCRIPTION:END -->
