---
id: TASK-261
title: >-
  In-daemon bounded announce-retry for the lone zero-bootstrap mDNS provider
  (put-quorum race; TASK-257 harness-restart workaround -> production fix)
status: Done
assignee: []
created_date: '2026-08-18 23:15'
updated_date: '2026-08-19 08:52'
labels:
  - daemon-libp2p
  - discovery
  - mdns
  - hardening
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Surfaced by the TASK-257 DEEP gate (mped Finding 2). A lone genesis provider on a fresh LAN pool (zero-bootstrap, mDNS on) can LOSE the put-quorum race if it fires its one-shot startup announce BEFORE any peer is mDNS-discoverable: there is no in-daemon retry, so its provider records may fail to put and it stays undiscoverable until something re-triggers the announce. The TASK-257 e2e harness papers over this with a bounded restart under a durable --libp2p-state-dir (stable allowlist key) -- it needed 0 restarts on the passing runs, but that is a TEST-HARNESS workaround standing in for a missing PRODUCTION behaviour (CLAUDE.md: no workarounds; the gap must be owned as a task). FIX: a bounded IN-DAEMON announce-retry for the zero-bootstrap case -- after the kad routing table fills via mDNS (a peer becomes discoverable), re-attempt the provider-record put within a bounded budget, so a lone first provider becomes discoverable without an external restart. Respect the TASK-77 announce budget + the TASK-56 supply-integrity floor. Relates TASK-257 (mDNS bootstrap), TASK-77 (announce budget), TASK-163 (readiness signal). Common case (multiple peers already present) works; this is the first/only-provider edge.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
FOLDED INTO TASK-257 (commit 3028ef1, mped-confirmed F-4). announce_seed_records now retries announcer.announce in-process on AnnounceError::Unreachable, waiting routing_peers>=1 between attempts, bounded by ANNOUNCE_QUORUM_RETRY_WINDOW_SECS=30; record-level/budget faults return immediately. The mDNS-bootstrap e2e passes RESTART-FREE because of this retry. Readiness-gate refinement (same-scope counting) -> the F-4.a follow-up.
<!-- SECTION:NOTES:END -->
