---
id: TASK-167
title: >-
  Iroh relay evidence: produce finer typed failure reasons or amend AC#3
  (deadline-collapse)
status: To Do
assignee: []
created_date: '2026-08-12 14:13'
labels:
  - iroh
  - evidence
  - relay
  - hardening
  - wave-2c
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
F3 from TASK-142 DEEP gate (mped-architect + codex, MEDIUM). 4 of 6 typed-failure arms (relay-outage, wrong-certificate, wrong-identity, forced-direct-failure) collapse to reason=deadline; the finalizer's allowed-reason sets were widened to permit it (wrong-certificate accepts wrong_certificate|relay_outage|deadline, so it cannot distinguish a cert failure from an outage). Injections are genuinely distinct and the collapse is documented in LIMITATIONS, but this is TASK-139 N1/N3 debt accepted via a relaxed oracle. Options: (a) surface finer connect-error classification from iroh's connect error instead of only timing out, or (b) formally narrow AC#3 to accept the documented deadline-collapse.
<!-- SECTION:DESCRIPTION:END -->
