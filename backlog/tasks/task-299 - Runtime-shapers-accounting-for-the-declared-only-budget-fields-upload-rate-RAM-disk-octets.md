---
id: TASK-299
title: >-
  Runtime shapers/accounting for the declared-only budget fields (upload-rate,
  RAM, disk, octets)
status: To Do
assignee: []
created_date: '2026-08-21 10:13'
updated_date: '2026-08-22 07:50'
labels:
  - hardening
  - resource-controls
  - follow-up
dependencies:
  - TASK-264
  - TASK-120
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Routed from TASK-264: enforcing these declared-only profile-budget fields needs dedicated shaper/accounting subsystems, not a plumbing pass (264 correctly refused to fake them). Per-field: upload rate/bytes (compressed-wire per window) needs an egress shaper/token bucket; transient RAM (bytes_ram) needs live RSS/allocation accounting with a decline-at-ceiling; disk (bytes_ondisk) needs on-disk accounting; discovery/announce octets need an octet shaper. Each must be integer/rational (no floats), attributable, and mutation-biteable (revert the charge -> unbounded -> RED). open_fds_count is documented as capacity-only (setrlimit=declared RAISES the soft limit, so it is not a runtime-enforceable ceiling without a process-global fd-exhaustion harness - out of scope unless that harness is built). concurrent_serves count-cap is redundant with the shipped inflight-BYTE ceiling; its only non-redundant meaning is a concurrent-REGENERATE cap -> TASK-297/229.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Each of upload-rate, transient-RAM, and disk-bytes has a runtime enforcement point that declines/caps at the declared integer bound, attributable to that budget, mutation-proven (revert the charge => unbounded => RED); the effective-config output shows the active bound. No floats.
- [ ] #2 discovery/announce octet volume is shaped/accounted against its declared window bound with a biting test; OR a recorded decision that the existing count/deadline bounds suffice and the octet field is documented capacity-only.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
inc1 LANDED (commit f10580a): the upload-RATE egress shaper — the highest-value genuinely-unenforced declared field. Integer node-wide tumbling-window over compressed-wire octets on the shipped libp2p /nar serve path; admit_plan declines once the window is spent (attributable via refused_upload_rate); ShapingWriter charges actual accepted octets. Profile-varying cap from the frozen artifact (0 non-serving; 128MiB/1s lan/public-share). Both binaries wired via wire_disclose_serve_provider. Gate green (lint 19/19, e2e 16/16), mutation-proven; reviews mped GO + qa GREEN + codex GO (2 self-corrected rounds). See git note on f10580a for provenance (cross-model was implementer-orchestrated).

AC status: AC#1 PARTIAL — upload-rate ENFORCED; transient-RAM + disk-bytes remain (inc2). AC#2 (discovery/announce octet) remains (inc2: shape or a recorded decision that deadline/count bounds suffice). inc2 is largely assess-and-decide: RAM likely covered by peer-fabric InflightMeter (document the enforcement point + a --status line); disk = "serving holds nothing at rest" so the only byte-accounting target is the narinfo disk cache (byte-cap or documented capacity-only); octet = likely deadline/count suffices (recorded decision).
<!-- SECTION:NOTES:END -->
