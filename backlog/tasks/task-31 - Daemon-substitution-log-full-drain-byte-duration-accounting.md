---
id: TASK-31
title: 'Daemon substitution log: full-drain byte + duration accounting'
status: To Do
assignee: []
created_date: '2026-08-08 11:35'
updated_date: '2026-08-08 11:47'
labels:
  - journey-finding
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-6 (J1 journey) added a per-substitution log line in daemon/src/server.rs (log_substitution): 'daemon: substituted path=... source=... bytes=... duration_ms=...'. WAVE-1 LIMITATION: duration_ms is time-to-upstream-response-headers, not the full NAR body drain (the body streams verbatim after the line is emitted), and bytes is the upstream Content-Length, not a counted drain. Both are exact for the fixed-size Content-Length fixtures used today but mis-report on chunked or truncated transfers. Wave-2 should wrap the streamed NAR body to count actual bytes and fire the log line on stream completion for a true duration. TASK-9 (measurement) will consume these numbers, so accuracy matters there.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Daemon logs actual drained NAR byte count (not Content-Length) per substitution
- [ ] #2 duration_ms covers the full body transfer, emitted on stream completion
- [ ] #3 Chunked/truncated transfer reports honest bytes (a truncated stream is not logged as a full substitution)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Scope clarification (mped-architect review of TASK-6): the wave-1 log reports bytes=Content-Length (the COMPRESSED on-wire size) and duration=time-to-upstream-headers. When the upstream sends no Content-Length (chunked) the daemon now logs bytes=unknown - it deliberately does NOT fall back to the signed NarSize, which is the UNCOMPRESSED size and thus a unit mismatch for any compressed NAR. Wave-2 full-drain accounting (wrap the streamed NarBody, count actual bytes, emit on completion) resolves both the drain-accuracy and the unknown-length cases with a single honest compressed-byte count.
<!-- SECTION:NOTES:END -->
