---
id: TASK-220
title: >-
  daemon-core: a Compression:none narinfo lacking FileHash silently disables the
  p2p path (rewrite-to-raw over-rejects)
status: To Do
assignee: []
created_date: '2026-08-15 17:03'
labels:
  - daemon-core
  - p2p
  - hardening
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found during TASK-218 (mped-architect Q8). daemon-core rewrite::to_raw REQUIRES a FileHash field (rewrite.rs ~224-227) even though it OVERWRITES the value with NarHash - a well-formedness gate that over-rejects. On the p2p-discovery HIT path (server.rs ~354-386) will_serve_raw=true -> to_raw is called -> a narinfo lacking FileHash returns MissingField(FileHash) -> the narinfo is served VERBATIM and NO token->SignedNarHash correlation is recorded -> the follow-up NAR request falls to the URL-less UpstreamPath (peer_source.rs) and the p2p path is NEVER attempted. Perverse coupling: the MORE reliably discovery succeeds at narinfo-serve time, the MORE likely p2p is silently disabled (correlation is only recorded on the will_serve_raw=false verbatim else-branch, server.rs ~390-392). A Compression:none narinfo lacking FileHash is VALID per Nix (FileHash defaults to NarHash) and is p2p-serveable as-is. Severity Medium-Low: degrades to upstream (safe, never wrong bytes, not in the frozen TCB), but silently kills p2p for a real narinfo class. FIX options: (a) in to_raw, default FileHash := NarHash when absent for Compression:none (it already overwrites it), or (b) record parse_correlation on the to_raw-failure verbatim branch so a raw case needing no rewrite still correlates. WORKAROUND in place (TASK-218): the nat-vm-test.nix signed narinfo now emits FileHash=NarHash + FileSize=NarSize (nixos/sign-narinfo.py) so its p2p path is deterministic; this masks the daemon gap for that harness only. Add a daemon-core unit test: a Compression:none narinfo WITHOUT FileHash must still correlate token->SignedNarHash and dispatch the p2p path (not UpstreamPath).
<!-- SECTION:DESCRIPTION:END -->
