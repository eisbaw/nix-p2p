---
id: TASK-220
title: >-
  daemon-core: a Compression:none narinfo lacking FileHash silently disables the
  p2p path (rewrite-to-raw over-rejects)
status: Done
assignee:
  - '@claude'
created_date: '2026-08-15 17:03'
updated_date: '2026-08-16 01:32'
labels:
  - daemon-core
  - p2p
  - hardening
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found during TASK-218 (mped-architect Q8). daemon-core rewrite::to_raw REQUIRES a FileHash field (rewrite.rs ~224-227) even though it OVERWRITES the value with NarHash - a well-formedness gate that over-rejects. On the p2p-discovery HIT path (server.rs ~354-386) will_serve_raw=true -> to_raw is called -> a narinfo lacking FileHash returns MissingField(FileHash) -> the narinfo is served VERBATIM and NO token->SignedNarHash correlation is recorded -> the follow-up NAR request falls to the URL-less UpstreamPath (peer_source.rs) and the p2p path is NEVER attempted. Perverse coupling: the MORE reliably discovery succeeds at narinfo-serve time, the MORE likely p2p is silently disabled (correlation is only recorded on the will_serve_raw=false verbatim else-branch, server.rs ~390-392). A Compression:none narinfo lacking FileHash is VALID per Nix (FileHash defaults to NarHash) and is p2p-serveable as-is. Severity Medium-Low: degrades to upstream (safe, never wrong bytes, not in the frozen TCB), but silently kills p2p for a real narinfo class. FIX options: (a) in to_raw, default FileHash := NarHash when absent for Compression:none (it already overwrites it), or (b) record parse_correlation on the to_raw-failure verbatim branch so a raw case needing no rewrite still correlates. WORKAROUND in place (TASK-218): the nat-vm-test.nix signed narinfo now emits FileHash=NarHash + FileSize=NarSize (nixos/sign-narinfo.py) so its p2p path is deterministic; this masks the daemon gap for that harness only. Add a daemon-core unit test: a Compression:none narinfo WITHOUT FileHash must still correlate token->SignedNarHash and dispatch the p2p path (not UpstreamPath).
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Implemented FIX option (a): to_raw now relaxes the FileHash/FileSize presence gate ONLY for Compression: none (rewrite.rs). Pass 1 now captures the Compression VALUE (not just presence); is_uncompressed = ascii_trim == "none". For none, absent FileHash/FileSize are allowed (Nix defaults each to its nar counterpart; the served file IS the raw nar). For COMPRESSED input they stay REQUIRED (FileHash/FileSize are compressed-transport units, distinct from NarHash/NarSize - the recurring unit trap). No FileHash/FileSize line is fabricated in the output; the client re-derives the defaults against the raw bytes.

Tests added (daemon-core):
- rewrite::none_narinfo_without_filehash_or_filesize_rewrites_to_raw (unit)
- rewrite::compressed_narinfo_missing_filehash_still_errors_no_unit_trap (deliverable #3)
- server::none_narinfo_without_filehash_correlates_and_dispatches_p2p (integration: proves correlation recorded -> meta_for_token Some -> Route::Nar dispatches SignedNarHash/p2p, NOT UpstreamPath)

BITE PROVEN BY MUTATION: restoring the strict gate (dropping && !is_uncompressed) makes the two none-tests FAIL (MissingField(FileHash); server correlation absent), while the compressed test stays green.

Gate so far: cargo test -p daemon-core -p daemon GREEN (daemon-core 203 passed, all daemon suites green); cargo fmt --check GREEN; cargo clippy -p daemon-core -p daemon --all-targets -- -D warnings GREEN; scripts/check-no-floats.py GREEN. just e2e RUNNING.

Note: TASK-218 workaround (nixos/sign-narinfo.py emitting FileHash=NarHash) is now non-load-bearing but left in place (not removed). No FROZEN surfaces touched; TASK-25 authoritative-Compression handling untouched (determination reads the authoritative Compression value, never the URL suffix).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
FIX (option a) landed: to_raw relaxes the FileHash/FileSize presence gate ONLY for Compression: none, where each defaults to its nar counterpart and the served file IS the raw nar. Compressed input still requires both (compressed-transport units != nar units; the recurring unit trap). Determination reads the AUTHORITATIVE Compression value, never the URL suffix; no FileHash/FileSize line is fabricated in the output.

Deliverables: (1) met - a Compression:none narinfo without FileHash now rewrites to raw, records token->SignedNarHash, and its NAR request dispatches p2p (SignedNarHash), not the URL-less UpstreamPath. (2) met - three tests; BITE proven by mutation (strict gate -> both none-tests fail). (3) met - compressed-missing-FileHash still errors (honest MissingField -> verbatim serve), no silent NarHash default.

Full gate GREEN: cargo test -p daemon-core -p daemon (daemon-core 203 passed incl. new server test; all daemon suites green); cargo fmt --check; cargo clippy -p daemon-core -p daemon --all-targets -- -D warnings; scripts/check-no-floats.py; just e2e ALL SCENARIOS PASSED (s6-p2p 11/11, tamper-narhash 4/4, s1 11/11, s2 9/9, chain 13/13). No FROZEN surfaces touched; TASK-25 authoritative-Compression handling untouched. TASK-218 workaround (nixos/sign-narinfo.py) now non-load-bearing, left in place.
<!-- SECTION:FINAL_SUMMARY:END -->
