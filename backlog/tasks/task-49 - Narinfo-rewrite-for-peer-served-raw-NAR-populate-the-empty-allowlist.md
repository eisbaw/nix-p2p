---
id: TASK-49
title: Narinfo rewrite for peer-served raw NAR (populate the empty allowlist)
status: Done
assignee: []
created_date: '2026-08-08 20:28'
updated_date: '2026-08-09 00:45'
labels: []
dependencies:
  - TASK-48
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Codex: as planned S6 is NOT buildable - the client follows the narinfo URL/Compression/FileHash/FileSize and a peer returning a raw NAR for a .nar.xz object fails before the NarHash gate. Populate the wave-1 EMPTY rewrite allowlist: for a peer-served path, rewrite ONLY unsigned transport fields - Compression: none, URL -> the daemon raw endpoint, FileHash: sha256(raw NAR)=the NarHash-equivalent, FileSize: NarSize - preserving ALL signed fields (StorePath, NarHash, NarSize, References, Sig). Correlate the rewritten URL token back to the NarHash. Peer-MISS / mid-transfer fallback: either the daemon serves the raw NAR itself (decompress upstream once, cache raw) OR proves Nix cleanly retries the next substituter. Exercise none/xz/zstd fixtures with REAL nix.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A client given the rewritten narinfo accepts the raw NAR from the daemon and passes its FileHash + NarHash checks; signed fields byte-identical to upstream (bite: mutate a signed field -> client rejects)
- [x] #2 none/xz/zstd fixtures all work end-to-end through the rewrite with real nix
- [x] #3 Peer-miss mid-transfer: the client either gets the raw NAR from the daemon or cleanly falls back to upstream (S2) - documented which, and asserted
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
DONE (commit 69b5170). Implemented rewrite::to_raw + populated REWRITE_ALLOWLIST={Compression,URL,FileHash,FileSize}; signed fields (StorePath,NarHash,NarSize,References,Deriver,CA,Sig) byte-identical. Key insight: for Compression:none the served file IS the raw nar, so FileHash=NarHash and FileSize=NarSize - NO sha256 needed (copy the signed values). URL rewritten to nar/<NarHash-digest>.nar; the none fixture is already this canonical form (byte-for-byte fixed point). Allowlist GATES pass-2 and is proven disjoint from SIGNED_FIELDS, so a signed field cannot be rewritten structurally.

TRIGGER: server rewrites iff RawServeDecision::will_serve_raw(nar_hash) - coupled with a raw-capable NarSource by construction. Wave-1 binary wires NoRawServe (never rewrite -> verbatim upstream narinfo + compressed nar, S2); no production behaviour change. respond_narinfo correlates the REWRITTEN url-token back to the signed NarHash so GET /nar/<token> dispatches SignedNarHash.

PEER-MISS DECISION (asserted): rewrite-to-raw only when a raw source backs it, so nix is never handed a raw narinfo the daemon cannot serve. Mid-transfer raw-source failure -> fast clean 502 -> nix falls back to next substituter/upstream (S2); daemon never masks corruption. On rewrite-error, serve verbatim and record NO correlation so the NAR request fetches the actual compressed bytes.

RAW-NAR ENDPOINT: nar/<NarHash-digest>.nar served by the NarSource (task-38 TransportNarSource returns raw; task-41 wires it live).

VERIFICATION: unit tests + integration (narinfo_rewrite.rs) + scripts/check-rewrite-realnix.py: REAL nix accepts the daemon's own rewrite (via 'daemon rewrite-narinfo' filter) + raw nar for none/xz/zstd, and REJECTS a one-char signed-NarHash mutation. Gates: build/lint/test(exit 0)/nix build .#daemon all green.

GOTCHAS: (1) NarSize-vs-FileSize unit trap avoided - rewritten FileSize=NarSize (raw), pinned by !=compressed-size asserts. (2) Source guard forbids literal 'fixtures/' in .rs (reworded a comment). (3) check-fixtures.py prints a 'FAIL' line for its OWN empty-out negative self-test - not a real failure. (4) xz/zstd raw nars produced by xz -dc/zstd -dc (both in devshell); store paths also exist for nix-store --dump.

FORWARD-CARRY task-41 (S6): wire an availability-index-backed RawServeDecision + a raw NAR source so a RUNNING node B serves its raw nar and node A's REAL nix accepts through the live daemon (this task proved the rewrite OUTPUT is accepted; the live running-daemon end-to-end is task-41). Re-check the finding: with a raw-ONLY source, an UpstreamPath fallback (uncorrelated/rewrite-error) 502s -> S2 (fine).
FORWARD-CARRY task-51: the raw-serve path interacts with the safety envelope (NarSize abort bound already crosses the seam as expected_size).
<!-- SECTION:NOTES:END -->
