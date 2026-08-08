---
id: TASK-49
title: Narinfo rewrite for peer-served raw NAR (populate the empty allowlist)
status: To Do
assignee: []
created_date: '2026-08-08 20:28'
updated_date: '2026-08-08 23:10'
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
- [ ] #1 A client given the rewritten narinfo accepts the raw NAR from the daemon and passes its FileHash + NarHash checks; signed fields byte-identical to upstream (bite: mutate a signed field -> client rejects)
- [ ] #2 none/xz/zstd fixtures all work end-to-end through the rewrite with real nix
- [ ] #3 Peer-miss mid-transfer: the client either gets the raw NAR from the daemon or cleanly falls back to upstream (S2) - documented which, and asserted
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
FROM task-38 (commit 0d9d6e7): the narinfo URL rewrite composes with the raw NAR that TransportNarSource.resolve() returns (an UpstreamResponse streaming the verified raw NAR bytes, status 200, Content-Length set). The transport delivers the UNCOMPRESSED RawNarV1 (blake3-addressed); your rewrite handles the narinfo URL/FileHash/Compression fields so the client fetches this raw NAR via the daemon. Gate2 (sha256==NarHash) stays Nix's; the daemon returns byte-identical raw NAR so it passes.
<!-- SECTION:NOTES:END -->
