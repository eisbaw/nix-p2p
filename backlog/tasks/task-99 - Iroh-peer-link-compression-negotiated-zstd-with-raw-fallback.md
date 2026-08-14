---
id: TASK-99
title: 'Iroh peer-link compression: negotiated zstd with raw fallback'
status: In Progress
assignee:
  - '@mped'
created_date: '2026-08-10 09:10'
updated_date: '2026-08-14 07:28'
labels:
  - wave-2b
dependencies:
  - TASK-94
  - TASK-157
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
THE fix for the wire-cost asymmetry that TASK-94 measures, and the reason that asymmetry is not fatal. See figures/fig-arch-4-signing-and-compression.svg for the whole picture in one page.

THE PROBLEM, measured 2026-08-10 on 20 signed paths >10 MiB from the live cache: cache.nixos.org serves xz at FileSize/NarSize = 0.278 aggregate (median 0.216). Our peers serve RAW nar - daemon/src/rewrite.rs rewrites Compression:none with FileHash=NarHash and FileSize=NarSize, asserted in daemon/tests/narinfo_rewrite.rs. So a peer moves ~3.6x the bytes upstream moves for the same store path, and must sustain >75 MB/s (604 Mbit/s) upload merely to BREAK EVEN before discovery latency is counted. A home uplink is 1.25-5 MB/s. Below the threshold no NAR size wins and the deficit grows with size. Every speedup number this project has published was measured against a FIXTURE cache that also served uncompressed (task-64's assert_unit_coincidence proves file_size == nar_size for the speedup attrs), so none of them included this.

WHY IT IS FIXABLE AND WHY IT TOUCHES NOTHING FROZEN. The ed25519 Sig covers only 1;StorePath;NarHash;NarSize;References, and NarHash is the sha256 of the UNCOMPRESSED nar. Compression/URL/FileHash/FileSize are unsigned transport fields. So the encoding on the wire is free to be anything the two ends agree on: the client decompresses and re-checks the signed hash regardless. The PRD anticipated exactly this at round 3 - the addressed-unit row reads '~3x wire bytes until per-connection zstd (a policy surface, not frozen)'.

COMPRESS THE LINK, NOT THE CONTENT - this distinction is the whole design and getting it wrong breaks the swarm:
  * The addressed unit MUST stay RawNarV1 = BLAKE3(raw nar). It is deterministic, so every peer derives the SAME blob id and a blob is shareable/multi-sourceable. It is also a FROZEN surface.
  * If we instead addressed COMPRESSED bytes, two peers compressing the same nar would produce different bytes (compressor version/settings are not reproducible), hence different ids, hence no sharing and no multi-holder fanout. Do NOT do this.
  * Rejected alternative worth recording: serve the upstream's exact .nar.xz addressed by its FileHash. It would give 0.278x AND perfect sharing among everyone who downloaded it - but nix DISCARDS the compressed file after unpacking, so it needs a retained second copy (~13 GB for this machine's signed set), which is the 'no second copy of the store' position TASK-61 just decided against. Revisit only if link compression underdelivers.

MEASURE, DO NOT ASSUME: zstd on nar data may not reach xz's ratio. Report the achieved ratio and the CPU cost, and remember TASK-64/PRD risk 11 - the peer transport is already CPU-bound at ~204 MB/s doing ~13x TCP's work per byte, so compression CPU competes with transport CPU on the same core. A ratio win that halves throughput is not a win.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The peer link carries compressed bytes while the ADDRESSED UNIT stays BLAKE3(raw nar) - assert the content id is unchanged by compression, so two peers with different compressor settings still offer the SAME blob id and can both serve one fetch
- [x] #2 Achieved ratio and CPU cost measured on real NAR data across >=5 sizes, reported against the 0.278x upstream baseline; the net effect on end-to-end throughput is measured, not inferred from the ratio (compression CPU competes with the transport's own CPU-bound path, PRD risk 11)
- [x] #3 Gate-2 still holds: nix accepts the result byte-identically, and a corrupt or truncated compressed stream still FAILS rather than yielding a short nar - proven by mutation at the new boundary
- [ ] #4 TASK-94's peer-wins inequality is re-evaluated with compression ON, and the README's speedup figures are re-measured or withdrawn - the current ones were taken against an uncompressed fixture upstream and overstate the peer path
- [x] #5 Codec/version is negotiated explicitly per connection; raw remains available, mixed-version peers interoperate, and unsupported codec negotiation falls back to raw or upstream with a named reason.
- [x] #6 Decode is streaming and bounded by signed NarSize, zstd window, CPU/time and memory limits; decompression bombs, corruption and truncation fail closed with bounded resource use.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Authoritative order: mandatory decentralized Iroh node and content discovery TASK-89/TASK-103/TASK-116 and authenticated HTTPS land first. This task then adds negotiated Iroh zstd; TASK-87/88 exercise raw and compressed Iroh; comparative raw Stage A is TASK-125; BitTorrent starts only at TASK-117/75. Tracker work is optional tournament comparison and is not a prerequisite. Raw fallback remains mandatory.

COMPASS 2026-08-13: link compression is THE break-even lever (raw NAR vs compressed CDN) - the single feature that most determines whether the value thesis passes. It is filed IROH-ONLY and blocked behind the iroh discovery chain (89/116/103), but the shipped primary transport is libp2p (PRD Wave-2c). Re-scope: generalise compression to the transport-agnostic NarTransfer/NarServer seam (both backends) OR file a libp2p sibling, and re-audit the iroh-89/116 deps for staleness under libp2p-primary. As filed, the most thesis-critical feature is pinned to a non-shipped stack.

COMPASS backlog surgery 2026-08-13 (F2): RE-SCOPED from 'Iroh peer-link compression' to TRANSPORT-AGNOSTIC negotiated zstd-with-raw-fallback on the peer-fabric NarTransfer/NarServer seam (both backends), because link compression is THE break-even lever (a peer serves the RAW NAR vs the CDN's compressed file) and the shipped primary transport is libp2p (PRD Wave-2c), NOT iroh. Was blocked behind the iroh discovery chain (deps included TASK-89 iroh no-address + TASK-116 iroh BatchHoldQuery + 103/114/115/24/62) — that pinned the most thesis-critical feature to a non-shipped stack. Deps reset to the MEANINGFUL on-ramp: TASK-94 (measure the RAW break-even baseline FIRST — the honest disproof) then compression, over TASK-157 (the shipped libp2p streaming transport it rides on, now Done). The compressed bytes are an UNSIGNED TRANSPORT field; the addressed unit stays the raw NAR (frozen). Wire the negotiation at the seam so both libp2p and iroh transports get it. A future impl may re-add a specific dep if genuinely needed; the iroh-discovery blockers were the stale part.

PLAN (impl by mped-agent, 2026-08-14):
DESIGN: compress the LINK, not the content. Addressed unit stays BLAKE3(RawNarV1) (frozen). New protocol /nix-p2p/<scope>/nar/3 wholesale-replaces /nar/2 (precedent: TASK-157 replaced /nar/1 with /nar/2, no dual-accept) with IN-BAND per-connection codec negotiation.
WIRE /nar/3: Request = 32B digest + 1 accept byte (bitmask; bit0=raw MANDATORY, bit1=zstd) + keep write half open (still-interested). Response status byte: 0 NotHeld / 2 Declined(+reason) / 1 Nar => 1 codec byte (server's chosen codec, must be one fetcher offered) then body streamed to EOF. codec 0=raw (body = raw NAR, identical to /nar/2), codec 1=zstd (single zstd frame of the raw NAR).
INTEGRITY (AC#3/#6): fetch side decodes INCREMENTALLY; counts DECOMPRESSED cumulative bytes vs expected_size (signed uncompressed NarSize) and aborts mid-stream on overflow (bomb fails closed, bounded mem ~cap+block); ALSO caps compressed INPUT at the same cap (a compressed body bigger than the uncompressed bound is a lie); bounds zstd window log. Gate-1 BLAKE3 over DECODED bytes unchanged; corrupt/truncated zstd => TransferError, never short/wrong NAR.
NEGOTIATION (AC#5): fetcher always offers raw|zstd; server picks zstd iff offered+enabled+policy; raw always available (bit0). Mixed codec-capability peers interop via the bitmask. Unsupported => raw fallback with named reason.
AC#1: content id identical compression on/off; two compressor levels (3 vs 19) => same blob id, both serve one fetch.
SEAM: reusable pieces (WireCodec enum, accept bitmask+negotiate, BoundedZstdDecoder push-decoder, compress) in peer-fabric::codec (transport-agnostic, iroh CAN adopt). zstd added to peer-fabric. fabric-libp2p wires it into nar.rs. fabric-iroh port = follow-up.
INDEPENDENCE: zstd is not an HTTP-stack crate and not reachable by testproxy (std-only), so no allowlist/denylist change; note in commit.
MEASUREMENT (AC#2): Rust harness over REAL NARs (nix-store --dump) across >=5 sizes; integer-exact artifact: ratio as (compressed_bytes,raw_bytes) exact pair (baseline (383084972,1176685088)=0.32556); CPU integer ns; throughput integer bytes/sec; net compare via (bytes,ns) cross-multiply. Python finalizer integer-exact, rejects non-finite. NO floats in any gate/decision.
AC#4: thin re-eval of peer-wins inequality with compression ON; TASK-198 owns full shaped-link speedup re-statement.

OUTCOME (mped-agent, HEAD 68cc354):
LANDED: transport-agnostic peer-LINK compression. peer_fabric::codec (WireCodec, ACCEPT bitmask, negotiate_serve_codec + CodecChoiceReason named reasons, compress_zstd, BoundedZstdDecoder streaming bounded decode) + zstd dep. fabric-libp2p wires it: protocol bumped /nar/2 -> /nar/3 (wholesale, precedent TASK-157), request carries a 1-byte accept bitmask, Nar response carries a 1-byte chosen-codec then body; serve_stream negotiates per connection, ServeGate.codec_policy (default zstd on). Addressed unit stays BLAKE3(RawNarV1) - FROZEN, untouched; golden-vectors + content-key + independence all GREEN.
AC STATUS: #1 DONE (content id identical on/off; two levels one blob id - unit+wire tests). #2 DONE (measurement below). #3 DONE (corrupt/truncated/bomb fail closed, proven by mutation at the new boundary - codec + wire + live 2-node nar_transport). #5 DONE (per-conn negotiation, raw mandatory floor, mixed codec-capability interop, named fallback reason). #6 DONE (streaming decode bounded by signed NarSize on DECOMPRESSED bytes + input-cap at zstd compress-bound + window-log bound; bomb aborts mid-stream bounded mem). #4 THIN (inequality re-eval in evidence README; README carries no speedup figures to withdraw; full shaped-link re-statement = TASK-198).
MEASUREMENT (evidence/task-99/68cc354/, integer-exact, no floats in any decision; ratios as exact (compressed,raw) pairs cross-multiplied, ns integers, bytes/sec integers): 7 real nars 7.8KB-178MB. HONEST VERDICT (same-path xz-vs-zstd, 5 CDN paths): xz aggregate 0.1616, zstd-19 0.1681, zstd-3 0.2226 -> zstd does NOT reach xz parity (measure-not-assume confirmed). BUT compression cuts peer wire ~4.5x (raw->zstd-3), collapsing the ~3-6x raw-vs-CDN deficit to ~1.04-1.38x. PRD risk 11 CONFIRMED: zstd-19 near-xz ratio but 2.9 MB/s compress (< home uplink) net-LOSES end-to-end even at 2.5 MB/s; zstd-3 at 340 MB/s wins ~4.3x net on a home uplink. => DEFAULT LEVEL set to 3 (measurement-driven; 19 was wrong). On LAN (~204 MB/s) even zstd-3 marginally loses under the serial whole-nar-compress model -> follow-ups: pipelined streaming compress, adaptive level/disable on fast links.
FOLLOW-UPS: TASK-201 (fabric-iroh adopt peer_fabric::codec) filed; TASK-198 owns full shaped-link speedup re-statement. GOTCHA recorded: comparing zstd on THESE nars vs TASK-94's DIFFERENT 220-nar 0.3256 aggregate falsely reads 'zstd beats xz' - only the SAME-PATH xz compare is honest (nar-set confound).
<!-- SECTION:NOTES:END -->
