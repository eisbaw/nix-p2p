---
id: TASK-62
title: >-
  Store-and-forward: Transport::fetch buffers the whole NAR in RAM before Nix
  sees a byte
status: In Progress
assignee: []
created_date: '2026-08-09 13:24'
updated_date: '2026-08-21 13:35'
labels:
  - streaming
  - memory
  - trust-boundary
dependencies:
  - TASK-65
  - TASK-197
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found by TASK-42. daemon/src/transport_fetch.rs:295 - 'async fn fetch(..) -> Result<Vec<u8>, TransportError>' - the p2p path materializes the ENTIRE NAR in memory, verifies it, then serves it to Nix.

CORRECTED JUSTIFICATION (Mark-emulator review, supersedes the original filing): this is NOT a latency fix. The measured 3.5x peer-path latency penalty is explained, to within noise, by iroh's throughput deficit alone (110 MiB / 758 MB/s = 0.152 s vs / 210 MB/s = 0.549 s; measured 0.159 vs 0.562; latency ratio 3.53 vs throughput ratio 3.61 - see TASK-64). Store-and-forward overlaps only the CHEAP daemon->Nix loopback leg, so expect wall clock ~0.562 -> ~0.55 s. If this ships claiming a latency win it will not deliver one.

The three real reasons to do it:
(1) FETCHER RSS decouples from NAR size (measured 1.23x today).
(2) It RESTRICTS THE ADMISSIBLE POLICY SET, which is why it must land before TASK-44. Once the 200 and the first body byte are committed to Nix, abort-to-cache is no longer invisible. 'Abort after T' and 'hedge' become fundamentally different mechanisms than under buffering - hedge becomes 'hold the response head until first-past-the-gate, then commit and stream' with a bounded-buffer cost, rather than 'run both to completion, double the memory, pick a winner'. Modeling three candidates in a world with no commit deadline and then implementing them in a world with one is wasted modeling.
(3) It creates a NEW BYTE-CROSSING CLASS (peer stream committed, aborted mid-body, Nix refetches upstream) that the frozen counting rule must be able to express - hence TASK-52 (counting-rule v3 freeze) comes AFTER this, not before. Freezing an irreversible rule before landing the change that creates a new provenance case is how a frozen surface gets burned.

Streaming is safe on trust grounds: iroh-blobs uses bao verified streaming so gate-1 is incremental per chunk, Nix independently re-verifies sha256==NarHash over the whole stream (gate-2), and the daemon and peers sit outside the trust base. daemon/src/transport_iroh.rs:480 (dial_and_stream) already loops leaf-by-leaf for the NarSize abort, and NarBody is already a BoxBody stream - the seam exists.

WHAT IT COSTS (do not merge without these): the INVISIBLE FALLBACK is lost. Today TransportNarSource::resolve (transport_fetch.rs:423-489) fails BEFORE any response head is written, so FallbackNarSource turns a peer failure into a silent upstream fetch (S2). After streaming, a mid-body peer failure is client-visible, and the build's survival depends on Nix's retry behavior across substituters after a partial NAR - an empirical question about NIX, not about our code, and it is the PRD's headline additive invariant.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 TTFB oracle: time-to-first-byte measured AT THE HTTP CLIENT, with a pinned TTFB/total ratio; it must BITE - revert to buffering and the check fails. Inspection is not an oracle, and streaming into an unbounded channel that flushes at the end must not pass
- [ ] #2 BACKPRESSURE: with a deliberately slow-reading client, daemon RSS stays bounded and independent of NAR size. Without this the buffer has moved, not gone
- [ ] #3 FAILURE SEMANTICS at the new boundary: after a mid-body peer abort or corruption (kill a peer at ~50% of a 110 MiB NAR), the BUILD STILL SUCCEEDS via fallback and the store path is absent-or-correct, never wrong. The daemon can no longer prevent partial delivery, so the guarantee moves to gate-2 plus Nix's retry - extend TASK-7's killed-mid-NAR suite and prove by mutation
- [ ] #4 FRAMING: Content-Length from the signed NarSize on the correlated path, chunked framing on the cold-start None path - both tested (transport_fetch.rs:481 currently sets it from bytes.len()). Peer stream torn down on HEAD and on client disconnect (server.rs:137 notes a HEAD NAR opens the stream)
- [ ] #5 RSS decouples from NAR size, GATED on a fitted slope over >=5 sizes with CI (needs TASK-65's axis; a single-point check is unfalsifiable). Wall-clock is predicted UNCHANGED - record that prediction up front so 'no latency win' reads as confirmation, not failure
- [ ] #6 The NarTransfer and PeerFabricNarSource contract is streaming end to end: no Result<Vec<u8>> or equivalent whole-object collect remains at the transport/HTTP boundary, and both iroh and libp2p adapters deliver the first verified chunk before the final peer chunk arrives.
- [ ] #7 Cancellation, client disconnect, HEAD, timeout, and backpressure tear down the peer stream within existing integer deadlines and release every in-flight byte/accounting permit; a bounded-channel implementation whose producer can still accumulate O(NarSize) fails.
- [x] #8 Before implementation measurement, a machine-readable manifest freezes integer/rational TTFB-to-total, slow-reader buffered-byte/inflight, cancellation deadline, RSS-slope CI, framing, and A/A/noise bounds plus the exact sample sizes. Missing or post-result thresholds invalidate the claim; floating-point display never becomes the decision authority.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
## Forward-carried from TASK-64: what streaming CAN and CANNOT claim

TASK-64 decomposed the peer path by layer (daemon/examples/iroh_throughput.rs,
`just iroh-bench`, 110 MiB loopback, medians). Per-byte cost of the product's
`IrohTransport::fetch` = 5.345 ns/B, attributed:

    2.695 ns/B (50.4%)  raw QUIC/UDP on the same iroh Endpoint stack   NOT YOURS
    1.222 ns/B (22.9%)  iroh-blobs + bao on top of QUIC                NOT YOURS
    0.689 ns/B (12.9%)  the `Vec` accumulation in dial_and_stream      YOURS
    0.314 ns/B ( 5.9%)  verify_blake3 re-hash + per-leaf timeout       YOURS

WHAT THIS MEANS FOR YOUR CLAIM. Streaming removes the buffer-the-whole-NAR
step, i.e. AT MOST the 0.689 ns/B copy plus part of the 0.314 (an incremental
BLAKE3 over arriving leaves costs the same total hashing, so the re-hash saving
is smaller than it looks). Upper bound: 187 -> 255 MB/s = 1.36x on the transport
leg, and only if streaming costs literally nothing itself.

So: do NOT write an AC or a claim that streaming closes the task-42 3.6x gap.
It cannot. 73% of the cost is below our code and is inherent to QUIC-over-UDP
datagram rate (plain loopback UDP at QUIC's 1452 B datagram size, with no
crypto/CC/reliability, runs at 196 MB/s - SLOWER than the full iroh path).

The honest claim streaming CAN make is about TIME-TO-FIRST-BYTE and about
MEMORY, not about throughput: today the whole NAR is resident before the client
sees byte one, so the client's realise cannot overlap the transfer at all. That
overlap is worth more than 1.36x of transfer rate and it is the reason to do
this task. State it that way.

MEASURED NEGATIVE RESULT, do not redo it: pre-sizing the receive `Vec` was
measured in situ (`iroh_collect` 217.1 vs `iroh_collect_resvd` 231.6 MB/s at
110 MiB) and is INSIDE the run-to-run band; at 8 MiB it inverted. Standalone the
same change is worth 17%, in situ it is worth nothing, because the copy is
dominated by first-touch page faults and by interleaving with network wakeups.
It also carries a hazard worth remembering while you restructure that buffer:
`expected_size` is the narinfo's NarSize, which the daemon does NOT verify, so
`Vec::with_capacity(expected_size)` lets a hostile narinfo turn a dial into a
huge eager allocation - and allocation failure in Rust aborts the process.

Use `just iroh-bench` to pin your own before/after; `daemon_fetch` is the arm
that tracks the product path.

## Correction, forward-carried from TASK-64's review pass

The ladder numbers in the note above shifted after a measurement bug was found
and fixed. The load-bearing conclusion for YOU is unchanged but the figures are:

    below our code   ~70% (68-73% across runs), STABLE - quote this
    our Vec copy     ~0.7 ns/B, ~13%, STABLE
    our verify+timeout   NOT RESOLVED by the instrument (swings +-0.7 ns/B)

Upper bound if streaming removed ALL of our overhead: 188.5 -> 274.1 MB/s =
1.45x (1.36x on the prior run). Still nowhere near 3.6x, so the guidance stands:
claim TIME-TO-FIRST-BYTE and MEMORY, not throughput.

## Forward-carried from TASK-65: the axis your AC#2 and AC#5 are built on

YOUR BEFORE-NUMBER, measured. Fetcher (node-a) peak RSS per byte of uncompressed
NAR, fitted over 5 sizes with 95% CI: see the size axis in `just profile`
(measured on a five-size smoke grid at 1.0322 [0.9928 .. 1.0717], R^2 0.9996,
selected model O(n)). Holder was 2.0363 [1.9852 .. 2.0873]. AC#5 is now
falsifiable: re-run `just profile` and compare the fetcher SLOPE INTERVAL, not
a single point. If streaming works, the fetcher slope's CI should exclude 1.0.

HOW TO USE IT:
 * `scripts/sizeaxis.py` is the module. `nix develop -c just profile` runs it;
   `--skip-speedup --swarm 1 --repeats 1 --size-repeats 1` is the dev loop.
 * the fitted slope with its interval is at
   `models['size.fetcher_rss_hwm_bytes_ram']['slope_ci95']`.
 * scalefit now returns slope_std_error / slope_ci95 /
   slope_distinguishable_from_zero on EVERY fit. Its coverage is Monte-Carlo
   verified in scalefit --self-test.

AC#2 (BACKPRESSURE) - what the axis gives you and what it does NOT. The axis
drives a host-side streaming HTTP reader that reads as fast as it can, so it is
NOT a slow-reading client. You still have to build that. What you get for free:
the residency oracle (below) and the fitted-slope machinery to gate it, plus a
CONCURRENCY arm (k overlapping serves, overlap MEASURED at the holder) which is
the right shape for 'k slow readers'.

THE RESIDENCY ORACLE - use it, do not rebuild it. Peak RSS cannot verify that a
buffer moved rather than vanished: VmHWM is monotone so it never observes a
release, and glibc need not return a freed arena so VmRSS need not either.
IrohProvider::store_residency() asks the blob store what it HOLDS; the daemon
logs it as IROH-STORE-RESIDENT and the profiler consumes it. Discrimination
proven by mutation in daemon/tests/store_residency_oracle.rs.

CAUTION, measured: on this host glibc returned ~97-100% of a freed payload to
the OS whether it was one 32 MiB blob or 512 fragmented 64 KiB ones. So VmRSS
HAPPENED to track release here. Do not conclude VmRSS is a fine oracle - nothing
guarantees it, and VmHWM (what this project FITS) provably never tracks it.

TRAP for streaming specifically: the residency oracle currently reads the
HOLDER's store. Your change is on the FETCHER side, where the buffer is a plain
Vec<u8> in transport_fetch.rs and NOT in any store - so store residency will not
see it. You need a fetcher-side equivalent (an accounting counter around the
in-flight buffer) or the AC#2 oracle will be vacuous. This is the single most
likely way TASK-62 ships a green-for-the-wrong-reason gate.

ALSO: task-68's peer-side half is closed. holder_send_bytes_uncompressed_nar_per_s
is bytes served / the union of the holder's own serve windows - a real
denominator. It is NOT comparable with task-64's 204 MB/s (that is the fetcher's
end-to-end fetch including bao verify; this is the send side only, measured at
447 MB/s at one serve). And sizeaxis.derived_quantity_independence() is the
mechanical gate: two quoted rates that are one quantity restated have a ratio
with ~zero variance. Run any new derived quantity through it.

## Forward-carried from TASK-61/TASK-72: the supply path you are about to stream through

THE HOLDER SIDE IS NO LONGER A STARTUP SEED. `IrohProvider` now regenerates on
demand: an admission gate (iroh-blobs `RequestMode::InterceptLog`) answers each
get-request BEFORE it is served, materialises the blob via a `NarSupplier`, holds
a `TempTag` for the serve, and releases afterwards. Your streaming change lands
in the FETCHER, but it shares this surface and there are three things you need.

1. THE FETCHER SLOPE IS STILL 1.0156-1.02 B RAM per B NAR and it is still the
   whole-NAR buffer at `transport_fetch.rs fetch(..) -> Result<Vec<u8>>`. TASK-72
   did NOT touch it - measure `size.fetcher_rss_hwm_bytes_ram` before/after with
   the same reduced profile grid task-72 used (see its notes) so the numbers are
   comparable.

2. THE HOLDER PATH ALREADY TAKES ITS Vec BY VALUE. `materialise` calls
   `add_bytes(raw)` with an owned `Vec<u8>`, so the supply path costs ~1x the NAR,
   not 2x. `IrohProvider::seed` still pays the `to_vec` (TASK-46 owns that). Do
   not attribute a holder-slope change to your streaming work without splitting
   those two.

3. STREAMING INTO THE STORE IS THE HARDER HALF, and the reason is the collector.
   `iroh_blobs::api::blobs::add_stream` exists, but the ReleaseAfterServe race
   argument in `StoreRetention`'s docs depends on the hash being known and
   registered in the in-flight table BEFORE the add starts. With a stream you do
   not know the hash until the end. Either keep the digest-first admission (you
   do know it - the peer asked for it by digest) or re-derive the race argument;
   do not silently drop it. A blob swept mid-add is a failed serve, not corruption,
   but it is exactly the flake that is impossible to reproduce later.

4. `STREAM_CHUNK_BYTES` (content_id.rs, 64 KiB) and
   `Blake3Digest::stream_raw_nar` are already there if you need a bounded-memory
   pass over a NAR. The recipe stays in content_id.rs - there is a unit test that
   the streaming and one-shot constructors agree across the chunk boundary.

2026-08-18 dependency audit: TASK-247 cannot honestly measure latency hiding while PeerFabricNarSource constructs the HTTP body only after NarTransfer::fetch has collected the entire NAR. TASK-62 is therefore a correctness/measurement prerequisite for TASK-247, even though its expected total-throughput win remains small.

2026-08-18 dependency correction: TASK-197 is a hard prerequisite for AC#6 on libp2p. /nar/3 authenticates the whole BLAKE3 only at EOF, so releasing libp2p bytes to the HTTP body earlier would not be a verified-chunk stream. Implement and mutation-prove the bao-capable protocol first; iroh already has bao leaves but still needs its Vec seam removed here.

2026-08-19 front-loaded de-risking (no source touched; two data files committed):

AC#8 measurement manifest FROZEN before any streaming measurement:
artifacts/task62-streaming-manifest-v1.json. Integer/rational thresholds + sample
sizes, no float as decision authority (sizeaxis/scalefit float slope-CI flagged as
an implementation obligation to reduce to a rational + cross-multiply, not silently
accepted). Bites: AC#1 TTFB ttfb*4<=total (buffering counterfactual >=3/4 fails; a
flush-at-end unbounded channel fails because first-byte is measured AT THE CLIENT);
AC#2/#7 inflight hwm <= 4*STREAM_CHUNK_BYTES (262144) and size-independent (a
bounded channel that still accumulates O(NarSize) fails); AC#7 permits released
within an injected 2s deadline; AC#5 fetcher RSS slope 95% CI must EXCLUDE 1 and
CI-high < 1/2 over the 5-size grid (single-point unfalsifiable).

AC#3 NIX-retry empirical question answered EARLY and GREEN -> NOT design-blocking.
Ran crash-kill-mid-nar (SIGKILL daemon at ~50% of the 110 MiB NAR): 11/11 checks,
40.0s, exit 0. Build succeeds via fallback; surviving store path NarHash matches
signed upstream (correct, never wrong); no orphaned tmp/lock residue; verify-path
BITES red on an injected corrupt path. Evidence: evidence/task-62/9b71c48/.
CAVEAT (honest): this de-risks the NIX half only -- it kills the DAEMON on the
upstream path, a faithful proxy for "200 + truncated body -> Nix falls back". It
does NOT prove the DAEMON-side truncation streaming introduces (peer dies mid-body,
daemon alive, daemon truncates its own response). That is a to-build mutation
oracle (kill the iroh/libp2p PEER at ~50% of a p2p-served NAR) for AC#3's
implementation half.

SCOPE: the streaming refactor (AC#1,2,4,5,6,7 + AC#3 daemon-side oracle) is NOT
done this session. The irreducible core is a trait-signature change: NarTransfer::fetch
-> Result<Vec<u8>> (peer-fabric/src/capabilities.rs:409) must yield incrementally,
rippling through BOTH adapters (fabric-iroh transport_iroh.rs dial_and_stream collects
a Vec; fabric-libp2p transport.rs collects /nar/4 leaves -- its own comment says "until
TASK-62"), the serve swap at transport_fetch.rs:460 (Full::new(Bytes::from(bytes)) ->
Stream), a NEW fetcher-side inflight accounting counter + its oracle, and the 5-size
RSS grid + e2e. The HTTP body is ALREADY streaming-capable (NarBody = BoxBody, source.rs:56),
so there is no cheap "wire up the body" bite left -- the only remaining work IS the DEEP
core. TASK-197 (bao /nar/4) is Done so libp2p AC#6 is unblocked at the protocol level.
Committing a half version would fake green under the codex integrity gate. GO
recommendation: AC#3's Nix-half holds, design is not blocked, refactor is safe to
pursue against the frozen manifest. No honest partial exists short of the trait change
(any fetch->Vec wrapped in a channel is flush-at-end = exactly the AC#1/#7 anti-pattern).

ORCHESTRATOR VERIFICATION 2026-08-19: AC#3 evidence RE-DERIVED from evidence/task-62/9b71c48/ (not self-report): rawlog 11/11 PASS exit 0 — build succeeds via fallback after SIGKILL at ~50% of the 115343872 B NAR, surviving NarHash matches signed upstream, fallback served full NAR (bytes_sent==file_size), verify-path passes on surviving path AND BITES red on an injected corrupt path. measurement.json records the honest residual (the post-head-truncation-specifically property rests on the code path upstream.rs::fetch_streaming, not a client assertion — a client-side "saw 200 then short body" strengthening is to add with the implementation-half peer-kill scenario). SHOWSTOPPER CLEARED: NOT design-blocking; S2 holds under the new mid-body-abort class. Manifest artifacts/task62-streaming-manifest-v1.json frozen (integer/rational, no float authority; mped added the below-the-counter negative control + the float-CI-must-reduce-to-rational obligation). STATE: this is a de-risking MILESTONE (AC#8 manifest frozen + AC#3 Nix-half GREEN); the streaming REFACTOR (AC#1/#2/#4/#5/#6/#7 — trait fetch->Vec removal rippling through both fabric-iroh + fabric-libp2p adapters, serve swap at transport_fetch.rs:460, fetcher accounting counter+oracle, 5-size RSS grid, e2e) is a GO-recommended DEDICATED multi-session DEEP change against the frozen manifest. TO-BUILD residuals for the refactor: the daemon-side truncation mutation oracle, and reducing sizeaxis/scalefit float CI to the frozen outward-rounded rational.

AC#8 (pre-register the measurement manifest) CLOSED 2026-08-21 (commit 9a5bb8b, LIGHT-gated). The manifest DATA was already frozen (ae68554, artifacts/task62-streaming-manifest-v1.json); what was missing was enforcement - added check-streaming-manifest.py (BLAKE3(JCS) content-hash pin b98c41d7... + presence/type + no-float, wired into just lint as 2 stages), leaving the manifest bytes byte-identical. Anti-post-hoc guard mutation-proven (loosen a threshold after results -> hash drift -> fail-closed; 9 bites + controls). Frozen thresholds: AC#1 TTFB/total pass_ratio 1/4 (buffering bite 3/4); AC#2/7 inflight 262144 bytes + size-independence 5/4; AC#7 cancellation 2000000000 ns; AC#5 RSS-slope CI-high < 1/2 (grounded in TASK-65's >=5-size fitted slope); AC#4 both framings; A/A band 1/20, >=5 RSS grid + >=3 TTFB repeats. Prediction recorded: wall-clock UNCHANGED (~0.55s, NOT a latency win), RSS decouples, TTFB drops. STREAMING ACs #1-#7 remain open - the refactor must be MEASURED against this frozen manifest (its float-CI reduction to rational is an obligation on that measurement gate). just lint 19/19 orchestrator-re-derived.

inc1 landed (commit a4594c4, LIGHT gate green) — DE-RISKING FOUNDATION ONLY; NO AC fully landed and the serve seam is NOT flipped. Master serve path unchanged.

Committed (3 files): peer-fabric/src/stream.rs (InflightMeter, integer bytes; MAX_INFLIGHT_FETCH_BYTES_RAM = 4*STREAM_CHUNK_BYTES = 262144, tied to the frozen manifest); peer-fabric/src/lib.rs exports; fabric-libp2p/src/nar.rs (read_nar_header factored as the single pre-body gate, the production collector read_response_streamed_since reimplemented on it behaviour-preserving; plus cfg(test) open_nar_response_stream + MeteredNarStream + 4 mutation-proven oracles).

Gate: clippy -p peer-fabric -p fabric-libp2p --all-targets -D warnings exit 0; peer-fabric 144 pass; fabric-libp2p 169 pass (52 pre-existing nar tests preserved); cargo check --workspace 0 errors. AC#3 truncation oracle bites by mutation at the READER (suppress terminal-error emission -> RED), NOT e2e.

WHY the seam was NOT flipped (honest, correct call): AC#6 is inseparable from the AC#3 build-survives-peer-abort e2e, which was not driven to green this session. Shipping the streaming seam without that e2e is the exact build-breaking hazard the task forbids (loses the invisible fallback). A standalone streaming reader is dead code under -D warnings, so it is deliberately cfg(test) design-validation, not production.

Per-AC: #1 mechanism only (reader prefix-before-whole proven; HTTP-client ttfb*4<=total oracle + buffering counterfactual NOT built). #3 mechanism only (reader terminal-error-on-truncation mutation-proven; the PRD additive invariant e2e UNPROVEN). #6 NOT landed. #4 NOT landed (declared_size plumbed). #7 mechanism proven at the test reader (hwm<=262144, size-independent, current==0 at EOF, Drop aborts producer) — NOT on shipped path. #8 pre-existing, thresholds honoured.

inc2 remaining (exact seams, in order):
1. AC#6: add NarStream/NarChunkSource to peer-fabric; flip peer-fabric/src/capabilities.rs:409 (fetch -> stream); promote open_nar_response_stream (drop cfg(test)); swarm streaming entry over the owned substream from fabric-libp2p/src/swarm.rs:1414 (open_stream_on_connection); update fabric-libp2p/src/transport.rs:61, fabric-iroh/src/transport_iroh.rs:2774/2954 (iroh raw.extend loop is symmetric), peer-fabric/src/fake.rs, ~15 mechanical .collect() test callers, daemon/src/transport_iroh_bridge.rs collect.
2. AC#4: daemon-core/src/peer_source.rs:220 consume stream -> NarBody; Content-Length from signed NarSize (correlated) vs chunked (cold-start None).
3. AC#1 e2e: TTFB at HTTP client + buffering mutation.
4. AC#3 e2e (MERGE GATE — seam must NOT merge until green): new peer-kill-mid-stream scenario (model on s9-libp2p + scenario_crash_kill_mid_nar _kill_daemon_at_bytes in scripts/e2e_harness.py); build STILL succeeds via fallback, store path absent-or-correct never wrong.
5. AC#2/#5: real RSS-under-slow-reader + slope CI (the unit meter is necessary not sufficient — must confirm the meter observes the load-bearing buffer once hyper body-buffering is in the path).

inc2 landed (commit 0ac6832, LIGHT gate green) — AC#3 MERGE-GATE e2e scenario, harness-only, seam still NOT flipped.

New e2e scenario 'libp2p-peer-kill-mid-nar' (scripts/e2e_harness.py, +318): s8 store-supply topology; A holds the 110MiB 'big' NAR, B (told only BOOT) peer-fetches it, A is SIGKILLed mid-serve, B STILL builds correctly (NarHash==signed, absent-or-correct never wrong), invisible S2 fallback fold proven, non-vacuity proven (B discovered A then failover, not empty-index miss). 17/17 PASS 31.4s against a HEAD-behavior image. Run: just e2e-full (or --only libp2p-peer-kill-mid-nar); NOT in the fast loop (heavy).

HONEST LIMITS: survives TRIVIALLY on buffering via the invisible fallback; the STRONG property (survival via Nix cross-substituter retry after a client-visible partial) bites ONLY once inc3 flips the seam — THIS scenario re-run is inc3's merge gate. ~50% kill is not byte-precise on buffering (no fetcher byte-gauge); inc3 must fire at 50% of peer-fabric InflightMeter bytes.

AC#1 client-TTFB oracle: BLOCKED/not landed. Exact remaining: new scenario with a raw-socket HTTP client (reuse _raw_read_response) GET B:/nar/<big-narhash> through PeerFabricNarSource (Content-Length path, transport_fetch.rs:481) while B peer-fetches from A; timestamp request->first-byte (ttfb_ns) and ->last-byte (total_ns); assert manifest buffering counterfactual integer-compare ttfb*4>=total*3 (buffering_bite_ratio 3/4, no floats) as the RED-now proof it bites; flip to ttfb*4<=total at the inc3 seam flip.

TWO PRE-EXISTING HEAD BLOCKERS the inc2 run surfaced, both FIXED by orchestrator (not the implementer):
1. just lint RED (rustfmt on nar.rs/peer-fabric-lib.rs from inc1 a4594c4 — inc1 gate was clippy-only) -> fixed commit 1551bb9.
2. just e2e RED since TASK-168 (5567569) landed: its Disclosed::QueriedNodeId disclosure changed the locate accounting (hit=miss+2 not +1) and tripped the libp2p_production_path.rs oracle, which runs in the e2e image checkPhase; 168 updated its own per-crate test but missed this cross-cutting daemon oracle -> fixed commit c046bb1. just e2e now exit 0 (validated).

inc3 (the seam flip) remains — gated by the 'libp2p-peer-kill-mid-nar' scenario staying green post-flip. Keep AC#1/#3/#7 rigorous; do NOT gold-plate AC#5 RSS-slope (modest 1.23x property; 62 gates only Low 44/52).
<!-- SECTION:NOTES:END -->
