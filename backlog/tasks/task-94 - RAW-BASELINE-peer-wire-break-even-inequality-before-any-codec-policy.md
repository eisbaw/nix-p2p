---
id: TASK-94
title: 'RAW BASELINE: peer-wire break-even inequality before any codec policy'
status: Done
assignee:
  - '@mped'
created_date: '2026-08-10 08:43'
updated_date: '2026-08-14 06:36'
labels:
  - wave-2b
dependencies:
  - TASK-64
  - TASK-70
  - TASK-114
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Establish the raw/uncompressed peer-wire economics used by Stage A. Measure cache.nixos.org FileSize/NarSize over a reproducible signed-path sample, measure raw peer socket throughput under validated controlled link conditions, and compute the break-even inequality without smuggling compression or policy conclusions into the result. This is diagnostic evidence: raw WAN losing at every size is a valid outcome, but it cannot decide the compressed Stage-B policy. Compression implementation and re-evaluation belong to TASK-99.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 FileSize/NarSize is measured over at least 200 cache.nixos.org-signed paths spanning all size deciles, with Compression recorded; an uncompressed fixture sample is classified and excluded from the compressed-upstream aggregate.
- [x] #2 Raw peer socket throughput is measured at at least three NAR sizes under TASK-70's externally verified link profiles; loopback results are labelled loopback and the harness refuses to label them WAN.
- [x] #3 The report computes the break-even size from measured ratio, upstream bandwidth, peer bandwidth and discovery/dial latency; when the denominator is non-positive it prints NO SIZE THRESHOLD EXISTS, proven by a pinned negative-denominator bite.
- [x] #4 Wire bytes, uncompressed NarSize, discovery/control bytes and protocol overhead stay in distinct fields, and provider-side counters plus shaping controls make each arm non-vacuous.
- [x] #5 The artifact is structurally tagged diagnostic_uncompressed and cannot select a production policy; TASK-99 owns codec implementation and the compressed re-evaluation.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
IMPL PLAN + DEP-GUARD (task-94, In Progress)

DEP-GUARD CONFIRMED = NO. task-94 does NOT route bytes through net-upstream-egress-v2/v3.
Evidence: measure.classify_run(records, url_sizes, delivered_by_url, stats_bytes_sent,
client_exit, wall_s) consumes the TESTPROXY per-request log + stats endpoint for the
daemon-on/off arms. task-94 produces none of those inputs: it fetches cache.nixos.org
narinfo METADATA over HTTP (FileSize/NarSize/Compression) and runs a raw TCP transfer
over a tc-netem-shaped netns link (scripts/shaped_link.py), then does arithmetic. No
testproxy, no classify_run, no hedge/winner accounting. => task-52 dep correctly pruned;
proceeding without re-adding it.

DELIVERABLE: scripts/peer_wire_baseline.py (mirrors measure.py/shaped_link.py discipline:
one script, --self-test proving every oracle bites by mutation).
 AC#1 real cache.nixos.org narinfo BFS over closure References (metadata only, no NARs),
      >=200 signed compressed paths; Compression:none classified + EXCLUDED from the
      compressed aggregate (project fixtures manifest supplies deliberate none entries);
      per-decile ratios + span gate (refuses a narrow-band sample -> the prior 0.278 flaw).
 AC#2 raw peer socket throughput at 3 NAR sizes over shaped_link.py's netns+tc primitive;
      loopback labelled loopback; assert_link_label REFUSES a wan_shaped label on a
      loopback/unshaped run (red-green bitten).
 AC#3 break_even(): denom = ratio/B_up - 1/B_peer (sec saved per NAR byte); denom<=0 ->
      NO SIZE THRESHOLD EXISTS (red-green bitten). Break-even needs B_peer > B_up/ratio
      (~75 MB/s for ratio 0.278, 21 MB/s CDN).
 AC#4 distinct unit-suffixed fields (_bytes_compressed_wire / _bytes_uncompressed_nar /
      _bytes_control); unit_violations gate + self-test bite.
 AC#5 diagnostic_uncompressed tag + assert_cannot_select_policy (bitten).

GATE so far: ruff check + format clean; py_compile OK; --self-test OK; 3 mutations
(neg-denominator, loopback-label, compression-exclusion) each proven RED then reverted.
Real cache sample + shaped-link runs in progress.

RESULTS (measured 2026-08-14, nix-shell):
 AC#1: 220 cache.nixos.org-signed COMPRESSED paths, closure BFS from gcc/python3/ffmpeg/git
   (nixpkgs rev 044bfe75), metadata-only (no NARs, 0 drops). Aggregate FileSize/NarSize=
   0.3256 (byte-weighted) => peer moves 3.07x the CDN wire bytes; per-path median 0.340.
   NarSize 4968 B .. 277 MB (55,805x span), all 10 deciles populated (22 paths each).
   Per-decile ratio stable 0.30-0.43 => compression is NOT a big-file artifact. 2
   Compression:none fixtures classified + EXCLUDED. NOTE: the wider decile-spanning
   sample gives 3.07x, LOWER than the legacy 3.6x/0.278 which was taken over 20 large
   (>10 MiB) paths only -- the honest broad number is the point of this task.
 AC#2: raw TCP over shaped_link.py netns+tc (100mbit/20ms): 8/20/40 MiB -> 9.2/10.7/11.3
   MB/s shaped (RTT ~48ms), loopback control ~45-61 Gbit @ 0.05ms; every shaped arm earned
   wan_shaped only after assert_shaping fired; loopback arm REFUSED wan_shaped (bitten).
 AC#3: peer must sustain >67.6 MB/s (=CDN 21MB/s / ratio 0.3256) to break even. home
   uplink 5 MB/s and the measured shaped peer ~11 MB/s => NO SIZE THRESHOLD EXISTS (raw
   WAN loses at every size, expected). 125 MB/s LAN peer => break-even at 21 MB NarSize.
 AC#4: distinct unit-suffixed fields (_bytes_compressed_wire / _bytes_uncompressed_nar /
   _bytes_control); unit_violations gate clean on the real merged report.
 AC#5: report tagged diagnostic_uncompressed; assert_cannot_select_policy passes; no
   policy field. finalize() PASSED end-to-end on the merged real report.

RED-GREEN proof: 3 mutations (neg-denominator guard, loopback-label refusal, compression
exclusion) each driven RED via sed then reverted; self-test green after. ruff check+format
clean, py_compile OK. Shared-box: no orphan netns/procs after shaped runs (verified).

GOTCHA fed forward: the 3.6x/0.278 legacy asymmetry is a NARROW-SAMPLE artifact (large
paths only). The honest decile-spanning ratio is ~0.326 (3.07x). Anyone re-deriving the
"peer must sustain X MB/s" threshold must use the broad ratio, not 0.278, or they overstate
the peer deficit by ~18%.

DEEP GATE 2026-08-14 = NO-GO for Done (qa GO / mped GO-WITH-FIXES / codex NO-GO-as-canonical; NOT a store-integrity issue — TASK-94 ships no bytes). The numbers are CONFIRMED reproducible (codex independently got ratio 0.3255628680, 3.07x, shaped 9.2/10.7/11.3 MB/s; raw peer loses at every size in the measured latency quadrant). But the ARTIFACT is not yet an acceptable canonical baseline for TASK-99/198. Unticked AC#1/#3/#4 pending the fix cycle. Fix set (dispatched to a fresh implementer): (1) BLOCKER re-derivability — the report/--json-out must RETAIN per-path records (store_hash,Compression,FileSize,NarSize,Sig) and a finalizer must recompute every aggregate from them; commit the raw sample under evidence/task-94/<rev>/; (2) reframe the headline — codex's rerun shows the current >10MiB subset aggregates to 0.324 not 0.278 and the legacy cohort was xz vs current all-zstd, so '0.326 corrects the size-only 0.278' is codec/cohort-confounded and unsupported: state it as 'a broader current zstd seed-closure convenience sample estimates 0.3256', not a population ratio nor a correction; fix docstrings :19/:225/:555 that still assert the legacy 3.6x/0.278 as present fact; drop 'all 10 deciles populated' as a strength (post-hoc equal-count cut is near-tautological; the span gate does the real work); (3) FAIL-CLOSED admission — enforce/count 'signed', don't classify unknown-compression as compressed, and make a failed sample_gate exit nonzero with NO published aggregate (self-test must prove the CLI refuses to publish, not just that sample_gate returns nonempty); (4) fix break_even() denom<=0: when numer<0 (discovery<cdn latency) the peer wins at every size (denom==0) or below an upper crossover (denom<0) — handle the numer sign; add oracle cases for the other latency quadrants; (5) MiB/MB consistency on the 21/5/125 constants + the 67.6 headline; add inline provenance (source: profile_p2p/task-35) + emit assumed_not_measured_here:true on scenario inputs; (6) shaped_link_xfer.py receiver must check got==expect before acking (a truncated transfer currently reports success) and shaped_link.py must verify RECV_DONE bytes==expect — strengthens AC#4 non-vacuity (also improves TASK-70's primitive); (7) WARN when zero Compression:none fixtures found (load_fixture_uncompressed silent-empty); (8) soften diagnostic_uncompressed / assert_cannot_select_policy docstring — it's a producer-side tripwire, not a barrier against downstream derivation.

DEEP-GATE FIX CYCLE (fresh implementer, 2026-08-14) — PLAN
Applying the 8-point fix set. Conclusion (raw peer loses at every size in measured quadrant) STANDS; making the artifact re-derivable, the claim honestly framed, gates fail-closed.
 F1 BLOCKER re-derivability: retain per-path records (store_hash,name,Compression,FileSize,NarSize,Sig,signed,classification) in the aggregate; independent verify_rederivable() recomputes sum_file/sum_nar/ratio/deciles from records + asserts match (RederivationError bite). --verify-artifact CLI reloads committed JSON + re-derives headline. Commit real >=200 sample + shaped log under evidence/task-94/<rev>/.
 F2 reframe: 0.3256 = broad current zstd seed-closure convenience-sample ESTIMATE, not a population ratio, not a correction of legacy xz 0.278 (codec/cohort-confounded). Fix docstrings :19/:225/:555. Drop 'deciles populated' as a strength; credit span gate.
 F3 fail-closed: admission=compressed(known codec)+signed; unknown/missing compression -> own bucket (excluded); failed sample_gate raises SampleGateError -> main exits nonzero, NO published aggregate; self-test proves the pipeline REFUSES to publish.
 F4 break_even quadrants: denom<=0 branch handle numer sign (denom==0&numer<0 -> peer wins every size; denom<0&numer<0 -> peer wins BELOW upper crossover). Pin new oracle cases.
 F5 MiB/MB: constants are MiB/s; relabel scenarios *MiBps, headline in MiB/s; inline provenance (profile_p2p/task-35, ASSUMED) + assumed_not_measured_here on scenario inputs.
 F6 shaped receiver counter: xfer recv checks got==expect (ack 'E'/short on mismatch); parse RECV_DONE; run_arm asserts recv_bytes==total. Re-run shaped_link --self-test.
 F7 load_fixture_uncompressed WARN on missing manifest / zero none-fixtures.
 F8 soften diagnostic_uncompressed docstring: producer-side tripwire, not a barrier against downstream derivation.

DEEP-GATE FIX CYCLE — DONE (2026-08-14). Code @ 17db75e, evidence @ 65a6e91.
All 8 fixes landed; conclusion UNCHANGED (raw peer loses at every size in the measured quadrant).

RE-DERIVED headline (from committed records, NOT self-reported):
  evidence/task-94/17db75e/sample.json -> FileSize/NarSize = 0.3255628680152017 (3.0716x)
  reproduce: python3 scripts/peer_wire_baseline.py --verify-artifact evidence/task-94/17db75e/sample.json
  Matches codex's independent 0.3255628680. 220 admitted (signed+known-codec) paths; 2 Compression:none excluded; 0 unknown / 0 unsigned; NarSize span ~55806x, all deciles populated.

Shaped arm (100mbit/20ms): 8/20/40 MiB -> 73.9/85.6/90.3 mbit, RTT ~48ms; loopback control ~38 Gbit @ 0.1ms; sender(SEND_DONE)+receiver(RECV_DONE status=ok) counters in the committed transcripts, delivered==expected every size. No netns leak (ip netns list empty post-run).

Break-even: home-uplink 5 MiBps and the MEASURED shaped peer both -> NO SIZE THRESHOLD EXISTS; 125 MiBps LAN peer -> BREAK-EVEN ABOVE THRESHOLD. CDN/peer bw ASSUMED (profile_p2p/task-35), flagged assumed_not_measured_here per scenario.

GATE (bounded, nix develop): peer_wire --self-test PASS (10 oracles incl new re-derivability/fail-closed/quadrant); shaped_link --self-test PASS (6 mut + 4 trunc + delivery-counter); ruff check clean; ruff format --check clean; py_compile OK; just independence GREEN. New oracles proven RED-under-mutation (monkeypatch demo): quadrant-collapse, rederive-noop, fail-open-publish, unknown-as-compressed, delivery-noop each turn the self-test RED.

Re-ticked AC#1 (>=200 signed, re-derivable artifact committed, uncompressed excluded), AC#3 (break-even correct across quadrants + pinned bites), AC#4 (distinct unit fields + non-vacuous provider+receiver counters). AC#2/#5 unchanged.

HONEST LIMITS / gotchas fed forward:
 - 0.3256 is a CONVENIENCE-SAMPLE estimate (BFS from 4 seeds), NOT a population ratio; do not compare to legacy xz 0.278 (codec+cohort confounded).
 - break-even bandwidths/latencies are ASSUMED, not re-measured here; only the shaped peer bw is measured (over an EMULATED link: mean RTT + rate cap, no loss/jitter/NAT — see shaped_link HONEST_LIMITS).
 - unknown-codec classification uses a KNOWN-codec allowlist {xz,zstd,bzip2,gzip,br,lzip,lz4}; a real future codec outside it would be conservatively excluded+counted (fail-closed), not silently folded in.

RE-GATE 2026-08-14 = NO-GO (2nd, codex). F2/F4-algebra/F6/F7/F8 RESOLVED. Remaining, 2nd fix cycle: (F1 BLOCKER, codex proved by mutation that finalize() PUBLISHED all of: 1-byte NarSize-sum drift [integer sums compared with a relative FLOAT tolerance], NaN in stored ratio / decile ratio / record FileSize [non-finite not rejected -> classic fail-open], decile n=999 / false decile min / changed decile index [decile verify compares only ratio, ignores index/n/min/max], exclusion-count 999 [n_uncompressed_excluded / n_unknown_compression_excluded / n_unsigned_excluded / n_records_total not verified], stored signed/classification not re-derived from raw sig/compression, and finalize() SILENTLY SKIPS verify when sample['aggregate'] is not a dict). FIX: verify_rederivable must recompute and STRICTLY compare EVERY aggregate incl. all exclusion counts + n_records_total + FULL decile fields (index,n,min,max,ratio); re-derive signed/classification from raw; REJECT non-finite (NaN/inf) explicitly; compare integer sums with EXACT integer equality (no float tolerance); finalize() must fail-CLOSED - raise (not skip) on missing/non-dict aggregate. DEFINITION OF DONE FOR THIS CYCLE: add a pinned self-test mutation case for EACH mutation codex accepted (1-byte drift, ratio NaN, decile NaN, FileSize NaN, decile n=999, false decile min, changed decile index, exclusion-count 999, gate_passed:false+valid aggregate, failed-gate-block-without-aggregate) and each MUST turn verify/finalize RED. (F3) finalize() must inspect gate_passed/gate_violations and refuse a failed/absent-gate report; self-test must prove the CLI/finalize path refuses to publish (not just build_sample_block); --verify-artifact must also re-run sample_gate (canonical admission). (F5) make assumed_not_measured_here honest per-input (measured-shaped: peer_bw measured, up_bw+latencies assumed) and fix the units string. (F4 minor) pin numer==0 and denom==0&&numer>=0 oracle cases; fix denom==0&&numer==0 interpretation to 'ties at every size' not 'loses'. Then REGENERATE the committed evidence artifact (fresh live sample; number will shift slightly, expected). Scope notes to state explicitly (not overclaim): 'signed'=nonempty Sig (not crypto verification); the verifier shares _aggregate_from_records (strictness + mutation-bites compensate; a fully independent 2nd impl is out of scope for a diagnostic).

RE-GATE 2nd NO-GO CLOSED (2026-08-14). Code @ cdf5c3a, evidence @ ec6fbe3 (evidence/task-94/cdf5c3a/sample.json; stale 17db75e removed).

ROOT-CAUSE fix (owner steer 'what do we need floats for?'): verify_rederivable is now a NO-FLOAT trust path. Every integrity quantity is an INTEGER (FileSize/NarSize, sums, ALL exclusion counts, n_records_total, each decile index/n/min/max) recomputed from raw records and compared EXACT ==. Display ratios are derived from those integers and asserted exactly == the re-derived value (NaN/None/doctored float fails != for free). No tolerance anywhere; NaN unrepresentable in an integer field -> the class codex broke cannot exist. signed/classification re-derived from raw sig/compression and must match stored.

finalize() FAIL-CLOSED: raises (never skips) on missing/non-dict aggregate and on gate_passed!=true/absent gate. --verify-artifact now also re-runs sample_gate (canonical admission).

11 PINNED mutations in --self-test, each proven RED when its guard is reverted (monkeypatch demo: verify no-op -> #1-8/#11 RED; old fail-open finalize -> #9/#10 RED). BEFORE (original committed code, run against real evidence/task-94/17db75e): 10/11 ACCEPTED (only record-FileSize-NaN rejected, and only incidentally via a median shift). AFTER: 11/11 REJECTED with named causes.
 1 sum_nar +1B; 2 aggregate ratio NaN; 3 decile ratio NaN; 4 record FileSize NaN; 5 decile n=999; 6 false decile min; 7 changed decile index; 8 exclusion counts=999 (all 4: uncompressed/unknown/unsigned/total); 9 valid aggregate + gate_passed:false; 10 failed-gate block w/o aggregate; 11 stored signed/classification lying vs raw.

F5: assumed_not_measured_here honest per-input (true for every scenario; per-input map marks only peer_bw measured on the shaped scenario); units string no longer claims the measured peer bw is a MiB/s constant (it derives from decimal Mbit/s, x1e6/8).
F4: denom==0&numer==0 now TIES at every size (draw, not loss); pinned numer==0 and denom==0&numer>=0 oracle cases.

REGEN: fresh live seed-closure sample under corrected finalizer. BFS is deterministic vs the pinned nixpkgs registry so it reproduced the prior snapshot EXACTLY (not a slight shift): FileSize/NarSize=0.3255628680 (3.0716x), 220 admitted, 2 none-excluded, 0 unknown/0 unsigned; shaped 8/20/40 MiB -> 73.9/85.6/90.3 mbit; no netns leak. verify-artifact re-derives from raw + re-runs sample_gate -> rc=0.

GATE (bounded, nix develop): peer --self-test / shaped_link --self-test / ruff check / ruff format --check / py_compile / just independence / --verify-artifact all rc=0. netns empty, disk 84G free.

CONCLUSION UNCHANGED: raw peer loses at every size in the measured quadrant (home_uplink 5MiBps and measured shaped peer -> NO SIZE THRESHOLD EXISTS; assumed 125MiBps LAN peer -> break-even above threshold).

SCOPE (honest, not overclaimed): 'signed'=nonempty Sig field, NOT crypto signature verification. The verifier shares _aggregate_from_records with the producer; a fully independent 2nd impl is out of scope for a diagnostic -- the integer-exact strictness + the 11 mutation-bites are the assurance. Residual naming smell (nar_size_span_orders_of_magnitude holds a linear multiple) tracked separately as TASK-199.

AC#1/#3/#4 genuinely met and remain ticked.

RE-GATE 2026-08-14 = codex NO-GO (3rd), ARBITRATED DOWN. codex CONFIRMED the core is fixed: numbers auditable + deterministically reproducible (BFS deterministic vs pinned nixpkgs), integer-exact re-derivation closed the NaN/drift class, quadrant algebra + receiver counter + headline framing all sound, committed artifact clean. codex-3's NEW findings are a NARROWER class — tamper-resistance of a diagnostic artifact + one boundary-float — above the bar for a task that ships no wire bytes / freezes no surface / whose artifact is machine-generated from real narinfo. Per the PRD threat model (store-path integrity is Nix's job; a measurement artifact is not a security surface) I arbitrate the NO-GO to NOT block Done as a class. BUT the concrete sub-findings are cheap and two touch claims 94 makes, so FINAL hardening cycle: (a) validate positivity — every FileSize/NarSize must be a positive int; (b) uniqueness gate — admitted store_hashes must be unique (a duplicate must not inflate the path count); (c) exact-type checks — 'signed'/'gate_passed' compared by EXACT bool (is True / isinstance bool), not truthiness (string 'false' / int 1 must be rejected); (d) finalize must require gate_passed is True AND gate_violations empty (reject truthy-nonbool + nonempty-violations-with-passing-gate); (e) INTEGER span gate — replace the float max/min span with an integer comparison (max_nar >= min_nar * min_span_int) so there is genuinely no float in the admission trust path, and RENAME the field (fold + CLOSE TASK-199: nar_size_span_orders_of_magnitude holds a linear multiple). Add a pinned self-test mutation for each of (a)-(d) + the span boundary; each must bite RED. Regenerate the evidence artifact. Correct any 'no float in trust path' wording that is now literally true only after (e). This is the FINAL cycle — orchestrator re-verifies codex-3's mutations directly, no 4th codex gate.

FINAL HARDENING CYCLE — DONE (2026-08-14). Code @ 59e7d3b, evidence @ e03ed53 (evidence/task-94/59e7d3b/sample.json; stale cdf5c3a removed). Conclusion UNCHANGED: raw peer loses at every size in the measured quadrant.

codex-3's arbitrated-down sub-findings all fixed; EACH has a pinned self-test mutation that is REJECTED after the fix and ACCEPTED once its specific guard is monkeypatch-reverted (proving the guard, not an unrelated check, is what bites):
 (a) POSITIVITY — _require_int_field now rejects zero/negative FileSize/NarSize. BEFORE: a negative record FileSize with a re-generated (internally consistent) summary re-derived clean (exact sums matched the doctored record). AFTER: rejected fail-closed ('byte counts must be POSITIVE').
 (b) UNIQUENESS — _require_unique_admitted rejects duplicate admitted store_hashes. BEFORE: 199 unique + 1 duplicate reported n_compressed=200 and passed. AFTER: rejected ('duplicate admitted store_hash ... inflates n_compressed').
 (c) EXACT-TYPE signed — _stored_bool_matches requires isinstance(bool) AND is. BEFORE (truthiness): signed=1 / "false" / "true" all agreed with re-derived True. AFTER: all three rejected ('must be an EXACT bool').
 (d) GATE CONSISTENCY in finalize — _assert_gate_block_publishable requires gate_passed IS True AND empty gate_violations. BEFORE (decisive blocker): a truthy-non-bool gate_passed (1 / "true") published, and a passing gate carrying nonempty gate_violations published (violations never inspected). AFTER: all refused.
 (e) INTEGER span gate + CLOSES TASK-199 — sample_gate span is now max_nar >= min_nar * MIN_SPAN_MULTIPLE (pure int; --min-span is int). BEFORE (float max/min): the boundary max=min*10000-1 with min=2**41 rounds to 10000.0 and passed. AFTER: rejected exactly; a sample AT the bar still passes (no false-positive). Field renamed nar_size_span_orders_of_magnitude -> nar_size_span_multiple, plus a true nar_size_span_log10.

WORDING: the module docstring now states accurately (only literally true after (e)) that NO float is on the integrity/admission trust path — integrity re-derivation, positivity, uniqueness, exact-bool and the span gate are all integer/exact; floats live ONLY in display/analysis outputs (displayed ratio, span multiple/log10, break-even threshold, throughput).

RE-DERIVED headline (from committed records, --verify-artifact, rc=0): FileSize/NarSize = 0.3255628680152017 (3.0716x); 220 admitted signed+compressed, 2 Compression:none excluded, 0 unknown / 0 unsigned; NarSize 4968 B .. 277242232 B (span_multiple 55805.6, span_log10 4.75). Seed-closure BFS is deterministic vs the pinned nixpkgs registry so it reproduced the prior snapshot EXACTLY.

BOUNDED GATE (nix develop, all rc=0): peer_wire --self-test (all prior 11 tamper mutations + new (a)-(e), each RED-under-reverted-guard); shaped_link --self-test (6 mut + 4 trunc + delivery-counter); ruff check clean; ruff format --check clean (30 files); py_compile OK; just independence GREEN; --verify-artifact rc=0. No netns leak; disk ~84G free.

AC#1/#3/#4 genuinely met and remain ticked; AC#2/#5 unchanged. This was the FINAL cycle (orchestrator re-verified codex-3's mutations directly; no 4th codex gate). TASK-199 closed here.

DONE 2026-08-14. Value-thesis raw break-even baseline is auditable, deterministically reproducible, integer-exact re-derivable, fail-closed, and honestly framed. Final GO after 3 codex DEEP gates (2 real NO-GOs closed at root: re-derivability + fail-open finalizer; 3rd NO-GO arbitrated down as tamper-resistance above the diagnostic bar, sub-findings still fixed). Independently re-verified by the orchestrator: signed-string + duplicate-record + NaN + sum-drift mutations all bite; positivity/uniqueness/integer-span/gate-consistency guards static-confirmed; baseline re-derives to 0.3255628680 (3.0716x) from committed records. CONCLUSION (stands, not policy): raw peer moves ~3.07x the CDN's compressed wire bytes; peer must sustain >64.5 MiB/s to break even; measured shaped peer ~10.8 MiB/s and home uplink 5 MiB/s -> NO SIZE THRESHOLD EXISTS (raw WAN loses at every size). This is the diagnostic_uncompressed baseline; TASK-99 (link compression) is the fix and re-measures against it; TASK-198 re-states the speedup through a shaped link. Artifact: evidence/task-94/59e7d3b/sample.json. Scope: 'signed'=nonempty Sig (not crypto); verifier shares producer aggregation fn (strictness + mutation battery are the assurance).
<!-- SECTION:NOTES:END -->
