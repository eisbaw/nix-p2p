# Measurement counting rule (task-9) — the cross-wave comparison basis

**Status: comparison basis (kill criterion DESCOPED by owner, 2026-08-08).**
Originally this was the irreversible freeze for a `<20%` GO/NO-GO kill
criterion; the owner has since directed that the project proceeds to the p2p
wave regardless of the measurement outcome, so this definition is no longer a
project gate. It remains the **stable comparison basis**: the wave-1 baseline
(task-12) and any later p2p offload numbers are only comparable if they mean the
same thing by "net upstream egress", so keep the definition and the version
string stable and record them in every report. Changing the definition doesn't
kill anything now, but it silently breaks cross-wave comparison — so still bump
the version rather than adjusting a definition in place. (Historical PRD
reference: the retired kill criterion was *"<20% net cache-egress cut on the
favorable testbed kills the p2p thesis"*.)

The measurement instrument is `scripts/measure.py` (`just measure`); it emits a
machine-readable JSON report whose `counting_rule` block quotes this file's
version and the definition below.

Counting-rule version: **`net-upstream-egress-v1`**.

---

## 1. The boundary and the ground truth

Topology under measurement (task-5 Pod seam):

```
  daemon-on arm:   client(real nix) ── daemon ── testproxy ── mock-origin
  daemon-off arm:  client(real nix) ─────────────testproxy ── mock-origin
```

The **testproxy is the cache-egress boundary**. It is the stand-in for the
authoritative upstream cache (cache.nixos.org). The quantity the p2p thesis
must reduce is *the bytes that cross this boundary toward the client side* —
because when a peer serves a payload instead, the daemon never requests it from
the testproxy and those bytes never cross.

**Ground truth = the testproxy's own byte counters.** Specifically, each served
request appends one `Record` (see `testproxy/src/record.rs`) whose `bytes_sent`
field is *"body bytes actually written to the client"*. Net upstream egress for
an arm is derived from these records. The counters are computed from the append-
only request log on demand (`Log::stats`), so the stats endpoint and the raw log
can never disagree.

**Explicitly NOT ground truth:**

- **The daemon's self-reported counters.** The daemon emits one
  `daemon: substituted path=… bytes=… duration_ms=…` line per served NAR
  (`daemon/src/server.rs::log_substitution`). This is *narration*, and it is
  *measured against* the testproxy — never substituted for it. See §6.
- **The client's view** (`nix path-info`, download progress). The client sits
  downstream of the daemon; its view includes decompression and local-store
  effects that are not egress.

---

## 2. What "net upstream egress" INCLUDES

`net_upstream_egress_bytes` for an arm = the sum of `bytes_sent` over every
**valid** served-response record in that arm (see §4 for validity), across all
`N` runs unless a per-run figure is named.

**The offload comparison metric is PAYLOAD (NAR) egress, not total egress.** The
project's go/no-go (PRD: `<20%` net cache-egress cut) is evaluated on
`egress_payload_nar_bytes` — the NAR body bytes crossing the boundary — because
(a) that is precisely what p2p offloads, and (b) it is **symmetric across the
two arms** and cannot be moved by anything other than real offload. Total egress
and each metadata channel (narinfo, cache-info) are reported as **context**, not
the decision metric. Two consequences are frozen here:

- The daemon serves `nix-cache-info` **locally**, so the daemon-on arm shows near-
  zero `cache-info` egress at the boundary while the daemon-off arm fetches it
  every run. Measuring offload on *total* egress would therefore credit
  the daemon a small fixed "offload" for absorbing metadata — a definitional
  artifact, not offload. Measuring on payload egress removes it.
- The daemon narinfo cache (task-8, `--narinfo-cache-dir`) reduces *narinfo*
  egress with **zero peers** (the product-side bite in §measure proves exactly
  this). If the comparison metric were total egress, enabling that cache could push a
  marginal result over the 20% bar via metadata, not p2p. **Frozen rule: the
  daemon's narinfo-cache and cache-info handling are held IDENTICAL across the
  daemon-on and daemon-off arms**, and the decision metric is payload egress, so
  metadata configuration cannot move the go/no-go number.

| Included | Rule |
|---|---|
| **Response BODIES** | Yes. `bytes_sent` is body bytes written to the socket. |
| **Response HEADERS** | **No.** Headers are not in `bytes_sent`. Egress is a body-byte figure by definition; header overhead is a fixed per-request framing cost that does not scale with payload and is out of scope for the offload comparison. |
| **NAR bytes** | Yes. Reported as `nar` and summed into the total. |
| **narinfo bytes** | Yes. Reported as `narinfo` and summed into the total. The product-side bite (task-8 narinfo cache) moves precisely this figure. |
| **`nix-cache-info` bytes** | Yes, counted into the total, reported as `cache_info`. Tiny and constant; kept in the total so "total egress" is literally every body byte the boundary emitted. |
| **Compressed WIRE bytes** | The figure is **compressed on-wire bytes** — the `FileSize`/`bytes_sent` a NAR occupies crossing the boundary. It is **NEVER `NarSize`** (the uncompressed serialized size). For the fixture set: `lib`/`big` are `Compression: none` so wire == disk == NarSize; `app` (xz) and `zstd` cross at their *compressed* `file_size`, which is smaller than their `nar_size`. `fixtures/out/current/manifest.json` carries both per path; the counting rule reads `file_size`. |

## 3. What "net upstream egress" EXCLUDES

| Excluded | Rule and rationale |
|---|---|
| **Truncated transfers (wave 1)** | A NAR record with `0 < bytes_sent < file_size` (a short body under a full `Content-Length`) is **not a delivered payload**. **Wave 1 has no hedging and no retries by design** (single substituter, `max-substitution-jobs=1`, no faults in the honest scenario), so *any* such record is a defect: it is excluded from the egress sum and makes the whole **run INVALID** (§4) — never silently summed as partial egress, never counted as 0. Discriminator: `bytes_sent < file_size` on a `kind == "nar"` record (task-7). |
| **Retried / duplicate crossings** | When a transfer is retried (e.g. a killed daemon hop plus a fallback re-fetch), the SAME payload can cross the boundary more than once. Counting every crossing double-counts egress and corrupts the with/without-daemon delta. §4 enforces **exactly one full NAR record per payload** (a LIST, not a set, so a duplicate *full* crossing is caught, not just a truncated one) — any extra or duplicate NAR record makes the run INVALID. |
| **Hedge losers — UNRESOLVED, deferred to the wave-2 freeze (do NOT read this row as settled)** | A hedge race issues a duplicate request and aborts the loser; the loser's bytes *do* cross the boundary and are real cost (PRD: *duplicated pulls make egress worse*). This creates a **direct tension with the wave-1 rule above**: a hedge loser is a partial NAR (`bytes_sent < file_size`), which is byte-for-byte indistinguishable from a truncated primary under the current discriminator, yet one must be COUNTED (hedge-loser waste) and the other EXCLUDED (truncated primary). **Wave 1 has zero hedging, so the tension does not arise and the wave-1 rule stands.** When hedging is introduced, this row MUST be resolved at that freeze by: (a) attributing exactly one *primary/winning* full transfer per payload for the offload metric, and (b) counting hedge-loser bytes into a **separate `hedge_waste` channel** (not the payload metric), discriminated by request provenance (which the testproxy log must then carry), NOT by byte count. Until then, `net-upstream-egress-v1` is defined only for the no-hedge regime. |
| **The signing key / control-plane bytes** | `__testproxy/*` admin traffic is never served as a cache response and is not in the request log; it cannot enter the sum. |

## 4. Run validity (fail-closed)

A single run is one scripted workload execution (`nix-store --realise` of the
fixture closure). A run is **VALID** iff *all* of:

1. the client exited 0 (the workload actually completed);
2. no truncated NAR: every `kind == "nar"` record matching a requested payload
   has `bytes_sent == file_size`;
3. **exactly one full NAR record per payload** — the count of matching NAR
   records equals the payload count AND each payload appears exactly once at its
   full size (tracked as a LIST, so a *duplicate full* crossing is caught, not
   just a truncated one; this is what excludes retried/duplicate crossings);
4. **accounting closes**: `egress_total == nar + narinfo + cache_info + other`,
   and `other == 0` (no unexpected `Kind::Other` passthrough traffic). A non-zero
   `other` during a measurement run means an un-named channel is contributing
   bytes to the headline total — the run is INVALID until it is explained.

If a run cannot have its egress determined — a counter missing, a transfer
truncated, a duplicate crossing, an un-named channel, the client failed — that
run is **INVALID**, excluded from the sample, and the reason is logged in the
report's `invalid_runs` list. An invalid run is **never** counted as 0 egress and
**never** counted as success.

**Arm usability threshold:** an arm needs at least `BASELINE_MIN_VALID_RUNS = 10`
**valid** runs (§5) to be `usable`. Requesting `--runs < 10` (a dev smoke)
requires all of them valid and is marked `dev_smoke_below_n10`; requesting more
than 10 lets flakes be absorbed as long as ≥ 10 valid runs survive. An arm below
the floor is flagged unusable rather than reported as if clean, and the report's
`verdict.arms_usable` is false.

## 5. Statistics

- **Sampling:** N ≥ 10 valid runs per arm. The report records N, mean, stdev,
  and p95 for both egress and wall-clock, per arm.
- **p95 wall-clock:** the build wall-clock is the wall time of the scripted
  `realise` workload. p95 is the 95th percentile by linear interpolation on the
  sorted per-run times.
- **A/A calibration:** two independent daemon-**off** arms are measured. The
  noise floor is `|p95(A1) − p95(A2)| / p95(A1)`. If it is **≥ 10%** (the S4
  threshold), **S4 is flagged UNUSABLE in the report itself** — the harness
  cannot resolve a 10% latency effect it cannot distinguish from its own noise.
  This is surfaced, never hidden.
- **Client knobs pinned per run** (oracle-pairing rule, TESTING.md): fresh store
  + wiped narinfo cache, `max-substitution-jobs=1`, `http-connections=1`,
  `narinfo-cache-*-ttl=0`. Egress is not made vacuous by a warm client.
- **`instrument_trustworthy` is orthogonal to S4 usability.** The report's
  `verdict.instrument_trustworthy` = (all bites pass) AND (arms usable); it does
  **not** require `s4_usable`. A report can be trustworthy for the *egress*
  measurement while S4 (the latency axis) is flagged UNUSABLE — the two are
  reported as separate axes so a noisy latency floor never silently invalidates a
  sound egress baseline, nor a sound egress baseline hides an unusable S4.

## 6. Daemon self-counter agreement (product measured, not trusted)

The daemon's `substituted … bytes=<Content-Length>` lines are summed over a
clean single run and compared to the testproxy's `nar` `bytes_sent` for that run.

- **Stated tolerance: ≤ 1%** relative difference. For an untruncated transfer
  the upstream `Content-Length` equals the NAR body length, so the expected
  delta is **exactly 0**; the 1% band only absorbs a future framing change.
- **Scope: NAR only.** The daemon logs `substituted` on a 200 NAR; it does not
  narrate narinfo, so this agreement covers NAR egress, not narinfo egress.
- **Wave-1 limitation (TASK-31):** `bytes=` is `Content-Length`, not a counted
  body drain, so a *truncated* transfer would still log its advertised length.
  This is exactly why the daemon self-counter is compared to, and never
  substituted for, the testproxy — the testproxy counts bytes actually written.

## 7. Provenance recorded in every report (task-3 deep-gate)

Every report embeds, so a number is never quoted against an unverified tree:

- `workload_version` (`nix-p2p-fixture-workload-v1`) — the fixture identity;
  cross-wave comparison is meaningful only between equal strings.
- the fixture lock **public key** and per-payload **hashes**
  (`file_hash`, `nar_hash`, `store_path`) read from the resolved immutable
  generation's `lock.json`.
- this file's `counting_rule_version` (`net-upstream-egress-v1`).
- the fixture `tier` (`full` is required — the 110 MiB payload must be present).

`just measure` runs the fail-closed `check-fixtures.py` gate **before** serving
anything (a measurement against an unverified tree is not a baseline). The
separately-required pre-J2 steps `just fixtures-large` and
`just fixtures-verify-rebuild` are the caller's responsibility and are named in
the task-12 handoff — this instrument does not silently stand in for them.

## 8. Honest scope (what this instrument does and does not prove)

- **Wave 1 has no p2p.** With no peers, the daemon-on and daemon-off arms fetch
  identical bytes from the boundary, so the measured offload is ≈ 0 **by
  construction**. This is expected and reported as such. What is validated here
  is the **instrument's trustworthiness**, not offload: that egress moves when it
  must (magnitude bite, product-side bite) and that a 10% latency effect is
  resolvable above the noise floor (A/A). Offload > 0 is a wave-2 measurement
  this same instrument will make.
- **Determinism on one machine, not cross-host.** The lock makes fixture drift
  loud; a cross-host regeneration diff (task-3 deep-gate) is a separate, still-
  required proof before J2 quotes a number.
- **The compression ratios here are not representative.** The fixture payloads
  are incompressible by construction (seeded SHAKE256), so xz/zstd bodies sit
  close to their raw size. Do not read the narinfo/nar egress split here as
  representative of real nixpkgs closures; the baseline text must say so.
- **The gap histogram's LARGE-gap regime is unvalidated.** The gap-oracle bite
  synthesizes a known narinfo→nar gap by delaying the NAR *response*; the daemon's
  1000 ms upstream `header_timeout` (`daemon/src/upstream.rs`) caps that technique
  at `< ~950 ms`, so the instrument is only *proven to bite* for sub-second gaps.
  This bounds the SYNTHESIS technique, not the measurement: a genuine
  client-side narinfo→nar gap of any size would still be recorded on a real run
  (the timeout is on the daemon→proxy hop, not on client think-time). But the
  histogram's fidelity for multi-second real gaps is not demonstrated by any bite
  here. Empirically, the real gap on this loopback harness is **sub-millisecond**
  (~0.5 ms median) — itself the PRD-risk-3 finding that the prefetch window is
  structurally near-zero on fast/repeat paths.
