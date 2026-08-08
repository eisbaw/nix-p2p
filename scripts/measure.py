#!/usr/bin/env python3
"""`just measure` (task-9): the S3/S4 egress + latency measurement instrument.

Runs an identical scripted workload with-daemon vs without-daemon over the
task-5 container harness (Pod seam) and emits a MACHINE-READABLE JSON report:
net upstream egress (both arms), p95 wall-clock (both arms), and the narinfo->nar
gap histogram. The counting rule that freezes the J2 baseline lives next to this
file in `MEASUREMENT_COUNTING_RULE.md` (version `net-upstream-egress-v2`); this
script is its executable form and every report quotes it.

GROUND TRUTH is the testproxy's own byte counters (`Pod.proxy_stats` /
`proxy_log`), never the daemon's self-report and never the client's view. The
daemon self-counter is COMPARED to ground truth (Section 6 of the doc), never
substituted for it.

FAIL-CLOSED: a run whose egress cannot be determined (client failed, a NAR
truncated, a counter missing) is INVALID, excluded with a logged reason, and
never counted as 0 or as success.

Every oracle bites by MUTATION: each bite runs a control (green) and a mutation
that must make it RED, and asserts the flip. A metric that reports plausible-but-
unfalsifiable numbers is the worst outcome for the cross-wave comparison basis, so
the instrument refuses to pass unless each bite is shown able to fail.

WAVE-1 HONESTY: there is no p2p, so the daemon-on and daemon-off arms fetch
identical bytes and the measured offload is ~0 BY CONSTRUCTION. This validates
the INSTRUMENT, not offload. Offload > 0 is a wave-2 measurement this same
machinery will make (forward-carried to task-12/16/18).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import statistics
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

import e2e_harness as e2e
import fixturelib as fx

# ---- frozen constants (mirror MEASUREMENT_COUNTING_RULE.md) -----------------

# v2 (codex re-gate): the validity rule allows ZERO-or-one full NAR crossing per
# target - a ZERO-crossing is the wave-2 offload event (a peer served the payload,
# so the cache saw nothing), VALID iff the client independently confirms delivery.
# v1 required exactly one crossing and would have REJECTED every real-offload run.
COUNTING_RULE_VERSION = "net-upstream-egress-v2"
COUNTING_RULE_DOC = "scripts/MEASUREMENT_COUNTING_RULE.md"

# A baseline needs at least this many VALID runs per arm (counting rule SECTION 5,
# TESTING.md "N >= 10"). An arm with fewer valid runs is flagged unusable.
BASELINE_MIN_VALID_RUNS = 10

# S4 latency bound (PRD kill criterion / TESTING.md S4): p95 with-daemon must be
# <= 110% of daemon-off. The A/A noise floor must sit BELOW this to be usable.
S4_THRESHOLD = 0.10
# Daemon self-counter vs testproxy tolerance (counting rule Section 6). For an
# untruncated transfer the expected delta is exactly 0; the band absorbs framing.
SELF_COUNTER_TOL = 0.01
# Injected per-request latency for the S4 bite (AC#5): the classic 200 ms.
LATENCY_INJECT_MS = 200
# Injected narinfo->nar gaps for the gap-oracle bite (AC#4): two values, so the
# histogram must both REPORT a known X and TRACK a changed X. Both MUST stay
# below the daemon's 1000 ms upstream header_timeout (daemon/src/upstream.rs):
# the injection works by delaying the NAR *response* (the proxy computes the gap
# after the delay), and a delay past that timeout makes the daemon abort the
# fetch before the proxy can log the gap - a real ceiling on the synthesizable
# gap, surfaced in the report rather than worked around.
# 300/500 keeps a wide margin below the 1000 ms ceiling: the accept band upper
# bound is 500 + max(0.4*500, 250) = 750 ms, ~250 ms of headroom, so loopback +
# relay jitter on a loaded machine cannot push a pass into a ceiling-abort (a
# non-reproducible green->red flip near the ceiling would poison the verdict).
DAEMON_HEADER_TIMEOUT_MS = 1000
GAP_INJECT_MS = (300, 500)

# The daemon's per-substitution narration (daemon/src/server.rs::log_substitution).
# `bytes=` is the upstream Content-Length - the self-report we MEASURE, never trust.
SUBST_RE = re.compile(
    r"daemon: substituted path=\S+ source=\S+ bytes=(\d+) duration_ms=\d+"
)


def proxy_only_substituter() -> str:
    """Daemon-off arm: the client talks directly to the testproxy - the SAME
    egress boundary the daemon-on arm measures at, so the two arms are comparable
    at one meter."""
    return f"http://127.0.0.1:{e2e.PROXY_PORT}"


def _silent_expect(collector: list) -> object:
    """A Pod `expect` that records AC#5 key-exclusion results without printing.
    The secret-key abort in Pod raises on its own; this only captures checks."""

    def expect(ok: bool, name: str, detail: str = "") -> bool:
        collector.append((bool(ok), name, detail))
        return bool(ok)

    return expect


# ---- percentile + stats -----------------------------------------------------


def percentile(values: list[float], pct: float) -> float:
    """Linear-interpolated percentile (pct in [0,100]) on a copy-sorted list.
    Returns 0.0 for an empty list (callers guard emptiness separately)."""
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    rank = (pct / 100.0) * (len(ordered) - 1)
    low = int(rank)
    frac = rank - low
    if low + 1 < len(ordered):
        return float(ordered[low] + frac * (ordered[low + 1] - ordered[low]))
    return float(ordered[low])


def stat_block(values: list[float]) -> dict:
    """mean/stdev/p95/min/max + the raw values, so a reader can re-derive."""
    if not values:
        return {
            "n": 0,
            "mean": None,
            "stdev": None,
            "p95": None,
            "min": None,
            "max": None,
            "values": [],
        }
    return {
        "n": len(values),
        "mean": statistics.fmean(values),
        "stdev": statistics.pstdev(values) if len(values) > 1 else 0.0,
        "p95": percentile(values, 95),
        "min": min(values),
        "max": max(values),
        "values": values,
    }


# ---- one run: the counting rule made executable -----------------------------


@dataclass
class RunResult:
    valid: bool
    reason: str
    wall_s: float
    egress_total: int
    egress_nar: int
    egress_narinfo: int
    egress_cacheinfo: int
    egress_other: int = 0
    gap_ms: list[float] = field(default_factory=list)
    client_exit: int = 0


def _url_sizes(fixtures, attrs) -> dict[str, int]:
    """Map each payload's NAR url -> its COMPRESSED wire size (file_size). This is
    the on-wire byte count per the counting rule - NEVER nar_size (the trap)."""
    return {
        fixtures.entry(a)["url"]: int(fixtures.entry(a)["file_size"]) for a in attrs
    }


def classify_run(
    records: list[dict],
    url_sizes: dict[str, int],
    delivered_by_url: dict[str, bool],
    stats_bytes_sent: int | None,
    client_exit: int,
    wall_s: float,
) -> RunResult:
    """PURE validity + egress derivation from a proxy log (single source of truth).
    Extracted from I/O so the validator can be unit-tested with synthetic logs
    (`--self-test`) - the codex re-gate wants the wave-2 shapes proven directly.

    The counting rule (doc SECTION 3/4), v2:
      * per target: ZERO-OR-ONE full NAR crossing. ZERO is the wave-2 OFFLOAD event
        (a peer served it, the cache saw nothing) and is VALID *iff* the client
        independently confirms delivery (`delivered_by_url`); ZERO crossings AND no
        delivery is a real MISS -> INVALID.
      * a SECOND full crossing of the same target (retry/duplicate) -> INVALID.
      * any truncated crossing (0 < bytes_sent < file_size) -> INVALID.
      * a record MISSING bytes_sent -> INVALID (unknown != 0; fail-closed).
      * any Kind::Other body during a measurement -> INVALID (un-named channel).
      * cross-check: the proxy_log byte sum MUST equal the proxy_stats endpoint's
        independently-derived bytes_sent (a real falsifiable check, not a tautology).
    """
    egress_total = egress_nar = egress_narinfo = egress_cacheinfo = egress_other = 0
    gaps: list[float] = []
    truncated: list[tuple] = []
    full_count = {u: 0 for u in url_sizes}
    missing_bytes = 0

    for record in records:
        kind = record.get("kind")
        # Fold-in (codex #3): a missing/absent bytes_sent is a HARD error - unknown
        # is not 0. Do not sum it; flag the run.
        raw = record.get("bytes_sent")
        if raw is None:
            missing_bytes += 1
            continue
        sent = int(raw)
        egress_total += sent
        if kind == "nar":
            egress_nar += sent
            gap = record.get("gap_ms")
            if gap is not None:
                gaps.append(float(gap))
            matched = next((u for u in url_sizes if u in record.get("path", "")), None)
            if matched is not None:
                size = url_sizes[matched]
                if sent == size:
                    full_count[matched] += 1
                elif 0 < sent < size:
                    truncated.append((matched, sent, size))
        elif kind == "narinfo":
            egress_narinfo += sent
        elif kind == "cache-info":
            egress_cacheinfo += sent
        else:
            egress_other += sent

    reasons: list[str] = []
    if client_exit != 0:
        reasons.append(f"client exit {client_exit}")
    if missing_bytes:
        reasons.append(
            f"{missing_bytes} record(s) missing bytes_sent "
            "(egress undeterminable; unknown != 0)"
        )
    if truncated:
        reasons.append(f"truncated NAR (bytes_sent<file_size): {truncated}")
    duplicates = [u for u, c in full_count.items() if c > 1]
    if duplicates:
        reasons.append(
            f"duplicate full NAR crossing for {duplicates} (would double-count egress)"
        )
    # ZERO crossing is VALID only with verified client delivery (a wave-2 peer hit,
    # or an already-in-store target); ZERO crossing + not delivered = a real miss.
    missed = [
        u
        for u, c in full_count.items()
        if c == 0 and not delivered_by_url.get(u, False)
    ]
    if missed:
        reasons.append(
            f"target(s) neither crossed the cache nor delivered to the client "
            f"(real miss, NOT offload): {missed}"
        )
    if egress_other != 0:
        reasons.append(f"unexpected non-payload/metadata egress: {egress_other} bytes")
    # Real cross-check (replaces the v1 tautology): the proxy's OWN stats endpoint
    # derives bytes_sent from the same log in Rust; a mismatch means our parse and
    # the proxy disagree - fail closed rather than trust a silently-drifted number.
    if stats_bytes_sent is not None and egress_total != stats_bytes_sent:
        reasons.append(
            f"egress accounting mismatch: proxy_log sum {egress_total} != "
            f"proxy_stats bytes_sent {stats_bytes_sent}"
        )

    return RunResult(
        valid=not reasons,
        reason="; ".join(reasons),
        wall_s=wall_s,
        egress_total=egress_total,
        egress_nar=egress_nar,
        egress_narinfo=egress_narinfo,
        egress_cacheinfo=egress_cacheinfo,
        egress_other=egress_other,
        gap_ms=gaps,
        client_exit=client_exit,
    )


def measure_one_run(pod, substituter: str, keys: str, fixtures, attrs) -> RunResult:
    """One workload execution. Resets the proxy COUNTERS (not its disk cache) so
    each run's egress is the full workload; times the client; then derives egress
    and validity (via the pure `classify_run`) from the proxy log + stats."""
    url_sizes = _url_sizes(fixtures, attrs)
    targets = [fixtures.store_path(a) for a in attrs]
    pod.proxy_reset()
    started = time.perf_counter()
    result = pod.client_run(targets, substituter, keys)
    wall_s = time.perf_counter() - started

    log = pod.proxy_log()
    stats_bytes_sent = pod.proxy_stats().get("bytes_sent")
    # Verified client delivery per target: `nix path-info` reported a NarHash for
    # the store path, i.e. nix realised/imported it. This is what makes a ZERO
    # cache-crossing a legitimate OFFLOAD (peer hit) rather than a miss (v2 rule).
    delivered_by_url = {
        fixtures.entry(a)["url"]: (result.narhash(fixtures.store_path(a)) is not None)
        for a in attrs
    }
    return classify_run(
        log, url_sizes, delivered_by_url, stats_bytes_sent, result.exit_code, wall_s
    )


def summarize_arm(name: str, results: list[RunResult], attrs) -> dict:
    """Aggregate an arm's runs, splitting valid from invalid (fail-closed)."""
    valid = [r for r in results if r.valid]
    invalid = [
        {"run": i, "reason": r.reason} for i, r in enumerate(results) if not r.valid
    ]
    all_gaps = [g for r in valid for g in r.gap_ms]
    # Counting rule SECTION 5: a baseline needs >= BASELINE_MIN_VALID_RUNS valid
    # runs. Requesting fewer (a dev smoke) requires all of them valid; requesting
    # more lets flakes be absorbed as long as >= the floor survive.
    min_valid = min(len(results), BASELINE_MIN_VALID_RUNS)
    return {
        "arm": name,
        "runs": len(results),
        "valid_runs": len(valid),
        "min_valid_required": min_valid,
        "invalid_runs": invalid,
        "usable": len(valid) >= min_valid,
        # THE kill-criterion metric is payload (NAR) egress - symmetric across arms
        # and immune to metadata-cache gaming (counting rule SECTION 2/8).
        "egress_payload_nar_bytes": stat_block([r.egress_nar for r in valid]),
        # Total + the metadata channels are reported as CONTEXT, not the metric.
        "egress_total_bytes": stat_block([r.egress_total for r in valid]),
        "egress_narinfo_bytes": stat_block([r.egress_narinfo for r in valid]),
        "egress_cacheinfo_bytes": stat_block([r.egress_cacheinfo for r in valid]),
        "egress_other_bytes": stat_block([r.egress_other for r in valid]),
        "wall_clock_s": stat_block([r.wall_s for r in valid]),
        "gap_histogram_ms": gap_histogram(all_gaps),
    }


def gap_histogram(gaps: list[float]) -> dict:
    """A coarse fixed-bucket histogram of narinfo->nar gaps (ms), plus the raw
    samples and percentiles. This is the empirical prefetch-window input the DHT
    wave needs (PRD risk 3: is the prefetch window real?)."""
    edges = [0, 10, 50, 100, 250, 500, 1000, 2000, 5000]
    buckets = {f"[{edges[i]},{edges[i + 1]})": 0 for i in range(len(edges) - 1)}
    buckets[f">={edges[-1]}"] = 0
    for g in gaps:
        placed = False
        for i in range(len(edges) - 1):
            if edges[i] <= g < edges[i + 1]:
                buckets[f"[{edges[i]},{edges[i + 1]})"] += 1
                placed = True
                break
        if not placed:
            buckets[f">={edges[-1]}"] += 1
    return {
        "n": len(gaps),
        "median_ms": statistics.median(gaps) if gaps else None,
        "p95_ms": percentile(gaps, 95) if gaps else None,
        "min_ms": min(gaps) if gaps else None,
        "max_ms": max(gaps) if gaps else None,
        "buckets": buckets,
        "samples_ms": gaps,
    }


def run_arm(
    ctx, fixtures, name, *, with_daemon, substituter, attrs, runs, daemon_extra=()
):
    """Stand up one Pod and measure `runs` workloads through `substituter`."""
    key_checks: list = []
    results: list[RunResult] = []
    with e2e.Pod(
        ctx,
        f"measure-{name}",
        fixtures.cache,
        with_daemon=with_daemon,
        expect=_silent_expect(key_checks),
        daemon_extra_args=daemon_extra,
    ) as pod:
        for _ in range(runs):
            results.append(
                measure_one_run(pod, substituter, fixtures.public_key, fixtures, attrs)
            )
    failed_key_checks = [c for c in key_checks if not c[0]]
    if failed_key_checks:
        e2e.die(f"arm {name}: AC#5 key-exclusion check failed: {failed_key_checks}")
    return summarize_arm(name, results, attrs)


# ---- provenance -------------------------------------------------------------


def provenance(fixtures, out_root: Path) -> dict:
    """Everything that makes a number a BASELINE and not just a number (task-3
    deep-gate): the workload version, the fixture lock public key + per-payload
    hashes, and this counting rule's version."""
    generation = fx.resolve_current(out_root)
    lock = json.loads((generation / "lock.json").read_text())
    manifest = fixtures.manifest
    payloads = {
        attr: {
            "store_path": entry["store_path"],
            "file_hash": entry["file_hash"],
            "nar_hash": entry["nar_hash"],
            "file_size": entry["file_size"],
            "nar_size": entry["nar_size"],
            "compression": entry["compression"],
        }
        for attr, entry in ((p["attr"], p) for p in manifest["paths"])
    }
    return {
        "workload_version": manifest["workload_version"],
        "fixture_tier": manifest["tier"],
        "fixture_public_key": lock["public_key"],
        "counting_rule_version": COUNTING_RULE_VERSION,
        "counting_rule_doc": COUNTING_RULE_DOC,
        "generation": generation.name,
        "payloads": payloads,
    }


# ---- bites (each must fail-before / pass-after by MUTATION) ------------------


def bite_magnitude_and_self_counter(ctx, fixtures, attrs) -> dict:
    """AC#3. CONTROL: one clean daemon run -> NAR egress == known sum of served
    fixture FileSizes (compressed wire bytes), AND the daemon self-counter agrees
    with the testproxy within tolerance. MUTATION: truncate_pct=50 -> the SAME
    two oracles must go RED (egress != expected; and the daemon still logs the
    full Content-Length while the proxy counts half, so the self-report disagrees
    - the exact reason it is measured, not trusted)."""
    expected_sum = sum(int(fixtures.entry(a)["file_size"]) for a in attrs)
    substituter = ctx.substituter_daemon_only()
    keys = fixtures.public_key
    targets = [fixtures.store_path(a) for a in attrs]

    control = {}
    mutant = {}
    with e2e.Pod(
        ctx,
        "bite-magnitude",
        fixtures.cache,
        with_daemon=True,
        expect=_silent_expect([]),
    ) as pod:
        # -- CONTROL: clean run --
        pod.proxy_faults("")  # no faults
        rr = measure_one_run(pod, substituter, keys, fixtures, attrs)
        daemon_lines = SUBST_RE.findall(pod.logs("daemon"))
        daemon_nar_bytes = sum(int(m) for m in daemon_lines)
        proxy_nar_bytes = rr.egress_nar
        delta = (
            abs(daemon_nar_bytes - proxy_nar_bytes) / proxy_nar_bytes
            if proxy_nar_bytes
            else 1.0
        )
        # N1: distinguish "self-report disagrees" from "could not parse the daemon
        # narration". Zero substitution lines on a clean run means the log-line
        # format drifted, not that the counters disagree - fail loud on the RIGHT
        # thing rather than masquerading as a tolerance breach.
        parsed_ok = len(daemon_lines) == len(attrs)
        control = {
            "valid": rr.valid,
            "nar_egress_bytes": rr.egress_nar,
            "expected_file_size_sum": expected_sum,
            "magnitude_matches": rr.valid and rr.egress_nar == expected_sum,
            "daemon_substitution_lines": len(daemon_lines),
            "daemon_narration_parsed": parsed_ok,
            "daemon_self_nar_bytes": daemon_nar_bytes,
            "proxy_nar_bytes": proxy_nar_bytes,
            "self_counter_rel_delta": delta,
            "self_counter_agrees": parsed_ok and delta <= SELF_COUNTER_TOL,
        }

        # -- MUTATION: truncate every NAR to 50% of its body --
        pod.proxy_reset()
        pod.proxy_faults("truncate_pct=50")
        started = time.perf_counter()
        result = pod.client_run(targets, substituter, keys)
        _ = time.perf_counter() - started
        log = pod.proxy_log()
        # Discriminate truncation per-record against each payload's OWN file_size
        # (S4) - NOT the four-payload sum, under which every record looks "short".
        url_sizes = _url_sizes(fixtures, attrs)
        m_nar = 0
        m_truncated = []
        for r in log:
            if r.get("kind") != "nar":
                continue
            sent = int(r.get("bytes_sent", 0))
            m_nar += sent
            matched = next((u for u in url_sizes if u in r.get("path", "")), None)
            if matched is not None and 0 < sent < url_sizes[matched]:
                m_truncated.append((matched, sent, url_sizes[matched]))
        # The daemon log is CUMULATIVE (podman logs), so the mutant's self-report
        # is the total minus the control run's lines already counted above.
        m_daemon_total = sum(int(x) for x in SUBST_RE.findall(pod.logs("daemon")))
        m_daemon = m_daemon_total - daemon_nar_bytes
        m_delta = abs(m_daemon - m_nar) / m_nar if m_nar else 1.0
        pod.proxy_faults("")
        mutant = {
            "client_exit": result.exit_code,
            "nar_egress_bytes": m_nar,
            "expected_file_size_sum": expected_sum,
            "magnitude_matches": m_nar == expected_sum,  # must be False
            "truncated_records": len(m_truncated),
            "daemon_self_nar_bytes": m_daemon,
            "proxy_nar_bytes": m_nar,
            "self_counter_rel_delta": m_delta,
            "self_counter_agrees": m_delta <= SELF_COUNTER_TOL,  # must be False
        }

    magnitude_bites = control["magnitude_matches"] and not mutant["magnitude_matches"]
    self_counter_bites = (
        control["daemon_narration_parsed"]
        and control["self_counter_agrees"]
        and not mutant["self_counter_agrees"]
    )
    return {
        "name": "magnitude+self-counter (AC#3)",
        "control": control,
        "mutant_truncate50": mutant,
        "magnitude_bites": magnitude_bites,
        "self_counter_bites": self_counter_bites,
        "bites": magnitude_bites and self_counter_bites,
    }


def _measure_gap_median(
    pod, substituter, keys, fixtures, attr, latency_ms, samples
) -> list[float]:
    """Collect narinfo->nar gap_ms samples with `latency_nar_ms=latency_ms`
    injected. The proxy computes the gap AFTER applying NAR latency, so the
    injected delay lands inside the recorded gap - this is how the testproxy
    'paces' a known narinfo->nar gap (AC#4)."""
    gaps: list[float] = []
    pod.proxy_faults(f"latency_nar_ms={latency_ms}" if latency_ms else "")
    for _ in range(samples):
        rr = measure_one_run(pod, substituter, keys, fixtures, [attr])
        gaps.extend(rr.gap_ms)
    pod.proxy_faults("")
    return gaps


def bite_gap_oracle(ctx, fixtures) -> dict:
    """AC#4. Inject a KNOWN narinfo->nar delay X via the testproxy and assert the
    gap histogram reports X within tolerance AND tracks a changed X. The bite:
    the X=0 reading must NOT look like X (else the oracle is vacuous), and the
    median must move X0 -> X1 -> X2 as injected."""
    attr = "lib"  # small + uncompressed: fast, one clean gap per run
    substituter = ctx.substituter_daemon_only()
    keys = fixtures.public_key
    x1, x2 = GAP_INJECT_MS
    if max(x1, x2) >= DAEMON_HEADER_TIMEOUT_MS:
        e2e.die(
            f"gap injections {GAP_INJECT_MS} must stay below the daemon "
            f"header_timeout ({DAEMON_HEADER_TIMEOUT_MS} ms) or the daemon aborts "
            "the NAR fetch before the proxy logs the gap"
        )
    samples = 5
    readings = {}
    with e2e.Pod(
        ctx, "bite-gap", fixtures.cache, with_daemon=True, expect=_silent_expect([])
    ) as pod:
        base = _measure_gap_median(pod, substituter, keys, fixtures, attr, 0, samples)
        g1 = _measure_gap_median(pod, substituter, keys, fixtures, attr, x1, samples)
        g2 = _measure_gap_median(pod, substituter, keys, fixtures, attr, x2, samples)
    readings = {
        "baseline_no_inject": gap_histogram(base),
        f"inject_{x1}ms": gap_histogram(g1),
        f"inject_{x2}ms": gap_histogram(g2),
    }
    med_base = statistics.median(base) if base else 0.0
    med1 = statistics.median(g1) if g1 else 0.0
    med2 = statistics.median(g2) if g2 else 0.0

    # Tolerance: measured ~= injected + a small loopback/daemon-relay baseline.
    # Accept the greater of 40% of X or 250 ms of slack, and require the measured
    # value to sit at or above the injected floor.
    def near(measured, injected):
        tol = max(0.40 * injected, 250.0)
        return injected - 50 <= measured <= injected + tol

    reports_x1 = near(med1, x1)
    reports_x2 = near(med2, x2)
    baseline_not_vacuous = med_base < (x1 * 0.5)  # X=0 reading must not look like X
    tracks_change = (med2 - med1) >= 0.5 * (x2 - x1)  # histogram moved with X
    return {
        "name": "gap-oracle (AC#4)",
        "readings": readings,
        "median_baseline_ms": med_base,
        f"median_inject_{x1}ms": med1,
        f"median_inject_{x2}ms": med2,
        "reports_x1": reports_x1,
        "reports_x2": reports_x2,
        "baseline_not_vacuous": baseline_not_vacuous,
        "tracks_changed_x": tracks_change,
        "injection_ceiling_ms": DAEMON_HEADER_TIMEOUT_MS,
        "note": (
            "gap injected by delaying the NAR response; bounded above by the "
            f"daemon's {DAEMON_HEADER_TIMEOUT_MS} ms header_timeout. The real "
            "narinfo->nar gap on this loopback harness is sub-millisecond (see "
            "arm gap_histogram) - relevant to PRD risk 3 (prefetch window)."
        ),
        "bites": reports_x1 and reports_x2 and baseline_not_vacuous and tracks_change,
    }


def bite_latency_p95(ctx, fixtures, attrs, runs, s4_usable, aa_noise_floor) -> dict:
    """AC#5 (first half). Injected 200 ms/request must trip the >10% p95 flag.

    PASSES-AFTER (the mutation): 200 ms on every path-kind makes p95(injected) /
    p95(baseline) exceed 1.10 - the flag trips. This is a LARGE, robust effect
    (~1.8 s added over ~9 requests vs a ~0.5 s baseline, ratio ~9x), so it is the
    biting criterion.

    FAILS-BEFORE (the control) is NOT a fresh, small, noise-prone A/A inside this
    bite - it is the MAIN A/A noise floor (`s4_usable`), measured at full 10-run
    rigor on the daemon-off arms. When that noise floor is below the 10% threshold,
    a no-injection run does NOT trip the flag (fails-before holds); when it is at
    or above threshold, S4 is UNUSABLE and reported as such (the flag's two-sided
    falsifiability is genuinely noise-limited, surfaced not hidden). Tying the
    control to the main A/A avoids a knife-edge 5-run sub-arm flipping the verdict
    under transient host load - the earlier design's flaw."""
    substituter = ctx.substituter_daemon_only()
    keys = fixtures.public_key
    inject = (
        f"latency_cache_info_ms={LATENCY_INJECT_MS}"
        f"&latency_narinfo_ms={LATENCY_INJECT_MS}"
        f"&latency_nar_ms={LATENCY_INJECT_MS}"
    )

    def arm(pod, fault):
        pod.proxy_faults(fault)
        rows = [
            measure_one_run(pod, substituter, keys, fixtures, attrs)
            for _ in range(runs)
        ]
        pod.proxy_faults("")
        return [r.wall_s for r in rows if r.valid]

    with e2e.Pod(
        ctx, "bite-latency", fixtures.cache, with_daemon=True, expect=_silent_expect([])
    ) as pod:
        base = arm(pod, "")
        slow = arm(pod, inject)
    p95_base = percentile(base, 95)
    p95_slow = percentile(slow, 95)
    ratio = (p95_slow / p95_base) if p95_base else 0.0
    flag_trips = ratio > (1.0 + S4_THRESHOLD)
    # Fails-before evidence = the main A/A noise floor is below threshold (so a
    # no-injection run does not trip). REPORTED as a companion, not the biting
    # criterion: when S4 is unusable the bite still proves the flag TRIPS on signal
    # and flags the fails-before as noise-limited rather than silently passing.
    return {
        "name": "latency-p95 (AC#5)",
        "injected_ms_per_request": LATENCY_INJECT_MS,
        "p95_baseline_s": p95_base,
        "p95_injected_s": p95_slow,
        "p95_ratio": ratio,
        "s4_threshold": 1.0 + S4_THRESHOLD,
        "flag_trips_under_injection": flag_trips,
        "fails_before_via_main_aa_noise_floor": aa_noise_floor,
        "fails_before_holds": s4_usable,
        "fails_before_note": (
            "no main A/A in --only-bites mode; flag-trips proven, fails-before "
            "deferred to a full run's A/A noise floor"
            if aa_noise_floor is None
            else "no-injection does not trip: main A/A noise floor "
            f"{aa_noise_floor:.4f} < {S4_THRESHOLD} (S4 usable)"
            if s4_usable
            else "S4 NOISE-LIMITED: main A/A noise floor >= 10%, the fails-before "
            "(no-injection is quiet) cannot be cleanly shown; flag-trips still proven"
        ),
        # The biting criterion is passes-after (flag trips on a known 200ms effect).
        # fails-before rides the main A/A; when S4 is unusable it is reported, and
        # the instrument-trust verdict treats S4 as a separate axis (counting rule
        # doc SECTION 5: instrument_trustworthy is orthogonal to s4_usable).
        "bites": flag_trips,
    }


def bite_product_narinfo_cache(ctx, fixtures, attrs) -> dict:
    """AC#5 (second half): the PRODUCT-side bite. Toggling task-8's daemon narinfo
    cache (--narinfo-cache-dir) must measurably MOVE narinfo egress - validating
    the instrument against a real product change, not only a fixture toggle.

    Client narinfo cache is wiped per run (ttl 0), so the client always re-asks
    the daemon. With the daemon cache OFF the daemon re-fetches narinfo from the
    proxy every run (per-run narinfo egress stays flat). With it ON, run 1 fetches
    and runs 2..N are served from the daemon's disk cache (per-run narinfo egress
    drops toward 0). The bite: the ON arm's narinfo egress DROPS after run 1 while
    the OFF arm's stays flat."""
    substituter = ctx.substituter_daemon_only()
    keys = fixtures.public_key
    runs = 3

    def per_run_narinfo(daemon_extra):
        vals = []
        with e2e.Pod(
            ctx,
            "bite-product",
            fixtures.cache,
            with_daemon=True,
            expect=_silent_expect([]),
            daemon_extra_args=daemon_extra,
        ) as pod:
            for _ in range(runs):
                rr = measure_one_run(pod, substituter, keys, fixtures, attrs)
                vals.append(rr.egress_narinfo)
        return vals

    off = per_run_narinfo(())
    on = per_run_narinfo(("--narinfo-cache-dir", "/tmp/nix-p2p-narinfo-cache"))
    # ON must drop after run 1; OFF must stay flat (control that the drop is the
    # product, not the harness).
    on_drops = on[0] > 0 and on[1] < 0.5 * on[0]
    off_flat = off[0] > 0 and off[1] >= 0.8 * off[0]
    return {
        "name": "product-narinfo-cache (AC#5)",
        "per_run_narinfo_egress_off": off,
        "per_run_narinfo_egress_on": on,
        "on_drops_after_run1": on_drops,
        "off_stays_flat": off_flat,
        "bites": on_drops and off_flat,
    }


# ---- report assembly --------------------------------------------------------


def run_bites(ctx, fixtures, attrs, runs, s4_usable, aa_noise_floor) -> dict:
    """The four falsifiability bites (AC#3/#4/#5), each fail-before/pass-after by
    mutation. Extracted so `--only-bites` can re-check the instrument without the
    slow main arms (the deep gate re-runs these). The latency bite's fails-before
    rides the MAIN A/A noise floor (s4_usable/aa_noise_floor), not a noisy sub-arm."""
    print(
        "measure: === BITES (each must fail-before / pass-after) ===", file=sys.stderr
    )
    print("measure: magnitude + self-counter bite", file=sys.stderr)
    bite_mag = bite_magnitude_and_self_counter(ctx, fixtures, attrs)
    print("measure: gap-oracle bite", file=sys.stderr)
    bite_gap = bite_gap_oracle(ctx, fixtures)
    print("measure: latency-p95 bite", file=sys.stderr)
    bite_lat = bite_latency_p95(
        ctx, fixtures, attrs, max(4, runs // 2), s4_usable, aa_noise_floor
    )
    print("measure: product-side narinfo-cache bite", file=sys.stderr)
    bite_prod = bite_product_narinfo_cache(ctx, fixtures, attrs)
    return {
        "magnitude_self_counter": bite_mag,
        "gap_oracle": bite_gap,
        "latency_p95": bite_lat,
        "product_narinfo_cache": bite_prod,
    }


def build_report(ctx, fixtures, out_root, runs) -> dict:
    prov = provenance(fixtures, out_root)
    attrs = list(e2e.ALL_ATTRS)

    print("measure: === MAIN ARMS (egress + p95 wall-clock) ===", file=sys.stderr)
    print(f"measure: daemon-off arm A1 ({runs} runs)", file=sys.stderr)
    off_a1 = run_arm(
        ctx,
        fixtures,
        "daemon-off-A1",
        with_daemon=False,
        substituter=proxy_only_substituter(),
        attrs=attrs,
        runs=runs,
    )
    print(f"measure: daemon-off arm A2 (A/A calibration, {runs} runs)", file=sys.stderr)
    off_a2 = run_arm(
        ctx,
        fixtures,
        "daemon-off-A2",
        with_daemon=False,
        substituter=proxy_only_substituter(),
        attrs=attrs,
        runs=runs,
    )
    print(f"measure: daemon-on arm ({runs} runs)", file=sys.stderr)
    on = run_arm(
        ctx,
        fixtures,
        "daemon-on",
        with_daemon=True,
        substituter=ctx.substituter_daemon_only(),
        attrs=attrs,
        runs=runs,
    )

    # A/A noise floor: two daemon-off arms should agree; if not below the S4
    # threshold, S4 is flagged UNUSABLE in the report (never hidden).
    p95_a1 = off_a1["wall_clock_s"]["p95"]
    p95_a2 = off_a2["wall_clock_s"]["p95"]
    noise_floor = abs(p95_a1 - p95_a2) / p95_a1 if p95_a1 else 1.0
    s4_usable = noise_floor < S4_THRESHOLD

    # Offload delta on PAYLOAD (NAR) egress - THE kill-criterion metric (S1): it is
    # symmetric across arms and cannot be moved by the daemon absorbing metadata
    # (nix-cache-info) or by the narinfo cache. Total egress is reported as context.
    payload_on = on["egress_payload_nar_bytes"]["mean"]
    payload_off = off_a1["egress_payload_nar_bytes"]["mean"]
    offload_frac = ((payload_off - payload_on) / payload_off) if payload_off else None
    total_on = on["egress_total_bytes"]["mean"]
    total_off = off_a1["egress_total_bytes"]["mean"]

    bites = run_bites(ctx, fixtures, attrs, runs, s4_usable, noise_floor)
    all_bite = all(b["bites"] for b in bites.values())
    arms_usable = off_a1["usable"] and off_a2["usable"] and on["usable"]

    return {
        "report_version": 1,
        "counting_rule": {
            "version": COUNTING_RULE_VERSION,
            "doc": COUNTING_RULE_DOC,
            "ground_truth": "testproxy bytes_sent (body bytes); daemon self-report measured, not trusted",
            "unit": "compressed on-wire bytes (file_size), NEVER nar_size",
            "kill_criterion_metric": "payload (NAR) egress - symmetric across arms, not gameable by metadata caching",
            "crossings_per_target": "zero-or-one full NAR crossing; zero is offload, VALID only with verified client delivery",
            "excludes": "response headers; truncated transfers; duplicate crossings; a real miss (zero crossing + no delivery) is INVALID",
            "baseline_min_valid_runs": BASELINE_MIN_VALID_RUNS,
        },
        "provenance": prov,
        "arms": {"daemon_on": on, "daemon_off_A1": off_a1, "daemon_off_A2": off_a2},
        "offload": {
            "metric": "payload (NAR) egress - the kill-criterion metric",
            "payload_egress_daemon_on_mean_bytes": payload_on,
            "payload_egress_daemon_off_mean_bytes": payload_off,
            "net_payload_egress_cut_fraction": offload_frac,
            "total_egress_daemon_on_mean_bytes": total_on,
            "total_egress_daemon_off_mean_bytes": total_off,
            "note": (
                "wave 1 has no p2p: ~0 payload offload is EXPECTED (instrument, "
                "not offload, is validated). Total egress differs only by the "
                "nix-cache-info the daemon serves locally (metadata), which is why "
                "the kill-criterion metric is PAYLOAD egress, not total."
            ),
        },
        "s4_latency": {
            "aa_noise_floor_fraction": noise_floor,
            "s4_threshold_fraction": S4_THRESHOLD,
            "s4_usable": s4_usable,
            "note": (
                "A/A noise floor below the 10% S4 threshold"
                if s4_usable
                else "A/A NOISE FLOOR >= 10%: S4 IS UNUSABLE in this harness (surfaced, not hidden)"
            ),
        },
        "bites": bites,
        "verdict": {
            "all_bites_pass": all_bite,
            "arms_usable": arms_usable,
            "s4_usable": s4_usable,
            "instrument_trustworthy": all_bite and arms_usable,
        },
    }


def print_human_summary(report: dict) -> None:
    p = report["provenance"]
    print(
        "\n===================== measure: HUMAN SUMMARY =====================",
        file=sys.stderr,
    )
    print(
        f"  workload_version : {p['workload_version']} (tier={p['fixture_tier']})",
        file=sys.stderr,
    )
    print(
        f"  counting_rule    : {p['counting_rule_version']} ({p['counting_rule_doc']})",
        file=sys.stderr,
    )
    print(f"  fixture_pubkey   : {p['fixture_public_key']}", file=sys.stderr)
    on = report["arms"]["daemon_on"]
    off = report["arms"]["daemon_off_A1"]
    print(
        f"  payload daemon-on : mean={on['egress_payload_nar_bytes']['mean']} "
        f"p95_wall={on['wall_clock_s']['p95']:.3f}s (valid {on['valid_runs']}/{on['runs']})",
        file=sys.stderr,
    )
    print(
        f"  payload daemon-off: mean={off['egress_payload_nar_bytes']['mean']} "
        f"p95_wall={off['wall_clock_s']['p95']:.3f}s (valid {off['valid_runs']}/{off['runs']})",
        file=sys.stderr,
    )
    print(
        f"  payload offload   : {report['offload']['net_payload_egress_cut_fraction']} "
        f"(wave-1: ~0 expected)",
        file=sys.stderr,
    )
    s4 = report["s4_latency"]
    print(
        f"  A/A noise floor  : {s4['aa_noise_floor_fraction']:.4f} -> S4 usable={s4['s4_usable']}",
        file=sys.stderr,
    )
    gh = on["gap_histogram_ms"]
    print(
        f"  gap histogram    : n={gh['n']} median={gh['median_ms']}ms p95={gh['p95_ms']}ms",
        file=sys.stderr,
    )
    print("  bites:", file=sys.stderr)
    for key, bite in report["bites"].items():
        print(
            f"    {'PASS' if bite['bites'] else 'FAIL'}  {bite['name']}",
            file=sys.stderr,
        )
    v = report["verdict"]
    print(
        f"  VERDICT: instrument_trustworthy={v['instrument_trustworthy']} "
        f"(bites={v['all_bites_pass']} arms_usable={v['arms_usable']} s4_usable={v['s4_usable']})",
        file=sys.stderr,
    )
    print(
        "==================================================================\n",
        file=sys.stderr,
    )


# ---- self-test (pure validator + provenance; no containers) -----------------


def _rec(kind, path, bytes_sent, gap_ms=None):
    r = {"kind": kind, "path": path}
    if bytes_sent is not None:
        r["bytes_sent"] = bytes_sent
    if gap_ms is not None:
        r["gap_ms"] = gap_ms
    return r


def run_self_test() -> int:
    """Pure unit tests of the v2 validator (the codex re-gate's wave-2 shapes) and
    the provenance fail-closed fix. No containers, no nix - safe under `just test`.
    Each check prints PASS/FAIL; returns 0 iff all pass."""
    import tempfile

    A, B = "nar/aaaa.nar", "nar/bbbb.nar"
    sizes = {A: 100, B: 200}
    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        ok = ok and cond
        print(
            f"  {'PASS' if cond else 'FAIL'}  {name}"
            + (f"  [{detail}]" if not cond and detail else "")
        )

    # 1. clean wave-1: each target crosses once, both delivered.
    r = classify_run(
        [_rec("nar", A, 100), _rec("nar", B, 200), _rec("narinfo", "x.narinfo", 10)],
        sizes,
        {A: True, B: True},
        310,
        0,
        0.5,
    )
    check("clean wave-1 (1 crossing/target, delivered) -> VALID", r.valid, r.reason)
    check("clean wave-1 egress_nar == 300", r.egress_nar == 300, str(r.egress_nar))

    # 2. WAVE-2 OFFLOAD shape (the codex correctness case): B served by a peer ->
    #    ZERO proxy crossings for B, but the client delivered it. VALID, and B's
    #    bytes are NOT counted as egress (that is the offload).
    r = classify_run(
        [_rec("nar", A, 100), _rec("narinfo", "x.narinfo", 10)],
        sizes,
        {A: True, B: True},
        110,
        0,
        0.5,
    )
    check("wave-2 offload (B zero-crossing + delivered) -> VALID", r.valid, r.reason)
    check(
        "wave-2 offload counts only A (egress_nar == 100)",
        r.egress_nar == 100,
        str(r.egress_nar),
    )

    # 3. zero-crossing + NOT delivered = a real MISS -> INVALID (the falsifying
    #    mutation of case 2: flip B's delivery to False).
    r = classify_run(
        [_rec("nar", A, 100), _rec("narinfo", "x.narinfo", 10)],
        sizes,
        {A: True, B: False},
        110,
        0,
        0.5,
    )
    check(
        "zero-crossing + undelivered (real miss) -> INVALID",
        not r.valid,
        "unexpectedly valid",
    )

    # 4. duplicate FULL crossing of the same target -> INVALID (double-count guard).
    r = classify_run(
        [_rec("nar", A, 100), _rec("nar", A, 100), _rec("nar", B, 200)],
        sizes,
        {A: True, B: True},
        400,
        0,
        0.5,
    )
    check("duplicate full crossing -> INVALID", not r.valid, "unexpectedly valid")

    # 5. truncated crossing -> INVALID.
    r = classify_run(
        [_rec("nar", A, 50), _rec("nar", B, 200)],
        sizes,
        {A: True, B: True},
        250,
        0,
        0.5,
    )
    check("truncated NAR -> INVALID", not r.valid, "unexpectedly valid")

    # 6. missing bytes_sent (unknown != 0) -> INVALID.
    r = classify_run(
        [_rec("nar", A, None), _rec("nar", B, 200)],
        sizes,
        {A: True, B: True},
        200,
        0,
        0.5,
    )
    check("missing bytes_sent -> INVALID", not r.valid, "unexpectedly valid")

    # 7. proxy_log sum != proxy_stats bytes_sent -> INVALID (real cross-check).
    r = classify_run(
        [_rec("nar", A, 100), _rec("nar", B, 200)],
        sizes,
        {A: True, B: True},
        999,
        0,
        0.5,
    )
    check("log-sum != stats bytes_sent -> INVALID", not r.valid, "unexpectedly valid")

    # 8. client exit != 0 -> INVALID even if crossings look right.
    r = classify_run(
        [_rec("nar", A, 100), _rec("nar", B, 200)],
        sizes,
        {A: True, B: True},
        300,
        1,
        0.5,
    )
    check("client exit nonzero -> INVALID", not r.valid, "unexpectedly valid")

    # 9. PROVENANCE fail-closed (codex blocker 2): preflight_gate threaded with an
    #    unverified --out tree must fail closed (SystemExit nonzero).
    with tempfile.TemporaryDirectory() as d:
        empty = Path(d) / "empty-out"
        empty.mkdir()
        raised_nonzero = False
        try:
            e2e.preflight_gate(empty)
        except SystemExit as ex:
            raised_nonzero = (ex.code or 0) != 0
        check(
            "preflight_gate(--out unverified tree) -> fail-closed",
            raised_nonzero,
            "did not fail closed",
        )

    print(f"\nmeasure --self-test: {'ALL PASS' if ok else 'FAILURES PRESENT'}")
    return 0 if ok else 1


# ---- main -------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--runs",
        type=int,
        default=10,
        help="valid runs per main arm (AC#2 requires >=10; lower only for dev)",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=None,
        help="write the JSON report to this path (always printed to stdout too)",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=fx.repo_root() / "fixtures" / "out",
        help="fixture publication root",
    )
    parser.add_argument(
        "--only-bites",
        action="store_true",
        help="run only the falsifiability bites (skip the slow main arms); for "
        "dev iteration and deep-gate re-checks. Emits no baseline.",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run the pure validator + provenance unit tests (no containers, no "
        "nix) and exit. Wired into `just test`.",
    )
    args = parser.parse_args()

    if args.self_test:
        return run_self_test()

    out_root = args.out.resolve()
    # Provenance fail-closed (codex): verify the SAME tree we are about to measure,
    # not the default one - thread --out into the gate.
    e2e.preflight_gate(out_root)
    fixtures = e2e.resolve_fixtures(out_root)
    image = e2e.load_image()
    e2e.cleanup_pods()

    scratch = Path(os.environ.get("TMPDIR", "/tmp")) / f"nix-p2p-measure-{os.getpid()}"
    scratch.mkdir(parents=True, exist_ok=True)
    ctx = e2e.Ctx(podman=e2e.podman(), image=image, fixtures=fixtures, scratch=scratch)

    if args.runs < 10:
        print(
            f"measure: WARNING runs={args.runs} < 10 - a DEV smoke, NOT a baseline "
            "(AC#2 requires N>=10). The report is marked accordingly.",
            file=sys.stderr,
        )

    try:
        if args.only_bites:
            # No main arms in this mode -> no A/A noise floor; the latency bite
            # proves flag-trips and defers fails-before to a full run.
            bites = run_bites(ctx, fixtures, list(e2e.ALL_ATTRS), args.runs, None, None)
            report = {
                "mode": "only-bites (NOT a baseline)",
                "provenance": provenance(fixtures, out_root),
                "bites": bites,
                "verdict": {
                    "all_bites_pass": all(b["bites"] for b in bites.values()),
                    "arms_usable": None,
                    "s4_usable": None,
                    "instrument_trustworthy": all(b["bites"] for b in bites.values()),
                },
            }
        else:
            report = build_report(ctx, fixtures, out_root, args.runs)
        report["dev_smoke_below_n10"] = args.runs < 10 and not args.only_bites
    finally:
        e2e.cleanup_pods()
        shutil.rmtree(scratch, ignore_errors=True)

    if not args.only_bites:
        print_human_summary(report)
    text = json.dumps(report, indent=2, default=str)
    if args.report:
        args.report.write_text(text + "\n")
        print(f"measure: report written to {args.report}", file=sys.stderr)
    print(text)  # machine-readable report to stdout

    verdict = report["verdict"]
    return 0 if verdict["instrument_trustworthy"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        e2e.cleanup_pods("(interrupted)")
        sys.exit(130)
