#!/usr/bin/env python3
"""Measure the narinfo->nar request gap of a REAL `nix` fetch against a REAL
upstream binary cache (default cache.nixos.org) -- task-35.

WHY THIS EXISTS
---------------
The wave-1 J2 baseline (task-12) measured the narinfo->nar gap over LOOPBACK
against a local mock origin: sub-millisecond (median ~0.5 ms, max < 2 ms). On
those numbers a 1-4 s DHT resolve (PRD risk 3) cannot be hidden in the gap by
prefetch. BUT loopback carries no real RTT; it is not a verdict on the real
internet. This script re-measures the SAME quantity against a real upstream so
wave-2's prefetch-vs-hedge design (task-15) rests on a real number.

WHAT "THE GAP" MEANS (kept identical to the loopback instrument)
----------------------------------------------------------------
The loopback testproxy (`testproxy/src/proxy.rs`) defines, per path:
  * on serving a narinfo, it remembers `Instant::now()` keyed by the nar URL
    that narinfo's `URL:` field points at (last write wins);
  * on serving that nar, gap_ms = now - that remembered instant.
So the gap is a REQUEST-boundary quantity: nar-request-time minus the most
recent preceding narinfo activity for the SAME store path. That is exactly the
lead time a fronting daemon would get to prefetch: it sees the narinfo request,
and the window closes when the nar is demanded.

We reproduce this client-side against the real cache by reading `nix`'s own
`-vvvv` debug log. Every request nix issues emits `starting download of <URL>`;
we timestamp that line at READ time (when our reader sees it), which is a proxy
for the request-issue time. The two differ by nix-side stderr buffering and, in
the noisy NAR phase, reader backpressure -- a per-line lag that is NOT constant
and does NOT fully cancel in a gap. This jitter is order tens of ms: negligible
for the TAIL (seconds) but a real fraction of the HEAD gaps (tens-hundreds ms),
so head numbers are order-of-magnitude, not precise. (`starting download of`
requires `-vvvv`, so the line volume cannot be reduced; this is an inherent
fidelity limit of the log-parsing method, stated not hidden.)

We report TWO anchors so the reader can see both ends:
  * gap_first = nar_start - FIRST narinfo_start for that path
    (the earliest signal a daemon gets -> the best-case prefetch window);
  * gap_last  = nar_start - LAST  narinfo_start for that path
    (matches the loopback instrument's last-write-wins semantics).

PAIRING nar-url -> store path: a nar URL is `nar/<filehash>.nar.<ext>`, whose
filehash is NOT the store-path hash. We recover the mapping the same way the
testproxy does -- by reading each narinfo's `URL:` field -- fetched ONCE out of
band (does not perturb the measured timing).

FORCING A REAL CACHE MISS: we `nix copy --from <cache> --to <fresh temp store>`
with a fresh `XDG_CACHE_HOME` (cold narinfo sqlite) so every narinfo and nar is
actually fetched over the network. `nix copy`'s substitution download path is
the same machinery `nix build` uses to pull a cache-miss closure. We keep the
DEFAULT narinfo TTL so each narinfo is fetched once per run (setting TTL=0 makes
nix redundantly re-fetch each narinfo right before its nar, collapsing the gap
to one RTT -- an artifact, not the realistic first-sight build).

CAVEATS (also printed in the report):
  * One machine's RTT to one Fastly PoP at one time -- not universal.
  * nix downloads with concurrency (http-connections, default 25), so a path's
    gap depends on its queue position; we report the distribution, not a point.
  * The gap scales with closure nar-download duration: a bigger closure's tail
    paths get larger gaps (their narinfo was seen early, their nar is demanded
    late). We measure a small polite closure and reason about scaling.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path

DEFAULT_CACHE = "https://cache.nixos.org"
# hello: ~5-path closure, ~11 MB. Small and polite for a public cache.
DEFAULT_PATH_ATTR = "nixpkgs#hello"

# Kept byte-identical to scripts/measure.py:gap_histogram so the two baselines
# are directly comparable.
HIST_EDGES = [0, 10, 50, 100, 250, 500, 1000, 2000, 5000]

STARTING_RE = re.compile(r"starting download of (\S+)")


def log(msg: str) -> None:
    """Fail-loud progress to stderr; stdout is reserved for the JSON report."""
    print(f"[measure_real_gap] {msg}", file=sys.stderr, flush=True)


@dataclass
class Event:
    t: float  # read-time seconds (monotonic); only differences are meaningful
    url: str
    kind: str  # "narinfo" | "nar" | "cache-info" | "other"


def classify(url: str) -> str:
    tail = url.rsplit("/", 1)[-1]
    if url.endswith(".narinfo"):
        return "narinfo"
    if "/nar/" in url or tail.startswith("nar"):
        return "nar"
    if tail == "nix-cache-info":
        return "cache-info"
    return "other"


def resolve_store_path(attr: str) -> str:
    """Resolve an attr (e.g. nixpkgs#hello) to its .outPath by EVAL only."""
    log(f"resolving {attr} (eval only, no build)")
    out = subprocess.run(
        ["nix", "eval", "--raw", f"{attr}.outPath"],
        capture_output=True,
        text=True,
        timeout=300,
    )
    if out.returncode != 0:
        raise SystemExit(f"could not resolve {attr}: {out.stderr.strip()}")
    path = out.stdout.strip()
    if not path.startswith("/nix/store/"):
        raise SystemExit(f"unexpected outPath for {attr}: {path!r}")
    return path


def run_copy(cache: str, store_path: str) -> list[Event]:
    """One cold-cache `nix copy` of store_path's closure from `cache` into a
    fresh temp store, capturing per-request issue timestamps. Fail-fast on any
    non-zero exit -- a partial fetch would silently bias the gap distribution."""
    dest = Path(tempfile.mkdtemp(prefix="nixstore-realgap-"))
    xdg = Path(tempfile.mkdtemp(prefix="nixcache-realgap-"))
    events: list[Event] = []
    try:
        cmd = [
            "nix",
            "copy",
            "--from",
            cache,
            "--to",
            str(dest),
            store_path,
            "-vvvv",
        ]
        # Inherit PATH etc.; override only the cache home (cold narinfo sqlite).
        full_env = dict(os.environ)
        full_env["XDG_CACHE_HOME"] = str(xdg)
        log(f"nix copy {store_path} -> {dest} (cold XDG_CACHE_HOME)")
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=full_env,
        )
        assert proc.stderr is not None
        for line in proc.stderr:
            m = STARTING_RE.search(line)
            if not m:
                continue
            t = time.monotonic()
            url = m.group(1).strip("'\"")
            events.append(Event(t=t, url=url, kind=classify(url)))
        rc = proc.wait(timeout=600)
        if rc != 0:
            raise SystemExit(
                f"nix copy failed (rc={rc}) -- refusing to report a partial run"
            )
    finally:
        # Store paths are made read-only by nix; chmod before removing.
        subprocess.run(["chmod", "-R", "u+w", str(dest)], capture_output=True)
        shutil.rmtree(dest, ignore_errors=True)
        shutil.rmtree(xdg, ignore_errors=True)
    return events


_narinfo_url_cache: dict[str, str] = {}


def narinfo_nar_basename(cache: str, narinfo_hash: str) -> str | None:
    """Fetch a narinfo ONCE out of band and return the basename of its `URL:`
    (nar path), e.g. '1abc....nar.zst'. Out-of-band: does not perturb timing."""
    if narinfo_hash in _narinfo_url_cache:
        return _narinfo_url_cache[narinfo_hash]
    url = f"{cache}/{narinfo_hash}.narinfo"
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            body = resp.read().decode("utf-8", "replace")
    except Exception as exc:  # noqa: BLE001 -- report, do not swallow
        log(f"WARN could not fetch {url} for pairing: {exc}")
        return None
    for line in body.splitlines():
        if line.startswith("URL:"):
            nar_path = line[4:].strip()  # e.g. nar/<filehash>.nar.zst
            base = nar_path.rsplit("/", 1)[-1]
            _narinfo_url_cache[narinfo_hash] = base
            return base
    log(f"WARN narinfo {narinfo_hash} had no URL: field")
    return None


def hash_from_narinfo_url(url: str) -> str:
    return url.rsplit("/", 1)[-1][: -len(".narinfo")]


def nar_basename_from_url(url: str) -> str:
    return url.rsplit("/", 1)[-1]


def compute_gaps(cache: str, events: list[Event]) -> list[dict]:
    """Per nar request, gap_first/gap_last vs its path's narinfo request(s)."""
    # Build path (nar basename) -> list of narinfo request times.
    narinfo_times: dict[str, list[float]] = {}
    for ev in events:
        if ev.kind != "narinfo":
            continue
        h = hash_from_narinfo_url(ev.url)
        base = narinfo_nar_basename(cache, h)
        if base is None:
            continue
        narinfo_times.setdefault(base, []).append(ev.t)

    gaps: list[dict] = []
    seen_nar: set[str] = set()
    unpaired: list[str] = []
    for ev in events:
        if ev.kind != "nar":
            continue
        base = nar_basename_from_url(ev.url)
        if base in seen_nar:
            continue  # first nar request for this path only
        seen_nar.add(base)
        ni = narinfo_times.get(base)
        if not ni:
            unpaired.append(base)
            continue
        preceding = [t for t in ni if t <= ev.t]
        if not preceding:
            # A nar request timestamped before every narinfo request for the
            # same path violates the two-phase model (clock/ordering anomaly).
            # Surface it, do not silently fold it in.
            log(f"WARN nar {base}: no narinfo request precedes it (ordering anomaly)")
            preceding = ni
        gaps.append(
            {
                "nar": base,
                "gap_first_ms": (ev.t - min(preceding)) * 1000.0,
                "gap_last_ms": (ev.t - max(preceding)) * 1000.0,
            }
        )
    # Fail-fast reconciliation: every NAR request MUST pair to a narinfo, or
    # the histogram silently reports a biased subset. The likeliest cause of a
    # drop is a transient failure of the out-of-band narinfo GET (a Fastly
    # 429/timeout), and a dropped TAIL path would understate max/p95 -- exactly
    # the number the task-35 conclusion rests on. Refuse a partial distribution,
    # same discipline as the non-zero `nix copy` exit.
    if unpaired:
        raise SystemExit(
            f"{len(unpaired)} of {len(seen_nar)} NAR requests failed to pair "
            f"to a narinfo (out-of-band narinfo fetch likely failed): "
            f"{unpaired} -- refusing to report a biased gap distribution"
        )
    return gaps


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return float("nan")
    s = sorted(values)
    if len(s) == 1:
        return s[0]
    rank = (pct / 100.0) * (len(s) - 1)
    lo = int(rank)
    hi = min(lo + 1, len(s) - 1)
    frac = rank - lo
    return s[lo] + (s[hi] - s[lo]) * frac


def histogram(values: list[float]) -> dict:
    buckets = {
        f"[{HIST_EDGES[i]},{HIST_EDGES[i + 1]})": 0 for i in range(len(HIST_EDGES) - 1)
    }
    buckets[f">={HIST_EDGES[-1]}"] = 0
    for v in values:
        placed = False
        for i in range(len(HIST_EDGES) - 1):
            if HIST_EDGES[i] <= v < HIST_EDGES[i + 1]:
                buckets[f"[{HIST_EDGES[i]},{HIST_EDGES[i + 1]})"] += 1
                placed = True
                break
        if not placed:
            buckets[f">={HIST_EDGES[-1]}"] += 1
    return {
        "n": len(values),
        "median_ms": statistics.median(values) if values else None,
        "p95_ms": percentile(values, 95) if values else None,
        "min_ms": min(values) if values else None,
        "max_ms": max(values) if values else None,
        "buckets": buckets,
    }


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--cache", default=DEFAULT_CACHE)
    ap.add_argument(
        "--attr",
        default=DEFAULT_PATH_ATTR,
        help="flake attr to resolve+fetch (default nixpkgs#hello)",
    )
    ap.add_argument(
        "--store-path", default=None, help="explicit /nix/store/... path (skips eval)"
    )
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--json-out", default=None, help="write the full JSON report here")
    args = ap.parse_args()

    store_path = args.store_path or resolve_store_path(args.attr)
    log(f"target closure: {store_path}")
    log(f"cache: {args.cache}   runs: {args.runs}")

    per_run = []
    all_first: list[float] = []
    all_last: list[float] = []
    for i in range(args.runs):
        log(f"--- run {i + 1}/{args.runs} ---")
        events = run_copy(args.cache, store_path)
        gaps = compute_gaps(args.cache, events)
        first = [g["gap_first_ms"] for g in gaps]
        last = [g["gap_last_ms"] for g in gaps]
        all_first += first
        all_last += last
        n_narinfo = sum(1 for e in events if e.kind == "narinfo")
        n_nar = sum(1 for e in events if e.kind == "nar")
        log(
            f"run {i + 1}: {n_narinfo} narinfo reqs, {n_nar} nar reqs, "
            f"{len(gaps)} paired gaps; "
            f"gap_first median={statistics.median(first):.0f}ms "
            f"min={min(first):.0f}ms max={max(first):.0f}ms"
            if gaps
            else f"run {i + 1}: no gaps"
        )
        per_run.append(
            {
                "run": i + 1,
                "n_narinfo_requests": n_narinfo,
                "n_nar_requests": n_nar,
                "gaps": gaps,
            }
        )

    report = {
        "cache": args.cache,
        "store_path": store_path,
        "runs": args.runs,
        "gap_first_ms": histogram(all_first),
        "gap_last_ms": histogram(all_last),
        "loopback_baseline_note": (
            "wave-1 J2 loopback (task-12): median ~0.44-0.57 ms, p95 "
            "~0.73-0.89 ms, max < 2 ms, n=40/arm, all in [0,10) ms bucket."
        ),
        "per_run": per_run,
    }

    print(json.dumps(report, indent=2))
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(report, indent=2))
        log(f"wrote {args.json_out}")

    gf = report["gap_first_ms"]
    log("=== SUMMARY (gap_first = best-case prefetch window) ===")
    log(
        f"n={gf['n']}  median={gf['median_ms']:.0f}ms  p95={gf['p95_ms']:.0f}ms  "
        f"min={gf['min_ms']:.0f}ms  max={gf['max_ms']:.0f}ms"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
