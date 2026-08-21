#!/usr/bin/env python3
"""TASK-282 AC#3 value-thesis harness: peer vs CDN, unit-labelled + float-free.

WHY THIS EXISTS
---------------
docs/status.md "A verdict on the value thesis" was open: whether peers usefully
beat or supplement a CDN was unmeasured on a real network. This harness closes
the CDN arm on the REAL internet and re-derives an honest, magnitude-bounded
verdict from raw captures. It has three subcommands:

  cdn       -- measure the REAL cache.nixos.org over verified TLS from the host
               dev shell (confirmed reachable; see scripts/measure_real_gap.py,
               task-35). Per store path, per run: the COMPRESSED transport bytes
               actually downloaded and the wall clock, plus the narinfo-declared
               UNCOMPRESSED NarSize. Writes raw per-run captures under
               evidence/task-282/cdn/.

  finalize  -- re-derive the verdict from the RAW captures on disk (never a
               self-reported summary). Fails CLOSED on missing/zero/NaN captures.
               Emits evidence/task-282/verdict.json.

  --self-test (on finalize) -- prove the finalizer BITES: a mutation harness that
               feeds it degenerate captures (empty, zero-byte, NaN) and asserts
               it refuses. A finalizer that cannot reject drift is false
               assurance (memory: rederivability-verifier-fail-open-traps).

WHAT IS AND IS NOT MEASURED (the crux; codex NOGO fix)
------------------------------------------------------
The MEASURED quantitative finding is the CDN's COMPRESSION ratio: uncompressed
NarSize : actually-downloaded compressed transport bytes, on the real cache. That
is a compression-ratio finding, NOT a peer-vs-CDN transport comparison. The
shipped daemon's /nar peer transport is ITSELF zstd-COMPRESSED on the wire
(fabric-libp2p /nar/4), so a peer's wire bytes are comparable to the CDN's
compressed bytes, NOT to the uncompressed NAR size. This harness does NOT measure
the peer's wire bytes, so it makes NO peer-vs-CDN transport verdict. The value
thesis stays UNPROVEN (cf. the shaped-link table in docs/profiling.md: peer-zstd
vs CDN-xz is near-parity / link-speed-dependent).

Every quantity is suffix-labelled: uncompressed_nar_bytes (narinfo NarSize),
compressed_transport_bytes (measured CDN .nar.<ext> download), wall_clock_ns
(integer ns; display mirror *_ms). Never compare uncompressed to compressed as if
equal, and never read the CDN compression ratio as a peer-vs-CDN gap.

FAIL-CLOSED (memory: rederivability-verifier-fail-open-traps)
-------------------------------------------------------------
finalize re-derives from the RAW captures on disk (never a self-report) and fails
CLOSED: a MANIFEST pins the exact store-path cohort + run count; a malformed
capture RAISES (never a silent skip); the cohort must match the manifest exactly
and be unique; provenance (real_internet/tls_verified) is DERIVED from the actual
endpoint and cross-checked, never trusted from the asserted boolean; a
present-but-invalid peer capture fails rather than being called 'unmeasured'; and
the byte-weighted aggregate must lie within the per-path [min,max]. The
`--self-test` mutation harness proves each of these bites.

NO FLOATS IN A GATE/SERIALIZED FIELD (owner rule; scripts/check-no-floats.py)
----------------------------------------------------------------------------
Ratios are carried as an EXACT rational num/denom and compared by
cross-multiplication. Byte counts and durations are integers. Floats appear only
in terminal *_display/*_ms report fields. This module is in the guard's SCANNED
list.

MAGNITUDE, NOT SIGN (memory: noise-dominated-measurement-frame-by-magnitude)
----------------------------------------------------------------------------
The peer arm (a hermetic KVM VM link, synthetic payload) and the CDN arm (the
host over the public internet, real paths) run in DIFFERENT environments and
DIFFERENT content -- not a paired trial. The harness NEVER claims a sign or a
delta between them; each wall clock is a separate labelled magnitude.
"""

from __future__ import annotations

import argparse
import json
import math
import ssl
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "evidence" / "task-282"
CDN_DIR = EVIDENCE / "cdn"
PEER_DIR = EVIDENCE / "peer"

DEFAULT_CACHE = "https://cache.nixos.org"
# The ONE canonical real upstream. A capture may claim real_internet ONLY if its
# endpoint host is exactly this over https; the finalizer enforces it fail-closed.
REAL_CACHE_HOST = "cache.nixos.org"
STORE = Path("/nix/store")

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_CANNOT_CHECK = 2


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _tls_context() -> ssl.SSLContext:
    """A default context that VERIFIES the full chain (no skip-verify)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def _http_get(url: str, ctx: ssl.SSLContext) -> tuple[int, bytes]:
    """GET url over verified TLS; return (status, body)."""
    req = urllib.request.Request(url, headers={"User-Agent": "nix-p2p-value-thesis"})
    with urllib.request.urlopen(req, context=ctx, timeout=60) as resp:
        return resp.status, resp.read()


# --------------------------------------------------------------------------
# CDN arm: REAL cache.nixos.org over verified TLS
# --------------------------------------------------------------------------


@dataclass
class NarInfo:
    store_hash: str
    nar_url: str  # e.g. nar/<filehash>.nar.xz
    compression: str
    uncompressed_nar_bytes: int  # NarSize
    declared_compressed_bytes: int  # FileSize (declared, verified against download)


def parse_narinfo(store_hash: str, text: str) -> NarInfo:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        if ": " in line:
            key, _, value = line.partition(": ")
            fields[key.strip()] = value.strip()
    nar_url = fields["URL"]
    return NarInfo(
        store_hash=store_hash,
        nar_url=nar_url,
        compression=fields.get("Compression", "unknown"),
        uncompressed_nar_bytes=int(fields["NarSize"]),
        declared_compressed_bytes=int(fields["FileSize"]),
    )


def fetch_narinfo(cache: str, store_hash: str, ctx: ssl.SSLContext) -> NarInfo | None:
    url = f"{cache}/{store_hash}.narinfo"
    try:
        status, body = _http_get(url, ctx)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError):
        return None
    if status != 200:
        return None
    return parse_narinfo(store_hash, body.decode("utf-8", "replace"))


def _store_hash_of(name: str) -> str | None:
    """The 32-char store hash prefix of a /nix/store basename, or None."""
    head = name.split("-", 1)[0]
    if len(head) == 32 and head.isalnum() and head.islower():
        return head
    return None


def discover_paths(
    cache: str, want: int, ctx: ssl.SSLContext, max_compressed_bytes: int
) -> list[str]:
    """Pick `want` local store paths whose narinfo resolves on the real cache,
    spanning small->large REALISTIC sizes and each under `max_compressed_bytes`
    (bound the download on a shared box). A greedy first-fit over a sorted store
    listing biases to tiny alphabetically-early paths, so instead COLLECT a
    bounded sample of resolving candidates, then SELECT `want` of them spread
    evenly across the observed uncompressed-size range. Deterministic: sorted
    listing + a fixed probe budget. Returns store-hash strings."""
    candidates: list[tuple[int, str]] = []  # (uncompressed_nar_bytes, store_hash)
    probed = 0
    for entry in sorted(STORE.iterdir()):
        if probed >= 600:
            break
        store_hash = _store_hash_of(entry.name)
        if store_hash is None:
            continue
        probed += 1
        info = fetch_narinfo(cache, store_hash, ctx)
        if info is None or info.declared_compressed_bytes > max_compressed_bytes:
            continue
        candidates.append((info.uncompressed_nar_bytes, store_hash))
    if not candidates:
        return []
    candidates.sort()
    if len(candidates) <= want:
        return [store_hash for _, store_hash in candidates]
    # Even index spread across the sorted-by-size candidates (smallest..largest).
    picks: list[str] = []
    for i in range(want):
        idx = (i * (len(candidates) - 1)) // (want - 1) if want > 1 else 0
        picks.append(candidates[idx][1])
    # De-duplicate while preserving order (spread may collide on a tiny sample).
    seen: set[str] = set()
    out: list[str] = []
    for store_hash in picks:
        if store_hash not in seen:
            seen.add(store_hash)
            out.append(store_hash)
    return out


def measure_cdn_download(
    cache: str, info: NarInfo, ctx: ssl.SSLContext
) -> tuple[int, int]:
    """Download the compressed NAR once; return (compressed_transport_bytes,
    wall_clock_ns). Streams and counts actual bytes on the wire."""
    url = f"{cache}/{info.nar_url}"
    req = urllib.request.Request(url, headers={"User-Agent": "nix-p2p-value-thesis"})
    start = time.monotonic_ns()
    total = 0
    with urllib.request.urlopen(req, context=ctx, timeout=120) as resp:
        while True:
            chunk = resp.read(1 << 16)
            if not chunk:
                break
            total += len(chunk)
    elapsed_ns = time.monotonic_ns() - start
    return total, elapsed_ns


def classify_endpoint(cache: str) -> tuple[bool, bool, str]:
    """Derive provenance from the ACTUAL endpoint, never assert it. Returns
    (real_internet, tls_verified, host). real_internet is true ONLY for the
    canonical real cache over https; tls_verified is true ONLY over https (we
    always use a full-chain-verifying context). A localhost/http fixture is thus
    honestly labelled real_internet=false / tls_verified=false and cannot be
    relabelled 'verified real'."""
    parsed = urllib.parse.urlsplit(cache)
    scheme = parsed.scheme.lower()
    host = parsed.hostname or ""
    tls_verified = scheme == "https"
    real_internet = tls_verified and host == REAL_CACHE_HOST
    return real_internet, tls_verified, host


def run_cdn(
    cache: str,
    store_hashes: list[str],
    runs: int,
    max_compressed_bytes: int,
    paths: int,
) -> int:
    ctx = _tls_context()
    if not store_hashes:
        print(f"discovering store paths resolvable on {cache} ...", file=sys.stderr)
        store_hashes = discover_paths(cache, paths, ctx, max_compressed_bytes)
    if not store_hashes:
        print("value-thesis cdn: no resolvable store paths found", file=sys.stderr)
        return EXIT_FAIL

    real_internet, tls_verified, host_ep = classify_endpoint(cache)
    CDN_DIR.mkdir(parents=True, exist_ok=True)
    host = _hostname()
    manifest_hashes: list[str] = []
    for store_hash in store_hashes:
        info = fetch_narinfo(cache, store_hash, ctx)
        if info is None:
            print(f"  skip {store_hash}: narinfo did not resolve", file=sys.stderr)
            continue
        if info.declared_compressed_bytes > max_compressed_bytes:
            print(
                f"  skip {store_hash}: {info.declared_compressed_bytes} compressed "
                f"bytes exceeds the {max_compressed_bytes} cap",
                file=sys.stderr,
            )
            continue
        runs_out = []
        for run_idx in range(runs):
            xfer_bytes, elapsed_ns = measure_cdn_download(cache, info, ctx)
            runs_out.append(
                {
                    "run_idx": run_idx,
                    "compressed_transport_bytes": xfer_bytes,
                    "wall_clock_ns": elapsed_ns,
                    "wall_clock_ms_display": elapsed_ns / 1_000_000,
                }
            )
            print(
                f"  {store_hash} run {run_idx}: "
                f"{xfer_bytes} compressed_transport_bytes in "
                f"{elapsed_ns / 1_000_000:.1f} ms",
                file=sys.stderr,
            )
        capture = {
            "arm": "cdn",
            # PROVENANCE derived from the actual endpoint (classify_endpoint), never
            # asserted -- the finalizer re-reads and cross-checks these.
            "real_internet": real_internet,
            "fixture": not real_internet,
            "cache": cache,
            "endpoint_host": host_ep,
            "tls_verified": tls_verified,
            "host": host,
            "utc": _utc_now(),
            "store_hash": store_hash,
            "runs_declared": runs,
            "narinfo": asdict(info),
            "uncompressed_nar_bytes": info.uncompressed_nar_bytes,
            "declared_compressed_bytes": info.declared_compressed_bytes,
            "runs": runs_out,
        }
        out = CDN_DIR / f"{store_hash}.json"
        out.write_text(json.dumps(capture, indent=2, sort_keys=True) + "\n")
        manifest_hashes.append(store_hash)
        print(f"  wrote {out}", file=sys.stderr)

    if not manifest_hashes:
        print("value-thesis cdn: no captures written", file=sys.stderr)
        return EXIT_FAIL
    # The MANIFEST is the fail-closed contract the finalizer enforces: the exact set
    # of store paths, the run count, and the endpoint/provenance the captures MUST
    # match. A partial or tampered capture set no longer produces a green verdict.
    manifest = {
        "arm": "cdn",
        "cache": cache,
        "endpoint_host": host_ep,
        "real_internet": real_internet,
        "tls_verified": tls_verified,
        "runs": runs,
        "store_hashes": sorted(manifest_hashes),
        "n_paths": len(manifest_hashes),
        "utc": _utc_now(),
    }
    (CDN_DIR / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    )
    print(
        f"value-thesis cdn: wrote {len(manifest_hashes)} capture(s) + manifest "
        f"under {CDN_DIR} (real_internet={real_internet}, tls_verified={tls_verified})"
    )
    return EXIT_OK


def _hostname() -> str:
    try:
        return Path("/proc/sys/kernel/hostname").read_text().strip()
    except OSError:
        return "unknown"


# --------------------------------------------------------------------------
# finalize: re-derive the verdict from RAW captures (fail closed)
# --------------------------------------------------------------------------


def _finite_positive_int(value: object) -> bool:
    """A capture field must be a finite, positive INTEGER byte/ns count. Rejects
    bool, float, NaN, inf, zero and negatives -- the fail-closed guard."""
    if isinstance(value, bool):
        return False
    if isinstance(value, float):
        return False
    if not isinstance(value, int):
        return False
    return value > 0


def _load_captures(
    directory: Path, exclude: frozenset[str] = frozenset()
) -> list[dict]:
    """Load every *.json capture (except `exclude` basenames). FAIL-CLOSED: a
    malformed/unreadable JSON RAISES ValueError rather than being silently skipped
    (a skipped capture is exactly how a partial set masqueraded as complete)."""
    if not directory.is_dir():
        return []
    out = []
    for path in sorted(directory.glob("*.json")):
        if path.name in exclude:
            continue
        try:
            out.append(json.loads(path.read_text()))
        except (OSError, json.JSONDecodeError) as error:
            raise ValueError(f"malformed/unreadable capture {path}: {error}") from error
    return out


@dataclass
class ArmTotals:
    n_captures: int
    n_runs: int
    total_transport_bytes: int  # compressed for cdn, uncompressed for peer
    total_uncompressed_nar_bytes: int
    min_wall_clock_ns: int
    max_wall_clock_ns: int
    # (uncompressed_nar_bytes, transport_bytes) per path -- the DISTRIBUTION, so a
    # single large near-incompressible path cannot dominate a byte-weighted sum
    # ratio and hide the typical per-path spread.
    per_path: list[tuple[int, int]]
    # Peer-arm discovery latency (kad get_providers / mDNS first-peer), integer ns.
    # None for the CDN arm (a CDN has no peer-discovery step). >=0 (a warm walk can be
    # sub-ms -> 0 integer ms).
    discovery_min_ns: int | None = None
    discovery_max_ns: int | None = None


def rederive_cdn(captures: list[dict], expected_runs: int) -> ArmTotals | None:
    """Re-derive CDN totals from raw captures. Returns None (fail closed) on ANY
    missing/zero/NaN/malformed field, a missing narinfo/declared size, or a run
    count that does not match `expected_runs` -- never a partial or clamped total."""
    n_runs = 0
    total_transport = 0
    total_uncompressed = 0
    min_ns = None
    max_ns = 0
    per_path: list[tuple[int, int]] = []
    for cap in captures:
        uncompressed = cap.get("uncompressed_nar_bytes")
        if not _finite_positive_int(uncompressed):
            return None
        # the narinfo + its declared compressed size must be present (a capture that
        # dropped them cannot be trusted as a real cache measurement).
        narinfo = cap.get("narinfo")
        if not isinstance(narinfo, dict) or "nar_url" not in narinfo:
            return None
        if not _finite_positive_int(cap.get("declared_compressed_bytes")):
            return None
        total_uncompressed += uncompressed
        runs = cap.get("runs")
        if not isinstance(runs, list) or len(runs) != expected_runs:
            return None
        path_transport: int | None = None
        for run in runs:
            xfer = run.get("compressed_transport_bytes")
            wall = run.get("wall_clock_ns")
            if not _finite_positive_int(xfer) or not _finite_positive_int(wall):
                return None
            # every run downloads the SAME file, so its compressed size is
            # constant across runs; a drift means a corrupted capture -> reject.
            if path_transport is None:
                path_transport = xfer
            elif xfer != path_transport:
                return None
            n_runs += 1
            min_ns = wall if min_ns is None else min(min_ns, wall)
            max_ns = max(max_ns, wall)
        if path_transport is None:
            return None
        # Accumulate the transport size ONCE PER PATH (the unique NAR), NOT once per
        # run: a byte-weighted uncompressed:compressed ratio must divide the sum of
        # unique uncompressed sizes by the sum of unique compressed sizes. Summing
        # compressed over every redundant run inflates the denominator by the run
        # count and drives the ratio below its own per-path minimum (impossible).
        total_transport += path_transport
        per_path.append((uncompressed, path_transport))
    if n_runs == 0 or min_ns is None:
        return None
    return ArmTotals(
        n_captures=len(captures),
        n_runs=n_runs,
        total_transport_bytes=total_transport,
        total_uncompressed_nar_bytes=total_uncompressed,
        min_wall_clock_ns=min_ns,
        max_wall_clock_ns=max_ns,
        per_path=per_path,
    )


def rederive_peer(captures: list[dict]) -> ArmTotals | None:
    """Re-derive peer totals from raw VM captures. A peer moves the UNCOMPRESSED
    NAR, so transport == uncompressed here. Fail closed on any bad field."""
    n_runs = 0
    total_uncompressed = 0
    min_ns = None
    max_ns = 0
    disc_min = None
    disc_max = 0
    for cap in captures:
        uncompressed = cap.get("uncompressed_nar_bytes")
        if not _finite_positive_int(uncompressed):
            return None
        runs = cap.get("runs")
        if not isinstance(runs, list) or not runs:
            return None
        for run in runs:
            transfer = run.get("transfer_wall_clock_ns")
            discovery = run.get("discovery_wall_clock_ns")
            if not _finite_positive_int(transfer):
                return None
            # discovery latency must be present and finite (>=0 allowed: a warm
            # cache can discover in <1ms, but the field must exist and be a
            # non-negative integer, never a float/NaN).
            if isinstance(discovery, bool) or not isinstance(discovery, int):
                return None
            if isinstance(discovery, float) or discovery < 0:
                return None
            total_uncompressed += uncompressed
            n_runs += 1
            min_ns = transfer if min_ns is None else min(min_ns, transfer)
            max_ns = max(max_ns, transfer)
            disc_min = discovery if disc_min is None else min(disc_min, discovery)
            disc_max = max(disc_max, discovery)
    if n_runs == 0 or min_ns is None:
        return None
    return ArmTotals(
        n_captures=len(captures),
        n_runs=n_runs,
        total_transport_bytes=total_uncompressed,
        total_uncompressed_nar_bytes=total_uncompressed,
        min_wall_clock_ns=min_ns,
        max_wall_clock_ns=max_ns,
        per_path=[],
        discovery_min_ns=disc_min,
        discovery_max_ns=disc_max,
    )


def _gcd_reduce(num: int, denom: int) -> tuple[int, int]:
    g = math.gcd(num, denom) or 1
    return num // g, denom // g


def _ratio_dict(num: int, denom: int) -> dict:
    rnum, rdenom = _gcd_reduce(num, denom)
    return {
        "num": rnum,
        "denom": rdenom,
        "display": rnum / rdenom,
    }


class _RatioKey:
    """A sort key over (uncompressed, compressed) that orders by the EXACT
    rational uncompressed/compressed using cross-multiplication -- no float."""

    __slots__ = ("u", "c")

    def __init__(self, pair: tuple[int, int]) -> None:
        self.u, self.c = pair

    def __lt__(self, other: _RatioKey) -> bool:
        return self.u * other.c < other.u * self.c


def per_path_ratio_stats(per_path: list[tuple[int, int]]) -> dict:
    """Per-path uncompressed:compressed ratios (exact rationals), ordered by
    cross-multiplication so no float ordering creeps in. Reports MIN, MAX and
    ALL points -- NOT a "median" (at this sample size a single middle element is
    not a meaningful central tendency; showing every point is the honest form).
    This is the DISTRIBUTION behind the byte-weighted aggregate."""
    ordered = sorted(per_path, key=_RatioKey)
    lo_u, lo_c = ordered[0]
    hi_u, hi_c = ordered[-1]
    return {
        "n_paths": len(ordered),
        "min_uncompressed_over_compressed": _ratio_dict(lo_u, lo_c),
        "max_uncompressed_over_compressed": _ratio_dict(hi_u, hi_c),
        "all_uncompressed_over_compressed": [
            {
                "uncompressed_nar_bytes": u,
                "compressed_transport_bytes": c,
                **_ratio_dict(u, c),
            }
            for u, c in ordered
        ],
    }


def check_aggregate_within_distribution(cdn: ArmTotals) -> None:
    """Fail CLOSED if the byte-weighted aggregate ratio falls OUTSIDE the observed
    per-path [min, max]. A weighted mean of positive ratios must lie within their
    range; a violation means the numerator and denominator were summed over
    DIFFERENT counts (the per-run vs per-path aggregation bug). All-integer
    cross-multiplication, no float. Raises ValueError on violation."""
    a_u = cdn.total_uncompressed_nar_bytes
    a_c = cdn.total_transport_bytes
    ordered = sorted(cdn.per_path, key=_RatioKey)
    lo_u, lo_c = ordered[0]
    hi_u, hi_c = ordered[-1]
    # min <= aggregate:  lo_u/lo_c <= a_u/a_c  <=>  lo_u*a_c <= a_u*lo_c
    if lo_u * a_c > a_u * lo_c:
        raise ValueError(
            f"aggregate ratio {a_u}/{a_c} is BELOW the per-path minimum "
            f"{lo_u}/{lo_c} -- impossible for a weighted mean; the numerator and "
            "denominator were summed over different counts (aggregation bug)"
        )
    # aggregate <= max:  a_u/a_c <= hi_u/hi_c  <=>  a_u*hi_c <= hi_u*a_c
    if a_u * hi_c > hi_u * a_c:
        raise ValueError(
            f"aggregate ratio {a_u}/{a_c} is ABOVE the per-path maximum "
            f"{hi_u}/{hi_c} -- impossible for a weighted mean (aggregation bug)"
        )


def build_verdict(
    cdn: ArmTotals,
    peer: ArmTotals | None,
    real_internet: bool,
    tls_verified: bool,
    cache: str,
) -> dict:
    """Assemble the float-free verdict dict. The ONLY measured quantitative finding
    is the CDN's COMPRESSION ratio (uncompressed NarSize : compressed transport on
    the real cache) -- NOT a peer-vs-CDN comparison. The shipped /nar peer transport
    is itself zstd-COMPRESSED on the wire, so the peer's wire bytes are comparable to
    the CDN's compressed bytes, NOT to the uncompressed NAR size; this harness does
    NOT measure the peer's wire bytes, so it makes NO peer-vs-CDN transport verdict
    (the value thesis stays UNPROVEN). Provenance is passed in from the validated
    endpoint, never hardcoded."""
    # Fail closed before emitting a headline number that violates its own bounds.
    check_aggregate_within_distribution(cdn)
    ratio_num, ratio_denom = _gcd_reduce(
        cdn.total_uncompressed_nar_bytes, cdn.total_transport_bytes
    )
    verdict: dict = {
        "task": "TASK-282 AC#3",
        "utc": _utc_now(),
        # The MEASURED finding: how much the cache compresses NARs. A compression
        # ratio, not a peer-vs-CDN transport verdict.
        "cdn_compression": {
            "note": (
                "How much the cache compresses NARs: uncompressed NarSize : "
                "actually-downloaded compressed transport bytes, exact rational, on "
                f"{'real cache.nixos.org over verified TLS' if real_internet else 'a FIXTURE endpoint'}. "
                "This is a COMPRESSION-ratio finding. It is NOT a peer-vs-CDN "
                "transport comparison -- the peer's shipped transport is ALSO "
                "compressed (see peer_vs_cdn_transport)."
            ),
            "aggregate_note": (
                "The aggregate is BYTE-WEIGHTED (sum of unique uncompressed sizes "
                "over sum of unique compressed sizes), so the LARGEST paths dominate "
                "it. Read per_path_distribution for every point."
            ),
            "uncompressed_over_compressed_ratio_num": ratio_num,
            "uncompressed_over_compressed_ratio_denom": ratio_denom,
            "uncompressed_over_compressed_ratio_display": ratio_num / ratio_denom,
            "cdn_total_unique_compressed_transport_bytes": cdn.total_transport_bytes,
            "cdn_total_unique_uncompressed_nar_bytes": cdn.total_uncompressed_nar_bytes,
            "per_path_distribution": per_path_ratio_stats(cdn.per_path),
        },
        # The crux honesty statement: no peer-vs-CDN transport verdict is made.
        "peer_vs_cdn_transport": {
            "measured": False,
            "value_thesis": "UNPROVEN",
            "reason": (
                "The shipped daemon's /nar peer transport is zstd-COMPRESSED on the "
                "wire (fabric-libp2p /nar/4; zstd above ~1 KiB), so a peer's wire "
                "bytes are comparable to the CDN's compressed bytes, NOT to the "
                "uncompressed NAR size. An honest comparison would be peer-zstd vs "
                "CDN-xz (near-parity / link-speed-dependent, cf. the shaped-link "
                "table in docs/profiling.md). This harness measured the CDN's "
                "compressed transport and the NAR's uncompressed size, but did NOT "
                "measure the peer's wire bytes, so it asserts NO peer-vs-CDN "
                "transport ratio. Do not read cdn_compression as a peer-vs-CDN gap."
            ),
        },
        "cdn_arm": {
            "real_internet": real_internet,
            "fixture": not real_internet,
            "cache": cache,
            "tls_verified": tls_verified,
            "n_captures": cdn.n_captures,
            "n_runs": cdn.n_runs,
            "min_wall_clock_ns": cdn.min_wall_clock_ns,
            "max_wall_clock_ns": cdn.max_wall_clock_ns,
            "min_wall_clock_ms_display": cdn.min_wall_clock_ns / 1_000_000,
            "max_wall_clock_ms_display": cdn.max_wall_clock_ns / 1_000_000,
        },
    }
    if peer is None:
        verdict["peer_arm"] = {
            "measured": False,
            "residual": (
                "peer arm not measured in this slice. Byte-identical peer transfer "
                "across a real KVM VM link (NarHash-verified) is separately GATED in "
                "nixos/nat-vm-test.nix and nixos/value-thesis-vm-test.nix."
            ),
        }
        return verdict

    disc_min = peer.discovery_min_ns if peer.discovery_min_ns is not None else 0
    disc_max = peer.discovery_max_ns if peer.discovery_max_ns is not None else 0
    verdict["peer_arm"] = {
        "measured": True,
        "kind": "existence-proof",
        "environment": "hermetic KVM VM link (multi-host beyond netns)",
        "content": "synthetic locally-generated payload (NOT real upstream content)",
        "byte_identity": "NarHash-verified byte-identical peer fetch (VM byte oracle)",
        "n_captures": peer.n_captures,
        "n_runs": peer.n_runs,
        # discovery latency (kad get_providers / mDNS first-peer) is PART of the peer
        # path -- surfaced so the peer cost is not hidden inside the transfer.
        "discovery_min_wall_clock_ns": disc_min,
        "discovery_max_wall_clock_ns": disc_max,
        "discovery_min_wall_clock_ms_display": disc_min / 1_000_000,
        "discovery_max_wall_clock_ms_display": disc_max / 1_000_000,
        "transfer_min_wall_clock_ns": peer.min_wall_clock_ns,
        "transfer_max_wall_clock_ns": peer.max_wall_clock_ns,
        "transfer_min_wall_clock_ms_display": peer.min_wall_clock_ns / 1_000_000,
        "transfer_max_wall_clock_ms_display": peer.max_wall_clock_ns / 1_000_000,
        # This is the NAR's UNCOMPRESSED size -- NOT the peer's wire transport, which
        # is zstd-compressed (~5.8 KB for this payload) and was NOT measured here.
        "uncompressed_nar_bytes": peer.total_uncompressed_nar_bytes,
        "wire_transport_bytes": "UNMEASURED (zstd-compressed /nar/4)",
        "note": (
            "n=1 warm refetch of ONE synthetic payload -- an existence proof, not a "
            "distribution and not a wire-byte measurement."
        ),
    }
    # Cross-environment: the peer arm (hermetic KVM VM link, synthetic payload) and
    # the CDN arm (host over the public internet) are DIFFERENT environments AND
    # DIFFERENT content -- not a paired trial. The harness computes no peer-vs-CDN
    # difference; a subtraction of two unrelated magnitudes would invite exactly the
    # paired-trial misreading this avoids (memory: noise-dominated-measurement).
    verdict["wall_clock_comparison"] = {
        "comparable": False,
        "reason": (
            "peer (hermetic KVM VM link, synthetic payload) and CDN (host over the "
            "public internet, real paths) are different environments AND different "
            "content -- not a paired trial. No sign, no delta; read cdn_arm and "
            "peer_arm as separate magnitudes."
        ),
    }
    return verdict


def _load_json(path: Path) -> dict | None:
    if not path.is_file():
        return None
    return json.loads(path.read_text())


def validate_cdn_cohort(manifest: dict, captures: list[dict]) -> str | None:
    """FAIL-CLOSED cohort + provenance check. Returns an error string on any
    violation (missing manifest field, capture set != manifest, duplicate paths,
    provenance disagreement, or a real-internet claim whose endpoint is not the
    real cache), else None. This is what makes a partial/tampered/relabelled
    capture set exit non-zero instead of emitting a green verdict."""
    expected = manifest.get("store_hashes")
    runs = manifest.get("runs")
    cache = manifest.get("cache")
    if not isinstance(expected, list) or not expected:
        return "manifest has no store_hashes"
    if not isinstance(runs, int) or runs < 1:
        return "manifest runs is not a positive integer"
    if not isinstance(cache, str) or not cache:
        return "manifest has no cache endpoint"

    got = [c.get("store_hash") for c in captures]
    if any(not isinstance(h, str) for h in got):
        return "a cdn capture lacks a string store_hash"
    if len(set(got)) != len(got):
        return f"duplicate store paths in cdn captures: {sorted(got)}"
    if sorted(got) != sorted(expected):
        return (
            f"cdn capture set {sorted(got)} does not match the manifest "
            f"{sorted(expected)} (missing or extra captures)"
        )

    # Provenance is DERIVED from the actual endpoint, never trusted from the boolean.
    real_derived, tls_derived, _host = classify_endpoint(cache)
    if manifest.get("real_internet") != real_derived:
        return (
            f"manifest real_internet={manifest.get('real_internet')} disagrees with "
            f"the endpoint {cache} (derived real_internet={real_derived})"
        )
    if manifest.get("tls_verified") != tls_derived:
        return (
            f"manifest tls_verified={manifest.get('tls_verified')} disagrees with "
            f"the endpoint {cache} (derived tls_verified={tls_derived})"
        )
    for cap in captures:
        if cap.get("cache") != cache:
            return f"capture {cap.get('store_hash')} endpoint != manifest endpoint"
        if cap.get("real_internet") != real_derived:
            return f"capture {cap.get('store_hash')} real_internet mislabelled"
        if cap.get("tls_verified") != tls_derived:
            return f"capture {cap.get('store_hash')} tls_verified mislabelled"
        if len(cap.get("runs", [])) != runs:
            return f"capture {cap.get('store_hash')} run count != manifest runs"
    return None


def run_finalize() -> int:
    # 1. the CDN manifest is the fail-closed contract; malformed/missing -> non-zero.
    try:
        manifest = _load_json(CDN_DIR / "manifest.json")
    except (OSError, json.JSONDecodeError) as error:
        print(
            f"value-thesis finalize: malformed cdn manifest: {error}", file=sys.stderr
        )
        return EXIT_FAIL
    if manifest is None:
        print(
            f"value-thesis finalize: NO cdn manifest under {CDN_DIR} -- run "
            "`just value-thesis-cdn` first (fail closed)",
            file=sys.stderr,
        )
        return EXIT_FAIL

    # 2. load captures FAIL-CLOSED (a malformed JSON raises, never a silent skip).
    try:
        cdn_caps = _load_captures(CDN_DIR, exclude=frozenset({"manifest.json"}))
        peer_caps = _load_captures(PEER_DIR)
    except ValueError as error:
        print(f"value-thesis finalize: {error} (fail closed)", file=sys.stderr)
        return EXIT_FAIL

    # 3. cohort + provenance: the set must EXACTLY match the manifest, be unique, and
    #    carry provenance that matches the actual endpoint.
    cohort_error = validate_cdn_cohort(manifest, cdn_caps)
    if cohort_error is not None:
        print(
            f"value-thesis finalize: cohort/provenance check FAILED: {cohort_error} "
            "-- refusing to emit a verdict (fail closed)",
            file=sys.stderr,
        )
        return EXIT_FAIL

    # 4. re-derive the CDN totals from raw, strict on the manifest run count.
    cdn = rederive_cdn(cdn_caps, manifest["runs"])
    if cdn is None:
        print(
            "value-thesis finalize: a cdn capture had a missing/zero/NaN field or a "
            "wrong run count -- refusing to emit a verdict (fail closed)",
            file=sys.stderr,
        )
        return EXIT_FAIL

    # 5. peer arm: present-but-invalid FAILS CLOSED; genuinely absent is 'unmeasured'.
    peer: ArmTotals | None = None
    if peer_caps:
        peer = rederive_peer(peer_caps)
        if peer is None:
            print(
                "value-thesis finalize: peer capture(s) present but INVALID "
                "(missing/zero/NaN transfer or discovery) -- refusing to emit a peer "
                "verdict (fail closed)",
                file=sys.stderr,
            )
            return EXIT_FAIL

    real_internet, tls_verified, _host = classify_endpoint(manifest["cache"])
    try:
        verdict = build_verdict(
            cdn, peer, real_internet, tls_verified, manifest["cache"]
        )
    except ValueError as error:
        print(
            f"value-thesis finalize: internal aggregate-bounds check FAILED: "
            f"{error} -- refusing to emit a verdict (fail closed)",
            file=sys.stderr,
        )
        return EXIT_FAIL
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    out = EVIDENCE / "verdict.json"
    out.write_text(json.dumps(verdict, indent=2, sort_keys=True) + "\n")

    comp = verdict["cdn_compression"]
    dist = comp["per_path_distribution"]
    lo = dist["min_uncompressed_over_compressed"]
    hi = dist["max_uncompressed_over_compressed"]
    label = (
        "REAL cache.nixos.org, verified TLS"
        if real_internet
        else f"FIXTURE ({manifest['cache']})"
    )
    print(f"value-thesis verdict -> {out}")
    print(
        f"  COMPRESSION on {label}: over {dist['n_paths']} paths, cache NARs "
        f"compress uncompressed:compressed by {lo['num']}/{lo['denom']} "
        f"(~{lo['display']:.2f}x) to {hi['num']}/{hi['denom']} "
        f"(~{hi['display']:.2f}x). This is a COMPRESSION-ratio finding, not a "
        "peer-vs-CDN verdict."
    )
    print(
        "  PEER-vs-CDN TRANSPORT: UNMEASURED -- the shipped /nar peer transport is "
        "zstd-COMPRESSED, so peer wire bytes are comparable to (not several times) "
        "the CDN's compressed bytes; this harness did not measure the peer wire "
        "bytes. The value thesis remains UNPROVEN."
    )
    if peer is None:
        print("  peer arm: not measured (existence proof absent)")
    else:
        print(
            "  peer arm: existence proof only -- a byte-identical NarHash-verified "
            "peer fetch over a real VM link (discovery + transfer are time "
            "magnitudes, NOT wire-byte measurements)."
        )
    return EXIT_OK


# --------------------------------------------------------------------------
# self-test: prove the finalizer BITES (fail closed on drift)
# --------------------------------------------------------------------------


def _cdn_cap(
    store_hash: str,
    uncompressed: int,
    compressed: int,
    runs: int = 1,
    cache: str = DEFAULT_CACHE,
    real_internet: bool = True,
    tls_verified: bool = True,
) -> dict:
    """A well-formed CDN capture for the mutation harness (all required fields)."""
    return {
        "arm": "cdn",
        "store_hash": store_hash,
        "cache": cache,
        "real_internet": real_internet,
        "tls_verified": tls_verified,
        "uncompressed_nar_bytes": uncompressed,
        "declared_compressed_bytes": compressed,
        "narinfo": {"nar_url": f"nar/{store_hash}.nar.xz"},
        "runs": [
            {"compressed_transport_bytes": compressed, "wall_clock_ns": 5_000_000}
            for _ in range(runs)
        ],
    }


def _bv(cdn: ArmTotals, peer: ArmTotals | None) -> dict:
    """build_verdict with the canonical real-cache provenance (test shorthand)."""
    return build_verdict(cdn, peer, True, True, DEFAULT_CACHE)


def self_test() -> list[str]:  # noqa: C901 - a flat list of mutation bites
    failures: list[str] = []

    # --- rederive_cdn field-level fail-closed -------------------------------
    if rederive_cdn([], 1) is not None:
        failures.append("rederive_cdn accepted EMPTY captures")
    if rederive_cdn([_cdn_cap("a", 1000, 300)], 1) is None:
        failures.append("rederive_cdn REJECTED a well-formed capture")
    zero = _cdn_cap("a", 1000, 300)
    zero["runs"][0]["compressed_transport_bytes"] = 0
    if rederive_cdn([zero], 1) is not None:
        failures.append("rederive_cdn accepted a ZERO-byte transport run")

    # a bad wall clock injected via subscript (not a dict LITERAL) so the source
    # itself does not trip check-no-floats.py Rule B on the _ns key.
    for label, bad in (("NaN", float("nan")), ("float", 5_000_000.0)):
        cap = _cdn_cap("a", 1000, 300)
        cap["runs"][0]["wall_clock_ns"] = bad
        if rederive_cdn([cap], 1) is not None:
            failures.append(f"rederive_cdn accepted a {label} wall clock")

    noruns = _cdn_cap("a", 1000, 300)
    noruns["runs"] = []
    if rederive_cdn([noruns], 1) is not None:
        failures.append("rederive_cdn accepted a capture with NO runs")

    # wrong run count vs the expected manifest count -> reject.
    if rederive_cdn([_cdn_cap("a", 1000, 300, runs=1)], 2) is not None:
        failures.append("rederive_cdn accepted a run count != expected")

    # missing narinfo / declared_compressed_bytes -> reject.
    nonar = _cdn_cap("a", 1000, 300)
    del nonar["narinfo"]
    if rederive_cdn([nonar], 1) is not None:
        failures.append("rederive_cdn accepted a capture with NO narinfo")
    nodecl = _cdn_cap("a", 1000, 300)
    del nodecl["declared_compressed_bytes"]
    if rederive_cdn([nodecl], 1) is not None:
        failures.append("rederive_cdn accepted a capture with NO declared size")

    # --- peer fail-closed ---------------------------------------------------
    peer_nodisc = {
        "uncompressed_nar_bytes": 2000,
        "runs": [{"transfer_wall_clock_ns": 9_000_000}],
    }
    if rederive_peer([peer_nodisc]) is not None:
        failures.append("rederive_peer accepted a run with NO discovery latency")
    peer_good = {
        "uncompressed_nar_bytes": 2000,
        "runs": [
            {"transfer_wall_clock_ns": 9_000_000, "discovery_wall_clock_ns": 1_200_000}
        ],
    }
    if rederive_peer([peer_good]) is None:
        failures.append("rederive_peer REJECTED a well-formed peer capture")

    # --- exact-rational ratio + naming --------------------------------------
    cdn = rederive_cdn([_cdn_cap("a", 1000, 300)], 1)
    assert cdn is not None
    comp = _bv(cdn, None)["cdn_compression"]
    if comp["uncompressed_over_compressed_ratio_num"] != 10:
        failures.append("ratio num wrong: 1000/300 must reduce to 10/3")
    if comp["uncompressed_over_compressed_ratio_denom"] != 3:
        failures.append("ratio denom wrong: 1000/300 must reduce to 10/3")

    # --- multi-run aggregation (the per-run/per-path bug) -------------------
    cdn_mr = rederive_cdn([_cdn_cap("a", 1000, 300, runs=3)], 3)
    assert cdn_mr is not None
    if cdn_mr.total_transport_bytes != 300:
        failures.append(
            "multi-run aggregation bug: total_transport summed per RUN "
            f"({cdn_mr.total_transport_bytes}) not per PATH (300)"
        )
    comp_mr = _bv(cdn_mr, None)["cdn_compression"]
    if (
        comp_mr["uncompressed_over_compressed_ratio_num"] != 10
        or comp_mr["uncompressed_over_compressed_ratio_denom"] != 3
    ):
        failures.append("multi-run aggregate ratio drifted from the single-path 10/3")

    # --- aggregate-bounds invariant fails closed ----------------------------
    bad_totals = ArmTotals(
        n_captures=2,
        n_runs=2,
        total_transport_bytes=100,  # inflated denominator -> aggregate below min
        total_uncompressed_nar_bytes=110,
        min_wall_clock_ns=1,
        max_wall_clock_ns=1,
        per_path=[(70, 10), (40, 10)],  # per-path ratios 7 and 4; agg 110/100=1.1
    )
    try:
        _bv(bad_totals, None)
        failures.append(
            "build_verdict ACCEPTED an aggregate below the per-path minimum"
        )
    except ValueError:
        pass

    # --- cohort + provenance fail-closed (validate_cdn_cohort) --------------
    caps = [_cdn_cap("a", 1000, 300), _cdn_cap("b", 2000, 500)]
    manifest_ok = {
        "cache": DEFAULT_CACHE,
        "real_internet": True,
        "tls_verified": True,
        "runs": 1,
        "store_hashes": ["a", "b"],
    }
    if validate_cdn_cohort(manifest_ok, caps) is not None:
        failures.append("validate_cdn_cohort REJECTED a matching cohort")
    # missing a capture the manifest expects.
    if validate_cdn_cohort(manifest_ok, [caps[0]]) is None:
        failures.append("cohort accepted a MISSING capture (partial set)")
    # an extra capture not in the manifest.
    extra = caps + [_cdn_cap("c", 3000, 700)]
    if validate_cdn_cohort(manifest_ok, extra) is None:
        failures.append("cohort accepted an EXTRA capture")
    # duplicate store paths.
    if validate_cdn_cohort(manifest_ok, [caps[0], _cdn_cap("a", 1000, 300)]) is None:
        failures.append("cohort accepted DUPLICATE store paths")
    # provenance: manifest claims real over an http fixture endpoint.
    fixture_manifest = {
        "cache": "http://127.0.0.1:8080",
        "real_internet": True,  # a LIE -- endpoint is http localhost
        "tls_verified": True,
        "runs": 1,
        "store_hashes": ["a"],
    }
    fixture_cap = _cdn_cap(
        "a", 1000, 300, cache="http://127.0.0.1:8080", real_internet=True
    )
    if validate_cdn_cohort(fixture_manifest, [fixture_cap]) is None:
        failures.append("cohort accepted a FIXTURE endpoint mislabelled real_internet")
    # a capture whose endpoint disagrees with the manifest.
    mism = _cdn_cap("a", 1000, 300, cache="https://evil.example")
    if validate_cdn_cohort(manifest_ok, [mism, caps[1]]) is None:
        failures.append("cohort accepted a capture endpoint != manifest endpoint")

    # --- endpoint classifier ------------------------------------------------
    if classify_endpoint(DEFAULT_CACHE) != (True, True, REAL_CACHE_HOST):
        failures.append("classify_endpoint mis-classified the real cache")
    if classify_endpoint("http://127.0.0.1:8080")[0]:
        failures.append("classify_endpoint called an http localhost real_internet")
    if classify_endpoint("https://evil.example")[0]:
        failures.append("classify_endpoint called a non-cache host real_internet")

    # --- malformed capture RAISES (never silently skipped) -----------------
    with tempfile.TemporaryDirectory() as tmp:
        bad = Path(tmp) / "broken.json"
        bad.write_text("{not json")
        try:
            _load_captures(Path(tmp))
            failures.append("_load_captures SILENTLY SKIPPED a malformed capture")
        except ValueError:
            pass

    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_cdn = sub.add_parser("cdn", help="measure REAL cache.nixos.org over TLS")
    p_cdn.add_argument("--cache", default=DEFAULT_CACHE)
    p_cdn.add_argument("--runs", type=int, default=5)
    p_cdn.add_argument(
        "--paths",
        type=int,
        default=15,
        help="how many size-stratified store paths to auto-discover (default 15)",
    )
    p_cdn.add_argument(
        "--max-compressed-bytes",
        type=int,
        default=32 * 1024 * 1024,
        help="skip paths whose compressed NAR exceeds this (bound on shared box)",
    )
    p_cdn.add_argument(
        "store_hashes",
        nargs="*",
        help="store-hash prefixes to measure (default: auto-discover 3)",
    )

    p_fin = sub.add_parser("finalize", help="re-derive the verdict from captures")
    p_fin.add_argument(
        "--self-test",
        action="store_true",
        help="run the fail-closed mutation harness, then exit",
    )

    args = parser.parse_args()

    if args.cmd == "cdn":
        return run_cdn(
            args.cache,
            args.store_hashes,
            args.runs,
            args.max_compressed_bytes,
            args.paths,
        )
    if args.cmd == "finalize":
        if args.self_test:
            failures = self_test()
            if failures:
                for failure in failures:
                    print(f"value-thesis self-test FAILED: {failure}", file=sys.stderr)
                return EXIT_CANNOT_CHECK
            print("value-thesis finalize self-test: green (fail-closed guards bite)")
            return EXIT_OK
        return run_finalize()
    return EXIT_FAIL


if __name__ == "__main__":
    sys.exit(main())
