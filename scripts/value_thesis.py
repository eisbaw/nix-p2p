#!/usr/bin/env python3
"""TASK-282 AC#3 / TASK-298 value-thesis harness: peer vs CDN, unit-labelled + float-free.

WHY THIS EXISTS
---------------
docs/status.md "A verdict on the value thesis" was open: whether peers usefully
beat or supplement a CDN was unmeasured on a real network. This harness measures
the peer's ACTUAL /nar/4 transport bytes and the CDN's compressed download for the
SAME real store paths, and re-derives an honest, magnitude-bounded verdict from raw
captures. It has three subcommands:

  cdn       -- measure the REAL cache.nixos.org over verified TLS from the host
               dev shell. Per store path, per run: the COMPRESSED transport bytes
               actually downloaded and the wall clock, plus the narinfo NarSize and
               NarHash. Writes raw per-run captures under evidence/task-282/cdn/.
               `--cohort-from-peer` measures EXACTLY the peer cohort (fail-closed:
               a required path that will not resolve fails the run, never a partial).

  finalize  -- re-derive the verdict from the RAW captures on disk (never a
               self-reported summary). Fails CLOSED. Emits verdict.json (and
               INVALIDATES a prior verdict FIRST, so a failed run leaves no stale
               green capstone).

  --self-test (on finalize) -- prove the finalizer BITES: a mutation harness that
               feeds it degenerate/tampered captures and asserts it refuses.

WHAT IS MEASURED (the value thesis; codex-confirmed number)
-----------------------------------------------------------
The peer arm captures the shipped daemon's OWN /nar/4 `response_protocol_bytes`
(per-64-KiB-leaf zstd-3 + Bao proof + framing) served over a real multi-host KVM
link; the CDN arm downloads the compressed `.nar.zst` object for the SAME store
paths (joined by store_hash). Both are COMPRESSED transport bytes for the same NAR,
so the peer:CDN ratio is apples-to-apples -- NOT the uncompressed NarSize.

This is an APPLICATION-LAYER comparison: `response_protocol_bytes` excludes TCP/IP,
Noise, yamux, retransmits and the request, and the CDN figure is the HTTP object
body -- do not read either as NIC/link traffic. The finding is a near-parity
MAGNITUDE band (SAMPLE-level, small reference-free cohort), never a wall-clock sign;
the SPEED comparison stays UNPROVEN pending nix's parallel CDN download path.

Every quantity is suffix-labelled: uncompressed_nar_bytes (narinfo NarSize),
compressed_transport_bytes / peer_wire_transport_bytes (COMPRESSED transport),
wall_clock_ns (integer ns; display mirror *_ms).

FAIL-CLOSED (memory: rederivability-verifier-fail-open-traps)
-------------------------------------------------------------
finalize re-derives from RAW captures and fails CLOSED: a MANIFEST pins the exact
cohort + run count; a malformed capture RAISES; provenance (real_internet/
tls_verified) is DERIVED from the endpoint, never trusted; each arm's arm/kind/
codec/level/provenance fields are VALIDATED (a wrong-slot or relabelled capture is
rejected); the CDN declared FileSize must EQUAL the measured download; the peer,
CDN and manifest cohorts must be the IDENTICAL store-hash set (no set intersection);
per path the NarSize AND NarHash must match across arms (byte-identity is load-
bearing); the compression aggregate must lie within its per-path [min,max]; and a
failed run INVALIDATES the verdict. The `--self-test` mutation harness proves each
of these bites.

NO FLOATS IN A GATE/SERIALIZED FIELD (owner rule; scripts/check-no-floats.py)
----------------------------------------------------------------------------
Ratios are carried as an EXACT rational num/denom and compared by
cross-multiplication. Byte counts and durations are integers. Floats appear only
in terminal *_display/*_ms report fields. This module is in the guard's SCANNED
list.

MAGNITUDE, NOT SIGN (memory: noise-dominated-measurement-frame-by-magnitude)
----------------------------------------------------------------------------
The peer arm (a real KVM LAN VM link) and the CDN arm (the host over the public
internet) run on DIFFERENT links -- not a paired trial. The harness NEVER claims a
sign or a delta between their wall clocks; the BYTES comparison is the load-bearing,
link-independent finding.
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

# The peer arm's DECLARED transport contract, enforced fail-closed on every peer
# capture (a raw/zstd-19/wrong-arm capture must be REJECTED, not silently accepted).
# EXPECTED_SERVE_ZSTD_LEVEL mirrors peer-fabric/src/codec.rs DEFAULT_ZSTD_LEVEL.
EXPECTED_PEER_WIRE_CODEC = "zstd"
EXPECTED_SERVE_ZSTD_LEVEL = 3
EXPECTED_PEER_KIND = "real-transport-measurement"
NAR_HASH_PREFIX = "sha256:"

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
    nar_hash: str  # NarHash (sha256:...) -- the cross-arm content-identity key


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
        nar_hash=fields["NarHash"],
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
    require_all: bool = False,
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
    # Start FRESH: a cdn run measures ONE cohort. Stale captures from a different cohort
    # would make the finalizer's cohort check reject the set (extra capture) -- fail-closed
    # but confusing. Clear old captures + manifest so this run's cohort is the whole set.
    for stale in CDN_DIR.glob("*.json"):
        stale.unlink()
    host = _hostname()
    manifest_hashes: list[str] = []
    for store_hash in store_hashes:
        info = fetch_narinfo(cache, store_hash, ctx)
        if info is None:
            # HIGH-1: when the caller REQUIRES the whole cohort (the value-thesis
            # --cohort-from-peer join), a path that does not resolve must FAIL the run,
            # never be silently dropped into a smaller manifest than the peer arm.
            if require_all:
                print(
                    f"value-thesis cdn: REQUIRED cohort path {store_hash} did not "
                    f"resolve on {cache} -- refusing a partial cohort (fail closed)",
                    file=sys.stderr,
                )
                return EXIT_FAIL
            print(f"  skip {store_hash}: narinfo did not resolve", file=sys.stderr)
            continue
        if info.declared_compressed_bytes > max_compressed_bytes:
            if require_all:
                print(
                    f"value-thesis cdn: REQUIRED cohort path {store_hash} exceeds the "
                    f"{max_compressed_bytes}-byte cap ({info.declared_compressed_bytes})"
                    " -- refusing a partial cohort (fail closed)",
                    file=sys.stderr,
                )
                return EXIT_FAIL
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


def peer_cohort_hashes() -> list[str]:
    """The store hashes the peer arm captured (evidence/task-282/peer/*.json). The
    peer VM is the single source of truth for the value-thesis cohort; the CDN arm
    follows it via `--cohort-from-peer` so both arms carry IDENTICAL content and the
    finalizer can join them. Returns a sorted unique list; empty if no peer captures.
    Raises ValueError (fail closed) on a malformed capture -- never a silent skip."""
    captures = _load_captures(PEER_DIR)
    hashes: set[str] = set()
    for cap in captures:
        store_hash = cap.get("store_hash")
        if isinstance(store_hash, str) and store_hash:
            hashes.add(store_hash)
    return sorted(hashes)


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
    total_transport_bytes: int  # compressed-CDN transport, or peer zstd /nar/4 wire
    total_uncompressed_nar_bytes: int
    min_wall_clock_ns: int
    max_wall_clock_ns: int
    # (uncompressed_nar_bytes, transport_bytes) per path -- the DISTRIBUTION, so a
    # single large near-incompressible path cannot dominate a byte-weighted sum
    # ratio and hide the typical per-path spread.
    per_path: list[tuple[int, int]]
    # store_hash -> (uncompressed_nar_bytes, transport_bytes, nar_hash). The keyed view
    # used to JOIN the two arms on IDENTICAL content (same store path): the CDN arm's
    # compressed download vs the peer arm's real /nar/4 zstd wire bytes for the very same
    # NAR. The NarHash makes byte-identity load-bearing -- the join REQUIRES the peer and
    # CDN NarHash to match, so a capture cannot claim identity it does not have.
    by_hash: dict[str, tuple[int, int, str]]
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
    by_hash: dict[str, tuple[int, int, str]] = {}
    for cap in captures:
        if cap.get("arm") != "cdn":
            return None  # a non-cdn capture in the cdn slot -> reject
        uncompressed = cap.get("uncompressed_nar_bytes")
        if not _finite_positive_int(uncompressed):
            return None
        # the narinfo + its declared compressed size + NarHash must be present (a
        # capture that dropped them cannot be trusted as a real cache measurement).
        narinfo = cap.get("narinfo")
        if not isinstance(narinfo, dict) or "nar_url" not in narinfo:
            return None
        nar_hash = narinfo.get("nar_hash")
        if not isinstance(nar_hash, str) or not nar_hash.startswith(NAR_HASH_PREFIX):
            return None
        declared = cap.get("declared_compressed_bytes")
        if not _finite_positive_int(declared):
            return None
        store_hash = cap.get("store_hash")
        if not isinstance(store_hash, str) or not store_hash:
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
        # The narinfo's DECLARED FileSize must EQUAL the measured download bytes; a
        # capture whose declared size disagrees with what was actually transferred is
        # corrupt/tampered -> reject (do not trust either number in isolation).
        if declared != path_transport:
            return None
        # Accumulate the transport size ONCE PER PATH (the unique NAR), NOT once per
        # run: a byte-weighted uncompressed:compressed ratio must divide the sum of
        # unique uncompressed sizes by the sum of unique compressed sizes. Summing
        # compressed over every redundant run inflates the denominator by the run
        # count and drives the ratio below its own per-path minimum (impossible).
        total_transport += path_transport
        per_path.append((uncompressed, path_transport))
        if store_hash in by_hash:
            return None  # duplicate store hash within the CDN captures
        by_hash[store_hash] = (uncompressed, path_transport, nar_hash)
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
        by_hash=by_hash,
    )


def rederive_peer(captures: list[dict]) -> ArmTotals | None:
    """Re-derive peer totals from raw VM captures. TASK-298: each capture carries the
    REAL on-the-wire `peer_wire_transport_bytes` -- the shipped `/nar/4` response
    protocol bytes (per-leaf zstd + Bao proof + framing) that the provider actually
    emitted over the real multi-host VM link, NOT the uncompressed NarSize. This is
    the quantity the value thesis compares to the CDN's compressed transport. Fail
    closed on any missing/zero/NaN/float field, a missing store_hash, or a duplicate
    store hash."""
    n_runs = 0
    total_uncompressed = 0
    total_wire = 0
    min_ns = None
    max_ns = 0
    disc_min = None
    disc_max = 0
    per_path: list[tuple[int, int]] = []
    by_hash: dict[str, tuple[int, int, str]] = {}
    for cap in captures:
        # PROVENANCE + CODEC are load-bearing: read them, do not trust the hardcoded
        # verdict text. A capture in the wrong slot (arm), of the wrong kind, with the
        # wrong codec/level, or claiming public-internet provenance (the peer arm is a
        # hermetic VM), is REJECTED -- so the verdict's "real KVM link / zstd-3 /
        # byte-identical" claims cannot be asserted over a mutated capture.
        if cap.get("arm") != "peer":
            return None
        if cap.get("kind") != EXPECTED_PEER_KIND:
            return None
        if cap.get("wire_codec") != EXPECTED_PEER_WIRE_CODEC:
            return None
        level = cap.get("serve_zstd_level")
        if (
            not isinstance(level, int)
            or isinstance(level, bool)
            or level != EXPECTED_SERVE_ZSTD_LEVEL
        ):
            return None
        # The peer arm is a hermetic VM: it must NOT claim public-internet provenance
        # (a localhost/real-internet-relabelled capture must not become a real verdict).
        if cap.get("real_internet") is not False or cap.get("fixture") is not True:
            return None
        nar_hash = cap.get("nar_hash")
        if not isinstance(nar_hash, str) or not nar_hash.startswith(NAR_HASH_PREFIX):
            return None
        uncompressed = cap.get("uncompressed_nar_bytes")
        if not _finite_positive_int(uncompressed):
            return None
        # The REAL peer wire transport (integer bytes, > 0). This is what makes the
        # peer-vs-CDN transport comparison honest: measured wire bytes, not NarSize.
        wire = cap.get("peer_wire_transport_bytes")
        if not _finite_positive_int(wire):
            return None
        store_hash = cap.get("store_hash")
        if not isinstance(store_hash, str) or not store_hash:
            return None
        if store_hash in by_hash:
            return None  # duplicate store hash within the peer captures
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
            n_runs += 1
            min_ns = transfer if min_ns is None else min(min_ns, transfer)
            max_ns = max(max_ns, transfer)
            disc_min = discovery if disc_min is None else min(disc_min, discovery)
            disc_max = max(disc_max, discovery)
        # Accumulate transport ONCE PER PATH (the unique NAR), not once per run.
        total_uncompressed += uncompressed
        total_wire += wire
        per_path.append((uncompressed, wire))
        by_hash[store_hash] = (uncompressed, wire, nar_hash)
    if n_runs == 0 or min_ns is None:
        return None
    return ArmTotals(
        n_captures=len(captures),
        n_runs=n_runs,
        total_transport_bytes=total_wire,
        total_uncompressed_nar_bytes=total_uncompressed,
        min_wall_clock_ns=min_ns,
        max_wall_clock_ns=max_ns,
        per_path=per_path,
        by_hash=by_hash,
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


def _ratio_ge_one(num: int, denom: int) -> bool:
    """num/denom >= 1 by integer cross-multiplication (denom > 0). No float."""
    return num >= denom


def build_peer_vs_cdn(
    peer: ArmTotals, cdn: ArmTotals, declared_cohort: frozenset[str]
) -> dict:
    """TASK-298: the value-thesis JOIN. For every store path in the cohort, compare the
    peer's REAL `/nar/4` zstd wire transport bytes to the CDN's REAL compressed-download
    transport bytes -- IDENTICAL content, so this is a true apples-to-apples transport
    comparison, not the NarSize unit error.

    FAIL-CLOSED cohort (not a set intersection). The peer cohort, the CDN cohort AND the
    declared CDN manifest cohort must be the EXACT SAME store_hash set; ANY missing or
    extra path on either arm RAISES (a smaller silent measurement is exactly the
    fail-open codex caught). Per path it also RAISES if the uncompressed NarSize OR the
    NarHash disagrees between the arms -- the arms would then NOT carry the same content
    and any ratio would be a lie; byte-identity is thereby load-bearing.

    Every quantity is exact-integer / exact-rational. The finding is stated as a
    MAGNITUDE band (min..max of the per-path peer:CDN ratio), never a wall-clock sign."""
    peer_set = frozenset(peer.by_hash)
    cdn_set = frozenset(cdn.by_hash)
    if peer_set != cdn_set or peer_set != declared_cohort:
        raise ValueError(
            "cohort mismatch: the peer, CDN and declared-manifest store-hash sets must "
            f"be IDENTICAL. peer={sorted(peer_set)} cdn={sorted(cdn_set)} "
            f"manifest={sorted(declared_cohort)} -- refusing a partial/smaller "
            "measurement (fail closed)"
        )
    shared = sorted(peer_set)
    per_path = []
    total_peer_wire = 0
    total_cdn_transport = 0
    ratios: list[tuple[int, int]] = []  # (peer_wire, cdn_transport) per shared path
    for store_hash in shared:
        peer_unc, peer_wire, peer_hash = peer.by_hash[store_hash]
        cdn_unc, cdn_transport, cdn_hash = cdn.by_hash[store_hash]
        if peer_unc != cdn_unc:
            raise ValueError(
                f"content mismatch for {store_hash}: peer uncompressed_nar_bytes "
                f"{peer_unc} != cdn {cdn_unc} -- the arms are NOT the same content, "
                "refusing to compare their transport bytes"
            )
        if peer_hash != cdn_hash:
            raise ValueError(
                f"NarHash mismatch for {store_hash}: peer {peer_hash} != cdn {cdn_hash}"
                " -- byte-identity is claimed but false; refusing to compare"
            )
        total_peer_wire += peer_wire
        total_cdn_transport += cdn_transport
        ratios.append((peer_wire, cdn_transport))
        per_path.append(
            {
                "store_hash": store_hash,
                "uncompressed_nar_bytes": peer_unc,
                "peer_wire_transport_bytes": peer_wire,
                "cdn_compressed_transport_bytes": cdn_transport,
                # peer:CDN transport ratio (exact rational). >1 => peer moves MORE
                # bytes than the CDN for this NAR; ~1 => parity; <1 => peer moves fewer.
                **{
                    f"peer_over_cdn_{k}": v
                    for k, v in _ratio_dict(peer_wire, cdn_transport).items()
                },
            }
        )
    ordered = sorted(ratios, key=_RatioKey)  # orders by peer/cdn cross-multiplication
    lo_p, lo_c = ordered[0]
    hi_p, hi_c = ordered[-1]
    # Classify by INTEGER comparison of the band endpoints to 1 (no float, no sign on a
    # noisy wall clock -- this is a byte-count magnitude, exact).
    all_ge_one = _ratio_ge_one(lo_p, lo_c)  # smallest ratio >= 1 => every path >= 1
    all_le_one = hi_p <= hi_c  # largest ratio <= 1 => every path <= 1
    if all_ge_one:
        finding = (
            "SUPPLEMENT: on every compared path the peer's /nar/4 zstd wire transport "
            "is >= the CDN's compressed transport (peers move comparable-to-MORE bytes, "
            "not fewer). The peer's value is locality / offload / CDN-independence, NOT "
            "a transport-byte win. The gap is the fast per-serve zstd-3 the peer "
            "regenerates on the fly vs the cache's once-off high-level whole-NAR zstd."
        )
        headline = "SUPPLEMENT_NOT_FEWER_BYTES"
    elif all_le_one:
        finding = (
            "BEAT: on every compared path the peer's /nar/4 zstd wire transport is <= "
            "the CDN's compressed transport."
        )
        headline = "BEAT_ON_BYTES"
    else:
        finding = (
            "MIXED / near-parity: the peer beats the CDN on transport bytes for some "
            "paths and loses for others; read the per-path band."
        )
        headline = "MIXED_NEAR_PARITY"
    return {
        "measured": True,
        "value_thesis": headline,
        "finding": finding,
        "comparison": (
            "peer_wire_transport_bytes (the peer's /nar/4 APPLICATION-response protocol "
            "bytes: per-64-KiB-leaf zstd-3 + Bao proof + framing, from the provider serve "
            "over a real multi-host KVM link) : cdn_compressed_transport_bytes (the CDN's "
            "compressed-OBJECT bytes downloaded from cache.nixos.org over verified TLS) -- "
            "IDENTICAL content per store_hash (uncompressed NarSize AND NarHash asserted "
            "equal across arms)."
        ),
        "layer_note": (
            "APPLICATION-LAYER comparison, not NIC/link traffic. Both counts exclude "
            "transport framing: the peer figure is /nar/4 response_protocol_bytes and "
            "EXCLUDES TCP/IP, Noise, yamux, retransmits and the 33-byte request; the CDN "
            "figure is the HTTP compressed-object body and excludes TCP/IP/TLS framing. A "
            "fair application-layer comparison -- do not read it as on-the-wire NIC bytes."
        ),
        "units_note": (
            "Both sides are COMPRESSED transport bytes for the SAME NAR (apples to "
            "apples). This is NOT the uncompressed NarSize and NOT a compression ratio."
        ),
        "n_paths_compared": len(shared),
        "peer_total_wire_transport_bytes": total_peer_wire,
        "cdn_total_compressed_transport_bytes": total_cdn_transport,
        # The MAGNITUDE band of the per-path peer:CDN transport ratio (exact rationals).
        "peer_over_cdn_min": _ratio_dict(lo_p, lo_c),
        "peer_over_cdn_max": _ratio_dict(hi_p, hi_c),
        # Byte-weighted aggregate (largest NARs dominate); read the band + per_path for spread.
        "peer_over_cdn_aggregate": _ratio_dict(total_peer_wire, total_cdn_transport),
        "per_path": per_path,
    }


def build_verdict(
    cdn: ArmTotals,
    peer: ArmTotals | None,
    real_internet: bool,
    tls_verified: bool,
    cache: str,
    declared_cohort: frozenset[str] = frozenset(),
) -> dict:
    """Assemble the float-free verdict dict. Two findings:
    * cdn_compression -- how much cache.nixos.org compresses NARs (a compression
      ratio; uncompressed NarSize : compressed transport on the real cache).
    * peer_vs_cdn_transport -- TASK-298: the value thesis itself. When a peer arm is
      present, `build_peer_vs_cdn` JOINS it to the CDN arm and REQUIRES the peer, CDN
      and declared-manifest cohorts to be identical (else it RAISES, fail closed);
      absent a peer arm the thesis stays UNPROVEN. Provenance is passed in from the
      validated endpoint, never hardcoded."""
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
        # TASK-298: the value thesis. Default UNPROVEN; replaced by the measured JOIN
        # below when the peer arm carries real /nar/4 wire bytes for shared paths.
        "peer_vs_cdn_transport": {
            "measured": False,
            "value_thesis": "UNPROVEN",
            "reason": (
                "No peer arm carrying REAL /nar/4 wire bytes for a store path the CDN "
                "arm also measured was present, so no peer-vs-CDN transport ratio is "
                "asserted. Do not read cdn_compression as a peer-vs-CDN gap: the peer's "
                "shipped /nar/4 transport is itself zstd-compressed, so its wire bytes "
                "are comparable to the CDN's compressed bytes, not to the NarSize."
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
        "kind": "real-transport-measurement",
        "environment": "real 3-node KVM LAN VM link (router+provider+consumer, mDNS+kad); multi-host beyond netns",
        "content": "real cache.nixos.org store paths (identical to the CDN arm, joined by store_hash)",
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
        # The REAL measured /nar/4 zstd wire transport (per-leaf zstd-3 + Bao proof),
        # summed over the cohort. This is the value-thesis quantity, NOT the NarSize.
        "total_wire_transport_bytes": peer.total_transport_bytes,
        "uncompressed_nar_bytes": peer.total_uncompressed_nar_bytes,
    }
    # TASK-298: JOIN the arms on IDENTICAL content and emit the measured verdict. RAISES
    # (fail closed) if the peer/CDN/manifest cohorts are not the exact same set, or if a
    # path's NarSize or NarHash disagrees between arms. Always measured when it returns.
    verdict["peer_vs_cdn_transport"] = build_peer_vs_cdn(peer, cdn, declared_cohort)
    # Wall clocks stay MAGNITUDE-only, never a sign. The peer transfer time (real VM
    # link) and the CDN download time (single TCP stream over the public internet) are
    # separate magnitudes measured on different links; the CDN wall clock is a
    # SINGLE-STREAM lower bound on nix's real throughput (nix fetches with parallel
    # connections + keep-alive, so a distant Fastly edge's single-stream bandwidth-
    # delay-product does NOT bound nix's aggregate), so it must NOT drive a
    # "peer beats CDN on speed" claim. The load-bearing finding is the BYTES
    # comparison (peer_vs_cdn_transport), which is link-independent.
    verdict["wall_clock_comparison"] = {
        "comparable": False,
        "reason": (
            "peer transfer (real KVM VM link) and CDN download (single TCP stream over "
            "the public internet) are different links -- not a paired trial. The CDN "
            "wall clock is a SINGLE-STREAM lower bound on nix's real (parallel) CDN "
            "throughput and must not drive a speed-win claim. No sign, no delta; read "
            "the wall clocks as separate magnitudes. The load-bearing, link-independent "
            "finding is peer_vs_cdn_transport (BYTES)."
        ),
    }
    return verdict


def _load_json(path: Path) -> dict | None:
    if not path.is_file():
        return None
    return json.loads(path.read_text())


def _invalidate_verdict() -> None:
    """Delete any existing verdict.json so a FAILED re-run cannot leave a stale green
    capstone on disk (MED-2). Called at the very start of `run_finalize`; only a fully
    successful run re-writes it. Idempotent."""
    verdict_path = EVIDENCE / "verdict.json"
    if verdict_path.exists():
        verdict_path.unlink()


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
    # 0. INVALIDATE any prior verdict FIRST (MED-2): every early return below is a
    #    failure, and none of them may leave a stale measured=true verdict.json behind.
    #    Only a fully successful run re-writes it at the end.
    _invalidate_verdict()

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
    declared_cohort = frozenset(manifest.get("store_hashes", []))
    try:
        verdict = build_verdict(
            cdn, peer, real_internet, tls_verified, manifest["cache"], declared_cohort
        )
    except ValueError as error:
        print(
            f"value-thesis finalize: aggregate-bounds or cohort/identity check FAILED: "
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
    pvc = verdict["peer_vs_cdn_transport"]
    if pvc.get("measured"):
        band_lo = pvc["peer_over_cdn_min"]
        band_hi = pvc["peer_over_cdn_max"]
        agg = pvc["peer_over_cdn_aggregate"]
        print(
            f"  PEER-vs-CDN TRANSPORT (value thesis, MEASURED over {pvc['n_paths_compared']} "
            f"identical real paths): peer /nar/4 zstd-3 wire : CDN compressed transport "
            f"= {band_lo['num']}/{band_lo['denom']} (~{band_lo['display']:.2f}x) .. "
            f"{band_hi['num']}/{band_hi['denom']} (~{band_hi['display']:.2f}x) per path, "
            f"byte-weighted aggregate {agg['num']}/{agg['denom']} (~{agg['display']:.2f}x)."
        )
        print(f"  -> {pvc['value_thesis']}: {pvc['finding']}")
    else:
        print(
            "  PEER-vs-CDN TRANSPORT: UNPROVEN -- no peer arm carrying real /nar/4 wire "
            "bytes for a store path the CDN arm also measured was present."
        )
    return EXIT_OK


# --------------------------------------------------------------------------
# self-test: prove the finalizer BITES (fail closed on drift)
# --------------------------------------------------------------------------


def _nar_hash(store_hash: str) -> str:
    """A deterministic well-formed sha256: NarHash for a test store hash."""
    return NAR_HASH_PREFIX + store_hash + "z" * 32


def _cdn_cap(
    store_hash: str,
    uncompressed: int,
    compressed: int,
    runs: int = 1,
    cache: str = DEFAULT_CACHE,
    real_internet: bool = True,
    tls_verified: bool = True,
    nar_hash: str | None = None,
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
        "narinfo": {
            "nar_url": f"nar/{store_hash}.nar.zst",
            "nar_hash": nar_hash or _nar_hash(store_hash),
        },
        "runs": [
            {"compressed_transport_bytes": compressed, "wall_clock_ns": 5_000_000}
            for _ in range(runs)
        ],
    }


def _peer_cap(
    store_hash: str,
    uncompressed: int,
    wire: int,
    discovery: int = 1_200_000,
    transfer: int = 9_000_000,
    nar_hash: str | None = None,
) -> dict:
    """A well-formed peer capture (TASK-298 schema): a REAL /nar/4 wire-byte count,
    validated provenance/codec, and per-run discovery+transfer wall clocks."""
    return {
        "arm": "peer",
        "kind": EXPECTED_PEER_KIND,
        "store_hash": store_hash,
        "nar_hash": nar_hash or _nar_hash(store_hash),
        "real_internet": False,
        "fixture": True,
        "wire_codec": EXPECTED_PEER_WIRE_CODEC,
        "serve_zstd_level": EXPECTED_SERVE_ZSTD_LEVEL,
        "uncompressed_nar_bytes": uncompressed,
        "peer_wire_transport_bytes": wire,
        "runs": [
            {"transfer_wall_clock_ns": transfer, "discovery_wall_clock_ns": discovery}
        ],
    }


def _bv(cdn: ArmTotals, peer: ArmTotals | None) -> dict:
    """build_verdict with the canonical real-cache provenance + a declared cohort that
    matches the CDN arm's store hashes (test shorthand)."""
    return build_verdict(cdn, peer, True, True, DEFAULT_CACHE, frozenset(cdn.by_hash))


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
    peer_nodisc = _peer_cap("a", 2000, 800)
    del peer_nodisc["runs"][0]["discovery_wall_clock_ns"]
    if rederive_peer([peer_nodisc]) is not None:
        failures.append("rederive_peer accepted a run with NO discovery latency")
    # missing the REAL wire-byte count -> reject (the whole point of TASK-298).
    peer_nowire = _peer_cap("a", 2000, 800)
    del peer_nowire["peer_wire_transport_bytes"]
    if rederive_peer([peer_nowire]) is not None:
        failures.append(
            "rederive_peer accepted a capture with NO peer_wire_transport_bytes"
        )
    peer_zerowire = _peer_cap("a", 2000, 0)
    if rederive_peer([peer_zerowire]) is not None:
        failures.append("rederive_peer accepted a ZERO peer_wire_transport_bytes")
    # missing store_hash -> reject (cannot join without it).
    peer_nohash = _peer_cap("a", 2000, 800)
    del peer_nohash["store_hash"]
    if rederive_peer([peer_nohash]) is not None:
        failures.append("rederive_peer accepted a capture with NO store_hash")
    # duplicate store hash within the peer captures -> reject.
    if (
        rederive_peer([_peer_cap("a", 2000, 800), _peer_cap("a", 2000, 800)])
        is not None
    ):
        failures.append("rederive_peer accepted DUPLICATE store hashes")
    if rederive_peer([_peer_cap("a", 2000, 800)]) is None:
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
        by_hash={"x": (70, 10, _nar_hash("x")), "y": (40, 10, _nar_hash("y"))},
    )
    try:
        _bv(bad_totals, None)
        failures.append(
            "build_verdict ACCEPTED an aggregate below the per-path minimum"
        )
    except ValueError:
        pass

    # --- HIGH-2 peer provenance/codec/hash fail-closed ----------------------
    # A capture in the wrong slot / of the wrong codec / level / provenance, or missing
    # its NarHash, must be REJECTED -- otherwise the verdict's real-KVM/zstd-3/byte-
    # identity claims are hardcoded fiction over a mutated capture (codex mutation).
    for label, mutate in (
        ("arm=cdn", lambda c: c.__setitem__("arm", "cdn")),
        ("kind wrong", lambda c: c.__setitem__("kind", "existence-proof")),
        ("wire_codec=raw", lambda c: c.__setitem__("wire_codec", "raw")),
        ("serve_zstd_level=19", lambda c: c.__setitem__("serve_zstd_level", 19)),
        ("real_internet=True", lambda c: c.__setitem__("real_internet", True)),
        ("fixture=False", lambda c: c.__setitem__("fixture", False)),
        ("no nar_hash", lambda c: c.pop("nar_hash")),
        ("bad nar_hash", lambda c: c.__setitem__("nar_hash", "deadbeef")),
    ):
        cap = _peer_cap("a", 2000, 800)
        mutate(cap)
        if rederive_peer([cap]) is not None:
            failures.append(f"rederive_peer accepted a peer capture with {label}")

    # --- HIGH-2 cdn arm/declared/hash fail-closed ---------------------------
    cdn_wrongarm = _cdn_cap("a", 1000, 300)
    cdn_wrongarm["arm"] = "peer"
    if rederive_cdn([cdn_wrongarm], 1) is not None:
        failures.append("rederive_cdn accepted a non-cdn capture (arm=peer)")
    # declared FileSize must EQUAL the measured download bytes.
    cdn_decldrift = _cdn_cap("a", 1000, 300)
    cdn_decldrift["declared_compressed_bytes"] = 301  # runs still measure 300
    if rederive_cdn([cdn_decldrift], 1) is not None:
        failures.append("rederive_cdn accepted declared_compressed_bytes != download")
    # missing narinfo NarHash.
    cdn_nohash = _cdn_cap("a", 1000, 300)
    del cdn_nohash["narinfo"]["nar_hash"]
    if rederive_cdn([cdn_nohash], 1) is not None:
        failures.append("rederive_cdn accepted a capture with NO narinfo nar_hash")

    # --- TASK-298 peer-vs-CDN JOIN fail-closed + exactness -------------------
    # Two shared paths: peer /nar/4 wire vs CDN compressed. hash a: 400 peer vs 300 cdn
    # (peer moves MORE, ratio 4/3); hash b: 900 peer vs 600 cdn (ratio 3/2). Both >1 =>
    # SUPPLEMENT. CDN uncompressed must MATCH peer uncompressed per hash (same content).
    cdn_join = rederive_cdn([_cdn_cap("a", 1000, 300), _cdn_cap("b", 2000, 600)], 1)
    peer_join = rederive_peer([_peer_cap("a", 1000, 400), _peer_cap("b", 2000, 900)])
    assert cdn_join is not None and peer_join is not None
    cohort_ab = frozenset({"a", "b"})
    pvc = build_peer_vs_cdn(peer_join, cdn_join, cohort_ab)
    if pvc.get("measured") is not True:
        failures.append("peer-vs-CDN join did not set measured=True")
    if pvc.get("n_paths_compared") != 2:
        failures.append("peer-vs-CDN join miscounted shared paths")
    # aggregate = (400+900)/(300+600) = 1300/900 = 13/9 exact.
    agg = pvc["peer_over_cdn_aggregate"]
    if agg["num"] != 13 or agg["denom"] != 9:
        failures.append(
            f"peer-vs-CDN aggregate wrong: 1300/900 must reduce to 13/9, got "
            f"{agg['num']}/{agg['denom']}"
        )
    # band: min ratio 4/3 (a), max 3/2 (b); both >1 -> SUPPLEMENT.
    if pvc["peer_over_cdn_min"]["num"] != 4 or pvc["peer_over_cdn_min"]["denom"] != 3:
        failures.append("peer-vs-CDN min ratio wrong (expected 4/3)")
    if pvc["peer_over_cdn_max"]["num"] != 3 or pvc["peer_over_cdn_max"]["denom"] != 2:
        failures.append("peer-vs-CDN max ratio wrong (expected 3/2)")
    if pvc["value_thesis"] != "SUPPLEMENT_NOT_FEWER_BYTES":
        failures.append(
            f"peer-vs-CDN classification wrong: both ratios >1 must be SUPPLEMENT, "
            f"got {pvc['value_thesis']}"
        )

    # HIGH-1 cohort mismatch (drop one PEER capture) => REJECT (not a smaller n=1 join).
    peer_short = rederive_peer([_peer_cap("a", 1000, 400)])
    assert peer_short is not None
    try:
        build_peer_vs_cdn(peer_short, cdn_join, cohort_ab)
        failures.append("build_peer_vs_cdn ACCEPTED a peer cohort smaller than CDN")
    except ValueError:
        pass
    # declared manifest larger than the measured arms => REJECT.
    try:
        build_peer_vs_cdn(peer_join, cdn_join, frozenset({"a", "b", "c"}))
        failures.append("build_peer_vs_cdn ACCEPTED a cohort != declared manifest")
    except ValueError:
        pass
    # content-mismatch (NarSize) fails CLOSED.
    cdn_mism = rederive_cdn([_cdn_cap("a", 1000, 300)], 1)
    peer_mism = rederive_peer([_peer_cap("a", 999, 400)])  # 999 != 1000
    assert cdn_mism is not None and peer_mism is not None
    try:
        build_peer_vs_cdn(peer_mism, cdn_mism, frozenset({"a"}))
        failures.append("build_peer_vs_cdn ACCEPTED a content (NarSize) mismatch")
    except ValueError:
        pass
    # NarHash-mismatch (same NarSize, DIFFERENT NarHash) fails CLOSED -- byte-identity
    # is load-bearing.
    cdn_hm = rederive_cdn([_cdn_cap("a", 1000, 300, nar_hash=_nar_hash("a"))], 1)
    peer_hm = rederive_peer([_peer_cap("a", 1000, 400, nar_hash=_nar_hash("other"))])
    assert cdn_hm is not None and peer_hm is not None
    try:
        build_peer_vs_cdn(peer_hm, cdn_hm, frozenset({"a"}))
        failures.append("build_peer_vs_cdn ACCEPTED a NarHash mismatch")
    except ValueError:
        pass
    # end-to-end: a joined verdict carries measured=True under peer_vs_cdn_transport.
    joined_verdict = _bv(cdn_join, peer_join)
    if joined_verdict["peer_vs_cdn_transport"].get("measured") is not True:
        failures.append("build_verdict did not surface the measured peer-vs-CDN join")

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

    # --- MED-2 a FAILED finalize INVALIDATES a stale green verdict -----------
    # Point the module dirs at a temp evidence tree seeded with a stale measured=true
    # verdict + a manifest whose CDN capture is broken (declared != download). The run
    # must exit non-zero AND the stale verdict.json must be GONE, never left green.
    global EVIDENCE, CDN_DIR, PEER_DIR
    saved = (EVIDENCE, CDN_DIR, PEER_DIR)
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        EVIDENCE, CDN_DIR, PEER_DIR = root, root / "cdn", root / "peer"
        try:
            CDN_DIR.mkdir()
            PEER_DIR.mkdir()
            (EVIDENCE / "verdict.json").write_text(
                json.dumps({"peer_vs_cdn_transport": {"measured": True}}) + "\n"
            )
            broken = _cdn_cap("a", 1000, 300)
            broken["declared_compressed_bytes"] = (
                301  # != measured 300 -> rederive fails
            )
            (CDN_DIR / "a.json").write_text(json.dumps(broken) + "\n")
            (CDN_DIR / "manifest.json").write_text(
                json.dumps(
                    {
                        "cache": DEFAULT_CACHE,
                        "real_internet": True,
                        "tls_verified": True,
                        "runs": 1,
                        "store_hashes": ["a"],
                    }
                )
                + "\n"
            )
            rc = run_finalize()
            if rc == EXIT_OK:
                failures.append("run_finalize returned OK on a broken CDN capture")
            if (EVIDENCE / "verdict.json").exists():
                failures.append(
                    "a FAILED run_finalize left a STALE verdict.json on disk (fail-open)"
                )
        finally:
            EVIDENCE, CDN_DIR, PEER_DIR = saved

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
        "--cohort-from-peer",
        action="store_true",
        help=(
            "measure EXACTLY the store paths the peer arm already captured "
            "(evidence/task-282/peer/*.json). This is the value-thesis workflow: the "
            "peer VM defines the cohort; the CDN arm follows so the finalizer can JOIN "
            "the two arms on identical content per store_hash."
        ),
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
        store_hashes = args.store_hashes
        if args.cohort_from_peer:
            if store_hashes:
                print(
                    "value-thesis cdn: --cohort-from-peer and explicit store_hashes are "
                    "mutually exclusive",
                    file=sys.stderr,
                )
                return EXIT_FAIL
            store_hashes = peer_cohort_hashes()
            if not store_hashes:
                print(
                    "value-thesis cdn: --cohort-from-peer found no peer captures under "
                    f"{PEER_DIR} -- run `just value-thesis-vm` first",
                    file=sys.stderr,
                )
                return EXIT_FAIL
            print(
                f"value-thesis cdn: measuring the {len(store_hashes)} peer-cohort path(s) "
                f"on {args.cache}",
                file=sys.stderr,
            )
        return run_cdn(
            args.cache,
            store_hashes,
            args.runs,
            args.max_compressed_bytes,
            args.paths,
            require_all=args.cohort_from_peer,
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
