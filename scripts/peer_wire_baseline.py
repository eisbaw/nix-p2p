#!/usr/bin/env python3
"""RAW peer-wire break-even baseline (task-94) -- the HONEST, uncompressed economics.

WHAT THIS IS (and is emphatically NOT)
--------------------------------------
This is a DIAGNOSTIC that establishes the raw/uncompressed peer-wire economics
Stage A reasons about, WITHOUT smuggling compression or policy into the numbers:

  1. how many bytes a PEER moves vs the COMPRESSED CDN, from real cache.nixos.org
     narinfo metadata (FileSize/NarSize) over a broad signed-path sample (AC#1);
  2. the RAW peer socket throughput under task-70's externally-verified shaped
     link profiles, at several NAR sizes (AC#2);
  3. the BREAK-EVEN NAR size from the measured ratio, upstream/peer bandwidth and
     discovery/dial latency -- and, when a peer can never catch up by getting
     bigger, the honest verdict `NO SIZE THRESHOLD EXISTS` (AC#3).

The whole point is the honest baseline/disproof. Peers serve RAW nar (Compression
none: FileHash==NarHash, FileSize==NarSize -- see daemon narinfo rewrite), which
is ~3.6x the CDN's xz/zstd wire bytes. A result where the raw WAN peer LOSES at
every size is a VALID, EXPECTED outcome. This artifact is structurally tagged
`diagnostic_uncompressed` and MUST NOT select a production policy: the compressed
re-evaluation (per-connection codec) is task-99's job, the speedup re-statement is
task-198's. `assert_cannot_select_policy` enforces that mechanically (AC#5).

WHY IT DOES NOT ROUTE THROUGH THE FROZEN COUNTING RULE (dep guard, task-94)
--------------------------------------------------------------------------
`net-upstream-egress-v2/v3` (scripts/MEASUREMENT_COUNTING_RULE.md, executed by
`measure.classify_run`) attributes bytes from the TESTPROXY's per-request log for
the daemon-on vs daemon-off arms. This task touches NONE of that: it reads
cache.nixos.org narinfo metadata over HTTP, runs a raw TCP transfer over a
tc-netem-shaped netns link, and does arithmetic. No testproxy, no classify_run,
no hedge/winner accounting. Hence task-52's dep was correctly pruned. (Confirmed
by reading measure.classify_run's signature: it consumes proxy-log `records`,
`stats_bytes_sent`, `client_exit` -- inputs this task never produces.)

THE UNIT TRAP (recurred 4x in this project -- this is where it bites hardest)
----------------------------------------------------------------------------
NarSize is the UNCOMPRESSED serialized NAR length (what a raw peer moves).
FileSize is the COMPRESSED on-wire length (what the CDN moves). They are DIFFERENT
UNITS; a ratio across them is meaningful (compression ratio) but a SUM or an
equality is a lie except where `Compression: none` makes them coincide. Every
`*_bytes` key in the report MUST end in one of UNIT_SUFFIXES, and `unit_violations`
fails the report otherwise. `--self-test` proves the gate bites by mutation.

ORACLES (each proven RED-under-mutation by `--self-test`)
--------------------------------------------------------
  * compression exclusion: a `Compression: none` path (FileSize==NarSize, ratio
    1.0) must be CLASSIFIED and EXCLUDED from the compressed-upstream aggregate,
    or it inflates the peer's competitiveness toward parity (AC#1).
  * negative-denominator: when the peer saves nothing per byte (denominator <= 0)
    the break-even computation prints NO SIZE THRESHOLD EXISTS -- never a bogus
    (negative) size (AC#3).
  * loopback-label refusal: a run over an UNSHAPED loopback channel may NEVER be
    labelled `wan_shaped`; the label is earned only when task-70's shaping oracle
    fired (AC#2). Mirrors profile_p2p's named-condition discipline.
  * unit gate + policy-selection guard (AC#4/#5).
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent

# The structural tag. This artifact is a raw/uncompressed DIAGNOSTIC; it is not a
# policy input. `assert_cannot_select_policy` refuses any report that grew a
# policy-decision field (AC#5).
DIAGNOSTIC_TAG = "diagnostic_uncompressed"

DEFAULT_CACHE = "https://cache.nixos.org"

# Broad seed attrs whose combined closures span tiny (setup-hook, terminfo) to
# large (glibc, gcc-libs, ffmpeg codecs) NAR sizes, so the FileSize/NarSize sample
# is not clustered in one size band -- the exact flaw of the prior 0.278 figure,
# which was taken over only 20 paths all > 10 MiB. The seeds are RESOLVED to
# outPaths and their hashes recorded, so the sample is reproducible against a
# recorded nixpkgs revision even as the registry pin moves.
DEFAULT_SEED_ATTRS = ("gcc", "python3", "ffmpeg", "git")

# The recognised byte-unit suffixes (identical set to profile_p2p, deliberately:
# one project-wide vocabulary so a reader never has to learn two). A `*_bytes`
# key ending in none of these is a unit violation.
UNIT_SUFFIXES = (
    "_bytes_ram",
    "_bytes_ondisk",
    "_bytes_uncompressed_nar",  # NarSize units -- raw serialized NAR length
    "_bytes_compressed_wire",  # FileSize units -- compressed on-wire length
    "_bytes_control",  # discovery/handshake/framing bytes -- NEVER payload
)

LOOPBACK_LABEL = "loopback"
WAN_LABEL = "wan_shaped"

# task-70 shaped-link default profiles. Three NAR sizes so AC#2's ">=3 sizes" is
# met; SMALL transfers (tens of MiB) for the shared, near-full disk/RAM. The
# profile knobs mirror shaped_link.py's defaults, chosen so TCP leaves slow-start.
DEFAULT_SHAPED_SIZES_MIB = (8, 20, 40)
DEFAULT_DELAY_MS = 20
DEFAULT_RATE_MBIT = 100


def log(msg: str) -> None:
    """Fail-loud progress to stderr; stdout is reserved for the JSON report."""
    print(f"[peer_wire_baseline] {msg}", file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# AC#4 -- the unit gate (mechanical; NarSize and FileSize cannot share a name)
# ---------------------------------------------------------------------------


def unit_labelled(key: str) -> bool:
    """Does a byte-valued key carry a recognised unit (optionally rate `_per_s`)?"""
    body = key[: -len("_per_s")] if key.endswith("_per_s") else key
    return any(body.endswith(suffix) for suffix in UNIT_SUFFIXES)


def unit_violations(node, path: str = "") -> list[str]:
    """Every key naming a byte quantity must carry a recognised unit. Empty == clean.

    `bytes` is matched as a whole underscore token, so `bytesize`-style words do
    not trip while `wire_bytes` and `total_bytes_moved` do. This is the mechanical
    form of the rule prose keeps breaking: NarSize (uncompressed) and FileSize
    (compressed wire) are different units and an unlabelled byte key lets them be
    summed or equated.
    """
    problems: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            here = f"{path}.{key}" if path else str(key)
            names_bytes = isinstance(key, str) and "bytes" in key.split("_")
            if names_bytes and not unit_labelled(key):
                problems.append(
                    f"{here}: byte-valued key without a unit label; must end in "
                    f"one of {', '.join(UNIT_SUFFIXES)} (optionally +'_per_s'). "
                    "NarSize and FileSize are different units."
                )
            problems += unit_violations(value, here)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            problems += unit_violations(value, f"{path}[{index}]")
    return problems


# ---------------------------------------------------------------------------
# AC#5 -- the policy-selection guard (this diagnostic cannot decide policy)
# ---------------------------------------------------------------------------

# Keys whose presence would mean the artifact tried to SELECT a production policy.
# A raw/uncompressed diagnostic must not; task-99 owns the compressed re-eval.
_POLICY_SELECTION_KEYS = (
    "policy_selected",
    "selected_policy",
    "production_policy",
    "recommended_codec",
    "codec_decision",
    "enable_peers",
    "go_no_go",
)


def assert_cannot_select_policy(report: dict) -> None:
    """AC#5: refuse a report that is not tagged, or that grew a policy decision.

    RAISES so a future edit that quietly attaches `policy_selected: ...` to this
    diagnostic breaks LOUDLY rather than letting a raw/uncompressed number decide
    the compressed Stage-B policy.
    """
    if report.get("diagnostic_tag") != DIAGNOSTIC_TAG:
        raise ValueError(
            f"report is not tagged {DIAGNOSTIC_TAG!r}; a raw peer-wire baseline "
            "must be structurally marked as diagnostic, not policy-selecting"
        )

    found: list[str] = []

    def walk(node, path: str) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if isinstance(key, str) and key.lower() in _POLICY_SELECTION_KEYS:
                    found.append(f"{path}.{key}" if path else key)
                walk(value, f"{path}.{key}" if path else str(key))
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, f"{path}[{index}]")

    walk(report, "")
    if found:
        raise ValueError(
            "diagnostic_uncompressed artifact carries policy-selection field(s) "
            f"{found}; this baseline CANNOT select a production policy (task-99 "
            "owns the codec + compressed re-evaluation)"
        )


# ---------------------------------------------------------------------------
# AC#1 -- FileSize/NarSize over a broad signed-path sample; exclude uncompressed
# ---------------------------------------------------------------------------


@dataclass
class NarinfoSample:
    """One narinfo's size fields. `compression` decides which aggregate it joins."""

    store_hash: str
    name: str
    compression: str
    file_size_bytes_compressed_wire: int  # FileSize -- what the CDN moves
    nar_size_bytes_uncompressed_nar: int  # NarSize -- what a raw peer moves
    signed: bool


def classify_compression(compression: str) -> str:
    """`none` -> uncompressed (EXCLUDED from the compressed aggregate); else compressed.

    An uncompressed path has FileSize==NarSize (ratio 1.0). Folding it into the
    compressed-upstream FileSize/NarSize aggregate would drag the ratio toward
    parity and make the peer look 1x instead of ~3.6x -- the unit trap. So it is
    classified out.
    """
    return "uncompressed" if compression.strip().lower() == "none" else "compressed"


def compressed_ratio_aggregate(samples: list[NarinfoSample]) -> dict:
    """Aggregate FileSize/NarSize over COMPRESSED samples only, plus per-decile.

    Returns the aggregate ratio (Sum FileSize / Sum NarSize -- byte-weighted, the
    quantity that governs how many wire bytes a raw peer must move), the mean of
    per-path ratios, and per-decile breakdown. Uncompressed samples are counted
    and reported SEPARATELY so the exclusion is visible, never silent.
    """
    compressed = [
        s for s in samples if classify_compression(s.compression) == "compressed"
    ]
    excluded = [
        s for s in samples if classify_compression(s.compression) == "uncompressed"
    ]

    if not compressed:
        raise ValueError("no compressed samples -- cannot form a compressed aggregate")

    sum_file = sum(s.file_size_bytes_compressed_wire for s in compressed)
    sum_nar = sum(s.nar_size_bytes_uncompressed_nar for s in compressed)
    per_path_ratios = [
        s.file_size_bytes_compressed_wire / s.nar_size_bytes_uncompressed_nar
        for s in compressed
        if s.nar_size_bytes_uncompressed_nar > 0
    ]

    # Deciles OF THE COMPRESSED SAMPLE by NarSize: report the ratio within each
    # decile so a reader can see the compression ratio is not a big-file artifact
    # (the prior-figure flaw). Sorted ascending by NarSize.
    by_nar = sorted(compressed, key=lambda s: s.nar_size_bytes_uncompressed_nar)
    n = len(by_nar)
    deciles = []
    for d in range(10):
        lo = (d * n) // 10
        hi = ((d + 1) * n) // 10
        chunk = by_nar[lo:hi]
        if not chunk:
            deciles.append({"decile": d + 1, "n": 0, "note": "empty"})
            continue
        c_file = sum(s.file_size_bytes_compressed_wire for s in chunk)
        c_nar = sum(s.nar_size_bytes_uncompressed_nar for s in chunk)
        deciles.append(
            {
                "decile": d + 1,
                "n": len(chunk),
                "nar_size_min_bytes_uncompressed_nar": chunk[
                    0
                ].nar_size_bytes_uncompressed_nar,
                "nar_size_max_bytes_uncompressed_nar": chunk[
                    -1
                ].nar_size_bytes_uncompressed_nar,
                "aggregate_file_over_nar_ratio": c_file / c_nar if c_nar else None,
            }
        )

    nar_sizes = [s.nar_size_bytes_uncompressed_nar for s in compressed]
    aggregate_ratio = sum_file / sum_nar
    return {
        "n_compressed": len(compressed),
        "n_uncompressed_excluded": len(excluded),
        "excluded_uncompressed": [
            {
                "store_hash": s.store_hash,
                "name": s.name,
                "compression": s.compression,
                "file_size_bytes_compressed_wire": s.file_size_bytes_compressed_wire,
                "nar_size_bytes_uncompressed_nar": s.nar_size_bytes_uncompressed_nar,
            }
            for s in excluded
        ],
        "aggregate_file_over_nar_ratio": aggregate_ratio,
        "peer_raw_over_cdn_wire_multiple": 1.0 / aggregate_ratio,
        "per_path_ratio_mean": statistics.mean(per_path_ratios)
        if per_path_ratios
        else None,
        "per_path_ratio_median": statistics.median(per_path_ratios)
        if per_path_ratios
        else None,
        "sum_file_size_bytes_compressed_wire": sum_file,
        "sum_nar_size_bytes_uncompressed_nar": sum_nar,
        "nar_size_min_bytes_uncompressed_nar": min(nar_sizes),
        "nar_size_max_bytes_uncompressed_nar": max(nar_sizes),
        "nar_size_span_orders_of_magnitude": (
            (max(nar_sizes) / min(nar_sizes)) if min(nar_sizes) > 0 else None
        ),
        "deciles_by_nar_size": deciles,
    }


def sample_gate(agg: dict, *, min_paths: int, min_span: float) -> list[str]:
    """AC#1 admission: >=min_paths compressed signed paths, spanning a wide range.

    The span check is the non-vacuous part: a sample clustered in one size band
    (the prior-figure flaw) is REFUSED even if it has 200 paths. Empty == clean.
    """
    problems: list[str] = []
    if agg["n_compressed"] < min_paths:
        problems.append(
            f"only {agg['n_compressed']} compressed signed paths, need >= {min_paths}"
        )
    span = agg.get("nar_size_span_orders_of_magnitude")
    if span is None or span < min_span:
        problems.append(
            f"NarSize span {span} is below {min_span}x -- the sample is clustered "
            "in one size band, not spanning the deciles (the prior-figure flaw)"
        )
    empty = [d["decile"] for d in agg["deciles_by_nar_size"] if d["n"] == 0]
    if empty:
        problems.append(f"deciles {empty} are empty -- the size axis is not covered")
    return problems


# --- real cache.nixos.org sampling (HTTP narinfo BFS over the closure) --------


def _fetch_narinfo(cache: str, store_hash: str, timeout: float) -> str | None:
    url = f"{cache}/{store_hash}.narinfo"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.read().decode("utf-8", "replace")
    except Exception as exc:  # noqa: BLE001 -- report, never swallow
        log(f"WARN narinfo fetch failed for {store_hash}: {exc}")
        return None


def parse_narinfo(store_hash: str, body: str) -> tuple[NarinfoSample | None, list[str]]:
    """Parse one narinfo body -> (sample, reference_hashes). Fail-loud on missing
    size fields (a narinfo without FileSize/NarSize is not usable, never a 0)."""
    fields: dict[str, str] = {}
    refs: list[str] = []
    for line in body.splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k, v = k.strip(), v.strip()
        if k == "References":
            refs = [r.split("-", 1)[0] for r in v.split() if r]
        else:
            fields[k] = v
    try:
        file_size = int(fields["FileSize"])
        nar_size = int(fields["NarSize"])
    except (KeyError, ValueError):
        return None, refs
    store_path = fields.get("StorePath", "")
    name = store_path.split("-", 1)[1] if "-" in store_path else store_path
    signed = "Sig" in fields and bool(fields["Sig"])
    return (
        NarinfoSample(
            store_hash=store_hash,
            name=name,
            compression=fields.get("Compression", "unknown"),
            file_size_bytes_compressed_wire=file_size,
            nar_size_bytes_uncompressed_nar=nar_size,
            signed=signed,
        ),
        refs,
    )


def resolve_seed_hashes(seed_attrs: tuple[str, ...]) -> tuple[list[str], dict]:
    """Resolve seed attrs to store-path hashes via `nix eval` (eval only, no build).

    Records the nixpkgs revision for provenance so the reproducible sample is
    anchored even as the flake registry pin moves.
    """
    import subprocess

    provenance = {"seed_attrs": list(seed_attrs), "resolved": {}}
    hashes: list[str] = []
    for attr in seed_attrs:
        out = subprocess.run(
            ["nix", "eval", "--raw", f"nixpkgs#{attr}.outPath"],
            capture_output=True,
            text=True,
            timeout=600,
        )
        if out.returncode != 0:
            log(f"WARN could not resolve nixpkgs#{attr}: {out.stderr.strip()[:200]}")
            continue
        path = out.stdout.strip()
        h = path.removeprefix("/nix/store/").split("-", 1)[0]
        hashes.append(h)
        provenance["resolved"][attr] = path
    try:
        meta = subprocess.run(
            ["nix", "flake", "metadata", "nixpkgs", "--json"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if meta.returncode == 0:
            provenance["nixpkgs"] = json.loads(meta.stdout).get("locked", {})
    except Exception as exc:  # noqa: BLE001
        log(f"WARN could not read nixpkgs flake metadata: {exc}")
    if not hashes:
        raise SystemExit(
            "could not resolve any seed attr to a store path -- no network / no "
            "nix eval. Report BLOCKED (see task-94 notes), do not fake numbers."
        )
    return hashes, provenance


def sample_real_cache(
    cache: str,
    seed_hashes: list[str],
    target: int,
    *,
    timeout: float = 30.0,
    max_fetches: int | None = None,
    polite_delay_s: float = 0.02,
) -> tuple[list[NarinfoSample], dict]:
    """BFS the closure over cache.nixos.org narinfos (metadata only -- NO NARs).

    Fetches narinfos, following `References`, until `target` distinct usable
    samples are collected. Only metadata crosses the wire (~1 KiB each), so 200
    samples is ~200 KiB, polite for a public cache. Fail-loud on every drop.
    """
    max_fetches = max_fetches or (target * 6)
    queue = list(seed_hashes)
    seen: set[str] = set()
    samples: list[NarinfoSample] = []
    fetched = 0
    drops = 0
    while queue and len(samples) < target and fetched < max_fetches:
        h = queue.pop(0)
        if h in seen:
            continue
        seen.add(h)
        body = _fetch_narinfo(cache, h, timeout)
        fetched += 1
        if body is None:
            drops += 1
            continue
        sample, refs = parse_narinfo(h, body)
        for r in refs:
            if r not in seen:
                queue.append(r)
        if sample is None:
            drops += 1
            continue
        samples.append(sample)
        time.sleep(polite_delay_s)
    stats = {
        "cache": cache,
        "seed_hashes": seed_hashes,
        "narinfos_fetched": fetched,
        "samples_collected": len(samples),
        "drops": drops,
        "max_fetches": max_fetches,
        "note": "metadata-only closure BFS over References; no NAR bodies fetched",
    }
    return samples, stats


def load_fixture_uncompressed(manifest: Path) -> list[NarinfoSample]:
    """Load the project's OWN `Compression: none` fixtures as a deliberate
    uncompressed sample, so AC#1's exclusion mechanism is exercised on real
    Compression:none entries (FileSize==NarSize) that MUST be classified out."""
    if not manifest.is_file():
        return []
    data = json.loads(manifest.read_text())
    entries = data.get("paths") or data.get("entries") or []
    if isinstance(data, dict) and not entries:
        # Some manifests key by attr; flatten dict values that look like entries.
        entries = [v for v in data.values() if isinstance(v, dict) and "nar_size" in v]
    out: list[NarinfoSample] = []
    for e in entries:
        if not isinstance(e, dict) or "nar_size" not in e:
            continue
        if str(e.get("compression", "")).lower() != "none":
            continue
        out.append(
            NarinfoSample(
                store_hash=str(e.get("store_path", ""))[:32] or "fixture",
                name=str(e.get("store_path", "fixture")),
                compression="none",
                file_size_bytes_compressed_wire=int(e["file_size"]),
                nar_size_bytes_uncompressed_nar=int(e["nar_size"]),
                signed=False,
            )
        )
    return out


# ---------------------------------------------------------------------------
# AC#3 -- the break-even inequality (with the non-positive-denominator verdict)
# ---------------------------------------------------------------------------

NO_THRESHOLD = "NO SIZE THRESHOLD EXISTS"


@dataclass
class BreakEvenInputs:
    """The four measured inputs to the break-even inequality, with EXPLICIT units.

    ratio            = FileSize/NarSize (compressed aggregate). The CDN moves
                       `ratio` compressed wire bytes per NAR byte; the raw peer
                       moves 1 NAR byte per NAR byte.
    up_bytes_per_s   = upstream (CDN) sustained bandwidth, bytes_compressed_wire/s.
    peer_bytes_per_s = peer sustained bandwidth, bytes_uncompressed_nar/s (raw).
    cdn_latency_s    = CDN first-byte latency (RTT/TTFB) in seconds.
    discovery_latency_s = peer discovery + dial latency in seconds.
    """

    ratio: float
    up_bytes_per_s: float
    peer_bytes_per_s: float
    cdn_latency_s: float
    discovery_latency_s: float


def break_even(inp: BreakEvenInputs) -> dict:
    """Compute the break-even NAR size, or NO SIZE THRESHOLD EXISTS.

    A peer wins iff its total fetch time is below the CDN's:
        discovery + S_nar/B_peer  <  cdn_latency + ratio*S_nar/B_up
    Rearranged around size S_nar (NarSize):
        S_nar * (ratio/B_up - 1/B_peer)  >  discovery - cdn_latency
                    \\_______ denom ______/       \\____ numer ____/

    `denom` is the seconds the peer SAVES per NAR byte. If denom <= 0 the peer
    saves nothing (or loses) per byte, so no larger size ever lets it catch up:
    NO SIZE THRESHOLD EXISTS. denom > 0 requires B_peer > B_up/ratio -- e.g. with
    ratio ~ 0.278 and a 21 MB/s CDN, the peer must sustain > ~75 MB/s.

    When denom > 0 the break-even size is numer/denom NarSize bytes:
      * threshold > 0: the peer wins ABOVE it (its per-byte advantage overtakes
        the discovery-latency premium);
      * threshold <= 0: the peer wins at EVERY size (it is both faster per byte
        AND lower-latency) -- reported with that interpretation, still not a policy.
    """
    denom = inp.ratio / inp.up_bytes_per_s - 1.0 / inp.peer_bytes_per_s
    numer = inp.discovery_latency_s - inp.cdn_latency_s
    result: dict = {
        "inputs": {
            "ratio_file_over_nar": inp.ratio,
            "upstream_bandwidth_bytes_compressed_wire_per_s": inp.up_bytes_per_s,
            "peer_bandwidth_bytes_uncompressed_nar_per_s": inp.peer_bytes_per_s,
            "cdn_latency_s": inp.cdn_latency_s,
            "discovery_latency_s": inp.discovery_latency_s,
        },
        "per_byte_saving_s_per_nar_byte": denom,
        "latency_premium_s": numer,
        "peer_bandwidth_needed_to_break_even_bytes_uncompressed_nar_per_s": (
            inp.up_bytes_per_s / inp.ratio if inp.ratio > 0 else None
        ),
    }
    if denom <= 0:
        result["verdict"] = NO_THRESHOLD
        result["interpretation"] = (
            "the peer saves nothing per NAR byte (it moves raw NAR, ~1/ratio the "
            "CDN's wire bytes); no size lets it catch up. Raw WAN loses at every "
            "size -- the expected honest baseline."
        )
        result["break_even_nar_size_bytes_uncompressed_nar"] = None
        return result

    threshold = numer / denom
    result["break_even_nar_size_bytes_uncompressed_nar"] = threshold
    if threshold <= 0:
        result["verdict"] = "PEER WINS AT EVERY SIZE"
        result["interpretation"] = (
            "denom > 0 (peer faster per byte) AND the discovery latency is below "
            "the CDN's first-byte latency, so the peer wins at all sizes."
        )
    else:
        result["verdict"] = "BREAK-EVEN ABOVE THRESHOLD"
        result["interpretation"] = (
            "the peer wins for NAR sizes ABOVE the threshold, where its per-byte "
            "bandwidth advantage overtakes the discovery-latency premium."
        )
    return result


# ---------------------------------------------------------------------------
# AC#2 -- raw peer socket throughput; the loopback-label refusal oracle
# ---------------------------------------------------------------------------


class LoopbackLabelError(Exception):
    """A run was claimed as `wan_shaped` without earning it -- the recurring trap."""


def assert_link_label(
    label: str,
    *,
    rtt_ms: float,
    throughput_mbit: float,
    rate_cap_mbit: float,
    delay_ms: float,
    shaping_asserted: bool,
) -> None:
    """Refuse to label a run `wan_shaped` unless task-70's shaping provably fired.

    A `loopback` label is always honest (a loopback run IS loopback). The claim
    that must be EARNED is `wan_shaped`: it requires the shaping oracle to have
    passed AND the observed RTT/throughput to look shaped, not like loopback. A
    near-zero-RTT, line-rate run tagged `wan_shaped` is the loopback-label trap;
    this raises with a NAMED cause. Mirrors profile_p2p's named-condition rule.
    """
    if label == LOOPBACK_LABEL:
        return
    if label != WAN_LABEL:
        raise LoopbackLabelError(f"unknown link label {label!r}")
    problems: list[str] = []
    if not shaping_asserted:
        problems.append(
            "claims wan_shaped but the shaping oracle (shaped_link.assert_shaping) "
            "did not pass -- an unasserted shaper is an unearned WAN label"
        )
    want_rtt = 2 * delay_ms
    if rtt_ms < 0.7 * want_rtt:
        problems.append(
            f"claims wan_shaped but RTT {rtt_ms:.2f}ms is loopback-fast "
            f"(< 0.7 x injected {want_rtt}ms) -- this is a loopback run"
        )
    if throughput_mbit > 1.3 * rate_cap_mbit:
        problems.append(
            f"claims wan_shaped but throughput {throughput_mbit:.0f}mbit exceeds "
            f"1.3 x the {rate_cap_mbit}mbit cap -- the cap did not bite, this is "
            "an unshaped loopback run"
        )
    if problems:
        raise LoopbackLabelError("; ".join(problems))


def measure_shaped_throughput(
    sizes_mib: tuple[int, ...],
    delay_ms: int,
    rate_mbit: int,
) -> dict:
    """AC#2: raw peer socket throughput at >=3 NAR sizes over the task-70 shaped
    link. Reuses shaped_link.py's netns machinery + shaping oracle (no reimpl).

    Each size runs a SHAPED arm and an UNSHAPED negative control; the shaped arm
    is labelled `wan_shaped` ONLY after `assert_shaping` passes and the label is
    re-checked by `assert_link_label`. The unshaped arm is labelled `loopback`
    and, as a live bite, we assert that claiming it `wan_shaped` RAISES.
    """
    import shaped_link  # dependency-free; test/measurement surface only

    if len(sizes_mib) < 3:
        raise ValueError("AC#2 requires >= 3 NAR sizes")

    per_size = []
    for mib in sizes_mib:
        total = mib * 1024 * 1024
        shaped = shaped_link.run_arm(True, total, delay_ms, rate_mbit)
        unshaped = shaped_link.run_arm(False, total, delay_ms, rate_mbit)
        shaping_ok = True
        shaping_error = None
        try:
            shaped_link.assert_shaping(shaped, unshaped, delay_ms, rate_mbit)
        except shaped_link.ShapingViolation as exc:
            shaping_ok = False
            shaping_error = str(exc)

        # The shaped arm earns `wan_shaped` only if the oracle fired.
        assert_link_label(
            WAN_LABEL,
            rtt_ms=shaped["rtt_ms"],
            throughput_mbit=shaped["mbit"],
            rate_cap_mbit=rate_mbit,
            delay_ms=delay_ms,
            shaping_asserted=shaping_ok,
        )
        # The unshaped arm is loopback; asserting WAN on it MUST raise (live bite).
        refused = False
        try:
            assert_link_label(
                WAN_LABEL,
                rtt_ms=unshaped["rtt_ms"],
                throughput_mbit=unshaped["mbit"],
                rate_cap_mbit=rate_mbit,
                delay_ms=delay_ms,
                shaping_asserted=False,
            )
        except LoopbackLabelError:
            refused = True
        if not refused:
            raise LoopbackLabelError(
                "harness FAILED to refuse a wan_shaped label on the loopback arm"
            )

        per_size.append(
            {
                "nar_size_bytes_uncompressed_nar": total,
                "shaped": {
                    "link_label": WAN_LABEL,
                    "rtt_ms": shaped["rtt_ms"],
                    "throughput_mbit_per_s": shaped["mbit"],
                    "throughput_bytes_uncompressed_nar_per_s": shaped["mbit"] * 1e6 / 8,
                    "shaping_asserted": shaping_ok,
                    "shaping_error": shaping_error,
                },
                "loopback_control": {
                    "link_label": LOOPBACK_LABEL,
                    "rtt_ms": unshaped["rtt_ms"],
                    "throughput_mbit_per_s": unshaped["mbit"],
                    "throughput_bytes_uncompressed_nar_per_s": unshaped["mbit"]
                    * 1e6
                    / 8,
                    "wan_label_refused": refused,
                },
            }
        )
    return {
        "profile": {"delay_ms": delay_ms, "rate_cap_mbit": rate_mbit},
        "shaping_primitive": "scripts/shaped_link.py (task-70), tc netem over veth",
        "per_size": per_size,
        "note": (
            "raw TCP over an emulated link; NOT the real libp2p transport (that is "
            "task-198's deferred scope). Peer bytes here are RAW NAR bytes."
        ),
    }


# ---------------------------------------------------------------------------
# report assembly
# ---------------------------------------------------------------------------


@dataclass
class Report:
    """The assembled diagnostic. Kept as a dataclass so the unit gate and the
    policy guard run over a single canonical dict before it is emitted."""

    sample: dict = field(default_factory=dict)
    throughput: dict | None = None
    break_even_scenarios: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "diagnostic_tag": DIAGNOSTIC_TAG,
            "task": "task-94",
            "counting_rule": (
                "NONE -- this diagnostic does not route bytes through "
                "net-upstream-egress-v2/v3 (measure.classify_run). It reads "
                "cache.nixos.org narinfo metadata over HTTP and runs raw TCP over "
                "a tc-netem-shaped netns link. Confirmed dep-guard (task-94)."
            ),
            "asymmetry_source": (
                "peers serve RAW nar (Compression:none, FileHash==NarHash, "
                "FileSize==NarSize -- daemon narinfo rewrite); the CDN serves "
                "xz/zstd. The raw peer therefore moves ~1/ratio the CDN wire bytes."
            ),
            "forbidden": (
                "this artifact CANNOT select a production policy; task-99 owns the "
                "codec + compressed re-evaluation, task-198 re-states the speedup."
            ),
            "cdn_wire_vs_peer_raw_sample": self.sample,
            "raw_peer_socket_throughput": self.throughput,
            "break_even": self.break_even_scenarios,
        }

    def finalize(self) -> dict:
        d = self.to_dict()
        violations = unit_violations(d)
        if violations:
            raise ValueError("UNIT VIOLATIONS: " + "; ".join(violations))
        assert_cannot_select_policy(d)
        return d


# ---------------------------------------------------------------------------
# self-test -- every oracle must bite by mutation (task-63 discipline)
# ---------------------------------------------------------------------------


def _good_samples() -> list[NarinfoSample]:
    """A tiny synthetic compressed sample spanning sizes, plus one uncompressed."""
    out = []
    for i in range(20):
        nar = 1000 * (2 ** (i % 10))  # spans ~1 KB .. ~512 KB
        out.append(
            NarinfoSample(
                store_hash=f"h{i:031d}",
                name=f"pkg-{i}",
                compression="xz",
                file_size_bytes_compressed_wire=int(nar * 0.3),
                nar_size_bytes_uncompressed_nar=nar,
                signed=True,
            )
        )
    # One Compression:none path: FileSize==NarSize, ratio 1.0. MUST be excluded.
    out.append(
        NarinfoSample(
            store_hash="u" + "0" * 31,
            name="uncompressed-fixture",
            compression="none",
            file_size_bytes_compressed_wire=100_000_000,
            nar_size_bytes_uncompressed_nar=100_000_000,
            signed=True,
        )
    )
    return out


def self_test() -> int:
    failures: list[str] = []

    # --- AC#1: the uncompressed path is excluded from the compressed aggregate.
    agg = compressed_ratio_aggregate(_good_samples())
    if agg["n_uncompressed_excluded"] != 1:
        failures.append(
            "compression exclusion: uncompressed path was not classified out"
        )
    if agg["n_compressed"] != 20:
        failures.append("compression exclusion: wrong compressed count")
    # BITE: had the huge ratio-1.0 uncompressed path been folded in, the aggregate
    # ratio would jump toward 1.0. Prove exclusion actually moved the number.
    folded = _good_samples()
    sum_file = sum(s.file_size_bytes_compressed_wire for s in folded)
    sum_nar = sum(s.nar_size_bytes_uncompressed_nar for s in folded)
    folded_ratio = sum_file / sum_nar
    if not (agg["aggregate_file_over_nar_ratio"] < 0.5 <= folded_ratio):
        failures.append(
            f"compression exclusion is vacuous: excluded ratio "
            f"{agg['aggregate_file_over_nar_ratio']:.3f} vs folded {folded_ratio:.3f} "
            "-- excluding the uncompressed path did not move the ratio as expected"
        )

    # --- AC#3: negative-denominator prints NO SIZE THRESHOLD EXISTS (red-green).
    # Home-uplink regime: peer saves nothing per byte -> no threshold.
    home = break_even(
        BreakEvenInputs(
            ratio=0.278,
            up_bytes_per_s=21 * 1024**2,
            peer_bytes_per_s=5 * 1024**2,  # 5 MB/s home uplink << 75 MB/s needed
            cdn_latency_s=0.05,
            discovery_latency_s=1.0,
        )
    )
    if home["verdict"] != NO_THRESHOLD:
        failures.append(
            f"negative-denominator bite: expected {NO_THRESHOLD!r}, got {home['verdict']!r}"
        )
    if home["break_even_nar_size_bytes_uncompressed_nar"] is not None:
        failures.append(
            "negative-denominator bite: a size was reported despite denom <= 0 "
            "(the guard did not fire -- this is the exact mutation that must go RED)"
        )
    # A denom>0 case must produce a finite threshold (proves the guard is not a
    # blanket refusal that would pass the test vacuously).
    fast = break_even(
        BreakEvenInputs(
            ratio=0.278,
            up_bytes_per_s=20 * 1024**2,
            peer_bytes_per_s=200 * 1024**2,  # 200 MB/s LAN peer > 75 MB/s
            cdn_latency_s=0.05,
            discovery_latency_s=1.0,
        )
    )
    if fast["verdict"] == NO_THRESHOLD:
        failures.append(
            "denom>0 case wrongly reported NO SIZE THRESHOLD -- the verdict is a "
            "blanket refusal, so the negative bite proves nothing"
        )
    if fast.get("break_even_nar_size_bytes_uncompressed_nar") is None:
        failures.append("denom>0 case produced no break-even size")

    # --- AC#2: loopback-label refusal (red-green).
    # Loopback-looking metrics tagged wan_shaped MUST raise.
    try:
        assert_link_label(
            WAN_LABEL,
            rtt_ms=0.05,
            throughput_mbit=2000.0,
            rate_cap_mbit=100,
            delay_ms=20,
            shaping_asserted=False,
        )
        failures.append(
            "loopback-label bite: a loopback run claimed wan_shaped was NOT refused "
            "(this is the exact mutation that must go RED)"
        )
    except LoopbackLabelError:
        pass
    # The same metrics tagged loopback are honest and must pass.
    try:
        assert_link_label(
            LOOPBACK_LABEL,
            rtt_ms=0.05,
            throughput_mbit=2000.0,
            rate_cap_mbit=100,
            delay_ms=20,
            shaping_asserted=False,
        )
    except LoopbackLabelError as exc:
        failures.append(f"loopback label wrongly refused: {exc}")
    # A genuinely shaped run earns wan_shaped.
    try:
        assert_link_label(
            WAN_LABEL,
            rtt_ms=40.0,
            throughput_mbit=95.0,
            rate_cap_mbit=100,
            delay_ms=20,
            shaping_asserted=True,
        )
    except LoopbackLabelError as exc:
        failures.append(f"genuinely shaped run wrongly refused wan_shaped: {exc}")

    # --- AC#4: the unit gate bites on an unlabelled byte key.
    if not unit_violations({"wire_bytes": 5}):
        failures.append("unit gate is vacuous: an unlabelled `wire_bytes` key passed")
    if unit_violations(
        {"wire_bytes_compressed_wire": 5, "nar_bytes_uncompressed_nar": 5}
    ):
        failures.append("unit gate false-positive: labelled keys were rejected")

    # --- AC#5: the policy-selection guard bites.
    try:
        assert_cannot_select_policy(
            {
                "diagnostic_tag": DIAGNOSTIC_TAG,
                "nested": {"policy_selected": "peers-on"},
            }
        )
        failures.append("policy guard is vacuous: a policy_selected field passed")
    except ValueError:
        pass
    try:
        assert_cannot_select_policy({"diagnostic_tag": "something_else"})
        failures.append("policy guard did not reject a mis-tagged report")
    except ValueError:
        pass
    try:
        assert_cannot_select_policy({"diagnostic_tag": DIAGNOSTIC_TAG, "ok": 1})
    except ValueError as exc:
        failures.append(f"policy guard false-positive on a clean report: {exc}")

    # --- sample_gate refuses a clustered (narrow-band) sample even at n>=200.
    clustered = [NarinfoSample(f"h{i}", "p", "xz", 300, 1000, True) for i in range(200)]
    cagg = compressed_ratio_aggregate(clustered)
    if not sample_gate(cagg, min_paths=200, min_span=1e3):
        failures.append(
            "sample_gate is vacuous: a clustered single-size sample passed the "
            "span check (the prior-figure flaw would slip through)"
        )

    if failures:
        for f in failures:
            print(f"SELF-TEST FAIL: {f}", file=sys.stderr)
        return 1
    print(
        "SELF-TEST OK: compression-exclusion, negative-denominator, "
        "loopback-label, unit-gate, policy-guard and span-gate oracles all bite"
    )
    return 0


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--self-test", action="store_true", help="prove the oracles bite")
    ap.add_argument("--cache", default=DEFAULT_CACHE)
    ap.add_argument(
        "--sample", type=int, default=0, help="collect N real narinfos (AC#1)"
    )
    ap.add_argument(
        "--seed-attrs",
        default=",".join(DEFAULT_SEED_ATTRS),
        help="comma-separated nixpkgs attrs to seed the closure BFS",
    )
    ap.add_argument(
        "--fixture-manifest",
        default=str(HERE.parent / "fixtures/out/current/manifest.json"),
        help="project manifest with Compression:none fixtures to classify+exclude",
    )
    ap.add_argument(
        "--shaped-link", action="store_true", help="run the AC#2 shaped throughput"
    )
    ap.add_argument("--delay-ms", type=int, default=DEFAULT_DELAY_MS)
    ap.add_argument("--rate-mbit", type=int, default=DEFAULT_RATE_MBIT)
    ap.add_argument(
        "--shaped-sizes-mib",
        default=",".join(str(m) for m in DEFAULT_SHAPED_SIZES_MIB),
        help="comma-separated NAR sizes (MiB) for the shaped throughput arm",
    )
    ap.add_argument("--min-paths", type=int, default=200)
    ap.add_argument("--min-span", type=float, default=1e4)
    ap.add_argument("--json-out", default=None)
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    report = Report()

    if args.sample > 0:
        seed_attrs = tuple(a.strip() for a in args.seed_attrs.split(",") if a.strip())
        seed_hashes, provenance = resolve_seed_hashes(seed_attrs)
        samples, stats = sample_real_cache(args.cache, seed_hashes, args.sample)
        samples += load_fixture_uncompressed(Path(args.fixture_manifest))
        agg = compressed_ratio_aggregate(samples)
        gate = sample_gate(agg, min_paths=args.min_paths, min_span=args.min_span)
        report.sample = {
            "provenance": provenance,
            "fetch_stats": stats,
            "aggregate": agg,
            "gate_violations": gate,
            "gate_passed": not gate,
        }
        log(
            f"sample: {agg['n_compressed']} compressed paths, "
            f"aggregate FileSize/NarSize={agg['aggregate_file_over_nar_ratio']:.4f} "
            f"(peer moves {agg['peer_raw_over_cdn_wire_multiple']:.2f}x), "
            f"{agg['n_uncompressed_excluded']} uncompressed excluded"
        )
        if gate:
            log(f"SAMPLE GATE FAILED: {gate}")

    if args.shaped_link:
        sizes = tuple(int(m) for m in args.shaped_sizes_mib.split(","))
        report.throughput = measure_shaped_throughput(
            sizes, args.delay_ms, args.rate_mbit
        )

    # Break-even scenarios: driven by the MEASURED ratio when available, else a
    # documented placeholder, over both a home-uplink and a LAN-peer regime.
    ratio = None
    if report.sample:
        ratio = report.sample["aggregate"]["aggregate_file_over_nar_ratio"]
    peer_bw = None
    if report.throughput:
        peer_bw = max(
            s["shaped"]["throughput_bytes_uncompressed_nar_per_s"]
            for s in report.throughput["per_size"]
        )
    if ratio is not None:
        scenarios = [
            ("home_uplink_5MBps", 21 * 1024**2, 5 * 1024**2, 0.05, 1.0),
            ("lan_peer_125MBps", 21 * 1024**2, 125 * 1024**2, 0.05, 0.2),
        ]
        if peer_bw is not None:
            scenarios.append(("measured_shaped_peer", 21 * 1024**2, peer_bw, 0.05, 1.0))
        for name, up, peer, cdn_lat, disc_lat in scenarios:
            r = break_even(
                BreakEvenInputs(
                    ratio=ratio,
                    up_bytes_per_s=up,
                    peer_bytes_per_s=peer,
                    cdn_latency_s=cdn_lat,
                    discovery_latency_s=disc_lat,
                )
            )
            r["scenario"] = name
            report.break_even_scenarios.append(r)

    final = report.finalize()
    print(json.dumps(final, indent=2))
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(final, indent=2))
        log(f"wrote {args.json_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
