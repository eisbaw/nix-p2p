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
none: FileHash==NarHash, FileSize==NarSize -- see daemon narinfo rewrite), so a
peer moves the full uncompressed NAR where the CDN moves its compressed wire
bytes. Over a broad CURRENT zstd seed-closure convenience sample (BFS from
gcc/python3/ffmpeg/git) this project ESTIMATES FileSize/NarSize ~= 0.3256, i.e.
the raw peer moves ~3.07x the CDN's wire bytes ON THIS SAMPLE. Read 0.3256 as a
convenience-sample estimate, NOT a population ratio and NOT a correction of the
legacy size-only 0.278: that cohort was xz over ~20 large (>10 MiB) paths, this
one is all-zstd over a size-spanning closure -- codec- and cohort-confounded, so
the two numbers are not comparable (do not claim one "corrects" the other). A
result where the raw WAN peer LOSES at every size is a VALID, EXPECTED outcome.

This artifact is tagged `diagnostic_uncompressed`. That tag is a PRODUCER-SIDE
tripwire: `assert_cannot_select_policy` asserts the artifact emits none of a known
set of policy-selection field names -- it does NOT and cannot prevent a downstream
reader from computing its own decision from the ratio. The compressed re-evaluation
(per-connection codec) is task-99's job, the speedup re-statement is task-198's.

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
  * unknown-compression bucket: a path whose Compression is missing/unrecognised
    is classified out (its OWN bucket), never silently folded in as "compressed".
  * signed admission: only cache-signed paths enter the aggregate; unsigned ones
    are counted and excluded (fail-closed, not fail-open).
  * re-derivability: the aggregate carries the per-path records; an INDEPENDENT
    verifier recomputes sum_file/sum_nar/ratio/deciles FROM those records and
    refuses any report whose headline does not match its own committed inputs.
  * fail-closed publish: a failed sample_gate raises and the CLI publishes NO
    aggregate and exits nonzero (a clustered/short sample cannot slip through).
  * break-even quadrants: denom<=0 dispatches on the numer sign -- NO SIZE
    THRESHOLD when the peer also loses on latency, PEER WINS AT EVERY SIZE / PEER
    WINS BELOW an upper crossover when the peer has the latency advantage (AC#3).
  * loopback-label refusal: a run over an UNSHAPED loopback channel may NEVER be
    labelled `wan_shaped`; the label is earned only when task-70's shaping oracle
    fired (AC#2). Mirrors profile_p2p's named-condition discipline.
  * receiver-counter: the shaped arm's receiver must confirm got==expect; a
    truncated transfer is refused, not accepted as a measurement (AC#4).
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

# Break-even scenario bandwidth/latency assumptions. These are ASSUMED inputs, NOT
# re-measured by this script: the upstream (CDN) figure derives from
# scripts/profile_p2p.py / the task-35 real-upstream measurement; the home/LAN peer
# figures and the latencies are round illustrative values. Units are MiB/s (binary
# mebibytes per second) throughout -- the `1024**2` factor -- so every scenario
# label reads *MiBps and the derived "bandwidth needed" is quoted in MiB/s too.
# (Do not relabel these MB/s: 21*1024**2 B/s is 21 MiB/s = ~22.02 decimal MB/s.)
ASSUMED_CDN_BYTES_PER_S = 21 * 1024**2  # 21 MiB/s upstream (profile_p2p / task-35)
ASSUMED_HOME_PEER_BYTES_PER_S = 5 * 1024**2  # 5 MiB/s home uplink (illustrative)
ASSUMED_LAN_PEER_BYTES_PER_S = 125 * 1024**2  # 125 MiB/s LAN peer (illustrative)


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
    """One narinfo's size fields. `compression` decides which aggregate it joins.

    `sig` is the RAW `Sig:` value as read off the narinfo -- the ground truth from
    which `signed` is derived, retained so admission is re-derivable from raw and
    never rests on a self-reported boolean.
    """

    store_hash: str
    name: str
    compression: str
    file_size_bytes_compressed_wire: int  # FileSize -- what the CDN moves
    nar_size_bytes_uncompressed_nar: int  # NarSize -- what a raw peer moves
    sig: str  # RAW Sig line value ("" if absent); `signed` is bool(sig)

    @property
    def signed(self) -> bool:
        return bool(self.sig.strip())


# The compression codecs we RECOGNISE as producing a real compressed wire byte
# count distinct from NarSize. Anything not in this set and not `none` is
# UNKNOWN -- classified into its own bucket and excluded, never folded in as
# "compressed" (that was the fail-open: a missing/garbled Compression field
# silently counted as compressed and skewed the ratio).
_KNOWN_COMPRESSED = frozenset({"xz", "zstd", "bzip2", "gzip", "br", "lzip", "lz4"})


def classify_compression(compression: str) -> str:
    """Three-way: `none` -> uncompressed; a known codec -> compressed; else unknown.

    An uncompressed path has FileSize==NarSize (ratio 1.0). Folding it into the
    compressed-upstream FileSize/NarSize aggregate would drag the ratio toward
    parity and make the peer look 1x instead of ~3x -- the unit trap. So it is
    classified out. An UNKNOWN/missing Compression is likewise classified out (its
    own bucket): we do not know its wire units, so we must not assume "compressed".
    """
    value = compression.strip().lower()
    if value == "none":
        return "uncompressed"
    if value in _KNOWN_COMPRESSED:
        return "compressed"
    return "unknown_compression"


def _record_of(sample: NarinfoSample) -> dict:
    """The RETAINED raw per-path record -- the committed source of truth from which
    every aggregate is re-derivable. `classification`/`signed` are stored for
    readability but the verifier RE-DERIVES them from `compression`/`sig`."""
    return {
        "store_hash": sample.store_hash,
        "name": sample.name,
        "compression": sample.compression,
        "file_size_bytes_compressed_wire": sample.file_size_bytes_compressed_wire,
        "nar_size_bytes_uncompressed_nar": sample.nar_size_bytes_uncompressed_nar,
        "sig": sample.sig,
        "signed": sample.signed,
        "classification": classify_compression(sample.compression),
    }


def _admitted_records(records: list[dict]) -> list[dict]:
    """The paths that enter the aggregate: a KNOWN compressed codec AND signed.

    This is the single admission predicate, applied identically by the aggregate
    builder and by the independent re-derivation verifier -- so a reader who
    reloads the committed records and re-runs it lands on the same headline."""
    return [
        r
        for r in records
        if classify_compression(r["compression"]) == "compressed"
        and bool(str(r.get("sig", "")).strip())
    ]


def _deciles_by_nar(admitted: list[dict]) -> list[dict]:
    """Per-decile FileSize/NarSize over the admitted records (ascending NarSize).

    Deciles are a POST-HOC equal-count cut; they are near-tautologically populated
    for n>=10 and are NOT the anti-clustering guarantee (the span gate is). They
    are reported only so a reader can see the ratio is roughly stable across the
    size axis -- i.e. compression is not purely a big-file artifact."""
    by_nar = sorted(admitted, key=lambda r: r["nar_size_bytes_uncompressed_nar"])
    n = len(by_nar)
    deciles = []
    for d in range(10):
        lo = (d * n) // 10
        hi = ((d + 1) * n) // 10
        chunk = by_nar[lo:hi]
        if not chunk:
            deciles.append({"decile": d + 1, "n": 0, "note": "empty"})
            continue
        c_file = sum(r["file_size_bytes_compressed_wire"] for r in chunk)
        c_nar = sum(r["nar_size_bytes_uncompressed_nar"] for r in chunk)
        deciles.append(
            {
                "decile": d + 1,
                "n": len(chunk),
                "nar_size_min_bytes_uncompressed_nar": chunk[0][
                    "nar_size_bytes_uncompressed_nar"
                ],
                "nar_size_max_bytes_uncompressed_nar": chunk[-1][
                    "nar_size_bytes_uncompressed_nar"
                ],
                "aggregate_file_over_nar_ratio": c_file / c_nar if c_nar else None,
            }
        )
    return deciles


def _aggregate_from_records(records: list[dict]) -> dict:
    """Compute every aggregate quantity from the RAW records. This is the one
    computation path; the report stores its output and the verifier re-runs it on
    the reloaded records to prove the headline is re-derivable from committed raw.
    """
    admitted = _admitted_records(records)
    if not admitted:
        raise ValueError(
            "no admitted (known-compressed AND signed) records -- cannot form an "
            "aggregate"
        )
    sum_file = sum(r["file_size_bytes_compressed_wire"] for r in admitted)
    sum_nar = sum(r["nar_size_bytes_uncompressed_nar"] for r in admitted)
    per_path_ratios = [
        r["file_size_bytes_compressed_wire"] / r["nar_size_bytes_uncompressed_nar"]
        for r in admitted
        if r["nar_size_bytes_uncompressed_nar"] > 0
    ]
    nar_sizes = [r["nar_size_bytes_uncompressed_nar"] for r in admitted]
    return {
        "n_compressed": len(admitted),
        "aggregate_file_over_nar_ratio": sum_file / sum_nar,
        "peer_raw_over_cdn_wire_multiple": sum_nar / sum_file,
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
        "deciles_by_nar_size": _deciles_by_nar(admitted),
    }


def compressed_ratio_aggregate(samples: list[NarinfoSample]) -> dict:
    """Aggregate FileSize/NarSize over ADMITTED (known-compressed + signed) samples.

    Admission is fail-CLOSED: a path enters the aggregate only if its Compression
    is a recognised codec AND it carries a signature. Uncompressed, unknown-codec
    and unsigned paths are each COUNTED in their own bucket and excluded, so every
    exclusion is visible, never silent. The per-path `records` are retained so the
    headline is re-derivable from committed raw (see `verify_rederivable`).
    """
    records = [_record_of(s) for s in samples]
    agg = _aggregate_from_records(records)

    n_uncompressed = sum(
        1 for r in records if classify_compression(r["compression"]) == "uncompressed"
    )
    n_unknown = sum(
        1
        for r in records
        if classify_compression(r["compression"]) == "unknown_compression"
    )
    n_unsigned = sum(
        1
        for r in records
        if classify_compression(r["compression"]) == "compressed"
        and not bool(str(r.get("sig", "")).strip())
    )
    agg.update(
        {
            "n_uncompressed_excluded": n_uncompressed,
            "n_unknown_compression_excluded": n_unknown,
            "n_unsigned_excluded": n_unsigned,
            "n_records_total": len(records),
            "admission_rule": (
                "admitted iff Compression in a known codec set AND Sig present; "
                "uncompressed/unknown-codec/unsigned each excluded and counted"
            ),
            "records": records,
        }
    )
    return agg


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


# --- re-derivability: recompute the headline from the committed raw records -----


class RederivationError(Exception):
    """A reported aggregate does not match what its own records re-derive to."""


# Aggregate scalars the verifier recomputes from records and demands match.
_REDERIVED_SCALARS = (
    "n_compressed",
    "aggregate_file_over_nar_ratio",
    "peer_raw_over_cdn_wire_multiple",
    "per_path_ratio_mean",
    "per_path_ratio_median",
    "sum_file_size_bytes_compressed_wire",
    "sum_nar_size_bytes_uncompressed_nar",
    "nar_size_min_bytes_uncompressed_nar",
    "nar_size_max_bytes_uncompressed_nar",
    "nar_size_span_orders_of_magnitude",
)


def verify_rederivable(agg: dict, *, tol: float = 1e-9) -> dict:
    """Recompute EVERY reported aggregate FROM `agg['records']` and assert a match.

    This is the re-derivability oracle: the committed artifact carries the raw
    per-path records, and a reader (or `--verify-artifact`) recomputes the headline
    from them WITHOUT trusting the stored summary. Any drift -- a hand-edited sum,
    a stale ratio, a doctored decile -- raises RederivationError. Returns the freshly
    re-derived aggregate on success (the headline a consumer should quote).
    """
    records = agg.get("records")
    if not isinstance(records, list) or not records:
        raise RederivationError(
            "aggregate carries no per-path records -- the headline is not "
            "re-derivable (this is the BLOCKER the fix cycle closes)"
        )
    fresh = _aggregate_from_records(records)

    mismatches: list[str] = []
    for key in _REDERIVED_SCALARS:
        want, got = agg.get(key), fresh.get(key)
        if isinstance(want, (int, float)) and isinstance(got, (int, float)):
            denom = max(1.0, abs(want))
            if abs(want - got) > tol * denom:
                mismatches.append(f"{key}: reported {want!r} != re-derived {got!r}")
        elif want != got:
            mismatches.append(f"{key}: reported {want!r} != re-derived {got!r}")

    want_dec = agg.get("deciles_by_nar_size", [])
    got_dec = fresh["deciles_by_nar_size"]
    if len(want_dec) != len(got_dec):
        mismatches.append("deciles_by_nar_size: length differs from re-derived")
    else:
        for wd, gd in zip(want_dec, got_dec):
            wr, gr = (
                wd.get("aggregate_file_over_nar_ratio"),
                gd.get("aggregate_file_over_nar_ratio"),
            )
            if isinstance(wr, float) and isinstance(gr, float):
                if abs(wr - gr) > tol * max(1.0, abs(wr)):
                    mismatches.append(
                        f"decile {wd.get('decile')}: reported ratio {wr!r} != "
                        f"re-derived {gr!r}"
                    )
            elif wr != gr:
                mismatches.append(
                    f"decile {wd.get('decile')}: reported ratio {wr!r} != "
                    f"re-derived {gr!r}"
                )

    if mismatches:
        raise RederivationError(
            "headline is NOT re-derivable from committed records: "
            + "; ".join(mismatches)
        )
    return fresh


# --- fail-closed publish: a failed sample gate yields NO aggregate --------------


class SampleGateError(Exception):
    """The sample gate failed; the pipeline must publish NO aggregate and exit
    nonzero. Carries the concrete violations so the refusal is traceable."""

    def __init__(self, violations: list[str]):
        self.violations = violations
        super().__init__("; ".join(violations))


def build_sample_block(
    samples: list[NarinfoSample], *, min_paths: int, min_span: float
) -> dict:
    """Build the AC#1 sample block, fail-CLOSED: raise SampleGateError (publishing
    nothing) if the gate fails. On success the block is re-derivable-verified so a
    report can never carry a headline that disagrees with its own records."""
    agg = compressed_ratio_aggregate(samples)
    gate = sample_gate(agg, min_paths=min_paths, min_span=min_span)
    if gate:
        raise SampleGateError(gate)
    verify_rederivable(agg)  # a published aggregate is always self-consistent
    return {"aggregate": agg, "gate_violations": [], "gate_passed": True}


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
    return (
        NarinfoSample(
            store_hash=store_hash,
            name=name,
            compression=fields.get("Compression", "unknown"),
            file_size_bytes_compressed_wire=file_size,
            nar_size_bytes_uncompressed_nar=nar_size,
            sig=fields.get("Sig", ""),  # RAW; `signed` is derived as bool(sig)
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
    Compression:none entries (FileSize==NarSize) that MUST be classified out.

    Fail-LOUD on an empty result: if the manifest is missing or carries zero
    Compression:none entries the exclusion arm is vacuous for this run, so we WARN
    rather than return [] silently."""
    if not manifest.is_file():
        log(
            f"WARN fixture manifest {manifest} not found -- the Compression:none "
            "exclusion arm is VACUOUS for this run (no uncompressed fixtures loaded)"
        )
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
                sig="",  # fixtures are unsigned; classified out either way
            )
        )
    if not out:
        log(
            f"WARN {manifest} carries zero Compression:none entries -- the "
            "uncompressed-exclusion arm is VACUOUS for this run"
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


PEER_WINS_EVERY = "PEER WINS AT EVERY SIZE"
PEER_WINS_ABOVE = "BREAK-EVEN ABOVE THRESHOLD"
PEER_WINS_BELOW = "PEER WINS BELOW THRESHOLD"


def break_even(inp: BreakEvenInputs) -> dict:
    """Compute the peer-vs-CDN break-even NAR size across ALL latency quadrants.

    A peer wins iff its total fetch time is below the CDN's:
        discovery + S_nar/B_peer  <  cdn_latency + ratio*S_nar/B_up
    Rearranged around size S_nar (NarSize):
        S_nar * (ratio/B_up - 1/B_peer)  >  discovery - cdn_latency
                    \\_______ denom ______/       \\____ numer ____/

    `denom` = seconds the peer SAVES per NAR byte; `numer` = the discovery-latency
    premium the peer pays up front. The inequality `S*denom > numer` splits on the
    SIGN OF BOTH terms -- the earlier code collapsed the whole denom<=0 half-plane
    to NO SIZE THRESHOLD, which is only correct when numer >= 0:

      denom > 0 (peer faster per byte):
        numer <= 0 -> peer also wins on latency  -> PEER WINS AT EVERY SIZE
        numer  > 0 -> lower crossover S=numer/denom -> BREAK-EVEN ABOVE THRESHOLD
      denom == 0 (per-byte parity):
        numer  < 0 -> PEER WINS AT EVERY SIZE (size-independent latency win)
        numer >= 0 -> NO SIZE THRESHOLD EXISTS
      denom < 0 (peer SLOWER per byte -- the raw-NAR regime):
        numer >= 0 -> NO SIZE THRESHOLD EXISTS (loses per byte AND on latency)
        numer  < 0 -> peer's latency lead is eaten by size: it wins BELOW an
                       UPPER crossover S=numer/denom (>0) -> PEER WINS BELOW THRESHOLD

    denom > 0 requires B_peer > B_up/ratio; e.g. at the measured ratio ~0.3256 and
    a 21 MiB/s CDN the peer must sustain > ~64.5 MiB/s. (The legacy xz 0.278 figure
    would demand ~75 MiB/s, but it is a different codec/cohort and not used here.)
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

    no_threshold = {
        "verdict": NO_THRESHOLD,
        "interpretation": (
            "the peer saves nothing per NAR byte (it moves raw NAR, ~1/ratio the "
            "CDN's wire bytes) and holds no latency advantage; no size lets it catch "
            "up. Raw WAN loses at every size -- the expected honest baseline."
        ),
        "threshold_kind": None,
        "break_even_nar_size_bytes_uncompressed_nar": None,
    }

    if denom > 0:
        threshold = numer / denom
        if numer <= 0:
            result.update(
                verdict=PEER_WINS_EVERY,
                interpretation=(
                    "denom > 0 (peer faster per byte) AND discovery latency <= the "
                    "CDN's first-byte latency, so the peer wins at all sizes."
                ),
                threshold_kind="wins_at_every_size",
                break_even_nar_size_bytes_uncompressed_nar=None,
            )
        else:
            result.update(
                verdict=PEER_WINS_ABOVE,
                interpretation=(
                    "the peer wins for NAR sizes ABOVE the lower crossover, where "
                    "its per-byte bandwidth advantage overtakes the discovery premium."
                ),
                threshold_kind="lower_crossover_wins_above",
                break_even_nar_size_bytes_uncompressed_nar=threshold,
            )
    elif denom == 0:
        if numer < 0:
            result.update(
                verdict=PEER_WINS_EVERY,
                interpretation=(
                    "per-byte parity (denom == 0) but the peer's discovery latency "
                    "is below the CDN's first-byte latency, a size-independent win."
                ),
                threshold_kind="wins_at_every_size",
                break_even_nar_size_bytes_uncompressed_nar=None,
            )
        else:
            result.update(no_threshold)
    else:  # denom < 0: peer slower per byte
        if numer < 0:
            threshold = numer / denom  # neg/neg -> positive upper crossover
            result.update(
                verdict=PEER_WINS_BELOW,
                interpretation=(
                    "the peer starts ahead on latency but loses per byte, so it wins "
                    "only for NAR sizes BELOW the upper crossover; beyond it the "
                    "per-byte deficit overtakes the latency lead."
                ),
                threshold_kind="upper_crossover_wins_below",
                break_even_nar_size_bytes_uncompressed_nar=threshold,
            )
        else:
            result.update(no_threshold)
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
                    # Provider-side counter: the receiver's confirmed delivered
                    # bytes (== total, enforced by assert_full_delivery). This is
                    # what makes the arm non-vacuous -- a truncated transfer never
                    # reaches here.
                    "delivered_bytes_uncompressed_nar": shaped["recv_bytes"],
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
                    "delivered_bytes_uncompressed_nar": unshaped["recv_bytes"],
                    "wan_label_refused": refused,
                },
                # Raw arm transcripts retained as evidence: they carry the verbatim
                # sender (SEND_DONE bytes=) AND receiver (RECV_DONE bytes= expect=
                # status=) counter lines and the ping RTT lines, so the shaped-arm
                # measurement is auditable from the committed artifact.
                "shaped_arm_transcript": shaped.get("raw", ""),
                "loopback_arm_transcript": unshaped.get("raw", ""),
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
                "this artifact emits no known policy-selection field (producer-side "
                "tripwire, not a barrier against a downstream reader deriving its own "
                "decision); task-99 owns the codec + compressed re-evaluation, "
                "task-198 re-states the speedup."
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
        # A published report must be re-derivable from its own committed records:
        # never emit a headline that disagrees with the raw it carries.
        agg = (self.sample or {}).get("aggregate")
        if isinstance(agg, dict):
            verify_rederivable(agg)
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
                sig="sig:test:AAAA",
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
            sig="sig:test:AAAA",
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

    # --- AC#1 fail-closed: unknown-compression is its OWN bucket, NOT compressed.
    with_unknown = _good_samples() + [
        NarinfoSample("k" + "0" * 31, "mystery", "wizardry", 300, 1000, "sig:x")
    ]
    uagg = compressed_ratio_aggregate(with_unknown)
    if uagg["n_unknown_compression_excluded"] != 1:
        failures.append(
            "unknown-compression bite: an unrecognised codec was not classified into "
            "its own bucket (the fail-open path would fold it in as 'compressed')"
        )
    if uagg["n_compressed"] != 20:
        failures.append(
            "unknown-compression bite: the unknown-codec path leaked into the "
            "admitted compressed aggregate"
        )

    # --- AC#1 fail-closed: an UNSIGNED compressed path is excluded and counted.
    with_unsigned = _good_samples() + [
        NarinfoSample("n" + "0" * 31, "unsigned", "zstd", 300, 1000, "")
    ]
    sagg = compressed_ratio_aggregate(with_unsigned)
    if sagg["n_unsigned_excluded"] != 1:
        failures.append(
            "signed-admission bite: an unsigned compressed path was not excluded/"
            "counted (admission is not fail-closed on the signature)"
        )
    if sagg["n_compressed"] != 20:
        failures.append(
            "signed-admission bite: an unsigned path leaked into the aggregate"
        )

    # --- AC#1 re-derivability: the headline recomputes from the committed records,
    # and a doctored aggregate is REFUSED (the BLOCKER oracle).
    try:
        verify_rederivable(agg)
    except RederivationError as exc:
        failures.append(
            f"re-derivability: a clean aggregate was wrongly refused: {exc}"
        )
    tampered = json.loads(json.dumps(agg))  # deep copy via round-trip
    tampered["aggregate_file_over_nar_ratio"] = 0.999  # a lie vs the records
    try:
        verify_rederivable(tampered)
        failures.append(
            "re-derivability bite: a doctored ratio that disagrees with the records "
            "was NOT refused (this is the exact mutation that must go RED)"
        )
    except RederivationError:
        pass
    no_records = {k: v for k, v in agg.items() if k != "records"}
    try:
        verify_rederivable(no_records)
        failures.append(
            "re-derivability bite: an aggregate WITHOUT per-path records passed -- "
            "the headline must not be accepted as re-derivable when it is not"
        )
    except RederivationError:
        pass

    # --- AC#3: break-even across ALL FOUR latency quadrants, each pinned.
    MiB = 1024**2
    quadrants = [
        # (name, ratio, up, peer, cdn_lat, disc_lat, want_verdict, want_threshold)
        # denom<0 (peer slower/byte) & numer>0 (peer also slower to start):
        ("raw-wan-loses", 0.3256, 21 * MiB, 5 * MiB, 0.05, 1.0, NO_THRESHOLD, None),
        # denom>0 (peer faster/byte) & numer>0: finite LOWER crossover.
        (
            "lan-wins-above",
            0.3256,
            20 * MiB,
            200 * MiB,
            0.05,
            1.0,
            PEER_WINS_ABOVE,
            "finite+",
        ),
        # denom>0 & numer<=0 (peer faster/byte AND lower latency): every size.
        (
            "lan-wins-every",
            0.3256,
            20 * MiB,
            200 * MiB,
            0.05,
            0.0,
            PEER_WINS_EVERY,
            None,
        ),
        # denom<0 & numer<0 (peer slower/byte but lower latency): UPPER crossover.
        # ratio/up=0.05, 1/peer=0.1 -> denom=-0.05; numer=0.1-0.6=-0.5 -> S=10.0.
        ("peer-wins-below", 0.5, 10.0, 10.0, 0.6, 0.1, PEER_WINS_BELOW, 10.0),
        # denom==0 (per-byte parity) & numer<0: size-independent latency win.
        # ratio/up=0.05, 1/peer=0.05 -> denom=0; numer=-0.5 -> every size.
        ("parity-wins-every", 0.5, 10.0, 20.0, 0.6, 0.1, PEER_WINS_EVERY, None),
    ]
    for name, ratio, up, peer, cdn_lat, disc, want_v, want_t in quadrants:
        r = break_even(
            BreakEvenInputs(
                ratio=ratio,
                up_bytes_per_s=up,
                peer_bytes_per_s=peer,
                cdn_latency_s=cdn_lat,
                discovery_latency_s=disc,
            )
        )
        if r["verdict"] != want_v:
            failures.append(
                f"quadrant {name}: expected verdict {want_v!r}, got {r['verdict']!r}"
            )
        thr = r["break_even_nar_size_bytes_uncompressed_nar"]
        if want_t is None:
            if thr is not None:
                failures.append(f"quadrant {name}: expected no threshold, got {thr!r}")
        elif want_t == "finite+":
            if not (isinstance(thr, float) and thr > 0):
                failures.append(
                    f"quadrant {name}: expected a finite positive threshold, got {thr!r}"
                )
        else:
            if thr is None or abs(thr - want_t) > 1e-9:
                failures.append(
                    f"quadrant {name}: expected threshold {want_t}, got {thr!r}"
                )

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
    clustered = [
        NarinfoSample(f"h{i}", "p", "xz", 300, 1000, "sig:x") for i in range(200)
    ]
    cagg = compressed_ratio_aggregate(clustered)
    if not sample_gate(cagg, min_paths=200, min_span=1e3):
        failures.append(
            "sample_gate is vacuous: a clustered single-size sample passed the "
            "span check (the prior-figure flaw would slip through)"
        )

    # --- fail-CLOSED publish: build_sample_block REFUSES (publishes nothing) on a
    # failed gate, and SUCCEEDS on a good sample (proves it is not a blanket refusal).
    try:
        build_sample_block(clustered, min_paths=200, min_span=1e3)
        failures.append(
            "fail-closed bite: build_sample_block published an aggregate for a "
            "clustered sample that FAILS the gate (must raise SampleGateError and "
            "publish nothing)"
        )
    except SampleGateError:
        pass
    try:
        block = build_sample_block(_good_samples(), min_paths=20, min_span=100.0)
        if not block.get("gate_passed"):
            failures.append("fail-closed: a passing sample was not marked gate_passed")
    except SampleGateError as exc:
        failures.append(
            f"fail-closed false-positive: a good sample was refused publication: {exc}"
        )

    if failures:
        for f in failures:
            print(f"SELF-TEST FAIL: {f}", file=sys.stderr)
        return 1
    print(
        "SELF-TEST OK: compression-exclusion, unknown-compression, signed-admission, "
        "re-derivability, break-even-quadrants, loopback-label, unit-gate, "
        "policy-guard, span-gate and fail-closed-publish oracles all bite"
    )
    return 0


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def verify_artifact(path: Path) -> int:
    """Reload a committed artifact and RE-DERIVE the headline from its records.

    This is the auditor's entrypoint: it trusts none of the stored summary, finds
    the sample aggregate (or accepts a bare aggregate), recomputes every quantity
    from `records`, and prints the re-derived headline. Nonzero on any drift."""
    doc = json.loads(path.read_text())
    agg = doc
    if isinstance(doc, dict) and "cdn_wire_vs_peer_raw_sample" in doc:
        agg = doc["cdn_wire_vs_peer_raw_sample"].get("aggregate", {})
    elif isinstance(doc, dict) and "aggregate" in doc:
        agg = doc["aggregate"]
    try:
        fresh = verify_rederivable(agg)
    except RederivationError as exc:
        log(f"RE-DERIVATION FAILED for {path}: {exc}")
        return 1
    log(
        f"RE-DERIVED from {path}: n={fresh['n_compressed']} admitted paths, "
        f"FileSize/NarSize={fresh['aggregate_file_over_nar_ratio']:.10f} "
        f"(peer moves {fresh['peer_raw_over_cdn_wire_multiple']:.4f}x the CDN wire)"
    )
    print(
        json.dumps(
            {
                "verified_rederivable": True,
                "source": str(path),
                "rederived_aggregate_file_over_nar_ratio": fresh[
                    "aggregate_file_over_nar_ratio"
                ],
                "rederived_peer_raw_over_cdn_wire_multiple": fresh[
                    "peer_raw_over_cdn_wire_multiple"
                ],
                "rederived_n_compressed": fresh["n_compressed"],
            },
            indent=2,
        )
    )
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--self-test", action="store_true", help="prove the oracles bite")
    ap.add_argument(
        "--verify-artifact",
        default=None,
        help="re-derive the headline from a committed artifact JSON and exit",
    )
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

    if args.verify_artifact:
        return verify_artifact(Path(args.verify_artifact))

    report = Report()

    if args.sample > 0:
        seed_attrs = tuple(a.strip() for a in args.seed_attrs.split(",") if a.strip())
        seed_hashes, provenance = resolve_seed_hashes(seed_attrs)
        samples, stats = sample_real_cache(args.cache, seed_hashes, args.sample)
        samples += load_fixture_uncompressed(Path(args.fixture_manifest))
        # Fail CLOSED: a failed gate raises, we publish NO aggregate, exit nonzero.
        try:
            block = build_sample_block(
                samples, min_paths=args.min_paths, min_span=args.min_span
            )
        except SampleGateError as exc:
            log(f"SAMPLE GATE FAILED -- publishing NO aggregate: {exc.violations}")
            return 2
        agg = block["aggregate"]
        report.sample = {"provenance": provenance, "fetch_stats": stats, **block}
        log(
            f"sample: {agg['n_compressed']} admitted (signed+compressed) paths, "
            f"aggregate FileSize/NarSize={agg['aggregate_file_over_nar_ratio']:.4f} "
            f"(peer moves {agg['peer_raw_over_cdn_wire_multiple']:.2f}x), excluded: "
            f"{agg['n_uncompressed_excluded']} uncompressed / "
            f"{agg['n_unknown_compression_excluded']} unknown-codec / "
            f"{agg['n_unsigned_excluded']} unsigned"
        )

    if args.shaped_link:
        sizes = tuple(int(m) for m in args.shaped_sizes_mib.split(","))
        report.throughput = measure_shaped_throughput(
            sizes, args.delay_ms, args.rate_mbit
        )

    # Break-even scenarios over the MEASURED ratio, in a home-uplink and a LAN-peer
    # regime (both bandwidths ASSUMED), plus the measured-shaped-peer regime when a
    # shaped arm ran. All bandwidth/latency inputs except the shaped peer bandwidth
    # are ASSUMED, not re-measured here -- flagged per scenario.
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
        _assumed = "ASSUMED (scripts/profile_p2p.py / task-35 real-upstream; not re-measured here)"
        # (name, up, peer, cdn_lat, disc_lat, peer_bw_measured)
        scenarios = [
            (
                "home_uplink_5MiBps",
                ASSUMED_CDN_BYTES_PER_S,
                ASSUMED_HOME_PEER_BYTES_PER_S,
                0.05,
                1.0,
                False,
            ),
            (
                "lan_peer_125MiBps",
                ASSUMED_CDN_BYTES_PER_S,
                ASSUMED_LAN_PEER_BYTES_PER_S,
                0.05,
                0.2,
                False,
            ),
        ]
        if peer_bw is not None:
            scenarios.append(
                (
                    "measured_shaped_peer",
                    ASSUMED_CDN_BYTES_PER_S,
                    peer_bw,
                    0.05,
                    1.0,
                    True,
                )
            )
        for name, up, peer, cdn_lat, disc_lat, peer_measured in scenarios:
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
            # Provenance: every input except (optionally) the shaped peer bandwidth
            # is assumed, not measured by this script.
            r["inputs"]["assumed_not_measured_here"] = not peer_measured
            r["input_provenance"] = {
                "upstream_bandwidth": _assumed,
                "cdn_latency_s": "ASSUMED (illustrative)",
                "discovery_latency_s": "ASSUMED (illustrative)",
                "peer_bandwidth": (
                    "MEASURED (this run's shaped arm, raw NAR bytes/s)"
                    if peer_measured
                    else "ASSUMED (illustrative)"
                ),
                "units": "all bandwidths are bytes/s of MiB/s constants (1024**2)",
            }
            report.break_even_scenarios.append(r)

    final = report.finalize()
    print(json.dumps(final, indent=2))
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(final, indent=2))
        log(f"wrote {args.json_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
