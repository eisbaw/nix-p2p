#!/usr/bin/env python3
"""TASK-65: the axis that actually binds - RSS against the SIZE of what a node
serves, and against how many serves OVERLAP.

`scripts/profile_p2p.py` owns the peer-COUNT axis (task-42): n holder processes at
roughly constant held bytes, which correctly found per-peer RSS flat at 19-21 MiB.
That says nothing about the constraint a real deployment hits. A node's memory is
bounded by the SIZE of the content it holds and serves, and by how many of those
serves are in flight at once. This module is that axis, kept in its own file
because `profile_p2p` is already 4.5k lines and a second sweep bolted into it
would be a third copy of "how a sweep decides a point is valid".

WHAT IS FITTED, and what the fitted number MEANS
------------------------------------------------
n is the UNCOMPRESSED NAR SIZE IN BYTES (NarSize units - `nix-store --dump`
output length). It is never FileSize; the synthesised payloads are
`Compression: none` so the two coincide by construction, and
`unit_coincidence()` asserts it rather than assuming it.

The quantity a reader quotes off this axis is the SLOPE - bytes of resident
memory per byte of NAR - for the HOLDER (node-b, which seeds the NAR into its
iroh-blobs store) and for the FETCHER (node-a, which buffers the whole NAR before
the client sees a byte). Both come with a 95% confidence interval
(`scalefit.slope_interval`), because TASK-61's and TASK-62's RSS criteria are
claims about a SLOPE and a slope tested at one size is unfalsifiable.

Extrapolation targets are SIZES (256 MiB / 1 GiB / 8 GiB), not the swarm axis's
10/100/1000 - extrapolating a per-byte RSS law to "n = 10" would be a statement
about a ten-BYTE NAR.

THE CONCURRENCY DIMENSION, and why the overlap is measured at the HOLDER
-----------------------------------------------------------------------
k overlapping serves of the same size, k DISTINCT blobs so nothing dedupes. The
overlap is measured from the HOLDER's own per-transfer windows
(`IROH-SERVE-WINDOW`, daemon-side, task-65) and a point whose measured overlap is
not k is INVALID - the task-18 rule.

Measuring the overlap at the fetching HTTP client would have been vacuous: k
client request windows overlap even when the daemon serialises the peer fetches
internally, so the precondition could not fail. That is the exact shape of the
three vacuous oracles this project has already shipped.

THE RESIDENCY ORACLE IS NOT PEAK RSS
------------------------------------
`IROH-STORE-RESIDENT` carries what the holder's blob store says it HOLDS, asked
of the store itself. Peak RSS cannot answer that question - `VmHWM` is monotone,
so it never observes a release, and glibc need not return a freed arena, so
`VmRSS` need not either. The discrimination is proven by mutation in
`daemon/tests/store_residency_oracle.rs`; this module consumes the reading, and
FAILS THE POINT when the reading is absent (unknown is not zero).

The profiler RECORDS residency and asserts only what is true of any correct
implementation - the store cannot hold MORE than was seeded, and the reading must
exist. It deliberately does NOT assert "residency == seeded": that is today's
retain-everything policy, and gating on it would make TASK-61's or TASK-62's
correct eviction change fail `just profile`.

WHY A HOST-SIDE HTTP READER AND NOT A REAL `nix build`
------------------------------------------------------
The thing under measurement is the DAEMON's memory: node-b's store and node-a's
whole-NAR buffer. A real nix client would add a container, a store and a disk
write per point without changing either daemon's memory behaviour, and this axis
needs >= 5 sizes x replicates x a concurrency grid on a host with 45 GiB free.
So the consumer is a host-side streaming HTTP GET through node-a - the same
observation point `profile_p2p.probe_upstream_link` already uses.

STATED LIMIT: this measures the daemon, not the end-to-end build. Latency numbers
from this axis are transport-and-buffer numbers and are NOT comparable with the
speedup arm's `realise_s`, which includes real nix. Nothing here produces a
speedup ratio, on purpose.

The payloads are SYNTHESISED: real `nix-archive-1` framing, real sha256 NarHash,
really signed with the fixture key - but never realised by nix. They exist to
move bytes of a known length through the peer path. They are built into a scratch
cache and deleted with it.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import random
import shutil
import statistics
import sys
import time
import traceback
import urllib.request
from dataclasses import dataclass
from pathlib import Path

import e2e_harness as e2e
import fixturelib as fx
import scale_sweep as ss
import scalefit

# ---- frozen constants -------------------------------------------------------

SIZE_RULE_VERSION = "p2p-size-axis-v1"

# The size grid, in MiB of UNCOMPRESSED NAR. Five distinct values because
# `scalefit.MIN_POINTS` is 5 and the fitter RAISES below that rather than
# guessing; 8..128 is a 16x span, which is what lets a slope be separated from an
# intercept at all. Every value is a multiple of 8 so `synth_raw_nar` hits the
# target NAR length EXACTLY (see `payload_bytes_for`).
DEFAULT_SIZE_GRID_MIB = (8, 16, 32, 64, 128)

# Replicates per size. Fitted as separate observations at the same n, never
# averaged: the fitter needs the spread to size the slope interval honestly, and
# 5 points with 3 draws each gives 13 residual dof instead of 3.
DEFAULT_SIZE_REPEATS = 3

# The concurrency grid and the size it runs at. FIVE distinct k, because a fitted
# "RAM per concurrent serve" is the number the owner goal's pathological scenario
# needs and `scalefit.MIN_POINTS` is 5; a shorter grid is still measured but is
# reported UNFITTED rather than fitted on three points. 32 MiB is mid-grid: large
# enough that k concurrent serves separate from the ~20 MiB process floor, small
# enough that k=5 (160 MiB held and 160 MiB buffered) is not a host memory
# experiment.
DEFAULT_CONCURRENCY = (1, 2, 3, 4, 5)
CONCURRENCY_SIZE_MIB = 32

# Extrapolation targets for the SIZE axis, in uncompressed NAR bytes. A size axis
# extrapolated to the swarm axis's 10/100/1000 would be predicting the RSS cost
# of a ten-byte NAR, which is not a question anybody has.
SIZE_EXTRAPOLATION_TARGETS_BYTES = (256 * 1024**2, 1024**3, 8 * 1024**3)

# NAR framing overhead for a single regular file (see `payload_bytes_for`).
NAR_FRAMING_OVERHEAD_BYTES = 112

# How much free disk the graded fixtures need per byte of payload. Each NAR is
# written once into the scratch cache and once more into a per-point seed dir
# (`e2e.build_p2p_seed_dir` copies it), so 2x is the floor; 3x leaves room for
# the copy to exist while the previous point's is being removed.
GRADED_DISK_FACTOR = 3
# Absolute slack on top, for container state dirs and the podman image layer.
GRADED_DISK_SLACK_BYTES = 2 * 1024**3

# Bound on one host-side NAR GET. Generous: this bounds a HANG, it is not a
# latency assertion. 128 MiB over the loopback peer path measures in seconds.
FETCH_TIMEOUT_S = 300.0

# How long to wait for the holder's monitor to log a serve window / residency
# reading after the transfer completed. The monitor polls at 200 ms.
HOLDER_LOG_SETTLE_S = 3.0

# Two derived rates whose ratio has a coefficient of variation below this are
# indistinguishable from ONE quantity restated (TASK-68). Deliberately tiny: the
# gate is for algebraic identity, not for correlation - two genuinely different
# rates that happen to track each other are a finding, not a violation.
DERIVED_IDENTITY_CV = 1e-9


# ---- pure: payload synthesis ------------------------------------------------


def payload_bytes_for(nar_bytes: int) -> int:
    """Content length whose single-file NAR is EXACTLY `nar_bytes` long.

    The `nix-archive-1` framing of one regular file costs a fixed 112 bytes:
    six length-prefixed, 8-padded tokens (`nix-archive-1` 24, `(` 16, `type` 16,
    `regular` 16, `contents` 16, `)` 16 = 104) plus the contents' own 8-byte
    length prefix. With `nar_bytes` a multiple of 8 the contents need no padding,
    so the NAR length is EXACT and the fitted axis's n values are the round
    numbers they claim to be rather than "about 8 MiB". The self-test asserts the
    exact length at every grid size, because an axis whose n is not the number it
    prints is worse than no axis.
    """
    if nar_bytes % 8 != 0:
        raise ValueError(f"NAR size {nar_bytes} must be a multiple of 8")
    if nar_bytes <= NAR_FRAMING_OVERHEAD_BYTES:
        raise ValueError(
            f"NAR size {nar_bytes} is not larger than the {NAR_FRAMING_OVERHEAD_BYTES} "
            "byte framing overhead"
        )
    return nar_bytes - NAR_FRAMING_OVERHEAD_BYTES


def _nar_token(out: bytearray, raw: bytes) -> None:
    out += len(raw).to_bytes(8, "little")
    out += raw
    out += b"\x00" * ((8 - (len(raw) % 8)) % 8)


def synth_raw_nar(contents: bytes) -> bytes:
    """A valid raw (uncompressed) `nix-archive-1` NAR for one regular file.

    The same framing `daemon/tests/*.rs` synthesises, and the same one
    `nix-store --dump` emits for a single file - so the bytes that cross the peer
    path are a real NAR of a known length, not an opaque blob called one.
    """
    out = bytearray()
    _nar_token(out, b"nix-archive-1")
    _nar_token(out, b"(")
    _nar_token(out, b"type")
    _nar_token(out, b"regular")
    _nar_token(out, b"contents")
    _nar_token(out, contents)
    _nar_token(out, b")")
    return bytes(out)


def synth_contents(length: int, seed: int) -> bytes:
    """`length` deterministic, non-constant bytes.

    NOT zeros: a page of zeros is exactly the thing a kernel or a container
    runtime is entitled to share, and this module's whole output is a resident
    memory measurement. Tiled from a 64 KiB pseudo-random block rather than
    drawn byte-by-byte, because 128 MiB of `random` calls is minutes and 128 MiB
    of tiling is milliseconds; the payload's job is to occupy pages, not to be
    incompressible (every payload here is `Compression: none`, so nothing
    compresses it anyway).
    """
    block = random.Random(seed).randbytes(min(length, 65536)) or b"\x00"
    repeats = length // len(block) + 1
    return (block * repeats)[:length]


@dataclass(frozen=True)
class GradedPayload:
    """One synthesised payload on the size axis."""

    attr: str
    nar_bytes_uncompressed_nar: int
    store_path: str
    nar_hash: str
    url: str


def build_graded_cache(
    root: Path, plan: list[tuple[str, int]], nix_cache_info: str
) -> tuple[e2e.Fixtures, list[GradedPayload]]:
    """Materialise a signed, `Compression: none` binary cache for `plan`.

    `plan` is [(attr, nar_bytes)]. Returns an `e2e.Fixtures` the existing Pod and
    seed-dir machinery consume unchanged - deliberately the SAME type, so this
    module drives `e2e.Pod` and `e2e.build_p2p_seed_dir` through their real
    seams rather than through a parallel implementation that could drift.

    HONESTY, stated at the source rather than discovered in the report: these
    store paths are SYNTHETIC. The narinfos are correctly signed with the fixture
    key and the NarHash really is sha256 of the NAR, so every check the daemon
    performs is a real check - but no nix ever built these, and the store path
    hash is derived from the content rather than from a derivation. They exist to
    move a known number of bytes through the peer path. Nothing in this module
    hands them to a nix client.
    """
    cache = root / "cache"
    (cache / "nar").mkdir(parents=True)
    (cache / "nix-cache-info").write_text(nix_cache_info)
    key_name, private, _secret_line, public_line = fx.keypair()

    payloads: list[GradedPayload] = []
    for index, (attr, nar_bytes) in enumerate(plan):
        contents = synth_contents(payload_bytes_for(nar_bytes), seed=0x65_0000 + index)
        nar = synth_raw_nar(contents)
        if len(nar) != nar_bytes:
            raise ValueError(
                f"{attr}: synthesised NAR is {len(nar)} B but {nar_bytes} B was "
                "requested - the framing arithmetic is wrong, and an axis whose n "
                "is not the number it says is worse than no axis"
            )
        digest = hashlib.sha256(nar).digest()
        nar_hash = "sha256:" + fx.nix_base32(digest)
        # A store path hash is 20 bytes of nix-base32. Derived from the content so
        # the tree is reproducible and two payloads never collide.
        path_hash = fx.nix_base32(hashlib.sha256(b"task-65-" + digest).digest()[:20])
        store_path = f"{fx.STORE_DIR}/{path_hash}-{attr}"
        url = f"nar/{path_hash}.nar"
        (cache / url).write_bytes(nar)
        pairs = [
            ("StorePath", store_path),
            ("URL", url),
            ("Compression", "none"),
            # Compression: none, so FileHash/FileSize ARE NarHash/NarSize. Written
            # out rather than omitted because `fx.REQUIRED_NARINFO_FIELDS` lists
            # them and a half-populated narinfo is not a fixture.
            ("FileHash", nar_hash),
            ("FileSize", str(len(nar))),
            ("NarHash", nar_hash),
            ("NarSize", str(len(nar))),
            ("References", ""),
            ("Sig", ""),
        ]
        pairs = fx.sign_narinfo(pairs, private, key_name)
        if not fx.verify_narinfo(pairs, public_line):
            raise ValueError(f"{attr}: freshly signed narinfo does not verify")
        (cache / fx.narinfo_name(store_path)).write_text(fx.format_narinfo(pairs))
        payloads.append(
            GradedPayload(
                attr=attr,
                nar_bytes_uncompressed_nar=len(nar),
                store_path=store_path,
                nar_hash=nar_hash,
                url=url,
            )
        )

    manifest = {
        "workload_version": SIZE_RULE_VERSION,
        "public_key": public_line,
        "paths": [
            {
                "attr": p.attr,
                "compression": "none",
                "store_path": p.store_path,
                "url": p.url,
                "nar_hash": p.nar_hash,
                "nar_size": p.nar_bytes_uncompressed_nar,
                "file_size": p.nar_bytes_uncompressed_nar,
            }
            for p in payloads
        ],
    }
    fixtures = e2e.Fixtures(
        generation=root,
        cache=cache,
        manifest=manifest,
        public_key=public_line,
    )
    return fixtures, payloads


def unit_coincidence(payloads: list[GradedPayload], manifest: dict) -> dict:
    """ASSERT, do not assume, that every graded payload's wire size equals its
    NarSize.

    The whole axis is stated in uncompressed NAR bytes. If a payload were ever
    generated compressed, the fetcher's measured bytes would be FileSize while
    the axis's n was NarSize, and the fitted slope would silently be a ratio
    across two different units - the confusion this project has now made three
    times. Raises rather than returning a flag: there is no useful partial run.
    """
    bad = []
    for entry in manifest["paths"]:
        if entry["compression"] != "none" or entry["file_size"] != entry["nar_size"]:
            bad.append(
                f"{entry['attr']}: compression={entry['compression']} "
                f"file_size={entry['file_size']} nar_size={entry['nar_size']}"
            )
    if bad:
        raise ValueError(
            "the size axis is stated in UNCOMPRESSED NAR bytes and requires "
            "`compression: none` payloads so the wire size coincides; it does not "
            "for " + "; ".join(bad)
        )
    return {
        "payloads": len(payloads),
        "all_uncompressed": True,
        "why": (
            "n is NarSize (uncompressed, signed). With Compression: none the "
            "bytes read at the HTTP client are the same unit, so the fetcher's "
            "measured byte count and the axis's n are comparable BY CHECKED "
            "PRECONDITION rather than by hope."
        ),
    }


# ---- pure: disk precondition ------------------------------------------------


def graded_disk_requirement_bytes_ondisk(plan: list[tuple[str, int]]) -> int:
    """Free disk this module needs for `plan`, fail-fast before anything runs."""
    return (
        sum(size for _attr, size in plan) * GRADED_DISK_FACTOR + GRADED_DISK_SLACK_BYTES
    )


def disk_precondition_violations(
    free_bytes_ondisk: int, plan: list[tuple[str, int]]
) -> list[str]:
    """Empty == there is room. A named violation == there is not.

    Separate from `profile_p2p`'s flat 8 GiB floor because this arm's appetite is
    a FUNCTION of the grid: someone widening `--size-grid` must be told the new
    number, not the old constant. The host this was developed on ran at 95% used
    with 45 GiB free, which is the tightest constraint any task here has had.
    """
    need = graded_disk_requirement_bytes_ondisk(plan)
    if free_bytes_ondisk >= need:
        return []
    return [
        f"the size axis needs {need / 1024**3:.1f} GiB free (grid totals "
        f"{sum(s for _a, s in plan) / 1024**2:.0f} MiB of NAR, written once into "
        f"the scratch cache and once per point into a seed dir, x{GRADED_DISK_FACTOR} "
        f"+ {GRADED_DISK_SLACK_BYTES / 1024**3:.0f} GiB slack) but only "
        f"{free_bytes_ondisk / 1024**3:.1f} GiB is free. Refusing to start rather "
        "than dying with ENOSPC mid-run; shrink --size-grid or free space, and if "
        "the grid you need does not fit, that belongs on TASK-54 rather than "
        "quietly reducing coverage"
    ]


# ---- pure: holder-log parsing (the two task-65 daemon lines) ----------------


def parse_serve_windows(log: str) -> list[dict]:
    """Every `IROH-SERVE-WINDOW` the holder logged, in log order.

    Returns [{start_ms, end_ms, served_bytes_uncompressed_nar}]. An empty list means the
    holder recorded no completed serve - which every caller must treat as "no
    evidence of a peer serve", never as a zero-concurrency measurement.
    """
    windows = []
    for line in log.splitlines():
        if not line.startswith("IROH-SERVE-WINDOW "):
            continue
        fields = {}
        for token in line.split()[1:]:
            key, _, value = token.partition("=")
            fields[key] = value
        try:
            windows.append(
                {
                    "start_ms": float(fields["start_ms"]),
                    "end_ms": float(fields["end_ms"]),
                    "served_bytes_uncompressed_nar": int(
                        fields["bytes_uncompressed_nar"]
                    ),
                }
            )
        except (KeyError, ValueError):
            # A malformed line is DROPPED and the shortfall shows up as a failed
            # overlap precondition. Silently coercing it to a window would be a
            # fabricated serve.
            continue
    return windows


def parse_store_residency(log: str) -> dict | None:
    """The LAST `IROH-STORE-RESIDENT` reading, or None when there is none.

    None means UNKNOWN. Every caller must invalidate the point rather than
    substitute 0: "we could not see what the store holds" and "the store holds
    nothing" are opposite findings, and conflating them is how a residency claim
    becomes unfalsifiable.
    """
    found = None
    for line in log.splitlines():
        if not line.startswith("IROH-STORE-RESIDENT "):
            continue
        fields = {}
        for token in line.split()[1:]:
            key, _, value = token.partition("=")
            fields[key] = value
        try:
            found = {
                "blobs": int(fields["blobs"]),
                "resident_bytes_uncompressed_nar": int(
                    fields["bytes_uncompressed_nar"]
                ),
            }
        except (KeyError, ValueError):
            continue
    return found


def residency_violations(residency: dict | None, seeded_bytes_uncompressed_nar: int):
    """What the profiler may ASSERT about a residency reading. Empty == fine.

    Two rules only, and the choice of which two is the point:

      * the reading must EXIST. Absent is invalid, not zero.
      * the store may not hold MORE than was seeded into it. A store reporting
        more than it was given is broken under any retention policy.

    NOT asserted: `residency == seeded`. That is today's retain-everything
    behaviour, and gating on it would turn TASK-61's or TASK-62's CORRECT
    eviction change into a `just profile` failure. What the report does instead
    is RECORD the ratio, so the change shows up as a number that moved.
    """
    if residency is None:
        return [
            "no IROH-STORE-RESIDENT reading from the holder: what its blob store "
            "holds is UNKNOWN, and unknown is not zero. The residency oracle is "
            "the reason this axis exists, so a point without it is invalid"
        ]
    if residency["resident_bytes_uncompressed_nar"] > seeded_bytes_uncompressed_nar:
        return [
            f"holder store reports {residency['resident_bytes_uncompressed_nar']} B resident "
            f"but only {seeded_bytes_uncompressed_nar} B were seeded - a store "
            "cannot hold more than it was given"
        ]
    return []


# ---- pure: concurrency ------------------------------------------------------


def measured_overlap(windows: list[dict]) -> int:
    """Peak simultaneous serves across `windows`, measured at the HOLDER.

    Delegates the interval algebra to `scale_sweep.max_overlap` - one definition
    of "how many of these were happening at once" in this repo, not two - after
    converting the holder's float milliseconds to integer microseconds.
    """
    return ss.max_overlap(
        [(int(w["start_ms"] * 1000), int(w["end_ms"] * 1000)) for w in windows]
    )


def concurrency_violations(windows: list[dict], k: int) -> list[str]:
    """The task-18 rule for this axis. Empty == the point is honestly labelled.

    A point labelled k=4 whose serves took turns is MISLABELLED DATA, not noisy
    data, and averaging it into a fitted law would report the cost of one serve
    as the cost of four.
    """
    problems = []
    if len(windows) != k:
        problems.append(
            f"holder logged {len(windows)} completed serve window(s) for k={k}: "
            "the point did not run the workload it is labelled with"
        )
    observed = measured_overlap(windows)
    if observed != k:
        problems.append(
            f"MEASURED overlap at the holder is {observed}, not k={k}. The serves "
            "did not actually coincide, so this point is mislabelled data - the "
            "overlap is measured, never assumed (task-18)"
        )
    return problems


# ---- pure: the peer-side transport rate, and the derived-quantity gate -------


def peer_serve_rate(windows: list[dict]) -> dict:
    """Bytes the HOLDER served divided by the time it was actually serving.

    This closes the peer-side half of TASK-68. The upstream half already has a
    real link rate (`upstream_nar_transport_bytes_compressed_wire_per_s`, from
    the testproxy's own per-record bytes/duration); the peer side had none, and
    the figure that used to stand in for one was a latency reciprocal wearing a
    throughput name.

    The DENOMINATOR is what makes it a rate rather than a restatement: the union
    of the holder's own per-transfer windows, on the holder's clock, from
    iroh-blobs' Started/Completed events. It contains no dial setup, no HTTP
    framing and no client-side accumulate-or-verify time, so it is not derivable
    from any latency figure this report quotes -
    `derived_quantity_independence` checks that mechanically rather than trusting
    this paragraph.

    NOT COMPARABLE WITH TASK-64's 204 MB/s, and named `holder_send` so it cannot
    be quoted as if it were. Task-64 measured the FETCHER's end-to-end
    `IrohTransport::fetch` - dial, receive, bao-verify and accumulate. This is the
    HOLDER's send side only, which finishes earlier, so it is larger by
    construction (measured here: ~447 MB/s at one serve). Two numbers describing
    different halves of one transfer are not a speedup and not a contradiction.
    """
    if not windows:
        return {"measured": False, "why": "the holder recorded no completed serve"}
    total_bytes = sum(w["served_bytes_uncompressed_nar"] for w in windows)
    # UNION of the windows, not the sum of their lengths: with k overlapping
    # serves the sum would double-count wall time and understate the rate. The
    # union is the interval during which the provider was serving anything.
    span_ms = max(w["end_ms"] for w in windows) - min(w["start_ms"] for w in windows)
    if span_ms <= 0.0:
        return {
            "measured": False,
            "why": "the holder's serve window has zero length; a rate would be a "
            "division by zero, not a fast transfer",
        }
    return {
        "measured": True,
        "serves": len(windows),
        "served_bytes_uncompressed_nar": total_bytes,
        "holder_serving_span_s": span_ms / 1000.0,
        "holder_send_bytes_uncompressed_nar_per_s": (total_bytes / (span_ms / 1000.0)),
        "denominator": (
            "the union of the HOLDER's own per-transfer windows (iroh-blobs "
            "Started->Completed, holder clock). Not a client latency, not a "
            "realise duration - see `derived_quantity_independence`"
        ),
    }


def derived_quantity_independence(
    name_a: str, series_a: list[float], name_b: str, series_b: list[float]
) -> dict:
    """Are two quoted rates ACTUALLY two quantities, or one restated?

    The mechanical half of TASK-68. task-42 reported a "throughput" that was the
    latency figure rescaled by a constant, so `throughput_ratio` was identically
    `1/latency_ratio` and the report appeared to corroborate itself. Two
    quantities related by a constant factor have a RATIO WITH ZERO VARIANCE
    across points; that is checkable without knowing anything about either one.

    A very small CV threshold on purpose: the gate is for ALGEBRAIC IDENTITY, not
    for correlation. Two genuinely different rates that happen to track each
    other closely are a finding about the system, and flagging that as a
    reporting defect would make the gate the thing people learn to ignore.
    """
    pairs = [
        (a, b)
        for a, b in zip(series_a, series_b)
        if a is not None and b is not None and b != 0
    ]
    if len(pairs) < 2:
        return {
            "checked": False,
            "quantities": [name_a, name_b],
            "why": "fewer than 2 paired observations; independence is not testable",
        }
    ratios = [a / b for a, b in pairs]
    mean = statistics.fmean(ratios)
    stdev = statistics.pstdev(ratios)
    cv = abs(stdev / mean) if mean else float("inf")
    identical = cv < DERIVED_IDENTITY_CV
    return {
        "checked": True,
        "quantities": [name_a, name_b],
        "paired_observations": len(pairs),
        "ratio_mean": mean,
        "ratio_coefficient_of_variation": cv,
        "algebraically_identical": identical,
        "verdict": (
            f"{name_a} and {name_b} are ONE quantity restated (their ratio is "
            f"constant to within {cv:.2e}); quoting both as evidence is circular"
            if identical
            else f"{name_a} and {name_b} vary independently (ratio CV {cv:.3f}), so "
            "neither is a rescaling of the other"
        ),
    }


# ---- pure: point assembly ---------------------------------------------------

# (metric key, unit, description) fitted against NAR SIZE IN BYTES.
SIZE_METRICS = (
    (
        "holder_rss_hwm_bytes_ram",
        "bytes (RSS)",
        "holder peak RSS (VmHWM) vs held NAR size, uncompressed NAR bytes",
    ),
    (
        "fetcher_rss_hwm_bytes_ram",
        "bytes (RSS)",
        "fetcher peak RSS (VmHWM) vs fetched NAR size, uncompressed NAR bytes",
    ),
    (
        "holder_store_resident_bytes_uncompressed_nar",
        "bytes (NarSize)",
        "holder store residency vs held NAR size, uncompressed NAR bytes",
    ),
    (
        "fetcher_fd_max",
        "descriptors",
        "fetcher peak open fds vs fetched NAR size, uncompressed NAR bytes",
    ),
)

# The same metrics against the CONCURRENCY variable. `client_realise_s` has no
# analogue here on purpose: there is no nix client on this arm.
CONCURRENCY_METRICS = (
    (
        "holder_rss_hwm_bytes_ram",
        "bytes (RSS)",
        "holder peak RSS (VmHWM) vs concurrent serves at a fixed NAR size",
    ),
    (
        "fetcher_rss_hwm_bytes_ram",
        "bytes (RSS)",
        "fetcher peak RSS (VmHWM) vs concurrent serves at a fixed NAR size",
    ),
    (
        "fetcher_fd_max",
        "descriptors",
        "fetcher peak open fds vs concurrent serves at a fixed NAR size",
    ),
)

HOLDER_ROLE = "node-b"
FETCHER_ROLE = "node-a"


def role_metrics(resources: dict) -> dict:
    """Per-ROLE RSS/fd figures, unit-labelled, holder and fetcher named.

    Named roles rather than a max across daemons: the two ends of this axis
    answer DIFFERENT questions (what a node pays to HOLD vs to FETCH) and
    collapsing them to a worst-node figure would fit one law through two.
    """
    per_role = resources["per_role"]
    missing = [r for r in (HOLDER_ROLE, FETCHER_ROLE) if r not in per_role]
    if missing:
        raise ss.SampleError(
            f"no samples for {missing} - the size axis is a holder-vs-fetcher "
            "comparison and cannot be reported with one end missing"
        )
    out = {}
    for label, role in (("holder", HOLDER_ROLE), ("fetcher", FETCHER_ROLE)):
        row = per_role[role]
        out[f"{label}_rss_hwm_bytes_ram"] = row["rss_hwm_bytes"]
        out[f"{label}_rss_point_max_bytes_ram"] = row["rss_point_max_bytes"]
        out[f"{label}_fd_max"] = row["fd_max"]
    return out


def ram_per_nar_byte(metrics: dict, nar_bytes_uncompressed_nar: int) -> dict:
    """Peak RSS per byte of NAR, per end. A legitimate CROSS-UNIT RATIO (the two
    units are named in the key); a cross-unit SUM would not be."""
    if nar_bytes_uncompressed_nar <= 0:
        return {"measured": False}
    return {
        "measured": True,
        "nar_bytes_uncompressed_nar": nar_bytes_uncompressed_nar,
        "holder_peak_rss_ram_per_nar_byte_ratio": (
            metrics["holder_rss_hwm_bytes_ram"] / nar_bytes_uncompressed_nar
        ),
        "fetcher_peak_rss_ram_per_nar_byte_ratio": (
            metrics["fetcher_rss_hwm_bytes_ram"] / nar_bytes_uncompressed_nar
        ),
    }


def slope_line(fit: dict) -> str:
    """One human line for a fitted slope WITH its interval, or a refusal.

    A slope printed without its interval is the single-point claim this whole
    task exists to replace, so the formatter has no path that prints one.
    """
    metric = fit.get("metric", "?")
    if fit.get("slope_ci95") is None:
        return (
            f"    {metric}: model {fit.get('selected_label')} - NO SLOPE INTERVAL "
            "(the selected model has no estimable slope, or the design has no "
            "residual degrees of freedom). Not quotable as a per-byte cost."
        )
    low, high = fit["slope_ci95"]
    return (
        f"    {metric}: {fit['slope']:.4f} "
        f"[95% CI {low:.4f} .. {high:.4f}] {fit.get('unit')} per byte of NAR "
        f"(model {fit.get('selected_label')}, R^2={fit.get('r_squared'):.4f}, "
        f"distinguishable from zero: {fit.get('slope_distinguishable_from_zero')})"
    )


# ---- container arms ---------------------------------------------------------


def _stream_get(
    url: str, timeout_s: float = FETCH_TIMEOUT_S
) -> tuple[int, float, float]:
    """GET `url`, stream the body to nowhere. Returns (bytes, start_s, end_s).

    Streamed rather than `.read()`: a host-side probe that resident-sizes a
    128 MiB NAR would be measuring its own allocator alongside the daemon's.
    Absolute monotonic timestamps are returned (not a duration) because the
    concurrency arm needs INTERVALS, not lengths.
    """
    started = time.monotonic()
    total = 0
    with urllib.request.urlopen(url, timeout=timeout_s) as response:  # noqa: S310
        while True:
            chunk = response.read(1 << 20)
            if not chunk:
                break
            total += len(chunk)
    return total, started, time.monotonic()


def fetch_through_fetcher(payload: GradedPayload) -> dict:
    """One narinfo + NAR GET through node-a, exactly as a nix client would order
    them (the narinfo is what correlates the NAR token to a claim).

    Returns the measurement; RAISES nothing on a short body - the caller decides
    validity, because a short read is a data point about the daemon and this
    function's job is to observe, not to judge.
    """
    base = f"http://127.0.0.1:{e2e.HOST_DAEMON}"
    narinfo_url = f"{base}/{fx.narinfo_name(payload.store_path)}"
    with urllib.request.urlopen(narinfo_url, timeout=60.0) as response:  # noqa: S310
        served_narinfo = response.read().decode()
    pairs = fx.parse_narinfo(served_narinfo)
    # The URL the DAEMON serves, not the one upstream published: on the peer path
    # the daemon rewrites it to the raw NAR (task-49). Reading it back is what
    # makes this probe follow the product's own indirection instead of assuming
    # it.
    nar_url = f"{base}/{fx.field(pairs, 'URL')}"
    read_bytes, started, ended = _stream_get(nar_url)
    return {
        "attr": payload.attr,
        "expected_bytes_uncompressed_nar": payload.nar_bytes_uncompressed_nar,
        "read_bytes_uncompressed_nar": read_bytes,
        "served_compression": fx.field(pairs, "Compression"),
        "client_started_s": started,
        "client_ended_s": ended,
        "client_elapsed_s": ended - started,
    }


def _drive_fetches(payloads: list[GradedPayload]) -> list[dict]:
    """Fetch every payload, CONCURRENTLY when there is more than one.

    One thread per payload with no barrier: the overlap that matters is measured
    at the holder afterwards, so a barrier here would only make the harness look
    more careful without making the measurement more true.
    """
    if len(payloads) == 1:
        return [fetch_through_fetcher(payloads[0])]
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(payloads)) as pool:
        return list(pool.map(fetch_through_fetcher, payloads))


def measure_point(
    ctx,
    fixtures: e2e.Fixtures,
    payloads: list[GradedPayload],
    *,
    n: int,
    name: str,
    state_root: Path,
    expect_overlap: int | None,
) -> ss.SweepPoint:
    """One point: stand up holder+fetcher, fetch `payloads` through the fetcher,
    and record both ends' resources, the holder's residency and its serve windows.

    `expect_overlap` is the concurrency arm's k, or None on the size arm (which
    runs one serve and asserts nothing about overlap beyond it happening).
    """
    point = ss.SweepPoint(n=n, valid=False)
    scratch = ctx.scratch / name
    attrs = [p.attr for p in payloads]
    try:
        seed_dir, seeds = e2e.build_p2p_seed_dir(fixtures, scratch, attrs)
        seeded_bytes = sum(s.nar_size for s in seeds)
        with e2e.Pod(
            ctx,
            name,
            fixtures.cache,
            with_daemon=False,
            expect=ss.silent_expect([]),
            p2p_seed_dir=seed_dir,
            p2p_seeds=seeds,
            p2p_holders=1,
            state_root=state_root / name,
        ) as pod:
            pod.proxy_reset()
            with ss.NodeSampler(pod, pod.roles()) as sampler:
                fetches = _drive_fetches(payloads)
            resources = ss.aggregate_samples(sampler.samples, pod.daemon_roles())
            served = pod.node_b_served_bytes(want_at_least=seeded_bytes)
            # The holder's monitor polls at 200 ms, so its last serve window and
            # residency reading can land just after the transfer returned.
            time.sleep(HOLDER_LOG_SETTLE_S)
            holder_log = pod.logs(HOLDER_ROLE)
            upstream_nar = pod.proxy_stats().get("nar", 0)

        windows = parse_serve_windows(holder_log)
        residency = parse_store_residency(holder_log)

        reasons: list[str] = list(sampler.errors)
        for fetch in fetches:
            if (
                fetch["read_bytes_uncompressed_nar"]
                != fetch["expected_bytes_uncompressed_nar"]
            ):
                reasons.append(
                    f"{fetch['attr']}: read {fetch['read_bytes_uncompressed_nar']} B "
                    f"but NarSize is {fetch['expected_bytes_uncompressed_nar']} B - a "
                    "partial body makes every figure derived from it a fiction"
                )
            if fetch["served_compression"] != "none":
                reasons.append(
                    f"{fetch['attr']}: the daemon served Compression="
                    f"{fetch['served_compression']!r}, so the bytes measured are "
                    "FileSize and the axis's n is NarSize - different units"
                )
        # THE peer-path precondition, same shape as the swarm axis's: without it a
        # point could be a fully-upstream fetch wearing a peer label. The proxy's
        # own NAR count is the independent witness - a fallback moved payload
        # across the cache boundary, a lagging holder monitor did not.
        if served < seeded_bytes:
            reasons.append(
                f"peer-serve precondition failed: holder served {served} B < "
                f"{seeded_bytes} B expected (uncompressed NAR); upstream served "
                f"{upstream_nar} NAR request(s) - "
                + (
                    "this fetch fell back to upstream"
                    if upstream_nar > 0
                    else "nothing crossed the cache boundary, so the holder's log "
                    "monitor lagged rather than the peer failing"
                )
            )
        if upstream_nar > 0:
            reasons.append(
                f"{upstream_nar} NAR request(s) crossed the cache boundary: this "
                "point is not purely peer-served"
            )
        reasons += residency_violations(residency, seeded_bytes)
        if expect_overlap is not None:
            reasons += concurrency_violations(windows, expect_overlap)
        elif not windows:
            reasons.append(
                "the holder recorded no completed serve window, so there is no "
                "holder-side evidence that a peer serve happened at all"
            )

        metrics = role_metrics(resources)
        metrics["holder_store_resident_bytes_uncompressed_nar"] = (
            residency["resident_bytes_uncompressed_nar"] if residency else None
        )
        rate = peer_serve_rate(windows)
        metrics["holder_send_bytes_uncompressed_nar_per_s"] = rate.get(
            "holder_send_bytes_uncompressed_nar_per_s"
        )
        # The HOST-side rate, kept beside it so the two denominators can be
        # compared mechanically (TASK-68). Same numerator, DIFFERENT clock and a
        # different interval, which is exactly what the independence gate tests.
        host_span_s = max(f["client_ended_s"] for f in fetches) - min(
            f["client_started_s"] for f in fetches
        )
        total_read = sum(f["read_bytes_uncompressed_nar"] for f in fetches)
        metrics["host_read_bytes_uncompressed_nar_per_s"] = (
            total_read / host_span_s if host_span_s > 0 else None
        )

        point = ss.SweepPoint(
            n=n,
            valid=not reasons,
            reason="; ".join(reasons),
            metrics=metrics,
            detail={
                "attrs": attrs,
                "seeded_bytes_uncompressed_nar": seeded_bytes,
                "peer_served_bytes_uncompressed_nar": served,
                "upstream_nar_requests": upstream_nar,
                "holder_store_residency": residency,
                "holder_serve_windows": windows,
                "measured_overlap_at_holder": measured_overlap(windows),
                "expected_overlap": expect_overlap,
                "peer_serve_rate": rate,
                "host_fetch_span_s": host_span_s,
                "fetches": fetches,
                "ram_per_nar_byte": ram_per_nar_byte(metrics, n),
            },
        )
    except (RuntimeError, ss.SampleError, OSError, ValueError) as error:
        point.reason = f"size-axis point raised: {error!r}"
        point.detail["traceback"] = traceback.format_exc()
    except SystemExit as error:
        # Same contract as `profile_p2p.sweep_swarm`: `e2e.die`'s exit code 2 is
        # fatal to a SCENARIO but must only invalidate a POINT here. Any other
        # code - notably the SIGTERM handler's 143 - is a real request to stop.
        if error.code != 2:
            raise
        point.reason = (
            f"size-axis point aborted by the Pod seam (e2e.die, exit {error.code}); "
            "see the harness output above"
        )
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return point


def sweep_size(
    ctx,
    fixtures: e2e.Fixtures,
    by_size: dict[int, GradedPayload],
    repeats: int,
    state_root: Path,
) -> ss.Axis:
    """The fitted SIZE axis: one holder + one fetcher, one NAR per point."""
    axis = ss.Axis(
        name="size",
        variable="held/served NAR size (uncompressed NAR bytes, NarSize units)",
        description=(
            "The axis that binds a deployment. One holder (node-b, seeding exactly "
            "this NAR into its iroh-blobs MemStore) and one fetcher (node-a, which "
            "buffers the whole NAR before its client sees a byte). Fitted: bytes of "
            "peak RSS per byte of NAR, with a confidence interval, separately for "
            "each end."
        ),
    )
    axis.notes.append(
        "n is UNCOMPRESSED NAR bytes and every payload is `Compression: none`, "
        "asserted by `unit_coincidence` - so the bytes the fetcher moves and the "
        "axis's n are the same unit by checked precondition"
    )
    axis.notes.append(
        "the consumer is a host-side streaming HTTP reader, not real nix: what is "
        "measured is the DAEMONS' memory, which a nix client would not change. "
        "Timings from this axis are transport-and-buffer numbers and are NOT "
        "comparable with the speedup arm's realise_s"
    )
    axis.notes.append(
        "the fetcher slope measures the whole-NAR buffer at "
        "transport_fetch.rs `fetch(..) -> Result<Vec<u8>>`. It is the BEFORE "
        "number TASK-62's streaming change is judged against"
    )
    for size in sorted(by_size):
        for rep in range(repeats):
            print(
                f"profile: size axis, NAR={size / 1024**2:.0f} MiB "
                f"(replicate {rep + 1}/{repeats})",
                file=sys.stderr,
            )
            axis.points.append(
                measure_point(
                    ctx,
                    fixtures,
                    [by_size[size]],
                    n=size,
                    name=f"prof-size-{size}-{rep}",
                    state_root=state_root,
                    expect_overlap=None,
                )
            )
    return axis


def sweep_concurrency(
    ctx,
    fixtures: e2e.Fixtures,
    concurrency_payloads: list[GradedPayload],
    ks,
    repeats: int,
    state_root: Path,
) -> ss.Axis:
    """The CONCURRENCY axis: k overlapping serves of the SAME size."""
    size = concurrency_payloads[0].nar_bytes_uncompressed_nar
    axis = ss.Axis(
        name="concurrency",
        variable="concurrent peer serves of one fixed NAR size",
        description=(
            f"k simultaneous serves of {size / 1024**2:.0f} MiB each, k DISTINCT "
            "blobs so nothing dedupes. The overlap is MEASURED at the holder from "
            "its own per-transfer windows and a point whose measured overlap is "
            "not k is INVALID (task-18)."
        ),
    )
    axis.notes.append(
        "overlap is measured at the HOLDER, not at the HTTP client: k client "
        "request windows overlap even when the daemon serialises the peer fetches "
        "internally, so a client-side precondition could not fail and would be "
        "vacuous"
    )
    for k in sorted(ks):
        if k > len(concurrency_payloads):
            raise ValueError(
                f"k={k} needs {k} distinct payloads of the same size but only "
                f"{len(concurrency_payloads)} were generated"
            )
        for rep in range(repeats):
            print(
                f"profile: concurrency axis, k={k} at "
                f"{size / 1024**2:.0f} MiB (replicate {rep + 1}/{repeats})",
                file=sys.stderr,
            )
            axis.points.append(
                measure_point(
                    ctx,
                    fixtures,
                    concurrency_payloads[:k],
                    n=k,
                    name=f"prof-conc-{k}-{rep}",
                    state_root=state_root,
                    expect_overlap=k,
                )
            )
    return axis


# ---- report -----------------------------------------------------------------


def axis_measured_block(axis: ss.Axis, extra: dict | None = None) -> dict:
    """The MEASURED half of one axis, in the shape `scale_sweep.build_report`
    uses, so a reader moves between the three instruments without relearning it."""
    block = {
        "variable": axis.variable,
        "description": axis.description,
        "notes": axis.notes,
        "distinct_n": sorted({p.n for p in axis.points}),
        "valid_observations_per_n": {
            str(n): sum(1 for p in axis.points if p.n == n and p.valid)
            for n in sorted({p.n for p in axis.points})
        },
        "points": [
            {
                "n": p.n,
                "valid": p.valid,
                "reason": p.reason,
                "metrics": p.metrics,
                "detail": p.detail,
            }
            for p in axis.points
        ],
        "invalid_points": [
            {"n": p.n, "reason": p.reason} for p in axis.points if not p.valid
        ],
    }
    if extra:
        block.update(extra)
    return block


def residency_summary(axis: ss.Axis) -> dict:
    """What the holder's STORE said it held, across the axis.

    Reported as a RATIO of resident bytes to seeded bytes, never as a difference
    against RSS: RSS is `_bytes_ram` and residency is NarSize, and a cross-unit
    SUM is the forbidden operation (a cross-unit ratio, named as one, is not).
    """
    rows = []
    for point in axis.points:
        if not point.valid:
            continue
        residency = point.detail.get("holder_store_residency")
        seeded = point.detail.get("seeded_bytes_uncompressed_nar")
        if not residency or not seeded:
            continue
        rows.append(
            {
                "n": point.n,
                "resident_bytes_uncompressed_nar": residency[
                    "resident_bytes_uncompressed_nar"
                ],
                "seeded_bytes_uncompressed_nar": seeded,
                "resident_over_seeded_ratio": (
                    residency["resident_bytes_uncompressed_nar"] / seeded
                ),
                "holder_peak_rss_ram_per_resident_nar_byte_ratio": (
                    point.metrics["holder_rss_hwm_bytes_ram"]
                    / residency["resident_bytes_uncompressed_nar"]
                    if residency["resident_bytes_uncompressed_nar"]
                    else None
                ),
            }
        )
    return {
        "oracle": (
            "IROH-STORE-RESIDENT: what the holder's blob store says it HOLDS, "
            "asked of the store itself (IrohProvider::store_residency). NOT peak "
            "RSS: VmHWM is monotone so it never observes a release, and glibc need "
            "not return a freed arena so VmRSS need not either. Discrimination "
            "proven by mutation in daemon/tests/store_residency_oracle.rs"
        ),
        "limit": (
            "answers 'does the STORE hold this content'. With MemStore that IS "
            "resident memory by construction; under a future on-disk store it is "
            "not, and the mapping must be re-derived (TASK-61)"
        ),
        "asserted": (
            "the reading must EXIST (absent is invalid, not zero) and the store may "
            "not hold MORE than was seeded. 'residency == seeded' is RECORDED, not "
            "asserted - it is today's retain-everything policy, and gating on it "
            "would fail a correct eviction change from TASK-61/TASK-62"
        ),
        "observations": rows,
        "holder_retains_everything_it_served": (
            all(abs(r["resident_over_seeded_ratio"] - 1.0) < 1e-9 for r in rows)
            if rows
            else None
        ),
    }


def independence_block(size_axis: ss.Axis) -> dict:
    """TASK-68's mechanical gate applied to the two rates this arm quotes."""
    peer, host = [], []
    for point in size_axis.points:
        if not point.valid:
            continue
        peer.append(point.metrics.get("holder_send_bytes_uncompressed_nar_per_s"))
        host.append(point.metrics.get("host_read_bytes_uncompressed_nar_per_s"))
    return derived_quantity_independence(
        "holder_send_bytes_uncompressed_nar_per_s",
        peer,
        "host_read_bytes_uncompressed_nar_per_s",
        host,
    )


def build_blocks(
    size_axis: ss.Axis, concurrency_axis: ss.Axis | None, targets
) -> tuple[dict, dict, list[str]]:
    """(measured, models, fit problems) for this module's two axes."""
    models: dict = {}
    problems: list[str] = []

    size_fits, size_problems = ss.fit_axis(size_axis, SIZE_METRICS, targets)
    models.update(size_fits)
    problems += size_problems

    independence = independence_block(size_axis)
    measured = {
        "size": axis_measured_block(
            size_axis,
            {
                "residency": residency_summary(size_axis),
                "derived_quantity_independence": independence,
                "high_water_vs_point_sample": ss_hwm_gap(size_axis),
            },
        )
    }
    if concurrency_axis is not None:
        # Fit ONLY when the grid can carry a fit. `scalefit` RAISES below
        # MIN_POINTS rather than guessing, and turning that refusal into a "fit
        # problem" would make a deliberately short dev grid (`--concurrency 1,2`)
        # look like a broken instrument. A short grid is still MEASURED - the
        # measured-overlap precondition, the residency reading and the per-k
        # figures are all there; what it does not get is a law.
        distinct = len({p.n for p in concurrency_axis.points if p.valid})
        concurrency_axis.fitted = distinct >= scalefit.MIN_POINTS
        if concurrency_axis.fitted:
            conc_fits, conc_problems = ss.fit_axis(
                concurrency_axis,
                CONCURRENCY_METRICS,
                scalefit.DEFAULT_EXTRAPOLATION_TARGETS,
            )
            models.update(conc_fits)
            problems += conc_problems
        else:
            concurrency_axis.notes.append(
                f"NOT FITTED: {distinct} distinct valid k, and scalefit needs "
                f">= {scalefit.MIN_POINTS}. The per-k measurements and the "
                "measured-overlap precondition stand; no law is claimed from them"
            )
        measured["concurrency"] = axis_measured_block(
            concurrency_axis,
            {
                "fitted": concurrency_axis.fitted,
                "residency": residency_summary(concurrency_axis),
                "measured_overlap_per_point": [
                    {
                        "k": p.n,
                        "measured_overlap_at_holder": p.detail.get(
                            "measured_overlap_at_holder"
                        ),
                        "valid": p.valid,
                    }
                    for p in concurrency_axis.points
                ],
            },
        )
    return measured, models, problems


def ss_hwm_gap(axis: ss.Axis) -> dict:
    """Was VmHWM ever separated from the largest VmRSS the sampler caught, on
    either end? Delegates the shape to nothing - it is three lines - but keeps the
    same wording as the swarm axis so the two are comparable."""
    gaps = []
    for point in axis.points:
        if not point.valid:
            continue
        for label in ("holder", "fetcher"):
            hwm = point.metrics.get(f"{label}_rss_hwm_bytes_ram")
            pnt = point.metrics.get(f"{label}_rss_point_max_bytes_ram")
            if hwm is not None and pnt is not None:
                gaps.append(int(hwm) - int(pnt))
    separated = [g for g in gaps if g > 0]
    return {
        "source": "size axis, both ends per point",
        "observations": len(gaps),
        "observations_where_hwm_exceeds_point_sample": len(separated),
        "max_gap_bytes_ram": max(gaps) if gaps else None,
        "exercised": bool(separated),
        "note": (
            "a gap of 0 everywhere means the 0.2 s sampler happened to catch every "
            "peak, so the distinction is UNEXERCISED by this data - not validated"
        ),
    }


def human_lines(measured: dict, models: dict) -> list[str]:
    """The printed summary for this arm. Deliberately quotes SLOPES WITH
    INTERVALS and never a bare per-byte number."""
    lines = ["", "SIZE AXIS (peak RSS vs held/served NAR bytes) - task-65"]
    size = measured.get("size", {})
    valid = sum(1 for p in size.get("points", []) if p["valid"])
    total = len(size.get("points", []))
    lines.append(
        f"  {valid}/{total} valid observations over "
        f"{len(size.get('distinct_n', []))} distinct NAR sizes "
        f"({', '.join(f'{n / 1024**2:.0f} MiB' for n in size.get('distinct_n', []))})"
    )
    lines.append("  fitted slopes (bytes of RSS per byte of uncompressed NAR):")
    for key in ("size.holder_rss_hwm_bytes_ram", "size.fetcher_rss_hwm_bytes_ram"):
        if key in models:
            lines.append(slope_line(models[key]))
    residency = size.get("residency", {})
    retains = residency.get("holder_retains_everything_it_served")
    lines.append(
        "  residency oracle (store-side, NOT peak RSS): holder retains everything "
        f"it served = {retains}"
    )
    independence = size.get("derived_quantity_independence", {})
    if independence.get("checked"):
        lines.append(f"  derived-quantity gate: {independence['verdict']}")
    concurrency = measured.get("concurrency")
    if concurrency:
        overlaps = concurrency.get("measured_overlap_per_point", [])
        good = sum(1 for o in overlaps if o["valid"])
        lines.append(
            f"  CONCURRENCY: {good}/{len(overlaps)} points whose overlap MEASURED "
            "at the holder equalled k "
            + ", ".join(
                f"k={o['k']}->{o['measured_overlap_at_holder']}" for o in overlaps
            )
        )
    return lines


# ---- self-test (pure; no containers) ----------------------------------------


def run_self_test() -> int:  # noqa: C901 - a flat list of checks reads better here
    """Every pure rule in this module, each proven to BITE by mutation."""
    ok = True

    def check(name: str, cond: bool, detail: str = "") -> None:
        nonlocal ok
        ok = ok and bool(cond)
        print(
            f"  {'PASS' if cond else 'FAIL'}  {name}"
            + (f"  [{detail}]" if not cond and detail else "")
        )

    print("sizeaxis --self-test")

    # --- 1. the NAR arithmetic: n IS the number the axis says ---------------
    for mib in (8, 16, 32, 64, 128):
        target = mib * 1024**2
        nar = synth_raw_nar(synth_contents(payload_bytes_for(target), seed=1))
        check(
            f"synthesised NAR is EXACTLY {mib} MiB", len(nar) == target, f"{len(nar)}"
        )
    check(
        "a non-multiple-of-8 NAR size is REFUSED, not rounded",
        _raises(lambda: payload_bytes_for(1001)),
    )
    check(
        "a NAR size below the framing overhead is REFUSED",
        _raises(lambda: payload_bytes_for(64)),
    )
    check(
        "synthesised contents are NOT constant (a page of zeros is shareable)",
        len(set(synth_contents(1 << 16, seed=7))) > 200,
    )
    nar = synth_raw_nar(synth_contents(payload_bytes_for(8192), seed=1))
    check(
        "the NAR really starts with the nix-archive-1 magic",
        nar[8:21] == b"nix-archive-1",
    )

    # --- 2. holder-log parsing, and the fail-closed reading -----------------
    log = (
        "IROH-PROVIDER-ADDR node_id=abc sockets=127.0.0.1:1\n"
        "IROH-SERVE-WINDOW start_ms=10.000 end_ms=110.000 bytes_uncompressed_nar=100\n"
        "IROH-STORE-RESIDENT blobs=2 bytes_uncompressed_nar=300\n"
        "IROH-SERVE-WINDOW start_ms=50.000 end_ms=150.000 bytes_uncompressed_nar=200\n"
        "IROH-STORE-RESIDENT blobs=2 bytes_uncompressed_nar=299\n"
    )
    windows = parse_serve_windows(log)
    check("both serve windows parsed", len(windows) == 2, str(windows))
    check(
        "the LAST residency reading wins",
        parse_store_residency(log)
        == {"blobs": 2, "resident_bytes_uncompressed_nar": 299},
    )
    check(
        "a log with no residency line reads as UNKNOWN, not 0",
        parse_store_residency("IROH-SERVED-TOTAL bytes=1 transfers=1") is None,
    )
    check(
        "a MALFORMED residency line is not silently coerced",
        parse_store_residency("IROH-STORE-RESIDENT blobs=x bytes_uncompressed_nar=y")
        is None,
    )
    check(
        "a malformed serve window is DROPPED, not fabricated",
        parse_serve_windows("IROH-SERVE-WINDOW start_ms=a end_ms=b") == [],
    )

    # --- 3. the residency oracle's two assertions, both proven to bite ------
    check(
        "an absent residency reading INVALIDATES the point",
        residency_violations(None, 100) != [],
    )
    check(
        "a store holding MORE than was seeded is REJECTED",
        residency_violations({"blobs": 1, "resident_bytes_uncompressed_nar": 101}, 100)
        != [],
    )
    check(
        "retain-everything is ACCEPTED (it is today's policy, not a defect)",
        residency_violations({"blobs": 1, "resident_bytes_uncompressed_nar": 100}, 100)
        == [],
    )
    check(
        "a RELEASED store is ACCEPTED, so a correct TASK-61/62 change does not "
        "fail the profile",
        residency_violations({"blobs": 0, "resident_bytes_uncompressed_nar": 0}, 100)
        == [],
    )

    # --- 4. the concurrency precondition, proven to bite --------------------
    overlapping = [
        {"start_ms": 0.0, "end_ms": 100.0, "served_bytes_uncompressed_nar": 1},
        {"start_ms": 50.0, "end_ms": 150.0, "served_bytes_uncompressed_nar": 1},
    ]
    serialised = [
        {"start_ms": 0.0, "end_ms": 100.0, "served_bytes_uncompressed_nar": 1},
        {"start_ms": 100.0, "end_ms": 200.0, "served_bytes_uncompressed_nar": 1},
    ]
    check(
        "two overlapping serves measure overlap 2", measured_overlap(overlapping) == 2
    )
    check(
        "two SERIALISED serves measure overlap 1 - the bite",
        measured_overlap(serialised) == 1,
    )
    check(
        "k=2 with two overlapping serves is VALID",
        concurrency_violations(overlapping, 2) == [],
    )
    check(
        "k=2 with two serves that TOOK TURNS is INVALID",
        any("MEASURED overlap" in p for p in concurrency_violations(serialised, 2)),
        str(concurrency_violations(serialised, 2)),
    )
    check(
        "k=2 with only one window is INVALID",
        concurrency_violations(overlapping[:1], 2) != [],
    )
    check("k=2 with NO windows is INVALID", concurrency_violations([], 2) != [])

    # --- 5. the peer-side rate: a real denominator, fail-closed -------------
    rate = peer_serve_rate(
        [
            {
                "start_ms": 0.0,
                "end_ms": 1000.0,
                "served_bytes_uncompressed_nar": 2_000_000,
            }
        ]
    )
    check(
        "holder send rate = bytes / holder-side serving seconds",
        rate["measured"]
        and abs(rate["holder_send_bytes_uncompressed_nar_per_s"] - 2_000_000) < 1e-6,
        str(rate),
    )
    check(
        "a zero-length serve window yields NO rate, not an infinite one",
        peer_serve_rate(
            [{"start_ms": 5.0, "end_ms": 5.0, "served_bytes_uncompressed_nar": 1}]
        )["measured"]
        is False,
    )
    check(
        "no serves yields NO rate",
        peer_serve_rate([])["measured"] is False,
    )
    overlap_rate = peer_serve_rate(overlapping)
    check(
        "k overlapping serves use the UNION of the windows, not the sum",
        abs(overlap_rate["holder_serving_span_s"] - 0.150) < 1e-9,
        str(overlap_rate),
    )

    # --- 6. the derived-quantity gate (TASK-68), proven both ways -----------
    a = [10.0, 20.0, 30.0, 40.0]
    check(
        "a series and a CONSTANT RESCALING of it is flagged as one quantity",
        derived_quantity_independence("a", a, "3a", [3 * x for x in a])[
            "algebraically_identical"
        ],
    )
    check(
        "two genuinely independent series are NOT flagged",
        not derived_quantity_independence("a", a, "b", [7.0, 9.0, 40.0, 11.0])[
            "algebraically_identical"
        ],
    )
    check(
        "fewer than two paired observations is 'not testable', not 'independent'",
        derived_quantity_independence("a", [1.0], "b", [2.0])["checked"] is False,
    )
    check(
        "a zero denominator does not crash the gate",
        derived_quantity_independence("a", a, "b", [0.0, 0.0, 0.0, 0.0])["checked"]
        is False,
    )

    # --- 7. the disk precondition ------------------------------------------
    plan = [("p", 128 * 1024**2)] * 5
    need = graded_disk_requirement_bytes_ondisk(plan)
    check("disk requirement grows with the grid", need > GRADED_DISK_SLACK_BYTES)
    check(
        "enough free disk -> no violation",
        disk_precondition_violations(need, plan) == [],
    )
    check(
        "one byte short -> a NAMED violation",
        disk_precondition_violations(need - 1, plan) != [],
    )

    # --- 8. the unit precondition, proven to bite ---------------------------
    good = {
        "paths": [
            {"attr": "a", "compression": "none", "file_size": 100, "nar_size": 100}
        ]
    }
    bad = {
        "paths": [{"attr": "a", "compression": "xz", "file_size": 40, "nar_size": 100}]
    }
    check(
        "all-uncompressed manifest passes",
        unit_coincidence([], good)["all_uncompressed"],
    )
    check(
        "a COMPRESSED payload is REFUSED (NarSize vs FileSize)",
        _raises(lambda: unit_coincidence([], bad)),
    )

    # --- 9. the slope formatter never prints a bare per-byte number ---------
    fitted = scalefit.fit_scaling(
        [8, 16, 32, 64, 128],
        [80.0, 96.0, 128.0, 192.0, 320.0],
        metric="synthetic holder RSS",
        unit="bytes (RSS)",
        targets=SIZE_EXTRAPOLATION_TARGETS_BYTES,
    )
    line = slope_line(fitted)
    check("a fitted slope prints WITH its interval", "95% CI" in line, line)
    stripped = dict(fitted)
    stripped["slope_ci95"] = None
    check(
        "a slope with NO interval prints a refusal, never the bare number",
        "NO SLOPE INTERVAL" in slope_line(stripped)
        and f"{fitted['slope']:.4f}" not in slope_line(stripped),
        slope_line(stripped),
    )

    # --- 10. role metrics are fail-closed on a missing end ------------------
    resources = {
        "daemon_roles_sampled": [HOLDER_ROLE, FETCHER_ROLE],
        "per_role": {
            HOLDER_ROLE: {
                "rss_hwm_bytes": 300,
                "rss_point_max_bytes": 280,
                "fd_max": 30,
                "ticks": 5,
            },
            FETCHER_ROLE: {
                "rss_hwm_bytes": 200,
                "rss_point_max_bytes": 190,
                "fd_max": 20,
                "ticks": 5,
            },
        },
    }
    metrics = role_metrics(resources)
    check(
        "holder and fetcher are reported SEPARATELY, not as a worst-node max",
        metrics["holder_rss_hwm_bytes_ram"] == 300
        and metrics["fetcher_rss_hwm_bytes_ram"] == 200,
    )
    one_end = {
        "daemon_roles_sampled": [HOLDER_ROLE],
        "per_role": {
            k: v for k, v in resources["per_role"].items() if k == HOLDER_ROLE
        },
    }
    check(
        "a point with one end missing RAISES rather than reporting half an axis",
        _raises(lambda: role_metrics(one_end)),
    )

    # --- 11. a short concurrency grid is UNFITTED, not "broken" -------------
    def _conc_axis(ks):
        axis = ss.Axis(
            name="concurrency", variable="k", description="synthetic", fitted=True
        )
        for k in ks:
            axis.points.append(
                ss.SweepPoint(
                    n=k,
                    valid=True,
                    metrics={
                        "holder_rss_hwm_bytes_ram": 20_000_000 + 33_000_000 * k,
                        "holder_rss_point_max_bytes_ram": 19_000_000 + 33_000_000 * k,
                        "fetcher_rss_hwm_bytes_ram": 20_000_000 + 33_000_000 * k,
                        "fetcher_rss_point_max_bytes_ram": 19_000_000 + 32_000_000 * k,
                        "holder_fd_max": 11,
                        "fetcher_fd_max": 12,
                        "holder_store_resident_bytes_uncompressed_nar": 33_000_000 * k,
                        "holder_send_bytes_uncompressed_nar_per_s": 4.0e8 * k,
                        "host_read_bytes_uncompressed_nar_per_s": 3.0e8 * k + k * k,
                    },
                    detail={
                        "holder_store_residency": {
                            "blobs": k,
                            "resident_bytes_uncompressed_nar": 33_000_000 * k,
                        },
                        "seeded_bytes_uncompressed_nar": 33_000_000 * k,
                        "measured_overlap_at_holder": k,
                    },
                )
            )
        return axis

    size_axis = _conc_axis([8 * 1024**2 * m for m in (1, 2, 4, 8, 16)])
    size_axis.name = "size"
    long_measured, long_models, long_problems = build_blocks(
        size_axis, _conc_axis([1, 2, 3, 4, 5]), SIZE_EXTRAPOLATION_TARGETS_BYTES
    )
    check(
        "a 5-point concurrency grid IS fitted",
        long_measured["concurrency"]["fitted"] is True
        and "concurrency.holder_rss_hwm_bytes_ram" in long_models,
    )
    check(
        "a fittable grid reports no fit problems",
        long_problems == [],
        str(long_problems),
    )
    short_measured, short_models, short_problems = build_blocks(
        size_axis, _conc_axis([1, 2]), SIZE_EXTRAPOLATION_TARGETS_BYTES
    )
    check(
        "a 2-point concurrency grid is UNFITTED, and that is not a fit problem",
        short_measured["concurrency"]["fitted"] is False
        and short_problems == []
        and not any(k.startswith("concurrency.") for k in short_models),
        f"problems={short_problems} models={sorted(short_models)}",
    )
    check(
        "the short grid still carries its measured overlap per point",
        [
            o["measured_overlap_at_holder"]
            for o in short_measured["concurrency"]["measured_overlap_per_point"]
        ]
        == [1, 2],
    )
    check(
        "the size axis still gets a slope interval through build_blocks",
        long_models["size.holder_rss_hwm_bytes_ram"]["slope_ci95"] is not None,
    )

    print(f"\nsizeaxis --self-test: {'ALL PASS' if ok else 'FAILURES PRESENT'}")
    return 0 if ok else 1


def _raises(thunk) -> bool:
    try:
        thunk()
    except (ValueError, ss.SampleError):
        return True
    return False


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return run_self_test()
    print(
        "sizeaxis is a library (imported by scripts/profile_p2p.py) plus "
        "`--self-test`. Run the axis with `just profile`.",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
