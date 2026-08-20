#!/usr/bin/env python3
"""TASK-269 compression sweep driver.

Measures, for each real package NAR x each codec/level, the EXACT compressed
byte count, the compress CPU time, and the decompress CPU time. These are the
raw inputs the crossover model (task269_crossover.py) is COMPUTED from; nothing
downstream re-measures, it only re-derives from the JSON this writes.

WHAT IS MEASURED (real), WHAT IS MODELLED (elsewhere):
  * measured here: raw NAR bytes (== `nix-store --dump | wc -c`), compressed
    bytes per codec, compress/decompress CPU time per codec.
  * modelled in task269_crossover.py: peer wall-time at several link speeds, from
    these measurements + the docs/profiling.md regen model. NOT measured here.

UNITS (kept separate and suffixed, never conflated):
  * raw_nar_bytes  -- UNCOMPRESSED NAR size (the bytes the peer regenerates+serves
    on the primary libp2p path; the peer serves the RAW NAR).
  * compressed_bytes -- the codec's compressed-wire size (a DIFFERENT unit; this
    is what a hypothetical negotiated-link-compression would put on the wire).
  These are different units and are never compared or summed.

CPU TIME, not wall: compress/decompress cost is taken from getrusage(CHILDREN)
user+sys delta around each child, so it isolates codec CPU from pipe/IO wait and
from process spawn. Codecs are forced single-thread (zstd -T1, xz -T1) so the
per-core CPU we charge the peer per serve equals the codec's own work. Stored as
integer nanoseconds.

NO FLOATS in any serialized-integrity field: *_bytes and *_ns are ints; the
compression ratio is carried as an exact rational (num=compressed_bytes,
den=raw_nar_bytes). getrusage returns float seconds -> converted to int ns by
`int(round(...))` before storage; the stored value is an int, never a float.

BOUNDED SWEEP (shared box, ~21G disk, prior stress loops exhausted tmpfs):
  * NARs are streamed to memory once per package (peak ~raw+compressed in RAM),
    never written to disk; no compressed temp files touch the tight filesystem.
  * FULL codec grid on the small/mid packages (<= ~3 MB).
  * REDUCED grid on the large packages (git 50 MB, python3 133 MB): the high-CPU
    middle levels (zstd-9, xz-6) and the slow brotli levels are SKIPPED and
    recorded as {"status":"skipped"} cells -- never silently dropped.
  * disk is checked before and after; a floor aborts the run.
"""

from __future__ import annotations

import json
import os
import resource
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "evidence" / "task-269"
OUT_FILE = OUT_DIR / "sweep_results.json"

DISK_FLOOR_BYTES = 10 * 1000 * 1000 * 1000  # stop below ~10 GB free

# Real realized store paths (raw NAR is `nix-store --dump <path>`).
# raw NAR size is MEASURED at runtime (dump byte count) and cross-checked against
# this declared NarSize from the narinfo; a mismatch aborts (fail fast).
PACKAGES = [
    (
        "hello",
        "/nix/store/2bcv91i8fahqghn8dmyr791iaycbsjdd-hello-2.12.2",
        274568,
        "small",
    ),
    (
        "curl",
        "/nix/store/0y90rp9g4i4rahyw18k0zcyfs8gl1v37-curl-8.21.0",
        1181408,
        "small",
    ),
    (
        "bash",
        "/nix/store/00zrahbb32nzawrmv9sjxn36h7qk9vrs-bash-5.2p37",
        1654112,
        "small",
    ),
    (
        "glibc-locales",
        "/nix/store/0blk7gr1f1qcf1h59igmgxr9qkz520pn-glibc-locales-2.42-51",
        3070464,
        "small",
    ),
    (
        "git",
        "/nix/store/2z9pz49718aq8cnxbxc3x4ahmwrxaqx7-git-2.42.2",
        50548816,
        "large",
    ),
    (
        "python3",
        "/nix/store/05xfwnl62nipbw1ankbcv2crjhb9a918-python3-3.13.14",
        133215664,
        "large",
    ),
]

# codec id -> (compress argv reading stdin/writing stdout, decompress argv, tiers)
# tiers: which package classes run this codec. "small" runs everywhere; "all"
# runs everywhere; codecs marked only {"small"} are SKIPPED on large packages
# (the bounded-sweep cap) and recorded as skipped cells.
CODECS = [
    ("none", None, None, {"small", "large"}),
    ("lz4", ["lz4", "-c", "-1"], ["lz4", "-d", "-c"], {"small", "large"}),
    ("zstd-1", ["zstd", "-1", "-T1", "-c"], ["zstd", "-d", "-c"], {"small", "large"}),
    ("zstd-3", ["zstd", "-3", "-T1", "-c"], ["zstd", "-d", "-c"], {"small", "large"}),
    ("zstd-9", ["zstd", "-9", "-T1", "-c"], ["zstd", "-d", "-c"], {"small"}),
    ("zstd-19", ["zstd", "-19", "-T1", "-c"], ["zstd", "-d", "-c"], {"small", "large"}),
    ("xz-6", ["xz", "-6", "-T1", "-c"], ["xz", "-d", "-c"], {"small"}),
    ("xz-9", ["xz", "-9", "-T1", "-c"], ["xz", "-d", "-c"], {"small", "large"}),
    ("brotli-5", ["brotli", "-q", "5", "-c"], ["brotli", "-d", "-c"], {"small"}),
    ("brotli-11", ["brotli", "-q", "11", "-c"], ["brotli", "-d", "-c"], {"small"}),
]

RUNS_SMALL = 3  # take min CPU over repeats for the small/mid set
RUNS_LARGE = 1  # one pass on the big NARs (bounded)


def free_bytes() -> int:
    st = os.statvfs(ROOT)
    return st.f_bavail * st.f_frsize


def children_cpu_seconds() -> float:
    """Accumulated user+sys CPU of reaped children (float seconds)."""
    ru = resource.getrusage(resource.RUSAGE_CHILDREN)
    return ru.ru_utime + ru.ru_stime


def run_codec(argv: list[str], data: bytes) -> tuple[bytes, int]:
    """Run one codec child over `data`; return (output_bytes, cpu_ns).

    cpu_ns is this child's user+sys CPU, isolated via a getrusage(CHILDREN)
    delta. int(round(seconds * 1e9)) -> the stored value is an int, not a float.
    """
    before = children_cpu_seconds()
    proc = subprocess.run(argv, input=data, stdout=subprocess.PIPE, check=True)
    after = children_cpu_seconds()
    cpu_ns = int(round((after - before) * 1_000_000_000))
    if cpu_ns < 0:
        cpu_ns = 0
    return proc.stdout, cpu_ns


def measure_cell(codec, comp_argv, decomp_argv, nar: bytes, runs: int) -> dict:
    """Measure one (package, codec) cell: compressed bytes + min compress/decompress CPU."""
    if codec == "none":
        # identity: the peer would serve raw bytes; no per-serve codec CPU.
        return {
            "status": "ok",
            "compressed_bytes": len(nar),
            "compress_cpu_ns": 0,
            "decompress_cpu_ns": 0,
        }
    best_compress_ns = None
    best_decompress_ns = None
    compressed_bytes = None
    comp_blob = None
    for _ in range(runs):
        out, c_ns = run_codec(comp_argv, nar)
        if compressed_bytes is None:
            compressed_bytes = len(out)
            comp_blob = out
        elif len(out) != compressed_bytes:
            raise SystemExit(
                f"non-deterministic compressed size for {codec}: "
                f"{len(out)} != {compressed_bytes}"
            )
        best_compress_ns = (
            c_ns if best_compress_ns is None else min(best_compress_ns, c_ns)
        )
    for _ in range(runs):
        back, d_ns = run_codec(decomp_argv, comp_blob)
        if len(back) != len(nar):
            raise SystemExit(
                f"roundtrip size mismatch for {codec}: {len(back)} != {len(nar)}"
            )
        best_decompress_ns = (
            d_ns if best_decompress_ns is None else min(best_decompress_ns, d_ns)
        )
    return {
        "status": "ok",
        "compressed_bytes": compressed_bytes,
        "compress_cpu_ns": best_compress_ns,
        "decompress_cpu_ns": best_decompress_ns,
    }


def dump_nar(store_path: str) -> bytes:
    """`nix-store --dump` to memory. The byte count IS the raw NAR size."""
    proc = subprocess.run(
        ["nix-store", "--dump", store_path],
        stdout=subprocess.PIPE,
        check=True,
    )
    return proc.stdout


def main() -> int:
    for tool in ("nix-store", "zstd", "xz", "lz4", "brotli"):
        if shutil.which(tool) is None:
            print(f"FATAL: required tool not on PATH: {tool}", file=sys.stderr)
            return 2
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    disk_start = free_bytes()
    print(f"disk free at start: {disk_start / 1e9:.1f} GB", file=sys.stderr)

    results = {
        "task": "TASK-269",
        "generated_unix": int(time.time()),
        "model_note": "raw_nar_bytes and compressed_bytes are DIFFERENT units; "
        "never conflated. CPU times are single-thread getrusage "
        "user+sys, integer ns.",
        "packages": [],
    }

    for name, path, declared_narsize, tier in PACKAGES:
        if free_bytes() < DISK_FLOOR_BYTES:
            print(f"FATAL: disk below floor before {name}; aborting", file=sys.stderr)
            return 2
        print(f"[{name}] dumping NAR ...", file=sys.stderr)
        t0 = time.time()
        nar = dump_nar(path)
        raw_bytes = len(nar)
        if raw_bytes != declared_narsize:
            print(
                f"FATAL: {name} raw NAR {raw_bytes} != declared NarSize {declared_narsize}",
                file=sys.stderr,
            )
            return 2
        runs = RUNS_SMALL if tier == "small" else RUNS_LARGE
        pkg = {
            "name": name,
            "store_path": path,
            "raw_nar_bytes": raw_bytes,
            "tier": tier,
            "runs_per_cell": runs,
            "cells": {},
        }
        for codec, comp_argv, decomp_argv, tiers in CODECS:
            if tier not in tiers:
                pkg["cells"][codec] = {
                    "status": "skipped",
                    "reason": f"bounded-sweep cap: {codec} not run on {tier} packages",
                }
                print(f"  [{name}/{codec}] SKIPPED (cap)", file=sys.stderr)
                continue
            print(f"  [{name}/{codec}] measuring ...", file=sys.stderr)
            cell = measure_cell(codec, comp_argv, decomp_argv, nar, runs)
            pkg["cells"][codec] = cell
            cb = cell["compressed_bytes"]
            print(
                f"    -> compressed={cb} bytes  compress_cpu={cell['compress_cpu_ns']}ns "
                f"decompress_cpu={cell['decompress_cpu_ns']}ns",
                file=sys.stderr,
            )
        results["packages"].append(pkg)
        del nar  # free the big buffer before the next package
        print(
            f"[{name}] done in {time.time() - t0:.1f}s; "
            f"disk free {free_bytes() / 1e9:.1f} GB",
            file=sys.stderr,
        )

    disk_end = free_bytes()
    results["disk_free_start_bytes"] = disk_start
    results["disk_free_end_bytes"] = disk_end
    OUT_FILE.write_text(json.dumps(results, indent=2) + "\n")
    print(f"wrote {OUT_FILE}", file=sys.stderr)
    print(f"disk free at end: {disk_end / 1e9:.1f} GB", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
