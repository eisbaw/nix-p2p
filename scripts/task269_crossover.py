#!/usr/bin/env python3
"""TASK-269 peer-serve vs CDN crossover map.

COMPUTES (does not re-measure) the crossover map from the raw sweep results
(evidence/task-269/sweep_results.json) + a measured CDN baseline. Run it and the
map re-derives; nothing here is hand-entered from a prior run.

THE MODEL (a transfer+compression model, NOT a shaped-link e2e):

  peer_wall_ns(pkg, codec, link) =
        regen_ns(raw_nar_bytes)         # measured serve model, docs/profiling.md
      + compress_cpu_ns                 # MEASURED per-serve codec CPU (the peer
                                        #   compresses ON THE FLY, every serve)
      + transfer_ns(compressed_bytes, link)
      + decompress_cpu_ns               # client turns wire bytes back into a NAR

  regen_ns(raw) = FLOOR_NS + raw_nar_bytes * 10 // 22
     FLOOR_NS = 22_000_000 ns  (~22 ms nix-store --dump fork/exec + DB floor)
     per-byte = 1e9 / 2.2e9 s/byte = 10/22 ns/byte  (measured ~2.2 GB/s streaming)

  cdn_wall_ns(pkg) = a REAL measured single-sample download (see CDN_BASELINE).

THE CRITICAL ASYMMETRY (modelled honestly): the peer regenerates the RAW NAR and
compresses it PER SERVE, so compress_cpu_ns is charged on every peer serve. The
CDN serves a PRE-COMPUTED compressed file, so it pays NO per-serve compress cost;
its compress work is amortized to zero in cdn_wall.

NO FLOATS in any decision field. Every quantity is an integer (ns or bytes). The
crossover decision is the integer comparison peer_wall_ns < cdn_wall_ns. The
compression ratio is an exact rational num/den (compressed/raw). The crossover
link speed is an integer ceil-division. Floats appear ONLY in *_display fields
and prints (terminal display).

CDN-side caveat, stated so the map is not read as broader than it is: cdn_wall is
DOWNLOAD ONLY; it excludes the client's decompress of the CDN file, while
peer_wall includes the client's decompress. This favours the CDN by one small
decompress term. It is negligible in the crossover region (WAN-ish peer links,
where transfer dominates and decompress is a low-single-digit-% term); at LAN
speeds where decompress is non-negligible the peer already wins by a wide margin
because the CDN baseline is a slow WAN link. See docs/profiling.md.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SWEEP_FILE = ROOT / "evidence" / "task-269" / "sweep_results.json"
MAP_FILE = ROOT / "evidence" / "task-269" / "crossover_map.json"

# --- serve model constants (integers) ---
REGEN_FLOOR_NS = 22_000_000  # 22 ms per-path floor
REGEN_PER_BYTE_NUM = 10  # 10/22 ns per byte == 1e9/2.2e9 s/byte
REGEN_PER_BYTE_DEN = 22

# --- link speeds: (id, bytes_per_s, human label). Decimal MB (10^6 bytes). ---
LINKS = [
    ("wan_2MBs", 2_000_000, "2 MB/s (~16 Mbit/s slow WAN)"),
    ("home_12_5MBs", 12_500_000, "12.5 MB/s (100 Mbit/s home)"),
    ("lan_125MBs", 125_000_000, "125 MB/s (1 Gbit/s LAN)"),
    ("fast_1000MBs", 1_000_000_000, "1000 MB/s (~10 GbE / datacenter)"),
]

# --- measured CDN baseline, per package. cdn_wall_ns is a REAL single-sample
#     download time; cdn_filesize_bytes is the CDN's precomputed compressed size
#     (narinfo FileSize). Provenance is carried explicitly. ---
CDN_BASELINE = {
    "hello": {
        "cdn_wall_ns": 50_000_000,
        "cdn_filesize_bytes": 57568,
        "cdn_compression": "xz",
        "source": "TASK-268 measured, single WAN sample (0.05 s, coarse)",
    },
    "curl": {
        "cdn_wall_ns": 260_000_000,
        "cdn_filesize_bytes": 554177,
        "cdn_compression": "zstd",
        "source": "TASK-268 measured, single WAN sample (0.26 s)",
    },
    "bash": {
        "cdn_wall_ns": 378_112_000,
        "cdn_filesize_bytes": 448312,
        "cdn_compression": "xz",
        "source": "TASK-269 measured this session, single WAN sample (0.378112 s)",
    },
    "glibc-locales": {
        "cdn_wall_ns": 235_198_000,
        "cdn_filesize_bytes": 234832,
        "cdn_compression": "xz",
        "source": "TASK-269 measured this session, single WAN sample (0.235198 s)",
    },
    "git": {
        "cdn_wall_ns": 2_140_000_000,
        "cdn_filesize_bytes": 8011464,
        "cdn_compression": "xz",
        "source": "TASK-268 measured, single WAN sample (2.14 s)",
    },
    "python3": {
        "cdn_wall_ns": 48_300_000_000,
        "cdn_filesize_bytes": 56616908,
        "cdn_compression": "zstd",
        "source": "TASK-268 measured, single WAN sample (48.3 s)",
    },
}


def regen_ns(raw_nar_bytes: int) -> int:
    return REGEN_FLOOR_NS + raw_nar_bytes * REGEN_PER_BYTE_NUM // REGEN_PER_BYTE_DEN


def transfer_ns(compressed_bytes: int, link_bps: int) -> int:
    return compressed_bytes * 1_000_000_000 // link_bps


def ceil_div(a: int, b: int) -> int:
    return (a + b - 1) // b


def crossover_link_bps(compressed_bytes: int, cdn_wall_ns: int, fixed_ns: int):
    """Slowest integer link (bytes/s) at which the peer still beats the CDN.

    peer_wall < cdn_wall  <=>  compressed/link < (cdn_wall - fixed)
    If fixed_ns >= cdn_wall_ns the peer can NEVER win (even an infinite link):
    regen+compress+decompress alone already meet or exceed the CDN wall.
    """
    headroom_ns = cdn_wall_ns - fixed_ns
    if headroom_ns <= 0:
        return None  # never wins
    return ceil_div(compressed_bytes * 1_000_000_000, headroom_ns)


def load_sweep() -> dict:
    if not SWEEP_FILE.is_file():
        print(f"FATAL: sweep results missing: {SWEEP_FILE}", file=sys.stderr)
        sys.exit(2)
    return json.loads(SWEEP_FILE.read_text())


def build_map(sweep: dict) -> dict:
    out = {
        "task": "TASK-269",
        "derived_from": str(SWEEP_FILE.relative_to(ROOT)),
        "model": {
            "regen_floor_ns": REGEN_FLOOR_NS,
            "regen_per_byte_num": REGEN_PER_BYTE_NUM,
            "regen_per_byte_den": REGEN_PER_BYTE_DEN,
            "links": [{"id": i, "bytes_per_s": b, "label": lbl} for i, b, lbl in LINKS],
        },
        "cdn_baseline": CDN_BASELINE,
        "packages": [],
    }
    for pkg in sweep["packages"]:
        name = pkg["name"]
        raw = pkg["raw_nar_bytes"]
        base = CDN_BASELINE.get(name)
        if base is None:
            print(f"FATAL: no CDN baseline for {name}", file=sys.stderr)
            sys.exit(2)
        cdn_wall = base["cdn_wall_ns"]
        rg = regen_ns(raw)
        pkg_out = {
            "name": name,
            "raw_nar_bytes": raw,
            "regen_ns": rg,
            "cdn_wall_ns": cdn_wall,
            "cdn_filesize_bytes": base["cdn_filesize_bytes"],
            "cells": {},
        }
        for codec, cell in pkg["cells"].items():
            if cell.get("status") != "ok":
                pkg_out["cells"][codec] = {
                    "status": cell.get("status"),
                    "reason": cell.get("reason"),
                }
                continue
            cb = cell["compressed_bytes"]
            comp = cell["compress_cpu_ns"]
            dec = cell["decompress_cpu_ns"]
            fixed = rg + comp + dec
            per_link = {}
            for lid, lbps, _label in LINKS:
                pw = fixed + transfer_ns(cb, lbps)
                per_link[lid] = {
                    "peer_wall_ns": pw,
                    "peer_beats_cdn": pw < cdn_wall,  # integer decision
                }
            xbps = crossover_link_bps(cb, cdn_wall, fixed)
            pkg_out["cells"][codec] = {
                "status": "ok",
                "compressed_bytes": cb,
                "ratio_num": cb,  # exact rational compressed/raw
                "ratio_den": raw,
                "compress_cpu_ns": comp,
                "decompress_cpu_ns": dec,
                "fixed_ns": fixed,
                "per_link": per_link,
                "crossover_link_bps": xbps,  # None == never beats CDN
            }
        out["packages"].append(pkg_out)
    return out


def fmt_mbs(bps) -> str:
    if bps is None:
        return "never"
    return f"{bps / 1_000_000:.2f} MB/s"  # terminal display only


def fmt_ms(ns: int) -> str:
    return f"{ns / 1_000_000:.1f} ms"  # terminal display only


def fmt_ratio(num: int, den: int) -> str:
    if num == 0:
        return "-"
    return f"{den / num:.2f}x"  # terminal display only


def print_report(m: dict) -> None:
    print("=" * 78)
    print("TASK-269 CROSSOVER MAP  (peer-serve vs cache.nixos.org)")
    print("model: peer_wall = regen + compress_cpu + compressed/link + decompress_cpu")
    print("       (peer compresses ON THE FLY per serve; CDN serves precomputed)")
    print("=" * 78)
    links = m["model"]["links"]

    for pkg in m["packages"]:
        print(
            f"\n### {pkg['name']}  raw NAR={pkg['raw_nar_bytes']} B  "
            f"regen={fmt_ms(pkg['regen_ns'])}  "
            f"CDN={fmt_ms(pkg['cdn_wall_ns'])} / {pkg['cdn_filesize_bytes']} B"
        )
        header = f"{'codec':<11}{'ratio':>7}{'comp_cpu':>11}{'decomp':>10}"
        for lk in links:
            header += f"{lk['id'].split('_')[0]:>9}"
        header += f"{'xover':>11}"
        print(header)
        for codec, cell in pkg["cells"].items():
            if cell.get("status") != "ok":
                print(f"{codec:<11}  [{cell.get('status')}] {cell.get('reason', '')}")
                continue
            row = (
                f"{codec:<11}{fmt_ratio(cell['ratio_num'], cell['ratio_den']):>7}"
                f"{fmt_ms(cell['compress_cpu_ns']):>11}"
                f"{fmt_ms(cell['decompress_cpu_ns']):>10}"
            )
            for lk in links:
                pl = cell["per_link"][lk["id"]]
                row += f"{('WIN' if pl['peer_beats_cdn'] else '.'):>9}"
            row += f"{fmt_mbs(cell['crossover_link_bps']):>11}"
            print(row)

    # Per-link winning codecs and the min-wall (sweet-spot) codec.
    print("\n" + "=" * 78)
    print("SWEET SPOT: codec giving MIN peer_wall per (package, link), and whether")
    print(
        "that best codec beats the CDN. (min wall accounts for per-serve compress CPU)"
    )
    print("=" * 78)
    for pkg in m["packages"]:
        print(f"\n{pkg['name']}:")
        for lk in links:
            best_codec, best_wall, best_win = None, None, None
            for codec, cell in pkg["cells"].items():
                if cell.get("status") != "ok":
                    continue
                pl = cell["per_link"][lk["id"]]
                if best_wall is None or pl["peer_wall_ns"] < best_wall:
                    best_wall = pl["peer_wall_ns"]
                    best_codec = codec
                    best_win = pl["peer_beats_cdn"]
            verdict = "PEER WINS" if best_win else "CDN wins"
            print(
                f"  {lk['label']:<34} best={best_codec:<10} "
                f"wall={fmt_ms(best_wall):>9}  -> {verdict}"
            )


def main() -> int:
    sweep = load_sweep()
    m = build_map(sweep)
    MAP_FILE.write_text(json.dumps(m, indent=2) + "\n")
    print_report(m)
    print(f"\nwrote {MAP_FILE}")
    print(f"re-derived from {SWEEP_FILE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
