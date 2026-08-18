#!/usr/bin/env python3
"""TASK-197 AC9: live `/nar/4` two-ends-shaped raw-vs-zstd measurement.

WHAT THIS IS. TASK-203 (`scripts/task203_pipelined_measure.py`) produced an IDEALIZED, integer-
exact MODEL of whether link zstd beats raw over a link; it is explicitly NOT a measured wall-clock
result, and it names this task as the live counterpart it defers to ("a live two-ends-shaped serve
trace (TASK-198) is out of scope; the flip is a conditional estimate, not a measured wall-clock
result"). TASK-197 evolves that TASK-198 harness to the authenticated v4 wire: it runs the REAL
libp2p streamed `/nar/4` fetch between two swarm nodes whose traffic traverses a `tc netem`-shaped
`veth` pair with BOTH ends shaped, transfers paired RAW and ZSTD arms in alternating order over
that same link, and reports the MEASURED wall-clock of each arm.

WHAT IS AND IS NOT IN THE TIMED WINDOW (the TASK-198 F3 honesty correction). The two nodes discover
nothing over the DHT here and the dial + Noise/yamux handshake are driven to COMPLETION before the
clock starts: the probe injects the provider multiaddr+PeerId, dials, then POLLS `is_connected`
until the swarm reports the peer fully ESTABLISHED (ConnectionEstablished fired — handshake done),
and only THEN starts timing. So this measures an ALREADY-CONNECTED open-stream `/nar/4` fetch — not a
discover->fetch->serve round. What both arms pay ONCE inside the timed window, independent of
payload size, is the request round-trip: open the `/nar/4` substream, write the request header, and
wait for the first response byte (~one RTT of first-byte latency), plus the stream's flow-control
ramp (TCP + yamux windows opening from their initial size). That per-fetch fixed cost does NOT
shrink with compression, which is exactly why the measured wall-clock speedup sits a little BELOW
the wire-byte ratio — stated explicitly, not attributed to a dial/handshake that the clock excludes.

WHY BOTH ENDS SHAPED (the TASK-70 AC#3 correction). Every earlier peer-vs-upstream number shaped
only the UPSTREAM (CDN) arm while the peer transport ran over pod loopback, so every peer-advantage
figure was an UPPER BOUND — the peer looked unrealistically fast. TASK-70's own wire-cost
correction forbade re-deriving the speedup until link compression (TASK-99) landed, because the
peer byte-volume depends on whether the link is compressed. Both have landed; this shapes the PEER
link too, removing that loopback upper bound. It is still a shaped EMULATION (netns + tc netem),
NOT real hardware / a real WAN — an honest emulation, not a field trial (see HONEST_LIMITS; the
real-hardware residual is TASK-207's two-VM NAT harness).

THE DELIVERABLE — an HONEST measured number, integer/rational only (owner no-floats rule +
`scripts/check-no-floats.py`):
  * raw-arm wall-clock (integer ns) and zstd-arm wall-clock (integer ns) over the SAME shaped link;
  * the EXACT successful `/nar/4` response-protocol bytes each arm shipped (integer bytes, from
    the fetcher's CountingReader), decomposed into header, Bao proof, per-leaf prefixes, encoded
    leaves, and COMPLETE. The provider independently reports the same components after clean FIN;
    any mismatch rejects the run. The HEADLINE ratio uses like-unit exact response totals (raw v4 /
    zstd v4), never NarSize-vs-compressed. A separately generated whole-NAR zstd frame is retained
    only as an explicit prior-`/nar/3` BYTE COUNTERFACTUAL, not a cross-check expected to match v4's
    independently framed leaves and not a source of latency or throughput claims;
  * throughput (integer bytes/sec) and the raw/zstd wall-clock speedup as an EXACT RATIONAL
    (`fractions.Fraction`, compared by cross-multiplication).

WHY THE OBSERVED SIGN PASSES THE PREDECLARED GATE (unlike TASK-203's noise-straddling CPU delta).
The raw-vs-zstd delta here is NOT a scheduler-dominated CPU micro-delta. On a BANDWIDTH-BOUND link
the transfer time is set by the WIRE-BYTE volume, and the zstd arm measurably puts ~R x fewer bytes
on the wire. The load-bearing noise gate is the exact integer predicate `min_margin_ns >= 3 *
(raw_spread_ns + zstd_spread_ns)`; equality passes. Three alternating-order runs cannot GUARANTEE
no future re-sample ever flips the sign; the claim is only that this observed sample passes that
stated threshold.

FAIL CLOSED (the TASK-198 F2 correction). This is an EVIDENCE GENERATOR: it must never publish its
conclusion when its own guard trips. Every load-bearing check — zstd faster in every shaped run,
the predeclared 3x combined-spread threshold, EVERY headline run shape-gated against the negative control, the
exact v4 response bytes consistent across runs, paired arm order alternating, and the legacy
counterfactual consistently labeled —
is required. If ANY fails, the report prints `VERDICT: REJECTED` (NOT the win/noise-gate/parity
conclusions), the affirmative evidence is NOT written, and the process exits NON-ZERO. `--self-test`
asserts on the RENDERED report text AND the exit status (not merely internal booleans): a mutation
(slower zstd, spread-swamped margin, shaping removed, a run not shape-gated, or byte drift)
must make the rendered report omit the win/parity conclusion AND exit non-zero.

THE SHAPING ORACLE (reused verbatim, TASK-70/206). A number without a biting shaping-oracle is not
evidence. `shaped_link.assert_shaping` refuses a run unless, on its RAW arm: the injected RTT is
recovered on the shaped arm, the UNSHAPED negative control's RTT is near zero, the shaped throughput
sits near the cap, and the unshaped control is MEASURABLY faster (>=2x). EVERY shaped run that
contributes to the headline is gated (not just the first), so an unshaped run cannot slip into the
minimum. `--self-test` proves the parse AND the verdict/oracle bite by mutation, with no netns.

PEER-VS-UPSTREAM re-statement (honest scope). The CDN serves the artifact xz-compressed (~3.6x
smaller than the raw NarSize, per the project's TASK-99 corpus). The peer's disadvantage was
serving RAW — ~3.6x the CDN's bytes. Link zstd shrinks the peer's WIRE VOLUME by the MEASURED ratio
R, closing that ~3.6x raw BYTE gap toward parity. A smaller wire volume does mean a shorter transfer
on a bandwidth-bound link, but the WALL-CLOCK does NOT shrink by R — it shrinks by a SMALLER factor
(the per-fetch request round-trip both arms pay once). Never equate the two: the wire VOLUME shrinks
~R; the measured WALL-CLOCK shrinks less. The near-parity is a STRUCTURAL result on WIRE VOLUME (the
peer reaches near-parity with the CDN exactly where R approaches the xz ratio).
This script MEASURES the peer arms and R over a real shaped link (removing the loopback upper
bound); the CDN xz ratio is a STATED corpus reference, not re-measured here, and the payload is
SYNTHETIC (a stated construction), so we report R and the structural parity condition, NOT a claim
about a specific nixpkgs closure. The LAN regime (where the compressor CPU, not the link, can
dominate) is TASK-203's modeled territory and out of scope for this bandwidth-bound run.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
from fractions import Fraction

import shaped_link  # sibling module: the proven shaping oracle + honest-limits text

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
INNER = os.path.join(HERE, "shaped_compress_inner.sh")
# Honour the shared CARGO_TARGET_DIR (TASK-54) so the probe is found whether cargo built into the
# in-tree ./target or the shared cache; fall back to the in-tree path.
_TARGET_DIR = os.environ.get("CARGO_TARGET_DIR") or os.path.join(ROOT, "target")
DEFAULT_BIN = os.path.join(_TARGET_DIR, "debug", "examples", "shaped_probe")
TASK197_EVIDENCE_ROOT = os.path.join(ROOT, "evidence", "task-197")

# 16 MiB compressible nar over a 20 mbit (~2.5 MB/s) home-uplink cap is ~6.7 s raw / ~1.7 s zstd —
# long enough that the per-fetch fixed cost (the request round-trip + one RTT of ramp; NOT dial or
# handshake, which are out of the timed window) is a small fraction of the transfer (so the
# wall-clock reflects the shaped rate, not startup), small enough to be gentle on a shared box
# (the provider writes one replayable temporary NAR file, removed with the namespace harness).
DEFAULT_NAR_BYTES = 16 * 1024 * 1024
DEFAULT_DELAY_MS = 20  # -> ~40 ms RTT, a modest home-broadband round trip
DEFAULT_RATE_MBIT = 20  # ~2.5 MB/s, a mid home uplink
DEFAULT_NAR_SEED = 20198
PAYLOAD_KIND = "compressible"
PAYLOAD_CONSTRUCTION = "splitmix64-1of4-entropy-plus-3of4-seeded-motif-v1"
FETCHER_IDENTITY_SEED = 2
NOISE_MARGIN_MULTIPLIER_NUMERATOR = 3
NOISE_MARGIN_MULTIPLIER_DENOMINATOR = 1
SYNTHETIC_CONTENT = "blake3:" + ("ab" * 32)
_CONTENT_DIGEST_RE = re.compile(r"blake3:[0-9a-f]{64}")
DEFAULT_RUNS = (
    3  # a FEW bounded shaped runs for a noise estimate — never a CPU-hog farm
)

NS_PER_SEC = 1_000_000_000


class MeasureFailure(Exception):
    """The measurement could not be established; the run is not evidence (fail closed)."""


def _file_sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as probe:
        for chunk in iter(lambda: probe.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _text_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _process_capture(stdout: str, stderr: str, return_code: int) -> dict:
    """Retain both subprocess streams and hash a canonical JSON encoding of the capture."""
    capture = {
        "stdout": stdout,
        "stderr": stderr,
        "return_code": return_code,
    }
    canonical = json.dumps(
        capture, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    return {
        **capture,
        "sha256": _text_sha256(canonical),
        "sha256_recipe": "sha256(utf8(canonical-json(stdout,stderr,return_code)))",
    }


def _measurement_provenance(probe_bin: str) -> dict:
    """Bind live output to the executable that produced it and to repository context.

    A dirty worktree is reported so an exploratory run remains diagnosable, but durable evidence
    publication rejects it: an implementation commit plus the executable digest form the identity.
    The caller re-hashes the probe and both harness files after all arms and re-checks Git state,
    rejecting any identity that changed during the run.
    """
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    status = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=normal"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return {
        "harness_origin": "TASK-197 /nar/4 shaped-link evidence harness (evolved from TASK-198)",
        "wire_revision": "TASK-197 Bao-authenticated /nar/4 with independently framed 64-KiB leaves",
        "probe_binary": os.path.realpath(probe_bin),
        "probe_sha256": _file_sha256(probe_bin),
        "harness_sha256": _file_sha256(__file__),
        "inner_harness_sha256": _file_sha256(INNER),
        "git_head": head.stdout.strip() if head.returncode == 0 else "unavailable",
        "git_worktree_dirty": status.returncode != 0 or bool(status.stdout),
    }


def _write_new_evidence(
    out_path: str,
    report: dict,
    *,
    evidence_root: str = TASK197_EVIDENCE_ROOT,
) -> None:
    """Publish one accepted, clean-commit-bound TASK-197 artifact with no-clobber creation.

    Destination creation is an atomic no-clobber hard link: the path must live below
    ``evidence/task-197/<git-sha-prefix>/`` and must not already exist. A same-directory temporary
    file is fully flushed before publication, and successful return means the directory was synced.
    A late cleanup/sync failure can leave the complete destination present; a retry still refuses to
    replace it. Git supplies durable history and integrity after the artifact is added.
    """
    if report.get("task") != "task-197" or report.get("accepted") is not True:
        raise MeasureFailure("refusing to publish non-accepted TASK-197 evidence")
    provenance = report.get("provenance")
    if not isinstance(provenance, dict):
        raise MeasureFailure("refusing to publish evidence without provenance")
    git_head = provenance.get("git_head")
    if not isinstance(git_head, str) or not re.fullmatch(r"[0-9a-f]{40,64}", git_head):
        raise MeasureFailure("refusing to publish evidence without an exact Git commit")
    if provenance.get("git_worktree_dirty") is not False:
        raise MeasureFailure("refusing to publish evidence from a dirty worktree")
    if provenance.get("verified_unchanged_after_run") is not True:
        raise MeasureFailure(
            "refusing to publish evidence not re-verified after all arms"
        )
    for identity in ("probe_sha256", "harness_sha256", "inner_harness_sha256"):
        digest = provenance.get(identity)
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise MeasureFailure(
                f"refusing to publish evidence without exact {identity}"
            )

    destination = os.path.abspath(out_path)
    root = os.path.abspath(evidence_root)
    try:
        relative = os.path.relpath(destination, root)
    except ValueError as exc:
        raise MeasureFailure(f"evidence destination cannot be resolved: {exc}") from exc
    path_parts = relative.split(os.sep)
    revision = path_parts[0] if len(path_parts) >= 2 else ""
    if (
        relative == os.pardir
        or relative.startswith(os.pardir + os.sep)
        or len(revision) < 7
        or not git_head.startswith(revision)
    ):
        raise MeasureFailure(
            "evidence destination must be below "
            f"{root}/<git-sha-prefix>/ and match git_head={git_head}"
        )

    directory = os.path.dirname(destination)
    os.makedirs(directory, exist_ok=True)
    resolved_root = os.path.realpath(root)
    resolved_directory = os.path.realpath(directory)
    try:
        inside_root = (
            os.path.commonpath([resolved_root, resolved_directory]) == resolved_root
        )
    except ValueError:
        inside_root = False
    if not inside_root:
        raise MeasureFailure(
            f"evidence destination resolves outside evidence root {resolved_root}"
        )
    destination = os.path.join(resolved_directory, os.path.basename(destination))
    payload = json.dumps(report, indent=2) + "\n"
    temporary_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=directory,
            prefix=f".{os.path.basename(destination)}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_path = temporary.name
            temporary.write(payload)
            temporary.flush()
            os.fsync(temporary.fileno())
        try:
            os.link(temporary_path, destination, follow_symlinks=False)
        except FileExistsError as exc:
            raise MeasureFailure(
                f"refusing to overwrite existing evidence {destination}"
            ) from exc
        os.unlink(temporary_path)
        temporary_path = None
        directory_fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except MeasureFailure:
        raise
    except OSError as exc:
        raise MeasureFailure(
            f"failed to publish durable evidence at {destination}: {exc}"
        ) from exc
    finally:
        if temporary_path is not None:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass


def _ms_str_to_ns(ms_text: str) -> int:
    """Exact decimal-millisecond STRING -> integer nanoseconds (a finite decimal * 1e6 is an
    integer, so no rounding enters the reported ns). Owner rule: latency is whole integer ns."""
    return int(Fraction(ms_text) * 1_000_000)


def throughput_bytes_per_s(byte_count: int, elapsed_ns: int) -> int:
    """Integer bytes/sec (floor). No float: bytes * 1e9 as integer, divided by ns."""
    if elapsed_ns <= 0:
        raise MeasureFailure("non-positive elapsed_ns -- cannot form a throughput")
    return (byte_count * NS_PER_SEC) // elapsed_ns


def parse_fetch(line: str) -> dict:
    """Parse ONE FETCH_DONE line, failing closed on anything that is not a complete, byte-identical,
    BLAKE3-verified, full-length delivery (a silent absence must never read as a passing zero).
    Pure so `--self-test` bites it with no netns."""
    if "FETCH_DONE" not in line:
        raise MeasureFailure(f"unparseable FETCH_DONE line: {line!r}")
    values = dict(re.findall(r"([a-z0-9_]+)=([^\s]+)", line))
    integer_fields = {
        "bytes",
        "expect",
        "elapsed_ns",
        "byte_identical",
        "blake3_ok",
        "request_protocol_bytes",
        "response_header_bytes",
        "proof_bytes",
        "leaf_count",
        "leaf_length_prefix_bytes",
        "encoded_leaf_bytes",
        "complete_marker_bytes",
        "response_body_bytes",
        "response_protocol_bytes",
        "exchange_protocol_bytes",
        "request_complete_ns",
        "first_response_byte_ns",
        "authenticated_first_leaf_ns",
        "total_fetch_ns",
    }
    required = integer_fields | {"content", "codec_requested", "selected_codec"}
    missing = sorted(required - values.keys())
    if missing:
        raise MeasureFailure(f"FETCH_DONE missing fields {missing}: {line!r}")
    parsed = {name: int(values[name]) for name in integer_fields}
    got, expect, elapsed_ns = parsed["bytes"], parsed["expect"], parsed["elapsed_ns"]
    byte_identical, blake3_ok = parsed["byte_identical"], parsed["blake3_ok"]
    codec = values["codec_requested"]
    selected = values["selected_codec"]
    if codec not in {"raw", "both"}:
        raise MeasureFailure(f"unknown codec_requested {codec!r}")
    if got != expect:
        raise MeasureFailure(
            f"fetch delivered {got} of {expect} bytes -- truncated, not evidence"
        )
    if byte_identical != 1:
        raise MeasureFailure("fetched bytes are NOT byte-identical to the served NAR")
    if blake3_ok != 1:
        raise MeasureFailure("fetched bytes do NOT BLAKE3-verify to the content id")
    if elapsed_ns <= 0:
        raise MeasureFailure("non-positive elapsed_ns -- cannot form a throughput")
    if parsed["request_protocol_bytes"] != 33:
        raise MeasureFailure(
            "/nar/4 request accounting is not exactly 33 protocol bytes"
        )
    if parsed["response_header_bytes"] != 10:
        raise MeasureFailure("/nar/4 response header is not exactly 10 protocol bytes")
    if parsed["complete_marker_bytes"] != 4:
        raise MeasureFailure(
            "/nar/4 COMPLETE accounting is not exactly 4 protocol bytes"
        )
    expected_leaves = max(1, (got + 65_535) // 65_536)
    if parsed["leaf_count"] != expected_leaves:
        raise MeasureFailure("/nar/4 leaf count disagrees with raw geometry")
    if selected not in {"raw", "zstd"}:
        raise MeasureFailure(f"unknown selected_codec {selected!r}")
    if parsed["proof_bytes"] != 64 * (expected_leaves - 1):
        raise MeasureFailure(
            "/nar/4 proof bytes disagree with full-range Bao tree geometry"
        )
    expected_prefixes = 4 * expected_leaves if selected == "zstd" else 0
    if parsed["leaf_length_prefix_bytes"] != expected_prefixes:
        raise MeasureFailure(
            "/nar/4 leaf-prefix bytes disagree with selected codec/geometry"
        )
    if selected == "raw" and parsed["encoded_leaf_bytes"] != got:
        raise MeasureFailure("raw /nar/4 encoded-leaf bytes differ from NarSize")
    if codec == "raw" and selected != "raw":
        raise MeasureFailure("raw-only request did not select raw")
    if codec == "both" and selected != "zstd":
        raise MeasureFailure("raw+zstd measurement arm did not select zstd")
    body_sum = (
        parsed["proof_bytes"]
        + parsed["leaf_length_prefix_bytes"]
        + parsed["encoded_leaf_bytes"]
        + parsed["complete_marker_bytes"]
    )
    if parsed["response_body_bytes"] != body_sum:
        raise MeasureFailure(
            "response_body_bytes violates the exact component equation"
        )
    if parsed["response_protocol_bytes"] != parsed["response_header_bytes"] + body_sum:
        raise MeasureFailure(
            "response_protocol_bytes violates the exact header+body equation"
        )
    if parsed["exchange_protocol_bytes"] != (
        parsed["request_protocol_bytes"] + parsed["response_protocol_bytes"]
    ):
        raise MeasureFailure(
            "exchange_protocol_bytes violates the exact request+response equation"
        )
    timing = [
        parsed["request_complete_ns"],
        parsed["first_response_byte_ns"],
        parsed["authenticated_first_leaf_ns"],
        parsed["total_fetch_ns"],
    ]
    if any(value <= 0 for value in timing) or timing != sorted(timing):
        raise MeasureFailure(
            "request/first-response/first-auth/completion timings must be positive, monotonic, and share one request origin"
        )
    parsed["codec_requested"] = codec
    parsed["selected_codec"] = selected
    parsed["content"] = values["content"]
    if _CONTENT_DIGEST_RE.fullmatch(parsed["content"]) is None:
        raise MeasureFailure(
            "FETCH_DONE content is not canonical blake3:<64 lowercase hex>"
        )
    return parsed


_WIRE_FIELDS = (
    "request_protocol_bytes",
    "response_header_bytes",
    "proof_bytes",
    "leaf_count",
    "leaf_length_prefix_bytes",
    "encoded_leaf_bytes",
    "complete_marker_bytes",
    "response_body_bytes",
    "response_protocol_bytes",
    "exchange_protocol_bytes",
)


def parse_provider_observation(line: str) -> dict:
    values = dict(re.findall(r"([a-z0-9_]+)=([^\s]+)", line))
    integer_fields = {
        "pass1_bytes",
        "pass2_bytes",
        "proof_preparation_ns",
        "total_serve_ns",
        *_WIRE_FIELDS,
    }
    required = integer_fields | {"content", "selected_codec"}
    missing = sorted(required - values.keys())
    if missing:
        raise MeasureFailure(f"PROVIDE_DONE missing fields {missing}: {line!r}")
    parsed = {name: int(values[name]) for name in integer_fields}
    parsed["content"] = values["content"]
    if _CONTENT_DIGEST_RE.fullmatch(parsed["content"]) is None:
        raise MeasureFailure(
            "PROVIDE_DONE content is not canonical blake3:<64 lowercase hex>"
        )
    parsed["selected_codec"] = values["selected_codec"]
    if parsed["selected_codec"] not in {"raw", "zstd"}:
        raise MeasureFailure("PROVIDE_DONE has an unknown selected codec")
    if parsed["proof_preparation_ns"] <= 0 or parsed["total_serve_ns"] <= 0:
        raise MeasureFailure(
            "provider proof-preparation and total-serve timings must be positive"
        )
    if parsed["proof_preparation_ns"] > parsed["total_serve_ns"]:
        raise MeasureFailure(
            "provider proof preparation cannot exceed total serve time"
        )
    return parsed


def parse_run(text: str, *, process_capture: dict | None = None) -> dict:
    """Pull RTT, arm order, provider metadata, and both fetch/provider observations."""
    if "FATAL" in text:
        fatal = next((ln for ln in text.splitlines() if "FATAL" in ln), "FATAL")
        raise MeasureFailure(
            f"inner harness reported {fatal!r} -- link/fetch setup failed"
        )

    m = re.search(r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)/", text)
    if not m:
        raise MeasureFailure("run reported no RTT line (ping did not complete)")
    rtt_avg_str = m.group(1)
    rtt_ns = _ms_str_to_ns(rtt_avg_str)

    payload_events = re.findall(r"^PAYLOAD_CONFIG (.+)$", text, re.MULTILINE)
    if len(payload_events) != 1:
        raise MeasureFailure(
            f"run requires exactly one PAYLOAD_CONFIG event, got {len(payload_events)}"
        )
    payload_pairs = re.findall(r"([a-z0-9_]+)=([^\s]+)", payload_events[0])
    payload_values = dict(payload_pairs)
    payload_fields = {
        "nar_seed",
        "payload_kind",
        "payload_construction",
        "raw_bytes",
        "fetcher_identity_seed",
    }
    if (
        len(payload_pairs) != len(payload_fields)
        or set(payload_values) != payload_fields
    ):
        raise MeasureFailure(
            "PAYLOAD_CONFIG fields differ from the fixed evidence schema: "
            f"{sorted(payload_values)}"
        )
    payload_config = {
        "nar_seed": int(payload_values["nar_seed"]),
        "payload_kind": payload_values["payload_kind"],
        "payload_construction": payload_values["payload_construction"],
        "raw_bytes": int(payload_values["raw_bytes"]),
        "fetcher_identity_seed": int(payload_values["fetcher_identity_seed"]),
    }

    provider_meta_events = re.findall(r"^PROVIDE_META (.+)$", text, re.MULTILINE)
    if len(provider_meta_events) != 1:
        raise MeasureFailure(
            "run requires exactly one PROVIDE_META event, got "
            f"{len(provider_meta_events)}"
        )
    provider_meta_pairs = re.findall(r"([a-z0-9_]+)=([^\s]+)", provider_meta_events[0])
    provider_meta_values = dict(provider_meta_pairs)
    provider_meta_fields = {
        "content",
        "raw_bytes",
        "nar_seed",
        "payload_kind",
        "payload_construction",
        "legacy_single_frame_bytes",
        "legacy_response_protocol_bytes",
    }
    if (
        len(provider_meta_pairs) != len(provider_meta_fields)
        or set(provider_meta_values) != provider_meta_fields
    ):
        raise MeasureFailure(
            "PROVIDE_META fields differ from the fixed evidence schema: "
            f"{sorted(provider_meta_values)}"
        )
    meta = {
        "content": provider_meta_values["content"],
        "raw_bytes": int(provider_meta_values["raw_bytes"]),
        "nar_seed": int(provider_meta_values["nar_seed"]),
        "payload_kind": provider_meta_values["payload_kind"],
        "payload_construction": provider_meta_values["payload_construction"],
        "legacy_single_frame_bytes": int(
            provider_meta_values["legacy_single_frame_bytes"]
        ),
        "legacy_response_protocol_bytes": int(
            provider_meta_values["legacy_response_protocol_bytes"]
        ),
    }
    if _CONTENT_DIGEST_RE.fullmatch(meta["content"]) is None:
        raise MeasureFailure(
            "PROVIDE_META content is not canonical blake3:<64 lowercase hex>"
        )
    if meta["raw_bytes"] <= 0:
        raise MeasureFailure("provider NarSize must be positive")
    if meta["legacy_single_frame_bytes"] <= 0:
        raise MeasureFailure("legacy single-frame counterfactual must be positive")
    if meta["legacy_response_protocol_bytes"] <= 0:
        raise MeasureFailure("legacy response counterfactual must be positive")
    if meta["legacy_response_protocol_bytes"] != 2 + meta["legacy_single_frame_bytes"]:
        raise MeasureFailure(
            "legacy /nar/3 byte counterfactual must be 2-byte header + one frame"
        )
    for field in ("raw_bytes", "nar_seed", "payload_kind", "payload_construction"):
        if meta[field] != payload_config[field]:
            raise MeasureFailure(
                f"PROVIDE_META {field} differs from PAYLOAD_CONFIG {field}"
            )

    order_events = re.findall(r"^ARM_ORDER order=([^\s]+)$", text, re.MULTILINE)
    if len(order_events) != 1:
        raise MeasureFailure(
            f"run requires exactly one ARM_ORDER event, got {len(order_events)}"
        )
    arm_order = order_events[0]
    if arm_order not in {"raw-first", "zstd-first"}:
        raise MeasureFailure(f"run reported unknown paired arm order {arm_order!r}")

    arms = {}
    observed_fetch_order = []
    provider_events = []
    for line in text.splitlines():
        if "FETCH_DONE" in line:
            arm = parse_fetch(line)
            # 'raw' arm offered the raw-only accept set; the zstd arm offered 'both'.
            key = "raw" if arm["codec_requested"] == "raw" else "zstd"
            if key in arms:
                raise MeasureFailure(f"duplicate FETCH_DONE event for {key}")
            arms[key] = arm
            observed_fetch_order.append(key)
        if line.startswith("PROVIDE_DONE "):
            provider_events.append(parse_provider_observation(line))
    if "raw" not in arms:
        raise MeasureFailure("run reported no RAW-arm FETCH_DONE line")
    if "zstd" not in arms:
        raise MeasureFailure("run reported no ZSTD-arm FETCH_DONE line")
    expected_fetch_order = (
        ["raw", "zstd"] if arm_order == "raw-first" else ["zstd", "raw"]
    )
    arm_start_events = re.findall(
        r"^ARM_START arm=(raw|zstd) fetcher_identity_seed=(\d+)$",
        text,
        re.MULTILINE,
    )
    if len(arm_start_events) != 2:
        raise MeasureFailure(
            f"run requires exactly two ARM_START events, got {len(arm_start_events)}"
        )
    observed_arm_start_order = [arm for arm, _seed in arm_start_events]
    if observed_arm_start_order != expected_fetch_order:
        raise MeasureFailure(
            f"ARM_ORDER {arm_order} disagrees with ARM_START order {observed_arm_start_order}"
        )
    arm_identity_seeds = {
        arm: int(identity_seed) for arm, identity_seed in arm_start_events
    }
    if len(arm_identity_seeds) != 2:
        raise MeasureFailure("ARM_START requires one raw and one zstd identity event")
    if set(arm_identity_seeds.values()) != {payload_config["fetcher_identity_seed"]}:
        raise MeasureFailure(
            "raw and zstd arms must use the PAYLOAD_CONFIG fetcher identity seed"
        )
    if observed_fetch_order != expected_fetch_order:
        raise MeasureFailure(
            f"ARM_ORDER {arm_order} disagrees with FETCH_DONE order {observed_fetch_order}"
        )
    if len(provider_events) != 2:
        raise MeasureFailure(
            f"run requires exactly two successful PROVIDE_DONE events, got {len(provider_events)}"
        )
    providers = {}
    for event in provider_events:
        codec = event["selected_codec"]
        if codec in providers:
            raise MeasureFailure(f"duplicate PROVIDE_DONE event for {codec}")
        providers[codec] = event
    if set(providers) != {"raw", "zstd"}:
        raise MeasureFailure(
            "PROVIDE_DONE must contain exactly one raw and one zstd success"
        )

    if arms["raw"]["bytes"] != meta["raw_bytes"]:
        raise MeasureFailure("raw arm NarSize differs from provider metadata")
    if arms["zstd"]["bytes"] != meta["raw_bytes"]:
        raise MeasureFailure("zstd arm NarSize differs from provider metadata")
    if arms["raw"]["content"] != arms["zstd"]["content"]:
        raise MeasureFailure(
            "raw and zstd arms did not request the same content identity"
        )
    if meta["content"] != arms["raw"]["content"]:
        raise MeasureFailure(
            "PROVIDE_META content differs from the raw/zstd content identity"
        )
    for codec in ("raw", "zstd"):
        provider = providers[codec]
        fetch = arms[codec]
        if provider["content"] != fetch["content"]:
            raise MeasureFailure(f"{codec} provider/fetch content identities differ")
        if provider["pass1_bytes"] != meta["raw_bytes"]:
            raise MeasureFailure(
                f"{codec} provider pass1 byte count differs from NarSize"
            )
        if provider["pass2_bytes"] != meta["raw_bytes"]:
            raise MeasureFailure(
                f"{codec} provider pass2 byte count differs from NarSize"
            )
        for field in _WIRE_FIELDS:
            if provider[field] != fetch[field]:
                raise MeasureFailure(
                    f"{codec} provider/fetch exact wire accounting differs at {field}"
                )
    if process_capture is None:
        process_capture = _process_capture(text, "", 0)
    else:
        expected_capture = _process_capture(
            process_capture["stdout"],
            process_capture["stderr"],
            process_capture["return_code"],
        )
        if process_capture != expected_capture:
            raise MeasureFailure("process capture SHA-256 or recipe is inconsistent")
        if process_capture["stdout"] + process_capture["stderr"] != text:
            raise MeasureFailure(
                "process capture streams disagree with parsed transcript"
            )
    return {
        "rtt_ns": rtt_ns,
        "rtt_avg_str": rtt_avg_str,
        "meta": meta,
        "payload_config": payload_config,
        "arms": arms,
        "providers": providers,
        "arm_order": arm_order,
        "arm_identity_seeds": arm_identity_seeds,
        "combined_transcript": text,
        "combined_transcript_sha256": _text_sha256(text),
        "process_capture": process_capture,
    }


def _arm_for_oracle(rtt_ns: int, wire_bytes: int, elapsed_ns: int) -> dict:
    """Build the dict shape `shaped_link.assert_shaping` decides on: exact integer `rtt_ns` and
    `rate_bytes_per_s` (the gate reads only these), plus float display fields. The rate is the RAW
    arm's throughput — the bandwidth-bound reference whose shaped value sits near the cap."""
    rate = throughput_bytes_per_s(wire_bytes, elapsed_ns)
    return {
        "rtt_ns": rtt_ns,
        "rate_bytes_per_s": rate,
        # Terminal display only (never gated): ns->ms and bytes/sec->mbit.
        "rtt_ms": rtt_ns / 1_000_000,
        "mbit": rate * 8 / 1_000_000,
    }


def _paired_arm_order(run_index: int) -> str:
    """Deterministically alternate which codec pays the first-arm warm-up position."""
    return "raw-first" if run_index % 2 == 0 else "zstd-first"


def run_inner(
    shape: bool,
    nar_bytes: int,
    delay_ms: int,
    rate_mbit: int,
    probe_bin: str,
    nar_seed: int,
    arm_order: str,
) -> dict:
    """Run one inner configuration inside `unshare -Urn` and return its parsed metrics."""
    cmd = [
        "unshare",
        "-Urn",
        "bash",
        INNER,
        "yes" if shape else "no",
        str(nar_bytes),
        str(delay_ms),
        str(rate_mbit),
        probe_bin,
        str(nar_seed),
        arm_order,
        str(FETCHER_IDENTITY_SEED),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    out = proc.stdout + proc.stderr
    if proc.returncode != 0 and "FATAL" not in out:
        raise MeasureFailure(
            f"{'shaped' if shape else 'unshaped'} run exited {proc.returncode}\n{out}"
        )
    parsed = parse_run(
        out,
        process_capture=_process_capture(proc.stdout, proc.stderr, proc.returncode),
    )
    if parsed["arm_order"] != arm_order:
        raise MeasureFailure(
            f"inner run reported {parsed['arm_order']}, requested {arm_order}"
        )
    return parsed


def _wire_equations(wire: dict) -> dict:
    """Serialize the exact integer equations needed to audit one `/nar/4` exchange."""
    body_component_sum = (
        wire["proof_bytes"]
        + wire["leaf_length_prefix_bytes"]
        + wire["encoded_leaf_bytes"]
        + wire["complete_marker_bytes"]
    )
    response_component_sum = wire["response_header_bytes"] + wire["response_body_bytes"]
    exchange_component_sum = (
        wire["request_protocol_bytes"] + wire["response_protocol_bytes"]
    )
    equations = {
        "response_body": {
            "reported_bytes": wire["response_body_bytes"],
            "component_sum_bytes": body_component_sum,
            "holds": wire["response_body_bytes"] == body_component_sum,
        },
        "response_protocol": {
            "reported_bytes": wire["response_protocol_bytes"],
            "component_sum_bytes": response_component_sum,
            "holds": wire["response_protocol_bytes"] == response_component_sum,
        },
        "exchange_protocol": {
            "reported_bytes": wire["exchange_protocol_bytes"],
            "component_sum_bytes": exchange_component_sum,
            "holds": wire["exchange_protocol_bytes"] == exchange_component_sum,
        },
    }
    equations["all_hold"] = all(equation["holds"] for equation in equations.values())
    return equations


def _actor_evidence(observation: dict) -> dict:
    wire = {field: observation[field] for field in _WIRE_FIELDS}
    return {
        "metadata": {
            field: value
            for field, value in observation.items()
            if field not in _WIRE_FIELDS
        },
        "wire": wire,
        "wire_equations": _wire_equations(wire),
    }


def _auditable_run(run: dict, label: str) -> dict:
    """Retain a lossless parsed/captured run plus independently checkable wire parity."""
    arm_evidence = {}
    for codec in ("raw", "zstd"):
        fetch = run["arms"][codec]
        provider = run["providers"][codec]
        wire_parity = {field: fetch[field] == provider[field] for field in _WIRE_FIELDS}
        arm_evidence[codec] = {
            "fetch": _actor_evidence(fetch),
            "provider": _actor_evidence(provider),
            "provider_fetch_parity": {
                "wire_fields": wire_parity,
                "all_wire_fields_equal": all(wire_parity.values()),
                "content_equal": fetch["content"] == provider["content"],
            },
        }
    capture = dict(run["process_capture"])
    expected_capture = _process_capture(
        capture["stdout"], capture["stderr"], capture["return_code"]
    )
    transcript_sha_matches = (
        _text_sha256(run["combined_transcript"]) == run["combined_transcript_sha256"]
    )
    capture_sha_matches = capture == expected_capture
    capture_matches_transcript = (
        capture["stdout"] + capture["stderr"] == run["combined_transcript"]
    )
    wire_equations_hold = all(
        actor["wire_equations"]["all_hold"]
        for arm in arm_evidence.values()
        for actor in (arm["fetch"], arm["provider"])
    )
    provider_fetch_parity_holds = all(
        arm["provider_fetch_parity"]["all_wire_fields_equal"]
        and arm["provider_fetch_parity"]["content_equal"]
        for arm in arm_evidence.values()
    )
    audit_checks = {
        "transcript_sha256_matches": transcript_sha_matches,
        "process_capture_sha256_matches": capture_sha_matches,
        "process_capture_matches_transcript": capture_matches_transcript,
        "wire_equations_hold": wire_equations_hold,
        "provider_fetch_parity_holds": provider_fetch_parity_holds,
    }
    audit_checks["all_hold"] = all(audit_checks.values())
    return {
        "label": label,
        "rtt_ns": run["rtt_ns"],
        "rtt_avg_source_decimal_ms": run["rtt_avg_str"],
        "arm_order": run["arm_order"],
        "arm_identity_seeds": dict(run["arm_identity_seeds"]),
        "payload_config": dict(run["payload_config"]),
        "provider_meta": dict(run["meta"]),
        "content": run["arms"]["raw"]["content"],
        "arms": arm_evidence,
        "parser_transcript": {
            "text": run["combined_transcript"],
            "sha256": run["combined_transcript_sha256"],
            "sha256_recipe": "sha256(utf8(text))",
        },
        "process_capture": capture,
        "audit_checks": audit_checks,
    }


def _measurement_contract(
    shaped_runs: list[dict],
    unshaped: dict,
    nar_bytes: int,
    nar_seed: int,
    runs: int,
) -> dict:
    """Bind every observation to one CLI-selected payload and one canonical digest."""
    expected_payload = {
        "raw_bytes": nar_bytes,
        "nar_seed": nar_seed,
        "payload_kind": PAYLOAD_KIND,
        "payload_construction": PAYLOAD_CONSTRUCTION,
    }
    expected_config = {
        **expected_payload,
        "fetcher_identity_seed": FETCHER_IDENTITY_SEED,
    }
    observed = []
    content_values: list[str] = []
    raw_size_values: list[int] = []
    payload_metadata_consistent = True
    fetcher_identity_consistent = True
    all_runs = [
        *((f"shaped-{index}", run) for index, run in enumerate(shaped_runs)),
        ("unshaped-control", unshaped),
    ]
    for label, run in all_runs:
        config = run["payload_config"]
        provider_meta = run["meta"]
        contents = {
            "provider_meta": provider_meta["content"],
            "raw_fetch": run["arms"]["raw"]["content"],
            "zstd_fetch": run["arms"]["zstd"]["content"],
            "raw_provider": run["providers"]["raw"]["content"],
            "zstd_provider": run["providers"]["zstd"]["content"],
        }
        sizes = {
            "payload_config_raw_bytes": config["raw_bytes"],
            "provider_meta_raw_bytes": provider_meta["raw_bytes"],
            "raw_fetch_bytes": run["arms"]["raw"]["bytes"],
            "raw_fetch_expect": run["arms"]["raw"]["expect"],
            "raw_fetch_encoded_leaf_bytes": run["arms"]["raw"]["encoded_leaf_bytes"],
            "zstd_fetch_bytes": run["arms"]["zstd"]["bytes"],
            "zstd_fetch_expect": run["arms"]["zstd"]["expect"],
            "raw_provider_pass1_bytes": run["providers"]["raw"]["pass1_bytes"],
            "raw_provider_pass2_bytes": run["providers"]["raw"]["pass2_bytes"],
            "raw_provider_encoded_leaf_bytes": run["providers"]["raw"][
                "encoded_leaf_bytes"
            ],
            "zstd_provider_pass1_bytes": run["providers"]["zstd"]["pass1_bytes"],
            "zstd_provider_pass2_bytes": run["providers"]["zstd"]["pass2_bytes"],
        }
        provider_payload = {field: provider_meta[field] for field in expected_payload}
        identities = dict(run["arm_identity_seeds"])
        content_values.extend(contents.values())
        raw_size_values.extend(sizes.values())
        payload_metadata_consistent = payload_metadata_consistent and (
            config == expected_config and provider_payload == expected_payload
        )
        fetcher_identity_consistent = fetcher_identity_consistent and (
            identities
            == {
                "raw": FETCHER_IDENTITY_SEED,
                "zstd": FETCHER_IDENTITY_SEED,
            }
        )
        observed.append(
            {
                "label": label,
                "contents": contents,
                "raw_sizes": sizes,
                "payload_config": dict(config),
                "provider_payload": provider_payload,
                "arm_identity_seeds": identities,
            }
        )

    canonical_contents = sorted(set(content_values))
    canonical_content_consistent = (
        len(canonical_contents) == 1
        and _CONTENT_DIGEST_RE.fullmatch(canonical_contents[0]) is not None
    )
    cli_nar_size_consistent = all(value == nar_bytes for value in raw_size_values)
    run_count_consistent = runs == len(shaped_runs)
    canonical_payload_consistent = (
        canonical_content_consistent
        and cli_nar_size_consistent
        and payload_metadata_consistent
    )
    return {
        "expected_payload": expected_payload,
        "expected_fetcher_identity_seed": FETCHER_IDENTITY_SEED,
        "canonical_content_digest": (
            canonical_contents[0] if canonical_content_consistent else None
        ),
        "canonical_payload": (
            {"content": canonical_contents[0], **expected_payload}
            if canonical_payload_consistent
            else None
        ),
        "observed_content_digests": canonical_contents,
        "canonical_payload_consistent": canonical_payload_consistent,
        "canonical_content_consistent": canonical_content_consistent,
        "cli_nar_size_consistent": cli_nar_size_consistent,
        "payload_metadata_consistent": payload_metadata_consistent,
        "fetcher_identity_consistent": fetcher_identity_consistent,
        "run_count_consistent": run_count_consistent,
        "observed": observed,
    }


def _noise_threshold(min_margin_ns: int, combined_spread_ns: int) -> dict:
    """Apply the predeclared exact rational `margin >= 3 * combined spread` gate."""
    scaled_margin = min_margin_ns * NOISE_MARGIN_MULTIPLIER_DENOMINATOR
    scaled_spread = combined_spread_ns * NOISE_MARGIN_MULTIPLIER_NUMERATOR
    return {
        "multiplier_numerator": NOISE_MARGIN_MULTIPLIER_NUMERATOR,
        "multiplier_denominator": NOISE_MARGIN_MULTIPLIER_DENOMINATOR,
        "predicate": "min_margin_ns * denominator >= combined_observed_spread_ns * numerator",
        "min_margin_ns": min_margin_ns,
        "combined_observed_spread_ns": combined_spread_ns,
        "scaled_margin": scaled_margin,
        "scaled_required_spread": scaled_spread,
        "passes": scaled_margin >= scaled_spread,
    }


def derive_verdict(shaped_runs: list[dict]) -> dict:
    """Integer/rational verdict over the shaped runs. The CONCLUSION depends on the predeclared
    exact 3x combined-spread threshold for `raw_elapsed - zstd_elapsed` — never on a tight
    percentage. `zstd_faster` per run is a pure INTEGER compare. The headline wire ratio is derived
    from the COUNTED per-run v4 response-protocol totals (raw vs zstd, like-units) — never
    NarSize-vs-compressed."""
    per_run = []
    zstd_faster_every_run = True
    wire_smaller_every_run = True
    for r in shaped_runs:
        raw_ns = r["arms"]["raw"]["elapsed_ns"]
        zstd_ns = r["arms"]["zstd"]["elapsed_ns"]
        wire_raw = r["arms"]["raw"]["response_protocol_bytes"]
        wire_zstd = r["arms"]["zstd"]["response_protocol_bytes"]
        zstd_faster = zstd_ns < raw_ns  # integer compare — the biting decision
        wire_smaller = wire_zstd < wire_raw  # integer compare
        zstd_faster_every_run = zstd_faster_every_run and zstd_faster
        wire_smaller_every_run = wire_smaller_every_run and wire_smaller
        per_run.append(
            {
                "arm_order": r["arm_order"],
                "raw_elapsed_ns": raw_ns,
                "zstd_elapsed_ns": zstd_ns,
                "margin_ns": raw_ns - zstd_ns,
                "raw_throughput_bytes_per_s": throughput_bytes_per_s(wire_raw, raw_ns),
                "zstd_throughput_bytes_per_s": throughput_bytes_per_s(
                    wire_zstd, zstd_ns
                ),
                "wire_raw_bytes": wire_raw,
                "wire_zstd_bytes": wire_zstd,
                "wallclock_speedup_pair": [raw_ns, zstd_ns],  # exact rational raw/zstd
                "wire_ratio_pair": [
                    wire_raw,
                    wire_zstd,
                ],  # exact rational raw/zstd (COUNTED)
                "raw_request_origin_intervals_ns": {
                    "request_complete": r["arms"]["raw"]["request_complete_ns"],
                    "first_response": r["arms"]["raw"]["first_response_byte_ns"],
                    "first_authenticated_leaf": r["arms"]["raw"][
                        "authenticated_first_leaf_ns"
                    ],
                    "complete": r["arms"]["raw"]["total_fetch_ns"],
                },
                "zstd_request_origin_intervals_ns": {
                    "request_complete": r["arms"]["zstd"]["request_complete_ns"],
                    "first_response": r["arms"]["zstd"]["first_response_byte_ns"],
                    "first_authenticated_leaf": r["arms"]["zstd"][
                        "authenticated_first_leaf_ns"
                    ],
                    "complete": r["arms"]["zstd"]["total_fetch_ns"],
                },
                "raw_provider_serve": {
                    "pass1_bytes": r["providers"]["raw"]["pass1_bytes"],
                    "pass2_bytes": r["providers"]["raw"]["pass2_bytes"],
                    "proof_preparation_ns": r["providers"]["raw"][
                        "proof_preparation_ns"
                    ],
                    "total_serve_ns": r["providers"]["raw"]["total_serve_ns"],
                },
                "zstd_provider_serve": {
                    "pass1_bytes": r["providers"]["zstd"]["pass1_bytes"],
                    "pass2_bytes": r["providers"]["zstd"]["pass2_bytes"],
                    "proof_preparation_ns": r["providers"]["zstd"][
                        "proof_preparation_ns"
                    ],
                    "total_serve_ns": r["providers"]["zstd"]["total_serve_ns"],
                },
                "zstd_faster": zstd_faster,
            }
        )
    # Noise framing: compare the minimum paired margin to a predeclared exact rational multiple of
    # the combined observed arm spread. Equality intentionally passes and is boundary-tested.
    raw_elapseds = [p["raw_elapsed_ns"] for p in per_run]
    zstd_elapseds = [p["zstd_elapsed_ns"] for p in per_run]
    min_margin_ns = min(p["margin_ns"] for p in per_run)
    raw_spread_ns = max(raw_elapseds) - min(raw_elapseds)
    zstd_spread_ns = max(zstd_elapseds) - min(zstd_elapseds)
    noise_threshold = _noise_threshold(min_margin_ns, raw_spread_ns + zstd_spread_ns)

    # The exact v4 response protocol bytes must be consistent across headline runs (payload + codec
    # deterministic, so every run must ship the same body volumes); if they drift, the headline ratio
    # is not well-defined and the run is rejected. The headline ratio is [counted raw, counted zstd].
    wire_raw_set = {p["wire_raw_bytes"] for p in per_run}
    wire_zstd_set = {p["wire_zstd_bytes"] for p in per_run}
    wire_bytes_consistent = len(wire_raw_set) == 1 and len(wire_zstd_set) == 1
    wire_raw_common = per_run[0]["wire_raw_bytes"]
    wire_zstd_common = per_run[0]["wire_zstd_bytes"]
    return {
        "per_run": per_run,
        "zstd_faster_every_run": zstd_faster_every_run,
        "wire_smaller_every_run": wire_smaller_every_run,
        "min_margin_ns": min_margin_ns,
        "raw_spread_ns": raw_spread_ns,
        "zstd_spread_ns": zstd_spread_ns,
        "noise_threshold": noise_threshold,
        "margin_meets_predeclared_noise_threshold": noise_threshold["passes"],
        "wire_bytes_consistent": wire_bytes_consistent,
        "wire_raw_common": wire_raw_common,
        "wire_zstd_common": wire_zstd_common,
    }


def gate_shaping(
    shaped_runs: list[dict], unshaped: dict, delay_ms: int, rate_mbit: int
) -> dict:
    """Apply the proven shaping oracle to the RAW arm of EVERY shaped run that contributes to the
    headline (TASK-198 F5), against the single unshaped negative control. Returns a per-run pass/
    fail plus the aggregate `all_gated`. An unshaped or mis-shaped run cannot slip into the minimum
    because its own gate fails and rejects the whole measurement (fail closed)."""
    unshaped_arm = _arm_for_oracle(
        unshaped["rtt_ns"],
        unshaped["arms"]["raw"]["response_protocol_bytes"],
        unshaped["arms"]["raw"]["elapsed_ns"],
    )
    per_run = []
    all_gated = True
    for r in shaped_runs:
        shaped_arm = _arm_for_oracle(
            r["rtt_ns"],
            r["arms"]["raw"]["response_protocol_bytes"],
            r["arms"]["raw"]["elapsed_ns"],
        )
        entry = {
            "shaped_rtt_ns": shaped_arm["rtt_ns"],
            "shaped_raw_throughput_bytes_per_s": shaped_arm["rate_bytes_per_s"],
        }
        try:
            shaped_link.assert_shaping(shaped_arm, unshaped_arm, delay_ms, rate_mbit)
            entry["passed"] = True
        except shaped_link.ShapingViolation as exc:
            entry["passed"] = False
            entry["reason"] = str(exc)
            all_gated = False
        per_run.append(entry)
    return {
        "all_gated": all_gated,
        "unshaped_rtt_ns": unshaped_arm["rtt_ns"],
        "unshaped_raw_throughput_bytes_per_s": unshaped_arm["rate_bytes_per_s"],
        "per_run": per_run,
    }


def legacy_counterfactual(shaped_runs: list[dict]) -> dict:
    """Compare exact v4 components to the prior `/nar/3` byte form. The old form is a
    counterfactual, never an observed v4 body: one bulk zstd frame plus a two-byte response
    header. We report frame-reset overhead separately from proof/header/COMPLETE overhead."""
    per_run = []
    for run in shaped_runs:
        zstd = run["arms"]["zstd"]
        meta = run["meta"]
        legacy_frame = meta["legacy_single_frame_bytes"]
        legacy_response = meta["legacy_response_protocol_bytes"]
        per_run.append(
            {
                "legacy_single_frame_bytes": legacy_frame,
                "v4_encoded_leaf_bytes": zstd["encoded_leaf_bytes"],
                "frame_reset_cost_pair": [zstd["encoded_leaf_bytes"], legacy_frame],
                "frame_reset_delta_bytes": zstd["encoded_leaf_bytes"] - legacy_frame,
                "legacy_response_protocol_bytes": legacy_response,
                "v4_response_protocol_bytes": zstd["response_protocol_bytes"],
                "response_protocol_cost_pair": [
                    zstd["response_protocol_bytes"],
                    legacy_response,
                ],
                "v4_response_delta_bytes": zstd["response_protocol_bytes"]
                - legacy_response,
            }
        )
    legacy_pairs = {
        (entry["legacy_single_frame_bytes"], entry["legacy_response_protocol_bytes"])
        for entry in per_run
    }
    v4_pairs = {
        (entry["v4_encoded_leaf_bytes"], entry["v4_response_protocol_bytes"])
        for entry in per_run
    }
    return {
        "all_ok": len(legacy_pairs) == 1 and len(v4_pairs) == 1,
        "per_run": per_run,
    }


def _frac_display(num: int, den: int) -> str:
    """A terminal decimal for DISPLAY ONLY (never re-read/compared)."""
    fr = Fraction(num, den)
    approx = fr.numerator / fr.denominator  # display-only float, never gated
    return f"~{approx:.3f}x (exact {fr.numerator}/{fr.denominator})"


def finalize(
    shaped_runs: list[dict],
    unshaped: dict,
    delay_ms: int,
    rate_mbit: int,
    nar_bytes: int,
    nar_seed: int,
    runs: int,
) -> dict:
    """Given the parsed shaped runs + the unshaped control, gate every run, derive the verdict,
    derive the explicit legacy byte counterfactual, and assemble the serialized report — including the FAIL-CLOSED
    `accepted` decision over every load-bearing flag. Pure of netns so `--self-test`
    can drive the whole render+exit path by mutation."""
    verdict = derive_verdict(shaped_runs)
    shaping = gate_shaping(shaped_runs, unshaped, delay_ms, rate_mbit)
    counterfactual = legacy_counterfactual(shaped_runs)
    measurement_contract = _measurement_contract(
        shaped_runs, unshaped, nar_bytes, nar_seed, runs
    )
    shaped_observations = [
        _auditable_run(run, f"shaped-{index}") for index, run in enumerate(shaped_runs)
    ]
    unshaped_observation = _auditable_run(unshaped, "unshaped-control")
    audit_evidence_consistent = all(
        observation["audit_checks"]["all_hold"]
        for observation in [*shaped_observations, unshaped_observation]
    )
    paired_order_alternates = (
        len(shaped_runs) >= 2
        and all(
            current["arm_order"] != previous["arm_order"]
            for previous, current in zip(shaped_runs, shaped_runs[1:])
        )
        and len({run["arm_order"] for run in shaped_runs}) == 2
    )

    # The load-bearing flags. EVERY one must hold or the run is not evidence of a win (fail closed).
    # The per-run flags (zstd_faster_every_run, wire_smaller_every_run, all_runs_shape_gated,
    # legacy_counterfactual_consistent) each AND across ALL runs, so a SINGLE failing run rejects the whole
    # verdict — no run-0-only shortcut inherited from the TASK-198 harness.
    flags = {
        "zstd_faster_every_run": verdict["zstd_faster_every_run"],
        "wire_smaller_every_run": verdict["wire_smaller_every_run"],
        "margin_meets_predeclared_noise_threshold": verdict[
            "margin_meets_predeclared_noise_threshold"
        ],
        "all_runs_shape_gated": shaping["all_gated"],
        "wire_bytes_consistent": verdict["wire_bytes_consistent"],
        "paired_order_alternates": paired_order_alternates,
        "legacy_counterfactual_consistent": counterfactual["all_ok"],
        "canonical_content_consistent": measurement_contract[
            "canonical_content_consistent"
        ],
        "canonical_payload_consistent": measurement_contract[
            "canonical_payload_consistent"
        ],
        "cli_nar_size_consistent": measurement_contract["cli_nar_size_consistent"],
        "payload_metadata_consistent": measurement_contract[
            "payload_metadata_consistent"
        ],
        "fetcher_identity_consistent": measurement_contract[
            "fetcher_identity_consistent"
        ],
        "run_count_consistent": measurement_contract["run_count_consistent"],
        "audit_evidence_consistent": audit_evidence_consistent,
    }
    accepted = all(flags.values())
    failure_reasons = [name for name, ok in flags.items() if not ok]

    meta = shaped_runs[0]["meta"]
    # The min-of-N (best) shaped arm elapsed — the standard shared-box min-of-N wall-clock proxy.
    best_raw_ns = min(p["raw_elapsed_ns"] for p in verdict["per_run"])
    best_zstd_ns = min(p["zstd_elapsed_ns"] for p in verdict["per_run"])
    # THE HEADLINE wire ratio: exact raw v4 response bytes / exact zstd v4 response bytes
    # (like-units, exact rational). Never NarSize-vs-compressed.
    wire_raw = verdict["wire_raw_common"]
    wire_zstd = verdict["wire_zstd_common"]
    return {
        "task": "task-197",
        "acceptance_criterion": "AC9 live wire/two-pass/timing evidence",
        "harness_lineage": "evolved from TASK-198's shaped-link harness",
        "wire_revision": "TASK-197 Bao-authenticated /nar/4 with independently framed 64-KiB leaves",
        "measures": "live raw-vs-zstd libp2p NAR transfer over a tc-netem shaped peer link with "
        "BOTH ends shaped (the two-ends-shaped serve trace TASK-203 deferred here). The timed "
        "window is an ALREADY-CONNECTED open-stream /nar/4 fetch: discovery, dial, and the "
        "Noise/yamux handshake happen out of band BEFORE the clock starts.",
        "environment_boundary": "shaped-link EMULATION (unshare -Urn nested netns + veth + tc "
        "netem), NOT real hardware / a real WAN. Models mean RTT + a rate cap; NOT loss, jitter, "
        "competing traffic, or NAT traversal. Removes the pod-loopback UPPER bound on the peer arm; "
        "is not itself a field measurement (the real-hardware residual is TASK-207).",
        "integer_exact": True,
        "no_floats_in_decisions": True,
        "accepted": accepted,
        "verdict": "ACCEPTED" if accepted else "REJECTED",
        "failure_reasons": failure_reasons,
        "load_bearing_flags": flags,
        "nar_bytes": nar_bytes,
        "delay_ms": delay_ms,
        "rate_mbit": rate_mbit,
        "nar_seed": nar_seed,
        "payload_kind": PAYLOAD_KIND,
        "payload_construction": PAYLOAD_CONSTRUCTION,
        "fetcher_identity_seed": FETCHER_IDENTITY_SEED,
        "content_digest": measurement_contract["canonical_content_digest"],
        "canonical_payload": measurement_contract["canonical_payload"],
        "shaped_runs": runs,
        "served_raw_bytes": meta["raw_bytes"],
        # Explicit byte counterfactual: prior one-frame `/nar/3` versus exact v4 components.
        "legacy_single_frame_bytes": meta["legacy_single_frame_bytes"],
        "legacy_response_protocol_bytes": meta["legacy_response_protocol_bytes"],
        "legacy_counterfactual": counterfactual,
        # THE HEADLINE wire ratio, from exact successful v4 response protocol bytes (like-units).
        "wire_raw_bytes": wire_raw,
        "wire_zstd_bytes": wire_zstd,
        "wire_ratio_pair": [wire_raw, wire_zstd],
        "wire_ratio_display": _frac_display(wire_raw, wire_zstd),
        "shaping_oracle": shaping,
        "measurement_contract": measurement_contract,
        "wire_fields_schema": list(_WIRE_FIELDS),
        "observations": {
            "shaped": shaped_observations,
            "unshaped_control": unshaped_observation,
        },
        "headline": {
            "zstd_faster_every_run": verdict["zstd_faster_every_run"],
            "wire_smaller_every_run": verdict["wire_smaller_every_run"],
            "margin_meets_predeclared_noise_threshold": verdict[
                "margin_meets_predeclared_noise_threshold"
            ],
            "noise_threshold": verdict["noise_threshold"],
            "min_margin_ns": verdict["min_margin_ns"],
            "raw_spread_ns": verdict["raw_spread_ns"],
            "zstd_spread_ns": verdict["zstd_spread_ns"],
            "best_raw_elapsed_ns": best_raw_ns,
            "best_zstd_elapsed_ns": best_zstd_ns,
            "best_wallclock_speedup_pair": [best_raw_ns, best_zstd_ns],
            "best_wallclock_speedup_display": _frac_display(best_raw_ns, best_zstd_ns),
        },
        "per_run": verdict["per_run"],
    }


def _print_report(report: dict) -> None:
    """Render the report. FAIL CLOSED: the win / noise-threshold / parity conclusions and the
    `VERDICT: ACCEPTED` line are printed ONLY when every load-bearing flag passed. When rejected,
    the raw per-run data is still shown (it is factual), but the affirmative conclusions are
    suppressed and a `VERDICT: REJECTED` line names the failed checks."""
    h = report["headline"]
    if provenance := report.get("provenance"):
        print(
            "  provenance: "
            f"{provenance['harness_origin']}; {provenance['wire_revision']}; "
            f"probe_sha256={provenance['probe_sha256']} git_head={provenance['git_head']} "
            f"git_worktree_dirty={provenance['git_worktree_dirty']}"
        )
    print(
        f"  served: raw NarSize {report['served_raw_bytes']} bytes; exact v4 response protocol: raw "
        f"{report['wire_raw_bytes']} bytes, zstd {report['wire_zstd_bytes']} bytes "
        f"(HEADLINE wire ratio raw/zstd {report['wire_ratio_display']})"
    )
    cc = report["legacy_counterfactual"]
    print(
        f"  explicit byte counterfactual (PER-RUN, all {len(cc['per_run'])} runs): prior one-frame "
        f"/nar/3 versus per-leaf-frame /nar/4; consistent={cc['all_ok']}. Byte cost only: no "
        f"latency or throughput inference."
    )
    for i, e in enumerate(cc["per_run"]):
        print(
            f"    run {i}: encoded leaves {e['v4_encoded_leaf_bytes']} vs legacy frame "
            f"{e['legacy_single_frame_bytes']} -> exact pair {e['frame_reset_cost_pair']}, "
            f"delta {e['frame_reset_delta_bytes']} bytes; "
            f"v4 response {e['v4_response_protocol_bytes']} vs legacy response "
            f"{e['legacy_response_protocol_bytes']} -> exact pair {e['response_protocol_cost_pair']}, "
            f"delta {e['v4_response_delta_bytes']} bytes"
        )
    o = report["shaping_oracle"]
    print(
        f"  shaping oracle: {sum(1 for p in o['per_run'] if p['passed'])}/{len(o['per_run'])} "
        f"shaped runs gated vs control (control RTT {o['unshaped_rtt_ns']} ns, control raw "
        f"throughput {o['unshaped_raw_throughput_bytes_per_s']} bytes/s); all_gated={o['all_gated']}"
    )
    for i, (p, g) in enumerate(zip(report["per_run"], o["per_run"])):
        print(
            f"  run {i} ({p['arm_order']}): raw {p['raw_elapsed_ns']} ns "
            f"({p['raw_throughput_bytes_per_s']} bytes/s)  "
            f"zstd {p['zstd_elapsed_ns']} ns ({p['zstd_throughput_bytes_per_s']} bytes/s)  "
            f"margin {p['margin_ns']} ns  speedup {_frac_display(*p['wallclock_speedup_pair'])}  "
            f"shape-gated={g['passed']}"
        )
        print(
            f"    request-origin intervals ns: raw={p['raw_request_origin_intervals_ns']} "
            f"zstd={p['zstd_request_origin_intervals_ns']}; open-stream-to-complete elapsed_ns "
            f"remains the separate wall-clock above"
        )
        print(
            f"    provider post-FIN observations: raw={p['raw_provider_serve']} "
            f"zstd={p['zstd_provider_serve']}"
        )

    if not report["accepted"]:
        print(
            "  VERDICT: REJECTED -- this run is NOT evidence of a win. Failed load-bearing checks: "
            + ", ".join(report["failure_reasons"])
        )
        return

    print(
        f"  VERDICT: ACCEPTED -- zstd faster every run={h['zstd_faster_every_run']}, wire smaller "
        f"every run={h['wire_smaller_every_run']}; best wall-clock speedup "
        f"{h['best_wallclock_speedup_display']}"
    )
    threshold = h["noise_threshold"]
    print(
        "  NOISE THRESHOLD: predicate min_margin_ns * denominator >= "
        "combined_observed_spread_ns * numerator; "
        f"numerator={threshold['multiplier_numerator']} "
        f"denominator={threshold['multiplier_denominator']} "
        f"min_margin_ns={threshold['min_margin_ns']} "
        f"combined_observed_spread_ns={threshold['combined_observed_spread_ns']} "
        f"scaled_margin={threshold['scaled_margin']} "
        f"scaled_required_spread={threshold['scaled_required_spread']} "
        f"passes={threshold['passes']}. The OBSERVED sign passes the predeclared 3x spread "
        "threshold; this does not guarantee a future re-sample."
    )
    print(
        "  PEER-VS-UPSTREAM: with the PEER link now shaped (both ends), the peer arm is no longer a "
        "loopback upper bound. Link zstd shrinks the peer's ~3.6x-raw WIRE-VOLUME disadvantage vs "
        f"the xz CDN by the measured COUNTED wire ratio {report['wire_ratio_display']} -- a "
        "WIRE-VOLUME ratio, NOT a time ratio. The near-parity is STRUCTURAL on WIRE VOLUME (payload "
        "is SYNTHETIC; the xz ratio is a stated corpus reference, not re-measured here) -- NOT a "
        "latency-parity claim. The two are NEVER equated: the measured WALL-CLOCK speedup "
        f"{h['best_wallclock_speedup_display']} is SMALLER than the wire ratio, by the shared "
        "per-fetch request round-trip both arms pay once."
    )


def measure(
    nar_bytes: int,
    delay_ms: int,
    rate_mbit: int,
    probe_bin: str,
    nar_seed: int,
    runs: int,
    out_path: str | None,
) -> int:
    if runs < 2:
        print(
            "MEASURE FAILURE: --runs must be at least 2 to alternate paired arm order",
            file=sys.stderr,
        )
        return 2
    if not os.path.exists(probe_bin):
        print(
            f"MEASURE FAILURE: probe binary not found at {probe_bin}\n"
            f"  build it: nix develop -c cargo build -p fabric-libp2p --example shaped_probe",
            file=sys.stderr,
        )
        return 2

    try:
        provenance = _measurement_provenance(probe_bin)
    except OSError as exc:
        print(f"MEASURE FAILURE: cannot identify probe binary: {exc}", file=sys.stderr)
        return 2

    print(
        f"# TASK-197 /nar/4 AC9: raw-vs-zstd over a BOTH-ends-shaped "
        f"peer link: {nar_bytes} byte compressible "
        f"nar, delay {delay_ms}ms, cap {rate_mbit}mbit, {runs} shaped run(s) (nar_seed={nar_seed})"
    )
    try:
        shaped_runs = [
            run_inner(
                True,
                nar_bytes,
                delay_ms,
                rate_mbit,
                probe_bin,
                nar_seed,
                _paired_arm_order(run_index),
            )
            for run_index in range(runs)
        ]
        unshaped = run_inner(
            False,
            nar_bytes,
            delay_ms,
            rate_mbit,
            probe_bin,
            nar_seed,
            _paired_arm_order(runs),
        )
    except subprocess.TimeoutExpired:
        print("MEASURE FAILURE: a run timed out (link/fetch hung)", file=sys.stderr)
        return 2
    except MeasureFailure as exc:
        print(f"MEASURE FAILURE: {exc}", file=sys.stderr)
        return 2

    try:
        provenance_after = _measurement_provenance(probe_bin)
    except OSError as exc:
        print(
            f"MEASURE FAILURE: cannot re-identify measurement inputs: {exc}",
            file=sys.stderr,
        )
        return 2
    stable_identity_fields = (
        "probe_binary",
        "probe_sha256",
        "harness_sha256",
        "inner_harness_sha256",
        "git_head",
        "git_worktree_dirty",
    )
    changed_fields = [
        field
        for field in stable_identity_fields
        if provenance_after[field] != provenance[field]
    ]
    if changed_fields:
        print(
            "MEASURE FAILURE: measurement identity changed while arms were running: "
            + ", ".join(changed_fields),
            file=sys.stderr,
        )
        return 2
    provenance["verified_unchanged_after_run"] = True

    report = finalize(
        shaped_runs, unshaped, delay_ms, rate_mbit, nar_bytes, nar_seed, runs
    )
    report["provenance"] = provenance
    _print_report(report)
    print()
    print(shaped_link.HONEST_LIMITS)

    if not report["accepted"]:
        # FAIL CLOSED: never write the affirmative evidence file when a guard tripped, and exit
        # non-zero so a caller/gate cannot mistake a rejected run for a passing measurement.
        print(
            "MEASURE RESULT: REJECTED -- failed load-bearing checks: "
            + ", ".join(report["failure_reasons"])
            + "; affirmative evidence NOT written",
            file=sys.stderr,
        )
        return 1

    if out_path:
        try:
            _write_new_evidence(out_path, report)
        except MeasureFailure as exc:
            print(f"MEASURE FAILURE: {exc}", file=sys.stderr)
            return 2
        print(f"\n  wrote {out_path}", file=sys.stderr)
    return 0


# --- self-test: prove the parse AND the render+exit bite by mutation (no netns) ----------------


def _good_fetch(
    codec: str,
    elapsed_ns: int,
    encoded: int,
    nar: int = 16 * 1024 * 1024,
    content: str = SYNTHETIC_CONTENT,
) -> str:
    selected = "raw" if codec == "raw" else "zstd"
    leaf_count = max(1, (nar + 65_535) // 65_536)
    proof = 64 * (leaf_count - 1)
    prefixes = 0 if selected == "raw" else 4 * leaf_count
    body = proof + prefixes + encoded + 4
    response = 10 + body
    exchange = 33 + response
    return (
        f"FETCH_DONE content={content} bytes={nar} expect={nar} elapsed_ns={elapsed_ns} "
        f"byte_identical=1 blake3_ok=1 request_protocol_bytes=33 response_header_bytes=10 "
        f"proof_bytes={proof} leaf_count={leaf_count} leaf_length_prefix_bytes={prefixes} "
        f"encoded_leaf_bytes={encoded} complete_marker_bytes=4 response_body_bytes={body} "
        f"response_protocol_bytes={response} exchange_protocol_bytes={exchange} "
        f"codec_requested={codec} selected_codec={selected} request_complete_ns=1000 "
        f"first_response_byte_ns=2000 authenticated_first_leaf_ns=3000 total_fetch_ns=4000\n"
    )


def _good_provider(
    codec: str, encoded: int, nar: int, content: str = SYNTHETIC_CONTENT
) -> str:
    leaf_count = max(1, (nar + 65_535) // 65_536)
    proof = 64 * (leaf_count - 1)
    prefixes = 0 if codec == "raw" else 4 * leaf_count
    body = proof + prefixes + encoded + 4
    response = 10 + body
    exchange = 33 + response
    return (
        f"PROVIDE_DONE content={content} selected_codec={codec} pass1_bytes={nar} "
        f"pass2_bytes={nar} proof_preparation_ns=10000 total_serve_ns=20000 "
        f"request_protocol_bytes=33 response_header_bytes=10 proof_bytes={proof} "
        f"leaf_count={leaf_count} leaf_length_prefix_bytes={prefixes} encoded_leaf_bytes={encoded} "
        f"complete_marker_bytes=4 response_body_bytes={body} response_protocol_bytes={response} "
        f"exchange_protocol_bytes={exchange}\n"
    )


def _good_provider_meta(
    nar: int,
    legacy_frame: int,
    content: str = SYNTHETIC_CONTENT,
    nar_seed: int = DEFAULT_NAR_SEED,
    payload_kind: str = PAYLOAD_KIND,
    payload_construction: str = PAYLOAD_CONSTRUCTION,
) -> str:
    return (
        f"PROVIDE_META content={content} raw_bytes={nar} nar_seed={nar_seed} "
        f"payload_kind={payload_kind} payload_construction={payload_construction} "
        f"legacy_single_frame_bytes={legacy_frame} "
        f"legacy_response_protocol_bytes={legacy_frame + 2}"
    )


def _good_run_text(
    raw_ns: int = 6_700_000_000,
    zstd_ns: int = 1_700_000_000,
    nar: int = 16 * 1024 * 1024,
    frame: int = 4 * 1024 * 1024,
    rtt_avg: str = "40.2",
    bulk_frame: int | None = None,
    arm_order: str = "raw-first",
    content: str = SYNTHETIC_CONTENT,
    nar_seed: int = DEFAULT_NAR_SEED,
    payload_kind: str = PAYLOAD_KIND,
    payload_construction: str = PAYLOAD_CONSTRUCTION,
    fetcher_identity_seed: int = FETCHER_IDENTITY_SEED,
) -> str:
    """A synthetic shaped-run capture. `frame` is the summed encoded size of v4's independently
    framed zstd leaves. `bulk_frame` is the explicit prior-v3 whole-NAR frame counterfactual; it
    defaults to the same convenient fixture value but is never required to equal v4."""
    if bulk_frame is None:
        bulk_frame = frame
    if arm_order not in {"raw-first", "zstd-first"}:
        raise ValueError(f"unknown synthetic arm order {arm_order!r}")
    raw_fetch = (
        f"ARM_START arm=raw fetcher_identity_seed={fetcher_identity_seed}\n"
        "=== XFER raw ===\n" + _good_fetch("raw", raw_ns, nar, nar, content)
    )
    zstd_fetch = (
        f"ARM_START arm=zstd fetcher_identity_seed={fetcher_identity_seed}\n"
        "=== XFER zstd ===\n" + _good_fetch("both", zstd_ns, frame, nar, content)
    )
    raw_provider = _good_provider("raw", nar, nar, content)
    zstd_provider = _good_provider("zstd", frame, nar, content)
    if arm_order == "raw-first":
        fetches = raw_fetch + zstd_fetch
        providers = raw_provider + zstd_provider
    else:
        fetches = zstd_fetch + raw_fetch
        providers = zstd_provider + raw_provider
    return (
        f"=== RTT probe (shape=yes) ===\n"
        f"rtt min/avg/max/mdev = {rtt_avg}/{rtt_avg}/{rtt_avg}/0.1 ms\n"
        f"PAYLOAD_CONFIG nar_seed={nar_seed} payload_kind={payload_kind} "
        f"payload_construction={payload_construction} raw_bytes={nar} "
        f"fetcher_identity_seed={fetcher_identity_seed}\n"
        f"{_good_provider_meta(nar, bulk_frame, content, nar_seed, payload_kind, payload_construction)}\n"
        f"ARM_ORDER order={arm_order}\n" + fetches + providers
    )


def _good_unshaped_text(
    nar: int = 16 * 1024 * 1024,
    frame: int = 4 * 1024 * 1024,
    arm_order: str = "raw-first",
    content: str = SYNTHETIC_CONTENT,
    nar_seed: int = DEFAULT_NAR_SEED,
    payload_kind: str = PAYLOAD_KIND,
    payload_construction: str = PAYLOAD_CONSTRUCTION,
    fetcher_identity_seed: int = FETCHER_IDENTITY_SEED,
) -> str:
    """A synthetic UNSHAPED negative control: near-zero RTT and a throughput far above the cap
    (raw ~56 MB/s), so the shaping oracle can tell the shaped runs apart from it."""
    return _good_run_text(
        raw_ns=300_000_000,
        zstd_ns=80_000_000,
        nar=nar,
        frame=frame,
        rtt_avg="0.05",
        arm_order=arm_order,
        content=content,
        nar_seed=nar_seed,
        payload_kind=payload_kind,
        payload_construction=payload_construction,
        fetcher_identity_seed=fetcher_identity_seed,
    )


def _render_and_exit(shaped_runs: list[dict], unshaped: dict) -> tuple[str, int]:
    """Drive the full finalize -> render -> exit path and capture BOTH the rendered text and the
    exit status the way `measure` would derive it (0 iff accepted). This is what the F2 self-test
    asserts on — the RENDERED OUTPUT and the EXIT STATUS, not merely internal booleans."""
    report = finalize(
        shaped_runs,
        unshaped,
        DEFAULT_DELAY_MS,
        DEFAULT_RATE_MBIT,
        DEFAULT_NAR_BYTES,
        DEFAULT_NAR_SEED,
        len(shaped_runs),
    )
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        _print_report(report)
    exit_code = 0 if report["accepted"] else 1
    return buf.getvalue(), exit_code


def self_test() -> int:
    failures: list[str] = []
    nar = 16 * 1024 * 1024
    frame = 4 * 1024 * 1024
    meta_line = _good_provider_meta(nar, frame)
    payload_line = (
        f"PAYLOAD_CONFIG nar_seed={DEFAULT_NAR_SEED} payload_kind={PAYLOAD_KIND} "
        f"payload_construction={PAYLOAD_CONSTRUCTION} raw_bytes={nar} "
        f"fetcher_identity_seed={FETCHER_IDENTITY_SEED}"
    )
    other_content = "blake3:" + ("cd" * 32)

    def _shaped_run(run_index: int, **overrides: object) -> dict:
        return parse_run(
            _good_run_text(arm_order=_paired_arm_order(run_index), **overrides)
        )

    # Baseline must parse and both arms verify.
    try:
        run = parse_run(_good_run_text())
        if run["arms"]["raw"]["codec_requested"] != "raw":
            failures.append("baseline raw arm mis-parsed")
        if run["arms"]["zstd"]["codec_requested"] != "both":
            failures.append("baseline zstd arm mis-parsed")
    except MeasureFailure as exc:
        failures.append(f"baseline run should PARSE but was rejected: {exc}")

    # parse mutations: each breaks exactly one invariant and MUST be caught.
    parse_mutations = {
        "fatal": "=== XFER ===\nFATAL provider-not-ready\n",
        "no-rtt": _good_run_text().replace(
            "rtt min/avg/max/mdev = 40.2/40.2/40.2/0.1 ms", ""
        ),
        "no-meta": _good_run_text().replace(meta_line, ""),
        "duplicate-meta": _good_run_text() + meta_line + "\n",
        "no-payload-config": _good_run_text().replace(payload_line + "\n", "", 1),
        "duplicate-payload-config": _good_run_text() + payload_line + "\n",
        "payload-config-extra-field": _good_run_text().replace(
            payload_line, payload_line + " unexpected=1", 1
        ),
        "provider-meta-seed-mismatch": _good_run_text().replace(
            f"PROVIDE_META content={SYNTHETIC_CONTENT} raw_bytes={nar} nar_seed={DEFAULT_NAR_SEED}",
            f"PROVIDE_META content={SYNTHETIC_CONTENT} raw_bytes={nar} nar_seed={DEFAULT_NAR_SEED + 1}",
            1,
        ),
        "no-arm-order": _good_run_text().replace("ARM_ORDER order=raw-first\n", "", 1),
        "duplicate-arm-order": _good_run_text() + "ARM_ORDER order=raw-first\n",
        "unknown-arm-order": _good_run_text().replace(
            "ARM_ORDER order=raw-first", "ARM_ORDER order=sideways", 1
        ),
        "arm-order-disagrees": _good_run_text().replace(
            "ARM_ORDER order=raw-first", "ARM_ORDER order=zstd-first", 1
        ),
        "zstd-fetcher-identity-drift": _good_run_text().replace(
            f"ARM_START arm=zstd fetcher_identity_seed={FETCHER_IDENTITY_SEED}",
            f"ARM_START arm=zstd fetcher_identity_seed={FETCHER_IDENTITY_SEED + 1}",
            1,
        ),
        "no-raw-arm": _good_run_text().replace(
            _good_fetch("raw", 6_700_000_000, nar, nar), "", 1
        ),
        "no-zstd-arm": _good_run_text().replace(
            _good_fetch("both", 1_700_000_000, frame, nar), "", 1
        ),
        "raw-truncated": _good_run_text().replace(
            f"content={SYNTHETIC_CONTENT} bytes={nar} expect={nar} elapsed_ns=6700000000",
            f"content={SYNTHETIC_CONTENT} bytes=1024 expect={nar} elapsed_ns=6700000000",
            1,
        ),
        "malformed-content": _good_run_text().replace(
            SYNTHETIC_CONTENT, "blake3:not-canonical"
        ),
        "not-byte-identical": _good_run_text().replace(
            "byte_identical=1", "byte_identical=0"
        ),
        "blake3-fail": _good_run_text().replace("blake3_ok=1", "blake3_ok=0"),
        "raw-encoded-not-narsize": _good_run_text().replace(
            f"encoded_leaf_bytes={nar} complete_marker_bytes=4",
            f"encoded_leaf_bytes={nar - 1} complete_marker_bytes=4",
            1,
        ),
        "proof-geometry": _good_run_text().replace(
            "proof_bytes=16320", "proof_bytes=16384", 1
        ),
        "unknown-selected-codec": _good_run_text().replace(
            "selected_codec=raw", "selected_codec=bogus", 1
        ),
        "unknown-requested-codec": _good_run_text().replace(
            "codec_requested=both", "codec_requested=bogus", 1
        ),
        "zero-legacy-counterfactual": _good_run_text().replace(
            f"legacy_single_frame_bytes={frame} legacy_response_protocol_bytes={frame + 2}",
            "legacy_single_frame_bytes=0 legacy_response_protocol_bytes=2",
            1,
        ),
        "zero-first-auth": _good_run_text().replace(
            "authenticated_first_leaf_ns=3000", "authenticated_first_leaf_ns=0", 1
        ),
        "missing-provider-event": _good_run_text().replace(
            _good_provider("raw", nar, nar), "", 1
        ),
        "duplicate-provider-event": _good_run_text() + _good_provider("raw", nar, nar),
        "duplicate-fetch-event": _good_run_text()
        + _good_fetch("raw", 6_700_000_000, nar, nar),
        "provider-pass1-mismatch": _good_run_text().replace(
            f"selected_codec=raw pass1_bytes={nar}",
            f"selected_codec=raw pass1_bytes={nar - 1}",
            1,
        ),
        "provider-wire-mismatch": _good_run_text().replace(
            _good_provider("raw", nar, nar),
            _good_provider("raw", nar, nar).replace(
                f"encoded_leaf_bytes={nar}", f"encoded_leaf_bytes={nar - 1}"
            ),
            1,
        ),
        "provider-zero-timing": _good_run_text().replace(
            "proof_preparation_ns=10000", "proof_preparation_ns=0", 1
        ),
        "provider-content-mismatch": _good_run_text().replace(
            f"PROVIDE_DONE content={SYNTHETIC_CONTENT} selected_codec=raw",
            f"PROVIDE_DONE content={other_content} selected_codec=raw",
            1,
        ),
    }
    for name, text in parse_mutations.items():
        try:
            parse_run(text)
            failures.append(
                f"parse mutation {name!r} should have been REJECTED but passed"
            )
        except MeasureFailure:
            pass

    # --- FAIL-CLOSED render+exit teeth: assert on the RENDERED OUTPUT + EXIT STATUS.
    good_unshaped = parse_run(
        _good_unshaped_text(arm_order=_paired_arm_order(DEFAULT_RUNS))
    )

    # CONTROL: a clean 3-run set is ACCEPTED, prints the win/parity conclusion, and exits 0.
    good_shaped = [_shaped_run(run_index) for run_index in range(3)]
    out, code = _render_and_exit(good_shaped, good_unshaped)
    if code != 0:
        failures.append("fail-closed control: a clean run should exit 0")
    if "VERDICT: ACCEPTED" not in out:
        failures.append(
            "fail-closed control: a clean run should render VERDICT: ACCEPTED"
        )
    accepted_noise_text = "OBSERVED sign passes the predeclared 3x spread threshold"
    if accepted_noise_text not in out:
        failures.append(
            "fail-closed control: a clean run should render the exact noise-threshold conclusion"
        )
    if "PEER-VS-UPSTREAM" not in out:
        failures.append(
            "fail-closed control: a clean run should render the parity conclusion"
        )

    def _bites(name: str, shaped_runs: list[dict], unshaped: dict) -> None:
        out, code = _render_and_exit(shaped_runs, unshaped)
        if code == 0:
            failures.append(f"F2 mutation {name!r}: should exit NON-ZERO but exited 0")
        if "VERDICT: ACCEPTED" in out:
            failures.append(
                f"F2 mutation {name!r}: rendered VERDICT: ACCEPTED (must be rejected)"
            )
        if "VERDICT: REJECTED" not in out:
            failures.append(f"F2 mutation {name!r}: did not render VERDICT: REJECTED")
        if accepted_noise_text in out:
            failures.append(
                f"F2 mutation {name!r}: still rendered the accepted noise-threshold conclusion"
            )
        if "PEER-VS-UPSTREAM" in out:
            failures.append(
                f"F2 mutation {name!r}: still rendered the parity conclusion"
            )

    # (1) slower zstd: raw/zstd elapsed swapped -> not a win.
    _bites(
        "slower-zstd",
        [
            _shaped_run(run_index, raw_ns=1_700_000_000, zstd_ns=6_700_000_000)
            for run_index in range(3)
        ],
        good_unshaped,
    )
    # (2) spread-swamped margin: zstd still faster every run, but its spread exceeds the margin.
    _bites(
        "swamped-margin",
        [
            _shaped_run(0, zstd_ns=1_700_000_000),
            _shaped_run(1, zstd_ns=6_600_000_000),
        ],
        good_unshaped,
    )
    # (3) shaping removed: the 'control' is as slow/shaped as the shaped runs -> not distinguishable.
    _bites(
        "shaping-removed",
        [_shaped_run(run_index) for run_index in range(3)],
        _shaped_run(3),  # control == shaped: oracle must reject every run's gate
    )
    # (4) a headline run NOT shape-gated: one run's raw arm collapses far below the cap (F5) — it
    #     must not slip into the minimum; its failed gate rejects the whole measurement.
    _bites(
        "run-not-shape-gated",
        [
            _shaped_run(0),
            _shaped_run(1),
            _shaped_run(2, raw_ns=60_000_000_000, zstd_ns=1_700_000_000),
        ],
        good_unshaped,
    )
    # (5) legacy counterfactual drift: the deterministic prior single-frame byte count changes in
    #     one run, so no single comparison pair is established.
    _bites(
        "legacy-counterfactual-inconsistent",
        [
            _shaped_run(0),
            _shaped_run(1, bulk_frame=1000),
            _shaped_run(2),
        ],
        good_unshaped,
    )
    # (6) wire bytes inconsistent across runs: the counted bodies drift, so the headline ratio is not
    #     well-defined.
    _bites(
        "wire-bytes-inconsistent",
        [
            _shaped_run(0, frame=frame),
            _shaped_run(1, frame=frame + 4096),
            _shaped_run(2, frame=frame),
        ],
        good_unshaped,
    )

    # (7) every run using the same first arm leaves warm-up/first-position bias uncontrolled.
    _bites(
        "non-alternating-arm-order",
        [parse_run(_good_run_text(arm_order="raw-first")) for _ in range(3)],
        good_unshaped,
    )

    def _contract_bites(
        name: str, shaped_runs: list[dict], unshaped: dict, expected_failed_flag: str
    ) -> None:
        report = finalize(
            shaped_runs,
            unshaped,
            DEFAULT_DELAY_MS,
            DEFAULT_RATE_MBIT,
            DEFAULT_NAR_BYTES,
            DEFAULT_NAR_SEED,
            len(shaped_runs),
        )
        if report["load_bearing_flags"].get(expected_failed_flag) is not False:
            failures.append(
                f"contract mutation {name!r} did not fail {expected_failed_flag}"
            )
        _bites(name, shaped_runs, unshaped)

    # Canonical payload contract teeth across shaped samples and the negative control.
    _contract_bites(
        "shaped-content-drift",
        [_shaped_run(0), _shaped_run(1, content=other_content), _shaped_run(2)],
        good_unshaped,
        "canonical_content_consistent",
    )
    _contract_bites(
        "control-content-drift",
        good_shaped,
        parse_run(
            _good_unshaped_text(
                arm_order=_paired_arm_order(DEFAULT_RUNS), content=other_content
            )
        ),
        "canonical_content_consistent",
    )
    _contract_bites(
        "shaped-cli-size-drift",
        [_shaped_run(0), _shaped_run(1, nar=nar + 65_536), _shaped_run(2)],
        good_unshaped,
        "cli_nar_size_consistent",
    )
    _contract_bites(
        "control-cli-size-drift",
        good_shaped,
        parse_run(
            _good_unshaped_text(
                nar=nar + 65_536, arm_order=_paired_arm_order(DEFAULT_RUNS)
            )
        ),
        "cli_nar_size_consistent",
    )
    _contract_bites(
        "shaped-nar-seed-drift",
        [_shaped_run(0), _shaped_run(1, nar_seed=DEFAULT_NAR_SEED + 1), _shaped_run(2)],
        good_unshaped,
        "payload_metadata_consistent",
    )
    _contract_bites(
        "control-payload-construction-drift",
        good_shaped,
        parse_run(
            _good_unshaped_text(
                arm_order=_paired_arm_order(DEFAULT_RUNS),
                payload_construction="different-construction-v1",
            )
        ),
        "payload_metadata_consistent",
    )

    # The exact predeclared rational threshold: one nanosecond below rejects, equality and one
    # nanosecond above pass. The equality case also traverses the complete render/exit path.
    equality_runs = [
        _shaped_run(0, raw_ns=6_700_000_000, zstd_ns=6_400_000_000),
        _shaped_run(1, raw_ns=6_800_000_000, zstd_ns=6_400_000_000),
        _shaped_run(2, raw_ns=6_700_000_000, zstd_ns=6_400_000_000),
    ]
    equality_report = finalize(
        equality_runs,
        good_unshaped,
        DEFAULT_DELAY_MS,
        DEFAULT_RATE_MBIT,
        nar,
        DEFAULT_NAR_SEED,
        len(equality_runs),
    )
    equality_threshold = equality_report["headline"]["noise_threshold"]
    if not equality_report["accepted"] or not equality_threshold["passes"]:
        failures.append("noise threshold equality boundary must be accepted")
    if (
        equality_threshold["scaled_margin"]
        != equality_threshold["scaled_required_spread"]
    ):
        failures.append(
            "noise threshold equality fixture did not land exactly on the boundary"
        )
    _bites(
        "noise-threshold-one-nanosecond-below",
        [
            _shaped_run(0, raw_ns=6_700_000_000, zstd_ns=6_400_000_001),
            _shaped_run(1, raw_ns=6_800_000_000, zstd_ns=6_400_000_001),
            _shaped_run(2, raw_ns=6_700_000_000, zstd_ns=6_400_000_001),
        ],
        good_unshaped,
    )
    if not _noise_threshold(300_000_001, 100_000_000)["passes"]:
        failures.append("noise threshold one-nanosecond-above boundary must pass")

    # --- PER-RUN mutation matrix: a corruption of a SINGLE run — ANY of
    # the three — must bite. The prior self-test only mutated EVERY run simultaneously, so a
    # run-2-only corruption slipped past checks that were keyed off run 0 (codex reproduced
    # `bulk_frame=1000` on run 2 alone -> VERDICT: ACCEPTED, PEER-VS-UPSTREAM, exit 0, evidence
    # written). Here each species corrupts EXACTLY ONE run (at each index 0,1,2) and must render
    # REJECTED + exit non-zero. `bulk-frame` is the exact codex escape; the others prove the other
    # per-run load-bearing checks also bite an isolated run.
    def _three_with(idx: int, mutation: dict[str, int]) -> list[dict]:
        return [_shaped_run(i, **(mutation if i == idx else {})) for i in range(3)]

    single_run_species = {
        # Legacy one-frame counterfactual changes on ONE deterministic run.
        "legacy-frame": {"bulk_frame": 1000},
        # ONE run ships a different exact v4 response -> wire_bytes_consistent fails.
        "v4-response-drift": {"frame": frame + 4096},
        # ONE run's zstd is slower than its raw -> zstd_faster_every_run fails.
        "slower-zstd": {
            "raw_ns": 1_700_000_000,
            "zstd_ns": 6_700_000_000,
        },
        # ONE run's raw arm collapses far below the cap -> its shape gate fails (all_runs_shape_gated).
        "shape-collapse": {
            "raw_ns": 60_000_000_000,
            "zstd_ns": 1_700_000_000,
        },
    }
    for idx in range(3):
        for species, mutant in single_run_species.items():
            _bites(f"run{idx}-only:{species}", _three_with(idx, mutant), good_unshaped)

    # shaping oracle unit teeth (via shaped_link, direct arms): an honest pair passes; a
    # shaping-removed arm is rejected.
    good_shaped_arm = _arm_for_oracle(_ms_str_to_ns("40.2"), nar, 6_700_000_000)
    good_control_arm = _arm_for_oracle(_ms_str_to_ns("0.05"), nar, 60_000_000)
    try:
        shaped_link.assert_shaping(
            good_shaped_arm, good_control_arm, DEFAULT_DELAY_MS, DEFAULT_RATE_MBIT
        )
    except shaped_link.ShapingViolation as exc:
        failures.append(f"shaping oracle rejected an honest shaped/control pair: {exc}")
    removed = _arm_for_oracle(
        _ms_str_to_ns("0.05"), nar, 60_000_000
    )  # 'shaped' == control
    try:
        shaped_link.assert_shaping(
            removed, good_control_arm, DEFAULT_DELAY_MS, DEFAULT_RATE_MBIT
        )
        failures.append(
            "shaping oracle: a shaping-removed arm should be REJECTED but passed"
        )
    except shaped_link.ShapingViolation:
        pass

    # integer-reporting checks (no-float rule).
    if not isinstance(throughput_bytes_per_s(nar, 6_700_000_000), int):
        failures.append("throughput must be an integer bytes/sec")
    if _ms_str_to_ns("40.2") != 40_200_000:
        failures.append("_ms_str_to_ns wrong for 40.2 ms")

    # Final JSON must retain enough exact evidence to audit every actor, equation, parity check,
    # subprocess stream, and transcript independently of this parser.
    audit_report = json.loads(
        json.dumps(
            finalize(
                good_shaped,
                good_unshaped,
                DEFAULT_DELAY_MS,
                DEFAULT_RATE_MBIT,
                nar,
                DEFAULT_NAR_SEED,
                len(good_shaped),
            )
        )
    )
    if audit_report["wire_fields_schema"] != list(_WIRE_FIELDS):
        failures.append("final JSON lost the exact /nar/4 wire field schema")
    audit_observations = [
        *audit_report["observations"]["shaped"],
        audit_report["observations"]["unshaped_control"],
    ]
    if len(audit_observations) != len(good_shaped) + 1:
        failures.append("final JSON lost a shaped run or the unshaped control")
    for observation in audit_observations:
        transcript = observation["parser_transcript"]
        if _text_sha256(transcript["text"]) != transcript["sha256"]:
            failures.append(
                f"{observation['label']} transcript SHA-256 is not reproducible"
            )
        capture = observation["process_capture"]
        if capture != _process_capture(
            capture["stdout"], capture["stderr"], capture["return_code"]
        ):
            failures.append(
                f"{observation['label']} process capture SHA-256 is not reproducible"
            )
        if capture["stdout"] + capture["stderr"] != transcript["text"]:
            failures.append(f"{observation['label']} process capture lost parser input")
        for codec in ("raw", "zstd"):
            arm = observation["arms"][codec]
            for actor_name in ("fetch", "provider"):
                actor = arm[actor_name]
                if set(actor["wire"]) != set(_WIRE_FIELDS):
                    failures.append(
                        f"{observation['label']} {codec} {actor_name} lost exact wire fields"
                    )
                if not actor["wire_equations"]["all_hold"]:
                    failures.append(
                        f"{observation['label']} {codec} {actor_name} wire equations do not hold"
                    )
                if "content" not in actor["metadata"]:
                    failures.append(
                        f"{observation['label']} {codec} {actor_name} lost content identity"
                    )
            if not arm["provider_fetch_parity"]["all_wire_fields_equal"]:
                failures.append(
                    f"{observation['label']} {codec} provider/fetch wire parity was lost"
                )
    if audit_report["content_digest"] != SYNTHETIC_CONTENT:
        failures.append("final JSON lost the canonical content digest")

    tampered_transcript_runs = json.loads(json.dumps(good_shaped))
    tampered_transcript_runs[1]["combined_transcript_sha256"] = "0" * 64
    _contract_bites(
        "final-transcript-sha-drift",
        tampered_transcript_runs,
        good_unshaped,
        "audit_evidence_consistent",
    )
    tampered_wire_runs = json.loads(json.dumps(good_shaped))
    tampered_wire_runs[1]["arms"]["zstd"]["response_body_bytes"] += 1
    _contract_bites(
        "final-wire-equation-drift",
        tampered_wire_runs,
        good_unshaped,
        "audit_evidence_consistent",
    )

    # Publication policy: clean-commit/probe bound and SHA-scoped, with atomic no-clobber
    # destination creation. A successful return has synced the containing directory.
    evidence_report = finalize(
        good_shaped,
        good_unshaped,
        DEFAULT_DELAY_MS,
        DEFAULT_RATE_MBIT,
        nar,
        DEFAULT_NAR_SEED,
        len(good_shaped),
    )
    fake_git_head = "a" * 40
    evidence_report["provenance"] = {
        "harness_origin": "TASK-197 self-test",
        "wire_revision": "TASK-197 /nar/4 self-test",
        "probe_binary": "/synthetic/shaped_probe",
        "probe_sha256": "b" * 64,
        "harness_sha256": "c" * 64,
        "inner_harness_sha256": "d" * 64,
        "git_head": fake_git_head,
        "git_worktree_dirty": False,
        "verified_unchanged_after_run": True,
    }
    with tempfile.TemporaryDirectory(prefix="task197-evidence-selftest-") as tmp:
        evidence_root = os.path.join(tmp, "evidence", "task-197")
        evidence_path = os.path.join(
            evidence_root, fake_git_head[:12], "measurement.json"
        )
        try:
            _write_new_evidence(
                evidence_path, evidence_report, evidence_root=evidence_root
            )
            with open(evidence_path, encoding="utf-8") as published:
                published_report = json.load(published)
            if published_report.get("provenance") != evidence_report["provenance"]:
                failures.append("published evidence lost its exact provenance")
        except (MeasureFailure, OSError, json.JSONDecodeError) as exc:
            failures.append(f"first durable evidence publication failed: {exc}")

        changed_report = json.loads(json.dumps(evidence_report))
        changed_report["nar_seed"] = DEFAULT_NAR_SEED + 1
        try:
            _write_new_evidence(
                evidence_path, changed_report, evidence_root=evidence_root
            )
            failures.append(
                "durable evidence publication overwrote an existing artifact"
            )
        except MeasureFailure:
            pass
        try:
            with open(evidence_path, encoding="utf-8") as published:
                after_collision = json.load(published)
            if after_collision.get("nar_seed") != DEFAULT_NAR_SEED:
                failures.append("existing evidence changed after overwrite rejection")
        except (OSError, json.JSONDecodeError) as exc:
            failures.append(f"cannot re-read evidence after overwrite rejection: {exc}")

        dirty_report = json.loads(json.dumps(evidence_report))
        dirty_report["provenance"]["git_worktree_dirty"] = True
        try:
            _write_new_evidence(
                os.path.join(evidence_root, fake_git_head[:12], "dirty.json"),
                dirty_report,
                evidence_root=evidence_root,
            )
            failures.append("dirty-worktree evidence should have been rejected")
        except MeasureFailure:
            pass

        unverified_report = json.loads(json.dumps(evidence_report))
        unverified_report["provenance"]["verified_unchanged_after_run"] = False
        try:
            _write_new_evidence(
                os.path.join(evidence_root, fake_git_head[:12], "unverified.json"),
                unverified_report,
                evidence_root=evidence_root,
            )
            failures.append(
                "evidence not re-verified after all arms should be rejected"
            )
        except MeasureFailure:
            pass

        try:
            _write_new_evidence(
                os.path.join(evidence_root, "wrong-sha", "measurement.json"),
                evidence_report,
                evidence_root=evidence_root,
            )
            failures.append(
                "evidence path not bound to git_head should have been rejected"
            )
        except MeasureFailure:
            pass

    if failures:
        for f in failures:
            print(f"SELF-TEST FAIL: {f}", file=sys.stderr)
        return 1
    print(
        f"SELF-TEST OK: baseline parsed; {len(parse_mutations)} parse mutations bitten (including duplicate fetch and provider event "
        "missing/duplicate/pass-count/wire/timing/content failures); fail-closed render+exit teeth "
        "bite on slower-zstd, swamped-margin, shaping-removed, run-not-shape-gated, "
        "legacy-counterfactual-inconsistent, wire-bytes-inconsistent, and non-alternating order; "
        "PER-RUN matrix bites a "
        "SINGLE-run corruption (legacy-frame, v4-response-drift, slower-zstd, shape-collapse) "
        "at EACH run index 0/1/2 "
        "(each: no VERDICT: ACCEPTED, VERDICT: REJECTED rendered, exit non-zero); shaping oracle "
        "bites a removed shaper; integer reporting checked; clean-provenance publication uses "
        "SHA-scoped atomic no-clobber destination creation"
    )
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="TASK-197 /nar/4 live two-ends-shaped measurement"
    )
    ap.add_argument(
        "--self-test",
        action="store_true",
        help="prove the parse + fail-closed render/exit + shaping oracle bite by mutation "
        "(hermetic, no netns)",
    )
    ap.add_argument("--nar-bytes", type=int, default=DEFAULT_NAR_BYTES)
    ap.add_argument("--delay-ms", type=int, default=DEFAULT_DELAY_MS)
    ap.add_argument("--rate-mbit", type=int, default=DEFAULT_RATE_MBIT)
    ap.add_argument("--nar-seed", type=int, default=DEFAULT_NAR_SEED)
    ap.add_argument("--runs", type=int, default=DEFAULT_RUNS)
    ap.add_argument("--probe-bin", default=DEFAULT_BIN)
    ap.add_argument(
        "--out",
        default=None,
        help="publish new evidence below evidence/task-197/<git-sha-prefix>/; refuses dirty "
        "worktrees and existing files",
    )
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    return measure(
        args.nar_bytes,
        args.delay_ms,
        args.rate_mbit,
        args.probe_bin,
        args.nar_seed,
        args.runs,
        args.out,
    )


if __name__ == "__main__":
    sys.exit(main())
