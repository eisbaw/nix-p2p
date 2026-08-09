#!/usr/bin/env python3
"""`just profile` (task-42): the owner-goal profiling instrument for the p2p testbed.

Answers, with numbers and with units: what does a peer COST (RAM, disk, fds),
how fast is a peer-served build (latency, throughput), and how much does it save
against the upstream cache (egress, speedup)? Two arms, deliberately different in
kind:

  SWARM axis (FITTED)  - a real swarm of n+1 daemon PROCESSES in one pod: node-a
      plus n independently-seeded iroh providers. n is swept over a grid with
      >= `scalefit.MIN_POINTS` distinct values, so the peer axis has REAL points;
      two nodes cannot discriminate O(n) from O(n log n) and nothing here is
      extrapolated from a pair. `scripts/scalefit.py` fits the family and
      extrapolates to 10/100/1000 with intervals - all MODEL OUTPUT.

  SPEEDUP arm (NOT FITTED) - peers-ON vs peers-OFF over the SAME scripted
      workload, scored by the FROZEN counting rule (`net-upstream-egress-v2`,
      `scripts/MEASUREMENT_COUNTING_RULE.md`, executed by `measure.classify_run`).
      A peer hit is a valid 0-egress crossing there; that is the speedup
      yardstick and this module does not invent a second one.

      Run under TWO NAMED UPSTREAM CONDITIONS (task-63), because "the speedup"
      is not a number until you say what the peer path was raced against:
        * `loopback_control` - the in-pod testproxy at ~0 RTT, measured at
          ~980 MB/s at the cache boundary.
          A CONTROL, not a user's cache: it isolates the peer transport's own
          cost (TASK-64) by removing the link from the comparison.
        * `wan_shaped` - the same testproxy carrying an injected per-request RTT
          and a NAR egress cap DERIVED from real-upstream measurement (task-35
          against cache.nixos.org, plus direct probes of it). This is the arm
          that answers the owner goal, which names a speedup over
          cache.nixos.org.
      The shaping is ASSERTED, never assumed: `probe_upstream_link` times the
      proxy HOST-SIDE, outside the shaper, unshaped and then shaped over the
      same channel, and `shaping_violations` fails the run when the injected
      RTT is not recovered, the cap is not achieved, OR the unshaped control is
      not fast enough to tell the two apart. Every speedup key carries its
      condition as a suffix and `speedup_qualifier_violations` (plus
      `human_summary_violations`, over the printed text) refuses a report that
      states a bare one.

WHY A SWARM OF PROCESSES. A peer IS one daemon process - it does not fork per
client. The heavy, host-bound component is the CLIENT (a whole `podman run` of
real nix with its own store), which is why task-18 swept clients against ONE
daemon. Here the axis is the thing task-18 could not reach: how much does a HOST
pay for n peers, and does a single peer's cost grow with n?

UNITS ARE MECHANICAL, NOT EDITORIAL (the trap that has recurred three times in
this project). NarSize is the UNCOMPRESSED, SIGNED NAR length; FileSize is the
COMPRESSED transport length; they are different units and a ratio across them is
a lie. Every key in this report ending in `_bytes` MUST end in one of:

    _bytes_ram              resident memory (VmHWM / VmRSS)
    _bytes_ondisk           bytes in files on a filesystem
    _bytes_uncompressed_nar NarSize units - `nix-store --dump` output length
    _bytes_compressed_wire  FileSize units - what crosses the cache boundary

`unit_violations()` walks the assembled report and FAILS the run on any other
`*_bytes` key, and the self-test proves it by mutation. On top of that the
speedup arm uses ONLY `compression: none` fixture attrs and ASSERTS
`file_size == nar_size` from the manifest, so for that arm the two units
coincide BY CHECKED PRECONDITION rather than by hope - which is what makes a
peer-served-bytes vs upstream-egress-bytes comparison legitimate at all.

WHAT IS MEASURED, precisely (this instrument's counting rule):
  * RSS: `VmHWM` (kernel peak) is the FITTED quantity, `VmRSS` point samples
    reported beside it, both read HOST-SIDE from /proc of the container init pid.
  * FDS: max entry count of /proc/<pid>/fd over the sampled ticks.
  * DISK: a host-side walk of the directory bind-mounted as each daemon's
    `--narinfo-cache-dir`. Host-side because `du`/`find`/`grep` are NOT in the
    e2e image - an in-container probe returns rc=127 and passes unconditionally,
    which is the dead-oracle trap this repo has shipped three times.
    FINDING, not an omission: the iroh blob store is `MemStore`
    (`daemon/src/transport_iroh.rs`), so held content costs RAM, not disk. The
    on-disk figure is therefore small and the RAM figure carries the content -
    see `disk_finding` in the report. (TASK-54 owns bounding the footprint.)
  * LATENCY: the IN-CONTAINER `nix-store --realise` duration (REALISE_NS). The
    host-side `podman run` wall clock is reported but NEVER fitted: it carries
    container create/start/teardown, which itself scales with the swarm, so
    fitting it would recover podman's law instead of the product's.
  * THROUGHPUT: transferred bytes / in-container realise seconds, per arm, in
    that arm's own unit.

S9 BITE (AC#2). The fitter's ability to tell a resource law apart from another
one is not asserted, it is MEASURED: `class_recovery_study()` runs a Monte-Carlo
over generators of each KNOWN class on the REAL swept grid and reports the
recovery rate per class. The self-test gates on those RATES (a single seed that
happens to pass is a coin flip, not an oracle) and specifically requires that a
known-SUPERLINEAR generator is never classified linear. `wrong_model_failures()`
defines wrong-model as "selected class outside the generated class's family" and
a non-empty list FAILS the self-test.

HONEST LIMIT OF THAT BITE, measured here rather than discovered later: on the
default grid O(n^2) is separated from linear at every noise level tried, but
O(n log n) is NOT reliably separated once relative noise reaches ~5%. The study
block reports the rate, and the real sweep's OBSERVED replicate spread is
reported next to it, so a reader can see whether the real data sits inside the
regime where the bite is proven.

`--self-test` runs all the pure logic (unit gate, report assembly, the S9
recovery study, disk walking, arm scoring) with NO containers and is wired into
the FAST `just test` tier.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import random
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.request
import zlib
from dataclasses import dataclass
from pathlib import Path

import e2e_harness as e2e
import fixturelib as fx
import scalefit

# Reuse, do not reimplement. `scale_sweep` owns the /proc sampling, the
# high-water aggregation, the measured-concurrency machinery and the sweep-point
# validity rules; a second copy of any of them would be a second definition of
# "peak RSS" whose first divergence would be invisible. `measure` owns the frozen
# egress counting rule. Both are import-clean (no side effects at import).
import scale_sweep as ss

# task-65's SIZE and CONCURRENCY axes. Its own module because this one is already
# 4.5k lines and because the two arms share nothing but the Pod seam; it is driven
# from `main` and folded into the report here, so `just profile` grows the axis
# without this file growing a second sweep.
import sizeaxis as sz
from measure import BASELINE_MIN_VALID_RUNS, classify_run, percentile, stat_block

# ---- frozen constants (this instrument's counting rule) ---------------------

REPORT_VERSION = 1
PROFILE_RULE_VERSION = "p2p-profile-v1"

# The peer-count grid. FIVE distinct n, exactly `scalefit.MIN_POINTS`, spanning a
# 16x range so a growth class has room to show itself; TESTING.md S5 names 1..30
# as the target range and `--swarm` raises the top end on a bigger host. Do NOT
# shrink below 5 valid points - the fitter refuses to fit, by design.
DEFAULT_SWARM_SIZES = (1, 2, 4, 8, 16)

# Replicates per swarm point, fed to the fitter as SEPARATE observations at the
# same n (never averaged), for exactly task-18's reason: with one draw per n the
# selected growth class moved between consecutive sweeps. 3 is the default there
# too; keeping them lets the residual variance absorb run-to-run noise instead of
# hiding it behind a mean.
DEFAULT_REPEATS = 3

# Runs per arm in the speedup/throughput arm. 10 is
# `measure.BASELINE_MIN_VALID_RUNS`, the frozen counting rule's floor for an arm
# to be `usable`; below it the arm is reported as a dev smoke, not a baseline.
DEFAULT_SPEEDUP_RUNS = BASELINE_MIN_VALID_RUNS

# Swarm-axis workload: SMALL attrs only. Every holder seeds every NAR into its
# in-RAM blob store, so a 110 MiB payload at n=16 would be ~1.8 GiB of held
# content and the axis would measure the host running out of memory. The swarm
# axis is about the BASE per-peer cost as the swarm grows; the cost of HELD
# CONTENT is what the speedup arm's `big` payload exposes.
SWARM_ATTRS = ("lib",)

# Speedup/throughput workload. Both attrs are `compression: none`, which is what
# makes wire bytes and NarSize the same number - ASSERTED against the manifest in
# `assert_unit_coincidence`, not assumed. `big` is 110 MiB: a real transfer, long
# enough for a throughput figure to mean something and bursty enough to finally
# separate VmHWM from point-sampled VmRSS (task-18 left that distinction
# unexercised because its workload grew RSS monotonically).
SPEEDUP_ATTRS = ("lib", "big")

# ---- the upstream condition (task-63) ---------------------------------------
#
# The speedup arm used to have ONE upstream: the in-pod testproxy on loopback,
# ~0 RTT and ~1 GB/s. No user owns that machine, and the owner goal names
# "speed up over cache.nixos.org". Against a fake upstream that fast the peer
# path measured 3.5x SLOWER, and every threshold fitted to that number would be
# fitted to an artifact. So the arm now runs under TWO named upstream
# conditions and the report may never state a speedup without saying which.
#
# `loopback_control` is NOT deleted: a zero-latency upstream is the useful
# control that isolates the peer transport's own cost (TASK-64).
LOOPBACK_CONTROL = "loopback_control"
WAN_SHAPED = "wan_shaped"
UPSTREAM_CONDITIONS = (LOOPBACK_CONTROL, WAN_SHAPED)

# Every speedup RATIO key must end in one of these, so a bare "speedup: 0.283"
# is not spellable. Mechanical, like the byte units above and for the same
# reason: the qualifier that lives only in a prose caveat is the qualifier that
# gets dropped when the number is quoted.
CONDITION_SUFFIXES = tuple(f"_{condition}" for condition in UPSTREAM_CONDITIONS)

# --- the WAN shaping parameters, DERIVED (see the task-63 notes) -------------
#
# RTT. TASK-35 measured the real thing against cache.nixos.org and TESTING.md
# ("Real-upstream gap (task-35)") records: steady-state RTT 50-110 ms to a
# Nordic Fastly edge PoP, and a head-of-closure gap - which is ~one round trip,
# un-prefetchable - of min 41 ms (`hello`) / 182 ms (`curl`). Direct probes from
# THIS host on 2026-08-09 (curl `time_connect`, 5 samples) measured one TCP
# round trip at 27, 28, 31, 77, 78 ms, and warm per-request TTFB-minus-connect
# at 27-31 ms. 50 ms is the BOTTOM of the task-35 band and above this host's
# median - i.e. deliberately at the upstream-FAVOURABLE end of the measured
# evidence, so the WAN arm understates real-world latency.
#
# The KNOB VALUE is upstream-favourable; the MODEL is not uniformly so. The
# delay is charged per REQUEST, and a real client on a reused keep-alive
# connection does not pay a fresh round trip for every one - that part is
# upstream-UNfavourable. Measured cost of it here: ~5 shaped requests x 50 ms =
# ~0.25 s out of a 5.92 s peers-off realise, about 4%. Stated rather than
# waved at, because "any peer advantage this shows is a lower bound" would be an
# overclaim while a bias of unknown sign is in the model.
WAN_RTT_MS = 50

# BANDWIDTH, in bytes_compressed_wire per second - the bytes actually on the
# wire, which is what the testproxy's mode-8 throttle paces. NOT NarSize: a cap
# applied to compressed bytes and reported against uncompressed NAR bytes is
# exactly the unit confusion this file gates against. (For the speedup arm the
# two coincide by CHECKED PRECONDITION - `assert_unit_coincidence` - because its
# payloads are `compression: none`; that coincidence is what makes the cap
# quotable in either unit for THIS workload and no other.)
#
# Derived two ways, and the larger (upstream-favourable) one taken:
#   * directly measured from this host, 2026-08-09: a single-stream HTTPS GET of
#     a real 56 616 908 B `.nar.zst` from cache.nixos.org sustained 21.4 MB/s
#     (2.65 s); a 2.5 MB NAR sustained 8.1-8.7 MB/s (slow-start dominated, so
#     the 56 MB figure is the sustained one);
#   * implied by TASK-35's own numbers: the tail gap is (narinfo phase + the NAR
#     queue ahead of it), so closure-NAR-bytes / max gap_first bounds the
#     aggregate rate from below - 11 MiB / 1.127 s ~ 9.8 MB/s (`hello`),
#     21 MiB / 3.082 s ~ 6.8 MB/s (`curl`).
# 20 MiB/s = 20 971 520 B/s is within 2% of this host's sustained single-stream
# rate and 2-3x what task-35's tail gaps imply, so the shaped upstream is faster
# than the distribution suggests. Same discipline as the RTT: err toward the
# upstream. NOT a proof that the arm is a lower bound overall - see
# `shaping_fidelity_note`, which names the one bias running the other way.
WAN_BANDWIDTH_BYTES_COMPRESSED_WIRE_PER_S = 20 * 1024**2

# The shaping probe's assertion bands. The probe times requests HOST-SIDE
# through the published proxy port - outside the shaper - unshaped and then
# shaped, through the same channel, so the channel's own overhead cancels.
#
# Latency: the recovered delta (shaped median - unshaped median) must land in
# [0.8, 1.6] x the injected RTT. The floor catches a shaper that did not fire;
# the ceiling catches one firing more than once per request (which would mean
# the arm carries an RTT nobody asked for).
SHAPING_RTT_DELTA_BAND = (0.8, 1.6)
# Bandwidth: the achieved rate must land in [0.70, 1.10] x the cap. The pacing
# sleep runs AFTER each 64 KiB chunk, so overshoot above the cap is structurally
# impossible beyond one chunk; the floor absorbs sleep-granularity overshoot
# (~1758 sleeps for a 110 MiB payload) plus the per-request RTT.
SHAPING_RATE_BAND = (0.70, 1.10)
# THE ANTI-VACUITY CHECK. A probe whose UNSHAPED control is already as slow as
# the shaping cannot tell shaped from unshaped, and would confirm any shaping
# whatsoever - the vacuous-oracle shape this project has been burned by three
# times. So the unshaped control must be at least this much faster, or the
# probe reports a NAMED failure rather than a pass.
#
# HEADROOM, and why it is also RECORDED. Measured margins on this host are ~67x
# the cap and ~1% of the injected RTT, so these floors only fire on a
# catastrophically degraded channel. A host whose port forwarding drifted to 5x
# would still pass - silently - so the probe records
# `control_headroom_rate_x_cap` and `control_headroom_latency_fraction_of_rtt`,
# which makes the drift visible while it is still passing.
SHAPING_CONTROL_MIN_RATE_FACTOR = 3.0
# Applied to TWO physically different quantities: a small cached narinfo GET,
# and the NAR's time to first byte (which additionally carries the cache open
# and one 64 KiB read, ~3 ms at the cap). One ceiling covers both because it is
# set at half the INJECTED RTT - 25 ms, against measured controls of 0.6 ms and
# 3.1 ms - not at either quantity's own scale.
SHAPING_CONTROL_MAX_LATENCY_FRACTION = 0.5
# Narinfo GETs per latency sample set. Small and cached, so the body time is
# negligible against a 50 ms injected RTT; the median of 7 shrugs off a single
# scheduler hiccup without making the probe expensive.
SHAPING_LATENCY_SAMPLES = 7

# Refuse to start below this much free disk. The host runs at ~95% used and this
# instrument spins swarms that each hold a blob store plus a per-pod seed copy of
# the 110 MiB payload; a mid-run ENOSPC would corrupt a sweep point into looking
# like a product failure. TASK-54 owns bounding the footprint properly - this is
# the guard that keeps the harness from being the thing that fills the disk.
MIN_FREE_DISK_BYTES = 8 * 1024**3

# The recognised byte units. A `*_bytes` key that ends in none of these is a
# violation: it would let NarSize and FileSize sit in one report under
# indistinguishable names, which is precisely how the three previous unit
# confusions in this project happened.
UNIT_SUFFIXES = (
    "_bytes_ram",
    "_bytes_ondisk",
    "_bytes_uncompressed_nar",
    "_bytes_compressed_wire",
)

# S9 study parameters. 5 classes x 3 noise levels x 120 replicates = 1800 fits,
# MEASURED at 4.0-4.8 s on this host (ten samples). That is the honest cost of
# putting this in the FAST tier; 120 replicates is what gives the rate floors
# below their resolution, and the seeds are stable (see `stable_seed`) so the
# rates are facts rather than a per-run draw.
STUDY_REPLICATES = 120
STUDY_NOISE_LEVELS = (0.01, 0.02, 0.05)

# Rate floors the self-test GATES on, at STUDY_GATE_NOISE. Because `stable_seed`
# makes the study deterministic, the measured rates below are FACTS, not draws -
# so a thin margin is safe: the number cannot move without a code change, and
# moving it is exactly what these floors exist to catch.
STUDY_GATE_NOISE = 0.02
GATE_EXACT_RATE = {
    # measured on grid 1,2,4,8,16 at noise 0.02, 120 replicates, stable seeds:
    # linear 0.933, constant 0.900, quadratic 1.000, linearithmic 1.000.
    "linear": 0.90,
    "constant": 0.88,
}
# THE bite: a known-superlinear generator must be classified superlinear, and
# must NEVER be classified linear. `linear_rate` is gated at exactly 0.0.
GATE_SUPERLINEAR_RATE = {"quadratic": 1.0, "linearithmic": 0.95}

# CEILINGS on the instrument's two error rates. These were previously PRINTED
# and not asserted - and they are precisely the rates that scalefit's
# `superlinear = basis AND slope > 0` change moves, so a regression that doubled
# the false-flag rate would have shipped green. Measured with stable seeds:
# a genuinely LINEAR law is falsely flagged superlinear 0.067 of the time at
# noise 0.02, and O(n log n) is mistaken for LINEAR 0.125 of the time at 0.05
# (the discrimination limit of this grid). Ceilings sit above those with room.
GATE_MAX_FALSE_SUPERLINEAR_RATE = 0.12
GATE_MAX_SUPERLINEAR_AS_LINEAR_RATE = 0.20

# The rate at which the LINEAR-vs-SUPERLINEAR split must hold, in both
# directions, for a noise level to count as a regime where the S9 bite is
# demonstrated (`bite_applicability`). 0.90 rather than 0.95 because the
# `constant` generator measures exactly 0.900 on pure noise - AICc occasionally buys
# a second parameter - and a floor no generator can reach would make the block
# report "unknown" forever, which is worse than a slightly loose but reachable
# one. It is a floor on the INSTRUMENT, not on the product.
DISCRIMINATION_FLOOR = 0.90

# Which selected classes count as "the same family" as a generated class, for the
# wrong-model rule. The split that matters (and that TESTING.md S9 names) is
# linear-vs-SUPERLINEAR; n log n vs n^2 is not reliably identifiable at n <= 30
# and treating that as a wrong model would gate on noise instead of on meaning.
CLASS_FAMILY = {
    "constant": frozenset({"constant"}),
    "logarithmic": frozenset({"logarithmic"}),
    "linear": frozenset({"linear"}),
    "linearithmic": frozenset({"linearithmic", "quadratic"}),
    "quadratic": frozenset({"linearithmic", "quadratic"}),
}


# ---- pure: the unit gate ----------------------------------------------------


def unit_labelled(key: str) -> bool:
    """Is `key` a properly unit-labelled byte quantity?

    ANY key mentioning `bytes` anywhere - not just as a suffix - must END in a
    recognised unit, optionally followed by the rate marker `_per_s`. The
    endswith-only version of this rule was itself the vacuous-oracle shape it
    exists to prevent: `bytes_sent` (a real key name in this codebase, see
    `Pod.proxy_stats`), `egress_bytes_total` and `total_bytes_moved` all passed
    it CLEAN, and the self-test's mutations had been chosen to match the
    implementation rather than the claim. A rule stated as "a reader cannot mix
    what the schema will not let the writer spell" has to cover what the writer
    can actually spell.
    """
    body = key[: -len("_per_s")] if key.endswith("_per_s") else key
    return any(body.endswith(suffix) for suffix in UNIT_SUFFIXES)


def unit_violations(node, path: str = "") -> list[str]:
    """Every key naming a byte quantity must carry a recognised unit. Empty == clean.

    This is the mechanical form of the rule the project keeps breaking in prose:
    NarSize (uncompressed, signed) and FileSize (compressed, on-wire) are
    DIFFERENT UNITS, and a report that names both `bytes` invites the ratio that
    has already been wrong three times.
    """
    problems: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            here = f"{path}.{key}" if path else str(key)
            # `bytes` as a whole TOKEN, so `bytesize`-style words do not trip it
            # while `bytes_sent` and `total_bytes_moved` do.
            names_bytes = isinstance(key, str) and "bytes" in key.split("_")
            if names_bytes and not unit_labelled(key):
                problems.append(
                    f"{here}: byte-valued key without a unit label. It must END "
                    f"in one of {', '.join(UNIT_SUFFIXES)} (optionally + "
                    "'_per_s') - NarSize and FileSize are different units and an "
                    "unlabelled byte key lets them be compared"
                )
            problems += unit_violations(value, here)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            problems += unit_violations(value, f"{path}[{index}]")
    return problems


def assert_unit_coincidence(fixtures, attrs) -> dict:
    """PRECONDITION for the speedup arm: for every attr used, the COMPRESSED wire
    size equals the UNCOMPRESSED NarSize (i.e. `compression: none`).

    Only under this condition may peer-served bytes (raw NAR, NarSize units) and
    upstream egress bytes (on-wire, FileSize units) appear in the same offload
    statement. Returns the evidence; RAISES when it does not hold, so a fixture
    regeneration that switched a payload to xz breaks the run LOUDLY here instead
    of silently producing a cross-unit ratio downstream.
    """
    evidence = {}
    bad = []
    for attr in attrs:
        entry = fixtures.entry(attr)
        file_size = int(entry["file_size"])
        nar_size = int(entry["nar_size"])
        evidence[attr] = {
            "compression": entry.get("compression"),
            "wire_bytes_compressed_wire": file_size,
            "nar_bytes_uncompressed_nar": nar_size,
            "coincide": file_size == nar_size,
        }
        if file_size != nar_size:
            bad.append(f"{attr}: file_size={file_size} != nar_size={nar_size}")
    if bad:
        raise ValueError(
            "speedup arm requires `compression: none` payloads so wire bytes and "
            "NarSize coincide; they do not for " + "; ".join(bad) + ". Comparing "
            "peer-served raw-NAR bytes against compressed upstream egress would "
            "mix units."
        )
    return evidence


# ---- pure: upstream shaping and its assertion (task-63) ---------------------


@dataclass(frozen=True)
class UpstreamShaping:
    """RTT + bandwidth injected into the testproxy so the upstream arm carries
    real-upstream cost instead of loopback's ~0 RTT and ~1 GB/s.

    WHERE IT IS INJECTED, and why there. The testproxy's own fault modes 1
    (per-kind added latency) and 8 (`throttle_nar_bps`) do the shaping. The
    fixture is where environment and adversarial behaviour belong - the PRD rule
    is that none of it ever lives inside the product daemon - and reusing the
    existing, unit-tested primitives means the measured path gains no extra hop
    and no extra CPU. It is also what makes the shaping observable: the proxy
    port is published to the host, so the assertion below times requests from
    OUTSIDE the shaper rather than asking the shaper how it did.

    Rejected alternatives: a Python TCP relay between daemon and testproxy (an
    extra hop and extra CPU on the very path whose throughput is in question,
    and it would have to re-implement pacing); `tc netem` in the pod netns
    (needs NET_ADMIN, which rootless podman does not have).

    HONEST LIMIT, stated where the knob is defined. This is a SERVICE-LATENCY
    and EGRESS-RATE shaper, not a link emulator. It adds one delay per REQUEST
    and paces the response body. It does NOT model per-round-trip RTT inside a
    transfer, TCP slow start, or a receive-window-over-RTT ceiling - so a
    bandwidth-delay-product effect is absent by construction, and the WAN arm
    therefore still FLATTERS the upstream. See `shaping_fidelity_note()`.
    """

    rtt_ms: int
    bandwidth_bytes_compressed_wire_per_s: int

    def fault_params(self) -> str:
        """The testproxy admin query string that arms this shaping."""
        return (
            f"latency_cache_info_ms={self.rtt_ms}"
            f"&latency_narinfo_ms={self.rtt_ms}"
            f"&latency_nar_ms={self.rtt_ms}"
            f"&throttle_nar_bps={self.bandwidth_bytes_compressed_wire_per_s}"
        )

    def as_report(self) -> dict:
        return {
            "injected_rtt_ms": self.rtt_ms,
            "injected_bandwidth_bytes_compressed_wire_per_s": (
                self.bandwidth_bytes_compressed_wire_per_s
            ),
            "applied_by": (
                "testproxy fault mode 1 (per-kind added latency) + mode 8 "
                "(throttle_nar_bps); armed through the Pod seam's proxy_faults"
            ),
            "cap_unit": (
                "bytes_compressed_wire per second - the bytes actually on the "
                "wire. For THIS workload wire == NarSize by checked "
                "precondition (assert_unit_coincidence), and only for this one."
            ),
            "derivation": (
                "RTT: task-35 / TESTING.md measured 50-110 ms steady-state to "
                "cache.nixos.org's Fastly PoP and a 41 ms head-of-closure gap; "
                "direct probes from this host measured 27-78 ms per TCP round "
                "trip. BANDWIDTH: a 56.6 MB single-stream GET from "
                "cache.nixos.org sustained 21.4 MB/s from this host, and "
                "task-35's tail gaps imply 6.8-9.8 MB/s aggregate. Both knobs "
                "are set at the UPSTREAM-FAVOURABLE end, so the arm understates "
                "any peer advantage."
            ),
        }


def shaping_fidelity_note() -> dict:
    """What this shaping does and - louder - what it does NOT do."""
    return {
        "models": [
            "one added round trip per upstream REQUEST (cache-info, narinfo, nar)",
            "a sustained cap on NAR egress in bytes_compressed_wire per second",
        ],
        "does_not_model": [
            "per-round-trip RTT WITHIN a transfer: no TCP slow start, no "
            "receive-window-over-RTT ceiling, so the bandwidth-delay product "
            "that binds a real WAN transfer is absent. TASK-64's forward-carried "
            "point - that WAN is window-over-RTT bound while loopback is "
            "CPU-bound - is therefore only PARTLY exercised here: this arm makes "
            "the upstream slow, it does not make it BDP-limited.",
            "TLS handshake and session-resumption cost (the testproxy is plain "
            "HTTP; TLS is TASK-22/TASK-24)",
            "loss, reordering, jitter, or a competing-flow-shaped queue",
            "CDN behaviour: PoP selection, cache-miss shielding, rate limits",
            "THE PEER SIDE. Only the upstream is shaped. The peer transport "
            "still runs over pod loopback at ~187-255 MB/s (TASK-64), which no "
            "real LAN peer reaches - a 1 GbE peer moves 125 MB/s. Every "
            "peer-advantage number here is therefore an UPPER bound on the peer "
            "side; see `bias_directions` for why the upstream side is NOT a "
            "clean bound in the other direction. "
            "Shaping the peer link needs a primitive we do not have rootless "
            "(see the follow-up filed by task-63).",
        ],
        "bias_directions": {
            "toward_the_upstream": [
                "both knob VALUES sit at the favourable end of the measured "
                "evidence (RTT at the bottom of task-35's 50-110 ms band; the "
                "cap at this host's sustained single-stream rate, 2-3x what "
                "task-35's tail gaps imply)",
                "no bandwidth-delay-product ceiling, so a real high-RTT link "
                "degrades WORSE than this arm shows",
                "no loss, no jitter, no TLS handshake",
            ],
            "toward_the_peer": [
                "the delay is charged per REQUEST; a real client on a reused "
                "keep-alive connection does not pay a fresh round trip for "
                "each one. Measured magnitude: ~5 shaped requests x 50 ms = "
                "~0.25 s of a 5.92 s peers-off realise, about 4%",
                "the PEER side is unshaped loopback (187-255 MB/s), which no "
                "real peer link reaches",
            ],
            "net": (
                "the upstream-side biases dominate in magnitude, but the sign "
                "is not uniform, so this arm is NOT a clean lower bound on the "
                "peer advantage and must not be quoted as one. The direction "
                "that IS safe: the peer-side loopback makes the peer advantage "
                "an upper bound on the peer side."
            ),
        },
        "consequence": (
            "The WAN-shaped arm is a REALISTIC-COST upstream, not a simulated "
            "network. It answers 'does the peer path win once the upstream is "
            "not a fiction' - it does not predict a wire-level WAN transfer."
        ),
    }


def shaping_violations(evidence: dict, shaping: UpstreamShaping) -> list[str]:
    """Did the shaping ACTUALLY take effect? Empty list == asserted, not assumed.

    PURE, so `--self-test` can prove it bites without containers. Three checks,
    and the third is the one that matters most:

      1. the recovered latency delta is the injected RTT, within band;
      2. the achieved NAR rate is the injected cap, within band;
      3. THE UNSHAPED CONTROL IS MATERIALLY FASTER. A probe whose unshaped
         channel is already as slow as the shaping would confirm ANY shaping,
         including none - it is the vacuous oracle in its natural habitat. So
         "I could not tell shaped from unshaped" is a NAMED FAILURE here, never
         a pass.
    """
    problems: list[str] = []

    def number(key: str):
        value = evidence.get(key)
        if not isinstance(value, (int, float)) or value != value:  # NaN-safe
            problems.append(
                f"shaping probe is missing a usable `{key}` ({value!r}); an "
                "unmeasured shaper is an unasserted one"
            )
            return None
        return float(value)

    unshaped_ms = number("unshaped_request_latency_median_ms")
    shaped_ms = number("shaped_request_latency_median_ms")
    unshaped_nar_ms = number("unshaped_nar_first_byte_ms")
    shaped_nar_ms = number("shaped_nar_first_byte_ms")
    unshaped_rate = number("unshaped_nar_bytes_compressed_wire_per_s")
    shaped_rate = number("shaped_nar_bytes_compressed_wire_per_s")

    # The latency knob is armed per request KIND, so it is checked per kind. The
    # narinfo pair alone would leave the NAR - the arm's dominant request -
    # asserted by a check that never looked at it.
    for kind, unshaped, shaped in (
        ("narinfo request", unshaped_ms, shaped_ms),
        ("NAR first byte", unshaped_nar_ms, shaped_nar_ms),
    ):
        if unshaped is None or shaped is None:
            continue
        delta_ms = shaped - unshaped
        low, high = SHAPING_RTT_DELTA_BAND
        if not low * shaping.rtt_ms <= delta_ms <= high * shaping.rtt_ms:
            problems.append(
                f"injected RTT NOT recovered on the {kind}: shaped "
                f"{shaped:.1f} ms - unshaped {unshaped:.1f} ms = "
                f"{delta_ms:.1f} ms, outside [{low * shaping.rtt_ms:.1f}, "
                f"{high * shaping.rtt_ms:.1f}] ms for an injected "
                f"{shaping.rtt_ms} ms"
            )
        ceiling = SHAPING_CONTROL_MAX_LATENCY_FRACTION * shaping.rtt_ms
        if unshaped > ceiling:
            problems.append(
                f"VACUOUS PROBE: the unshaped {kind} control already costs "
                f"{unshaped:.1f} ms, more than {ceiling:.1f} ms "
                f"({SHAPING_CONTROL_MAX_LATENCY_FRACTION:g} x the injected "
                f"{shaping.rtt_ms} ms), so this probe cannot tell a shaped "
                "request from an unshaped one"
            )

    cap = shaping.bandwidth_bytes_compressed_wire_per_s
    if shaped_rate is not None:
        low, high = SHAPING_RATE_BAND
        if not low * cap <= shaped_rate <= high * cap:
            problems.append(
                f"injected bandwidth cap NOT achieved: shaped NAR rate "
                f"{shaped_rate:.0f} B(wire)/s outside [{low * cap:.0f}, "
                f"{high * cap:.0f}] B(wire)/s for a {cap} B(wire)/s cap"
            )
    if unshaped_rate is not None:
        floor = SHAPING_CONTROL_MIN_RATE_FACTOR * cap
        if unshaped_rate < floor:
            problems.append(
                f"VACUOUS PROBE: the unshaped control only reached "
                f"{unshaped_rate:.0f} B(wire)/s, below the "
                f"{SHAPING_CONTROL_MIN_RATE_FACTOR:g}x-cap floor "
                f"{floor:.0f} B(wire)/s - the measurement channel is itself the "
                "limiter, so a rate at the cap proves nothing about the shaper"
            )
    return problems


def speedup_qualifier_violations(report: dict) -> list[str]:
    """AC#2, mechanically: no unqualified speedup number anywhere. Empty == clean.

    Scoped to the speedup subtree (elsewhere `speedup_runs` and friends are
    configuration, not ratios). Inside it, every key naming a `speedup` must end
    in an upstream-condition suffix, and the by-condition index must actually
    carry both conditions - a report that quietly dropped the WAN arm and kept
    one nicely-suffixed number would otherwise pass.
    """
    problems: list[str] = []
    speedup = (report.get("measured") or {}).get("speedup")
    if speedup is None:
        return problems  # --skip-speedup: nothing claimed, nothing to qualify

    def walk(node, path: str) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                here = f"{path}.{key}"
                # Substring, not token: `speedupRatio` and `speedups_by_x` are
                # both spellable and both would have slipped a token check.
                if isinstance(key, str) and "speedup" in key.lower():
                    if not any(key.endswith(s) for s in CONDITION_SUFFIXES):
                        problems.append(
                            f"{here}: speedup key without an upstream-condition "
                            f"suffix. It must end in one of "
                            f"{', '.join(CONDITION_SUFFIXES)} - a speedup "
                            "against a loopback testproxy and one against a "
                            "WAN-shaped upstream are different claims and the "
                            "schema must not let them be spelled the same"
                        )
                walk(value, here)
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, f"{path}[{index}]")
        elif isinstance(node, str):
            # PROSE counts. The key rule and the human-summary rule were
            # different rules with different reach, and the gap was real: a
            # `reading` field saying "peers measured 3.5x SLOWER" is a ranking
            # claim the key check cannot see, and the summary check would have
            # rejected the same sentence verbatim. One rule now.
            #
            # A claim nested UNDER a condition-named node is already qualified,
            # so the path counts as a qualifier - which is why the per-condition
            # caveats do not trip this while `cross_condition`'s do.
            haystack = f"{path} {node}".lower()
            if any(m in node.lower() for m in _SPEEDUP_CLAIM_MARKERS) and not any(
                condition in haystack for condition in UPSTREAM_CONDITIONS
            ):
                problems.append(
                    f"{path}: prose states a speedup or a ranking without "
                    f"naming an upstream condition, and nothing in its path "
                    f"names one either: {node!r}"
                )

    walk(speedup, "measured.speedup")

    if speedup.get("ran"):
        index = speedup.get("by_upstream_condition")
        if not isinstance(index, dict):
            problems.append(
                "measured.speedup: no `by_upstream_condition` index - a speedup "
                "report must be indexed by the upstream it was measured against"
            )
        else:
            missing = [c for c in UPSTREAM_CONDITIONS if c not in index]
            if missing:
                problems.append(
                    f"measured.speedup.by_upstream_condition is missing "
                    f"{missing}; both the loopback CONTROL and the WAN-shaped "
                    "arm must be present (or explicitly recorded as not run) so "
                    "neither can be quoted as if it were the other"
                )
    return problems


# What makes a summary LINE a speedup claim. Deliberately literal: `speedup=`
# is how this summary spells a ratio, and `faster`/`slower` are how it spells a
# ranking. `speedup_arms_usable=` is an instrument flag, not a claim, and does
# not contain `speedup=` - which is exactly why the marker is the equals sign.
#
# HONEST LIMIT of this rule: it is a substring check over our own output, so it
# catches the phrasings this file actually emits and not a future one that
# prints the ratio with no word attached. That is the same trade the unit gate
# makes, and the self-test proves it bites on the shapes we do emit.
_SPEEDUP_CLAIM_MARKERS = ("speedup=", "faster", "slower")


def human_summary_violations(lines: list[str]) -> list[str]:
    """AC#2 for the HUMAN summary, which is the part people actually read.

    The JSON gate above cannot see the printed text, and a report whose schema
    forbids an unqualified speedup while its summary prints one has satisfied
    the letter of the rule and none of its point.
    """
    problems: list[str] = []
    for number, line in enumerate(lines, start=1):
        lowered = line.lower()
        if not any(marker in lowered for marker in _SPEEDUP_CLAIM_MARKERS):
            continue
        if any(condition in lowered for condition in UPSTREAM_CONDITIONS):
            continue
        problems.append(
            f"human summary line {number} states a speedup without naming the "
            f"upstream condition ({' or '.join(UPSTREAM_CONDITIONS)}): {line!r}"
        )
    return problems


# ---- pure: disk footprint ---------------------------------------------------


@dataclass
class DiskFootprint:
    """One directory's on-disk footprint, measured two ways.

    `apparent` is the sum of file sizes; `allocated` is the sum of blocks*512,
    which is what the filesystem actually spends. They differ for sparse files
    and for many small files, and reporting only one of them is how a footprint
    number becomes unfalsifiable.
    """

    apparent_bytes_ondisk: int
    allocated_bytes_ondisk: int
    file_count: int


def dir_footprint(path: Path) -> DiskFootprint:
    """Walk `path` HOST-SIDE and total its files.

    Host-side is not an optimisation, it is the only observation point that
    works: the e2e image has no `du` and no `find`, so an in-container probe
    returns rc=127 with empty output and reads as 0 bytes.

    FAIL-CLOSED on a missing directory: `dir_footprint` on a path that was never
    created raises, because "the daemon wrote nothing" and "we measured the wrong
    place" must not produce the same reassuring 0.
    """
    if not path.is_dir():
        raise ss.SampleError(
            f"disk footprint: {path} is not a directory (a missing measurement "
            "point must not read as 0 bytes)"
        )
    apparent = allocated = count = 0
    for root, _dirs, files in os.walk(path):
        for name in files:
            try:
                info = os.lstat(os.path.join(root, name))
            except OSError:
                # A file that vanished between listing and stat is transient
                # daemon state; skip it rather than fail the whole point, but do
                # not count it as 0 bytes of something that exists.
                continue
            apparent += info.st_size
            allocated += info.st_blocks * 512
            count += 1
    return DiskFootprint(apparent, allocated, count)


# ---- pure: the S9 bite (class recovery, MEASURED not asserted) ---------------


def stable_seed(model: str, noise: float, replicate: int) -> int:
    """A reproducible seed for the S9 study.

    NOT `hash(...)`: Python randomises `str.__hash__` per process, so a seed
    derived from it is reproducible only while something happens to set
    PYTHONHASHSEED - which nixpkgs' python setup hook does, and this repo does
    NOT. Measured with that accident removed, the gated recovery rates wandered
    (constant 0.892..0.975 against a 0.88 floor), so a FAST-tier gate on every
    commit was one environment change away from being a lottery, and the rates
    quoted in TESTING.md were reproducible by luck. crc32 over the explicit text
    is stable across processes, machines and Python versions.
    """
    return zlib.crc32(f"{model}|{noise!r}|{replicate}".encode())


def synthetic_series(model: str, grid, repeats: int, noise: float, seed: int):
    """(xs, ys) drawn from a KNOWN class with reproducible RELATIVE noise.

    Relative (multiplicative) noise on purpose: resource metrics are
    multiplicative-ish, and task-18 measured that scalefit's intervals UNDER-cover
    under exactly this noise shape (0.865 vs 0.95 nominal at n=1000). Generating
    the study under the noise shape the real data has is what makes the recovery
    rate below a statement about this instrument rather than about a tidier one.
    """
    basis = scalefit.BASIS_BY_NAME[model]
    rnd = random.Random(seed)
    xs: list[float] = []
    ys: list[float] = []
    # An intercept much larger than the growth term is the REAL regime for daemon
    # RSS (a ~60 MB base plus a small per-peer increment), so the study is run in
    # the low-SNR regime the sweep actually operates in, not a flattering one.
    base, step = 64.0e6, 2.0e6
    for n in grid:
        for _ in range(repeats):
            xs.append(float(n))
            ys.append(
                (base + step * basis.transform(n)) * (1.0 + rnd.gauss(0.0, noise))
            )
    return xs, ys


def class_recovery_study(grid, *, repeats: int, replicates: int, noise_levels) -> dict:
    """MEASURE how well the fitter recovers a KNOWN class on THIS grid.

    Returns, per (class, noise): the exact-class recovery rate, the rate at which
    the fit was called superlinear, and the rate at which it was called LINEAR -
    the last being the dangerous one for a superlinear generator (TESTING.md S9:
    the confusion that matters is linear-vs-superlinear).

    This is deliberately a RATE over many seeds, not a single fit. A one-seed
    "the fitter got it right" check is a coin flip dressed as an oracle, and this
    project has shipped three oracles that passed for the wrong reason.

    FAIL-CLOSED, not fatal: a grid too short to fit (`< scalefit.MIN_POINTS`
    distinct n) yields a `ran: False` block naming the reason. The same grid also
    makes the real fit impossible, so the report is already unusable - the study
    must say "not measured", never quietly study a DIFFERENT grid than the one
    swept, which would be a bite proven somewhere the data does not live.
    """
    distinct = sorted(set(grid))
    if len(distinct) < scalefit.MIN_POINTS:
        return {
            "ran": False,
            "grid": list(grid),
            "reason": (
                f"{len(distinct)} distinct n {distinct} is below "
                f"scalefit.MIN_POINTS={scalefit.MIN_POINTS}; the S9 bite is NOT "
                "demonstrated for this grid (and neither is any fit on it)"
            ),
            "how_to_read": "no bite was demonstrated - treat every fit as absent",
        }
    study: dict = {}
    for model in scalefit.BASIS_BY_NAME:
        per_noise = {}
        for noise in noise_levels:
            selections: dict[str, int] = {}
            superlinear = 0
            for replicate in range(replicates):
                xs, ys = synthetic_series(
                    model,
                    grid,
                    repeats,
                    noise,
                    seed=stable_seed(model, noise, replicate),
                )
                fit = scalefit.fit_scaling(
                    xs, ys, metric=f"synthetic {model}", unit="bytes"
                )
                chosen = fit["selected_model"]
                selections[chosen] = selections.get(chosen, 0) + 1
                superlinear += bool(fit["superlinear"])
            per_noise[str(noise)] = {
                "replicates": replicates,
                "selections": selections,
                "exact_rate": selections.get(model, 0) / replicates,
                "superlinear_rate": superlinear / replicates,
                "linear_rate": selections.get("linear", 0) / replicates,
                "family_rate": sum(
                    count
                    for name, count in selections.items()
                    if name in CLASS_FAMILY[model]
                )
                / replicates,
            }
        study[model] = per_noise
    return {
        "ran": True,
        "grid": list(grid),
        "observations_per_n": repeats,
        "noise_shape": "multiplicative (relative), gaussian",
        "per_class": study,
        "how_to_read": (
            "Rates are properties of the FITTER ON THIS GRID, not of the product. "
            "`linear_rate` for a superlinear generator is the S9 failure mode: a "
            "law that does not survive scale reported as one that does."
        ),
    }


def wrong_model_failures(cases) -> list[str]:
    """The wrong-model rule. `cases` is an iterable of (generated, selected).

    Wrong model == the selected class is outside the generated class's FAMILY
    (`CLASS_FAMILY`). Families collapse only n log n with n^2, which are not
    reliably identifiable below n~30; every other class stands alone, so a
    linear generator reported as superlinear (or vice versa) is a failure.
    """
    failures = []
    for generated, selected in cases:
        family = CLASS_FAMILY.get(generated)
        if family is None:
            failures.append(f"unknown generated class {generated!r}")
        elif selected not in family:
            failures.append(
                f"WRONG MODEL: generated {generated}, selected {selected} "
                f"(outside family {sorted(family)})"
            )
    return failures


# ---- pure: swarm-point assembly ---------------------------------------------

# (metric key in point.metrics, unit, human description). Every one of these is
# fitted against the peer count.
SWARM_METRICS = (
    (
        "peer_rss_hwm_bytes_ram",
        "bytes (RSS)",
        "worst per-peer peak RSS (VmHWM) vs swarm size",
    ),
    (
        "swarm_total_rss_hwm_bytes_ram",
        "bytes (RSS)",
        "whole-swarm peak RSS total (what the HOST pays) vs swarm size",
    ),
    ("peer_fd_max", "descriptors", "worst per-peer peak open fds vs swarm size"),
    (
        "peer_disk_allocated_bytes_ondisk",
        "bytes (on disk)",
        "worst per-peer on-disk daemon state vs swarm size",
    ),
    (
        "client_realise_s",
        "seconds",
        "client in-container realise duration vs swarm size",
    ),
)


def label_resources(resources: dict) -> dict:
    """THE translation from `scale_sweep.aggregate_samples` keys to this report's
    UNIT-LABELLED names. One function, used by every caller.

    The renaming is not cosmetic: `aggregate_samples` returns bare `*_bytes`
    keys and this report's unit gate rejects those. It is also the ONLY place
    the mapping exists on purpose - three near-copies of it had already drifted
    into `swarm_total_rss_hwm_bytes_ram` in one and `total_rss_hwm_bytes_ram` in
    another, which is exactly how a report grows two names for one measurement.
    """
    # `aggregate_samples` samples EVERY long-lived pod role, so `per_role`
    # carries the fixture `origin` and the `testproxy` alongside the daemons.
    # Splitting them here is load-bearing, not tidiness: every per-role consumer
    # in this module is asking a question about PEERS. Left mixed, the
    # "RAM per held NarSize byte" line could name the fixture HTTP server as the
    # worst node and attribute its memory to the iroh blob store - a wrong claim
    # in the one line a reader quotes.
    # FAIL-CLOSED, not fail-open. An absent `daemon_roles_sampled` used to mean
    # "no peers": `per_role` came back EMPTY and every peer silently moved into
    # `infrastructure_per_role`, so a caller who built a resources dict without
    # the key lost all per-peer RAM statistics with no error. "We could not tell
    # which roles were peers" and "there were no peers" must not be the same
    # observation.
    if "daemon_roles_sampled" not in resources:
        raise ss.SampleError(
            "label_resources: the aggregate has no `daemon_roles_sampled`, so "
            "peers cannot be told apart from the fixture origin/testproxy. "
            "Refusing to report an empty peer set as if it were a measurement."
        )
    daemons = set(resources["daemon_roles_sampled"])

    def rows(selector) -> dict:
        return {
            role: {
                "rss_hwm_bytes_ram": row["rss_hwm_bytes"],
                "rss_point_max_bytes_ram": row["rss_point_max_bytes"],
                "rss_point_last_bytes_ram": row["rss_point_last_bytes"],
                "fd_max": row["fd_max"],
                "ticks": row["ticks"],
            }
            for role, row in resources["per_role"].items()
            if selector(role)
        }

    return {
        "peer_rss_hwm_bytes_ram": resources["daemon_rss_hwm_bytes"],
        "peer_rss_point_max_bytes_ram": resources["daemon_rss_point_max_bytes"],
        "swarm_total_rss_hwm_bytes_ram": resources["chain_total_rss_hwm_bytes"],
        "peer_fd_max": resources["daemon_fd_max"],
        # DAEMON roles only - the peers. Every per-role statistic in this report
        # is computed from this.
        "per_role": rows(lambda role: role in daemons),
        # The fixture origin and testproxy. Reported so nothing is hidden, but
        # never mixed into a claim about what a PEER costs.
        "infrastructure_per_role": rows(lambda role: role not in daemons),
    }


def swarm_metrics_from(resources: dict, disks: dict, realise_s: list[float]) -> dict:
    """The FITTABLE scalar metrics of one swarm point: the labelled aggregate
    (minus its per-role detail, which is not a scalar) plus the disk walk and the
    client's latency."""
    labelled = label_resources(resources)
    labelled.pop("per_role")
    labelled.pop("infrastructure_per_role")
    labelled.update(
        {
            "peer_disk_apparent_bytes_ondisk": max(
                (d.apparent_bytes_ondisk for d in disks.values()), default=0
            ),
            "peer_disk_allocated_bytes_ondisk": max(
                (d.allocated_bytes_ondisk for d in disks.values()), default=0
            ),
            "swarm_total_disk_allocated_bytes_ondisk": sum(
                d.allocated_bytes_ondisk for d in disks.values()
            ),
            # NOT named `_p95`. A swarm point runs ONE client, so `realise_s`
            # holds a single observation and its "p95" is just that observation.
            # A `_p95` key would promise a tail robustness the data has not got;
            # the tail lives in the REPLICATES, which are separate points.
            "client_realise_s": percentile(realise_s, 95) if realise_s else None,
        }
    )
    return labelled


def hwm_gap_summary(pairs, *, source: str) -> dict:
    """Did the workload SEPARATE high-water RSS (VmHWM) from the largest point
    sample the 0.2 s sampler caught? `pairs` is an iterable of (hwm, point).

    task-18 left this honest gap open: on its workload VmHWM == max VmRSS at
    every observation, so the distinction the harness reports was never exercised
    by real data. This block answers it with numbers rather than implying it - if
    the gap is 0 everywhere, the report SAYS the distinction is still unexercised
    rather than letting a reader infer it was validated.
    """
    gaps = [
        int(hwm) - int(pnt) for hwm, pnt in pairs if hwm is not None and pnt is not None
    ]
    separated = [g for g in gaps if g > 0]
    return {
        "source": source,
        "observations": len(gaps),
        "observations_where_hwm_exceeds_point_sample": len(separated),
        "max_gap_bytes_ram": max(gaps) if gaps else None,
        "median_gap_bytes_ram": statistics.median(gaps) if gaps else None,
        "exercised": bool(separated),
        "note": (
            "VmHWM is the kernel's peak; the point sample is the largest VmRSS "
            "the 0.2 s sampler happened to catch. A gap of 0 at every "
            "observation means the distinction is UNEXERCISED by this data "
            "(task-18 saw exactly that) - it does NOT mean it was validated."
        ),
    }


def hwm_vs_point(points) -> dict:
    """`hwm_gap_summary` over the swarm axis's per-point worst-peer figures."""
    return hwm_gap_summary(
        (
            (
                point.metrics.get("peer_rss_hwm_bytes_ram"),
                point.metrics.get("peer_rss_point_max_bytes_ram"),
            )
            for point in points
            if point.valid
        ),
        source="swarm axis, worst peer per point",
    )


def hwm_vs_point_roles(per_role: dict, source: str) -> dict:
    """`hwm_gap_summary` over every sampled ROLE of one arm.

    Per-role rather than per-arm-max on purpose: the arm maximum is one number,
    and the separation this is looking for happens on the ONE node that buffers
    the payload. Collapsing to a maximum first would hide which node burst.
    """
    return hwm_gap_summary(
        (
            (row.get("rss_hwm_bytes_ram"), row.get("rss_point_max_bytes_ram"))
            for row in per_role.values()
        ),
        source=source,
    )


def held_content_ram_cost(per_role: dict, held_bytes_uncompressed_nar: int) -> dict:
    """How much RESIDENT MEMORY a node pays per byte of content it holds/moves.

    The units on the two sides are deliberately DIFFERENT and both are named in
    the key: RSS is `_ram`, held content is NarSize. This is a legitimate
    cross-unit RATIO (memory per payload byte) precisely because it is spelled as
    one; what is forbidden is a cross-unit SUM or an offload fraction, which is
    why the offload block draws both of its terms from the wire unit only.

    This is the number that makes the MemStore finding concrete: with the blob
    store in RAM and a whole-NAR transport, BOTH the holder and the fetcher
    resident-size the payload.
    """
    if held_bytes_uncompressed_nar <= 0:
        return {"measured": False, "why": "no held content in this arm"}
    return {
        "measured": True,
        "held_bytes_uncompressed_nar": held_bytes_uncompressed_nar,
        "per_role_peak_rss_ram_per_held_nar_byte_ratio": {
            role: row["rss_hwm_bytes_ram"] / held_bytes_uncompressed_nar
            for role, row in per_role.items()
        },
        "note": (
            "Peak RSS / held NarSize bytes, per node. A ratio near or above 1 "
            "means the node resident-sizes the whole payload - the expected "
            "consequence of an in-RAM blob store (MemStore) plus a whole-NAR "
            "addressed unit. TASK-54 owns bounding this."
        ),
    }


# ---- pure: speedup / throughput arm scoring ---------------------------------


@dataclass
class ProfileRun:
    """One scored workload execution: the frozen counting rule's verdict plus the
    in-container timing the rule does not carry."""

    valid: bool
    reason: str
    realise_s: float | None
    wall_s: float
    egress_nar_bytes_compressed_wire: int
    egress_total_bytes_compressed_wire: int
    peer_served_bytes_uncompressed_nar: int = 0
    # A REAL transport rate at the cache boundary (see TASK-68 below). None when
    # nothing crossed - a peer hit has no upstream transfer to rate.
    upstream_nar_transport_bytes_compressed_wire_per_s: float | None = None


def upstream_nar_transport_rate(records: list[dict]) -> float | None:
    """Achieved bytes_compressed_wire per second at the CACHE BOUNDARY, from the
    testproxy's own per-record `bytes_sent` / `duration_ms`.

    TASK-68 context, partly addressed here. The arm's `realise_rate_*` figure is
    NOT a transport rate: its numerator is a constant and its denominator is a
    whole `nix-store --realise` (unpack + sha256 NarHash + store registration),
    so it is algebraically 1/realise_s times a constant and its ratio across arms
    is identically 1/latency-ratio. THIS figure is different in kind: it is bytes
    on a socket over the time that socket was being written, which is a link
    rate and the thing to compare against a peer link rate.

    It INCLUDES the per-request injected latency and the pacing sleeps, because
    both are part of what the client waits for - which is also what makes it a
    second, independent witness that the shaping took effect. It measures only
    the UPSTREAM side; the peer side has no equivalent instrument yet (TASK-68
    stays open for that half).
    """
    total_bytes = 0
    total_s = 0.0
    for record in records:
        if record.get("kind") != "nar":
            continue
        sent = record.get("bytes_sent")
        duration_ms = record.get("duration_ms")
        if sent is None or duration_ms is None:
            continue
        total_bytes += int(sent)
        total_s += float(duration_ms) / 1000.0
    if total_bytes <= 0 or total_s <= 0:
        return None
    return total_bytes / total_s


def summarize_profile_arm(
    name: str,
    runs: list[ProfileRun],
    *,
    workload_bytes_compressed_wire: int,
    workload_bytes_uncompressed_nar: int,
    min_valid: int,
) -> dict:
    """Aggregate one arm. Latency comes from the IN-CONTAINER realise duration;
    the host-side podman wall clock is reported beside it and never used for a
    speedup ratio, because container create/start/teardown is not the product.

    The rate figure is stated per UNIT and per arm; the two arms' rates are only
    comparable because `assert_unit_coincidence` proved wire == NarSize for this
    workload, which the report records as evidence."""
    valid = [r for r in runs if r.valid]
    realise = [r.realise_s for r in valid if r.realise_s is not None]
    # Per-run rate, not total/total: a mean of ratios and a ratio of means
    # differ, and the per-run figure is the one with a distribution.
    #
    # TASK-68: this used to be called `throughput_*`, which invited exactly the
    # reading it cannot support. The numerator is a CONSTANT (the workload) and
    # the denominator is a whole `nix-store --realise`, so this is 1/realise_s
    # rescaled - its cross-arm ratio is identically the inverse of the latency
    # ratio, and it carries unpack + NarHash + store registration on top of any
    # transfer. It is a REALISE RATE. The transport rate lives beside it, keyed
    # `upstream_nar_transport_bytes_compressed_wire_per_s`.
    realise_rate = [workload_bytes_uncompressed_nar / s for s in realise if s and s > 0]
    transport = [
        r.upstream_nar_transport_bytes_compressed_wire_per_s
        for r in valid
        if r.upstream_nar_transport_bytes_compressed_wire_per_s is not None
    ]
    return {
        "arm": name,
        "runs": len(runs),
        "valid_runs": len(valid),
        "min_valid_required": min_valid,
        "usable": len(valid) >= min_valid,
        # The frozen counting rule's SECTION 5 threshold. An arm below
        # `measure.BASELINE_MIN_VALID_RUNS` can be `usable` for a dev loop but it
        # is NOT a baseline, and saying so is the difference between a smoke run
        # and a number someone quotes later.
        "dev_smoke_below_n10": len(valid) < BASELINE_MIN_VALID_RUNS,
        "invalid_runs": [
            {"run": i, "reason": r.reason} for i, r in enumerate(runs) if not r.valid
        ],
        "workload_bytes_compressed_wire": workload_bytes_compressed_wire,
        "workload_bytes_uncompressed_nar": workload_bytes_uncompressed_nar,
        # THE latency figure: in-container realise.
        "realise_s": stat_block(realise),
        # Context only - carries container create/start/teardown.
        "container_wall_s": stat_block([r.wall_s for r in valid]),
        # THE offload figure, in wire units, per the frozen counting rule.
        "egress_payload_nar_bytes_compressed_wire": stat_block(
            [float(r.egress_nar_bytes_compressed_wire) for r in valid]
        ),
        "egress_total_bytes_compressed_wire": stat_block(
            [float(r.egress_total_bytes_compressed_wire) for r in valid]
        ),
        # Ground truth from the holder's OWN provider counter, in NarSize units.
        "peer_served_bytes_uncompressed_nar": stat_block(
            [float(r.peer_served_bytes_uncompressed_nar) for r in valid]
        ),
        # NOT a transport rate - see the TASK-68 note above.
        "realise_rate_bytes_uncompressed_nar_per_s": stat_block(realise_rate),
        "realise_rate_is_not_a_transport_rate": (
            "workload bytes / whole-`nix-store --realise` seconds. The numerator "
            "is constant, so this is 1/realise_s rescaled and its cross-arm "
            "ratio is identically 1/latency-ratio; the denominator additionally "
            "carries unpack, sha256 NarHash and store registration. Read "
            "`upstream_nar_transport_bytes_compressed_wire_per_s` for a link "
            "rate (TASK-68)."
        ),
        # The measured link rate at the cache boundary. Empty for an arm whose
        # payload never crossed it (a peer hit) - which is the correct answer,
        # not zero.
        "upstream_nar_transport_bytes_compressed_wire_per_s": stat_block(transport),
    }


def speedup_block(
    peers_on: dict, peers_off: dict, unit_evidence: dict, condition: str
) -> dict:
    """The S7 speedup/offload statement, assembled so a cross-unit ratio is not
    expressible: every quantity in a ratio here is drawn from ONE unit family.

    `egress_offload_fraction` is computed from `*_compressed_wire` on both sides.
    `latency_speedup` is a ratio of in-container SECONDS. The peer-served figure
    (NarSize units) is reported as corroboration - it is what proves the bytes
    really moved peer-to-peer - and is never a term in either ratio.

    TASK-63: every speedup key is suffixed with the UPSTREAM CONDITION it was
    measured against, because a speedup over a ~0-RTT loopback testproxy and a
    speedup over a WAN-shaped upstream are different claims about different
    machines. `speedup_qualifier_violations` fails a report that spells either
    one without saying which, and the self-test proves that by mutation.
    """
    if condition not in UPSTREAM_CONDITIONS:
        raise ValueError(
            f"unknown upstream condition {condition!r}; must be one of "
            f"{UPSTREAM_CONDITIONS} - an unnamed condition would produce exactly "
            "the unqualified speedup number this suffix exists to prevent"
        )
    suffix = f"_{condition}"
    off_nar = peers_off["egress_payload_nar_bytes_compressed_wire"]["mean"]
    on_nar = peers_on["egress_payload_nar_bytes_compressed_wire"]["mean"]
    # Named for what they ARE. `stat_block` has both a mean and a p95 and calling
    # the mean `p50` is a trap for the next reader, whatever the emitted key says.
    off_mean = peers_off["realise_s"]["mean"]
    on_mean = peers_on["realise_s"]["mean"]
    off_p95 = peers_off["realise_s"]["p95"]
    on_p95 = peers_on["realise_s"]["p95"]

    def ratio(numerator, denominator):
        if numerator is None or denominator in (None, 0):
            return None
        return numerator / denominator

    offload = None
    if off_nar not in (None, 0) and on_nar is not None:
        offload = (off_nar - on_nar) / off_nar
    # The speedup is THE number a reader will quote, so it does not get to be a
    # bare point ratio in a report that carries intervals everywhere else. A
    # worst/best pair built from each arm's own min and max brackets it without
    # assuming a distribution the sample is far too small to justify.
    on_values = peers_on["realise_s"]["values"]
    off_values = peers_off["realise_s"]["values"]
    bracket = None
    if on_values and off_values:
        bracket = {
            "worst_case": min(off_values) / max(on_values),
            "best_case": max(off_values) / min(on_values),
            "how": (
                "slowest-peer vs fastest-cache and vice versa, from the observed "
                "values only. NOT a confidence interval - it is the range the "
                "measured runs actually span, which is the honest statement for "
                "a sample this small."
            ),
        }
    if condition == LOOPBACK_CONTROL:
        caveat = (
            "CONTROL ARM. The 'upstream' here is the in-pod testproxy on "
            "loopback at ~0 RTT - NOT cache.nixos.org, and not a machine any "
            "user owns. This arm exists to isolate the PEER TRANSPORT's own "
            "cost (TASK-64) by removing the link from the comparison; it is not "
            "an answer to the owner goal, which names a speedup over "
            "cache.nixos.org. Read `wan_shaped` for that. Real-upstream timing "
            "(task-35, measured against cache.nixos.org): median narinfo->nar "
            "gap ~300 ms, up to 3.08 s at closure tails - absent from every "
            "number in this block, by design."
        )
    else:
        caveat = (
            "WAN-SHAPED ARM. The upstream carries an injected per-request RTT "
            "and a NAR egress cap derived from the real-upstream measurements "
            "(task-35 plus direct probes of cache.nixos.org); see "
            "`shaping` and `shaping_evidence` for the values and for the "
            "outside-the-shaper proof that they took effect. Both knobs sit at "
            "the upstream-FAVOURABLE end of the measured evidence, and the PEER "
            "side is NOT shaped (still pod loopback), so the peer advantage "
            "stated here is an UPPER bound on the peer side. It is NOT a clean "
            "lower bound on the upstream cost: see `shaping_fidelity."
            "bias_directions`, which names the ~4% that runs the other way, and "
            "what the shaper does not model at all - notably the "
            "receive-window-over-RTT ceiling."
        )
    return {
        "counting_rule": "net-upstream-egress-v2 (scripts/MEASUREMENT_COUNTING_RULE.md)",
        "upstream_condition": condition,
        "unit_coincidence_evidence": unit_evidence,
        "egress_payload_peers_off_bytes_compressed_wire": off_nar,
        "egress_payload_peers_on_bytes_compressed_wire": on_nar,
        # Both terms are compressed-wire; the ratio is within one unit family.
        "egress_offload_fraction": offload,
        "peer_served_corroboration_bytes_uncompressed_nar": peers_on[
            "peer_served_bytes_uncompressed_nar"
        ]["mean"],
        "realise_mean_peers_off_s": off_mean,
        "realise_mean_peers_on_s": on_mean,
        "realise_stdev_peers_off_s": peers_off["realise_s"]["stdev"],
        "realise_stdev_peers_on_s": peers_on["realise_s"]["stdev"],
        "realise_p95_peers_off_s": off_p95,
        "realise_p95_peers_on_s": on_p95,
        # >1 means peers are FASTER. A ratio of seconds; no bytes involved. The
        # condition suffix is not decoration - see the docstring.
        f"latency_speedup_mean{suffix}": ratio(off_mean, on_mean),
        f"latency_speedup_p95{suffix}": ratio(off_p95, on_p95),
        f"latency_speedup_observed_range{suffix}": bracket,
        "caveat": caveat,
    }


# ---- container arms ----------------------------------------------------------


def _drive_one_client(pod, substituter: str, keys: str, targets: list[str]):
    """One client container; returns (ClientResult, host wall seconds)."""
    started = time.perf_counter()
    result = pod.client_run(targets, substituter, keys)
    return result, time.perf_counter() - started


def score_run(
    pod, fixtures, attrs, result, wall_s: float, peer_served: int
) -> ProfileRun:
    """Score one run through the FROZEN counting rule (`measure.classify_run`),
    then attach the in-container realise duration.

    The counting rule is imported, not re-expressed: a second definition of "net
    upstream egress" in this repo would silently break every cross-wave
    comparison the rule exists to protect."""
    url_sizes = {
        fixtures.entry(a)["url"]: int(fixtures.entry(a)["file_size"]) for a in attrs
    }
    delivered = {
        fixtures.entry(a)["url"]: (result.narhash(fixtures.store_path(a)) is not None)
        for a in attrs
    }
    records = pod.proxy_log()
    verdict = classify_run(
        records,
        url_sizes,
        delivered,
        pod.proxy_stats().get("bytes_sent"),
        result.exit_code,
        wall_s,
    )
    realise_s = ss.parse_realise_seconds(result.stdout)
    reasons = [verdict.reason] if verdict.reason else []
    if realise_s is None:
        # Unknown timing is NOT the host wall clock and NOT zero. A run whose
        # in-container duration is unknown cannot contribute to a latency or
        # throughput figure, so it is invalid.
        reasons.append("missing REALISE_NS marker (in-container timing unknown)")
    return ProfileRun(
        valid=not reasons,
        reason="; ".join(reasons),
        realise_s=realise_s,
        wall_s=wall_s,
        egress_nar_bytes_compressed_wire=verdict.egress_nar,
        egress_total_bytes_compressed_wire=verdict.egress_total,
        peer_served_bytes_uncompressed_nar=peer_served,
        upstream_nar_transport_bytes_compressed_wire_per_s=(
            upstream_nar_transport_rate(records)
        ),
    )


def sweep_swarm(ctx, fixtures, sizes, repeats: int, state_root: Path) -> ss.Axis:
    """The FITTED axis: n holder peers (n+1 daemon processes) vs resources.

    Each point stands up a fresh pod with node-a plus n independently-seeded iroh
    providers, samples every node's /proc host-side for the duration of one real
    peer-served build, walks each node's on-disk state host-side, and records the
    in-container realise latency.
    """
    axis = ss.Axis(
        name="swarm",
        variable="peer holder count (iroh provider daemon processes)",
        description=(
            "The peer-count law. n holder peers plus one fetching node, all real "
            "daemon PROCESSES on this host. Fitted: what ONE peer pays "
            "(per-peer peak RSS / fds / on-disk state), what the HOST pays "
            "(swarm total), and what a build pays (client realise latency)."
        ),
    )
    axis.notes.append(
        "every holder seeds the SAME NARs, so per-peer figures are comparable "
        f"across the swarm; workload attrs = {list(SWARM_ATTRS)} (small on "
        "purpose - the iroh blob store is in RAM, so a 110 MiB payload at n=16 "
        "would measure the host running out of memory, not a scaling law)"
    )
    axis.notes.append(
        "node A's claims all name holder `node-b`: InMemoryDiscovery::announce "
        "REPLACES on key, so a multi-holder claim is not expressible through "
        "--p2p-claim today. This axis therefore measures the cost of n peer "
        "PROCESSES plus an n-entry peer address book, NOT holder selection or "
        "dial fan-out across n candidates (TASK-43/47)."
    )
    substituter = ctx.substituter_daemon_only()
    targets = [fixtures.store_path(a) for a in SWARM_ATTRS]

    for size in sizes:
        for rep in range(repeats):
            print(
                f"profile: swarm axis, holders={size} (replicate {rep + 1}/{repeats})",
                file=sys.stderr,
            )
            point = ss.SweepPoint(n=size, valid=False)
            scratch = ctx.scratch / f"swarm-{size}-{rep}"
            try:
                seed_dir, seeds = e2e.build_p2p_seed_dir(
                    fixtures, scratch, list(SWARM_ATTRS)
                )
                point_state = state_root / f"swarm-{size}-{rep}"
                with e2e.Pod(
                    ctx,
                    f"prof-swarm-{size}-{rep}",
                    fixtures.cache,
                    with_daemon=False,
                    expect=ss.silent_expect([]),
                    p2p_seed_dir=seed_dir,
                    p2p_seeds=seeds,
                    p2p_holders=size,
                    state_root=point_state,
                ) as pod:
                    pod.proxy_reset()
                    with ss.NodeSampler(pod, pod.roles()) as sampler:
                        result, wall_s = _drive_one_client(
                            pod, substituter, fixtures.public_key, targets
                        )
                    resources = ss.aggregate_samples(
                        sampler.samples, pod.daemon_roles()
                    )
                    disks = {
                        role: dir_footprint(pod.state_dir(role))
                        for role in pod.daemon_roles()
                    }
                    expected_served = sum(s.nar_size for s in seeds)
                    served = pod.node_b_served_bytes(want_at_least=expected_served)
                    realise_s = ss.parse_realise_seconds(result.stdout)
                    # The independent witness that tells a real upstream fallback
                    # apart from a lagging holder log (see below).
                    upstream_nar = pod.proxy_stats().get("nar", 0)

                reasons: list[str] = list(sampler.errors)
                if result.exit_code != 0:
                    tail = result.stderr.strip().splitlines()
                    reasons.append(
                        f"client exit {result.exit_code}: {tail[-1] if tail else ''}"
                    )
                if realise_s is None:
                    reasons.append("missing REALISE_NS marker (timing unknown)")
                # THE precondition that stops this axis from measuring a swarm
                # that quietly fell back to upstream: the claimed holder's OWN
                # provider counter must show it served the whole workload. Without
                # it a point could be a fully-upstream build wearing a peer label.
                #
                # `node_b_served_bytes` returns its best-so-far on timeout with no
                # signal that it timed out, so a shortfall ALONE cannot tell a real
                # fallback from a lagging monitor. The testproxy's upstream NAR
                # count is the independent witness: a fallback moved payload
                # across the cache boundary, a lagging log did not.
                if served < expected_served:
                    reasons.append(
                        f"peer-serve precondition failed: node-b served {served} B "
                        f"< expected {expected_served} B (uncompressed NAR); "
                        f"upstream served {upstream_nar} NAR request(s) - "
                        + (
                            "this build fell back to upstream"
                            if upstream_nar > 0
                            else "nothing crossed the cache boundary, so the "
                            "holder's log monitor lagged rather than the peer "
                            "failing"
                        )
                    )
                metrics = swarm_metrics_from(
                    resources, disks, [] if realise_s is None else [realise_s]
                )
                point = ss.SweepPoint(
                    n=size,
                    valid=not reasons,
                    reason="; ".join(reasons),
                    metrics=metrics,
                    detail={
                        "daemon_processes": size + 1,
                        "peer_served_bytes_uncompressed_nar": served,
                        "expected_served_bytes_uncompressed_nar": expected_served,
                        "upstream_nar_requests": upstream_nar,
                        "container_wall_s": wall_s,
                        "realise_s": realise_s,
                        "per_role_disk": {
                            role: vars(footprint) for role, footprint in disks.items()
                        },
                        "per_role_resources": label_resources(resources)["per_role"],
                    },
                )
            except (RuntimeError, ss.SampleError, OSError, ValueError) as error:
                point.reason = f"swarm point raised: {error!r}"
                # Fail VERBOSELY: a 20-minute instrument whose deliverable is a
                # JSON file must be able to explain its own invalid points
                # without a stderr scrollback.
                point.detail["traceback"] = traceback.format_exc()
            except SystemExit as error:
                # `e2e.die` (exit code 2) is fatal to a SCENARIO but must only
                # invalidate a POINT here: a swarm of 17 containers has 17 chances
                # for one holder to miss its identity announcement, and losing the
                # whole sweep to that would be a harness fault reported as a
                # missing law. Any OTHER exit code - notably the SIGTERM handler's
                # 143 - is a real request to stop and is re-raised.
                #
                # TASK-60: this is a WORKAROUND for `die()` being control flow.
                # Sniffing an exit code loses the message (the reason below can
                # only point at a stderr scrollback) and demotes any future
                # genuinely-fatal `die(..., code=2)` to a bad data point. The
                # root fix is a raisable `e2e.HarnessError`.
                if error.code != 2:
                    raise
                point.reason = (
                    f"swarm point aborted by the Pod seam (e2e.die, exit "
                    f"{error.code}); see the harness output above for the reason"
                )
            finally:
                shutil.rmtree(scratch, ignore_errors=True)
            axis.points.append(point)
    return axis


def _timed_get(
    url: str, *, timeout_s: float = 300.0
) -> tuple[int, float, float | None]:
    """GET `url`, stream the body to nowhere. Returns (bytes, seconds, ttfb).

    Streamed rather than `.read()`: the probe fetches a 110 MiB NAR and a
    host-side instrument that resident-sizes the payload would be measuring its
    own allocator alongside the link.

    TTFB (time to the FIRST body chunk) is returned separately because the two
    shaping knobs land in different places: the per-request latency is paid
    BEFORE the response head, so it shows up whole in the TTFB, while the
    bandwidth cap is paid across the body and shows up in the total. Without the
    split, a probe that only measures total time cannot tell the NAR request's
    injected latency from a 0.85% change in a 5.9-second transfer.
    """
    started = time.perf_counter()
    total = 0
    ttfb: float | None = None
    with urllib.request.urlopen(url, timeout=timeout_s) as response:  # noqa: S310
        if response.status != 200:
            raise RuntimeError(f"probe GET {url} returned {response.status}")
        while True:
            chunk = response.read(64 * 1024)
            if not chunk:
                break
            if ttfb is None:
                ttfb = time.perf_counter() - started
            total += len(chunk)
    return total, time.perf_counter() - started, ttfb


def _attr_urls(fixtures, attr: str) -> tuple[str, str, int]:
    """(narinfo URL, NAR URL, NAR wire bytes) for one payload, host-side."""
    base = f"http://127.0.0.1:{e2e.HOST_PROXY}"
    entry = fixtures.entry(attr)
    narinfo = f"{base}/{fx.narinfo_name(fixtures.store_path(attr))}"
    return narinfo, f"{base}/{entry['url']}", int(entry["file_size"])


def _probe_urls(fixtures) -> tuple[str, str, int]:
    """The PROBE's payload: `big`, because a 110 MiB body is long enough for a
    paced rate to be a rate rather than a scheduling accident."""
    return _attr_urls(fixtures, "big")


def prewarm_upstream_cache(fixtures) -> None:
    """Pull the workload through the testproxy once, host-side, before an arm.

    Applied to EVERY speedup pod in EVERY upstream condition, and that
    uniformity is the point: without it the first peers-OFF run of each arm
    would carry an origin fetch the other nine do not, and the WAN condition -
    which must probe the proxy anyway - would end up warm while the loopback
    CONTROL stayed cold. A confound that differs between the two conditions
    being compared is worse than one that is present in both.
    """
    # EVERY payload the arm will ask for, plus the cache-info the client fetches
    # first - not just the big one. Warming `big` alone still left `lib`, its
    # narinfo and nix-cache-info cold on run 1, which is the exact confound this
    # function claims to remove; small, but an unverified claim written into the
    # report as an asserted one is the defect, not the milliseconds.
    _timed_get(f"http://127.0.0.1:{e2e.HOST_PROXY}/nix-cache-info")
    for attr in SPEEDUP_ATTRS:
        narinfo_url, nar_url, wire_bytes = _attr_urls(fixtures, attr)
        _timed_get(narinfo_url)
        got, _, _ = _timed_get(nar_url)
        if got != wire_bytes:
            raise RuntimeError(
                f"prewarm read {got} B from {nar_url}, expected {wire_bytes} B "
                "(bytes_compressed_wire); refusing to measure against a proxy "
                "whose cache is not holding the whole payload"
            )


def probe_upstream_link(pod, fixtures, shaping: UpstreamShaping) -> dict:
    """ASSERT the shaping (AC#1). Measures the link HOST-SIDE, through the
    published proxy port - i.e. from OUTSIDE the shaper - unshaped and then
    shaped, over the same channel, and leaves the shaping armed.

    Measuring both states through one channel is what makes this an assertion
    rather than a reading: the channel's own cost (podman's rootless port
    forwarding, the host's scheduler, the proxy's own service time) is present
    in both and cancels out of the latency delta, while the unshaped rate is the
    negative control that stops a slow channel from masquerading as a working
    shaper. `shaping_violations` consumes the result and a non-empty verdict
    fails the run.

    A caller MUST NOT interpret "no exception" as "shaped": the numbers are
    returned and judged separately, on purpose, so the judging is a pure
    function the self-test can break.
    """
    narinfo_url, nar_url, wire_bytes = _probe_urls(fixtures)

    def latency_median_ms() -> float:
        samples = []
        for _ in range(SHAPING_LATENCY_SAMPLES):
            _, elapsed, _ = _timed_get(narinfo_url)
            samples.append(elapsed * 1000.0)
        return statistics.median(samples)

    def nar_rate_and_ttfb() -> tuple[float, float]:
        """(bytes/s over the whole body, ms to the first body byte).

        Both, because the two knobs land in different places. The rate proves
        mode 8 (the cap) fired; the TTFB proves mode 1 fired ON THE NAR KIND
        specifically. Without the second number the probe only ever observes the
        NARINFO latency, and a shaping that armed narinfo but not nar - the
        arm's dominant request - would be asserted by a check that never looked
        at it.
        """
        got, elapsed, ttfb = _timed_get(nar_url)
        if got != wire_bytes:
            raise RuntimeError(
                f"probe read {got} B from {nar_url}, expected {wire_bytes} B "
                "(bytes_compressed_wire) - a partial body would make the rate a "
                "fiction"
            )
        if ttfb is None:
            raise RuntimeError(f"probe got no body chunk from {nar_url}")
        return got / elapsed, ttfb * 1000.0

    pod.proxy_faults("")  # start from a known-unshaped state
    unshaped_ms = latency_median_ms()
    unshaped_rate, unshaped_nar_ttfb_ms = nar_rate_and_ttfb()

    pod.proxy_faults(shaping.fault_params())
    shaped_ms = latency_median_ms()
    shaped_rate, shaped_nar_ttfb_ms = nar_rate_and_ttfb()

    return {
        "measured_from": (
            "the HOST, through the published testproxy port - outside the "
            "shaper, not the shaper's own account of itself"
        ),
        "probe_payload_bytes_compressed_wire": wire_bytes,
        "latency_samples_per_state": SHAPING_LATENCY_SAMPLES,
        "unshaped_request_latency_median_ms": unshaped_ms,
        "shaped_request_latency_median_ms": shaped_ms,
        # The NAR kind's own latency, observed independently of the narinfo
        # kind's. The bandwidth cap adds only one chunk-time to the TTFB
        # (64 KiB at the cap ~ 3 ms), so the recovered delta here is the
        # injected RTT and not the pacing.
        "unshaped_nar_first_byte_ms": unshaped_nar_ttfb_ms,
        "shaped_nar_first_byte_ms": shaped_nar_ttfb_ms,
        "unshaped_nar_bytes_compressed_wire_per_s": unshaped_rate,
        "shaped_nar_bytes_compressed_wire_per_s": shaped_rate,
        "shaped_over_cap_fraction": (
            shaped_rate / shaping.bandwidth_bytes_compressed_wire_per_s
        ),
        # HOW MUCH ROOM the anti-vacuity checks had. They only fire on a
        # catastrophically degraded channel (3x the cap, half the injected RTT),
        # so a host whose port forwarding drifted from 67x to 5x would still
        # pass - silently. Recording the margins makes that drift visible while
        # it is still passing, which is the only time it is cheap to notice.
        "control_headroom_rate_x_cap": (
            unshaped_rate / shaping.bandwidth_bytes_compressed_wire_per_s
        ),
        "control_headroom_latency_fraction_of_rtt": (
            unshaped_ms / shaping.rtt_ms if shaping.rtt_ms else None
        ),
        "negative_control": (
            "the unshaped numbers ARE the control: `shaping_violations` fails "
            "when they are not materially faster than the shaped ones, so a "
            "shaper that never fired cannot pass by looking like a slow channel"
        ),
    }


def assert_shaping(
    pod, fixtures, shaping: UpstreamShaping, condition: str, where: str
) -> dict:
    """Probe, JUDGE IMMEDIATELY, and raise on a bad verdict. Returns the evidence.

    Judging here rather than after the arm is the whole point: a shaper that
    failed to arm used to cost twenty container runs before anyone was told, in a
    module that moves every other precondition as early as it can reach. The
    verdict still comes from the pure `shaping_violations` - the probe measures,
    the pure function decides, and the self-test can break the decider.
    """
    evidence = probe_upstream_link(pod, fixtures, shaping)
    problems = shaping_violations(evidence, shaping)
    if problems:
        raise ValueError(
            f"upstream shaping NOT verified for condition {condition!r} at "
            f"{where}: " + "; ".join(problems)
        )
    return evidence


def measured_link_rate_violations(
    peers_off: dict, condition: str, shaping: UpstreamShaping | None
) -> list[str]:
    """PURE. Does the SCORED arm's own link rate agree with the condition it is
    labelled with? Empty == it does.

    The probe asserts the shaping on the HOST->proxy path at one instant. This
    asserts it on the path that was actually measured (daemon->proxy, in-pod)
    over the whole arm, using the testproxy's own per-record
    bytes_sent/duration_ms. Both a temporal gap and a path gap, closed with data
    the report already carries.

    The loopback CONTROL is checked too, and not as a formality: a control that
    quietly ran shaped would make the "ranking flipped" finding vanish, and that
    is the one claim this whole task exists to make.
    """
    problems: list[str] = []
    rate = (
        peers_off.get("upstream_nar_transport_bytes_compressed_wire_per_s") or {}
    ).get("mean")
    if rate is None:
        problems.append(
            "the scored peers-OFF arm produced NO upstream link rate, so the "
            "condition's label is not corroborated by the runs it names"
        )
        return problems
    if shaping is None:
        # An unshaped control must be FAST. Reuse the anti-vacuity floor: the
        # same number that says "this channel can tell shaped from unshaped".
        floor = (
            SHAPING_CONTROL_MIN_RATE_FACTOR * WAN_BANDWIDTH_BYTES_COMPRESSED_WIRE_PER_S
        )
        if rate < floor:
            problems.append(
                f"the {condition!r} arm is labelled UNSHAPED but its measured "
                f"link rate was only {rate:.0f} B(wire)/s, below the "
                f"{floor:.0f} B(wire)/s an unshaped loopback upstream must "
                "clear - the control may have been shaped, which would erase "
                "the very contrast this report claims"
            )
        return problems
    low, high = SHAPING_RATE_BAND
    cap = shaping.bandwidth_bytes_compressed_wire_per_s
    if not low * cap <= rate <= high * cap:
        problems.append(
            f"the {condition!r} arm's SCORED runs moved {rate:.0f} B(wire)/s at "
            f"the cache boundary, outside [{low * cap:.0f}, {high * cap:.0f}] "
            f"B(wire)/s for a {cap} B(wire)/s cap - the shaping verified at the "
            "probe did not hold over the runs that were actually measured"
        )
    return problems


def run_speedup_arms(  # noqa: C901 - two arms x two conditions reads flatter inline
    ctx,
    fixtures,
    runs: int,
    state_root: Path,
    *,
    condition: str,
    shaping: UpstreamShaping | None,
) -> dict:
    """peers-ON vs peers-OFF over the same workload, scored by the frozen rule,
    against ONE named upstream condition.

    The two arms are held IDENTICAL in everything the counting rule says must be
    identical: same client script, same knobs, same narinfo-cache configuration
    (both get a state dir), same payloads, same upstream shaping. The ONLY
    difference is whether a peer holds the NARs.

    `condition` names the upstream both arms face and travels into every speedup
    key. `shaping` is None for the loopback CONTROL - which is deliberately left
    byte-for-byte as it was, so its numbers stay comparable with the task-42
    baseline - and an `UpstreamShaping` for the WAN arm, where it is ARMED on
    both pods and ASSERTED from outside the shaper before any run is scored.
    """
    if condition not in UPSTREAM_CONDITIONS:
        raise ValueError(f"unknown upstream condition {condition!r}")
    if (shaping is None) != (condition == LOOPBACK_CONTROL):
        raise ValueError(
            f"condition {condition!r} and shaping {shaping!r} disagree: the "
            "loopback control is the unshaped condition and the WAN condition "
            "is the shaped one. A mislabelled arm is worse than no arm."
        )
    unit_evidence = assert_unit_coincidence(fixtures, SPEEDUP_ATTRS)
    targets = [fixtures.store_path(a) for a in SPEEDUP_ATTRS]
    wire_total = sum(int(fixtures.entry(a)["file_size"]) for a in SPEEDUP_ATTRS)
    nar_total = sum(int(fixtures.entry(a)["nar_size"]) for a in SPEEDUP_ATTRS)
    substituter = ctx.substituter_daemon_only()
    min_valid = min(runs, BASELINE_MIN_VALID_RUNS)

    # -- peers ON --
    on_runs: list[ProfileRun] = []
    # Runs in which the holder's OWN provider counter did NOT advance by the full
    # workload. Such a run is still VALID - its egress figure is real, and the
    # frozen counting rule already scores an upstream fallback as full egress -
    # but it means the peers-ON arm partly measured the peers-OFF path, and that
    # has to be visible rather than averaged into a comfortable offload number.
    on_shortfalls: list[dict] = []
    shaping_evidence: dict = {}
    scratch = ctx.scratch / f"speedup-seed-{condition}"
    seed_dir, seeds = e2e.build_p2p_seed_dir(fixtures, scratch, list(SPEEDUP_ATTRS))
    expected_served = sum(s.nar_size for s in seeds)
    try:
        with e2e.Pod(
            ctx,
            f"prof-speed-on-{condition}",
            fixtures.cache,
            with_daemon=False,
            expect=ss.silent_expect([]),
            p2p_seed_dir=seed_dir,
            p2p_seeds=seeds,
            state_root=state_root / f"speedup-on-{condition}",
        ) as pod:
            prewarm_upstream_cache(fixtures)
            if shaping is not None:
                shaping_evidence["peers_on_pod"] = assert_shaping(
                    pod, fixtures, shaping, condition, "peers_on_pod"
                )
            with ss.NodeSampler(pod, pod.roles()) as sampler:
                for index in range(runs):
                    print(
                        f"profile: speedup arm peers-ON run {index + 1}/{runs}",
                        file=sys.stderr,
                    )
                    pod.proxy_reset()
                    before = pod.node_b_served_bytes(want_at_least=1, timeout_s=0.5)
                    result, wall_s = _drive_one_client(
                        pod, substituter, fixtures.public_key, targets
                    )
                    after = pod.node_b_served_bytes(
                        want_at_least=before + expected_served
                    )
                    scored = score_run(
                        pod,
                        fixtures,
                        SPEEDUP_ATTRS,
                        result,
                        wall_s,
                        peer_served=after - before,
                    )
                    on_runs.append(scored)
                    if after - before < expected_served:
                        # Record the EGRESS beside the shortfall: it is the
                        # disambiguator between "the build really fell back to
                        # upstream" (full crossing) and "the holder's log monitor
                        # lagged our poll" (zero crossing). Without it the two
                        # are the same observation.
                        on_shortfalls.append(
                            {
                                "run": index,
                                "served_bytes_uncompressed_nar": after - before,
                                "expected_bytes_uncompressed_nar": expected_served,
                                "egress_nar_bytes_compressed_wire": (
                                    scored.egress_nar_bytes_compressed_wire
                                ),
                                "likely_cause": (
                                    "upstream fallback (payload crossed the cache "
                                    "boundary)"
                                    if scored.egress_nar_bytes_compressed_wire > 0
                                    else "holder log-monitor lag (nothing crossed "
                                    "the cache boundary, so a peer did serve it)"
                                ),
                            }
                        )
            on_resources = ss.aggregate_samples(sampler.samples, pod.daemon_roles())
            on_disk = {
                role: vars(dir_footprint(pod.state_dir(role)))
                for role in pod.daemon_roles()
            }
            on_sampler_errors = list(sampler.errors)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)

    # -- peers OFF (the contrast that falsifies a 0-egress claim) --
    off_runs: list[ProfileRun] = []
    with e2e.Pod(
        ctx,
        f"prof-speed-off-{condition}",
        fixtures.cache,
        with_daemon=True,
        expect=ss.silent_expect([]),
        state_root=state_root / f"speedup-off-{condition}",
    ) as pod:
        prewarm_upstream_cache(fixtures)
        if shaping is not None:
            shaping_evidence["peers_off_pod"] = assert_shaping(
                pod, fixtures, shaping, condition, "peers_off_pod"
            )
        with ss.NodeSampler(pod, pod.roles()) as sampler:
            for index in range(runs):
                print(
                    f"profile: speedup arm peers-OFF run {index + 1}/{runs}",
                    file=sys.stderr,
                )
                pod.proxy_reset()
                result, wall_s = _drive_one_client(
                    pod, substituter, fixtures.public_key, targets
                )
                off_runs.append(
                    score_run(
                        pod, fixtures, SPEEDUP_ATTRS, result, wall_s, peer_served=0
                    )
                )
        off_resources = ss.aggregate_samples(sampler.samples, pod.daemon_roles())
        off_disk = {
            role: vars(dir_footprint(pod.state_dir(role)))
            for role in pod.daemon_roles()
        }
        off_sampler_errors = list(sampler.errors)

    peers_on = summarize_profile_arm(
        "peers-on",
        on_runs,
        workload_bytes_compressed_wire=wire_total,
        workload_bytes_uncompressed_nar=nar_total,
        min_valid=min_valid,
    )
    peers_off = summarize_profile_arm(
        "peers-off",
        off_runs,
        workload_bytes_compressed_wire=wire_total,
        workload_bytes_uncompressed_nar=nar_total,
        min_valid=min_valid,
    )
    peers_on["resources"] = label_resources(on_resources)
    peers_off["resources"] = label_resources(off_resources)
    peers_on["disk"] = on_disk
    peers_off["disk"] = off_disk
    peers_on["peer_serve_shortfall_runs"] = on_shortfalls
    peers_on["peer_serve_shortfall_note"] = (
        "runs where node-b's own provider counter did not advance by the full "
        "workload. The runs stay VALID (the egress figure is real). Read each "
        "entry's `egress_nar_bytes_compressed_wire` to tell the two causes "
        "apart: a FULL crossing means the build really fell back to upstream, a "
        "ZERO crossing means the peer served it and only node-b's log monitor "
        "lagged the 5 s poll (node_b_served_bytes returns its best-so-far on "
        "timeout, with no signal that it timed out). Asserting 'fell back to "
        "upstream' from the shortfall alone would conflate the two."
    )
    # The 110 MiB payload is the bursty workload task-18 never had: this is where
    # the high-water/point-sample distinction gets exercised (or does not), and
    # where the in-RAM blob store's cost per held byte becomes a number.
    for arm, held, errors in (
        (peers_on, nar_total, on_sampler_errors),
        (peers_off, 0, off_sampler_errors),
    ):
        arm["high_water_vs_point_sample"] = hwm_vs_point_roles(
            arm["resources"]["per_role"], f"speedup arm {arm['arm']}, per role"
        )
        arm["held_content_ram_cost"] = held_content_ram_cost(
            arm["resources"]["per_role"], held
        )
        # Sampler errors were being COLLECTED and never consumed: an arm whose
        # /proc reads mostly failed still reported `usable: true`, with its RSS
        # aggregates computed from whatever survived. They invalidate the
        # RESOURCE claims specifically - the EGRESS claims come from the
        # testproxy and are untouched by a failed /proc read, so scoping the
        # damage is more honest than failing the whole arm.
        arm["sampler_errors"] = errors
        arm["resources_trustworthy"] = not errors
        if errors:
            arm["resources"]["WARNING"] = (
                f"{len(errors)} resource sample(s) FAILED; every RSS/fd figure "
                "in this block is computed from an incomplete sample and must "
                "not be quoted. The egress figures are unaffected (different "
                "instrument)."
            )
    # The CLOSING half of the shaping assertion. The probe (asserted at pod
    # creation, before any run) is a point-in-time claim about the HOST->proxy
    # path; the arm is then measured over ~10 minutes on the IN-POD daemon->proxy
    # path. Nothing so far rules out the shaping being disarmed in between, or
    # never having applied to the path that was actually scored.
    #
    # This closes both gaps with data already collected: the testproxy's own
    # per-record bytes_sent/duration_ms over the SCORED peers-OFF runs is a link
    # rate on the real path, and it must land in the same band the probe was held
    # to. Free, and it is an oracle over the measurement rather than beside it.
    link_problems = measured_link_rate_violations(peers_off, condition, shaping)
    if link_problems:
        raise ValueError(
            f"upstream shaping NOT sustained across the scored runs for "
            f"condition {condition!r}: " + "; ".join(link_problems)
        )

    return condition_block(
        condition,
        shaping,
        shaping_evidence,
        peers_on,
        peers_off,
        unit_evidence,
        runs,
    )


def condition_block(
    condition: str,
    shaping: UpstreamShaping | None,
    shaping_evidence: dict,
    peers_on: dict,
    peers_off: dict,
    unit_evidence: dict,
    runs: int,
) -> dict:
    """The report block for ONE upstream condition. PURE.

    Extracted so the container path and the self-test build the SAME shape. The
    self-test used to hand-roll its own version, which had already drifted by
    four keys - so the honesty gates were being proven against a shape the real
    run does not produce, and a new speedup-bearing key would have shipped green.
    """
    return {
        "ran": True,
        "upstream_condition": condition,
        "shaping": None if shaping is None else shaping.as_report(),
        "shaping_fidelity": None if shaping is None else shaping_fidelity_note(),
        "shaping_evidence": shaping_evidence or None,
        # HONEST about what this field is. On the PRODUCER side it can never be
        # False: every failed assertion raises, and fail-loud is the stronger
        # contract. It exists for the CONSUMER - `build_report`'s usability gate -
        # so that a report assembled from anything other than a clean run of
        # `run_speedup_arms` (a hand-edited file, an older schema, a future
        # caller that forgets to probe) cannot read as verified by omission. For
        # `loopback_control` it is True BY DEFINITION, not by measurement, and
        # `shaping_assertion_note` says which of the two it is.
        "shaping_asserted": True,
        "shaping_assertion_note": (
            "TRUE BY DEFINITION, not by measurement: the loopback CONTROL is "
            "unshaped, so there is nothing to assert"
            if shaping is None
            else "TRUE BY MEASUREMENT, twice: timed host-side outside the "
            "shaper, unshaped then shaped over the same channel, per request "
            "KIND (`shaping_evidence`); and again over the SCORED runs via the "
            "arm's own measured link rate at the cache boundary, which closes "
            "the gap between what the probe saw and what was measured. Either "
            "failure RAISES rather than setting this flag False"
        ),
        "prewarm_note": (
            "every payload in `attrs`, plus nix-cache-info, is pulled through "
            "the testproxy host-side before every arm in every condition, so no "
            "run carries an origin fetch the others do not"
        ),
        "attrs": list(SPEEDUP_ATTRS),
        "runs_requested": runs,
        "topology_note": (
            "The two arms are identical in everything the COUNTING RULE requires "
            "(client script, knobs, narinfo-cache config, payloads); only the "
            "presence of a holding peer differs. They are NOT identical in "
            "TOPOLOGY: peers-on runs two daemon processes (node-a + node-b), "
            "peers-off one. The egress comparison is therefore sound, but the "
            "`resources` blocks are NOT like-for-like - peers-on's per-peer "
            "figure is a max over two daemons, peers-off's over one."
        ),
        "peers_on": peers_on,
        "peers_off": peers_off,
        f"speedup_{condition}": speedup_block(
            peers_on, peers_off, unit_evidence, condition
        ),
    }


# The task-42 loopback numbers this task PINS as the control (AC#3). Kept as
# data, not prose, so the current run can be compared against them mechanically
# and any drift is visible instead of remembered. The suffix is not optional
# even here - `speedup_qualifier_violations` walks this block too.
PINNED_TASK42_CONTROL = {
    "source": "task-42 `just profile`, the run that motivated task-63",
    "upstream": (
        "in-pod testproxy on pod loopback: ~0 RTT, ~1 GB/s at the cache "
        "boundary. UNSHAPED - this "
        "is the control, not a user's cache"
    ),
    "realise_mean_peers_on_s": 0.562,
    "realise_mean_peers_off_s": 0.159,
    "latency_speedup_mean_loopback_control": 0.283,
    "reading": (
        "under loopback_control - and ONLY under loopback_control - peers "
        "measured 3.5x slower. TASK-64 root-caused it: the peer transport tops "
        "out at ~187-255 MB/s, so the deficit binds only against an upstream "
        "faster than that, which on this testbed is one machine nobody owns. "
        "The arm is retained because a zero-latency upstream is the only one "
        "that isolates the peer transport's own cost."
    ),
}


def cross_condition_block(by_condition: dict) -> dict:
    """State the two conditions side by side, and say whether the RANKING moved.

    This is the deliverable sentence of task-63, so it is computed rather than
    written: the reader should not have to divide two numbers from opposite ends
    of a JSON file to find out whether shaping the upstream changed the answer.
    """
    rows = {}
    for condition, block in sorted(by_condition.items()):
        if not isinstance(block, dict) or not block.get("ran"):
            rows[condition] = {
                "ran": False,
                "reason": (block or {}).get("reason", "not run"),
            }
            continue
        speed = block[f"speedup_{condition}"]
        key = f"latency_speedup_mean_{condition}"
        value = speed.get(key)
        rows[condition] = {
            "ran": True,
            "realise_mean_peers_on_s": speed["realise_mean_peers_on_s"],
            "realise_mean_peers_off_s": speed["realise_mean_peers_off_s"],
            key: value,
            "peers_faster": None if value is None else value > 1.0,
            "egress_offload_fraction": speed["egress_offload_fraction"],
            "upstream_link_rate_peers_off_bytes_compressed_wire_per_s": (
                block["peers_off"][
                    "upstream_nar_transport_bytes_compressed_wire_per_s"
                ]["mean"]
            ),
        }
    ranks = {c: r.get("peers_faster") for c, r in rows.items() if r.get("ran")}
    comparable = {c: v for c, v in ranks.items() if v is not None}
    distinct = set(comparable.values())
    # NOT a bare bool. With one condition left standing, `len(distinct) > 1` is
    # False - and "the ranking did not flip" is a claim about a comparison that
    # never happened. None says so; the summary prints it as not-comparable.
    flipped = len(distinct) > 1 if len(comparable) >= 2 else None
    return {
        "per_condition": rows,
        "conditions_compared": sorted(comparable),
        "ranking_flipped": flipped,
        "ranking_note": (
            "TRUE means the peer path wins under one upstream condition and "
            "loses under the other - i.e. the task-42 result was a property of "
            "the upstream, not of the peer transport. FALSE with both true "
            "means peers win either way; FALSE with both false means the peer "
            "path is genuinely behind even against a realistic upstream. NULL "
            "means fewer than two conditions produced a comparable number, so "
            "there was no comparison to flip - never read that as FALSE."
        ),
        "peer_side_link_rate": (
            "NOT measured by this instrument. The upstream link rate above is "
            "real (testproxy bytes_sent / duration_ms at the cache boundary); "
            "the peer side has no equivalent counter yet, so the honest "
            "comparison uses TASK-64's separate bench: ~187 MB/s for the "
            "product's full peer fetch path and ~255 MB/s for iroh-blobs alone, "
            "both LOOPBACK. TASK-68 owns closing this half."
        ),
        "pinned_task42_control": PINNED_TASK42_CONTROL,
    }


def run_speedup_conditions(
    ctx, fixtures, runs: int, state_root: Path, shaping: UpstreamShaping
) -> dict:
    """The speedup arm under EVERY upstream condition, indexed by condition.

    Sequential, not parallel: the instruments share one podman label and one set
    of published ports, and two conditions racing each other would measure the
    contention (TASK-58).
    """
    by_condition: dict = {}
    for condition in UPSTREAM_CONDITIONS:
        print(
            f"profile: speedup arm under upstream condition {condition!r}",
            file=sys.stderr,
        )
        try:
            by_condition[condition] = run_speedup_arms(
                ctx,
                fixtures,
                runs,
                state_root,
                condition=condition,
                shaping=None if condition == LOOPBACK_CONTROL else shaping,
            )
        except (RuntimeError, ss.SampleError, OSError, ValueError) as error:
            # Per-CONDITION containment, for the reason `main` states for the
            # whole arm: a later failure must not destroy an earlier
            # measurement. `loopback_control` runs first, so without this a WAN
            # shaping that failed to arm would discard ten minutes of valid
            # control runs and replace them with a repr(). The downstream code
            # already handles a non-ran condition everywhere - `build_report`
            # marks the report UNUSABLE, `cross_condition_block` reports it as
            # not comparable - and until now nothing at runtime could produce
            # that shape.
            print(
                f"profile: upstream condition {condition!r} FAILED: {error!r}",
                file=sys.stderr,
            )
            by_condition[condition] = {
                "ran": False,
                "upstream_condition": condition,
                "reason": f"{error!r}",
                "traceback": traceback.format_exc(),
            }
        except SystemExit as error:
            if error.code != 2:  # see sweep_swarm for the code-2 contract
                raise
            by_condition[condition] = {
                "ran": False,
                "upstream_condition": condition,
                "reason": f"aborted by the Pod seam (e2e.die, exit {error.code})",
            }
    return {
        "ran": True,
        "why_two_conditions": (
            "The owner goal names a speedup over cache.nixos.org, and the "
            "task-42 arm measured against an in-pod testproxy at ~0 RTT and "
            "~1 GB/s - a machine no user owns. Both are reported and neither "
            "may be quoted without its condition: `loopback_control` isolates "
            "the peer transport's own cost, `wan_shaped` answers the goal."
        ),
        "by_upstream_condition": by_condition,
        "cross_condition": cross_condition_block(by_condition),
    }


# ---- report assembly ---------------------------------------------------------

DISK_FINDING = {
    "measured": (
        "on-disk daemon state = a host-side walk of the directory bind-mounted "
        "as each node's --narinfo-cache-dir (the ONLY on-disk state a daemon "
        "keeps today)"
    ),
    "blob_store_is_in_ram": (
        "FINDING, not an omission: the iroh blob store is `MemStore` "
        "(daemon/src/transport_iroh.rs `IrohProvider::spawn`), so a holder's "
        "content costs RESIDENT MEMORY, not disk. There is no castore/on-disk "
        "blob store to measure in wave-2a. Read the per-peer RSS figure as the "
        "cost of held content, and the on-disk figure as metadata only."
    ),
    "consequence_for_scale": (
        "A peer's held-content budget is therefore bounded by RAM, not by disk. "
        "Any 1000-peer statement about DISK from this report is a statement "
        "about narinfo metadata only. Bounding the footprint is TASK-54."
    ),
}


def build_report(
    axis,
    speedup: dict | None,
    study: dict,
    provenance: dict,
    config: dict,
    targets,
    size: tuple[dict, dict, list[str]] | None = None,
) -> dict:
    """Assemble the report. PURE: takes collected measurements, touches nothing.

    Two independent honesty gates run on the assembled object and BOTH must come
    back empty: `scalefit.sweep_report_violations` (the S5 measured/model split,
    fit quality, red-flag coverage, the resource-laws-only caveat) and this
    module's `unit_violations` (no unlabelled byte quantity anywhere).
    """
    models: dict = {}
    problems: list[str] = []
    valid_points = sum(1 for p in axis.points if p.valid)
    distinct_valid = len({p.n for p in axis.points if p.valid})

    fits, fit_problems = ss.fit_axis(axis, SWARM_METRICS, targets)
    models.update(fits)
    problems += fit_problems
    # task-65: the size/concurrency arms arrive pre-assembled from `sizeaxis`
    # (measured, models, fit problems) so this function stays what it says it is -
    # pure assembly over collected measurements.
    size_measured, size_models, size_problems = size or ({}, {}, [])
    models.update(size_models)
    problems += size_problems

    measured = {
        "swarm": {
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
            "high_water_vs_point_sample": hwm_vs_point(axis.points),
            "observed_replicate_spread": replicate_spread(axis.points),
        }
    }
    measured.update(size_measured)
    if speedup is not None:
        measured["speedup"] = speedup

    red_flags = scalefit.red_flags_for(models)
    report = {
        "report_version": REPORT_VERSION,
        "profile_rule_version": PROFILE_RULE_VERSION,
        "fitter_version": scalefit.FITTER_VERSION,
        "counting_rule": {
            "rss": (
                "VmHWM (kernel peak RSS) is FITTED; VmRSS point samples reported "
                "beside it. Both host-side from /proc of the container init pid."
            ),
            "fds": "max entry count of /proc/<pid>/fd over the sampled ticks",
            "disk": DISK_FINDING["measured"],
            "latency": (
                "in-container `nix-store --realise` duration (REALISE_NS). The "
                "host-side podman wall clock is reported but NEVER fitted and "
                "never used in a speedup ratio: it carries container "
                "create/start/teardown, which itself scales with the swarm."
            ),
            "throughput": (
                "workload bytes / in-container realise seconds, per arm, in that "
                "arm's own unit"
            ),
            "egress": (
                "net-upstream-egress-v2, executed by measure.classify_run - the "
                "SAME frozen rule the wave-1 baseline used. A peer hit is a VALID "
                "zero-egress crossing when the client confirms delivery."
            ),
            "units": (
                "every `*_bytes` key carries one of "
                + ", ".join(UNIT_SUFFIXES)
                + ". NarSize (uncompressed, signed) and FileSize (compressed, "
                "on-wire) are DIFFERENT UNITS and are never compared; the speedup "
                "arm additionally ASSERTS file_size == nar_size for its payloads "
                "so the two coincide by checked precondition."
            ),
            "validity": (
                "a point with a failed client, an unreadable /proc, a missing "
                "in-container timing, or a holder that did not actually serve the "
                "workload is INVALID: excluded with a reason, never recorded as 0"
            ),
            "residency": (
                "task-65: what a holder HOLDS is read from its blob store "
                "(IROH-STORE-RESIDENT), never inferred from peak RSS. VmHWM is "
                "monotone so it can never observe a release, and glibc need not "
                "return a freed arena so VmRSS need not either - an RSS-only "
                "residency oracle fails on a correct fix and passes on a wrong "
                "one. Discrimination proven by mutation in "
                "daemon/tests/store_residency_oracle.rs"
            ),
            "size_axis_concurrency": (
                "task-65: k overlapping serves are counted from the HOLDER's own "
                "per-transfer windows (IROH-SERVE-WINDOW) and a point whose "
                "MEASURED overlap is not k is INVALID. Counting at the fetching "
                "HTTP client would be vacuous - k client windows overlap even if "
                "the daemon served them one at a time"
            ),
        },
        "disk_finding": DISK_FINDING,
        "provenance": provenance,
        "config": config,
        "caveat": scalefit.CAVEAT,
        "s9_bite": study,
        "measured": measured,
        "models": models,
        "red_flags": red_flags,
    }
    s5_violations = scalefit.sweep_report_violations(report)
    unit_problems = unit_violations(report)
    qualifier_problems = speedup_qualifier_violations(report)
    report["honesty"] = {
        "rules": (
            "TESTING.md S5 (a)-(d) via scalefit.sweep_report_violations, this "
            "module's unit rule via unit_violations, and task-63's "
            "upstream-condition rule via speedup_qualifier_violations over the "
            "JSON plus human_summary_violations over the printed text"
        ),
        "s5_violations": s5_violations,
        "unit_violations": unit_problems,
        "speedup_qualifier_violations": qualifier_problems,
        # The summary is generated FROM this report, so its gate belongs here
        # too. Judging it only in `main` left the persisted artifact - the thing
        # someone quotes months later - saying `compliant: true` while the
        # process exited 1, which is the failure mode this whole block exists to
        # prevent. It runs in a SECOND pass below, because the summary reads
        # `verdict`, which does not exist yet.
        "human_summary_violations": [],
        "compliant": not s5_violations and not unit_problems and not qualifier_problems,
    }
    # A speedup arm that RAISED is not a missing arm - it is a failed one, and
    # `usable` must say so. `speedup is None` means it was never asked for
    # (--skip-speedup), which is a different statement.
    speedup_usable = True
    speedup_dev_smoke = False
    if speedup is not None:
        if not speedup.get("ran"):
            speedup_usable = False
        else:
            conditions = speedup.get("by_upstream_condition") or {}
            if not conditions:
                speedup_usable = False
            for block in conditions.values():
                if not block.get("ran"):
                    speedup_usable = False
                    continue
                # EVERY condition must stand on its own. A usable loopback
                # control next to a WAN arm that failed its shaping assertion
                # would let the control be quoted as if the goal question had
                # been answered.
                speedup_usable = (
                    speedup_usable
                    and block["peers_on"]["usable"]
                    and block["peers_off"]["usable"]
                    and bool(block.get("shaping_asserted"))
                )
                # The frozen counting rule's SECTION 5 floor. An arm below it is
                # a dev smoke, and a report containing one must not read as
                # quotable: `dev_smoke_below_n10` existed but gated nothing, so
                # `--speedup-runs 3` produced `usable: true`.
                speedup_dev_smoke = (
                    speedup_dev_smoke
                    or block["peers_on"]["dev_smoke_below_n10"]
                    or block["peers_off"]["dev_smoke_below_n10"]
                )
    # task-65: an arm that ran and produced a report which cannot be quoted must
    # not be able to make the WHOLE profile read as quotable. A size arm that was
    # never asked for (`--skip-size`) is a different statement from one that ran
    # and failed, so the two are distinguished.
    size_ran = bool(size_measured)
    size_usable = True
    size_independence = (
        size_measured.get("size", {}).get("derived_quantity_independence", {})
        if size_ran
        else {}
    )
    if size_ran:
        size_usable = size_problems == [] and not size_independence.get(
            "algebraically_identical", False
        )
    report["verdict"] = {
        "size_axis_ran": size_ran,
        "size_axis_usable": size_usable,
        "size_axis_derived_quantity_independence": size_independence,
        "swarm_valid_observations": valid_points,
        "swarm_total_observations": len(axis.points),
        "swarm_distinct_valid_n": distinct_valid,
        "fit_problems": problems,
        "all_metrics_fitted": problems == [],
        "speedup_arms_usable": speedup_usable,
        "speedup_dev_smoke": speedup_dev_smoke,
        "honesty_compliant": report["honesty"]["compliant"],
        "red_flag_count": len(red_flags),
        # AC#2 travels WITH the report: a profile whose grid was too short to
        # demonstrate the S9 bite must not read as one that demonstrated it.
        "s9_bite_demonstrated": bool(study.get("ran")),
        # Derived from two measured blocks, so it cannot drift from them. NOT a
        # usability gate: a metric whose noise exceeds the demonstrated regime is
        # a finding about that metric, not a broken instrument.
        "bite_applicability": bite_applicability(
            study, measured["swarm"]["observed_replicate_spread"], models
        ),
        "usable": (
            problems == []
            and report["honesty"]["compliant"]
            and speedup_usable
            and not speedup_dev_smoke
            and size_usable
            and bool(study.get("ran"))
        ),
        "note": (
            "`usable` means THESE NUMBERS MAY BE QUOTED. It is about the "
            "INSTRUMENT: red flags are findings about the PRODUCT and do not "
            "make the profile unusable - they make it useful. A speedup arm "
            "below the frozen counting rule's 10-valid-run floor DOES make it "
            "unusable, because a dev smoke is not a baseline."
        ),
    }
    # SECOND PASS: the summary is rendered from the finished report, gated, and
    # the verdict is corrected in place. Ordered this way and not earlier
    # because `human_summary_lines` reads `verdict`; done at all because a
    # violation must be visible in the FILE, not only in the exit code.
    summary_problems = human_summary_violations(human_summary_lines(report))
    if summary_problems:
        report["honesty"]["human_summary_violations"] = summary_problems
        report["honesty"]["compliant"] = False
        report["verdict"]["honesty_compliant"] = False
        report["verdict"]["usable"] = False
    return report


def bite_applicability(study: dict, spread: dict, models: dict) -> dict:
    """Per fitted metric: is the REAL data inside the regime where the S9 bite
    was demonstrated?

    Without this the report states two true things far apart - "a known-O(n^2)
    law is never fitted linear at 2% noise" and "here is a fitted latency law" -
    and lets a reader join them. They do not always join: task-42's measured
    latency spread was 8-20% and even its RSS spread was 2-4%, while the
    linear-vs-superlinear split is demonstrated only up to 1% relative noise on
    this grid; that same latency axis selected THREE different classes across
    three runs. The
    number that saves a reader from the wrong conclusion is the comparison, so
    the report computes it instead of leaving it as an exercise.

    Derived, never stored: both inputs are measurements that already live in the
    report, so this cannot drift from them.
    """
    if not study.get("ran"):
        return {"available": False, "why": "the S9 study did not run on this grid"}
    # The regime is defined by the split TESTING.md S9 actually names:
    # LINEAR-vs-SUPERLINEAR, in BOTH directions. At noise v the bite holds iff
    # every superlinear generator is flagged superlinear at >= floor AND every
    # non-superlinear generator is NOT flagged at >= floor (i.e. the false-flag
    # rate stays below 1-floor). Deliberately NOT exact-class recovery: n log n
    # vs n^2 is not identifiable below n~30, and gating on that would declare the
    # instrument broken over a distinction it never claimed to make.
    floor = DISCRIMINATION_FLOOR
    # `study["per_class"]` is {class: {noise-as-string: row}}; every class was
    # studied at the same noise levels with the same replicate count, so one
    # class's rows describe the whole grid.
    any_class_rows = next(iter(study["per_class"].values()))
    noise_levels = sorted(float(key) for key in any_class_rows)
    replicates = max(1, any_class_rows[str(noise_levels[0])]["replicates"])
    # Clear the floor by two Monte-Carlo standard errors before declaring the
    # regime. `stable_seed` makes the measured rate reproducible, so this is NOT
    # about a number that flips between runs - it is about the rate being an
    # ESTIMATE: 120 replicates pin the true rate only to about +/-0.027, so a
    # measured 0.933 is consistent with a true rate below the 0.90 floor. The
    # margin errs toward NOT declaring a marginal regime, which is the direction
    # that cannot mislead. It does mean the EFFECTIVE requirement is ~0.955, not
    # 0.90, and `effective_threshold` reports that rather than leaving a reader
    # to infer the floor was the bar.
    margin = 2.0 * math.sqrt(floor * (1.0 - floor) / replicates)
    threshold = min(1.0, floor + margin)
    # CONTIGUOUS from the quietest level, and it STOPS at the first failure.
    # Discrimination degrades with noise, but nothing here enforces that, and
    # without the break a study that failed at 2% and passed at 5% (a
    # Monte-Carlo fluke, or a genuinely non-monotone selector) would report the
    # regime as 5% - claiming coverage over a gap it does not have.
    proven_to = None
    for noise in noise_levels:
        ok = True
        for model, rows in study["per_class"].items():
            rate = rows[str(noise)]["superlinear_rate"]
            if scalefit.BASIS_BY_NAME[model].superlinear:
                ok = ok and rate >= threshold
            else:
                ok = ok and (1.0 - rate) >= threshold
        if not ok:
            break
        proven_to = noise
    per_metric = {}
    for fit_id, fit in models.items():
        key = fit_id.split(".", 1)[-1]
        observed = (spread.get(key) or {}).get("median_relative_spread")
        if observed is None or proven_to is None:
            verdict = "unknown (no replicates at any n, or no proven regime)"
            inside = None
        elif observed <= proven_to:
            verdict = "inside the demonstrated regime"
            inside = True
        else:
            verdict = (
                "OUTSIDE the demonstrated regime - at this metric's observed "
                "noise the linear-vs-superlinear split is not demonstrated on "
                "this grid, so read `identifiable`, R^2 and the interval width; "
                "do NOT read the class name as a law"
            )
            inside = False
        per_metric[fit_id] = {
            "observed_median_relative_spread": observed,
            "identifiable": fit.get("identifiable"),
            "r_squared": fit.get("r_squared"),
            "inside_demonstrated_regime": inside,
            "verdict": verdict,
        }
    return {
        "available": True,
        "rule": (
            "the regime is the largest studied noise at which the "
            "LINEAR-vs-SUPERLINEAR split holds in BOTH directions at >= the "
            "floor: superlinear generators flagged, non-superlinear ones not"
        ),
        "discrimination_floor": floor,
        "monte_carlo_replicates": replicates,
        "effective_threshold": threshold,
        "threshold_note": (
            "floor + 2 Monte-Carlo standard errors, so a rate landing ON the "
            "floor does not make the declared regime flip between runs"
        ),
        "bite_demonstrated_up_to_relative_noise": proven_to,
        "studied_noise_levels": noise_levels,
        "per_metric": per_metric,
    }


def replicate_spread(points) -> dict:
    """The OBSERVED relative spread between replicates at the same n.

    This is what closes the loop on the S9 study: the study proves the bite at
    synthetic noise levels, and this says which noise level the REAL data sits
    at. A bite proven at 2% noise says nothing about data with 20% spread, and a
    report that does not put the two numbers next to each other is inviting that
    exact mistake.
    """
    out: dict = {}
    for key, _unit, _desc in SWARM_METRICS:
        by_n: dict[int, list[float]] = {}
        for point in points:
            if not point.valid:
                continue
            value = point.metrics.get(key)
            if value is None:
                continue
            by_n.setdefault(point.n, []).append(float(value))
        spreads = []
        for values in by_n.values():
            if len(values) < 2:
                continue
            mean = statistics.fmean(values)
            if mean:
                spreads.append(statistics.pstdev(values) / abs(mean))
        out[key] = {
            "n_groups_with_replicates": len(spreads),
            "median_relative_spread": statistics.median(spreads) if spreads else None,
            "max_relative_spread": max(spreads) if spreads else None,
        }
    return out


def provenance(fixtures, out_root: Path) -> dict:
    """What makes these numbers re-derivable. The HOST is part of a resource
    result, so it is recorded: a law measured on one machine does not transfer.

    FAIL-VERBOSE, not fail-silent: every lookup that can fail records WHY under
    `unavailable` instead of leaving a blank field. This is the one block whose
    entire job is re-derivability, so "unknown" quietly reading as "" is exactly
    the failure it must not have.
    """
    generation = fx.resolve_current(out_root)
    lock = json.loads((generation / "lock.json").read_text())
    unavailable: dict[str, str] = {}

    total_ram = None
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                total_ram = int(line.split()[1]) * 1024
    except OSError as error:
        unavailable["mem_total_bytes_ram"] = str(error)

    def git(*argv) -> str | None:
        try:
            result = subprocess.run(
                ["git", *argv],
                capture_output=True,
                text=True,
                check=False,
                cwd=str(fx.repo_root()),
            )
        except OSError as error:
            unavailable[f"git {' '.join(argv)}"] = str(error)
            return None
        if result.returncode != 0:
            unavailable[f"git {' '.join(argv)}"] = (
                f"exit {result.returncode}: {result.stderr.strip()}"
            )
            return None
        return result.stdout

    commit = git("rev-parse", "HEAD")
    dirty = git("status", "--porcelain")
    return {
        "workload_version": fixtures.manifest["workload_version"],
        "fixture_tier": fixtures.manifest["tier"],
        "fixture_public_key": lock["public_key"],
        "generation": generation.name,
        "swarm_attrs": list(SWARM_ATTRS),
        "speedup_attrs": list(SPEEDUP_ATTRS),
        "git_commit": None if commit is None else commit.strip(),
        # A commit hash alone does NOT describe the code that produced these
        # numbers when the tree is dirty - and `just profile` is normally run
        # from a dirty tree during development. Say which it was.
        "git_clean": None if dirty is None else dirty.strip() == "",
        "unavailable": unavailable,
        "host": {
            "kernel": os.uname().release,
            "machine": os.uname().machine,
            "cpu_count": os.cpu_count(),
            "mem_total_bytes_ram": total_ram,
            "note": (
                "a resource scaling law is a property of the system ON THIS HOST; "
                "the constants do not transfer to different hardware, though the "
                "growth CLASS usually does"
            ),
        },
    }


# ---- human summary -----------------------------------------------------------


def _mib(value) -> str:
    return "n/a" if value is None else f"{value / 1024**2:.1f} MiB"


def _rate(value) -> str:
    """A bytes/second figure in MB/s, or `n/a`. Unit-agnostic on purpose: the
    caller says which byte unit it is, because this cannot know."""
    return "n/a" if value is None else f"{value / 1e6:.1f} MB/s"


def _condition_speedup_lines(condition: str, block: dict) -> list[str]:
    """The per-condition speedup paragraph. Every claim line names its
    condition - not as courtesy, but because `human_summary_violations`
    rejects the summary otherwise (AC#2)."""
    lines: list[str] = []
    if not block.get("ran"):
        return [f"    [{condition}] arm did NOT run: {block.get('reason', 'unknown')}"]
    speed = block[f"speedup_{condition}"]
    lines.append(f"    -- upstream condition: {condition} --")
    shaping = block.get("shaping")
    if shaping:
        evidence = (block.get("shaping_evidence") or {}).get("peers_off_pod") or {}
        lines.append(
            f"       shaping injected: RTT {shaping['injected_rtt_ms']} ms, cap "
            f"{_rate(shaping['injected_bandwidth_bytes_compressed_wire_per_s'])}"
            " (wire)"
        )
        if evidence:
            recovered = (
                evidence["shaped_request_latency_median_ms"]
                - evidence["unshaped_request_latency_median_ms"]
            )
            lines.append(
                f"       shaping ASSERTED host-side: recovered RTT "
                f"{recovered:.1f} ms, achieved "
                f"{_rate(evidence['shaped_nar_bytes_compressed_wire_per_s'])}"
                f" (wire); unshaped control "
                f"{evidence['unshaped_request_latency_median_ms']:.1f} ms / "
                f"{_rate(evidence['unshaped_nar_bytes_compressed_wire_per_s'])}"
            )
    else:
        lines.append(
            "       unshaped by definition: ~0 RTT, no cap - the control that "
            "isolates the peer transport's own cost"
        )
    lines.append(
        f"       egress payload  peers-off "
        f"{speed['egress_payload_peers_off_bytes_compressed_wire']} B(wire) -> "
        f"peers-on {speed['egress_payload_peers_on_bytes_compressed_wire']} "
        f"B(wire)   offload={speed['egress_offload_fraction']}"
    )
    lines.append(
        f"       realise mean    peers-off {speed['realise_mean_peers_off_s']} s "
        f"-> peers-on {speed['realise_mean_peers_on_s']} s   "
        f"[{condition}] speedup={speed[f'latency_speedup_mean_{condition}']}"
    )
    lines.append(
        "       upstream link   peers-off "
        + _rate(
            block["peers_off"]["upstream_nar_transport_bytes_compressed_wire_per_s"][
                "mean"
            ]
        )
        + " (wire, testproxy bytes_sent/duration_ms - a REAL link rate)"
    )
    lines.append(
        "       realise rate    peers-on "
        + _rate(block["peers_on"]["realise_rate_bytes_uncompressed_nar_per_s"]["mean"])
        + "  peers-off "
        + _rate(block["peers_off"]["realise_rate_bytes_uncompressed_nar_per_s"]["mean"])
        + " (NarSize; NOT a transport rate - TASK-68)"
    )
    return lines


def human_summary_lines(report: dict) -> list[str]:  # noqa: C901 - a flat report
    """The human summary as DATA, so it can be gated before it is printed.

    Returning lines instead of printing them is what lets
    `human_summary_violations` run over the actual text a reader will see. A
    summary that is only checked by eye is the part of the report where a
    carefully-qualified JSON number turns back into a bare speedup.
    """
    lines = ["", "============== profile: HUMAN SUMMARY =============="]
    flags = report.get("red_flags", [])
    if flags:
        lines.append("")
        lines.append("  *** RED FLAGS - SUPERLINEAR RESOURCE GROWTH ***")
        for flag in flags:
            worst = flag.get("worst_extrapolation") or {}
            lines.append(
                f"    {flag['id']}: {flag['selected_label']}  "
                f"R^2={flag['r_squared']:.4f} identifiable={flag['identifiable']}"
            )
            if worst.get("point_estimate") is not None:
                lines.append(
                    f"      MODEL OUTPUT at n={worst.get('n')}: "
                    f"{worst['point_estimate']:.6g} {flag['unit']}"
                )
    else:
        lines.append("  red flags        : none (no superlinear fit)")

    swarm = report["measured"]["swarm"]
    valid = sum(1 for p in swarm["points"] if p["valid"])
    lines.append(
        f"  swarm axis       : {valid}/{len(swarm['points'])} valid over "
        f"{len(swarm['distinct_n'])} distinct n {swarm['distinct_n']}"
    )
    for point in swarm["points"]:
        if not point["valid"]:
            lines.append(f"      INVALID n={point['n']}: {point['reason']}")
    for point in swarm["points"]:
        if point["valid"]:
            m = point["metrics"]
            lines.append(
                f"      n={point['n']:<3} peer_rss_hwm={_mib(m['peer_rss_hwm_bytes_ram'])}"
                f"  swarm_total={_mib(m['swarm_total_rss_hwm_bytes_ram'])}"
                f"  fds={m['peer_fd_max']}"
                f"  disk={m['peer_disk_allocated_bytes_ondisk']} B"
                f"  realise={m['client_realise_s']}"
            )
    hwm = swarm["high_water_vs_point_sample"]
    lines.append(
        f"  VmHWM vs VmRSS   : separated at "
        f"{hwm['observations_where_hwm_exceeds_point_sample']}/"
        f"{hwm['observations']} swarm points, max gap "
        f"{_mib(hwm['max_gap_bytes_ram'])} (exercised={hwm['exercised']})"
    )

    speed = report["measured"].get("speedup")
    if speed and speed.get("ran"):
        for condition, block in sorted(speed["by_upstream_condition"].items()):
            if not block.get("ran"):
                continue
            for arm in (block["peers_on"], block["peers_off"]):
                gap = arm["high_water_vs_point_sample"]
                smoke = (
                    "  [DEV SMOKE, < 10 valid runs]"
                    if arm["dev_smoke_below_n10"]
                    else ""
                )
                lines.append(
                    f"  {arm['arm']}/{condition}: {arm['valid_runs']}/{arm['runs']}"
                    f" valid   VmHWM separated at "
                    f"{gap['observations_where_hwm_exceeds_point_sample']}/"
                    f"{gap['observations']} roles, max gap "
                    f"{_mib(gap['max_gap_bytes_ram'])}{smoke}"
                )
                shortfalls = arm.get("peer_serve_shortfall_runs")
                if shortfalls:
                    lines.append(
                        f"               WARNING: {len(shortfalls)} run(s) fell "
                        "back to upstream (holder counter did not advance) - "
                        "this arm partly measured the peers-OFF path"
                    )
                cost = arm["held_content_ram_cost"]
                if cost.get("measured"):
                    worst = max(
                        cost["per_role_peak_rss_ram_per_held_nar_byte_ratio"].items(),
                        key=lambda kv: kv[1],
                    )
                    lines.append(
                        f"               RAM per held NarSize byte: worst node "
                        f"{worst[0]} = {worst[1]:.2f}x (in-RAM blob store)"
                    )
        lines.append("")
        lines.append(
            "  SPEEDUP / OFFLOAD, PER UPSTREAM CONDITION (measured, frozen "
            "counting rule)."
        )
        lines.append(
            "  There is no such thing as 'the' speedup here: the number depends "
            "on which upstream"
        )
        lines.append(
            "  the peer path was raced against, so every ratio below carries "
            "its condition."
        )
        for condition, block in sorted(speed["by_upstream_condition"].items()):
            lines += _condition_speedup_lines(condition, block)
        cross = speed.get("cross_condition") or {}
        pinned = cross.get("pinned_task42_control") or {}
        if pinned:
            lines.append(
                f"    PINNED task-42 loopback_control: peers-on "
                f"{pinned['realise_mean_peers_on_s']} s vs peers-off "
                f"{pinned['realise_mean_peers_off_s']} s, "
                f"[loopback_control] speedup="
                f"{pinned['latency_speedup_mean_loopback_control']}"
            )
        if cross:
            flipped = cross.get("ranking_flipped")
            per = cross.get("per_condition") or {}
            if flipped is None:
                lines.append(
                    "    RANKING: NOT COMPARABLE - fewer than two upstream "
                    f"conditions produced a number (compared: "
                    f"{cross.get('conditions_compared')})"
                )
            else:
                verdict = []
                for condition in sorted(per):
                    faster = per[condition].get("peers_faster")
                    if faster is None:
                        continue
                    verdict.append(
                        f"the peer path is "
                        f"{'faster' if faster else 'slower'} under {condition}"
                    )
                lines.append(f"    RANKING: {'; '.join(verdict)}")
                lines.append(
                    f"    RANKING FLIPPED between upstream conditions: {flipped}"
                )

    lines.append("")
    lines.append("  MODELS (every number below is a MODEL OUTPUT, not a measurement):")
    for fit_id, fit in report["models"].items():
        far = fit["extrapolations"][-1]
        lines.append(
            f"    {fit_id:<48} {fit['selected_label']:<10} R^2={fit['r_squared']:.4f}"
        )
        lines.append(
            f"        n={far['n']}: {far['point_estimate']:.6g} {fit['unit']} "
            f"(95% CI {far['ci95_mean_response']})"
            + ("" if fit["identifiable"] else "  [class NOT identifiable]")
            + (
                "  [UNINFORMATIVE: interval crosses zero]"
                if far["interval_extends_below_zero"]
                else ""
            )
        )
        applicability = report["verdict"].get("bite_applicability", {})
        row = (applicability.get("per_metric") or {}).get(fit_id)
        if row and row.get("inside_demonstrated_regime") is False:
            lines.append(
                f"        NOISE: observed replicate spread "
                f"{row['observed_median_relative_spread']:.1%} exceeds the "
                f"{applicability['bite_demonstrated_up_to_relative_noise']:.0%} "
                "at which class recovery is demonstrated - do not read the "
                "class name as a law"
            )
    lines.append("")
    lines.append(
        "  CAVEAT: resource scaling laws only. Emergent network effects (DHT k-buckets,"
    )
    lines.append(
        "  gossip fan-out, thundering herds) are NOT predictable from this sweep."
    )
    lines.append(
        "  DISK: the iroh blob store is in RAM (MemStore) - held content costs "
        "RSS, not disk."
    )
    lines.append(
        "  UPSTREAM: the WAN arm shapes SERVICE LATENCY and EGRESS RATE, not a link: no"
    )
    lines.append(
        "  slow start and no receive-window-over-RTT ceiling, and the PEER side is not"
    )
    lines.append("  shaped at all (still pod loopback). See `shaping_fidelity`.")
    verdict = report["verdict"]
    lines.append("")
    lines.append(
        f"  VERDICT: usable={verdict['usable']} "
        f"(honesty_compliant={verdict['honesty_compliant']} "
        f"all_metrics_fitted={verdict['all_metrics_fitted']} "
        f"arms_usable={verdict['speedup_arms_usable']} "
        f"s9_bite_demonstrated={verdict['s9_bite_demonstrated']} "
        f"red_flags={verdict['red_flag_count']})"
    )
    if verdict.get("size_axis_ran"):
        lines += sz.human_lines(report["measured"], report["models"])
        lines.append("")
    for problem in verdict["fit_problems"]:
        lines.append(f"    PROBLEM: {problem}")
    for violation in (
        report["honesty"]["s5_violations"]
        + report["honesty"]["unit_violations"]
        + report["honesty"]["speedup_qualifier_violations"]
        + report["honesty"].get("human_summary_violations", [])
    ):
        lines.append(f"    HONESTY VIOLATION: {violation}")
    lines.append("====================================================")
    lines.append("")
    return lines


def print_human_summary(report: dict) -> list[str]:
    """Print the summary and return its lines, so the caller can gate them."""
    lines = human_summary_lines(report)
    for line in lines:
        print(line, file=sys.stderr)
    return lines


# ---- self-test (pure; no containers) ----------------------------------------


def _synthetic_swarm_axis(model: str, metric: str = "peer_rss_hwm_bytes_ram"):
    """A swarm axis whose points follow a KNOWN growth class."""
    axis = ss.Axis(name="swarm", variable="holders", description="synthetic")
    basis = scalefit.BASIS_BY_NAME[model]
    for n in DEFAULT_SWARM_SIZES:
        metrics = {
            "peer_rss_hwm_bytes_ram": 64.0e6,
            "peer_rss_point_max_bytes_ram": 64.0e6,
            "swarm_total_rss_hwm_bytes_ram": 64.0e6 * n,
            "peer_fd_max": 12.0 + n,
            "peer_disk_apparent_bytes_ondisk": 4096.0,
            "peer_disk_allocated_bytes_ondisk": 4096.0,
            "swarm_total_disk_allocated_bytes_ondisk": 4096.0 * n,
            "client_realise_s": 1.0 + 0.05 * n,
        }
        metrics[metric] = 64.0e6 + 2.0e6 * basis.transform(n)
        axis.points.append(ss.SweepPoint(n=n, valid=True, metrics=metrics))
    return axis


def _fake_run(**kwargs) -> ProfileRun:
    base = {
        "valid": True,
        "reason": "",
        "realise_s": 1.0,
        "wall_s": 2.0,
        "egress_nar_bytes_compressed_wire": 0,
        "egress_total_bytes_compressed_wire": 0,
        "peer_served_bytes_uncompressed_nar": 0,
        "upstream_nar_transport_bytes_compressed_wire_per_s": 100e6,
    }
    base.update(kwargs)
    return ProfileRun(**base)


# A shaping and a probe result that SHOULD pass, so every mutation below is a
# single-variable change away from a known-clean baseline. Numbers chosen to sit
# inside the bands with room, not on their edges - a baseline that only just
# passes turns every band change into a self-test failure and teaches nothing.
_SELF_TEST_SHAPING = UpstreamShaping(
    rtt_ms=50, bandwidth_bytes_compressed_wire_per_s=20 * 1024**2
)
_GOOD_SHAPING_EVIDENCE = {
    "measured_from": "self-test (synthetic)",
    "probe_payload_bytes_compressed_wire": 115_343_872,
    "latency_samples_per_state": SHAPING_LATENCY_SAMPLES,
    "unshaped_request_latency_median_ms": 1.4,
    "shaped_request_latency_median_ms": 53.0,
    "recovered_rtt_ms": 51.6,
    "unshaped_nar_first_byte_ms": 1.1,
    "shaped_nar_first_byte_ms": 54.2,
    "recovered_nar_rtt_ms": 53.1,
    "unshaped_nar_bytes_compressed_wire_per_s": 700e6,
    "shaped_nar_bytes_compressed_wire_per_s": 20.5e6,
    "shaped_over_cap_fraction": 20.5e6 / (20 * 1024**2),
    "negative_control": "self-test (synthetic)",
}


def run_self_test() -> int:  # noqa: C901 - a flat list of checks reads better here
    """Pure tests of this instrument's logic: the unit gate, the S9 class-recovery
    bite, disk walking, arm scoring, report assembly and the honesty wiring. No
    containers, no nix - runs in the FAST `just test` tier.

    Every rule is proven by MUTATION: break it, watch the gate go red.
    """
    ok = True

    def check(name: str, cond: bool, detail: str = "") -> None:
        nonlocal ok
        ok = ok and bool(cond)
        print(
            f"  {'PASS' if cond else 'FAIL'}  {name}"
            + (f"  [{detail}]" if not cond and detail else "")
        )

    print("profile_p2p --self-test")

    # --- the unit gate (the NarSize-vs-FileSize trap, made mechanical) -------
    print("\n  -- unit discipline --")
    check(
        "a unit-suffixed byte key passes",
        unit_violations({"peer_rss_hwm_bytes_ram": 1}) == [],
    )
    for suffix in UNIT_SUFFIXES:
        check(
            f"suffix {suffix} is accepted",
            unit_violations({f"x{suffix}": 1}) == [],
        )
    check(
        "MUTATION: a bare `_bytes` key is REJECTED",
        unit_violations({"egress_bytes": 1}) != [],
    )
    check(
        "MUTATION: a bare `_bytes` key nested in a list is REJECTED",
        unit_violations({"arms": [{"served_bytes": 1}]}) != [],
    )
    check(
        "the violation names the offending path",
        "arms[0].served_bytes" in unit_violations({"arms": [{"served_bytes": 1}]})[0],
        str(unit_violations({"arms": [{"served_bytes": 1}]})),
    )
    check(
        "a non-byte key is untouched",
        unit_violations({"client_realise_s": 1, "fd_max": 3}) == [],
    )
    # The rule must cover what a WRITER CAN SPELL, not just the suffix shape the
    # implementation happened to test. Every name below passed the earlier
    # endswith-only version CLEAN - `bytes_sent` is a real key in this codebase
    # (Pod.proxy_stats), so it was one copy-paste from the report. That is the
    # vacuous-oracle species: mutations chosen to match the code rather than the
    # claim.
    for spelling in (
        "bytes_sent",
        "egress_bytes_total",
        "total_bytes_moved",
        "free_disk_bytes_ondisk_at_start",
        "throughput_bytes_per_s",
        "x_bytes_ram_extra",
        "bytes",
    ):
        check(
            f"MUTATION: `{spelling}` is REJECTED (bytes named anywhere, not just "
            "as a suffix)",
            unit_violations({spelling: 1}) != [],
        )
    check(
        "a rate key keeps its unit through `_per_s`",
        unit_violations({"throughput_bytes_uncompressed_nar_per_s": 1}) == [],
    )
    check(
        "a word merely CONTAINING 'bytes' is not a byte key",
        unit_violations({"bytesize_note": "x"}) == [],
    )

    # unit coincidence precondition, proven both ways with a fake fixture set.
    class _Fixtures:
        def __init__(self, entries):
            self._entries = entries

        def entry(self, attr):
            return self._entries[attr]

    same = _Fixtures(
        {"lib": {"compression": "none", "file_size": 66048, "nar_size": 66048}}
    )
    diff = _Fixtures({"app": {"compression": "xz", "file_size": 260, "nar_size": 408}})
    evidence = assert_unit_coincidence(same, ["lib"])
    check(
        "coincidence holds for a `compression: none` payload",
        evidence["lib"]["coincide"],
    )
    raised = False
    try:
        assert_unit_coincidence(diff, ["app"])
    except ValueError:
        raised = True
    check(
        "MUTATION: a COMPRESSED payload makes the speedup arm REFUSE to run "
        "(wire != NarSize)",
        raised,
    )

    # --- the S9 bite: class recovery, MEASURED ------------------------------
    print("\n  -- S9 bite: known-class recovery on the real grid --")
    study = class_recovery_study(
        DEFAULT_SWARM_SIZES,
        repeats=DEFAULT_REPEATS,
        replicates=STUDY_REPLICATES,
        noise_levels=STUDY_NOISE_LEVELS,
    )
    gate = str(STUDY_GATE_NOISE)
    for model, floor in GATE_EXACT_RATE.items():
        rate = study["per_class"][model][gate]["exact_rate"]
        check(
            f"known-{scalefit.BASIS_BY_NAME[model].label} generator recovers "
            f"{model} at >= {floor} (measured {rate:.3f})",
            rate >= floor,
            f"{rate:.3f} < {floor}",
        )
    for model, floor in GATE_SUPERLINEAR_RATE.items():
        row = study["per_class"][model][gate]
        check(
            f"known-{scalefit.BASIS_BY_NAME[model].label} generator is flagged "
            f"SUPERLINEAR at >= {floor} (measured {row['superlinear_rate']:.3f})",
            row["superlinear_rate"] >= floor,
            f"{row['superlinear_rate']:.3f} < {floor}",
        )
    quad = study["per_class"]["quadratic"][gate]
    check(
        "THE BITE: a known-O(n^2) generator is NEVER fitted as linear "
        f"(linear_rate={quad['linear_rate']:.3f})",
        quad["linear_rate"] == 0.0,
        f"{quad['linear_rate']:.3f} != 0",
    )
    # The two ERROR rates, now GATED rather than merely printed. They are the
    # rates scalefit's `superlinear = basis AND slope > 0` change moves, so
    # leaving them ungated meant nothing watched the metric most exposed to that
    # change: a regression doubling the false-flag rate would have shipped green.
    lin = study["per_class"]["linear"][gate]
    check(
        f"a genuinely LINEAR law is falsely flagged superlinear at most "
        f"{GATE_MAX_FALSE_SUPERLINEAR_RATE} (measured "
        f"{lin['superlinear_rate']:.3f}) - crying wolf makes a real flag "
        "ignorable",
        lin["superlinear_rate"] <= GATE_MAX_FALSE_SUPERLINEAR_RATE,
        f"{lin['superlinear_rate']:.3f}",
    )
    worst_noise = str(max(STUDY_NOISE_LEVELS))
    worst_nlogn = study["per_class"]["linearithmic"][worst_noise]
    check(
        f"O(n log n) is mistaken for LINEAR at most "
        f"{GATE_MAX_SUPERLINEAR_AS_LINEAR_RATE} even at the worst studied noise "
        f"{worst_noise} (measured {worst_nlogn['linear_rate']:.3f}) - this is the "
        "discrimination limit of this grid, and it must not silently worsen",
        worst_nlogn["linear_rate"] <= GATE_MAX_SUPERLINEAR_AS_LINEAR_RATE,
        f"{worst_nlogn['linear_rate']:.3f}",
    )

    # The guard is caught rather than let-crash on purpose: a mutation that
    # removes it makes `fit_scaling` RAISE, and a self-test that dies with a
    # traceback is red but does not NAME what broke. An oracle that cannot say
    # what it caught is half an oracle.
    try:
        short = class_recovery_study(
            (1, 2), repeats=DEFAULT_REPEATS, replicates=5, noise_levels=(0.02,)
        )
    except scalefit.FitError as error:
        short = {"ran": None, "reason": f"raised instead of failing closed: {error}"}
    check(
        "a grid below MIN_POINTS demonstrates NO bite and says so (fail-closed, "
        "not a crash)",
        short.get("ran") is False and "MIN_POINTS" in short.get("reason", ""),
        str(short)[:200],
    )
    short_report = build_report(
        _synthetic_swarm_axis("linear"),
        None,
        short,
        {"workload_version": "t", "fixture_tier": "full", "host": {}},
        {"self_test": True},
        (10,),
    )
    check(
        "MUTATION: a report whose S9 bite did not run is UNUSABLE, and says so "
        "in the verdict",
        not short_report["verdict"]["usable"]
        and short_report["verdict"]["s9_bite_demonstrated"] is False,
        str(short_report["verdict"]),
    )

    # wrong-model rule, both directions.
    check(
        "wrong_model_failures: matching classes produce no failure",
        wrong_model_failures([("linear", "linear"), ("constant", "constant")]) == [],
    )
    check(
        "MUTATION: a superlinear generator reported LINEAR is a WRONG MODEL",
        wrong_model_failures([("quadratic", "linear")]) != [],
    )
    check(
        "MUTATION: a linear generator reported quadratic is a WRONG MODEL",
        wrong_model_failures([("linear", "quadratic")]) != [],
    )
    check(
        "n log n vs n^2 is NOT a wrong model (not identifiable below n~30)",
        wrong_model_failures([("linearithmic", "quadratic")]) == [],
    )
    check(
        "an unknown generated class is itself a failure (fail-closed)",
        wrong_model_failures([("cubic", "linear")]) != [],
    )
    # End-to-end: fit each synthetic axis and run the wrong-model rule on the
    # ACTUAL selections, which is the AC#2 sentence made executable.
    cases = []
    for model in ("constant", "linear", "linearithmic", "quadratic"):
        axis = _synthetic_swarm_axis(model)
        fits, _ = ss.fit_axis(axis, SWARM_METRICS, (10, 100, 1000))
        cases.append((model, fits["swarm.peer_rss_hwm_bytes_ram"]["selected_model"]))
    failures = wrong_model_failures(cases)
    check(
        "end-to-end: every known-class swarm axis selects a class in its own "
        f"family {cases}",
        failures == [],
        str(failures),
    )

    # --- disk footprint ------------------------------------------------------
    print("\n  -- disk footprint (host-side walk) --")
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "sub").mkdir()
        (root / "sub" / "a.json").write_bytes(b"x" * 1000)
        (root / "b.json").write_bytes(b"y" * 10)
        footprint = dir_footprint(root)
        check("apparent size sums file sizes", footprint.apparent_bytes_ondisk == 1010)
        check("file count is recursive", footprint.file_count == 2)
        check(
            "allocated size is block-rounded and >= apparent here",
            footprint.allocated_bytes_ondisk >= footprint.apparent_bytes_ondisk,
            f"{footprint.allocated_bytes_ondisk} vs {footprint.apparent_bytes_ondisk}",
        )
        empty = root / "empty"
        empty.mkdir()
        check(
            "an empty dir is 0 bytes, not an error",
            dir_footprint(empty).file_count == 0,
        )
    raised = False
    try:
        dir_footprint(Path("/nonexistent-profile-p2p-path"))
    except ss.SampleError:
        raised = True
    check(
        "MUTATION: a MISSING measurement point raises, never reads as 0 bytes",
        raised,
    )

    # --- arm scoring + the cross-unit trap ----------------------------------
    print("\n  -- speedup arm scoring --")
    on = summarize_profile_arm(
        "peers-on",
        [
            _fake_run(
                realise_s=2.0,
                egress_nar_bytes_compressed_wire=0,
                peer_served_bytes_uncompressed_nar=115_343_872,
            )
            for _ in range(10)
        ],
        workload_bytes_compressed_wire=115_343_872,
        workload_bytes_uncompressed_nar=115_343_872,
        min_valid=10,
    )
    off = summarize_profile_arm(
        "peers-off",
        [
            _fake_run(realise_s=4.0, egress_nar_bytes_compressed_wire=115_343_872)
            for _ in range(10)
        ],
        workload_bytes_compressed_wire=115_343_872,
        workload_bytes_uncompressed_nar=115_343_872,
        min_valid=10,
    )
    check("an arm at the floor is usable", on["usable"] and off["usable"])
    block = speedup_block(on, off, {"lib": {"coincide": True}}, WAN_SHAPED)
    check(
        "a full peer hit is a 100% egress offload",
        block["egress_offload_fraction"] == 1.0,
        str(block["egress_offload_fraction"]),
    )
    check(
        "latency speedup is a ratio of IN-CONTAINER seconds (4.0/2.0 = 2.0)",
        block[f"latency_speedup_mean_{WAN_SHAPED}"] == 2.0,
        str(block[f"latency_speedup_mean_{WAN_SHAPED}"]),
    )
    check(
        "the speedup key CARRIES its upstream condition, so a loopback ratio "
        "and a WAN ratio cannot be spelled the same (task-63 AC#2)",
        f"latency_speedup_mean_{WAN_SHAPED}" in block
        and "latency_speedup_mean" not in block,
        str(sorted(k for k in block if "speedup" in k)),
    )
    control_block = speedup_block(
        on, off, {"lib": {"coincide": True}}, LOOPBACK_CONTROL
    )
    check(
        "the loopback CONTROL block is keyed differently from the WAN one",
        f"latency_speedup_mean_{LOOPBACK_CONTROL}" in control_block
        and f"latency_speedup_mean_{WAN_SHAPED}" not in control_block,
        str(sorted(k for k in control_block if "speedup" in k)),
    )
    unnamed = False
    try:
        speedup_block(on, off, {}, "some-upstream-i-did-not-name")
    except ValueError:
        unnamed = True
    check(
        "MUTATION: an UNNAMED upstream condition is REFUSED, not silently "
        "suffixed (that is how an unqualified number gets born)",
        unnamed,
    )
    check(
        "the realise rate says in its own key that it is a realise rate, and a "
        "REAL transport rate sits beside it (TASK-68)",
        "realise_rate_bytes_uncompressed_nar_per_s" in off
        and "throughput_bytes_uncompressed_nar_per_s" not in off
        and "upstream_nar_transport_bytes_compressed_wire_per_s" in off,
        str(sorted(k for k in off if k.endswith("_per_s"))),
    )
    # THE cross-unit trap, proven: make the peer-served (NarSize) figure absurdly
    # large and assert the offload fraction does NOT move. If NarSize had leaked
    # into the wire-unit ratio it would.
    on_inflated = json.loads(json.dumps(on))
    on_inflated["peer_served_bytes_uncompressed_nar"]["mean"] = 999_999_999_999
    inflated = speedup_block(on_inflated, off, {"lib": {"coincide": True}}, WAN_SHAPED)
    check(
        "MUTATION: inflating the NarSize-unit peer-served figure does NOT move "
        "the wire-unit offload fraction (no cross-unit leak)",
        inflated["egress_offload_fraction"] == block["egress_offload_fraction"],
        f"{inflated['egress_offload_fraction']} vs {block['egress_offload_fraction']}",
    )
    observed_range = block[f"latency_speedup_observed_range_{WAN_SHAPED}"]
    check(
        "the speedup ratio carries the range the runs actually spanned "
        "(not a bare point estimate)",
        isinstance(observed_range, dict)
        and observed_range.get("worst_case") == 2.0
        and observed_range.get("best_case") == 2.0,
        f"got {observed_range!r} - a bare ratio with no dispersion is the one "
        "number a reader quotes and the one you cannot defend",
    )
    spread_on = summarize_profile_arm(
        "peers-on",
        [_fake_run(realise_s=t) for t in [1.0, 2.0, 3.0] * 4],
        workload_bytes_compressed_wire=1,
        workload_bytes_uncompressed_nar=1,
        min_valid=10,
    )
    spread_range = speedup_block(spread_on, off, {}, WAN_SHAPED)[
        f"latency_speedup_observed_range_{WAN_SHAPED}"
    ]
    check(
        f"a noisy peers-ON arm widens that range instead of hiding the noise "
        f"({spread_range})",
        isinstance(spread_range, dict)
        and spread_range["worst_case"] < spread_range["best_case"],
    )

    starved = summarize_profile_arm(
        "peers-on",
        [_fake_run(valid=False, reason="client exit 1") for _ in range(10)],
        workload_bytes_compressed_wire=1,
        workload_bytes_uncompressed_nar=1,
        min_valid=10,
    )
    check("an arm with no valid runs is UNUSABLE", not starved["usable"])
    check(
        "and its reasons are kept, not dropped",
        len(starved["invalid_runs"]) == 10,
    )

    # --- report assembly + both honesty gates -------------------------------
    print("\n  -- report assembly + honesty gates --")
    prov = {"workload_version": "test", "fixture_tier": "full", "host": {}}
    config = {"self_test": True}

    def _condition_arm(condition: str) -> dict:
        """Build a condition block through the SAME factory the container path
        uses, so the honesty gates are proven against the shape that actually
        ships rather than a hand-rolled lookalike."""
        shaping = None if condition == LOOPBACK_CONTROL else _SELF_TEST_SHAPING
        # The two per-arm blocks the container path attaches after scoring; the
        # summary reads them, so a synthetic arm without them would only prove
        # the report assembles, not that it PRINTS.
        arms = {}
        for name in ("peers_on", "peers_off"):
            arm = json.loads(json.dumps(on if name == "peers_on" else off))
            arm["high_water_vs_point_sample"] = hwm_vs_point_roles(
                {"node-a": {"rss_hwm_bytes_ram": 300, "rss_point_max_bytes_ram": 100}},
                f"self-test {name}",
            )
            arm["held_content_ram_cost"] = held_content_ram_cost(
                {"node-a": {"rss_hwm_bytes_ram": 300}},
                100 if name == "peers_on" else 0,
            )
            arms[name] = arm
        return condition_block(
            condition,
            shaping,
            {} if shaping is None else {"peers_off_pod": dict(_GOOD_SHAPING_EVIDENCE)},
            arms["peers_on"],
            arms["peers_off"],
            {"lib": {"coincide": True}},
            10,
        )

    by_condition = {c: _condition_arm(c) for c in UPSTREAM_CONDITIONS}
    speedup_measured = {
        "ran": True,
        "by_upstream_condition": by_condition,
        "cross_condition": cross_condition_block(by_condition),
    }
    linear = _synthetic_swarm_axis("linear")
    report = build_report(
        linear, speedup_measured, study, prov, config, (10, 100, 1000)
    )
    check(
        "assembled report is honesty-COMPLIANT (S5 + units + condition labels)",
        report["honesty"]["compliant"],
        str(
            report["honesty"]["s5_violations"]
            + report["honesty"]["unit_violations"]
            + report["honesty"]["speedup_qualifier_violations"]
        ),
    )

    # --- task-63: the shaping assertion, proven to BITE by mutation ----------
    print("\n  -- upstream shaping: the assertion, and its bite --")
    check(
        "a probe that recovered the injected RTT and hit the cap is CLEAN",
        shaping_violations(_GOOD_SHAPING_EVIDENCE, _SELF_TEST_SHAPING) == [],
        str(shaping_violations(_GOOD_SHAPING_EVIDENCE, _SELF_TEST_SHAPING)),
    )
    # THE mutation the whole task turns on: the shaping was never applied, so
    # the shaped observations equal the unshaped ones. A checker that passes
    # here would confirm any shaping at all, including none.
    never_applied = dict(_GOOD_SHAPING_EVIDENCE)
    for shaped_key, unshaped_key in (
        ("shaped_request_latency_median_ms", "unshaped_request_latency_median_ms"),
        ("shaped_nar_first_byte_ms", "unshaped_nar_first_byte_ms"),
        (
            "shaped_nar_bytes_compressed_wire_per_s",
            "unshaped_nar_bytes_compressed_wire_per_s",
        ),
    ):
        never_applied[shaped_key] = never_applied[unshaped_key]
    problems = shaping_violations(never_applied, _SELF_TEST_SHAPING)
    check(
        "MUTATION: the shaping was NEVER APPLIED (shaped == unshaped) -> the "
        "assertion goes RED and NAMES every failure",
        len(problems) == 3
        and sum("RTT NOT recovered" in p for p in problems) == 2
        and any("bandwidth cap NOT achieved" in p for p in problems),
        str(problems),
    )
    # The narinfo kind armed, the NAR kind not. The dominant request in the arm
    # is the NAR, so a probe that only ever timed narinfos would call this shaped.
    nar_kind_missed = dict(_GOOD_SHAPING_EVIDENCE)
    nar_kind_missed["shaped_nar_first_byte_ms"] = nar_kind_missed[
        "unshaped_nar_first_byte_ms"
    ]
    check(
        "MUTATION: latency armed on narinfo but NOT on the NAR kind -> REJECTED, "
        "and the failure NAMES the NAR (per-kind, not one blanket check)",
        any(
            "NAR first byte" in p and "NOT recovered" in p
            for p in shaping_violations(nar_kind_missed, _SELF_TEST_SHAPING)
        ),
        str(shaping_violations(nar_kind_missed, _SELF_TEST_SHAPING)),
    )
    latency_only = dict(_GOOD_SHAPING_EVIDENCE)
    latency_only["shaped_nar_bytes_compressed_wire_per_s"] = 700e6
    check(
        "MUTATION: RTT injected but the bandwidth cap did not fire -> REJECTED, "
        "with only the bandwidth named (the checks are independent)",
        [p for p in shaping_violations(latency_only, _SELF_TEST_SHAPING) if "cap" in p]
        and not [
            p
            for p in shaping_violations(latency_only, _SELF_TEST_SHAPING)
            if "RTT" in p
        ],
        str(shaping_violations(latency_only, _SELF_TEST_SHAPING)),
    )
    # The anti-vacuity half: a channel already slower than the shaping would let
    # a dead shaper pass. It must be a NAMED failure, not a silent success.
    slow_channel = dict(_GOOD_SHAPING_EVIDENCE)
    slow_channel["unshaped_nar_bytes_compressed_wire_per_s"] = 21e6
    check(
        "MUTATION: the unshaped CONTROL is no faster than the cap -> VACUOUS "
        "PROBE, named and rejected (a slow channel must not pass as a shaper)",
        any(
            "VACUOUS PROBE" in p
            for p in shaping_violations(slow_channel, _SELF_TEST_SHAPING)
        ),
        str(shaping_violations(slow_channel, _SELF_TEST_SHAPING)),
    )
    slow_unshaped_latency = dict(_GOOD_SHAPING_EVIDENCE)
    slow_unshaped_latency["unshaped_request_latency_median_ms"] = 40.0
    slow_unshaped_latency["shaped_request_latency_median_ms"] = 90.0
    check(
        "MUTATION: an unshaped control already costing most of the injected RTT "
        "-> VACUOUS PROBE, even though the delta itself looks right",
        any(
            "VACUOUS PROBE" in p
            for p in shaping_violations(slow_unshaped_latency, _SELF_TEST_SHAPING)
        ),
        str(shaping_violations(slow_unshaped_latency, _SELF_TEST_SHAPING)),
    )
    missing = dict(_GOOD_SHAPING_EVIDENCE)
    missing.pop("shaped_nar_bytes_compressed_wire_per_s")
    check(
        "MUTATION: a probe MISSING a measurement is a failure, not a skip "
        "(unmeasured != asserted)",
        any(
            "missing a usable" in p
            for p in shaping_violations(missing, _SELF_TEST_SHAPING)
        ),
        str(shaping_violations(missing, _SELF_TEST_SHAPING)),
    )
    unverified = json.loads(json.dumps(speedup_measured))
    unverified["by_upstream_condition"][WAN_SHAPED]["shaping_asserted"] = False
    check(
        "MUTATION: a WAN arm whose shaping was NOT asserted makes the whole "
        "report UNUSABLE (an unverified shaper may not be quoted)",
        not build_report(linear, unverified, study, prov, config, (10, 100, 1000))[
            "verdict"
        ]["usable"],
    )

    # --- task-63 AC#2: no unqualified speedup, in JSON or in the summary -----
    print("\n  -- AC#2: every speedup names its upstream condition --")
    check(
        "the two-condition report passes the qualifier gate",
        speedup_qualifier_violations(report) == [],
        str(speedup_qualifier_violations(report)),
    )
    bare = json.loads(json.dumps(report))
    bare["measured"]["speedup"]["by_upstream_condition"][WAN_SHAPED][
        f"speedup_{WAN_SHAPED}"
    ]["latency_speedup_mean"] = 6.1
    check(
        "MUTATION: a BARE `latency_speedup_mean` anywhere in the speedup subtree "
        "-> REJECTED (task-63 AC#2)",
        speedup_qualifier_violations(bare) != [],
        str(speedup_qualifier_violations(bare)),
    )
    dropped = json.loads(json.dumps(report))
    dropped["measured"]["speedup"]["by_upstream_condition"].pop(WAN_SHAPED)
    check(
        "MUTATION: dropping the WAN arm and keeping only the nicely-suffixed "
        "loopback CONTROL -> REJECTED (the control alone is not the goal answer)",
        speedup_qualifier_violations(dropped) != [],
        str(speedup_qualifier_violations(dropped)),
    )
    unindexed = json.loads(json.dumps(report))
    unindexed["measured"]["speedup"].pop("by_upstream_condition")
    check(
        "MUTATION: a speedup report with no by-condition index -> REJECTED",
        speedup_qualifier_violations(unindexed) != [],
    )
    # The gate reads PROSE, not just keys. A ranking claim in a free-text field
    # is the same claim; the key rule could not see it, and the summary rule
    # would have rejected the identical sentence.
    prose = json.loads(json.dumps(report))
    prose["measured"]["speedup"]["cross_condition"]["pinned_task42_control"][
        "reading"
    ] = "peers measured 3.5x SLOWER than a zero-latency upstream"
    check(
        "MUTATION: a RANKING CLAIM in prose, naming no condition and under no "
        "condition-named path -> REJECTED (one rule, both gates)",
        any("prose states a speedup" in v for v in speedup_qualifier_violations(prose)),
        str(speedup_qualifier_violations(prose)),
    )
    check(
        "and a claim nested UNDER a condition-named path is already qualified, "
        "so the per-condition caveats do NOT trip it",
        speedup_qualifier_violations(report) == [],
    )
    camel = json.loads(json.dumps(report))
    camel["measured"]["speedup"]["by_upstream_condition"][WAN_SHAPED][
        "speedupRatio"
    ] = 9.5
    check(
        "MUTATION: a speedup key that does not tokenise on underscores "
        "(`speedupRatio`) -> still REJECTED",
        speedup_qualifier_violations(camel) != [],
    )

    # --- task-63: the ranking claim, and refusing to make it -----------------
    print("\n  -- ranking: computed, and withheld when not comparable --")
    one_only = cross_condition_block(
        {
            LOOPBACK_CONTROL: _condition_arm(LOOPBACK_CONTROL),
            WAN_SHAPED: {"ran": False, "reason": "shaping NOT verified"},
        }
    )
    check(
        "MUTATION: one condition failed -> `ranking_flipped` is NULL, NOT False "
        "(there was no comparison to flip)",
        one_only["ranking_flipped"] is None
        and one_only["conditions_compared"] == [LOOPBACK_CONTROL],
        str(one_only["ranking_flipped"]),
    )
    survivor = build_report(
        linear,
        {
            "ran": True,
            "by_upstream_condition": {
                LOOPBACK_CONTROL: _condition_arm(LOOPBACK_CONTROL),
                WAN_SHAPED: {"ran": False, "reason": "shaping NOT verified"},
            },
            "cross_condition": one_only,
        },
        study,
        prov,
        config,
        (10, 100, 1000),
    )
    check(
        "a FAILED condition does not discard the one that succeeded: the "
        "surviving arm is still in the report, and the report is UNUSABLE",
        not survivor["verdict"]["usable"]
        and survivor["measured"]["speedup"]["by_upstream_condition"][LOOPBACK_CONTROL][
            "ran"
        ],
    )
    check(
        "and its summary says NOT COMPARABLE rather than printing a ranking",
        any("NOT COMPARABLE" in line for line in human_summary_lines(survivor)),
    )

    # --- task-63: the shaping must hold over the SCORED runs, not just the probe
    print("\n  -- the scored runs corroborate the condition they are labelled --")

    def _off_with_rate(rate):
        arm = json.loads(json.dumps(off))
        arm["upstream_nar_transport_bytes_compressed_wire_per_s"]["mean"] = rate
        return arm

    cap = _SELF_TEST_SHAPING.bandwidth_bytes_compressed_wire_per_s
    check(
        "a WAN arm whose scored runs moved bytes at the cap is CLEAN",
        measured_link_rate_violations(
            _off_with_rate(cap * 0.95), WAN_SHAPED, _SELF_TEST_SHAPING
        )
        == [],
    )
    check(
        "MUTATION: the probe passed but the SCORED runs ran at loopback speed "
        "(shaping disarmed between probe and runs) -> REJECTED",
        measured_link_rate_violations(
            _off_with_rate(1.0e9), WAN_SHAPED, _SELF_TEST_SHAPING
        )
        != [],
    )
    check(
        "MUTATION: the loopback CONTROL was secretly SHAPED -> REJECTED (a "
        "shaped control would erase the contrast the whole report claims)",
        measured_link_rate_violations(_off_with_rate(cap), LOOPBACK_CONTROL, None)
        != [],
    )
    check(
        "an arm that produced NO link rate at all is a failure, not a skip",
        measured_link_rate_violations(
            {"upstream_nar_transport_bytes_compressed_wire_per_s": {"mean": None}},
            WAN_SHAPED,
            _SELF_TEST_SHAPING,
        )
        != [],
    )

    # --- task-63: the summary gate's verdict must reach the persisted JSON ---
    # Reached through data the summary really interpolates: an invalid swarm
    # point's reason is printed verbatim, so a reason that states a ranking
    # produces a genuinely unqualified LINE - the shape the gate exists for, and
    # the shape a future edit would introduce.
    tainted = _synthetic_swarm_axis("linear")
    tainted.points[0].valid = False
    tainted.points[0].reason = "the peer path was slower here"
    bad_report = build_report(
        tainted, speedup_measured, study, prov, config, (10, 100, 1000)
    )
    check(
        "MUTATION: an unqualified ranking reaches the printed summary -> the "
        "PERSISTED report says so (honesty.compliant False, verdict.usable "
        "False), not just an exit code nobody keeps",
        bad_report["honesty"]["human_summary_violations"]
        and not bad_report["honesty"]["compliant"]
        and not bad_report["verdict"]["usable"],
        str(bad_report["honesty"]["human_summary_violations"]),
    )
    check(
        "and a clean report carries an EMPTY human_summary_violations list, so "
        "the gate is visible in the artifact either way",
        report["honesty"]["human_summary_violations"] == []
        and "human_summary_violations" in report["honesty"],
    )
    summary_lines = human_summary_lines(report)
    check(
        "the printed HUMAN summary states no unqualified speedup either",
        human_summary_violations(summary_lines) == [],
        str(human_summary_violations(summary_lines)),
    )
    check(
        "MUTATION: an unqualified speedup line in the human summary -> REJECTED "
        "(the JSON gate cannot see the text a reader actually reads)",
        human_summary_violations(["    realise mean ... speedup=6.12"]) != [],
    )
    check(
        "and a line naming its condition passes",
        human_summary_violations([f"    [{WAN_SHAPED}] speedup=6.12"]) == [],
    )
    check(
        "the summary actually PRINTS both conditions (not just the JSON)",
        any(LOOPBACK_CONTROL in line for line in summary_lines)
        and any(WAN_SHAPED in line for line in summary_lines),
    )
    check(
        "the summary pins the task-42 loopback control numbers (AC#3)",
        any("PINNED task-42" in line and "0.562" in line for line in summary_lines),
        str([ln for ln in summary_lines if "PINNED" in ln]),
    )
    flipped = cross_condition_block(
        {
            LOOPBACK_CONTROL: _condition_arm(LOOPBACK_CONTROL),
            WAN_SHAPED: _condition_arm(WAN_SHAPED),
        }
    )
    check(
        "identical arms under both conditions do NOT report a ranking flip",
        flipped["ranking_flipped"] is False,
        str(flipped["ranking_flipped"]),
    )
    slow_peer = _condition_arm(LOOPBACK_CONTROL)
    slow_peer[f"speedup_{LOOPBACK_CONTROL}"][
        f"latency_speedup_mean_{LOOPBACK_CONTROL}"
    ] = 0.283
    check(
        "peers losing under one condition and winning under the other IS a "
        "ranking flip, computed not narrated",
        cross_condition_block(
            {LOOPBACK_CONTROL: slow_peer, WAN_SHAPED: _condition_arm(WAN_SHAPED)}
        )["ranking_flipped"]
        is True,
    )
    check(
        "known O(n) per-peer RSS recovers linear",
        report["models"]["swarm.peer_rss_hwm_bytes_ram"]["selected_model"] == "linear",
        report["models"]["swarm.peer_rss_hwm_bytes_ram"]["selected_model"],
    )
    check(
        "the whole-swarm RSS total is O(n) (n independent peers)",
        report["models"]["swarm.swarm_total_rss_hwm_bytes_ram"]["selected_model"]
        == "linear",
        report["models"]["swarm.swarm_total_rss_hwm_bytes_ram"]["selected_model"],
    )
    check("no red flag for a linear law", report["red_flags"] == [])
    check("verdict usable on a clean synthetic profile", report["verdict"]["usable"])

    # `usable` must mean "these numbers may be quoted". Two ways it must not.
    smoke = json.loads(json.dumps(speedup_measured))
    smoke["by_upstream_condition"][WAN_SHAPED]["peers_on"]["dev_smoke_below_n10"] = True
    smoke_report = build_report(linear, smoke, study, prov, config, (10, 100, 1000))
    check(
        "MUTATION: a speedup arm below the frozen 10-run floor makes the whole "
        "report UNUSABLE (dev_smoke_below_n10 used to gate nothing)",
        not smoke_report["verdict"]["usable"]
        and smoke_report["verdict"]["speedup_dev_smoke"],
        str(smoke_report["verdict"]),
    )
    # Caught, not let-crash: without the `ran` guard `build_report` reaches into
    # a failed arm's absent `peers_on` and dies with a KeyError. That is red, but
    # a self-test that dies with a traceback does not NAME what broke.
    try:
        failed_arm = build_report(
            linear,
            {"ran": False, "reason": "a holder never announced"},
            study,
            prov,
            config,
            (10, 100, 1000),
        )
        failed_ok = (
            not failed_arm["verdict"]["usable"]
            and failed_arm["models"] != {}
            and failed_arm["measured"]["speedup"]["reason"]
            == "a holder never announced"
        )
        failed_detail = str(failed_arm["verdict"])
    except (KeyError, TypeError) as error:
        failed_ok = False
        failed_detail = f"build_report raised on a FAILED arm: {error!r}"
    check(
        "MUTATION: a speedup arm that RAISED makes the report unusable, and the "
        "swarm axis SURVIVES into it (a late failure must not discard an earlier "
        "measurement)",
        failed_ok,
        failed_detail,
    )
    check(
        "--skip-speedup (speedup absent, not failed) still yields a usable report",
        build_report(linear, None, study, prov, config, (10, 100, 1000))["verdict"][
            "usable"
        ],
    )

    quad_axis = _synthetic_swarm_axis("quadratic")
    quad_report = build_report(
        quad_axis, speedup_measured, study, prov, config, (10, 100, 1000)
    )
    fit = quad_report["models"]["swarm.peer_rss_hwm_bytes_ram"]
    check(
        "known O(n^2) per-peer RSS is NOT reported linear",
        fit["selected_model"] != "linear",
    )
    check("known O(n^2) per-peer RSS is flagged superlinear", fit["superlinear"])
    check(
        "the superlinear fit reaches the red-flag section, by id",
        "swarm.peer_rss_hwm_bytes_ram" in [f["id"] for f in quad_report["red_flags"]],
        str([f["id"] for f in quad_report["red_flags"]]),
    )
    check(
        "a red-flagged report is still compliant and usable (a product finding "
        "is not an instrument failure)",
        quad_report["honesty"]["compliant"] and quad_report["verdict"]["usable"],
    )

    # MUTATIONS of the assembled report - both gates, on THIS report shape.
    broken = json.loads(json.dumps(quad_report))
    broken["red_flags"] = []
    check(
        "MUTATION: red_flags emptied on a superlinear report -> REJECTED",
        scalefit.sweep_report_violations(broken) != [],
    )
    broken = json.loads(json.dumps(quad_report))
    broken["models"]["swarm.peer_rss_hwm_bytes_ram"]["extrapolations"][0].pop("kind")
    check(
        "MUTATION: extrapolation model-output label stripped -> REJECTED",
        scalefit.sweep_report_violations(broken) != [],
    )
    broken = json.loads(json.dumps(quad_report))
    broken["measured"]["swarm"]["projection"] = {
        "kind": scalefit.MODEL_OUTPUT_KIND,
        "point_estimate": 1,
    }
    check(
        "MUTATION: model output pasted into `measured` -> REJECTED",
        scalefit.sweep_report_violations(broken) != [],
    )
    broken = json.loads(json.dumps(quad_report))
    broken["measured"]["swarm"]["points"][0]["metrics"]["peer_rss_hwm_bytes"] = 1
    check(
        "MUTATION: an UNLABELLED byte quantity in the report -> REJECTED by the "
        "unit gate",
        unit_violations(broken) != [],
    )
    check(
        "and the real report has no unlabelled byte quantity anywhere",
        unit_violations(quad_report) == [],
        str(unit_violations(quad_report)[:3]),
    )
    broken = json.loads(json.dumps(quad_report))
    broken.pop("caveat")
    check(
        "MUTATION: the resource-laws-only caveat removed -> REJECTED",
        scalefit.sweep_report_violations(broken) != [],
    )

    # --- starved axis: refuse to fit rather than fit what survived -----------
    starved_axis = _synthetic_swarm_axis("linear")
    for point in starved_axis.points[:2]:
        point.valid = False
        point.reason = "synthetic holder failure"
    starved_report = build_report(
        starved_axis, None, study, prov, config, (10, 100, 1000)
    )
    check(
        "an axis starved below MIN_POINTS is NOT fitted",
        starved_report["models"] == {},
        str(list(starved_report["models"])),
    )
    check(
        "and the starved profile reports itself UNUSABLE with the reason",
        not starved_report["verdict"]["usable"]
        and starved_report["verdict"]["fit_problems"],
    )
    check(
        "invalid points keep their reasons",
        len(starved_report["measured"]["swarm"]["invalid_points"]) == 2,
    )

    # --- high-water vs point sample ------------------------------------------
    print("\n  -- VmHWM vs VmRSS point sample --")
    equal = ss.Axis(name="swarm", variable="holders", description="x")
    equal.points.append(
        ss.SweepPoint(
            n=1,
            valid=True,
            metrics={
                "peer_rss_hwm_bytes_ram": 100,
                "peer_rss_point_max_bytes_ram": 100,
            },
        )
    )
    check(
        "HWM == point sample everywhere -> reported UNEXERCISED, not validated",
        hwm_vs_point(equal.points)["exercised"] is False,
    )
    burst = ss.Axis(name="swarm", variable="holders", description="x")
    burst.points.append(
        ss.SweepPoint(
            n=1,
            valid=True,
            metrics={
                "peer_rss_hwm_bytes_ram": 300,
                "peer_rss_point_max_bytes_ram": 100,
            },
        )
    )
    check(
        "a burst the sampler missed shows as a SEPARATED high-water",
        hwm_vs_point(burst.points)["exercised"]
        and hwm_vs_point(burst.points)["max_gap_bytes_ram"] == 200,
    )
    # ONE translation from the reused aggregate to this report's names, shared by
    # the swarm axis and both speedup arms. Asserted here because the previous
    # three copies had already drifted to two different names for the same
    # measurement, and because every key it emits must survive the unit gate.
    raw = {
        "daemon_rss_hwm_bytes": 300,
        "daemon_rss_point_max_bytes": 100,
        "chain_total_rss_hwm_bytes": 400,
        "daemon_fd_max": 12,
        "daemon_roles_sampled": ["node-b"],
        "per_role": {
            "node-b": {
                "rss_hwm_bytes": 300,
                "rss_point_max_bytes": 100,
                "rss_point_last_bytes": 90,
                "fd_max": 12,
                "ticks": 5,
            }
        },
    }
    labelled = label_resources(raw)
    check(
        "label_resources is the ONE translation and its output passes the unit gate",
        unit_violations(labelled) == []
        and labelled["peer_rss_hwm_bytes_ram"] == 300
        and labelled["swarm_total_rss_hwm_bytes_ram"] == 400
        and labelled["per_role"]["node-b"]["rss_hwm_bytes_ram"] == 300,
        str(labelled),
    )
    scalars = swarm_metrics_from(raw, {}, [1.0])
    check(
        "the swarm point's metrics are SCALARS only (no per_role dict reaches "
        "the fitter) and use the same names",
        "per_role" not in scalars
        and scalars["peer_rss_hwm_bytes_ram"] == labelled["peer_rss_hwm_bytes_ram"]
        and unit_violations(scalars) == [],
        str(scalars),
    )

    roles = {
        "node-a": {"rss_hwm_bytes_ram": 100, "rss_point_max_bytes_ram": 100},
        "node-b": {"rss_hwm_bytes_ram": 300, "rss_point_max_bytes_ram": 100},
    }
    role_gap = hwm_vs_point_roles(roles, "test")
    check(
        "per-ROLE separation finds the ONE node that burst, not the arm max",
        role_gap["observations"] == 2
        and role_gap["observations_where_hwm_exceeds_point_sample"] == 1
        and role_gap["max_gap_bytes_ram"] == 200,
        str(role_gap),
    )
    cost = held_content_ram_cost(roles, 100)
    check(
        "RAM cost per held NarSize byte is a NAMED cross-unit ratio",
        cost["measured"]
        and cost["per_role_peak_rss_ram_per_held_nar_byte_ratio"]["node-b"] == 3.0,
        str(cost),
    )
    check(
        "an arm that holds nothing reports NO ratio (not a 0, not a div-by-zero)",
        held_content_ram_cost(roles, 0)["measured"] is False,
    )
    # The S9 study seed must not depend on PYTHONHASHSEED. Measured: with the
    # `hash()` version and a randomized seed, the gated `constant` recovery rate
    # wandered to 0.892 against a 0.88 floor - a FAST-tier gate one environment
    # change from being a lottery, and TESTING.md's quoted rates true by accident.
    check(
        "the S9 seed is stable across processes (not `hash()`)",
        stable_seed("linear", 0.02, 7) == stable_seed("linear", 0.02, 7)
        and stable_seed("linear", 0.02, 7) == zlib.crc32(b"linear|0.02|7"),
        str(stable_seed("linear", 0.02, 7)),
    )
    check(
        "and it separates the inputs it is given",
        len(
            {
                stable_seed("linear", 0.02, 7),
                stable_seed("quadratic", 0.02, 7),
                stable_seed("linear", 0.05, 7),
                stable_seed("linear", 0.02, 8),
            }
        )
        == 4,
    )

    # Infrastructure roles must never enter a claim about what a PEER costs.
    mixed = {
        "daemon_rss_hwm_bytes": 300,
        "daemon_rss_point_max_bytes": 100,
        "chain_total_rss_hwm_bytes": 300,
        "daemon_fd_max": 12,
        "daemon_roles_sampled": ["node-b"],
        "per_role": {
            "node-b": {
                "rss_hwm_bytes": 300,
                "rss_point_max_bytes": 100,
                "rss_point_last_bytes": 90,
                "fd_max": 12,
                "ticks": 5,
            },
            # The fixture HTTP server, deliberately the LARGEST RSS here.
            "origin": {
                "rss_hwm_bytes": 900,
                "rss_point_max_bytes": 900,
                "rss_point_last_bytes": 900,
                "fd_max": 4,
                "ticks": 5,
            },
        },
    }
    split = label_resources(mixed)
    check(
        "MUTATION: the fixture `origin` is kept OUT of per_role (it would "
        "otherwise be the 'worst node' in the RAM-per-held-byte line)",
        list(split["per_role"]) == ["node-b"]
        and list(split["infrastructure_per_role"]) == ["origin"],
        str(list(split["per_role"])),
    )
    check(
        "so RAM-per-held-byte names the PEER, not the fixture server",
        max(
            held_content_ram_cost(split["per_role"], 100)[
                "per_role_peak_rss_ram_per_held_nar_byte_ratio"
            ].items(),
            key=lambda kv: kv[1],
        )[0]
        == "node-b",
    )
    check(
        "and the infrastructure roles are still REPORTED, not dropped",
        split["infrastructure_per_role"]["origin"]["rss_hwm_bytes_ram"] == 900,
    )

    check(
        "an arm below the counting rule's 10-valid-run floor is marked a DEV SMOKE",
        summarize_profile_arm(
            "x",
            [_fake_run() for _ in range(3)],
            workload_bytes_compressed_wire=1,
            workload_bytes_uncompressed_nar=1,
            min_valid=3,
        )["dev_smoke_below_n10"],
    )
    check(
        "an arm at 10 valid runs is NOT a dev smoke",
        not summarize_profile_arm(
            "x",
            [_fake_run() for _ in range(10)],
            workload_bytes_compressed_wire=1,
            workload_bytes_uncompressed_nar=1,
            min_valid=10,
        )["dev_smoke_below_n10"],
    )

    # --- replicate spread ----------------------------------------------------
    spread_axis = ss.Axis(name="swarm", variable="holders", description="x")
    for value in (100.0, 110.0):
        spread_axis.points.append(
            ss.SweepPoint(n=4, valid=True, metrics={"peer_fd_max": value})
        )
    spread = replicate_spread(spread_axis.points)["peer_fd_max"]
    check(
        "replicate spread is measured where replicates exist",
        spread["n_groups_with_replicates"] == 1
        and abs(spread["median_relative_spread"] - (5.0 / 105.0)) < 1e-9,
        str(spread),
    )
    single = ss.Axis(name="swarm", variable="holders", description="x")
    single.points.append(ss.SweepPoint(n=4, valid=True, metrics={"peer_fd_max": 1.0}))
    check(
        "a single draw yields NO spread claim (None, not 0)",
        replicate_spread(single.points)["peer_fd_max"]["median_relative_spread"]
        is None,
    )

    # --- does the REAL data sit where the bite was demonstrated? -------------
    print("\n  -- bite applicability (measured noise vs demonstrated regime) --")
    fake_models = {
        "swarm.peer_rss_hwm_bytes_ram": {
            "identifiable": True,
            "r_squared": 0.99,
        },
        "swarm.client_realise_s": {"identifiable": False, "r_squared": 0.31},
    }
    fake_spread = {
        "peer_rss_hwm_bytes_ram": {"median_relative_spread": 0.01},
        "client_realise_s": {"median_relative_spread": 0.20},
    }
    applicability = bite_applicability(study, fake_spread, fake_models)
    check(
        "a quiet metric is reported INSIDE the demonstrated regime",
        applicability["per_metric"]["swarm.peer_rss_hwm_bytes_ram"][
            "inside_demonstrated_regime"
        ]
        is True,
        str(applicability["per_metric"]["swarm.peer_rss_hwm_bytes_ram"]),
    )
    check(
        "a NOISY metric (20% spread) is reported OUTSIDE it - the class name is "
        "explicitly not a law there",
        applicability["per_metric"]["swarm.client_realise_s"][
            "inside_demonstrated_regime"
        ]
        is False
        and "OUTSIDE"
        in applicability["per_metric"]["swarm.client_realise_s"]["verdict"],
        str(applicability["per_metric"]["swarm.client_realise_s"]),
    )

    # A membership test ("the answer is one of the studied levels") would pass
    # with `proven_to = noise_levels[0]` hardcoded - a liveness check wearing a
    # derivation check's label. Prove DERIVATION by changing the study and
    # requiring the answer to follow.
    def study_with(rates: dict) -> dict:
        """A study whose linear-vs-superlinear split holds exactly at the noise
        levels in `rates` (mapping noise -> holds?)."""
        return {
            "ran": True,
            "per_class": {
                model: {
                    str(noise): {
                        "replicates": 120,
                        "selections": {},
                        "exact_rate": 1.0,
                        # A superlinear generator flagged, a non-superlinear one
                        # not - inverted at any level meant to fail.
                        "superlinear_rate": (
                            1.0
                            if scalefit.BASIS_BY_NAME[model].superlinear == holds
                            else 0.0
                        ),
                        "linear_rate": 0.0,
                        "family_rate": 1.0,
                    }
                    for noise, holds in rates.items()
                }
                for model in scalefit.BASIS_BY_NAME
            },
        }

    all_good = bite_applicability(
        study_with({0.01: True, 0.02: True, 0.05: True}), {}, {}
    )
    only_quiet = bite_applicability(
        study_with({0.01: True, 0.02: False, 0.05: False}), {}, {}
    )
    check(
        "DERIVATION: the regime FOLLOWS the study - a fitter good to 5% reports "
        f"{all_good['bite_demonstrated_up_to_relative_noise']}, one good only to "
        f"1% reports {only_quiet['bite_demonstrated_up_to_relative_noise']}",
        all_good["bite_demonstrated_up_to_relative_noise"] == 0.05
        and only_quiet["bite_demonstrated_up_to_relative_noise"] == 0.01,
        f"{all_good['bite_demonstrated_up_to_relative_noise']} / "
        f"{only_quiet['bite_demonstrated_up_to_relative_noise']}",
    )
    gapped = bite_applicability(
        study_with({0.01: True, 0.02: False, 0.05: True}), {}, {}
    )
    check(
        "a GAP does not extend the regime past it (contiguous from the quietest "
        f"level; reports {gapped['bite_demonstrated_up_to_relative_noise']}, not 0.05)",
        gapped["bite_demonstrated_up_to_relative_noise"] == 0.01,
        str(gapped["bite_demonstrated_up_to_relative_noise"]),
    )
    check(
        "a fitter that fails even at the quietest level demonstrates NO regime",
        bite_applicability(study_with({0.01: False, 0.02: False}), {}, {})[
            "bite_demonstrated_up_to_relative_noise"
        ]
        is None,
    )
    check(
        "with no study, applicability says so rather than guessing",
        bite_applicability({"ran": False}, fake_spread, fake_models)["available"]
        is False,
    )

    # task-65's pure logic lives in its own module; run it here so `just test`
    # keeps ONE entry point for this instrument's honesty machinery.
    print()
    ok = sz.run_self_test() == 0 and ok

    print(f"\nprofile_p2p --self-test: {'ALL PASS' if ok else 'FAILURES PRESENT'}")
    return 0 if ok else 1


# ---- the task-65 size + concurrency arms -------------------------------------


def run_size_axes(
    ctx, scratch: Path, state_root: Path, fixtures, size_plan, concurrency_plan, args
) -> tuple[dict, dict, list[str]]:
    """Build the graded cache, run both task-65 axes, and return the report blocks.

    The graded cache is SYNTHESISED here rather than added to `gen-fixtures.py`
    deliberately. The size axis needs >= 5 NAR sizes that exist only to move a
    known number of bytes through the peer path; adding five payloads to the
    fixture plan would put them in the lock, in `check-fixtures`, in the e2e image
    and in every other instrument's disk budget, for the benefit of one arm. It is
    torn down with the rest of `scratch` in `main`'s `finally`.

    HONEST COST of that choice, stated here so it is not discovered in review: the
    graded payloads never pass through real nix, so this arm proves nothing about
    nix's acceptance of what the daemon serves. That is `check-rewrite-realnix.py`
    and the S6 scenario's job, and both already run against the REAL fixtures.
    """
    graded_root = scratch / "graded"
    graded_root.mkdir(parents=True, exist_ok=True)
    # The real fixture tree's cache-info verbatim, so the synthetic origin answers
    # the same `StoreDir`/`Priority` the rest of the harness expects. Copied rather
    # than re-invented: a second definition of the cache's own metadata is a
    # second thing to forget.
    nix_cache_info = (fixtures.cache / "nix-cache-info").read_text()
    graded, payloads = sz.build_graded_cache(
        graded_root, size_plan + concurrency_plan, nix_cache_info
    )
    sz.unit_coincidence(payloads, graded.manifest)

    by_attr = {p.attr: p for p in payloads}
    by_size = {size: by_attr[attr] for attr, size in size_plan}
    concurrency_payloads = [by_attr[attr] for attr, _size in concurrency_plan]

    size_axis = sz.sweep_size(ctx, graded, by_size, args.size_repeats, state_root)
    concurrency_axis = None
    if concurrency_payloads and args.concurrency:
        concurrency_axis = sz.sweep_concurrency(
            ctx,
            graded,
            concurrency_payloads,
            args.concurrency,
            args.size_repeats,
            state_root,
        )
    measured, models, problems = sz.build_blocks(
        size_axis, concurrency_axis, sz.SIZE_EXTRAPOLATION_TARGETS_BYTES
    )
    measured["size"]["unit_coincidence"] = sz.unit_coincidence(
        payloads, graded.manifest
    )
    # Free the graded NARs as soon as the arms are done: on a host at 95% used the
    # cache is the largest thing this run created, and holding it through the
    # report assembly buys nothing.
    shutil.rmtree(graded_root, ignore_errors=True)
    return measured, models, problems


# ---- main --------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--swarm",
        type=ss.int_list,
        default=DEFAULT_SWARM_SIZES,
        help="holder-peer counts to sweep (default: %(default)s)",
    )
    parser.add_argument(
        "--repeats",
        type=int,
        default=DEFAULT_REPEATS,
        help="replicate runs per swarm point, fitted as separate observations "
        "at the same n (default: %(default)s)",
    )
    parser.add_argument(
        "--speedup-runs",
        type=int,
        default=DEFAULT_SPEEDUP_RUNS,
        help="runs per speedup arm (default: %(default)s; below 10 the frozen "
        "counting rule marks the arm a dev smoke, not a baseline)",
    )
    parser.add_argument(
        "--skip-speedup",
        action="store_true",
        help="run only the fitted swarm axis (dev loop)",
    )
    parser.add_argument(
        "--size-grid",
        type=ss.int_list,
        default=sz.DEFAULT_SIZE_GRID_MIB,
        help="task-65 size axis: NAR sizes in MiB of UNCOMPRESSED NAR (default: "
        "%(default)s). Needs >= scalefit.MIN_POINTS distinct values or the fitter "
        "refuses to fit",
    )
    parser.add_argument(
        "--size-repeats",
        type=int,
        default=sz.DEFAULT_SIZE_REPEATS,
        help="replicates per size point (default: %(default)s)",
    )
    parser.add_argument(
        "--concurrency",
        type=ss.int_list,
        default=sz.DEFAULT_CONCURRENCY,
        help="task-65 concurrency axis: numbers of OVERLAPPING serves at "
        f"{sz.CONCURRENCY_SIZE_MIB} MiB (default: %(default)s)",
    )
    parser.add_argument(
        "--skip-size",
        action="store_true",
        help="skip the task-65 size and concurrency axes (dev loop)",
    )
    parser.add_argument(
        "--wan-rtt-ms",
        type=int,
        default=WAN_RTT_MS,
        help="RTT injected into the WAN-shaped upstream arm, per request "
        "(default: %(default)s; derived from task-35, see the constant)",
    )
    parser.add_argument(
        "--wan-bandwidth-mib-s",
        type=float,
        default=WAN_BANDWIDTH_BYTES_COMPRESSED_WIRE_PER_S / 1024**2,
        help="NAR egress cap for the WAN-shaped arm, in MiB of "
        "bytes_compressed_wire per second (default: %(default)s)",
    )
    parser.add_argument(
        "--wan-probe-only",
        action="store_true",
        help="stand up ONE pod, arm the shaping, assert it from outside the "
        "shaper and exit. The cheap way to check the shaping still bites "
        "without paying for the whole ~30-minute profile",
    )
    parser.add_argument(
        "--extrapolate-to",
        type=ss.int_list,
        default=scalefit.DEFAULT_EXTRAPOLATION_TARGETS,
        help="n values to extrapolate to (default: %(default)s)",
    )
    parser.add_argument(
        "--report", type=Path, default=None, help="also write the JSON report here"
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=fx.repo_root() / "fixtures" / "out",
        help="fixture publication root",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run the pure logic tests (no containers, no nix) and exit",
    )
    args = parser.parse_args()

    if args.self_test:
        return run_self_test()

    # Reused, not re-declared: `scale_sweep` already owns the SIGTERM->teardown
    # contract, and two copies of "how a sweep cleans up when killed" is two
    # things to forget to update.
    ss.install_sigterm_cleanup()
    # PRECONDITIONS FIRST, all of them, before anything expensive. Both of these
    # used to fire late: the holder ceiling only when a pod was created (turning
    # an argument error into silently-invalid data points), and the wire==NarSize
    # assertion only at the top of the speedup arm, ~15 minutes into the run.
    over = [n for n in args.swarm if not 1 <= n <= e2e.MAX_P2P_HOLDERS]
    if over:
        e2e.die(
            f"--swarm values {over} are outside 1..{e2e.MAX_P2P_HOLDERS}; higher "
            "counts collide with other published host ports. This is an argument "
            "error, not a data point."
        )
    free = shutil.disk_usage(fx.repo_root()).free
    if free < MIN_FREE_DISK_BYTES:
        e2e.die(
            f"only {free / 1024**3:.1f} GiB free; this profile spins peer swarms "
            f"that each hold a blob store and copies the 110 MiB payload per pod, "
            f"and needs at least {MIN_FREE_DISK_BYTES / 1024**3:.0f} GiB. Refusing "
            "to start rather than dying with ENOSPC mid-run. Bounding the harness "
            "footprint is TASK-54."
        )

    out_root = args.out.resolve()
    e2e.preflight_gate(out_root)
    fixtures = e2e.resolve_fixtures(out_root)
    # Pure, cheap, reads only the manifest - so it belongs HERE, not 15 minutes
    # in at the top of the speedup arm. A fixture regenerated to xz must refuse
    # to start, not waste the swarm sweep first.
    if not args.skip_speedup:
        assert_unit_coincidence(fixtures, SPEEDUP_ATTRS)
    image = e2e.load_image()
    # TASK-58: this sweeps EVERY pod carrying the project label, not just ours,
    # because there is one shared label across all container instruments. Running
    # this concurrently with `just e2e`/`measure`/`scale-sweep` makes each tear
    # down the other's pods mid-measurement. The ~20-minute runtime here makes
    # that overlap far likelier than it was for the short instruments.
    e2e.cleanup_pods()

    scratch = Path(os.environ.get("TMPDIR", "/tmp")) / f"nix-p2p-profile-{os.getpid()}"
    scratch.mkdir(parents=True, exist_ok=True)
    state_root = scratch / "state"
    state_root.mkdir(parents=True, exist_ok=True)
    ctx = e2e.Ctx(podman=e2e.podman(), image=image, fixtures=fixtures, scratch=scratch)

    shaping = UpstreamShaping(
        rtt_ms=args.wan_rtt_ms,
        bandwidth_bytes_compressed_wire_per_s=int(args.wan_bandwidth_mib_s * 1024**2),
    )

    # The cheap bite check: one pod, arm the shaping, assert it from outside,
    # exit. This is how the shaping's oracle is re-proven after a change without
    # paying for the full profile - and how it was proven to go RED by disabling
    # the shaping (task-63 notes).
    if args.wan_probe_only:
        with e2e.Pod(
            ctx,
            "prof-wan-probe",
            fixtures.cache,
            with_daemon=True,
            expect=ss.silent_expect([]),
            state_root=state_root / "wan-probe",
        ) as pod:
            prewarm_upstream_cache(fixtures)
            evidence = probe_upstream_link(pod, fixtures, shaping)
        problems = shaping_violations(evidence, shaping)
        print(
            json.dumps(
                {
                    "shaping": shaping.as_report(),
                    "evidence": evidence,
                    "violations": problems,
                },
                indent=2,
            )
        )
        e2e.cleanup_pods()
        shutil.rmtree(scratch, ignore_errors=True)
        for problem in problems:
            print(f"profile: SHAPING NOT VERIFIED: {problem}", file=sys.stderr)
        return 1 if problems else 0

    size_plan = [
        (f"size-{mib}mib", mib * 1024**2) for mib in sorted(set(args.size_grid))
    ]
    concurrency_plan = [
        (f"conc-{i}", sz.CONCURRENCY_SIZE_MIB * 1024**2)
        for i in range(max(args.concurrency) if args.concurrency else 0)
    ]
    full_plan = size_plan + concurrency_plan
    if not args.skip_size:
        # PRECONDITION, before anything expensive and BEFORE the graded cache is
        # written: this arm's disk appetite is a function of the grid, so someone
        # widening --size-grid must be told the new number rather than checked
        # against `MIN_FREE_DISK_BYTES`, which was sized for a different arm.
        for problem in sz.disk_precondition_violations(free, full_plan):
            e2e.die(f"profile: {problem}")
        if len(size_plan) < scalefit.MIN_POINTS:
            e2e.die(
                f"--size-grid has {len(size_plan)} distinct sizes; scalefit needs "
                f">= {scalefit.MIN_POINTS} or it refuses to fit. This is an "
                "argument error, not a data point."
            )

    config = {
        "size_grid_bytes_uncompressed_nar": [size for _attr, size in size_plan],
        "size_repeats": args.size_repeats,
        "concurrency_values": list(args.concurrency),
        "concurrency_size_bytes_uncompressed_nar": sz.CONCURRENCY_SIZE_MIB * 1024**2,
        "size_axis_skipped": bool(args.skip_size),
        "size_axis_disk_requirement_bytes_ondisk": (
            sz.graded_disk_requirement_bytes_ondisk(full_plan)
        ),
        "size_extrapolation_targets_bytes_uncompressed_nar": list(
            sz.SIZE_EXTRAPOLATION_TARGETS_BYTES
        ),
        "swarm_sizes": list(args.swarm),
        "repeats_per_point": args.repeats,
        "speedup_runs": args.speedup_runs,
        "speedup_skipped": bool(args.skip_speedup),
        "upstream_conditions": list(UPSTREAM_CONDITIONS),
        "wan_shaping": shaping.as_report(),
        "swarm_attrs": list(SWARM_ATTRS),
        "speedup_attrs": list(SPEEDUP_ATTRS),
        "poll_interval_s": ss.POLL_INTERVAL_S,
        "extrapolation_targets": list(args.extrapolate_to),
        "free_disk_at_start_bytes_ondisk": free,
    }

    axis = ss.Axis(name="swarm", variable="peer holder count", description="not run")
    speedup = None
    size_blocks = None
    try:
        axis = sweep_swarm(ctx, fixtures, args.swarm, args.repeats, state_root)
        if not args.skip_size:
            # Its own try/except for the same reason the speedup arm has one: this
            # runs after ~15 minutes of swarm sweeping, and a holder that failed to
            # announce must not discard the completed axis and write no report.
            try:
                size_blocks = run_size_axes(
                    ctx,
                    scratch,
                    state_root,
                    fixtures,
                    size_plan,
                    concurrency_plan,
                    args,
                )
            except (RuntimeError, ss.SampleError, OSError, ValueError) as error:
                print(
                    f"profile: size axis FAILED: {error!r}",
                    file=sys.stderr,
                )
                size_blocks = (
                    {
                        "size": {
                            "ran": False,
                            "reason": f"{error!r}",
                            "traceback": traceback.format_exc(),
                        }
                    },
                    {},
                    [f"size axis raised: {error!r}"],
                )
        if not args.skip_speedup:
            # The speedup arm gets its OWN handler: it runs after ~15 minutes of
            # swarm sweeping, and letting a holder that failed to announce (or
            # any raise in here) propagate would discard the completed axis and
            # write no report at all. The same principle the JSON-before-summary
            # ordering below exists for - a later failure must not destroy an
            # earlier measurement.
            try:
                speedup = run_speedup_conditions(
                    ctx, fixtures, args.speedup_runs, state_root, shaping
                )
            except (RuntimeError, ss.SampleError, OSError, ValueError) as error:
                speedup = {
                    "ran": False,
                    "reason": f"{error!r}",
                    "traceback": traceback.format_exc(),
                }
            except SystemExit as error:
                if error.code != 2:  # see sweep_swarm for the code-2 contract
                    raise
                speedup = {
                    "ran": False,
                    "reason": f"aborted by the Pod seam (e2e.die, exit {error.code})",
                }
    finally:
        # Label-scoped teardown, same contract as `just e2e-clean`. Cleanup
        # FAILURES are reported: on a host at 95% used, a pod or scratch tree
        # that would not go away is signal, not noise.
        e2e.cleanup_pods()
        try:
            shutil.rmtree(scratch)
        except OSError as error:
            print(
                f"profile: WARNING - could not remove scratch {scratch}: {error}",
                file=sys.stderr,
            )

    study = class_recovery_study(
        args.swarm,
        repeats=args.repeats,
        replicates=STUDY_REPLICATES,
        noise_levels=STUDY_NOISE_LEVELS,
    )
    report = build_report(
        axis,
        speedup,
        study,
        provenance(fixtures, out_root),
        config,
        args.extrapolate_to,
        size=size_blocks,
    )
    # PERSIST BEFORE PRETTY-PRINTING. The human summary is a formatter over a
    # report that cost ~20 minutes of container runs to produce; a KeyError in
    # the formatter must not be able to throw the measurement away.
    text = json.dumps(report, indent=2, default=str)
    if args.report:
        args.report.write_text(text + "\n")
        print(f"profile: report written to {args.report}", file=sys.stderr)
    print_human_summary(report)
    print(text)
    return 0 if report["verdict"]["usable"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        e2e.cleanup_pods("(interrupted)")
        sys.exit(130)
