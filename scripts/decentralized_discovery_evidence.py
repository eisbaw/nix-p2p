#!/usr/bin/env python3
"""TASK-155 (over the TASK-103 AC#10 MVP): the FULL mutation-rich
`decentralized-content-discovery-v1` evidence artifact.

The MVP (TASK-103) bound the s7-libp2p decentralized-discovery proof to durable
raw captures + a re-derived verdict, so the claim "decentralized discovery works"
is checkable rather than asserted. It backed the honesty claim ("the consumer
found the provider ONLY via kad - no mdns/tracker/LAN shortcut") at the
HARNESS-STDOUT level (the consumer's real argv, the AC#9 source guard). TASK-155
HARDENS that further, along three axes:

  1. PACKET EVIDENCE (the load-bearing add). During the s7-libp2p discovery run
     the harness's pod netns is captured to a pcap (raw-s7.pcap). The finalizer
     RE-PARSES that pcap and asserts AT THE WIRE that: (a) the capture is complete
     (record count == tcpdump's own captured counter, 0 kernel drops - a lossy
     capture cannot license a zero-forbidden claim); (b) ZERO mdns (UDP/5353),
     ZERO IPv4 multicast/broadcast - the LAN discovery substrates - appear; (c)
     every IPv4 flow is same-host (src_ip == dst_ip: in-pod loopback, or the
     pasta-reflected host gateway for the published HTTP ports), so NO connection
     leaves to an external tracker or LAN peer; (d) the libp2p peer mesh actually
     spoke on the listener band (>=2 listener ports, mutually connected) and a
     NAR-scale payload moved PEER-TO-PEER over libp2p - a wire corroboration of the
     0-upstream-NAR oracle. HONEST LIMIT: the libp2p streams are noise-encrypted,
     so the wire cannot positively read the `kad` protocol id off it, and the three
     loopback peers are not individually attributable at the wire. The wire proves
     the ABSENCE of every non-kad discovery substrate and the PRESENCE of a
     peer-to-peer libp2p transfer; "it was kad specifically" stays attributed by
     the source guard (kad-EXCLUSIVE composition) + the noise-encrypted-stream
     construction. That is still a genuine strengthening of the flagship claim.

  2. FULLER MUTATION SET. Beyond the MVP's (miss-arm FAIL / omitted arm / truncated
     run / dropped oracle line / tampered raw / missing raw), the self-test now also
     BITES on: a missing no-injection oracle line; an mdns packet in the pcap; an
     external-unicast flow in the pcap; a truncated pcap; a kernel-drop in the
     capture; a libp2p mesh with no peer transfer; a golden whose ContentKey no
     longer matches the frozen TASK-126 value; and an absent frozen-anchor pass.

  3. FROZEN-TREE BINDING. The artifact is bound to the TASK-126 freeze (the frozen
     key/record contract the discovery run exercises): the finalizer hashes the
     committed golden `peer-fabric/tests/golden/provider_record_v1.json` and the
     independent anchor `scripts/check-content-key-derivation.py` into a frozen-tree
     manifest, asserts the golden's ContentKey equals the frozen TASK-126 value
     (context `nix-p2p/discovery/ContentKey/v1`), asserts both files are at git HEAD,
     and REQUIRES the anchor's own OK line in raw-frozen.log (an independent
     pure-python re-derivation of the frozen ContentKey + provider records). A drift
     in the frozen surface, or an anchor that did not reproduce, fails the verdict.

FOUR phases, deliberately separated so a verdict cannot launder a self-report:

  --capture   RUN the evidence and write ONLY raw captures to <out>/:
                * raw-e2e.log    - FULL stdout of `e2e_harness.py --only s7-libp2p
                                   [--only s7-libp2p-miss]` (the harness oracle).
                * raw-ac9.log    - FULL stdout+stderr of the AC#9 source guard.
                * raw-frozen.log - FULL stdout+stderr of the TASK-126 independent
                                   ContentKey/record anchor.
                * raw-s7.pcap    - a pcap of the s7-libp2p pod netns, captured host-
                                   side (nsenter into the rootless pod's user+net ns,
                                   host tcpdump; no image change needed).
                * pcap-meta.json - the capture's own counters (tcpdump captured /
                                   received / dropped) + attach metadata.
                * timings.json   - wall-clock ms per step.
              It writes NO verdict and NO tree manifest (those are computed LIVE at
              finalize so they can never go stale against the committed code).

  --finalize  RE-READ every raw capture and RE-DERIVE the verdict by reparsing them.
              It never trusts a summary line; it recounts checks, reparses the pcap
              bytes, re-checks the frozen golden, records every raw hash IN the
              artifact, computes the code + frozen tree manifests LIVE, and FAILS
              CLOSED on any missing/tampered/incomplete raw, any drift, any wire
              violation, any absent oracle. INTEGER counts only (owner no-float rule).

  --verify    RE-CHECK the tracked artifact against the on-disk raws: every recorded
              raw sha256 must still match (missing/tampered => the tracked pass dies).

  --self-test Run the mutation-bite self-tests (no containers): every bite above must
              FIRE. Exit 0 iff every bite fires and the clean baseline passes.

Default (no phase flag) runs --capture then --finalize.

Exit codes: 0 verdict=pass / self-test all-bit / verify-ok; 1 verdict=fail / a
required capture missing / verify mismatch; 2 the evidence could not be produced.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_OUT = REPO / "artifacts" / "decentralized-content-discovery"
DEFAULT_TRACKED = REPO / "artifacts" / "decentralized-content-discovery-v1.json"

# The e2e scenarios whose RAW harness output is the proof. s7-libp2p is the
# positive discovery proof (+ kill-provider control); s7-libp2p-miss keeps the
# clean-miss arm honest. BOTH are REQUIRED for a pass (omission => fail).
EVIDENCE_SCENARIOS = ("s7-libp2p", "s7-libp2p-miss")
REQUIRED_SCENARIOS = ("s7-libp2p", "s7-libp2p-miss")

# The pod (from e2e_harness POD_PREFIX + "s7") whose netns carries the POSITIVE
# discovery arm's wire traffic. Its member containers all share one netns.
PCAP_POD = "nix-p2p-e2e-s7"
# The pod members the watcher will try to attach to, in order. All share the pod's
# single netns, so any one is a valid capture point; the origin comes up first.
PCAP_ATTACH_TARGETS = (
    f"{PCAP_POD}-lp-consumer",
    f"{PCAP_POD}-lp-boot",
    f"{PCAP_POD}-lp-provider",
    f"{PCAP_POD}-origin",
)
# Bounded wait for the pod to appear (the harness rebuilds fixtures + the e2e image
# first; on a warm store that is ~1-2 min, cold it can be many minutes). Still
# BOUNDED - it never loops forever.
PCAP_ATTACH_TIMEOUT_S = 1800.0

# The shipped libp2p node listeners occupy LIBP2P_BASE_PORT + role_index (e2e_harness
# LIBP2P_BASE_PORT=37000, "deliberately far from the HTTP 808x band"). A flow is a
# libp2p flow iff either endpoint port is in this band.
LIBP2P_PORT_LO = 37000
LIBP2P_PORT_HI = 37100
# The mDNS port - the concrete LAN-multicast discovery substrate AC#9 forbids. Its
# ABSENCE on the wire during the real discovery run is the load-bearing negative.
MDNS_PORT = 5353
# A NAR-scale peer transfer must be at least this many bytes on a single libp2p
# conversation. The S7 target ("lib") NAR is 66048 B; over noise+yamux the observed
# peer conversation is ~80-94 kB. narinfo/handshake chatter is <=~4 kB, so 40000
# cleanly separates a real peer NAR transfer from control traffic. Documented, not
# magic: it is a floor well below the payload and well above the chatter.
LIBP2P_TRANSFER_MIN_BYTES = 40000

# ---- the TASK-126 freeze this evidence is bound to -------------------------
# The frozen discovery key contract. If the golden's ContentKey recipe or value
# drifts from these, the discovery surface this run exercises is no longer the
# frozen one, and the verdict fails. (Values pinned by TASK-126; independently
# re-derivable by scripts/check-content-key-derivation.py.)
FROZEN_GOLDEN_REL = "peer-fabric/tests/golden/provider_record_v1.json"
FROZEN_CONTENT_KEY_CONTEXT = "nix-p2p/discovery/ContentKey/v1"
FROZEN_CONTENT_KEY_HEX = (
    "4e61db15d59529f33ad8f264c93302500233a84605dc58cb2ac3b8f4a2ed007c"
)
FROZEN_ANCHOR_REL = "scripts/check-content-key-derivation.py"
# The anchor's own success marker (its stdout OK line). Its presence in raw-frozen.log
# is what proves the frozen ContentKey + records were independently reproduced.
FROZEN_ANCHOR_OK_SUBSTRING = "check-content-key-derivation: OK"

# The load-bearing source files, hashed into the code tree manifest so the verdict is
# bound to the exact code it was produced from.
TREE_FILES = (
    "daemon-libp2p/src/lib.rs",
    "daemon/src/main.rs",
    "daemon/src/lib.rs",
    "daemon-core/src/public_allowlist.rs",
    "scripts/e2e_harness.py",
    "scripts/check-discovery-no-shortcut.py",
)
# The FROZEN TASK-126 surface files, hashed into a SEPARATE frozen-tree manifest so
# the artifact is tied to the frozen key/record contract it exercises (part 3).
FROZEN_TREE_FILES = (FROZEN_GOLDEN_REL, FROZEN_ANCHOR_REL)

# The raw capture files whose content hashes are recorded IN the tracked artifact.
# raw-s7.pcap + raw-frozen.log are REQUIRED (fail-closed if absent), so a run that
# could not capture the wire or reproduce the frozen contract cannot pass.
RAW_FILES = ("raw-e2e.log", "raw-ac9.log", "raw-frozen.log", "raw-s7.pcap")
# The pcap is binary; --verify hashes it but its "text" reparse is byte-level.
RAW_TEXT_FILES = ("raw-e2e.log", "raw-ac9.log", "raw-frozen.log")

# REQUIRED oracle lines that MUST appear (as `ok` checks) in raw-e2e.log for a pass.
REQUIRED_OK_SUBSTRINGS = (
    "consumer argv does NOT contain the provider's PeerId",
    "consumer has NO --libp2p-provider-addr",
    "consumer --libp2p-bootstrap is EXACTLY the real BOOT node",
    "byte-identity",
    "0 upstream NAR egress",
    "upstream served the FULL NAR once P is dead",
)


def sha256_of(path: Path) -> tuple[str, int]:
    data = path.read_bytes()
    return hashlib.sha256(data).hexdigest(), len(data)


def _head_blob_sha256(rel: str) -> str | None:
    r = subprocess.run(["git", "show", f"HEAD:{rel}"], cwd=REPO, capture_output=True)
    if r.returncode != 0:
        return None
    return hashlib.sha256(r.stdout).hexdigest()


def _git_head_commit() -> str | None:
    r = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True, text=True
    )
    return r.stdout.strip() if r.returncode == 0 else None


def tree_manifest(tree_files: tuple[str, ...]) -> dict:
    """Hash each file FROM THE WORKING TREE at call time. Computed LIVE at finalize."""
    entries = []
    for rel in tree_files:
        p = REPO / rel
        if not p.is_file():
            raise SystemExit(f"tree manifest: file missing: {rel}")
        digest, size = sha256_of(p)
        entries.append({"path": rel, "sha256": digest, "bytes": int(size)})
    return {"files": entries, "count": len(entries)}


def _manifest_head_drift(manifest: dict) -> list[str]:
    """Problems for any manifest file whose working-tree content differs from git HEAD
    (evidence produced from uncommitted code) or that is untracked."""
    problems: list[str] = []
    for entry in manifest["files"]:
        rel = entry["path"]
        head = _head_blob_sha256(rel)
        if head is None:
            problems.append(
                f"tree manifest: {rel} is not at git HEAD (untracked/no git)"
            )
        elif head != entry["sha256"]:
            problems.append(
                f"tree manifest: {rel} working-tree sha256 {entry['sha256']} "
                f"!= HEAD {head} (evidence from uncommitted code)"
            )
    return problems


# ---- packet capture (host-side, rootless pod netns) ------------------------


def _podman() -> str:
    found = shutil.which("podman")
    if not found:
        raise SystemExit("podman not found on PATH (needed for the pcap capture)")
    return found


def _container_pid(container: str) -> int | None:
    r = subprocess.run(
        [_podman(), "inspect", "--format", "{{.State.Pid}}", container],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        return None
    try:
        pid = int((r.stdout or "0").strip() or "0")
    except ValueError:
        return None
    return pid or None


def _container_running(container: str) -> bool:
    r = subprocess.run(
        [_podman(), "inspect", "--format", "{{.State.Running}}", container],
        capture_output=True,
        text=True,
    )
    return r.returncode == 0 and r.stdout.strip() == "true"


_TCPDUMP_COUNTERS = re.compile(
    r"(\d+)\s+packets captured.*?(\d+)\s+packets received by filter.*?"
    r"(\d+)\s+packets dropped by kernel",
    re.DOTALL,
)


def _parse_tcpdump_counters(stderr: str) -> dict[str, int]:
    m = _TCPDUMP_COUNTERS.search(stderr)
    if not m:
        return {"captured": -1, "received": -1, "dropped": -1}
    return {
        "captured": int(m.group(1)),
        "received": int(m.group(2)),
        "dropped": int(m.group(3)),
    }


class _PcapWatcher(threading.Thread):
    """Attaches host tcpdump to the s7 pod's rootless user+net namespace and captures
    every packet until the pod goes away. Host-side capture (nsenter -U -n +
    host tcpdump) needs no tcpdump in the e2e image. Runs concurrently with the e2e
    harness subprocess; the caller starts it, runs the harness, then joins it."""

    def __init__(self, out: Path):
        super().__init__(daemon=True)
        self.out = out
        self.pcap = out / "raw-s7.pcap"
        self.meta = out / "pcap-meta.json"
        self._result: dict = {"attached": False, "target": None, "host_pid": None}
        self._stop = threading.Event()

    def request_stop(self) -> None:
        self._stop.set()

    def run(self) -> None:  # noqa: C901 - a bounded attach->capture->stop loop
        deadline = time.monotonic() + PCAP_ATTACH_TIMEOUT_S
        target: str | None = None
        pid: int | None = None
        while time.monotonic() < deadline and not self._stop.is_set():
            for candidate in PCAP_ATTACH_TARGETS:
                p = _container_pid(candidate)
                if p:
                    target, pid = candidate, p
                    break
            if pid:
                break
            time.sleep(0.2)
        if not pid or not target:
            self._result["error"] = "pod never appeared within the attach timeout"
            self._write_meta()
            return
        self._result.update(attached=True, target=target, host_pid=pid)
        self._result["attached_at"] = time.time()
        # -U -n: enter the rootless container's user+net ns so host tcpdump has
        # CAP_NET_RAW there. -U 0 preserved via --preserve-credentials. `not port 22`
        # keeps ssh noise out of the capture.
        cmd = [
            "nsenter",
            "-t",
            str(pid),
            "-U",
            "-n",
            "--preserve-credentials",
            "tcpdump",
            "-i",
            "any",
            "-w",
            str(self.pcap),
            "-U",
            "-s",
            "0",
            "not",
            "port",
            "22",
        ]
        proc = subprocess.Popen(cmd, stderr=subprocess.PIPE, stdout=subprocess.DEVNULL)
        # Stop when the attach target is gone (pod torn down) or a stop is requested.
        while not self._stop.is_set():
            if not _container_running(target):
                break
            if proc.poll() is not None:  # tcpdump died on its own
                break
            time.sleep(0.3)
        time.sleep(1.0)  # let the last packets flush
        if proc.poll() is None:
            proc.send_signal(signal.SIGINT)
        try:
            _, stderr = proc.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            _, stderr = proc.communicate()
        counters = _parse_tcpdump_counters((stderr or b"").decode("utf-8", "replace"))
        self._result.update(counters)
        self._result["stopped_at"] = time.time()
        self._write_meta()

    def _write_meta(self) -> None:
        self.meta.write_text(json.dumps(self._result, indent=2, sort_keys=True) + "\n")


# ---- pcap parsing + the wire oracle ----------------------------------------


def _pcap_endianness(data: bytes) -> str | None:
    if len(data) < 24:
        return None
    if data[:4] == b"\xa1\xb2\xc3\xd4":
        return ">"
    if data[:4] == b"\xd4\xc3\xb2\xa1":
        return "<"
    return None


def count_pcap_records(data: bytes) -> int:
    """Count every COMPLETE record in a classic pcap. A trailing record whose body is
    cut short is NOT counted, so truncation always undercounts and fails the
    equality-with-tcpdump-counter check."""
    endian = _pcap_endianness(data)
    if endian is None:
        return 0
    offset, count = 24, 0
    while offset + 16 <= len(data):
        incl_len = struct.unpack(endian + "I", data[offset + 8 : offset + 12])[0]
        if offset + 16 + incl_len > len(data):
            break
        offset += 16 + incl_len
        count += 1
    return count


def _iter_frames(data: bytes):
    endian = _pcap_endianness(data)
    if endian is None:
        return
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    offset = 24
    while offset + 16 <= len(data):
        incl_len = struct.unpack(endian + "I", data[offset + 8 : offset + 12])[0]
        offset += 16
        if offset + incl_len > len(data):
            break
        yield linktype, data[offset : offset + incl_len]
        offset += incl_len


def _l3_payload(linktype: int, frame: bytes) -> tuple[int, bytes] | None:
    """Strip the link layer, return (ethertype, l3_bytes). Handles Ethernet, Linux
    SLL and SLL2 (`-i any` uses SLL2), and raw IPv4."""
    if linktype == 1:  # Ethernet
        if len(frame) < 14:
            return None
        return int.from_bytes(frame[12:14], "big"), frame[14:]
    if linktype == 113:  # Linux SLL
        if len(frame) < 16:
            return None
        return int.from_bytes(frame[14:16], "big"), frame[16:]
    if linktype == 276:  # Linux SLL2
        if len(frame) < 20:
            return None
        return int.from_bytes(frame[0:2], "big"), frame[20:]
    if linktype == 101:  # raw IPv4
        return 0x0800, frame
    return None


class PcapAnalysis:
    """The structured wire facts a pcap yields, all INTEGER-exact."""

    def __init__(self) -> None:
        self.records = 0
        # (src_ip, sport, dst_ip, dport, proto) for IPv4 TCP/UDP
        self.ipv4_flows: list[tuple[str, int, str, int, int]] = []
        self.mdns_packets = 0
        self.ipv4_multicast_or_broadcast = 0
        self.external_ipv4_flows: list[tuple[str, str]] = []  # (src_ip, dst_ip)
        self.ipv6_total = 0
        self.ipv6_icmp = 0  # ND / MLD housekeeping - ALLOWED
        self.ipv6_non_icmp = 0  # any IPv6 UDP/TCP - unexpected in this topology
        # conversation bytes keyed by a canonical endpoint-pair
        self.conv_bytes: dict[tuple, int] = {}
        self.distinct_ipv4: set[str] = set()

    @property
    def libp2p_conv_max_bytes(self) -> int:
        best = 0
        for (a_ip, a_port, b_ip, b_port), nbytes in self.conv_bytes.items():
            if _is_libp2p_port(a_port) or _is_libp2p_port(b_port):
                best = max(best, nbytes)
        return best

    @property
    def libp2p_listener_ports(self) -> set[int]:
        ports: set[int] = set()
        for src_ip, sport, dst_ip, dport, _ in self.ipv4_flows:
            if _is_libp2p_port(sport):
                ports.add(sport)
            if _is_libp2p_port(dport):
                ports.add(dport)
        return ports


def _is_libp2p_port(port: int) -> bool:
    return LIBP2P_PORT_LO <= port < LIBP2P_PORT_HI


def _is_ipv4_multicast_or_broadcast(ip: str) -> bool:
    first = int(ip.split(".")[0])
    if 224 <= first <= 239:  # 224.0.0.0/4 multicast
        return True
    return ip == "255.255.255.255"


def analyze_pcap(data: bytes) -> PcapAnalysis:
    """Reparse a classic pcap into the wire facts the oracle needs. Pure over bytes so
    the mutation self-tests can drive it directly."""
    a = PcapAnalysis()
    a.records = count_pcap_records(data)
    for linktype, frame in _iter_frames(data):
        parsed = _l3_payload(linktype, frame)
        if parsed is None:
            continue
        ethertype, payload = parsed
        if ethertype == 0x0800:
            _analyze_ipv4(a, payload)
        elif ethertype == 0x86DD:
            _analyze_ipv6(a, payload)
    return a


def _analyze_ipv4(a: PcapAnalysis, payload: bytes) -> None:
    if len(payload) < 20 or (payload[0] >> 4) != 4:
        return
    ihl = (payload[0] & 0x0F) * 4
    protocol = payload[9]
    src_ip = ".".join(str(b) for b in payload[12:16])
    dst_ip = ".".join(str(b) for b in payload[16:20])
    a.distinct_ipv4.add(src_ip)
    a.distinct_ipv4.add(dst_ip)
    if _is_ipv4_multicast_or_broadcast(dst_ip):
        a.ipv4_multicast_or_broadcast += 1
    if protocol not in (6, 17) or len(payload) < ihl + 4:
        return
    src_port = struct.unpack(">H", payload[ihl : ihl + 2])[0]
    dst_port = struct.unpack(">H", payload[ihl + 2 : ihl + 4])[0]
    if protocol == 17 and (src_port == MDNS_PORT or dst_port == MDNS_PORT):
        a.mdns_packets += 1
    # Same-host invariant: in the shared-pod loopback topology EVERY legitimate flow
    # is loopback<->loopback or pasta-gateway<->pasta-gateway, so src_ip == dst_ip.
    # A different src/dst is a packet that left to an external host - a shortcut.
    if src_ip != dst_ip:
        a.external_ipv4_flows.append((src_ip, dst_ip))
    a.ipv4_flows.append((src_ip, src_port, dst_ip, dst_port, protocol))
    key = _conv_key(src_ip, src_port, dst_ip, dst_port)
    a.conv_bytes[key] = a.conv_bytes.get(key, 0) + len(payload)


# IPv6 extension headers that chain (next-header at byte 0). Hop-by-Hop / Dest Opts /
# Routing carry a Hdr-Ext-Len (byte 1, in 8-octet units beyond the first 8); Fragment
# is a fixed 8 bytes. ICMPv6 ND/MLD frequently sit BEHIND a Hop-by-Hop Router-Alert,
# so a naive read of the fixed-header next-header field misclassifies them.
_IPV6_EXT_HEADERS = {0, 43, 60}


def _ipv6_upper_layer(payload: bytes) -> tuple[int, int]:
    """Walk the IPv6 extension-header chain; return (upper_protocol, offset). Bounded:
    it stops at the first non-extension header, at end-of-buffer, or after a small cap."""
    next_header = payload[6]
    offset = 40
    for _ in range(8):  # a small, bounded chain cap
        if next_header in _IPV6_EXT_HEADERS:
            if offset + 2 > len(payload):
                break
            ext_len = (payload[offset + 1] + 1) * 8
            next_header = payload[offset]
            offset += ext_len
        elif next_header == 44:  # Fragment header, fixed 8 bytes
            if offset + 8 > len(payload):
                break
            next_header = payload[offset]
            offset += 8
        else:
            break
    return next_header, offset


def _analyze_ipv6(a: PcapAnalysis, payload: bytes) -> None:
    a.ipv6_total += 1
    if len(payload) < 40 or (payload[0] >> 4) != 6:
        a.ipv6_non_icmp += 1
        return
    upper, offset = _ipv6_upper_layer(payload)
    if upper == 58:  # ICMPv6 (neighbor discovery / MLD) - benign housekeeping
        a.ipv6_icmp += 1
        return
    # Any IPv6 UDP (esp. mdns on ff02::fb:5353) or TCP is unexpected here; flag it.
    if upper == 17 and offset + 4 <= len(payload):
        sport = struct.unpack(">H", payload[offset : offset + 2])[0]
        dport = struct.unpack(">H", payload[offset + 2 : offset + 4])[0]
        if sport == MDNS_PORT or dport == MDNS_PORT:
            a.mdns_packets += 1
    a.ipv6_non_icmp += 1


def _conv_key(src_ip: str, sport: int, dst_ip: str, dport: int) -> tuple:
    return min((src_ip, sport), (dst_ip, dport)) + max((src_ip, sport), (dst_ip, dport))


def derive_wire_verdict(pcap_bytes: bytes, meta: dict) -> dict:
    """PURE re-derivation of the wire oracle from the pcap bytes + the capture's own
    counters. FAILS CLOSED. A pass requires: a complete non-empty capture with 0
    kernel drops; zero mdns; zero IPv4 multicast/broadcast; zero external-unicast
    flows; zero unexpected IPv6 (ICMPv6 ND is allowed); a libp2p peer mesh (>=2
    listener ports) with a NAR-scale peer transfer."""
    problems: list[str] = []
    a = analyze_pcap(pcap_bytes)

    captured = int(meta.get("captured", -1))
    dropped = int(meta.get("dropped", -1))

    if not meta.get("attached"):
        problems.append("pcap capture did not attach to the s7 pod netns")
    if a.records <= 0:
        problems.append("pcap has zero parseable records (empty/not a pcap)")
    # Completeness: our own record count must equal tcpdump's captured counter. A
    # truncated/lossy pcap cannot license a zero-forbidden claim.
    if captured < 0:
        problems.append("pcap-meta has no tcpdump 'captured' counter")
    elif a.records != captured:
        problems.append(
            f"pcap record count {a.records} != tcpdump captured {captured} "
            "(truncated/incomplete capture)"
        )
    if dropped != 0:
        problems.append(
            f"tcpdump reported {dropped} kernel-dropped packet(s); a lossy capture "
            "cannot prove the absence of a forbidden substrate"
        )

    # NEGATIVE: no non-kad discovery substrate on the wire.
    if a.mdns_packets != 0:
        problems.append(f"{a.mdns_packets} mdns (UDP/5353) packet(s) on the wire")
    if a.ipv4_multicast_or_broadcast != 0:
        problems.append(
            f"{a.ipv4_multicast_or_broadcast} IPv4 multicast/broadcast packet(s) "
            "on the wire (a LAN-broadcast discovery substrate)"
        )
    if a.external_ipv4_flows:
        sample = sorted(set(a.external_ipv4_flows))[:4]
        problems.append(
            f"{len(a.external_ipv4_flows)} external-unicast packet(s) (src_ip != "
            f"dst_ip; sample {sample}) - a connection left to an external host"
        )
    if a.ipv6_non_icmp != 0:
        problems.append(
            f"{a.ipv6_non_icmp} non-ICMPv6 IPv6 packet(s) on the wire (unexpected; "
            "ICMPv6 ND is allowed, IPv6 UDP/TCP is not in this topology)"
        )

    # POSITIVE: the libp2p peer mesh spoke and moved a NAR-scale payload peer-to-peer.
    listener_ports = a.libp2p_listener_ports
    if len(listener_ports) < 2:
        problems.append(
            f"libp2p listener band shows <2 ports ({sorted(listener_ports)}); no "
            "peer mesh observed"
        )
    transfer = a.libp2p_conv_max_bytes
    if transfer < LIBP2P_TRANSFER_MIN_BYTES:
        problems.append(
            f"largest libp2p conversation is {transfer} bytes (< "
            f"{LIBP2P_TRANSFER_MIN_BYTES}); no NAR-scale peer transfer on the wire"
        )

    return {
        "wire_ok": not problems,
        "problems": problems,
        "records": int(a.records),
        "tcpdump_captured": captured,
        "tcpdump_dropped": dropped,
        "mdns_packets": int(a.mdns_packets),
        "ipv4_multicast_or_broadcast": int(a.ipv4_multicast_or_broadcast),
        "external_unicast_packets": int(len(a.external_ipv4_flows)),
        "ipv6_total": int(a.ipv6_total),
        "ipv6_icmp": int(a.ipv6_icmp),
        "ipv6_non_icmp": int(a.ipv6_non_icmp),
        "libp2p_listener_ports": sorted(int(p) for p in listener_ports),
        "libp2p_transfer_max_bytes": int(transfer),
        "distinct_ipv4": sorted(a.distinct_ipv4),
    }


# ---- the frozen TASK-126 binding -------------------------------------------


def derive_frozen_verdict(frozen_raw: str) -> dict:
    """RE-DERIVE the frozen-tree binding. A pass requires: the committed golden's
    ContentKey recipe + value equal the frozen TASK-126 constants; and the independent
    anchor reproduced them (its OK line present in raw-frozen.log)."""
    problems: list[str] = []
    golden_path = REPO / FROZEN_GOLDEN_REL
    content_key_hex = None
    context = None
    if not golden_path.is_file():
        problems.append(f"frozen golden {FROZEN_GOLDEN_REL} is absent")
    else:
        try:
            doc = json.loads(golden_path.read_text())
            ck = doc["content_key"]
            content_key_hex = ck.get("content_key_hex")
            context = ck.get("context")
        except (json.JSONDecodeError, KeyError) as exc:
            problems.append(f"frozen golden unparseable: {exc}")
    if context is not None and context != FROZEN_CONTENT_KEY_CONTEXT:
        problems.append(
            f"golden ContentKey context {context!r} != frozen "
            f"{FROZEN_CONTENT_KEY_CONTEXT!r} (freeze drift)"
        )
    if content_key_hex is not None and content_key_hex != FROZEN_CONTENT_KEY_HEX:
        problems.append(
            f"golden ContentKey {content_key_hex} != frozen TASK-126 "
            f"{FROZEN_CONTENT_KEY_HEX} (freeze drift)"
        )
    # The anchor's own OK line must be in its raw log (independent re-derivation).
    anchor_ok = FROZEN_ANCHOR_OK_SUBSTRING in frozen_raw
    if not anchor_ok:
        problems.append(
            "frozen anchor did not reproduce the ContentKey/records "
            f"(no {FROZEN_ANCHOR_OK_SUBSTRING!r} in raw-frozen.log)"
        )
    return {
        "frozen_ok": not problems,
        "problems": problems,
        "golden_content_key_hex": content_key_hex,
        "golden_context": context,
        "frozen_content_key_hex": FROZEN_CONTENT_KEY_HEX,
        "anchor_reproduced": bool(anchor_ok),
    }


# ---- capture ---------------------------------------------------------------


def run_capture(out: Path, scenarios: tuple[str, ...]) -> int:
    out.mkdir(parents=True, exist_ok=True)
    timings: dict[str, int] = {}

    # AC#9 source guard: self-test (bite) THEN real scan, captured verbatim.
    ac9_log = out / "raw-ac9.log"
    t0 = time.monotonic()
    guard = REPO / "scripts" / "check-discovery-no-shortcut.py"
    with ac9_log.open("wb") as fh:
        st = subprocess.run(
            [sys.executable, str(guard), "--self-test"],
            stdout=fh,
            stderr=subprocess.STDOUT,
            cwd=REPO,
        )
        fh.write(b"\n--- AC9-REAL-SCAN ---\n")
        sc = subprocess.run(
            [sys.executable, str(guard)], stdout=fh, stderr=subprocess.STDOUT, cwd=REPO
        )
    timings["ac9_guard_ms"] = int((time.monotonic() - t0) * 1000)
    if st.returncode != 0 or sc.returncode != 0:
        print(
            f"capture: AC#9 guard failed (self-test rc={st.returncode}, scan rc={sc.returncode})",
            file=sys.stderr,
        )

    # TASK-126 frozen-contract anchor, captured verbatim (part 3).
    frozen_log = out / "raw-frozen.log"
    t1 = time.monotonic()
    with frozen_log.open("wb") as fh:
        anchor = subprocess.run(
            [sys.executable, str(REPO / FROZEN_ANCHOR_REL)],
            stdout=fh,
            stderr=subprocess.STDOUT,
            cwd=REPO,
        )
    timings["frozen_anchor_ms"] = int((time.monotonic() - t1) * 1000)
    if anchor.returncode != 0:
        print(f"capture: frozen anchor rc={anchor.returncode}", file=sys.stderr)

    # Start the wire capture BEFORE the harness so it can attach to the s7 pod the
    # moment it appears, then run the harness (pcap is captured concurrently).
    watcher = _PcapWatcher(out)
    watcher.start()

    e2e_log = out / "raw-e2e.log"
    only_args: list[str] = []
    for s in scenarios:
        only_args += ["--only", s]
    t2 = time.monotonic()
    with e2e_log.open("wb") as fh:
        e2e = subprocess.run(
            [sys.executable, str(REPO / "scripts" / "e2e_harness.py"), *only_args],
            stdout=fh,
            stderr=subprocess.STDOUT,
            cwd=REPO,
        )
    timings["e2e_ms"] = int((time.monotonic() - t2) * 1000)
    print(f"capture: e2e harness exit={e2e.returncode} (raw log at {e2e_log})")

    # The watcher stops itself when the s7 pod is torn down; give it a bounded join.
    watcher.request_stop()
    watcher.join(timeout=30)

    (out / "timings.json").write_text(
        json.dumps(timings, indent=2, sort_keys=True) + "\n"
    )
    (out / "captured-scenarios.json").write_text(
        json.dumps({"scenarios": list(scenarios)}, indent=2) + "\n"
    )
    return 0


# ---- finalize --------------------------------------------------------------


def parse_e2e_checks(raw: str) -> dict:
    scenarios: dict[str, dict] = {}
    current: str | None = None
    for line in raw.splitlines():
        if line.startswith("=== scenario: ") and line.endswith(" ==="):
            current = line[len("=== scenario: ") : -len(" ===")].strip()
            scenarios[current] = {"ok": 0, "fail": 0, "ok_lines": [], "fail_lines": []}
            continue
        if current is None:
            continue
        if line.startswith("  ok  "):
            scenarios[current]["ok"] += 1
            scenarios[current]["ok_lines"].append(line.strip())
        elif line.startswith("  FAIL "):
            scenarios[current]["fail"] += 1
            scenarios[current]["fail_lines"].append(line.strip())
    return scenarios


def derive_verdict(e2e_raw: str, ac9_raw: str) -> dict:
    """PURE re-derivation of the harness + AC#9 half of the verdict from the two raw
    STRINGS (no file IO), so the mutation self-tests can drive it directly."""
    problems: list[str] = []
    scenarios = parse_e2e_checks(e2e_raw)
    checks_ok = sum(s["ok"] for s in scenarios.values())
    checks_fail = sum(s["fail"] for s in scenarios.values())

    if checks_fail != 0:
        problems.append(
            f"aggregate checks_fail={checks_fail} (must be 0; ANY arm's FAIL fails)"
        )
    for name in REQUIRED_SCENARIOS:
        if name not in scenarios:
            problems.append(f"raw e2e log has no {name} scenario section (arm omitted)")
        elif scenarios[name]["ok"] == 0:
            problems.append(f"{name} has zero ok checks (vacuous)")
        elif scenarios[name]["fail"] != 0:
            problems.append(
                f"{name} has {scenarios[name]['fail']} FAIL check(s) in the raw log"
            )

    all_ok_lines = "\n".join(ln for s in scenarios.values() for ln in s["ok_lines"])
    missing = [sub for sub in REQUIRED_OK_SUBSTRINGS if sub not in all_ok_lines]
    if missing:
        problems.append(f"required oracle line(s) absent from ok checks: {missing}")

    if "e2e: ALL SCENARIOS PASSED" not in e2e_raw:
        problems.append("raw e2e log does not end in ALL SCENARIOS PASSED")

    ac9_bite = "self-test OK" in ac9_raw and "BITES" in ac9_raw
    ac9_scan_ok = "OK - " in ac9_raw and "kad-EXCLUSIVE" in ac9_raw
    ac9_forbidden = "FORBIDDEN non-kad discovery substrate found" in ac9_raw
    if not ac9_bite:
        problems.append(
            "AC#9 guard self-test did not demonstrate the bite in its raw log"
        )
    if not ac9_scan_ok or ac9_forbidden:
        problems.append("AC#9 real scan not clean in its raw log")

    return {
        "verdict": "pass" if not problems else "fail",
        "problems": problems,
        "checks_ok": int(checks_ok),
        "checks_fail": int(checks_fail),
        "scenarios": scenarios,
        "all_ok_lines": all_ok_lines,
        "missing_required": missing,
        "ac9_bite": bool(ac9_bite),
        "ac9_scan_ok": bool(ac9_scan_ok),
        "ac9_forbidden": bool(ac9_forbidden),
    }


def _raw_captures_meta(out: Path) -> dict:
    meta: dict[str, dict] = {}
    for name in RAW_FILES:
        p = out / name
        if p.is_file():
            digest, size = sha256_of(p)
            meta[name] = {"sha256": digest, "bytes": int(size)}
    return meta


def _attach_capture_meta(out: Path, artifact: dict) -> None:
    for name in ("timings.json", "captured-scenarios.json", "pcap-meta.json"):
        p = out / name
        if p.is_file():
            key = name.replace(".json", "").replace("-", "_")
            artifact[key] = json.loads(p.read_text())


def _write_tracked(tracked_path: Path | None, out: Path, artifact: dict) -> None:
    serialised = json.dumps(artifact, indent=2, sort_keys=True) + "\n"
    out.mkdir(parents=True, exist_ok=True)
    (out / "verdict.json").write_text(serialised)
    if tracked_path is not None:
        tracked_path.write_text(serialised)


def run_finalize(
    out: Path,
    tracked_path: Path | None = DEFAULT_TRACKED,
    tree_files: tuple[str, ...] = TREE_FILES,
    verify_manifest_head: bool = True,
) -> int:
    required = [out / name for name in RAW_FILES]
    missing = [str(p) for p in required if not p.is_file()]
    if missing:
        problems = [f"missing raw capture {p}" for p in missing]
        _write_tracked(
            tracked_path,
            out,
            {
                "schema": "decentralized-content-discovery-v1",
                "task": "TASK-155",
                "verdict": "fail",
                "rederived_from_raw": True,
                "problems": problems,
            },
        )
        for p in problems:
            print(f"finalize: {p}", file=sys.stderr)
        return 1

    e2e_raw = (out / "raw-e2e.log").read_text(errors="replace")
    ac9_raw = (out / "raw-ac9.log").read_text(errors="replace")
    frozen_raw = (out / "raw-frozen.log").read_text(errors="replace")
    pcap_bytes = (out / "raw-s7.pcap").read_bytes()
    pcap_meta = {}
    if (out / "pcap-meta.json").is_file():
        pcap_meta = json.loads((out / "pcap-meta.json").read_text())

    d = derive_verdict(e2e_raw, ac9_raw)
    w = derive_wire_verdict(pcap_bytes, pcap_meta)
    fz = derive_frozen_verdict(frozen_raw)
    problems = list(d["problems"])
    problems += [f"wire: {p}" for p in w["problems"]]
    problems += [f"frozen: {p}" for p in fz["problems"]]

    manifest = tree_manifest(tree_files)
    frozen_manifest = tree_manifest(FROZEN_TREE_FILES)
    if verify_manifest_head:
        problems.extend(_manifest_head_drift(manifest))
        problems.extend(f"frozen {p}" for p in _manifest_head_drift(frozen_manifest))

    raw_captures = _raw_captures_meta(out)

    verdict = "pass" if not problems else "fail"
    artifact = {
        "schema": "decentralized-content-discovery-v1",
        "task": "TASK-155",
        "verdict": verdict,
        "rederived_from_raw": True,
        "git_head": _git_head_commit(),
        "checks": {
            "ok": int(d["checks_ok"]),
            "fail": int(d["checks_fail"]),
            "per_scenario": {
                name: {"ok": int(s["ok"]), "fail": int(s["fail"])}
                for name, s in d["scenarios"].items()
            },
        },
        "no_injection": {
            "consumer_lacks_provider_peerid": any(
                "consumer argv does NOT contain the provider's PeerId" in ln
                for ln in d["all_ok_lines"].splitlines()
            ),
            "consumer_lacks_provider_addr_flag": any(
                "consumer has NO --libp2p-provider-addr" in ln
                for ln in d["all_ok_lines"].splitlines()
            ),
            "consumer_bootstrap_is_boot_only": any(
                "consumer --libp2p-bootstrap is EXACTLY the real BOOT node" in ln
                for ln in d["all_ok_lines"].splitlines()
            ),
        },
        "ac9_discovery_kad_exclusive": {
            "self_test_bites": bool(d["ac9_bite"]),
            "real_scan_clean": bool(d["ac9_scan_ok"] and not d["ac9_forbidden"]),
        },
        "wire_evidence": {
            "ok": bool(w["wire_ok"]),
            "records": w["records"],
            "tcpdump_captured": w["tcpdump_captured"],
            "tcpdump_dropped": w["tcpdump_dropped"],
            "mdns_packets": w["mdns_packets"],
            "ipv4_multicast_or_broadcast": w["ipv4_multicast_or_broadcast"],
            "external_unicast_packets": w["external_unicast_packets"],
            "ipv6_total": w["ipv6_total"],
            "ipv6_icmp_nd": w["ipv6_icmp"],
            "ipv6_non_icmp": w["ipv6_non_icmp"],
            "libp2p_listener_ports": w["libp2p_listener_ports"],
            "libp2p_transfer_max_bytes": w["libp2p_transfer_max_bytes"],
            "libp2p_transfer_min_required": LIBP2P_TRANSFER_MIN_BYTES,
            "distinct_ipv4": w["distinct_ipv4"],
        },
        "frozen_binding": {
            "ok": bool(fz["frozen_ok"]),
            "golden": FROZEN_GOLDEN_REL,
            "content_key_context": fz["golden_context"],
            "content_key_hex": fz["golden_content_key_hex"],
            "frozen_content_key_hex": fz["frozen_content_key_hex"],
            "anchor_reproduced": fz["anchor_reproduced"],
        },
        "required_oracle_lines_present": int(
            len(REQUIRED_OK_SUBSTRINGS) - len(d["missing_required"])
        ),
        "required_oracle_lines_total": int(len(REQUIRED_OK_SUBSTRINGS)),
        "raw_captures": raw_captures,
        "tree_manifest": manifest,
        "frozen_tree_manifest": frozen_manifest,
        "problems": problems,
    }
    _attach_capture_meta(out, artifact)
    _write_tracked(tracked_path, out, artifact)
    print(
        f"finalize: verdict={verdict} (ok={d['checks_ok']}, fail={d['checks_fail']}, "
        f"wire_ok={w['wire_ok']} records={w['records']} mdns={w['mdns_packets']} "
        f"ext={w['external_unicast_packets']} xfer={w['libp2p_transfer_max_bytes']}B, "
        f"frozen_ok={fz['frozen_ok']} ck={fz['golden_content_key_hex']})"
    )
    if problems:
        for p in problems:
            print(f"finalize: PROBLEM {p}", file=sys.stderr)
    return 0 if verdict == "pass" else 1


def run_verify(out: Path, tracked_path: Path = DEFAULT_TRACKED) -> int:
    if not tracked_path.is_file():
        print(f"verify: no tracked artifact at {tracked_path}", file=sys.stderr)
        return 1
    art = json.loads(tracked_path.read_text())
    if art.get("verdict") != "pass":
        print(f"verify: tracked verdict is {art.get('verdict')!r}, not a pass")
        return 1
    recorded = art.get("raw_captures") or {}
    if not recorded:
        print(
            "verify: tracked artifact records NO raw_captures hashes", file=sys.stderr
        )
        return 1
    problems: list[str] = []
    for name, meta in recorded.items():
        p = out / name
        if not p.is_file():
            problems.append(f"raw {name} recorded in the artifact is MISSING on disk")
            continue
        digest, _ = sha256_of(p)
        if digest != meta.get("sha256"):
            problems.append(
                f"raw {name} sha256 {digest} != recorded {meta.get('sha256')} (tampered)"
            )
    if problems:
        for pr in problems:
            print(f"verify: PROBLEM {pr}", file=sys.stderr)
        return 1
    print(
        f"verify: tracked pass matches its {len(recorded)} on-disk raw capture(s) "
        f"({tracked_path.name})"
    )
    return 0


# ---- mutation-bite self-tests (no containers) ------------------------------

_GOOD_AC9 = (
    "check-discovery-no-shortcut: self-test OK - clean composition passes, the "
    "permitted NAT-traversal trio (autonat/dcutr/relay) is ALLOWED, and adding "
    "mdns::Behaviour BITES (AC#9 mutation caught)\n"
    "\n--- AC9-REAL-SCAN ---\n"
    "check-discovery-no-shortcut: OK - 7 shipped discovery source file(s) scanned; "
    "discovery is kad-EXCLUSIVE (no mdns/rendezvous/gossipsub/floodsub); the "
    "NAT-traversal trio (autonat/dcutr/relay) is permitted dial-assistance\n"
)

_GOOD_FROZEN = (
    "check-content-key-derivation: OK (ContentKey recipe + 4 records decoded + 8 "
    "rejects independently reproduced, pure-python ed25519)\n"
)

_GOOD_E2E = (
    "e2e: 2 scenarios registered\n"
    "=== scenario: s7-libp2p ===\n"
    "  ok   S7 no-injection: consumer argv does NOT contain the provider's PeerId\n"
    "  ok   S7 no-injection: consumer has NO --libp2p-provider-addr (dial resolved via kad)\n"
    "  ok   S7 no-injection: consumer --libp2p-bootstrap is EXACTLY the real BOOT node "
    "(no provider listen-addr or PeerId injected out-of-band)\n"
    "  ok   S7 S1 byte-identity: lib NarHash matches the signed upstream\n"
    "  ok   S7 oracle: 0 upstream NAR egress (the target was peer-served)\n"
    "  ok   S7 load-bearing control: upstream served the FULL NAR once P is dead\n"
    "=== scenario: s7-libp2p-miss ===\n"
    "  ok   S7 miss: build succeeds via upstream when no peer announces the target\n"
    "  ok   S7 miss: byte-identical (served by upstream after the kad miss)\n"
    "  ok   S7 miss: upstream actually served the NAR (kad miss -> fallback engaged)\n"
    "\ne2e: ALL SCENARIOS PASSED\n"
)


# -- synthetic classic-pcap builders (SLL2 / linktype 276, `-i any`) ---------


def _pcap_header(linktype: int = 276) -> bytes:
    # magic (big-endian a1b2c3d4), v2.4, tz 0, sigfigs 0, snaplen 262144, linktype.
    return struct.pack(">IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, linktype)


def _sll2_ipv4(src_ip: str, sport: int, dst_ip: str, dport: int, proto: int, pad: int):
    # Minimal SLL2 header (20 bytes): ethertype(2)=0x0800 + reserved to 20.
    sll2 = struct.pack(">H", 0x0800) + b"\x00" * 18
    src = bytes(int(x) for x in src_ip.split("."))
    dst = bytes(int(x) for x in dst_ip.split("."))
    l4 = struct.pack(">HH", sport, dport) + b"\x00" * (max(4, pad))
    total = 20 + len(l4)
    ip = (
        bytes([0x45, 0x00])
        + struct.pack(">H", total)
        + b"\x00\x00\x00\x00\x40"
        + bytes([proto])
        + b"\x00\x00"
        + src
        + dst
        + l4
    )
    return sll2 + ip


def _sll2_icmpv6_nd() -> bytes:
    # An IPv6 (ethertype 0x86DD) ICMPv6 (next-header 58) frame to ff02::1 - benign ND.
    sll2 = struct.pack(">H", 0x86DD) + b"\x00" * 18
    src = b"\xfe\x80" + b"\x00" * 14
    dst = b"\xff\x02" + b"\x00" * 13 + b"\x01"
    payload = b"\x87" + b"\x00" * 7  # neighbor solicitation-ish
    ipv6 = (
        b"\x60\x00\x00\x00"
        + struct.pack(">H", len(payload))
        + bytes([58, 255])
        + src
        + dst
        + payload
    )
    return sll2 + ipv6


def _record(frame: bytes) -> bytes:
    return struct.pack(">IIII", 0, 0, len(frame), len(frame)) + frame


def _good_pcap() -> bytes:
    """A synthetic pcap mirroring the real s7 capture shape: a libp2p peer mesh among
    three loopback listener ports with a NAR-scale transfer, in-pod + gateway HTTP,
    and one benign ICMPv6 ND frame. No mdns, no multicast, no external unicast."""
    frames: list[bytes] = []
    # libp2p mesh: 37000<->37001 (the NAR transfer), 37000<->37002, 37001<->37002.
    # Make 37000<->37001 carry >= LIBP2P_TRANSFER_MIN_BYTES total.
    big = LIBP2P_TRANSFER_MIN_BYTES + 5000
    n_big = 40
    per = big // n_big
    for _ in range(n_big):
        frames.append(_sll2_ipv4("127.0.0.1", 37000, "127.0.0.1", 37001, 6, per))
    for _ in range(6):
        frames.append(_sll2_ipv4("127.0.0.1", 37000, "127.0.0.1", 37002, 6, 40))
        frames.append(_sll2_ipv4("127.0.0.1", 37001, "127.0.0.1", 37002, 6, 40))
    # in-pod HTTP narinfo (small) + gateway-reflected HTTP (same IP both ends).
    for _ in range(4):
        frames.append(_sll2_ipv4("127.0.0.1", 40000, "127.0.0.1", 8081, 6, 20))
        frames.append(_sll2_ipv4("10.221.148.66", 47062, "10.221.148.66", 8081, 6, 20))
    frames.append(_sll2_icmpv6_nd())
    return _pcap_header() + b"".join(_record(f) for f in frames)


def _good_pcap_meta(data: bytes) -> dict:
    return {
        "attached": True,
        "target": PCAP_ATTACH_TARGETS[-1],
        "captured": count_pcap_records(data),
        "received": count_pcap_records(data),
        "dropped": 0,
    }


def _st_check(cond: bool, msg: str, failures: list[str]) -> None:
    if not cond:
        failures.append(msg)


def run_self_test() -> int:  # noqa: C901 - a flat list of independent bites
    failures: list[str] = []

    # -- harness/ac9 baseline + the MVP bites (unchanged) --
    base = derive_verdict(_GOOD_E2E, _GOOD_AC9)
    _st_check(
        base["verdict"] == "pass",
        f"baseline should be pass, got {base['verdict']} problems={base['problems']}",
        failures,
    )
    miss_fail = _GOOD_E2E.replace(
        "  ok   S7 miss: byte-identical", "  FAIL S7 miss: byte-identical"
    )
    d1 = derive_verdict(miss_fail, _GOOD_AC9)
    _st_check(
        d1["verdict"] == "fail" and d1["checks_fail"] == 1,
        f"BITE miss-arm-FAIL did not flip verdict ({d1['verdict']}, fail={d1['checks_fail']})",
        failures,
    )
    idx = _GOOD_E2E.index("=== scenario: s7-libp2p-miss ===")
    omitted = _GOOD_E2E[:idx] + "\ne2e: ALL SCENARIOS PASSED\n"
    d2 = derive_verdict(omitted, _GOOD_AC9)
    _st_check(
        d2["verdict"] == "fail" and any("s7-libp2p-miss" in p for p in d2["problems"]),
        f"BITE omitted-arm did not fail ({d2['verdict']}, {d2['problems']})",
        failures,
    )
    truncated = _GOOD_E2E.replace("\ne2e: ALL SCENARIOS PASSED\n", "\n")
    _st_check(
        derive_verdict(truncated, _GOOD_AC9)["verdict"] == "fail",
        "BITE truncated-run did not fail",
        failures,
    )
    drop_line = _GOOD_E2E.replace(
        "  ok   S7 no-injection: consumer --libp2p-bootstrap is EXACTLY the real BOOT node "
        "(no provider listen-addr or PeerId injected out-of-band)\n",
        "",
    )
    d2c = derive_verdict(drop_line, _GOOD_AC9)
    _st_check(
        d2c["verdict"] == "fail"
        and any("EXACTLY the real BOOT node" in m for m in d2c["missing_required"]),
        f"BITE dropped-strengthened-oracle-line did not fail ({d2c['missing_required']})",
        failures,
    )
    # NEW BITE: the no-injection-argv oracle line absent -> fail (part 2).
    drop_argv = _GOOD_E2E.replace(
        "  ok   S7 no-injection: consumer argv does NOT contain the provider's PeerId\n",
        "",
    )
    d_argv = derive_verdict(drop_argv, _GOOD_AC9)
    _st_check(
        d_argv["verdict"] == "fail"
        and any(
            "does NOT contain the provider's PeerId" in m
            for m in d_argv["missing_required"]
        ),
        "BITE missing-no-injection-argv-oracle did not fail",
        failures,
    )

    # -- WIRE oracle baseline + bites (part 1) --
    good_pcap = _good_pcap()
    good_meta = _good_pcap_meta(good_pcap)
    wbase = derive_wire_verdict(good_pcap, good_meta)
    _st_check(
        wbase["wire_ok"],
        f"wire baseline should pass, got {wbase['problems']}",
        failures,
    )
    # BITE: an mdns packet on the wire -> fail.
    mdns_frame = _sll2_ipv4("127.0.0.1", MDNS_PORT, "127.0.0.1", MDNS_PORT, 17, 20)
    mdns_pcap = good_pcap + _record(mdns_frame)
    mdns_meta = _good_pcap_meta(mdns_pcap)
    wm = derive_wire_verdict(mdns_pcap, mdns_meta)
    _st_check(
        not wm["wire_ok"] and wm["mdns_packets"] >= 1,
        f"BITE mdns-packet did not fail the wire oracle ({wm['problems']})",
        failures,
    )
    # BITE: an IPv4 multicast packet (224.0.0.251) -> fail.
    mcast_frame = _sll2_ipv4("127.0.0.1", 5000, "224.0.0.251", 5353, 17, 20)
    mcast_pcap = good_pcap + _record(mcast_frame)
    wmc = derive_wire_verdict(mcast_pcap, _good_pcap_meta(mcast_pcap))
    _st_check(
        not wmc["wire_ok"] and wmc["ipv4_multicast_or_broadcast"] >= 1,
        f"BITE multicast-packet did not fail the wire oracle ({wmc['problems']})",
        failures,
    )
    # BITE: an external-unicast flow (src_ip != dst_ip, e.g. to a tracker) -> fail.
    ext_frame = _sll2_ipv4("10.211.31.10", 44000, "203.0.113.7", 4001, 6, 40)
    ext_pcap = good_pcap + _record(ext_frame)
    we = derive_wire_verdict(ext_pcap, _good_pcap_meta(ext_pcap))
    _st_check(
        not we["wire_ok"] and we["external_unicast_packets"] >= 1,
        f"BITE external-unicast did not fail the wire oracle ({we['problems']})",
        failures,
    )
    # BITE: a truncated pcap (record count != tcpdump captured) -> fail.
    trunc_pcap = good_pcap[:-10]
    wt = derive_wire_verdict(trunc_pcap, good_meta)  # meta still claims full count
    _st_check(
        not wt["wire_ok"]
        and any("truncated" in p or "!= tcpdump" in p for p in wt["problems"]),
        f"BITE truncated-pcap did not fail ({wt['problems']})",
        failures,
    )
    # BITE: a kernel drop (dropped>0) -> fail (a lossy capture proves no absence).
    drop_meta = dict(good_meta)
    drop_meta["dropped"] = 3
    wd = derive_wire_verdict(good_pcap, drop_meta)
    _st_check(
        not wd["wire_ok"] and any("kernel-dropped" in p for p in wd["problems"]),
        f"BITE kernel-drop did not fail ({wd['problems']})",
        failures,
    )
    # BITE: a libp2p mesh with NO NAR-scale transfer -> fail (no peer-serve on wire).
    small_frames = [
        _sll2_ipv4("127.0.0.1", 37000, "127.0.0.1", 37001, 6, 40) for _ in range(4)
    ]
    small_frames.append(_sll2_ipv4("127.0.0.1", 37001, "127.0.0.1", 37002, 6, 40))
    small_pcap = _pcap_header() + b"".join(_record(f) for f in small_frames)
    ws = derive_wire_verdict(small_pcap, _good_pcap_meta(small_pcap))
    _st_check(
        not ws["wire_ok"]
        and any("NAR-scale peer transfer" in p for p in ws["problems"]),
        f"BITE no-peer-transfer did not fail ({ws['problems']})",
        failures,
    )
    # BITE: an unattached capture (harness ran but the watcher never attached) -> fail.
    wu = derive_wire_verdict(good_pcap, {**good_meta, "attached": False})
    _st_check(
        not wu["wire_ok"],
        "BITE unattached-capture did not fail",
        failures,
    )

    # -- FROZEN binding baseline + bites (part 3) --
    fbase = derive_frozen_verdict(_GOOD_FROZEN)
    _st_check(
        fbase["frozen_ok"]
        and fbase["golden_content_key_hex"] == FROZEN_CONTENT_KEY_HEX,
        f"frozen baseline should pass against the committed golden ({fbase['problems']})",
        failures,
    )
    # BITE: the anchor did not reproduce (its OK line absent) -> fail.
    fna = derive_frozen_verdict("some other output without the ok line\n")
    _st_check(
        not fna["frozen_ok"] and any("did not reproduce" in p for p in fna["problems"]),
        f"BITE anchor-not-reproduced did not fail ({fna['problems']})",
        failures,
    )
    # BITE: a golden whose ContentKey no longer matches the frozen TASK-126 value ->
    # fail. Point the derivation at a temp golden with a mutated key.
    _st_check(
        _frozen_golden_mutation_bites(),
        "BITE frozen-golden-drift did not fail",
        failures,
    )

    # -- IO layer: finalize a clean full capture set, then tamper (part 1+2+3) --
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "out"
        out.mkdir()
        (out / "raw-e2e.log").write_text(_GOOD_E2E)
        (out / "raw-ac9.log").write_text(_GOOD_AC9)
        (out / "raw-frozen.log").write_text(_GOOD_FROZEN)
        (out / "raw-s7.pcap").write_bytes(good_pcap)
        (out / "pcap-meta.json").write_text(json.dumps(good_meta))
        tracked = Path(tmp) / "tracked.json"
        rc = run_finalize(out, tracked_path=tracked, verify_manifest_head=False)
        art = json.loads(tracked.read_text())
        _st_check(
            rc == 0 and art["verdict"] == "pass",
            f"self-test finalize of a clean full capture set did not pass (rc={rc}, "
            f"problems={art.get('problems')})",
            failures,
        )
        _st_check(
            set(art.get("raw_captures", {})) == set(RAW_FILES),
            f"tracked artifact missing raw_captures hashes: {art.get('raw_captures')}",
            failures,
        )
        _st_check(
            run_verify(out, tracked_path=tracked) == 0,
            "verify untampered should pass",
            failures,
        )
        # TAMPER the pcap -> verify must fail.
        (out / "raw-s7.pcap").write_bytes(good_pcap + b"tampered")
        _st_check(
            run_verify(out, tracked_path=tracked) == 1,
            "BITE tampered-pcap did not fail --verify",
            failures,
        )
        # A vanished raw -> re-finalize INVALIDATES the tracked pass.
        (out / "raw-s7.pcap").unlink()
        rc2 = run_finalize(out, tracked_path=tracked, verify_manifest_head=False)
        _st_check(
            rc2 == 1 and json.loads(tracked.read_text())["verdict"] == "fail",
            "BITE re-finalize with a missing pcap did not invalidate the tracked pass",
            failures,
        )

    if failures:
        for f in failures:
            print(f"self-test FAILED: {f}", file=sys.stderr)
        return 1
    print(
        "decentralized_discovery_evidence: self-test OK - harness/ac9 bites "
        "(miss-arm FAIL, omitted arm, truncated run, dropped/absent oracle lines), "
        "WIRE bites (mdns, multicast, external unicast, truncated pcap, kernel drop, "
        "no peer transfer, unattached), FROZEN bites (anchor absent, golden drift), "
        "and IO bites (tampered/missing pcap, re-finalize invalidation) all BITE"
    )
    return 0


def _frozen_golden_mutation_bites() -> bool:
    """Drive derive_frozen_verdict against a mutated golden by pointing FROZEN_GOLDEN
    at a temp file with a wrong ContentKey; must fail. Restores the constant after."""
    global FROZEN_GOLDEN_REL
    original = FROZEN_GOLDEN_REL
    try:
        golden = json.loads((REPO / original).read_text())
        golden["content_key"]["content_key_hex"] = "00" * 32
        with tempfile.TemporaryDirectory() as tmp:
            mutated = Path(tmp) / "mutated_golden.json"
            mutated.write_text(json.dumps(golden))
            # derive_frozen_verdict reads `REPO / FROZEN_GOLDEN_REL`; pathlib collapses
            # `REPO / <absolute>` to the absolute path, so pointing the constant at an
            # absolute temp path drives the derivation against the mutated golden.
            FROZEN_GOLDEN_REL = str(mutated)
            fz = derive_frozen_verdict(_GOOD_FROZEN)
            return (not fz["frozen_ok"]) and any(
                "!= frozen TASK-126" in p for p in fz["problems"]
            )
    finally:
        FROZEN_GOLDEN_REL = original


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--capture", action="store_true", help="run + write raw captures only"
    )
    ap.add_argument(
        "--finalize", action="store_true", help="re-derive verdict from raw captures"
    )
    ap.add_argument(
        "--verify",
        action="store_true",
        help="re-check the tracked artifact against on-disk raws",
    )
    ap.add_argument(
        "--self-test", action="store_true", help="run the mutation-bite self-tests"
    )
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT, help="artifact directory")
    ap.add_argument(
        "--only",
        action="append",
        default=[],
        help="restrict capture to these scenario(s)",
    )
    args = ap.parse_args(argv)

    if args.self_test:
        return run_self_test()
    if args.verify:
        return run_verify(args.out)

    scenarios = tuple(args.only) if args.only else EVIDENCE_SCENARIOS

    do_capture = args.capture or not args.finalize
    do_finalize = args.finalize or not args.capture
    if do_capture:
        rc = run_capture(args.out, scenarios)
        if rc != 0 and not do_finalize:
            return rc
    if do_finalize:
        return run_finalize(args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
