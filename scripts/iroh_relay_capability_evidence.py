#!/usr/bin/env python3
"""Routed relay-capability evidence for TASK-142.

Captures namespace-isolated evidence that the deterministic TASK-139 relay
transport carries a REAL connection when the direct peer-to-peer path is
L3-blocked, and that a direct-positive control is NOT credited to the relay.
Emits a raw evidence tree (``run.json`` + per-arm peer outcomes, capture logs and
pcaps + ``manifest.json``) that ``scripts/finalize_iroh_relay_capability.py``
turns into the immutable ``iroh-relay-capability-v1`` artifact.

Topology (rootless podman, two internal DNS-disabled networks + a tiny L3
router):

    connector-net (10.x.a.0/24)          acceptor-net (10.x.b.0/24)
      connector .10  --- router .20 ==== router .20 --- acceptor .10
                                             relay .40

The relay lives on the acceptor network at a fixed IP that BOTH peers route to
through the router, so both rendezvous on the SAME relay URL. The connector is
given ONLY a /32 route to the relay IP, never a route to the acceptor peer, so
the direct path is blocked at L3: a successful connection can only be relayed,
which the capture inside the connector netns proves (packets to the relay, none
to the acceptor peer). The direct-positive control additionally routes the
connector to the acceptor peer, so that connection goes direct and must NOT be
credited to the relay.

This evidence is ``production-shaped-local``: the relay is locally operated and
self-signed. No n0/public relay is ever contacted.

``--self-test`` runs container-free: it asserts the command construction (both
networks internal + dns-disabled, capture filter, relay reachable from both
peers, direct blocked except the control) and bites the outcome validator by
mutation.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import struct
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

import iroh_node_publication_evidence as publication

SCHEMA = "iroh-relay-capability-evidence-v1"
MANIFEST_SCHEMA = "iroh-relay-capability-raw-evidence-manifest-v1"
LABEL_KEY = "org.nix-p2p.iroh-relay-evidence-run"
IMAGE_REVISION_LABEL = publication.IMAGE_REVISION_LABEL
NAME_PREFIX = "nix-p2p-task142"

SUBNET_POOL = ipaddress.ip_network("10.208.0.0/12")
SUBNET_PREFIX = 24

# Deterministic host offsets within each /24 (index into subnet.hosts()). These
# are the SINGLE SOURCE OF TRUTH for the packet-attribution coordinates: the
# finalizer re-derives relay_ip / acceptor_ip from the acceptor subnet at these
# exact offsets and rejects any run.json that relocates them, so the direct-block
# claim cannot be masked by a forged coordinate.
CONNECTOR_HOST_OFFSET = 9
ACCEPTOR_HOST_OFFSET = 9
RELAY_HOST_OFFSET = 39
DEAD_RELAY_HOST_OFFSET = 41

RELAY_HTTPS_PORT = 44380
IROH_PORT = 44330
DEADLINE_MS = 10_000
GRACE_MS = 1_000
CAPTURE_FILTER = "tcp or udp"
CAPTURE_INTERFACE = "any"
CAPTURE_SCOPE = "all-tcp-udp-in-peer-netns-v1"
PROFILE = "production-shaped-local"

OWNER = "nix-p2p-task142-evidence"

# Each connect arm and the expected typed outcome the finalizer asserts. A value
# of ``None`` reason means the arm must CONNECT (positive/control); otherwise the
# arm must be typed-unavailable and the reason must be in the allowed set.
CONNECT_ARMS: dict[str, dict[str, object]] = {
    "relay-success": {
        "verdict": "connected",
        "path": "relayed",
        "relay_attributed": True,
    },
    "direct-positive": {
        "verdict": "connected",
        "path": "direct",
        "relay_attributed": False,
    },
    "relay-outage": {"verdict": "unavailable", "reasons": ("relay_outage", "deadline")},
    "wrong-url": {"verdict": "unavailable", "reasons": ("wrong_relay_url",)},
    "wrong-certificate": {
        "verdict": "unavailable",
        "reasons": ("wrong_certificate", "relay_outage", "deadline"),
    },
    "wrong-identity": {
        "verdict": "unavailable",
        "reasons": ("wrong_identity", "deadline"),
    },
    "half-open-stream": {
        "verdict": "unavailable",
        "reasons": ("half_open_stream", "deadline"),
    },
    "forced-direct-failure": {
        "verdict": "unavailable",
        "reasons": ("forced_direct_failure", "deadline"),
    },
}


class EvidenceFailure(RuntimeError):
    """A routed run produced invalid or missing evidence."""


def fail(message: str) -> NoReturn:
    raise EvidenceFailure(message)


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


@dataclass(frozen=True)
class RunConfig:
    output: Path
    image: str
    podman: str = "podman"


@dataclass(frozen=True)
class Topology:
    run_id: str
    connector_network: str
    acceptor_network: str
    router: str
    connector_subnet: str
    acceptor_subnet: str
    connector_ip: str
    router_connector_ip: str
    acceptor_ip: str
    router_acceptor_ip: str
    relay_ip: str
    dead_relay_ip: str

    @property
    def label(self) -> str:
        return f"{LABEL_KEY}={self.run_id}"

    @property
    def prefix(self) -> str:
        return f"{NAME_PREFIX}-{self.run_id}"

    @property
    def relay(self) -> str:
        return f"{self.prefix}-relay"

    @property
    def acceptor(self) -> str:
        return f"{self.prefix}-acceptor"

    def connector(self, scenario: str) -> str:
        return f"{self.prefix}-connector-{scenario}"

    def capture(self, scenario: str) -> str:
        return f"{self.prefix}-capture-{scenario}"

    @property
    def relay_url(self) -> str:
        return f"https://{self.relay_ip}:{RELAY_HTTPS_PORT}"


def choose_subnets(
    run_id: str, occupied: tuple[ipaddress.IPv4Network, ...] = ()
) -> tuple[ipaddress.IPv4Network, ipaddress.IPv4Network]:
    """Deterministically pick two disjoint /24s from the pool, avoiding any
    already-occupied network. Hashing the run id keeps concurrent runs apart."""
    candidates = list(SUBNET_POOL.subnets(new_prefix=SUBNET_PREFIX))
    seed = int.from_bytes(run_id.encode("ascii"), "big")
    count = len(candidates)
    first = candidates[seed % count]
    second = candidates[(seed // count + 1) % count]
    step = 1
    while second == first or any(
        second.overlaps(net) or first.overlaps(net) for net in occupied
    ):
        second = candidates[(seed // count + 1 + step) % count]
        step += 1
        if step > count:
            fail("could not find two disjoint /24s free of occupied networks")
    return first, second


def make_topology(
    run_id: str, occupied: tuple[ipaddress.IPv4Network, ...] = ()
) -> Topology:
    connector_subnet, acceptor_subnet = choose_subnets(run_id, occupied)
    connector_hosts = list(connector_subnet.hosts())
    acceptor_hosts = list(acceptor_subnet.hosts())
    return Topology(
        run_id=run_id,
        connector_network=f"{NAME_PREFIX}-{run_id}-connector-net",
        acceptor_network=f"{NAME_PREFIX}-{run_id}-acceptor-net",
        router=f"{NAME_PREFIX}-{run_id}-router",
        connector_subnet=str(connector_subnet),
        acceptor_subnet=str(acceptor_subnet),
        connector_ip=str(connector_hosts[CONNECTOR_HOST_OFFSET]),
        router_connector_ip=str(connector_hosts[19]),
        acceptor_ip=str(acceptor_hosts[ACCEPTOR_HOST_OFFSET]),
        router_acceptor_ip=str(acceptor_hosts[19]),
        relay_ip=str(acceptor_hosts[RELAY_HOST_OFFSET]),
        # A routable-but-unused acceptor-subnet address: the relay-outage arm
        # points the connector here, so the relay is genuinely unreachable
        # (packets are forwarded by the router but nothing listens).
        dead_relay_ip=str(acceptor_hosts[DEAD_RELAY_HOST_OFFSET]),
    )


def network_commands(config: RunConfig, topology: Topology) -> list[list[str]]:
    return [
        [
            config.podman,
            "network",
            "create",
            "--label",
            topology.label,
            "--internal",
            "--disable-dns",
            "--subnet",
            topology.connector_subnet,
            topology.connector_network,
        ],
        [
            config.podman,
            "network",
            "create",
            "--label",
            topology.label,
            "--internal",
            "--disable-dns",
            "--subnet",
            topology.acceptor_subnet,
            topology.acceptor_network,
        ],
    ]


def router_commands(config: RunConfig, topology: Topology) -> list[list[str]]:
    return [
        [
            config.podman,
            "run",
            "--detach",
            "--name",
            topology.router,
            "--label",
            topology.label,
            "--cap-add",
            "NET_ADMIN",
            "--sysctl",
            "net.ipv4.ip_forward=1",
            "--network",
            topology.connector_network,
            "--ip",
            topology.router_connector_ip,
            config.image,
            "/bin/sleep",
            "infinity",
        ],
        [
            config.podman,
            "network",
            "connect",
            "--ip",
            topology.router_acceptor_ip,
            topology.acceptor_network,
            topology.router,
        ],
    ]


def route_wrapper(
    routes: list[tuple[str, str]], gate: str | None, argv: list[str]
) -> list[str]:
    """Wrap ``argv`` in a bash prelude that installs explicit L3 routes (each a
    ``dest via gateway`` pair) and optionally waits on a control gate file
    before exec. This is the ONLY way a container reaches another subnet, so a
    destination absent from ``routes`` is genuinely unreachable (direct-block)."""
    script_parts = ["set -euo pipefail"]
    for dest, gateway in routes:
        script_parts.append(f'ip route add "{dest}" via "{gateway}"')
    if gate is not None:
        script_parts.append(f'while test ! -e "{gate}"; do sleep 0.02; done')
    script_parts.append('exec "$@"')
    return ["/bin/bash", "-c", "; ".join(script_parts), "task142-route", *argv]


def relay_command(
    config: RunConfig, topology: Topology, image_revision: str
) -> list[str]:
    inner = [
        "/bin/iroh-relay-evidence-server",
        "--https-bind",
        f"{topology.relay_ip}:{RELAY_HTTPS_PORT}",
        "--lifetime-secs",
        "90",
        "--run-id",
        topology.run_id,
        "--owner",
        OWNER,
        "--image-revision",
        image_revision,
    ]
    return [
        config.podman,
        "run",
        "--detach",
        "--name",
        topology.relay,
        "--label",
        topology.label,
        "--cap-add",
        "NET_ADMIN",
        "--network",
        topology.acceptor_network,
        "--ip",
        topology.relay_ip,
        config.image,
        *route_wrapper(
            [(topology.connector_subnet, topology.router_acceptor_ip)], None, inner
        ),
    ]


def acceptor_command(
    config: RunConfig,
    topology: Topology,
    scenario: str = "relay-success",
    route_to_connector: bool = False,
) -> list[str]:
    inner = [
        "/bin/iroh-relay-evidence-peer",
        "--role",
        "accept",
        "--scenario",
        scenario,
        "--relay-url",
        topology.relay_url,
        "--iroh-bind",
        f"{topology.acceptor_ip}:{IROH_PORT}",
        "--run-id",
        topology.run_id,
        "--owner",
        OWNER,
    ]
    # The acceptor always reaches the relay on its own subnet, so a relayed
    # connection needs NO route to the connector: the relay brokers it. Only the
    # direct arm opens a route to the connector subnet, and only then. Without
    # it, the acceptor's own hole-punch probe to the connector is unroutable, so
    # a relay-only arm cannot leak a single direct peer packet in EITHER
    # direction — which is exactly what the finalizer's zero-direct guard needs.
    routes = (
        [(topology.connector_subnet, topology.router_acceptor_ip)]
        if route_to_connector
        else []
    )
    return [
        config.podman,
        "run",
        "--detach",
        "--name",
        topology.acceptor,
        "--label",
        topology.label,
        "--cap-add",
        "NET_ADMIN",
        "--network",
        topology.acceptor_network,
        "--ip",
        topology.acceptor_ip,
        config.image,
        *route_wrapper(routes, None, inner),
    ]


def connector_command(
    config: RunConfig,
    topology: Topology,
    scenario: str,
    peer_node_id: str,
    gate: str,
) -> list[str]:
    """The connector for one arm. Relay-only arms get a /32 route to the relay
    IP but NOT to the acceptor peer, so the direct path is blocked. The
    direct-positive control additionally routes to the acceptor peer."""
    relay_url = topology.relay_url
    if scenario == "wrong-url":
        # A config-time typed failure: an http (non-https) relay URL.
        relay_url = f"http://{topology.relay_ip}:{RELAY_HTTPS_PORT}"
    elif scenario == "relay-outage":
        # A routable address where no relay listens: a real relay outage.
        relay_url = f"https://{topology.dead_relay_ip}:{RELAY_HTTPS_PORT}"

    inner = [
        "/bin/iroh-relay-evidence-peer",
        "--role",
        "connect",
        "--scenario",
        scenario,
        "--relay-url",
        relay_url,
        "--iroh-bind",
        f"{topology.connector_ip}:{IROH_PORT}",
        "--run-id",
        topology.run_id,
        "--owner",
        OWNER,
    ]
    if scenario != "wrong-url":
        inner += ["--peer-node-id", peer_node_id]
    if scenario in ("direct-positive", "forced-direct-failure"):
        inner += ["--peer-direct-addr", f"{topology.acceptor_ip}:{IROH_PORT}"]

    if scenario == "relay-outage":
        routes = [(f"{topology.dead_relay_ip}/32", topology.router_connector_ip)]
    else:
        routes = [(f"{topology.relay_ip}/32", topology.router_connector_ip)]
    if scenario == "direct-positive":
        # The control deliberately opens the direct path so the connection goes
        # direct and is not credited to the relay.
        routes.append((f"{topology.acceptor_ip}/32", topology.router_connector_ip))

    return [
        config.podman,
        "run",
        "--detach",
        "--name",
        topology.connector(scenario),
        "--label",
        topology.label,
        "--cap-add",
        "NET_ADMIN",
        "--network",
        topology.connector_network,
        "--ip",
        topology.connector_ip,
        "--volume",
        f"{Path(gate).resolve()}:/control:ro,Z",
        config.image,
        *route_wrapper(routes, "/control/start", inner),
    ]


def capture_command(
    config: RunConfig, topology: Topology, scenario: str, out: Path
) -> list[str]:
    return [
        config.podman,
        "run",
        "--detach",
        "--name",
        topology.capture(scenario),
        "--label",
        topology.label,
        "--cap-add",
        "NET_RAW",
        "--network",
        f"container:{topology.connector(scenario)}",
        "--volume",
        f"{out.resolve()}:/evidence:Z",
        config.image,
        "/bin/tcpdump",
        "-i",
        CAPTURE_INTERFACE,
        "-U",
        "--immediate-mode",
        "-nn",
        "-s",
        "0",
        "-w",
        f"/evidence/{scenario}.pcap",
        CAPTURE_FILTER,
    ]


def image_preflight_command(config: RunConfig, topology: Topology) -> list[str]:
    binaries = [
        "/bin/iroh-relay-evidence-server",
        "/bin/iroh-relay-evidence-peer",
        "/bin/tcpdump",
        "/bin/ip",
        "/bin/bash",
    ]
    checks = " && ".join(f"test -x {binary}" for binary in binaries)
    return [
        config.podman,
        "run",
        "--rm",
        "--name",
        f"{topology.prefix}-preflight",
        "--label",
        topology.label,
        "--network",
        "none",
        config.image,
        "/bin/bash",
        "-c",
        checks,
    ]


def validate_outcome(scenario: str, outcome: dict[str, object]) -> None:
    """Assert a connector peer outcome matches the arm's expectation. This is
    the function the self-test bites by mutation."""
    spec = CONNECT_ARMS.get(scenario)
    if spec is None:
        fail(f"unknown scenario {scenario!r}")
    if outcome.get("scenario") != scenario:
        fail(f"{scenario}: outcome scenario mismatch: {outcome.get('scenario')!r}")
    verdict = outcome.get("verdict")
    if verdict != spec["verdict"]:
        fail(f"{scenario}: expected verdict {spec['verdict']!r}, got {verdict!r}")

    # Every arm that reaches the network connect emits a measured connect_ms.
    # wrong-url is rejected at CONFIG time (a non-https URL never touches the
    # network), so it legitimately carries no connect_ms.
    if scenario != "wrong-url" and not isinstance(outcome.get("connect_ms"), int):
        fail(f"{scenario}: outcome is missing an integer connect_ms")

    if spec["verdict"] == "connected":
        path = outcome.get("connection_path")
        if path != spec["path"]:
            fail(f"{scenario}: expected path {spec['path']!r}, got {path!r}")
        attributed = bool(outcome.get("relay_attributed"))
        if attributed != spec["relay_attributed"]:
            fail(
                f"{scenario}: relay_attributed {attributed} != expected "
                f"{spec['relay_attributed']} (a direct-positive control must never "
                "be credited to the relay)"
            )
        if spec["path"] == "direct" and attributed:
            fail(f"{scenario}: a direct path was credited to the relay")
    else:
        reason = outcome.get("reason")
        if reason not in spec["reasons"]:
            fail(
                f"{scenario}: typed reason {reason!r} not in allowed "
                f"{spec['reasons']!r}"
            )
        if outcome.get("relay_attributed"):
            fail(f"{scenario}: an unavailable arm must not be relay-attributed")


def sample_outcome(scenario: str) -> dict[str, object]:
    """Synthesize a well-formed peer outcome for the self-test."""
    spec = CONNECT_ARMS[scenario]
    base = {
        "schema": "iroh-relay-evidence-peer-outcome-v1",
        "role": "connect",
        "scenario": scenario,
        "run_id": "r1234567",
        "owner": OWNER,
        "relay_url": "https://10.208.1.40:44380",
        "authorization_class": PROFILE,
        "external_contact_authorized": False,
    }
    # Only the config-time wrong-url arm never reaches the network connect.
    if scenario != "wrong-url":
        base["connect_ms"] = 1200
    if spec["verdict"] == "connected":
        base.update(
            {
                "verdict": "connected",
                "node_id": "ab" * 32,
                "connection_path": spec["path"],
                "connection_path_at_accept": spec["path"],
                "relay_attributed": spec["relay_attributed"],
            }
        )
    else:
        base.update(
            {
                "verdict": "unavailable",
                "reason": spec["reasons"][0],
                "detail": "synthetic",
                "relay_attributed": False,
            }
        )
    return base


def command_plan(
    config: RunConfig, topology: Topology, gate: Path
) -> dict[str, list[str]]:
    peer_node_id = "cd" * 32
    plan: dict[str, list[str]] = {}
    for index, command in enumerate(network_commands(config, topology)):
        plan[f"network-{index}"] = command
    for index, command in enumerate(router_commands(config, topology)):
        plan[f"router-{index}"] = command
    plan["relay"] = relay_command(config, topology, "1" * 40)
    plan["acceptor"] = acceptor_command(config, topology)
    plan["preflight"] = image_preflight_command(config, topology)
    for scenario in CONNECT_ARMS:
        plan[f"connector-{scenario}"] = connector_command(
            config, topology, scenario, peer_node_id, str(gate)
        )
        plan[f"capture-{scenario}"] = capture_command(
            config, topology, scenario, config.output
        )
    return plan


# Which arms need a live acceptor peer (they establish a real connection), and
# which run against the relay/no-peer only. The order runs the fast config arm
# first and groups the slow deadline arms last.
ARM_ORDER = (
    "wrong-url",
    "relay-success",
    "direct-positive",
    "half-open-stream",
    "wrong-certificate",
    "wrong-identity",
    "relay-outage",
    "forced-direct-failure",
)
ACCEPTOR_ARMS = frozenset({"relay-success", "direct-positive", "half-open-stream"})

READY_SERVER = re.compile(r"iroh_relay_evidence_server_ready\b")
READY_ACCEPTOR = re.compile(r"node_id=([0-9a-f]{64})")


def foreign_node_id() -> str:
    """A valid, unrelated Ed25519 public key for the arms that must connect to a
    NodeId nobody serves (wrong-identity) or that never reach a peer at all."""
    key = ed25519.Ed25519PrivateKey.generate().public_key()
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return raw.hex()


def parse_pcap_flows(data: bytes) -> list[tuple[str, int, str, int]]:
    """Parse a classic pcap into (src_ip, src_port, dst_ip, dst_port) tuples for
    every IPv4 TCP/UDP packet. Handles Ethernet, Linux SLL and SLL2 link layers
    (``-i any`` uses SLL/SLL2). This is the packet-attribution primitive: it is
    what proves relay packets flowed and direct-peer packets did not."""
    if len(data) < 24:
        return []
    if data[:4] == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    elif data[:4] == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    else:
        return []
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    offset = 24
    flows: list[tuple[str, int, str, int]] = []
    while offset + 16 <= len(data):
        incl_len = struct.unpack(endian + "I", data[offset + 8 : offset + 12])[0]
        offset += 16
        frame = data[offset : offset + incl_len]
        offset += incl_len
        flow = _decode_ipv4_flow(linktype, frame)
        if flow is not None:
            flows.append(flow)
    return flows


def _decode_ipv4_flow(linktype: int, frame: bytes) -> tuple[str, int, str, int] | None:
    if linktype == 1:  # Ethernet
        if len(frame) < 14 or frame[12:14] != b"\x08\x00":
            return None
        payload = frame[14:]
    elif linktype == 113:  # Linux SLL
        if len(frame) < 16 or frame[14:16] != b"\x08\x00":
            return None
        payload = frame[16:]
    elif linktype == 276:  # Linux SLL2
        if len(frame) < 20 or frame[0:2] != b"\x08\x00":
            return None
        payload = frame[20:]
    elif linktype == 101:  # raw IPv4
        payload = frame
    else:
        return None
    if len(payload) < 20 or (payload[0] >> 4) != 4:
        return None
    ihl = (payload[0] & 0x0F) * 4
    protocol = payload[9]
    if protocol not in (6, 17) or len(payload) < ihl + 4:
        return None
    src_ip = ".".join(str(byte) for byte in payload[12:16])
    dst_ip = ".".join(str(byte) for byte in payload[16:20])
    src_port = struct.unpack(">H", payload[ihl : ihl + 2])[0]
    dst_port = struct.unpack(">H", payload[ihl + 2 : ihl + 4])[0]
    return (src_ip, src_port, dst_ip, dst_port)


def count_endpoint_packets(
    flows: list[tuple[str, int, str, int]], ip: str, port: int
) -> int:
    """Count packets to OR from ``ip:port`` — the traffic attributed to one
    endpoint (the relay, or the direct peer)."""
    total = 0
    for src_ip, src_port, dst_ip, dst_port in flows:
        if (src_ip == ip and src_port == port) or (dst_ip == ip and dst_port == port):
            total += 1
    return total


def count_pcap_records(data: bytes) -> int:
    """Count every complete record in a classic pcap, independent of link/L3
    decode. This is the capture-completeness axis: it must equal tcpdump's
    ``packets captured`` counter, so a truncated pcap (or a non-pcap file dressed
    up as one) is caught. A trailing record whose body is cut short is NOT
    counted, so truncation always undercounts and fails the equality check."""
    if len(data) < 24:
        return 0
    if data[:4] == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    elif data[:4] == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    else:
        return 0
    offset = 24
    count = 0
    while offset + 16 <= len(data):
        incl_len = struct.unpack(endian + "I", data[offset + 8 : offset + 12])[0]
        if offset + 16 + incl_len > len(data):
            break
        offset += 16 + incl_len
        count += 1
    return count


def cleanup_by_label(runner: publication.Runner, config: RunConfig, label: str) -> None:
    containers = runner.run(
        [config.podman, "ps", "-aq", "--filter", f"label={label}"], check=False
    ).stdout.split()
    for container in containers:
        runner.run([config.podman, "rm", "-f", container.decode()], check=False)
    networks = runner.run(
        [config.podman, "network", "ls", "-q", "--filter", f"label={label}"],
        check=False,
    ).stdout.split()
    for network in networks:
        runner.run(
            [config.podman, "network", "rm", "-f", network.decode()], check=False
        )


def occupied_networks(
    runner: publication.Runner, config: RunConfig
) -> tuple[ipaddress.IPv4Network, ...]:
    result = runner.run(
        [config.podman, "network", "ls", "-q"], check=False
    ).stdout.split()
    nets: list[ipaddress.IPv4Network] = []
    for name in result:
        inspect = runner.run(
            [config.podman, "network", "inspect", name.decode()], check=False
        )
        try:
            for entry in json.loads(inspect.stdout or b"[]"):
                for subnet in entry.get("subnets", []) or []:
                    with_prefix = subnet.get("subnet")
                    if with_prefix:
                        nets.append(ipaddress.ip_network(with_prefix, strict=False))
        except (json.JSONDecodeError, ValueError):
            continue
    return tuple(net for net in nets if isinstance(net, ipaddress.IPv4Network))


def read_outcome(runner: publication.Runner, config: RunConfig, name: str) -> dict:
    logs = publication.container_logs(runner, config.podman, name).decode(
        "utf-8", "backslashreplace"
    )
    for line in reversed(logs.splitlines()):
        line = line.strip()
        if line.startswith("{") and "iroh-relay-evidence-peer-outcome" in line:
            return json.loads(line)
    fail(f"connector {name!r} emitted no outcome JSON; log_tail={logs[-2048:]!r}")


def run_arm(
    runner: publication.Runner,
    config: RunConfig,
    topology: Topology,
    scenario: str,
    gate_dir: Path,
    foreign_id: str,
) -> dict[str, object]:
    """Run one arm: optional acceptor, gated capture + connector, then parse the
    connector outcome and count captured relay / direct-peer packets."""
    acceptor_id = foreign_id
    if scenario in ACCEPTOR_ARMS:
        acceptor_scenario = (
            "half-open-stream" if scenario == "half-open-stream" else "relay-success"
        )
        # Only the direct-positive control opens the acceptor->connector route;
        # relay-only arms keep it closed so neither peer can send a direct packet.
        runner.run(
            acceptor_command(
                config,
                topology,
                acceptor_scenario,
                route_to_connector=(scenario == "direct-positive"),
            )
        )
        match, _, _ = publication.wait_for_log(
            runner, config.podman, topology.acceptor, READY_ACCEPTOR, 20.0
        )
        acceptor_id = match.group(1)

    pcap = config.output / f"{scenario}.pcap"
    gate = gate_dir / "start"
    runner.run(
        connector_command(config, topology, scenario, acceptor_id, str(gate_dir))
    )
    runner.run(capture_command(config, topology, scenario, config.output))
    publication.wait_for_capture_ready(
        runner, config.podman, topology.capture(scenario), pcap, 15.0
    )

    started = time.monotonic()
    gate.write_bytes(b"go\n")
    exit_code = publication.wait_for_exit(
        runner, config.podman, topology.connector(scenario), 20.0
    )
    elapsed_ms = int((time.monotonic() - started) * 1000)
    if exit_code not in (0, 4):
        fail(f"{scenario}: connector exited unexpectedly with {exit_code}")

    outcome = read_outcome(runner, config, topology.connector(scenario))
    # Flush and stop the capture, then read its shutdown log BEFORE any cleanup:
    # tcpdump prints its captured/received/dropped counters to stderr on exit,
    # and those counters are the capture-completeness evidence. A kernel drop or
    # a filter/capture mismatch makes a zero-direct assertion unsafe, so the
    # counters are preserved into the raw tree and re-checked by the finalizer.
    capture_name = topology.capture(scenario)
    publication.signal_and_wait(runner, config.podman, capture_name, "INT", 10.0)
    capture_log = publication.container_logs(runner, config.podman, capture_name)
    publication.write_new(config.output / f"{scenario}.capture.log", capture_log)
    stats = publication.parse_tcpdump_shutdown_stats(capture_log)

    pcap_bytes = pcap.read_bytes()
    flows = parse_pcap_flows(pcap_bytes)
    pcap_records = count_pcap_records(pcap_bytes)
    relay_packets = count_endpoint_packets(flows, topology.relay_ip, RELAY_HTTPS_PORT)
    direct_packets = count_endpoint_packets(flows, topology.acceptor_ip, IROH_PORT)

    # Capture-completeness gate: only a complete, drop-free capture makes the
    # zero-direct attribution trustworthy. The finalizer re-derives this exact
    # check from the committed pcap + capture.log, so a run.json cannot claim it.
    if stats.dropped_by_kernel != 0:
        fail(
            f"{scenario}: tcpdump dropped {stats.dropped_by_kernel} packet(s) in kernel"
        )
    if stats.captured != stats.received_by_filter:
        fail(
            f"{scenario}: tcpdump captured {stats.captured} but its filter received "
            f"{stats.received_by_filter}; capture is incomplete"
        )
    if pcap_records != stats.captured:
        fail(
            f"{scenario}: pcap holds {pcap_records} record(s) but tcpdump captured "
            f"{stats.captured}; pcap is truncated"
        )
    # The direct-positive control must be CAPTURE-bound symmetric with
    # relay-success: it has to show real direct-peer traffic, else its claim to
    # exercise the direct path rests only on the peer self-report.
    if scenario == "direct-positive" and direct_packets <= 0:
        fail(
            f"{scenario}: control captured no direct-peer packets to "
            f"{topology.acceptor_ip}:{IROH_PORT}; the direct path is unproven"
        )

    if scenario in ACCEPTOR_ARMS:
        publication.signal_and_wait(
            runner, config.podman, topology.acceptor, "TERM", 15.0
        )
        # The acceptor is recreated per acceptor-arm under a run-scoped name;
        # signal_and_wait only stops it, so remove the exited container or the
        # next acceptor-arm collides on the name.
        runner.run([config.podman, "rm", "-f", topology.acceptor], check=False)

    validate_outcome(scenario, outcome)
    arm = {
        "scenario": scenario,
        "verdict": outcome["verdict"],
        "relay_attributed": bool(outcome.get("relay_attributed")),
        "captured_relay_packets": relay_packets,
        "captured_direct_peer_packets": direct_packets,
        "captured_packets": stats.captured,
        "received_by_filter": stats.received_by_filter,
        "dropped_by_kernel": stats.dropped_by_kernel,
        "captured_pcap_records": pcap_records,
        # elapsed_ms is the container wall-clock (gate-release -> connector exit):
        # connect + close + exchange. Kept UNCLAMPED and INFORMATIONAL only. The
        # gated timing is connect_ms below, the real pure-connect duration the
        # peer measures around its bounded connect.
        "elapsed_ms": elapsed_ms,
    }
    connect_ms = outcome.get("connect_ms")
    if isinstance(connect_ms, int):
        arm["connect_ms"] = connect_ms
    if outcome["verdict"] == "connected":
        arm["connection_path"] = outcome["connection_path"]
    else:
        arm["reason"] = outcome["reason"]
    return arm


def run_evidence(config: RunConfig) -> None:
    runner = publication.Runner()
    publication.validate_immutable_image_reference(config.image)
    run_id = f"r{int(time.time()) % 100_000_000:08d}"
    topology = make_topology(run_id, occupied_networks(runner, config))
    label = topology.label

    publication.create_private_directory(config.output)
    gate_dir = config.output / "control"
    publication.create_private_directory(gate_dir)

    cleanup_by_label(runner, config, label)
    try:
        runner.run(image_preflight_command(config, topology))
        for command in network_commands(config, topology):
            runner.run(command)
        for command in router_commands(config, topology):
            runner.run(command)
        runner.run(relay_command(config, topology, "1" * 40))
        publication.wait_for_log(
            runner, config.podman, topology.relay, READY_SERVER, 25.0
        )

        arms: list[dict[str, object]] = []
        for scenario in ARM_ORDER:
            foreign = foreign_node_id()
            arms.append(run_arm(runner, config, topology, scenario, gate_dir, foreign))
            # Reset the per-arm gate for the next connector.
            (gate_dir / "start").unlink(missing_ok=True)

        run_record = {
            "schema": SCHEMA,
            "profile": PROFILE,
            "run_id": run_id,
            "relay": {
                "kind": "local-routed-iroh-relay",
                "relay_url": topology.relay_url,
                "owner": OWNER,
                "authorization_class": PROFILE,
                "external_contact_authorized": False,
            },
            "capture": {
                "scope": CAPTURE_SCOPE,
                "interface": CAPTURE_INTERFACE,
                "filter": CAPTURE_FILTER,
            },
            "topology": {
                "run_id": run_id,
                "connector_network": topology.connector_network,
                "acceptor_network": topology.acceptor_network,
                "connector_subnet": topology.connector_subnet,
                "acceptor_subnet": topology.acceptor_subnet,
                "relay_ip": topology.relay_ip,
                "acceptor_ip": topology.acceptor_ip,
            },
            "deadline_ms": DEADLINE_MS,
            "grace_ms": GRACE_MS,
            "arms": [dict(arm) for arm in sorted(arms, key=lambda a: a["scenario"])],
        }
        publication.write_new(config.output / "run.json", canonical_json(run_record))
    finally:
        cleanup_by_label(runner, config, label)


def self_test() -> None:
    import tempfile

    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        config = RunConfig(
            output=root / "out",
            image="localhost/nix-p2p-task142:0123456789abcdefghij",
        )
        topology = make_topology("r1234567-test")
        gate = root / "control"
        plan = command_plan(config, topology, gate)

        # Both networks are internal and DNS-disabled.
        for key in ("network-0", "network-1"):
            command = plan[key]
            assert "--internal" in command, f"{key} must be internal"
            assert "--disable-dns" in command, f"{key} must disable dns"

        # The two subnets are disjoint.
        assert topology.connector_subnet != topology.acceptor_subnet
        connector_net = ipaddress.ip_network(topology.connector_subnet)
        acceptor_net = ipaddress.ip_network(topology.acceptor_subnet)
        assert not connector_net.overlaps(acceptor_net), "subnets must be disjoint"

        # Capture joins the connector netns with the tcp-or-udp filter.
        capture = plan["capture-relay-success"]
        assert capture[-1] == CAPTURE_FILTER
        assert f"container:{topology.connector('relay-success')}" in capture

        # The relay is reachable from the connector: its command routes the
        # relay /32 via the router, and both peers use the SAME relay URL.
        relay_success = " ".join(plan["connector-relay-success"])
        assert f"{topology.relay_ip}/32" in relay_success, "relay must be routable"
        assert topology.relay_url in relay_success
        assert topology.relay_url in " ".join(plan["acceptor"])

        # The direct path is BLOCKED for the relay-success arm: the connector
        # has no route to the acceptor peer IP.
        assert f"{topology.acceptor_ip}/32" not in relay_success, (
            "relay-success must not route to the acceptor peer (direct must be blocked)"
        )
        # The direct-positive control DOES route to the acceptor peer.
        direct = " ".join(plan["connector-direct-positive"])
        assert f"{topology.acceptor_ip}/32" in direct, (
            "direct-positive control must open the direct path"
        )
        assert "--peer-direct-addr" in plan["connector-direct-positive"]

        # wrong-url uses a non-https relay URL and no peer node id.
        wrong_url = plan["connector-wrong-url"]
        assert any(part.startswith("http://") for part in wrong_url)
        assert "--peer-node-id" not in wrong_url

        # Every arm's connector waits on the control gate before exec.
        for scenario in CONNECT_ARMS:
            joined = " ".join(plan[f"connector-{scenario}"])
            assert "/control/start" in joined, (
                f"{scenario} must gate on capture readiness"
            )

        # The image reference must be immutable.
        publication.validate_immutable_image_reference(config.image)
        try:
            publication.validate_immutable_image_reference(
                "example.invalid/relay:latest"
            )
        except Exception:  # noqa: BLE001 - any rejection is acceptable
            pass
        else:
            raise AssertionError("a mutable image tag must be rejected")

        # Positive/control outcomes validate.
        validate_outcome("relay-success", sample_outcome("relay-success"))
        validate_outcome("direct-positive", sample_outcome("direct-positive"))
        for scenario in CONNECT_ARMS:
            validate_outcome(scenario, sample_outcome(scenario))

        # --- Mutation bites: each must be rejected. ---

        # 1. A relay-success arm reporting a DIRECT path (relay not proven).
        mutated = sample_outcome("relay-success")
        mutated["connection_path"] = "direct"
        mutated["relay_attributed"] = False
        _expect_rejected(
            lambda: validate_outcome("relay-success", mutated), "relay-success-direct"
        )

        # 2. A direct-positive control CREDITED to the relay.
        mutated = sample_outcome("direct-positive")
        mutated["relay_attributed"] = True
        _expect_rejected(
            lambda: validate_outcome("direct-positive", mutated),
            "direct-positive-credited-to-relay",
        )

        # 3. An unavailable arm reporting a connected verdict.
        mutated = sample_outcome("relay-outage")
        mutated["verdict"] = "connected"
        _expect_rejected(
            lambda: validate_outcome("relay-outage", mutated), "outage-false-success"
        )

        # 4. A typed reason outside the arm's allowed set.
        mutated = sample_outcome("wrong-url")
        mutated["reason"] = "content_miss"
        _expect_rejected(
            lambda: validate_outcome("wrong-url", mutated), "wrong-url-bad-reason"
        )

        # 5. An unavailable arm claiming relay attribution.
        mutated = sample_outcome("half-open-stream")
        mutated["relay_attributed"] = True
        _expect_rejected(
            lambda: validate_outcome("half-open-stream", mutated),
            "unavailable-relay-attributed",
        )

        # 6. A network arm that omits the measured connect_ms (F1): the gated
        # timing must be present, so its absence is rejected.
        mutated = sample_outcome("relay-outage")
        del mutated["connect_ms"]
        _expect_rejected(
            lambda: validate_outcome("relay-outage", mutated), "missing-connect-ms"
        )

        # count_pcap_records must undercount a truncated tail (completeness bite).
        whole = build_pcap([("10.0.0.1", 1, "10.0.0.2", 2, 6)] * 3)
        assert count_pcap_records(whole) == 3, "a complete pcap counts every record"
        assert count_pcap_records(whole[:-4]) == 2, (
            "a truncated trailing record must not be counted"
        )
        assert count_pcap_records(b"not a pcap at all") == 0

    print("iroh-relay-capability evidence self-test: PASS")


def build_pcap(packets: list[tuple[str, int, str, int, int]]) -> bytes:
    """Build a minimal big-endian classic pcap (raw-IPv4 linktype 101) carrying
    one IPv4 TCP/UDP packet per tuple ``(src_ip, src_port, dst_ip, dst_port,
    proto)``. Shared by the harness completeness bite and, via re-parse, the
    finalizer's evidence-binding self-test."""
    header = b"\xa1\xb2\xc3\xd4" + struct.pack(">HHiIII", 2, 4, 0, 0, 65535, 101)
    out = bytearray(header)
    for src_ip, src_port, dst_ip, dst_port, proto in packets:
        ip = bytearray(24)
        ip[0] = 0x45
        ip[9] = proto
        ip[12:16] = bytes(int(octet) for octet in src_ip.split("."))
        ip[16:20] = bytes(int(octet) for octet in dst_ip.split("."))
        struct.pack_into(">H", ip, 20, src_port)
        struct.pack_into(">H", ip, 22, dst_port)
        out += struct.pack(">IIII", 0, 0, len(ip), len(ip)) + bytes(ip)
    return bytes(out)


def _expect_rejected(operation, label: str) -> None:
    try:
        operation()
    except (EvidenceFailure, AssertionError):
        return
    raise AssertionError(f"mutation bite {label!r} was NOT rejected")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="nix-p2p-iroh-relay-evidence:latest")
    parser.add_argument("--output", type=Path, default=Path("artifacts/iroh-relay"))
    parser.add_argument("--podman", default="podman")
    parser.add_argument("--self-test", action="store_true", dest="self_test")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        self_test()
        return 0
    try:
        run_evidence(RunConfig(args.output, args.image, args.podman))
    except (EvidenceFailure, publication.CommandFailure, OSError, ValueError) as error:
        print(f"FATAL - {error}", file=sys.stderr)
        return 1
    print(f"iroh-relay-capability routed evidence: PASS output={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
