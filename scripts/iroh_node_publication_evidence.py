#!/usr/bin/env python3
"""Capture routed evidence for the iroh-node-publication-v1 capability."""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import NoReturn


SCHEMA = "iroh-node-publication-evidence-v1"
LABEL_KEY = "org.nix-p2p.iroh-publication-evidence-run"
IMAGE_REVISION_LABEL = "org.nix-p2p.implementation-revision"
NAME_PREFIX = "nix-p2p-task137"
SUBNET_POOL = ipaddress.ip_network("10.224.0.0/11")
SUBNET_PREFIX = 24
AUTHORITY_PORT = 18080
IROH_PORT = 44330
DAEMON_HTTP_PORT = 8082
PUBLICATION_TTL_SECONDS = 12
PUBLICATION_REFRESH_SECONDS = 4
CAPTURE_SCOPE = "publisher-netns-authority-or-dns-bpf-v1"
CAPTURE_INTERFACE = "any"
CAPTURE_COUNT_SEMANTICS = "packets-matching-bpf"
AUTHORITY_STATE_FILENAME = "iroh-node-publication-authority.json"
AUTHORITY_ANCHOR_FILENAME = "iroh-node-publication-authority-anchor.json"
RUN_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{7,47}$")
TCPDUMP_CAPTURED_RE = re.compile(rb"(?m)^([0-9]+) packets captured\r?$")
TCPDUMP_RECEIVED_RE = re.compile(rb"(?m)^([0-9]+) packets received by filter\r?$")
TCPDUMP_DROPPED_RE = re.compile(rb"(?m)^([0-9]+) packets dropped by kernel\r?$")


@dataclass(frozen=True)
class RunConfig:
    output: Path
    image: str
    podman: str = "podman"
    namespace: str = "task137-evidence"
    recipient: str = "task137-authority:v1"
    authority_host: str = "task137-authority.invalid"
    owner: str = "nix-p2p-task137-evidence"


@dataclass(frozen=True)
class TcpdumpShutdownStats:
    captured: int
    received_by_filter: int
    dropped_by_kernel: int


@dataclass(frozen=True)
class Topology:
    run_id: str
    publication_network: str
    authority_network: str
    router: str
    authority: str
    publication_subnet: ipaddress.IPv4Network
    authority_subnet: ipaddress.IPv4Network
    publisher_ip: ipaddress.IPv4Address
    router_publication_ip: ipaddress.IPv4Address
    authority_ip: ipaddress.IPv4Address
    router_authority_ip: ipaddress.IPv4Address

    @property
    def label(self) -> str:
        return f"{LABEL_KEY}={self.run_id}"

    @property
    def resource_prefix(self) -> str:
        return f"{NAME_PREFIX}-{self.run_id}"

    def publisher(self, scenario: str) -> str:
        return f"{self.resource_prefix}-publisher-{scenario}"

    def capture(self, scenario: str) -> str:
        return f"{self.resource_prefix}-capture-{scenario}"

    def analyzer(self, scenario: str) -> str:
        return f"{self.resource_prefix}-analyzer-{scenario}"

    @property
    def preflight(self) -> str:
        return f"{self.resource_prefix}-preflight"

    def container_names(self) -> tuple[str, ...]:
        scenarios = (
            "bootstrap",
            "default-off",
            "offline-disabled",
            "offline-enabled",
            "live",
        )
        publishers = tuple(self.publisher(scenario) for scenario in scenarios)
        captures = tuple(
            self.capture(scenario) for scenario in scenarios if scenario != "bootstrap"
        )
        analyzers = tuple(
            self.analyzer(scenario) for scenario in scenarios if scenario != "bootstrap"
        )
        # Capture sidecars join publisher network namespaces. Remove them first,
        # then their publishers, then the authority, and the router last.
        return (
            *analyzers,
            *captures,
            *publishers,
            self.preflight,
            self.authority,
            self.router,
        )

    def network_names(self) -> tuple[str, str]:
        return (self.publication_network, self.authority_network)


class CommandFailure(RuntimeError):
    """A command could not run or returned a disallowed status."""


class Runner:
    """Execute argv directly and turn every ambiguous outcome into failure."""

    def run(
        self,
        argv: list[str],
        *,
        check: bool = True,
        timeout: float = 60.0,
        input_bytes: bytes | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        if not argv or any(not isinstance(part, str) or not part for part in argv):
            raise CommandFailure(f"invalid argv: {argv!r}")
        try:
            result = subprocess.run(
                argv,
                input=input_bytes,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise CommandFailure(
                f"command did not complete: {argv!r}: {error}"
            ) from error
        if check and result.returncode != 0:
            stdout = result.stdout[-4096:].decode("utf-8", "backslashreplace")
            stderr = result.stderr[-4096:].decode("utf-8", "backslashreplace")
            raise CommandFailure(
                f"command failed rc={result.returncode}: {argv!r}\n"
                f"stdout_tail={stdout!r}\nstderr_tail={stderr!r}"
            )
        return result


def fail(message: str) -> NoReturn:
    raise RuntimeError(message)


def new_run_id() -> str:
    return f"r{os.getpid():x}-{secrets.token_hex(6)}"


def choose_run_subnets(
    run_id: str, occupied: tuple[ipaddress.IPv4Network, ...] = ()
) -> tuple[ipaddress.IPv4Network, ipaddress.IPv4Network]:
    if not RUN_ID_RE.fullmatch(run_id):
        fail(f"run id {run_id!r} is not a canonical lower-case resource token")
    candidates = tuple(SUBNET_POOL.subnets(new_prefix=SUBNET_PREFIX))
    start = int.from_bytes(hashlib.sha256(run_id.encode()).digest()[:4], "big") % len(
        candidates
    )
    selected: list[ipaddress.IPv4Network] = []
    for offset in range(len(candidates)):
        candidate = candidates[(start + offset) % len(candidates)]
        if any(candidate.overlaps(network) for network in (*occupied, *selected)):
            continue
        selected.append(candidate)
        if len(selected) == 2:
            return selected[0], selected[1]
    fail(f"no two free /{SUBNET_PREFIX} networks remain in {SUBNET_POOL}")


def make_topology(
    run_id: str,
    occupied: tuple[ipaddress.IPv4Network, ...] = (),
) -> Topology:
    publication_subnet, authority_subnet = choose_run_subnets(run_id, occupied)
    prefix = f"{NAME_PREFIX}-{run_id}"
    return Topology(
        run_id=run_id,
        publication_network=f"{prefix}-publication-net",
        authority_network=f"{prefix}-authority-net",
        router=f"{prefix}-router",
        authority=f"{prefix}-authority",
        publication_subnet=publication_subnet,
        authority_subnet=authority_subnet,
        publisher_ip=publication_subnet.network_address + 10,
        router_publication_ip=publication_subnet.network_address + 20,
        authority_ip=authority_subnet.network_address + 10,
        router_authority_ip=authority_subnet.network_address + 20,
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
            str(subnet),
            name,
        ]
        for name, subnet in (
            (topology.publication_network, topology.publication_subnet),
            (topology.authority_network, topology.authority_subnet),
        )
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
            topology.publication_network,
            "--ip",
            str(topology.router_publication_ip),
            config.image,
            "/bin/sleep",
            "infinity",
        ],
        [
            config.podman,
            "network",
            "connect",
            "--ip",
            str(topology.router_authority_ip),
            topology.authority_network,
            topology.router,
        ],
    ]


def authority_command(
    config: RunConfig,
    topology: Topology,
    state_dir: Path,
    authorized_node_id: str,
) -> list[str]:
    if not re.fullmatch(r"[0-9a-f]{64}", authorized_node_id):
        fail("authorized node id must be exactly 64 lower-case hexadecimal characters")
    return [
        config.podman,
        "run",
        "--detach",
        "--name",
        topology.authority,
        "--label",
        topology.label,
        "--cap-add",
        "NET_ADMIN",
        "--network",
        topology.authority_network,
        "--ip",
        str(topology.authority_ip),
        "--volume",
        f"{state_dir.resolve()}:/state:Z",
        config.image,
        "/bin/bash",
        "-euc",
        'remote="$1"; router="$2"; shift 2; '
        'ip route add "$remote" via "$router"; exec "$@"',
        "evidence-authority",
        str(topology.publication_subnet),
        str(topology.router_authority_ip),
        "/bin/iroh-node-authority",
        "--listen",
        f"{topology.authority_ip}:{AUTHORITY_PORT}",
        "--state-dir",
        "/state",
        "--namespace",
        f"{config.namespace}-{topology.run_id}",
        "--recipient",
        config.recipient,
        "--expected-host",
        config.authority_host,
        "--owner",
        config.owner,
        "--authorized-node-id",
        authorized_node_id,
    ]


def publisher_command(
    config: RunConfig,
    topology: Topology,
    scenario: str,
    state_dir: Path,
    control_dir: Path,
    *,
    publication_enabled: bool,
    offline: bool,
) -> list[str]:
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,31}", scenario):
        fail(f"scenario {scenario!r} is not safe for a resource name")
    endpoint_scope = "offline-test" if offline else f"lan:{topology.publisher_ip}"
    daemon_args = [
        "/bin/daemon",
        "--listen",
        f"0.0.0.0:{DAEMON_HTTP_PORT}",
        "--upstream",
        "http://127.0.0.1:9",
        "--iroh-provider",
        "--iroh-print-peer-address",
        "--iroh-state-dir",
        "/state/iroh",
        "--iroh-endpoint-scope",
        endpoint_scope,
        "--iroh-port",
        str(IROH_PORT),
    ]
    if publication_enabled:
        daemon_args.extend(
            [
                "--iroh-publish-node",
                "--iroh-publication-namespace",
                f"{config.namespace}-{topology.run_id}",
                "--iroh-publication-recipient",
                config.recipient,
                "--iroh-publication-authority-socket",
                f"{topology.authority_ip}:{AUTHORITY_PORT}",
                "--iroh-publication-authority-host",
                config.authority_host,
                "--iroh-publication-owner",
                config.owner,
                "--iroh-publication-address",
                f"{topology.publisher_ip}:{IROH_PORT}",
                "--iroh-publication-ttl-seconds",
                str(PUBLICATION_TTL_SECONDS),
                "--iroh-publication-refresh-seconds",
                str(PUBLICATION_REFRESH_SECONDS),
            ]
        )
    return [
        config.podman,
        "run",
        "--detach",
        "--name",
        topology.publisher(scenario),
        "--label",
        topology.label,
        "--cap-add",
        "NET_ADMIN",
        "--network",
        topology.publication_network,
        "--ip",
        str(topology.publisher_ip),
        "--volume",
        f"{state_dir.resolve()}:/state:Z",
        "--volume",
        f"{control_dir.resolve()}:/control:ro,Z",
        config.image,
        "/bin/bash",
        "-euc",
        'remote="$1"; router="$2"; shift 2; '
        "trap 'exit 143' TERM; trap 'exit 130' INT; "
        'ip route add "$remote" via "$router"; '
        'while test ! -e /control/start; do sleep 0.02; done; exec "$@"',
        "evidence-publisher",
        str(topology.authority_subnet),
        str(topology.router_publication_ip),
        *daemon_args,
    ]


def capture_filter(topology: Topology) -> str:
    return (
        f"(host {topology.authority_ip} and tcp port {AUTHORITY_PORT}) "
        "or udp port 53 or tcp port 53"
    )


def capture_command(
    config: RunConfig,
    topology: Topology,
    scenario: str,
    evidence_dir: Path,
) -> list[str]:
    publisher = topology.publisher(scenario)
    packet_filter = capture_filter(topology)
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
        f"container:{publisher}",
        "--volume",
        f"{evidence_dir.resolve()}:/evidence:Z",
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
        packet_filter,
    ]


def image_preflight_command(config: RunConfig, topology: Topology) -> list[str]:
    return [
        config.podman,
        "run",
        "--rm",
        "--name",
        topology.preflight,
        "--label",
        topology.label,
        "--network",
        "none",
        config.image,
        "/bin/bash",
        "-euc",
        "test -x /bin/daemon; test -x /bin/iroh-node-authority; "
        "test -x /bin/tcpdump; test -x /bin/ip",
    ]


def pcap_read_command(
    config: RunConfig,
    topology: Topology,
    scenario: str,
    evidence_dir: Path,
) -> list[str]:
    return [
        config.podman,
        "run",
        "--rm",
        "--name",
        topology.analyzer(scenario),
        "--label",
        topology.label,
        "--network",
        "none",
        "--volume",
        f"{evidence_dir.resolve()}:/evidence:ro,Z",
        config.image,
        "/bin/tcpdump",
        "-nn",
        "-tt",
        "-r",
        f"/evidence/{scenario}.pcap",
    ]


@dataclass(frozen=True)
class CleanupTarget:
    kind: str
    name: str
    exists: tuple[str, ...]
    label: tuple[str, ...]
    remove: tuple[str, ...]


def cleanup_targets(config: RunConfig, topology: Topology) -> tuple[CleanupTarget, ...]:
    containers = tuple(
        CleanupTarget(
            kind="container",
            name=name,
            exists=(config.podman, "container", "exists", name),
            label=(
                config.podman,
                "inspect",
                "--format",
                f'{{{{ index .Config.Labels "{LABEL_KEY}" }}}}',
                name,
            ),
            remove=(config.podman, "rm", "--force", "--ignore", name),
        )
        for name in topology.container_names()
    )
    networks = tuple(
        CleanupTarget(
            kind="network",
            name=name,
            exists=(config.podman, "network", "exists", name),
            label=(
                config.podman,
                "network",
                "inspect",
                "--format",
                f'{{{{ index .Labels "{LABEL_KEY}" }}}}',
                name,
            ),
            remove=(config.podman, "network", "rm", name),
        )
        for name in reversed(topology.network_names())
    )
    return containers + networks


def validate_cleanup_target(target: CleanupTarget, topology: Topology) -> None:
    expected = set(topology.container_names()) | set(topology.network_names())
    if target.name not in expected:
        raise CommandFailure(f"refusing cleanup of unexpected name {target.name!r}")
    if target.remove[-1:] != (target.name,):
        raise CommandFailure(
            f"refusing cleanup whose exact target is not last: {target.remove!r}"
        )
    if "--all" in target.remove or "--latest" in target.remove:
        raise CommandFailure(f"refusing broad cleanup command: {target.remove!r}")
    if LABEL_KEY not in " ".join(target.label):
        raise CommandFailure(f"cleanup label check omits {LABEL_KEY!r}")


def validate_cleanup_label(
    target: CleanupTarget, topology: Topology, observed: str
) -> None:
    if observed != topology.run_id:
        raise CommandFailure(
            f"refusing cleanup of {target.kind} {target.name!r}: "
            f"label {LABEL_KEY!r} is {observed!r}, expected {topology.run_id!r}"
        )


def cleanup_exact(runner: Runner, config: RunConfig, topology: Topology) -> None:
    """Remove only exact run names after proving their exact run label."""
    for target in cleanup_targets(config, topology):
        validate_cleanup_target(target, topology)
        exists = runner.run(list(target.exists), check=False)
        if exists.returncode == 1:
            continue
        if exists.returncode != 0:
            raise CommandFailure(
                f"could not establish whether {target.kind} {target.name!r} exists"
            )
        observed = runner.run(list(target.label)).stdout.decode().strip()
        validate_cleanup_label(target, topology, observed)
        runner.run(list(target.remove))


def cleanup_one_container(
    runner: Runner, config: RunConfig, topology: Topology, name: str
) -> None:
    target = next(
        (
            candidate
            for candidate in cleanup_targets(config, topology)
            if candidate.kind == "container" and candidate.name == name
        ),
        None,
    )
    if target is None:
        raise CommandFailure(f"refusing cleanup of unregistered container {name!r}")
    validate_cleanup_target(target, topology)
    exists = runner.run(list(target.exists), check=False)
    if exists.returncode == 1:
        return
    if exists.returncode != 0:
        raise CommandFailure(f"could not establish whether container {name!r} exists")
    observed = runner.run(list(target.label)).stdout.decode().strip()
    validate_cleanup_label(target, topology, observed)
    runner.run(list(target.remove))


def occupied_ipv4_networks(
    runner: Runner, podman: str
) -> tuple[ipaddress.IPv4Network, ...]:
    occupied: set[ipaddress.IPv4Network] = set()
    networks = runner.run([podman, "network", "ls", "--format", "json"])
    try:
        network_rows = json.loads(networks.stdout)
        for row in network_rows:
            for subnet in row.get("subnets") or []:
                parsed = ipaddress.ip_network(subnet["subnet"], strict=False)
                if isinstance(parsed, ipaddress.IPv4Network):
                    occupied.add(parsed)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise CommandFailure(
            f"cannot parse Podman network inventory: {error}"
        ) from error

    routes = runner.run(["ip", "-json", "route", "show", "table", "all"])
    try:
        route_rows = json.loads(routes.stdout)
        for row in route_rows:
            destination = row.get("dst")
            if not destination or destination == "default":
                continue
            parsed = ipaddress.ip_network(destination, strict=False)
            if isinstance(parsed, ipaddress.IPv4Network):
                occupied.add(parsed)
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise CommandFailure(f"cannot parse host route inventory: {error}") from error
    return tuple(
        sorted(
            occupied,
            key=lambda network: (int(network.network_address), network.prefixlen),
        )
    )


def container_exists(runner: Runner, podman: str, name: str) -> bool:
    result = runner.run([podman, "container", "exists", name], check=False)
    if result.returncode not in (0, 1):
        raise CommandFailure(f"could not establish whether container {name!r} exists")
    return result.returncode == 0


def container_state(runner: Runner, podman: str, name: str) -> tuple[bool, int]:
    result = runner.run(
        [
            podman,
            "inspect",
            "--format",
            "{{.State.Running}} {{.State.ExitCode}}",
            name,
        ]
    )
    parts = result.stdout.decode().strip().split()
    if len(parts) != 2 or parts[0] not in ("true", "false"):
        raise CommandFailure(
            f"invalid state returned for container {name!r}: {parts!r}"
        )
    try:
        exit_code = int(parts[1])
    except ValueError as error:
        raise CommandFailure(
            f"invalid exit code returned for container {name!r}"
        ) from error
    return parts[0] == "true", exit_code


def container_logs(runner: Runner, podman: str, name: str) -> bytes:
    result = runner.run([podman, "logs", name])
    # `podman logs` preserves the container's stdout/stderr split on its own
    # stdout/stderr.  Both streams are evidence; ignoring stderr loses daemon
    # setup failures and tcpdump lifecycle diagnostics.
    return result.stdout + result.stderr


def wait_for_log(
    runner: Runner,
    podman: str,
    name: str,
    pattern: re.Pattern[str],
    timeout_seconds: float,
) -> tuple[re.Match[str], bytes, int]:
    started = time.monotonic_ns()
    deadline = time.monotonic() + timeout_seconds
    while True:
        logs = container_logs(runner, podman, name)
        text = logs.decode("utf-8", "backslashreplace")
        match = pattern.search(text)
        if match is not None:
            return match, logs, time.monotonic_ns() - started
        running, exit_code = container_state(runner, podman, name)
        if not running:
            raise CommandFailure(
                f"container {name!r} exited {exit_code} before log pattern "
                f"{pattern.pattern!r}; log_tail={text[-4096:]!r}"
            )
        if time.monotonic() >= deadline:
            raise CommandFailure(
                f"container {name!r} did not emit {pattern.pattern!r} within "
                f"{timeout_seconds}s; log_tail={text[-4096:]!r}"
            )
        time.sleep(0.05)


PCAP_MAGIC = {
    b"\xa1\xb2\xc3\xd4",
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
    b"\x4d\x3c\xb2\xa1",
}


def wait_for_capture_ready(
    runner: Runner,
    podman: str,
    name: str,
    pcap: Path,
    timeout_seconds: float,
) -> int:
    """Wait for tcpdump's pcap header, its stable readiness boundary."""
    started = time.monotonic_ns()
    deadline = time.monotonic() + timeout_seconds
    while True:
        running, exit_code = container_state(runner, podman, name)
        if not running:
            logs = container_logs(runner, podman, name).decode(
                "utf-8", "backslashreplace"
            )
            raise CommandFailure(
                f"capture container {name!r} exited {exit_code} before writing "
                f"a pcap header; log_tail={logs[-4096:]!r}"
            )
        try:
            if pcap.is_symlink():
                raise CommandFailure(f"capture path {pcap} is a symlink")
            header = pcap.read_bytes()[:24]
        except FileNotFoundError:
            header = b""
        if len(header) == 24:
            if header[:4] not in PCAP_MAGIC:
                raise CommandFailure(
                    f"capture path {pcap} has an invalid pcap magic {header[:4].hex()}"
                )
            return time.monotonic_ns() - started
        if time.monotonic() >= deadline:
            raise CommandFailure(
                f"capture container {name!r} did not write a complete pcap header "
                f"to {pcap} within {timeout_seconds}s"
            )
        time.sleep(0.05)


def wait_for_exit(
    runner: Runner, podman: str, name: str, timeout_seconds: float
) -> int:
    result = runner.run([podman, "wait", name], timeout=timeout_seconds)
    try:
        return int(result.stdout.decode().strip())
    except ValueError as error:
        raise CommandFailure(
            f"podman wait returned an invalid exit code for {name!r}: {result.stdout!r}"
        ) from error


def signal_and_wait(
    runner: Runner,
    podman: str,
    name: str,
    signal: str,
    timeout_seconds: float = 20.0,
) -> int:
    running, exit_code = container_state(runner, podman, name)
    if not running:
        return exit_code
    runner.run([podman, "kill", "--signal", signal, name])
    return wait_for_exit(runner, podman, name, timeout_seconds)


def write_new(path: Path, data: bytes) -> None:
    if path.exists():
        raise RuntimeError(f"refusing to overwrite evidence file {path}")
    path.write_bytes(data)


NODE_ID_PATTERN = re.compile(r"IROH-PROVIDER-ADDR node_id=([0-9a-f]{64}) sockets=\S+")
AUTHORITY_READY_PATTERN = re.compile(r"iroh_node_authority_ready\b")
AUTHORITY_STOPPED_PATTERN = re.compile(
    r"iroh_node_authority_stopped signal=\S+ requests=(\d+)"
)


def exact_node_id(log: bytes) -> str:
    matches = set(NODE_ID_PATTERN.findall(log.decode("utf-8", "backslashreplace")))
    if len(matches) != 1:
        raise RuntimeError(
            f"expected exactly one stable NodeId in bootstrap log, got {matches}"
        )
    return matches.pop()


def authority_request_count(log: bytes) -> int:
    matches = AUTHORITY_STOPPED_PATTERN.findall(log.decode("utf-8", "backslashreplace"))
    if len(matches) != 1:
        raise RuntimeError(
            f"expected exactly one authority request count, got {matches}"
        )
    return int(matches[0])


def assert_empty_authority_state(state_dir: Path) -> None:
    state_file = state_dir / AUTHORITY_STATE_FILENAME
    if not state_file.exists():
        return
    try:
        state = json.loads(state_file.read_bytes())
        records = state["body"]["records"]
    except (KeyError, TypeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"cannot verify empty authority state: {error}") from error
    if records != {}:
        raise RuntimeError(f"authority did not start/remain empty: {sorted(records)}")


def signer_z32(node_id: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{64}", node_id):
        raise RuntimeError(f"invalid canonical NodeId {node_id!r}")
    standard = base64.b32encode(bytes.fromhex(node_id)).decode().rstrip("=").lower()
    return standard.translate(
        str.maketrans(
            "abcdefghijklmnopqrstuvwxyz234567",
            "ybndrfg8ejkmcpqxot1uwisza345h769",
        )
    )


def decode_dns_name(packet: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    cursor = offset
    next_offset: int | None = None
    seen: set[int] = set()
    while True:
        if cursor >= len(packet) or cursor in seen:
            raise RuntimeError("DNS name is truncated or contains a compression loop")
        seen.add(cursor)
        length = packet[cursor]
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(packet):
                raise RuntimeError("DNS compression pointer is truncated")
            pointer = ((length & 0x3F) << 8) | packet[cursor + 1]
            if pointer >= len(packet):
                raise RuntimeError("DNS compression pointer is out of bounds")
            if next_offset is None:
                next_offset = cursor + 2
            cursor = pointer
            continue
        if length & 0xC0:
            raise RuntimeError("DNS name uses an unsupported label encoding")
        cursor += 1
        if length == 0:
            return ".".join(labels), next_offset or cursor
        if length > 63 or cursor + length > len(packet):
            raise RuntimeError("DNS label is invalid or truncated")
        try:
            label = packet[cursor : cursor + length].decode("ascii")
        except UnicodeDecodeError as error:
            raise RuntimeError("DNS name contains non-ASCII bytes") from error
        if not label or label.lower() != label:
            raise RuntimeError(
                f"DNS label is not canonical lower-case ASCII: {label!r}"
            )
        labels.append(label)
        cursor += length


def decode_signed_node_packet(packet: bytes) -> dict[str, object]:
    if len(packet) < 116:
        raise RuntimeError(
            "signed pkarr packet is shorter than its header plus DNS header"
        )
    public_key = packet[:32]
    sequence = int.from_bytes(packet[96:104], "big")
    dns = packet[104:]
    if dns[:4] != b"\x00\x00\x80\x00":
        raise RuntimeError(
            "signed DNS header is not the canonical zero-id standard reply"
        )
    questions = int.from_bytes(dns[4:6], "big")
    answers = int.from_bytes(dns[6:8], "big")
    name_servers = int.from_bytes(dns[8:10], "big")
    additional = int.from_bytes(dns[10:12], "big")
    if questions != 0 or name_servers != 0 or additional != 0 or answers == 0:
        raise RuntimeError("signed DNS packet is not an answers-only record")

    offset = 12
    decoded_answers: list[tuple[str, int, str]] = []
    for _ in range(answers):
        name, offset = decode_dns_name(dns, offset)
        if offset + 10 > len(dns):
            raise RuntimeError("DNS resource-record header is truncated")
        record_type = int.from_bytes(dns[offset : offset + 2], "big")
        record_class = int.from_bytes(dns[offset + 2 : offset + 4], "big")
        ttl = int.from_bytes(dns[offset + 4 : offset + 8], "big")
        data_length = int.from_bytes(dns[offset + 8 : offset + 10], "big")
        offset += 10
        end = offset + data_length
        if end > len(dns) or record_type != 16 or record_class != 1 or ttl == 0:
            raise RuntimeError("DNS answer is truncated or is not positive-TTL IN TXT")
        chunks: list[bytes] = []
        while offset < end:
            chunk_length = dns[offset]
            offset += 1
            if offset + chunk_length > end:
                raise RuntimeError("DNS TXT character string is truncated")
            chunks.append(dns[offset : offset + chunk_length])
            offset += chunk_length
        if not chunks:
            raise RuntimeError("DNS TXT answer is empty")
        try:
            value = b"".join(chunks).decode("utf-8")
        except UnicodeDecodeError as error:
            raise RuntimeError("DNS TXT answer is not UTF-8") from error
        decoded_answers.append((name, ttl, value))
    if offset != len(dns):
        raise RuntimeError("signed DNS packet contains trailing bytes")

    node_id = public_key.hex()
    signer = signer_z32(node_id)
    iroh_name = f"_iroh.{signer}"
    metadata_name = f"_nix-p2p-iroh.{signer}"
    metadata: dict[str, str] = {}
    locations: list[str] = []
    ttls: set[int] = set()
    for name, ttl, value in decoded_answers:
        ttls.add(ttl)
        if value.count("=") != 1:
            raise RuntimeError(
                f"TXT answer is not one canonical key=value pair: {value!r}"
            )
        key, raw = value.split("=", 1)
        if not key or not raw:
            raise RuntimeError(f"TXT answer has an empty key/value: {value!r}")
        if name == iroh_name:
            if key not in ("addr", "relay") or value in locations:
                raise RuntimeError(f"invalid or duplicate Iroh location {value!r}")
            locations.append(value)
        elif name == metadata_name:
            if key in metadata:
                raise RuntimeError(f"duplicate metadata key {key!r}")
            metadata[key] = raw
        else:
            raise RuntimeError(f"unexpected signed DNS answer name {name!r}")
    expected_keys = {
        "schema",
        "namespace",
        "signer",
        "node-id",
        "recipient",
        "ttl-seconds",
        "sequence",
        "expires-unix-micros",
        "state",
    }
    if set(metadata) != expected_keys or len(ttls) != 1:
        raise RuntimeError("signed metadata keys/TTLs are not exact and uniform")
    try:
        ttl_seconds = int(metadata["ttl-seconds"])
        metadata_sequence = int(metadata["sequence"])
        expires_unix_micros = int(metadata["expires-unix-micros"])
    except ValueError as error:
        raise RuntimeError(
            "signed numeric metadata is not canonical decimal"
        ) from error
    for key in ("ttl-seconds", "sequence", "expires-unix-micros"):
        raw = metadata[key]
        if not raw.isascii() or not raw.isdecimal() or (len(raw) > 1 and raw[0] == "0"):
            raise RuntimeError(f"signed {key} is not canonical decimal")
    if metadata_sequence != sequence or ttls != {ttl_seconds}:
        raise RuntimeError("signed pkarr sequence/DNS TTL does not match metadata")
    if metadata["signer"] != signer or metadata["node-id"] != node_id:
        raise RuntimeError("signed metadata identity does not match pkarr public key")
    if expires_unix_micros - sequence != ttl_seconds * 1_000_000:
        raise RuntimeError("signed expiry is not exactly sequence plus TTL")
    return {
        "node_id": node_id,
        "signer": signer,
        "schema": metadata["schema"],
        "namespace": metadata["namespace"],
        "recipient": metadata["recipient"],
        "ttl_seconds": ttl_seconds,
        "sequence": sequence,
        "expires_unix_micros": expires_unix_micros,
        "state": metadata["state"],
        "locations": sorted(locations),
        "packet_sha256": hashlib.sha256(packet).hexdigest(),
        "packet_bytes": len(packet),
        "signature_validated_by_authority": True,
    }


def read_strict_authority_snapshot(
    state_dir: Path,
    *,
    node_id: str,
    namespace: str,
    recipient: str,
    expected_address: str,
    expected_ttl_seconds: int = PUBLICATION_TTL_SECONDS,
) -> tuple[dict[str, object], bytes] | None:
    state_path = state_dir / "iroh-node-publication-authority.json"
    if not state_path.exists():
        return None
    raw_state = state_path.read_bytes()
    try:
        envelope = json.loads(raw_state)
        body = envelope["body"]
        records = body["records"]
    except (KeyError, TypeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"authority state is malformed: {error}") from error
    if body.get("schema_version") != 1:
        raise RuntimeError(
            f"authority state schema is not v1: {body.get('schema_version')!r}"
        )
    if body.get("namespace") != namespace or body.get("signed_recipient") != recipient:
        raise RuntimeError(
            "authority state namespace/recipient drifted from configuration"
        )
    if not records:
        return None
    signer = signer_z32(node_id)
    if set(records) != {signer}:
        raise RuntimeError(
            f"authority signer set is not the exact admitted NodeId: {records}"
        )
    entry = records[signer]
    try:
        packet_hex = entry["packet_hex"]
        packet = bytes.fromhex(packet_hex)
    except (KeyError, TypeError, ValueError) as error:
        raise RuntimeError(f"authority packet_hex is invalid: {error}") from error
    if packet_hex != packet_hex.lower() or len(packet_hex) != len(packet) * 2:
        raise RuntimeError("authority packet_hex is not canonical lower-case hex")
    record = decode_signed_node_packet(packet)
    if record["node_id"] != node_id or record["signer"] != signer:
        raise RuntimeError(
            "signed record identity does not match explicit authority ACL"
        )
    if record["schema"] != "iroh-node-publication-v1":
        raise RuntimeError(f"unexpected signed record schema {record['schema']!r}")
    if record["namespace"] != namespace or record["recipient"] != recipient:
        raise RuntimeError(
            "signed record namespace/recipient drifted from configuration"
        )
    if record["ttl_seconds"] != expected_ttl_seconds:
        raise RuntimeError(f"signed record TTL drifted: {record['ttl_seconds']!r}")
    if entry.get("high_water_sequence") != record["sequence"]:
        raise RuntimeError("authority high-water does not match signed sequence")
    if entry.get("expires_unix_micros") != record["expires_unix_micros"]:
        raise RuntimeError("authority expiry does not match signed expiry")
    if entry.get("state") != record["state"] or entry.get("expired") is not False:
        raise RuntimeError(
            "authority lifecycle state does not match current signed record"
        )
    locations = record["locations"]
    state = record["state"]
    if state == "live" and locations != [f"addr={expected_address}"]:
        raise RuntimeError(f"live record location is not exact: {locations!r}")
    if state == "withdrawn" and locations != []:
        raise RuntimeError(f"withdrawal retained locations: {locations!r}")
    if state not in ("live", "withdrawn"):
        raise RuntimeError(f"unknown signed lifecycle state {state!r}")
    forbidden = ("narhash", "storepath", "closure", "inventory", "/nix/store")
    # Inspect the signed DNS payload, not the public key/signature: arbitrary
    # signature bytes can coincidentally spell a token without publishing it.
    lowered = packet[104:].lower()
    leaked = [token for token in forbidden if token.encode() in lowered]
    if leaked or any(str(location).startswith("relay=") for location in locations):
        raise RuntimeError(f"record crossed content/relay boundary: leaked={leaked}")
    snapshot = {
        "authority_state_schema_version": body["schema_version"],
        "authority_wall_clock_high_water_unix_micros": body[
            "wall_clock_high_water_unix_micros"
        ],
        "authority_high_water_sequence": entry["high_water_sequence"],
        "authority_expired": entry["expired"],
        **record,
    }
    return snapshot, raw_state


def wait_for_authority_snapshot(
    state_dir: Path,
    *,
    node_id: str,
    namespace: str,
    recipient: str,
    expected_address: str,
    expected_state: str,
    minimum_sequence_exclusive: int,
    deadline_monotonic_ns: int,
    expected_ttl_seconds: int = PUBLICATION_TTL_SECONDS,
) -> tuple[dict[str, object], bytes, int]:
    while True:
        observed_monotonic_ns = time.monotonic_ns()
        snapshot = read_strict_authority_snapshot(
            state_dir,
            node_id=node_id,
            namespace=namespace,
            recipient=recipient,
            expected_address=expected_address,
            expected_ttl_seconds=expected_ttl_seconds,
        )
        if snapshot is not None:
            decoded, raw = snapshot
            sequence = decoded["sequence"]
            assert isinstance(sequence, int)
            if sequence > minimum_sequence_exclusive:
                if decoded["state"] != expected_state:
                    raise RuntimeError(
                        f"new sequence {sequence} has state {decoded['state']!r}, "
                        f"expected {expected_state!r}"
                    )
                return decoded, raw, observed_monotonic_ns
        if observed_monotonic_ns >= deadline_monotonic_ns:
            raise RuntimeError(
                f"authority did not expose a newer {expected_state} record before deadline"
            )
        time.sleep(0.02)


def preserve_authority_snapshot(
    output: Path,
    label: str,
    snapshot: dict[str, object],
    raw_state: bytes,
) -> None:
    write_new(output / f"{label}.authority-state.json", raw_state)
    write_new(output / f"{label}.record.json", canonical_json(snapshot))


def preserve_final_authority_files(
    state_dir: Path, output: Path, scenario: str
) -> None:
    """Keep the authority's raw durable files even when an assertion failed."""
    for source_name, evidence_name in (
        (AUTHORITY_STATE_FILENAME, f"{scenario}.final-authority-state.json"),
        (AUTHORITY_ANCHOR_FILENAME, f"{scenario}.final-authority-anchor.json"),
    ):
        source = state_dir / source_name
        if source.is_file():
            write_new(output / evidence_name, source.read_bytes())


def create_private_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=False)
    path.chmod(0o700)


def validate_immutable_image_reference(reference: str) -> None:
    digest_reference = re.search(r"@sha256:[0-9a-f]{64}$", reference)
    tag = reference.rsplit(":", 1)[1] if ":" in reference.rsplit("/", 1)[-1] else ""
    content_tag = re.fullmatch(r"[0-9a-z]{20,64}", tag)
    if digest_reference is None and content_tag is None:
        raise RuntimeError(
            f"live evidence refuses mutable/non-content image reference {reference!r}; "
            "pass a digest or a tag derived from the Nix image store hash"
        )


def validate_image_implementation_revision(value: object) -> str:
    if (
        not isinstance(value, str)
        or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})(?:-dirty)?", value) is None
    ):
        raise CommandFailure(
            f"image label {IMAGE_REVISION_LABEL!r} is not a canonical Git revision"
        )
    return value


def image_implementation_revision(row: dict[str, object]) -> str:
    candidates: list[object] = []
    labels = row.get("Labels")
    if isinstance(labels, dict) and IMAGE_REVISION_LABEL in labels:
        candidates.append(labels[IMAGE_REVISION_LABEL])
    config = row.get("Config")
    if isinstance(config, dict):
        config_labels = config.get("Labels")
        if isinstance(config_labels, dict) and IMAGE_REVISION_LABEL in config_labels:
            candidates.append(config_labels[IMAGE_REVISION_LABEL])
    if not candidates:
        raise CommandFailure(
            f"evidence image omits required OCI label {IMAGE_REVISION_LABEL!r}"
        )
    validated = [validate_image_implementation_revision(value) for value in candidates]
    if len(set(validated)) != 1:
        raise CommandFailure(
            f"evidence image reports conflicting {IMAGE_REVISION_LABEL!r} labels"
        )
    return validated[0]


def immutable_image_identity(runner: Runner, config: RunConfig) -> dict[str, object]:
    reference = config.image
    validate_immutable_image_reference(reference)
    exists = runner.run([config.podman, "image", "exists", config.image], check=False)
    if exists.returncode == 1:
        raise RuntimeError(
            f"evidence image {config.image!r} is not loaded; build "
            ".#iroh-publication-evidence-image and load its archive into Podman"
        )
    if exists.returncode != 0:
        raise CommandFailure(f"could not query evidence image {config.image!r}")
    inspected = runner.run([config.podman, "image", "inspect", config.image])
    try:
        rows = json.loads(inspected.stdout)
        if len(rows) != 1:
            raise ValueError(f"expected one image row, got {len(rows)}")
        row = rows[0]
        image_id = row["Id"]
        repo_digests = row.get("RepoDigests") or []
        digest = row.get("Digest") or None
        implementation_revision = image_implementation_revision(row)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise CommandFailure(f"cannot parse Podman image identity: {error}") from error
    if not re.fullmatch(r"(?:sha256:)?[0-9a-f]{64}", image_id):
        raise CommandFailure(f"Podman returned a non-content image ID {image_id!r}")
    return {
        "reference": reference,
        "podman_image_id": image_id,
        "podman_digest": digest,
        "podman_repo_digests": sorted(repo_digests),
        "implementation_revision": implementation_revision,
    }


def verify_image(
    runner: Runner, config: RunConfig, topology: Topology
) -> dict[str, object]:
    identity = immutable_image_identity(runner, config)
    rootless = (
        runner.run([config.podman, "info", "--format", "{{.Host.Security.Rootless}}"])
        .stdout.decode()
        .strip()
    )
    if rootless != "true":
        raise RuntimeError(
            f"evidence requires rootless Podman, observed rootless={rootless!r}"
        )
    runner.run(image_preflight_command(config, topology), timeout=30.0)
    return identity


def bootstrap_node_id(
    runner: Runner,
    config: RunConfig,
    topology: Topology,
    publisher_state: Path,
    scratch: Path,
    output: Path,
) -> tuple[str, dict[str, object]]:
    scenario = "bootstrap"
    name = topology.publisher(scenario)
    control = scratch / "control-bootstrap"
    create_private_directory(control)
    (control / "start").touch(mode=0o600)
    started_unix_ns = time.time_ns()
    started_monotonic_ns = time.monotonic_ns()
    log = b""
    exit_code: int | None = None
    error: BaseException | None = None
    cleanup_errors: list[str] = []
    try:
        runner.run(
            publisher_command(
                config,
                topology,
                scenario,
                publisher_state,
                control,
                publication_enabled=False,
                offline=False,
            )
        )
        _, log, ready_elapsed_ns = wait_for_log(
            runner, config.podman, name, NODE_ID_PATTERN, 15.0
        )
        exit_code = signal_and_wait(runner, config.podman, name, "TERM")
        log = container_logs(runner, config.podman, name)
        if exit_code != 0:
            raise RuntimeError(f"identity bootstrap exited {exit_code}, expected 0")
        node_id = exact_node_id(log)
        observation = {
            "scenario": scenario,
            "started_unix_ns": started_unix_ns,
            "started_monotonic_ns": started_monotonic_ns,
            "ready_elapsed_ns": ready_elapsed_ns,
            "exit_code": exit_code,
            "node_id": node_id,
            "elapsed_ns": time.monotonic_ns() - started_monotonic_ns,
        }
    except BaseException as caught:
        error = caught
        observation = {}
        node_id = ""
    finally:
        if container_exists(runner, config.podman, name):
            try:
                running, _ = container_state(runner, config.podman, name)
                if running:
                    exit_code = signal_and_wait(runner, config.podman, name, "TERM")
                log = container_logs(runner, config.podman, name)
            except Exception as cleanup_error:
                cleanup_errors.append(f"stopping bootstrap: {cleanup_error}")
            try:
                if not (output / "bootstrap.log").exists():
                    write_new(output / "bootstrap.log", log)
            except Exception as cleanup_error:
                cleanup_errors.append(f"saving bootstrap log: {cleanup_error}")
            try:
                cleanup_one_container(runner, config, topology, name)
            except Exception as cleanup_error:
                cleanup_errors.append(f"removing bootstrap: {cleanup_error}")
    if error is not None:
        if cleanup_errors:
            raise RuntimeError(f"{error}; cleanup errors: {cleanup_errors}") from error
        raise error
    if cleanup_errors:
        raise RuntimeError(f"identity bootstrap cleanup failed: {cleanup_errors}")
    return node_id, observation


def analyze_pcap(
    runner: Runner,
    config: RunConfig,
    topology: Topology,
    scenario: str,
    output: Path,
    capture_log: bytes,
) -> int:
    pcap = output / f"{scenario}.pcap"
    if not pcap.is_file() or pcap.stat().st_size < 24:
        raise RuntimeError(f"capture {pcap} is missing or lacks a pcap header")
    result = runner.run(pcap_read_command(config, topology, scenario, output))
    write_new(output / f"{scenario}.packets.log", result.stdout)
    write_new(output / f"{scenario}.pcap-read.log", result.stderr)
    packet_count = sum(1 for line in result.stdout.splitlines() if line.strip())
    validate_complete_capture(scenario, capture_log, packet_count)
    return packet_count


def parse_tcpdump_shutdown_stats(log: bytes) -> TcpdumpShutdownStats:
    def one(pattern: re.Pattern[bytes], label: str) -> int:
        matches = pattern.findall(log)
        if len(matches) != 1:
            tail = log[-4096:].decode("utf-8", "backslashreplace")
            raise RuntimeError(
                f"tcpdump log has {len(matches)} exact {label} shutdown counters, "
                f"expected one; log_tail={tail!r}"
            )
        return int(matches[0])

    return TcpdumpShutdownStats(
        captured=one(TCPDUMP_CAPTURED_RE, "packets-captured"),
        received_by_filter=one(TCPDUMP_RECEIVED_RE, "packets-received-by-filter"),
        dropped_by_kernel=one(TCPDUMP_DROPPED_RE, "packets-dropped-by-kernel"),
    )


def validate_complete_capture(
    scenario: str, capture_log: bytes, pcap_packet_count: int
) -> TcpdumpShutdownStats:
    stats = parse_tcpdump_shutdown_stats(capture_log)
    if stats.dropped_by_kernel != 0:
        raise RuntimeError(
            f"{scenario} tcpdump dropped {stats.dropped_by_kernel} packet(s) in kernel"
        )
    if stats.captured != stats.received_by_filter:
        raise RuntimeError(
            f"{scenario} tcpdump captured {stats.captured} packet(s), but its filter "
            f"received {stats.received_by_filter}; capture is incomplete"
        )
    if pcap_packet_count != stats.captured:
        raise RuntimeError(
            f"{scenario} pcap contains {pcap_packet_count} packet(s), but tcpdump "
            f"reported {stats.captured} captured; pcap is incomplete"
        )
    return stats


def run_zero_control(
    runner: Runner,
    config: RunConfig,
    topology: Topology,
    node_id: str,
    publisher_state: Path,
    scratch: Path,
    output: Path,
    *,
    scenario: str,
    publication_enabled: bool,
    offline: bool,
    expect_fail_closed: bool,
) -> dict[str, object]:
    authority_state = scratch / f"authority-{scenario}"
    control = scratch / f"control-{scenario}"
    create_private_directory(authority_state)
    create_private_directory(control)
    publisher = topology.publisher(scenario)
    capture = topology.capture(scenario)
    authority = topology.authority
    publisher_log = b""
    capture_log = b""
    authority_log = b""
    publisher_exit: int | None = None
    capture_exit: int | None = None
    authority_exit: int | None = None
    gate_unix_ns: int | None = None
    gate_monotonic_ns: int | None = None
    outcome_elapsed_ns: int | None = None
    control_hold_elapsed_ns: int | None = None
    primary: BaseException | None = None
    cleanup_errors: list[str] = []

    try:
        runner.run(authority_command(config, topology, authority_state, node_id))
        wait_for_log(runner, config.podman, authority, AUTHORITY_READY_PATTERN, 5.0)
        assert_empty_authority_state(authority_state)
        runner.run(
            publisher_command(
                config,
                topology,
                scenario,
                publisher_state,
                control,
                publication_enabled=publication_enabled,
                offline=offline,
            )
        )
        runner.run(capture_command(config, topology, scenario, output))
        wait_for_capture_ready(
            runner,
            config.podman,
            capture,
            output / f"{scenario}.pcap",
            5.0,
        )

        gate_unix_ns = time.time_ns()
        gate_monotonic_ns = time.monotonic_ns()
        (control / "start").touch(mode=0o600)
        if expect_fail_closed:
            publisher_exit = wait_for_exit(runner, config.podman, publisher, 10.0)
            outcome_elapsed_ns = time.monotonic_ns() - gate_monotonic_ns
            publisher_log = container_logs(runner, config.podman, publisher)
            text = publisher_log.decode("utf-8", "backslashreplace")
            if (
                publisher_exit == 0
                or "offline-test rejects node-publication" not in text
            ):
                raise RuntimeError(
                    "offline+publication did not fail closed with the expected boundary error"
                )
        else:
            wait_for_log(runner, config.podman, publisher, NODE_ID_PATTERN, 15.0)
            outcome_elapsed_ns = time.monotonic_ns() - gate_monotonic_ns
            minimum_hold_deadline = (
                gate_monotonic_ns
                + PUBLICATION_REFRESH_SECONDS * 1_000_000_000
                + 100_000_000
            )
            while time.monotonic_ns() <= minimum_hold_deadline:
                time.sleep(0.05)
            control_hold_elapsed_ns = time.monotonic_ns() - gate_monotonic_ns
            if control_hold_elapsed_ns <= PUBLICATION_REFRESH_SECONDS * 1_000_000_000:
                raise RuntimeError(
                    "zero control did not remain alive beyond one refresh interval"
                )
            publisher_exit = signal_and_wait(
                runner, config.podman, publisher, "TERM", 20.0
            )
            if publisher_exit != 0:
                raise RuntimeError(
                    f"zero-control publisher exited {publisher_exit}, expected 0"
                )
    except BaseException as caught:
        primary = caught

    for name, signal in ((publisher, "TERM"), (capture, "INT"), (authority, "TERM")):
        if not container_exists(runner, config.podman, name):
            continue
        try:
            running, observed_exit = container_state(runner, config.podman, name)
            final_exit = (
                signal_and_wait(runner, config.podman, name, signal, 20.0)
                if running
                else observed_exit
            )
            if name == publisher:
                publisher_exit = final_exit
            elif name == capture:
                capture_exit = final_exit
            else:
                authority_exit = final_exit
        except Exception as cleanup_error:
            cleanup_errors.append(f"stopping {name}: {cleanup_error}")

    for name, filename in (
        (publisher, f"{scenario}.publisher.log"),
        (capture, f"{scenario}.capture.log"),
        (authority, f"{scenario}.authority.log"),
    ):
        if not container_exists(runner, config.podman, name):
            continue
        try:
            observed = container_logs(runner, config.podman, name)
            if name == publisher:
                publisher_log = observed
            elif name == capture:
                capture_log = observed
            elif name == authority:
                authority_log = observed
            write_new(output / filename, observed)
        except Exception as cleanup_error:
            cleanup_errors.append(f"saving {name} log: {cleanup_error}")

    try:
        preserve_final_authority_files(authority_state, output, scenario)
    except Exception as cleanup_error:
        cleanup_errors.append(f"saving {scenario} authority state: {cleanup_error}")

    packet_count: int | None = None
    requests: int | None = None
    if primary is None and not cleanup_errors:
        try:
            if capture_exit != 0:
                raise RuntimeError(f"capture exited {capture_exit}, expected 0")
            packet_count = analyze_pcap(
                runner,
                config,
                topology,
                scenario,
                output,
                capture_log,
            )
            if packet_count != 0:
                raise RuntimeError(
                    f"{scenario} emitted {packet_count} in-scope "
                    "publication-recipient/DNS packets"
                )
            assert_empty_authority_state(authority_state)
            if authority_exit != 0:
                raise RuntimeError(f"authority exited {authority_exit}, expected 0")
            requests = authority_request_count(authority_log)
            if requests != 0:
                raise RuntimeError(
                    f"{scenario} reached authority {requests} time(s), expected 0"
                )
        except Exception as assertion_error:
            primary = assertion_error

    for name in (capture, publisher, authority):
        try:
            cleanup_one_container(runner, config, topology, name)
        except Exception as cleanup_error:
            cleanup_errors.append(f"removing {name}: {cleanup_error}")

    if primary is not None:
        if cleanup_errors:
            raise RuntimeError(
                f"{primary}; cleanup errors: {cleanup_errors}"
            ) from primary
        raise primary
    if cleanup_errors:
        raise RuntimeError(f"{scenario} cleanup failed: {cleanup_errors}")
    return {
        "scenario": scenario,
        "publication_enabled": publication_enabled,
        "offline": offline,
        "expected_fail_closed": expect_fail_closed,
        "gate_release_unix_ns": gate_unix_ns,
        "gate_release_monotonic_ns": gate_monotonic_ns,
        "outcome_elapsed_ns": outcome_elapsed_ns,
        "control_hold_elapsed_ns": control_hold_elapsed_ns,
        "publisher_exit_code": publisher_exit,
        "capture_exit_code": capture_exit,
        "authority_exit_code": authority_exit,
        "captured_in_scope_packet_count": packet_count,
        "authority_request_count": requests,
    }


def run_positive_arm(
    runner: Runner,
    config: RunConfig,
    topology: Topology,
    node_id: str,
    publisher_state: Path,
    scratch: Path,
    output: Path,
) -> dict[str, object]:
    scenario = "live"
    namespace = f"{config.namespace}-{topology.run_id}"
    expected_address = f"{topology.publisher_ip}:{IROH_PORT}"
    authority_state = scratch / "authority-live"
    control = scratch / "control-live"
    create_private_directory(authority_state)
    create_private_directory(control)
    publisher = topology.publisher(scenario)
    capture = topology.capture(scenario)
    authority = topology.authority
    publisher_log = b""
    capture_log = b""
    authority_log = b""
    publisher_exit: int | None = None
    capture_exit: int | None = None
    authority_exit: int | None = None
    packet_count: int | None = None
    requests: int | None = None
    gate_unix_ns: int | None = None
    gate_monotonic_ns: int | None = None
    live_observed_ns: int | None = None
    refresh_due_ns: int | None = None
    refresh_observed_ns: int | None = None
    signal_unix_ns: int | None = None
    signal_monotonic_ns: int | None = None
    withdrawal_observed_ns: int | None = None
    withdrawal_completed_ns: int | None = None
    live_record: dict[str, object] | None = None
    refresh_record: dict[str, object] | None = None
    withdrawal_record: dict[str, object] | None = None
    primary: BaseException | None = None
    cleanup_errors: list[str] = []

    try:
        assert_empty_authority_state(authority_state)
        runner.run(authority_command(config, topology, authority_state, node_id))
        wait_for_log(runner, config.podman, authority, AUTHORITY_READY_PATTERN, 5.0)
        assert_empty_authority_state(authority_state)
        runner.run(
            publisher_command(
                config,
                topology,
                scenario,
                publisher_state,
                control,
                publication_enabled=True,
                offline=False,
            )
        )
        runner.run(capture_command(config, topology, scenario, output))
        wait_for_capture_ready(
            runner,
            config.podman,
            capture,
            output / f"{scenario}.pcap",
            5.0,
        )

        gate_unix_ns = time.time_ns()
        gate_monotonic_ns = time.monotonic_ns()
        (control / "start").touch(mode=0o600)
        live_record, live_raw, live_observed_ns = wait_for_authority_snapshot(
            authority_state,
            node_id=node_id,
            namespace=namespace,
            recipient=config.recipient,
            expected_address=expected_address,
            expected_state="live",
            minimum_sequence_exclusive=-1,
            deadline_monotonic_ns=gate_monotonic_ns + 11_000_000_000,
        )
        if live_observed_ns - gate_monotonic_ns > 11_000_000_000:
            raise RuntimeError(
                "live visibility exceeded 10s plus 1s observer tolerance"
            )
        preserve_authority_snapshot(output, "live-initial", live_record, live_raw)

        initial_sequence = live_record["sequence"]
        assert isinstance(initial_sequence, int)
        startup_remaining = max(
            0.1,
            (gate_monotonic_ns + 11_000_000_000 - time.monotonic_ns()) / 1_000_000_000,
        )
        wait_for_log(
            runner,
            config.podman,
            publisher,
            re.compile(
                rf"IROH-NODE-PUBLICATION state=Live sequence={initial_sequence}\b"
            ),
            startup_remaining,
        )
        refresh_due_ns = live_observed_ns + PUBLICATION_REFRESH_SECONDS * 1_000_000_000
        refresh_record, refresh_raw, refresh_observed_ns = wait_for_authority_snapshot(
            authority_state,
            node_id=node_id,
            namespace=namespace,
            recipient=config.recipient,
            expected_address=expected_address,
            expected_state="live",
            minimum_sequence_exclusive=initial_sequence,
            deadline_monotonic_ns=live_observed_ns + 6_000_000_000,
        )
        refresh_elapsed_ns = refresh_observed_ns - live_observed_ns
        if refresh_elapsed_ns > 6_000_000_000:
            raise RuntimeError(
                "refresh visibility exceeded 5s plus 1s observer tolerance"
            )
        if refresh_record["packet_sha256"] == live_record["packet_sha256"]:
            raise RuntimeError("newer refresh sequence reused the initial packet hash")
        preserve_authority_snapshot(output, "live-refresh", refresh_record, refresh_raw)

        refresh_sequence = refresh_record["sequence"]
        assert isinstance(refresh_sequence, int)
        refresh_log_remaining = max(
            0.1,
            (live_observed_ns + 6_000_000_000 - time.monotonic_ns()) / 1_000_000_000,
        )
        wait_for_log(
            runner,
            config.podman,
            publisher,
            re.compile(
                rf"IROH-NODE-PUBLICATION-REFRESH state=Live sequence={refresh_sequence}\b"
            ),
            refresh_log_remaining,
        )
        signal_unix_ns = time.time_ns()
        signal_monotonic_ns = time.monotonic_ns()
        withdrawal_deadline_ns = signal_monotonic_ns + 6_000_000_000
        runner.run([config.podman, "kill", "--signal", "TERM", publisher])
        withdrawal_record, withdrawal_raw, withdrawal_observed_ns = (
            wait_for_authority_snapshot(
                authority_state,
                node_id=node_id,
                namespace=namespace,
                recipient=config.recipient,
                expected_address=expected_address,
                expected_state="withdrawn",
                minimum_sequence_exclusive=refresh_sequence,
                deadline_monotonic_ns=withdrawal_deadline_ns,
            )
        )
        if withdrawal_observed_ns - signal_monotonic_ns > 6_000_000_000:
            raise RuntimeError(
                "withdrawal visibility exceeded 5s plus 1s observer tolerance"
            )
        if withdrawal_record["packet_sha256"] in {
            live_record["packet_sha256"],
            refresh_record["packet_sha256"],
        }:
            raise RuntimeError("withdrawal did not produce a distinct signed packet")
        preserve_authority_snapshot(
            output, "live-withdrawal", withdrawal_record, withdrawal_raw
        )
        withdrawal_sequence = withdrawal_record["sequence"]
        assert isinstance(withdrawal_sequence, int)
        log_remaining_ns = withdrawal_deadline_ns - time.monotonic_ns()
        if log_remaining_ns <= 0:
            raise RuntimeError(
                "withdrawal log token was not observed before the absolute deadline"
            )
        wait_for_log(
            runner,
            config.podman,
            publisher,
            re.compile(
                rf"IROH-NODE-PUBLICATION-WITHDRAWN sequence={withdrawal_sequence}\b"
            ),
            log_remaining_ns / 1_000_000_000,
        )
        exit_remaining_ns = withdrawal_deadline_ns - time.monotonic_ns()
        if exit_remaining_ns <= 0:
            raise RuntimeError(
                "publisher did not exit cleanly before the absolute withdrawal deadline"
            )
        publisher_exit = wait_for_exit(
            runner,
            config.podman,
            publisher,
            exit_remaining_ns / 1_000_000_000,
        )
        withdrawal_completed_ns = time.monotonic_ns()
        if publisher_exit != 0:
            raise RuntimeError(
                f"positive publisher exited {publisher_exit}, expected 0"
            )
        if withdrawal_completed_ns > withdrawal_deadline_ns:
            raise RuntimeError(
                "publisher clean exit exceeded the absolute withdrawal deadline"
            )
    except BaseException as caught:
        primary = caught

    for name, signal in ((publisher, "TERM"), (capture, "INT"), (authority, "TERM")):
        if not container_exists(runner, config.podman, name):
            continue
        try:
            running, observed_exit = container_state(runner, config.podman, name)
            final_exit = (
                signal_and_wait(runner, config.podman, name, signal, 20.0)
                if running
                else observed_exit
            )
            if name == publisher:
                publisher_exit = final_exit
            elif name == capture:
                capture_exit = final_exit
            else:
                authority_exit = final_exit
        except Exception as cleanup_error:
            cleanup_errors.append(f"stopping {name}: {cleanup_error}")

    for name, filename in (
        (publisher, "live.publisher.log"),
        (capture, "live.capture.log"),
        (authority, "live.authority.log"),
    ):
        if not container_exists(runner, config.podman, name):
            continue
        try:
            observed = container_logs(runner, config.podman, name)
            if name == publisher:
                publisher_log = observed
            elif name == capture:
                capture_log = observed
            elif name == authority:
                authority_log = observed
            write_new(output / filename, observed)
        except Exception as cleanup_error:
            cleanup_errors.append(f"saving {name} log: {cleanup_error}")

    try:
        preserve_final_authority_files(authority_state, output, scenario)
    except Exception as cleanup_error:
        cleanup_errors.append(f"saving {scenario} authority state: {cleanup_error}")

    if primary is None and not cleanup_errors:
        try:
            if capture_exit != 0 or authority_exit != 0:
                raise RuntimeError(
                    f"positive capture/authority exits were {capture_exit}/{authority_exit}"
                )
            packet_count = analyze_pcap(
                runner,
                config,
                topology,
                scenario,
                output,
                capture_log,
            )
            if packet_count <= 0:
                raise RuntimeError(
                    "positive mutation did not produce routed in-scope packet evidence"
                )
            requests = authority_request_count(authority_log)
            if requests != 6:
                raise RuntimeError(
                    f"positive authority request count {requests} is not exactly "
                    "three live/refresh/withdraw PUT+GET pairs"
                )
            if b"IROH-NODE-AUTHORITY-REQUEST-FAILED" in authority_log:
                raise RuntimeError("positive authority log contains a failed request")
            assert live_record is not None
            assert refresh_record is not None
            assert withdrawal_record is not None
            sequences = [
                live_record["sequence"],
                refresh_record["sequence"],
                withdrawal_record["sequence"],
            ]
            if sequences != sorted(set(sequences)):
                raise RuntimeError(
                    f"publication sequences are not strictly increasing: {sequences}"
                )
            text = publisher_log.decode("utf-8", "backslashreplace")
            expected_log_tokens = (
                f"IROH-NODE-PUBLICATION state=Live sequence={sequences[0]}",
                f"IROH-NODE-PUBLICATION-REFRESH state=Live sequence={sequences[1]}",
                f"IROH-NODE-PUBLICATION-WITHDRAWN sequence={sequences[2]}",
            )
            missing = [token for token in expected_log_tokens if token not in text]
            if missing:
                raise RuntimeError(f"publisher lifecycle logs omit {missing}")
            failure_markers = (
                "IROH-NODE-PUBLICATION-REFRESH-FAILED",
                "IROH-NODE-PUBLICATION-ADDRESS-CHANGE-FAILED",
                "IROH-NODE-SHUTDOWN-FAILED",
            )
            observed_failures = [marker for marker in failure_markers if marker in text]
            if observed_failures:
                raise RuntimeError(
                    f"publisher lifecycle logs contain failures: {observed_failures}"
                )
        except Exception as assertion_error:
            primary = assertion_error

    for name in (capture, publisher, authority):
        try:
            cleanup_one_container(runner, config, topology, name)
        except Exception as cleanup_error:
            cleanup_errors.append(f"removing {name}: {cleanup_error}")

    if primary is not None:
        if cleanup_errors:
            raise RuntimeError(
                f"{primary}; cleanup errors: {cleanup_errors}"
            ) from primary
        raise primary
    if cleanup_errors:
        raise RuntimeError(f"positive arm cleanup failed: {cleanup_errors}")
    assert gate_monotonic_ns is not None
    assert live_observed_ns is not None
    assert refresh_due_ns is not None
    assert refresh_observed_ns is not None
    assert signal_monotonic_ns is not None
    assert withdrawal_observed_ns is not None
    assert withdrawal_completed_ns is not None
    assert live_record is not None
    assert refresh_record is not None
    assert withdrawal_record is not None
    return {
        "scenario": scenario,
        "configured_ttl_ns": PUBLICATION_TTL_SECONDS * 1_000_000_000,
        "configured_refresh_interval_ns": PUBLICATION_REFRESH_SECONDS * 1_000_000_000,
        "startup_visibility_bound_ns": 10_000_000_000,
        "refresh_visibility_bound_ns": 5_000_000_000,
        "withdrawal_visibility_bound_ns": 5_000_000_000,
        "scheduler_grace_ns": 1_000_000_000,
        "gate_release_unix_ns": gate_unix_ns,
        "gate_release_monotonic_ns": gate_monotonic_ns,
        "live_observed_monotonic_ns": live_observed_ns,
        "startup_observed_elapsed_ns": live_observed_ns - gate_monotonic_ns,
        "refresh_due_monotonic_ns": refresh_due_ns,
        "refresh_observed_monotonic_ns": refresh_observed_ns,
        "refresh_observed_elapsed_ns": refresh_observed_ns - live_observed_ns,
        "refresh_after_due_ns": max(0, refresh_observed_ns - refresh_due_ns),
        "signal_unix_ns": signal_unix_ns,
        "signal_monotonic_ns": signal_monotonic_ns,
        "withdrawal_observed_monotonic_ns": withdrawal_observed_ns,
        "withdrawal_observed_elapsed_ns": withdrawal_observed_ns - signal_monotonic_ns,
        "withdrawal_completed_monotonic_ns": withdrawal_completed_ns,
        "withdrawal_completion_elapsed_ns": withdrawal_completed_ns
        - signal_monotonic_ns,
        "initial_sequence": live_record["sequence"],
        "initial_packet_sha256": live_record["packet_sha256"],
        "refresh_sequence": refresh_record["sequence"],
        "refresh_packet_sha256": refresh_record["packet_sha256"],
        "withdrawal_sequence": withdrawal_record["sequence"],
        "withdrawal_packet_sha256": withdrawal_record["packet_sha256"],
        "publisher_exit_code": publisher_exit,
        "capture_exit_code": capture_exit,
        "authority_exit_code": authority_exit,
        "captured_in_scope_packet_count": packet_count,
        "authority_request_count": requests,
    }


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def command_plan(
    config: RunConfig, topology: Topology | None = None
) -> dict[str, object]:
    """Return the non-secret, inspectable execution plan used by dry-run."""
    topology = topology or make_topology("dryrun-00000000")
    scratch = Path("/tmp/nix-p2p-task137-dry-run")
    commands = {
        "image_preflight": image_preflight_command(config, topology),
        "networks": network_commands(config, topology),
        "router": router_commands(config, topology),
        "authority": authority_command(
            config, topology, scratch / "authority", "a" * 64
        ),
        "publisher_default_off": publisher_command(
            config,
            topology,
            "default-off",
            scratch / "publisher",
            scratch / "control-default-off",
            publication_enabled=False,
            offline=False,
        ),
        "publisher_offline_enabled": publisher_command(
            config,
            topology,
            "offline-enabled",
            scratch / "publisher",
            scratch / "control-offline-enabled",
            publication_enabled=True,
            offline=True,
        ),
        "publisher_offline_disabled": publisher_command(
            config,
            topology,
            "offline-disabled",
            scratch / "publisher",
            scratch / "control-offline-disabled",
            publication_enabled=False,
            offline=True,
        ),
        "publisher_live": publisher_command(
            config,
            topology,
            "live",
            scratch / "publisher",
            scratch / "control-live",
            publication_enabled=True,
            offline=False,
        ),
        "capture_live": capture_command(config, topology, "live", scratch / "evidence"),
        "pcap_read_live": pcap_read_command(
            config, topology, "live", scratch / "evidence"
        ),
    }
    cleanup = [
        {
            "kind": target.kind,
            "name": target.name,
            "exists": list(target.exists),
            "label": list(target.label),
            "remove": list(target.remove),
        }
        for target in cleanup_targets(config, topology)
    ]
    return {
        "schema": SCHEMA,
        "config": {
            "output": str(config.output),
            "image": config.image,
            "podman": config.podman,
            "namespace": config.namespace,
            "recipient": config.recipient,
            "authority_host": config.authority_host,
            "owner": config.owner,
        },
        "topology": {
            "run_id": topology.run_id,
            "label": topology.label,
            "publication_network": topology.publication_network,
            "authority_network": topology.authority_network,
            "publication_subnet": str(topology.publication_subnet),
            "authority_subnet": str(topology.authority_subnet),
            "publisher_ip": str(topology.publisher_ip),
            "router_publication_ip": str(topology.router_publication_ip),
            "authority_ip": str(topology.authority_ip),
            "router_authority_ip": str(topology.router_authority_ip),
        },
        "commands": commands,
        "cleanup": cleanup,
    }


def self_test() -> None:
    config = RunConfig(Path("evidence"), "example.invalid/nix-p2p:test")
    topology = make_topology("selftest-00000001")
    encoded = canonical_json(command_plan(config, topology))
    assert encoded == canonical_json(json.loads(encoded))
    validate_immutable_image_reference(
        "localhost/nix-p2p-iroh-publication-evidence:0123456789abcdefghijklmnopqrstuv"
    )
    try:
        validate_immutable_image_reference(
            "localhost/nix-p2p-iroh-publication-evidence:latest"
        )
    except RuntimeError:
        pass
    else:
        raise AssertionError(
            "mutable :latest image reference was accepted for live evidence"
        )
    clean_revision = "a" * 40
    dirty_revision = f"{'b' * 40}-dirty"
    assert validate_image_implementation_revision(clean_revision) == clean_revision
    assert validate_image_implementation_revision(dirty_revision) == dirty_revision
    assert (
        image_implementation_revision(
            {"Labels": {IMAGE_REVISION_LABEL: clean_revision}}
        )
        == clean_revision
    )
    assert (
        image_implementation_revision(
            {
                "Labels": {IMAGE_REVISION_LABEL: clean_revision},
                "Config": {"Labels": {IMAGE_REVISION_LABEL: clean_revision}},
            }
        )
        == clean_revision
    )
    for malformed in (
        {},
        {"Labels": {IMAGE_REVISION_LABEL: "dirty"}},
        {
            "Labels": {IMAGE_REVISION_LABEL: clean_revision},
            "Config": {"Labels": {IMAGE_REVISION_LABEL: dirty_revision}},
        },
    ):
        try:
            image_implementation_revision(malformed)
        except CommandFailure:
            pass
        else:
            raise AssertionError(
                f"malformed image revision labels accepted: {malformed}"
            )

    assert make_topology(topology.run_id) == topology
    occupied = (topology.publication_subnet, topology.authority_subnet)
    moved = make_topology(topology.run_id, occupied)
    assert not moved.publication_subnet.overlaps(topology.publication_subnet)
    assert not moved.authority_subnet.overlaps(topology.authority_subnet)
    try:
        make_topology("unsafe/UPPER")
    except RuntimeError:
        pass
    else:
        raise AssertionError("unsafe run id was accepted")

    plan = command_plan(config, topology)
    commands = plan["commands"]
    assert isinstance(commands, dict)
    serialized_commands = canonical_json(commands)
    assert b"--pod" not in serialized_commands
    assert topology.publication_network in commands["publisher_live"]
    assert topology.authority_network not in commands["publisher_live"]
    assert topology.authority_network in commands["authority"]
    assert topology.publication_network not in commands["authority"]
    assert "net.ipv4.ip_forward=1" in commands["router"][0]
    assert topology.authority_network in commands["router"][1]
    for network in commands["networks"]:
        assert "--internal" in network and "--disable-dns" in network
    assert "--iroh-publish-node" not in commands["publisher_default_off"]
    assert "--iroh-publish-node" not in commands["publisher_offline_disabled"]
    assert "--iroh-publish-node" in commands["publisher_live"]
    assert "offline-test" in commands["publisher_offline_enabled"]
    assert "/bin/iroh-node-authority" in commands["authority"]
    assert "/bin/iroh_node_authority" not in commands["authority"]
    authority_route = commands["authority"].index("evidence-authority")
    assert commands["authority"][authority_route + 1 : authority_route + 3] == [
        str(topology.publication_subnet),
        str(topology.router_authority_ip),
    ]
    publisher_route = commands["publisher_live"].index("evidence-publisher")
    assert commands["publisher_live"][publisher_route + 1 : publisher_route + 3] == [
        str(topology.authority_subnet),
        str(topology.router_publication_ip),
    ]
    publisher_gate = commands["publisher_live"][
        commands["publisher_live"].index("-euc") + 1
    ]
    assert "trap 'exit 143' TERM" in publisher_gate
    assert "trap 'exit 130' INT" in publisher_gate
    authority_listen = commands["authority"].index("--listen")
    assert commands["authority"][authority_listen + 1] == (
        f"{topology.authority_ip}:{AUTHORITY_PORT}"
    )
    recipient = commands["publisher_live"].index("--iroh-publication-authority-socket")
    assert commands["publisher_live"][recipient + 1] == (
        f"{topology.authority_ip}:{AUTHORITY_PORT}"
    )
    published = commands["publisher_live"].index("--iroh-publication-address")
    assert commands["publisher_live"][published + 1] == (
        f"{topology.publisher_ip}:{IROH_PORT}"
    )
    assert b"--iroh-publication-relay" not in serialized_commands
    assert f"container:{topology.publisher('live')}" in commands["capture_live"]
    immediate_mode = commands["capture_live"].index("--immediate-mode")
    assert commands["capture_live"].count("--immediate-mode") == 1
    assert commands["capture_live"][immediate_mode - 1] == "-U"
    observed_capture_filter = commands["capture_live"][-1]
    assert observed_capture_filter == capture_filter(topology)
    assert str(topology.authority_ip) in observed_capture_filter
    assert "tcp port 18080" in observed_capture_filter
    assert (
        "udp port 53" in observed_capture_filter
        and "tcp port 53" in observed_capture_filter
    )

    for argv in (*commands["networks"], commands["router"][0], commands["authority"]):
        assert "--label" in argv and topology.label in argv
    cleanup = cleanup_targets(config, topology)
    expected_names = set(topology.container_names()) | set(topology.network_names())
    assert {target.name for target in cleanup} == expected_names
    assert [target.name for target in cleanup[:4]] == [
        topology.analyzer("default-off"),
        topology.analyzer("offline-disabled"),
        topology.analyzer("offline-enabled"),
        topology.analyzer("live"),
    ]
    assert [target.name for target in cleanup[4:8]] == [
        topology.capture("default-off"),
        topology.capture("offline-disabled"),
        topology.capture("offline-enabled"),
        topology.capture("live"),
    ]
    assert [target.name for target in cleanup[-4:]] == [
        topology.authority,
        topology.router,
        topology.authority_network,
        topology.publication_network,
    ]
    for target in cleanup:
        assert target.name.startswith(f"{NAME_PREFIX}-{topology.run_id}-")
        assert target.remove[-1] == target.name
        assert "--all" not in target.remove and "--latest" not in target.remove
        assert LABEL_KEY in " ".join(target.label)
        validate_cleanup_target(target, topology)
    try:
        validate_cleanup_target(replace(cleanup[0], name="foreign-container"), topology)
    except CommandFailure:
        pass
    else:
        raise AssertionError("cleanup accepted a mutated resource name")
    try:
        validate_cleanup_label(cleanup[0], topology, "another-run")
    except CommandFailure:
        pass
    else:
        raise AssertionError("cleanup accepted a mutated run label")

    runner = Runner()
    success = runner.run([sys.executable, "-c", "print('ok')"])
    assert success.stdout == b"ok\n"
    allowed_failure = runner.run(
        [sys.executable, "-c", "raise SystemExit(7)"], check=False
    )
    assert allowed_failure.returncode == 7
    try:
        runner.run([sys.executable, "-c", "raise SystemExit(7)"])
    except CommandFailure:
        pass
    else:
        raise AssertionError("Runner allowed a failing checked command")

    class SplitLogRunner:
        def run(self, argv: list[str]) -> subprocess.CompletedProcess[bytes]:
            assert argv == ["podman", "logs", "sample"]
            return subprocess.CompletedProcess(argv, 0, b"stdout\n", b"stderr\n")

    assert container_logs(SplitLogRunner(), "podman", "sample") == (b"stdout\nstderr\n")

    class PcapReadRunner:
        def __init__(self, packet_count: int) -> None:
            self.packet_count = packet_count

        def run(self, argv: list[str]) -> subprocess.CompletedProcess[bytes]:
            assert "/bin/tcpdump" in argv and "-r" in argv
            stdout = b"".join(
                f"packet-{index}\n".encode() for index in range(self.packet_count)
            )
            return subprocess.CompletedProcess(argv, 0, stdout, b"")

    complete_capture_log = (
        b"tcpdump: listening on any\n"
        b"3 packets captured\n"
        b"3 packets received by filter\n"
        b"0 packets dropped by kernel\n"
    )
    assert parse_tcpdump_shutdown_stats(complete_capture_log) == TcpdumpShutdownStats(
        captured=3,
        received_by_filter=3,
        dropped_by_kernel=0,
    )

    def exercise_capture_validation(
        case: str, capture_log: bytes, decoded_packet_count: int
    ) -> int:
        with tempfile.TemporaryDirectory(prefix=f"task137-capture-{case}-") as raw:
            evidence = Path(raw)
            scenario = f"selftest-{case}"
            (evidence / f"{scenario}.pcap").write_bytes(b"\xd4\xc3\xb2\xa1" + bytes(20))
            return analyze_pcap(
                PcapReadRunner(decoded_packet_count),
                config,
                topology,
                scenario,
                evidence,
                capture_log,
            )

    assert exercise_capture_validation("complete", complete_capture_log, 3) == 3
    incomplete_capture_cases = (
        (
            "receive-mismatch",
            b"2 packets captured\n3 packets received by filter\n"
            b"0 packets dropped by kernel\n",
            2,
        ),
        (
            "kernel-drop",
            b"3 packets captured\n3 packets received by filter\n"
            b"1 packets dropped by kernel\n",
            3,
        ),
        (
            "pcap-mismatch",
            complete_capture_log,
            2,
        ),
        (
            "missing-shutdown-stats",
            b"tcpdump: listening on any\n",
            3,
        ),
        (
            "duplicate-shutdown-stats",
            complete_capture_log + complete_capture_log,
            3,
        ),
    )
    for case, capture_log, decoded_packet_count in incomplete_capture_cases:
        try:
            exercise_capture_validation(case, capture_log, decoded_packet_count)
        except RuntimeError:
            pass
        else:
            raise AssertionError(f"incomplete tcpdump capture {case!r} was accepted")

    sample_node = "1" * 64
    assert (
        exact_node_id(
            f"IROH-PROVIDER-ADDR node_id={sample_node} sockets=127.0.0.1:1\n".encode()
        )
        == sample_node
    )
    try:
        exact_node_id(b"no identity here")
    except RuntimeError:
        pass
    else:
        raise AssertionError("missing bootstrap NodeId was accepted")
    assert (
        authority_request_count(
            b"iroh_node_authority_stopped signal=sigterm requests=0\n"
        )
        == 0
    )
    assert PUBLICATION_TTL_SECONDS == 12
    assert PUBLICATION_REFRESH_SECONDS == 4
    assert signer_z32("00" * 32) == "y" * 52

    def dns_name(name: str) -> bytes:
        wire = bytearray()
        for label in name.split("."):
            encoded_label = label.encode("ascii")
            wire.append(len(encoded_label))
            wire.extend(encoded_label)
        wire.append(0)
        return bytes(wire)

    def txt_answer(name: str, value: str) -> bytes:
        encoded = value.encode()
        return (
            dns_name(name)
            + (16).to_bytes(2, "big")
            + (1).to_bytes(2, "big")
            + PUBLICATION_TTL_SECONDS.to_bytes(4, "big")
            + (len(encoded) + 1).to_bytes(2, "big")
            + bytes([len(encoded)])
            + encoded
        )

    sequence = 1_000_000
    expires = sequence + PUBLICATION_TTL_SECONDS * 1_000_000
    signer = signer_z32(sample_node)
    expected_address = "10.224.1.10:44330"
    values = [f"addr={expected_address}"] + [
        "schema=iroh-node-publication-v1",
        "namespace=selftest-00000001",
        f"signer={signer}",
        f"node-id={sample_node}",
        "recipient=task137-authority:v1",
        f"ttl-seconds={PUBLICATION_TTL_SECONDS}",
        f"sequence={sequence}",
        f"expires-unix-micros={expires}",
        "state=live",
    ]
    answers = [txt_answer(f"_iroh.{signer}", values[0])] + [
        txt_answer(f"_nix-p2p-iroh.{signer}", value) for value in values[1:]
    ]
    dns = (
        b"\x00\x00\x80\x00"
        + (0).to_bytes(2, "big")
        + len(answers).to_bytes(2, "big")
        + (0).to_bytes(2, "big")
        + (0).to_bytes(2, "big")
        + b"".join(answers)
    )
    synthetic_packet = (
        bytes.fromhex(sample_node) + bytes(64) + sequence.to_bytes(8, "big") + dns
    )
    decoded = decode_signed_node_packet(synthetic_packet)
    assert decoded["node_id"] == sample_node
    assert decoded["sequence"] == sequence
    assert decoded["locations"] == [f"addr={expected_address}"]

    with tempfile.TemporaryDirectory(prefix="task137-selftest-") as state_raw:
        state_dir = Path(state_raw)
        state = {
            "body": {
                "schema_version": 1,
                "namespace": "selftest-00000001",
                "signed_recipient": "task137-authority:v1",
                "signer_admission_blake3_hex": "0" * 64,
                "wall_clock_high_water_unix_micros": sequence,
                "records": {
                    signer: {
                        "high_water_sequence": sequence,
                        "expires_unix_micros": expires,
                        "state": "live",
                        "expired": False,
                        "packet_hex": synthetic_packet.hex(),
                    }
                },
            },
            "checksum_blake3_hex": "0" * 64,
        }
        (state_dir / "iroh-node-publication-authority.json").write_bytes(
            canonical_json(state)
        )
        strict = read_strict_authority_snapshot(
            state_dir,
            node_id=sample_node,
            namespace="selftest-00000001",
            recipient="task137-authority:v1",
            expected_address=expected_address,
        )
        assert strict is not None and strict[0]["state"] == "live"
        try:
            read_strict_authority_snapshot(
                state_dir,
                node_id=sample_node,
                namespace="selftest-00000001",
                recipient="task137-authority:v1",
                expected_address="0.0.0.0:44330",
            )
        except RuntimeError:
            pass
        else:
            raise AssertionError("strict snapshot accepted a wildcard/address mutation")


def run_live(config: RunConfig) -> None:
    runner = Runner()
    image_identity = immutable_image_identity(runner, config)

    run_id = new_run_id()
    topology = make_topology(run_id, occupied_ipv4_networks(runner, config.podman))
    output_root = config.output.expanduser().resolve()
    output_root.mkdir(mode=0o755, parents=True, exist_ok=True)
    output = output_root / run_id
    output.mkdir(mode=0o755, exist_ok=False)
    timing: dict[str, object] = {
        "schema": SCHEMA,
        "run_id": run_id,
        "status": "running-controls",
        "evidence_profile": "production-shaped-local",
        "image": image_identity,
        "authority": {
            "kind": "local-routed-pkarr-relay",
            "namespace": f"{config.namespace}-{topology.run_id}",
            "recipient": config.recipient,
            "expected_host": config.authority_host,
            "socket": f"{topology.authority_ip}:{AUTHORITY_PORT}",
            "owner": config.owner,
            "external_contact_authorized": False,
        },
        "publication": {
            "record_schema": "iroh-node-publication-v1",
            "published_address": f"{topology.publisher_ip}:{IROH_PORT}",
            "ttl_ns": PUBLICATION_TTL_SECONDS * 1_000_000_000,
            "refresh_interval_ns": PUBLICATION_REFRESH_SECONDS * 1_000_000_000,
        },
        "capture": {
            "scope": CAPTURE_SCOPE,
            "interface": CAPTURE_INTERFACE,
            "bpf_filter": capture_filter(topology),
            "count_semantics": CAPTURE_COUNT_SEMANTICS,
        },
        "topology": {
            "kind": "two-internal-networks-explicit-l3-router",
            "network_count": 2,
            "publication_network_internal": True,
            "authority_network_internal": True,
            "publication_network": topology.publication_network,
            "authority_network": topology.authority_network,
            "publication_subnet": str(topology.publication_subnet),
            "authority_subnet": str(topology.authority_subnet),
            "publisher_ip": str(topology.publisher_ip),
            "router_publication_ip": str(topology.router_publication_ip),
            "authority_ip": str(topology.authority_ip),
            "router_authority_ip": str(topology.router_authority_ip),
            "dns_enabled": False,
        },
        "observations": [],
    }
    primary: BaseException | None = None
    cleanup_error: Exception | None = None

    with tempfile.TemporaryDirectory(
        prefix=f"{topology.resource_prefix}-"
    ) as scratch_raw:
        scratch = Path(scratch_raw)
        publisher_state = scratch / "publisher-state"
        create_private_directory(publisher_state)
        try:
            preflight_identity = verify_image(runner, config, topology)
            if preflight_identity != image_identity:
                raise RuntimeError("evidence image identity changed during preflight")
            for command in network_commands(config, topology):
                runner.run(command)
            for command in router_commands(config, topology):
                runner.run(command)
            router_running, _ = container_state(runner, config.podman, topology.router)
            if not router_running:
                raise RuntimeError("explicit L3 router did not remain running")

            node_id, bootstrap = bootstrap_node_id(
                runner,
                config,
                topology,
                publisher_state,
                scratch,
                output,
            )
            timing["node_id"] = node_id
            observations = timing["observations"]
            assert isinstance(observations, list)
            observations.append(bootstrap)
            for specification in (
                {
                    "scenario": "default-off",
                    "publication_enabled": False,
                    "offline": False,
                    "expect_fail_closed": False,
                },
                {
                    "scenario": "offline-disabled",
                    "publication_enabled": False,
                    "offline": True,
                    "expect_fail_closed": False,
                },
                {
                    "scenario": "offline-enabled",
                    "publication_enabled": True,
                    "offline": True,
                    "expect_fail_closed": True,
                },
            ):
                observations.append(
                    run_zero_control(
                        runner,
                        config,
                        topology,
                        node_id,
                        publisher_state,
                        scratch,
                        output,
                        **specification,
                    )
                )
            observations.append(
                run_positive_arm(
                    runner,
                    config,
                    topology,
                    node_id,
                    publisher_state,
                    scratch,
                    output,
                )
            )
            if immutable_image_identity(runner, config) != image_identity:
                raise RuntimeError("evidence image identity changed during the run")
            timing["status"] = "pass"
        except BaseException as caught:
            primary = caught
            timing["status"] = "failed"
            timing["failure"] = str(caught)
        finally:
            try:
                cleanup_exact(runner, config, topology)
                timing["cleanup"] = "pass"
            except Exception as caught:
                cleanup_error = caught
                timing["cleanup"] = "failed"
                timing["cleanup_failure"] = str(caught)

    write_new(output / "timings.json", canonical_json(timing))
    if primary is not None:
        if cleanup_error is not None:
            raise RuntimeError(
                f"{primary}; exact cleanup also failed: {cleanup_error}"
            ) from primary
        raise primary
    if cleanup_error is not None:
        raise cleanup_error
    print(f"iroh-node-publication routed evidence: PASS output={output}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path, default=Path("artifacts/iroh-publication")
    )
    parser.add_argument("--image", default="nix-p2p-iroh-publication-evidence:latest")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    config = RunConfig(args.output, args.image)
    if args.self_test:
        self_test()
        print("iroh-node-publication evidence self-test: PASS")
        return 0
    if args.dry_run:
        print(canonical_json(command_plan(config)).decode(), end="")
        return 0
    try:
        run_live(config)
    except RuntimeError as error:
        print(f"iroh-node-publication evidence: FATAL - {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
