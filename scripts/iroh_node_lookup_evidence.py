#!/usr/bin/env python3
"""Capture routed, namespace-isolated evidence for Iroh NodeId lookup.

The resolver and authority live on different rootless-Podman internal networks
with DNS disabled.  A deliberately tiny L3 router is the only route between
them. tcpdump joins the resolver network namespace and captures every TCP or
UDP packet, so the finalizer can reject DNS, relay, content, publication, or any
destination other than the pinned authority. Autonomous kernel ICMP/IGMP/MLD
network convergence is explicitly outside this product-transport scope.

The positive, empty-namespace, and withdrawal arms use the production Task137
authority/publisher. The feature-gated fixture is used only for records a
correct authority will not store (bad signature, replay, expiry, live-empty)
and a bounded hanging peer.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import secrets
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn

import iroh_node_publication_evidence as publication
import blake3


SCHEMA = "iroh-node-lookup-evidence-v1"
MANIFEST_SCHEMA = "iroh-node-lookup-raw-evidence-manifest-v1"
LABEL_KEY = "org.nix-p2p.iroh-lookup-evidence-run"
IMAGE_REVISION_LABEL = publication.IMAGE_REVISION_LABEL
NAME_PREFIX = "nix-p2p-task138"
SUBNET_POOL = ipaddress.ip_network("10.192.0.0/11")
SUBNET_PREFIX = 24
AUTHORITY_PORT = 18080
IROH_PORT = 44330
DAEMON_HTTP_PORT = 8082
REAL_RECORD_TTL_SECONDS = 120
REAL_RECORD_REFRESH_SECONDS = 60
CAPTURE_FILTER = "tcp or udp"
CAPTURE_INTERFACE = "any"
DEADLINE_NS = 10_000_000_000
OBSERVER_GRACE_NS = 1_000_000_000
RUN_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{7,47}$")
NODE_ID_RE = re.compile(r"^[0-9a-f]{64}$")
FIXTURE_READY_RE = re.compile(
    r"iroh_node_lookup_fixture_ready scenario=([a-z-]+) "
    r"listen=\S+ node_id=([0-9a-f]{64}) signer=([a-z0-9]+) requests=(\d+)"
)
AUTHORITY_READY_RE = re.compile(r"iroh_node_authority_ready\b")
PUBLICATION_LIVE_RE = re.compile(r"IROH-NODE-PUBLICATION state=Live\b")
PROVIDER_NODE_RE = re.compile(r"IROH-PROVIDER-ADDR node_id=([0-9a-f]{64})\b")

REAL_EXPECTATIONS = {
    "not-found": (1, "empty_namespace"),
    "withdrawal": (1, "withdrawn"),
}
FIXTURE_EXPECTATIONS = {
    "hanging": (1, "deadline"),
    "bad-signature": (1, "bad_signature"),
    "stale": (2, "stale_sequence"),
    "equal-conflict": (2, "conflicting_replay"),
    "expired": (1, "expired"),
    "live-empty": (1, "no_dialable_candidate"),
}
UNAVAILABLE_EXPECTATIONS = {**REAL_EXPECTATIONS, **FIXTURE_EXPECTATIONS}
CONTROL_SCENARIOS = ("default-off", "offline-disabled", "offline-enabled")


class EvidenceFailure(RuntimeError):
    """The run is invalid or an assertion failed."""


def fail(message: str) -> NoReturn:
    raise EvidenceFailure(message)


@dataclass(frozen=True)
class RunConfig:
    output: Path
    image: str
    podman: str = "podman"
    namespace: str = "task138-evidence"
    recipient: str = "task138-authority:v1"
    authority_host: str = "task138-authority.invalid"
    owner: str = "nix-p2p-task138-evidence"


@dataclass(frozen=True)
class Topology:
    run_id: str
    resolver_network: str
    authority_network: str
    router: str
    resolver_subnet: ipaddress.IPv4Network
    authority_subnet: ipaddress.IPv4Network
    resolver_ip: ipaddress.IPv4Address
    router_resolver_ip: ipaddress.IPv4Address
    authority_ip: ipaddress.IPv4Address
    router_authority_ip: ipaddress.IPv4Address
    publisher_ip: ipaddress.IPv4Address

    @property
    def label(self) -> str:
        return f"{LABEL_KEY}={self.run_id}"

    @property
    def prefix(self) -> str:
        return f"{NAME_PREFIX}-{self.run_id}"

    @property
    def authority(self) -> str:
        return f"{self.prefix}-authority"

    @property
    def publisher(self) -> str:
        return f"{self.prefix}-publisher"

    @property
    def bootstrap(self) -> str:
        return f"{self.prefix}-bootstrap"

    @property
    def preflight(self) -> str:
        return f"{self.prefix}-preflight"

    def resolver(self, scenario: str) -> str:
        return f"{self.prefix}-resolver-{scenario}"

    def capture(self, scenario: str) -> str:
        return f"{self.prefix}-capture-{scenario}"

    def fixture(self, scenario: str) -> str:
        return f"{self.prefix}-fixture-{scenario}"

    def analyzer(self, scenario: str) -> str:
        return f"{self.prefix}-analyzer-{scenario}"

    def networks(self) -> tuple[str, str]:
        return self.resolver_network, self.authority_network

    def containers(self) -> tuple[str, ...]:
        scenarios = (
            *CONTROL_SCENARIOS,
            "live",
            *REAL_EXPECTATIONS,
            *FIXTURE_EXPECTATIONS,
            "refused",
        )
        per_scenario = tuple(
            name
            for scenario in scenarios
            for name in (
                self.analyzer(scenario),
                self.capture(scenario),
                self.resolver(scenario),
                self.fixture(scenario),
            )
        )
        return (
            *per_scenario,
            self.publisher,
            self.bootstrap,
            self.authority,
            self.preflight,
            self.router,
        )


Runner = publication.Runner
CommandFailure = publication.CommandFailure


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def write_new(path: Path, data: bytes) -> None:
    if path.exists() or path.is_symlink():
        fail(f"refusing to overwrite evidence path {path}")
    path.write_bytes(data)


def create_private_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=False)
    path.chmod(0o700)


def new_run_id() -> str:
    return f"r{os.getpid():x}-{secrets.token_hex(6)}"


def choose_subnets(
    run_id: str, occupied: tuple[ipaddress.IPv4Network, ...] = ()
) -> tuple[ipaddress.IPv4Network, ipaddress.IPv4Network]:
    if RUN_ID_RE.fullmatch(run_id) is None:
        fail(f"run id {run_id!r} is not a canonical lower-case resource token")
    candidates = tuple(SUBNET_POOL.subnets(new_prefix=SUBNET_PREFIX))
    start = int.from_bytes(hashlib.sha256(run_id.encode()).digest()[:4], "big") % len(
        candidates
    )
    selected: list[ipaddress.IPv4Network] = []
    for offset in range(len(candidates)):
        candidate = candidates[(start + offset) % len(candidates)]
        if any(candidate.overlaps(other) for other in (*occupied, *selected)):
            continue
        selected.append(candidate)
        if len(selected) == 2:
            return selected[0], selected[1]
    fail(f"no two free /{SUBNET_PREFIX} networks remain in {SUBNET_POOL}")


def make_topology(
    run_id: str, occupied: tuple[ipaddress.IPv4Network, ...] = ()
) -> Topology:
    resolver_subnet, authority_subnet = choose_subnets(run_id, occupied)
    prefix = f"{NAME_PREFIX}-{run_id}"
    return Topology(
        run_id=run_id,
        resolver_network=f"{prefix}-resolver-net",
        authority_network=f"{prefix}-authority-net",
        router=f"{prefix}-router",
        resolver_subnet=resolver_subnet,
        authority_subnet=authority_subnet,
        resolver_ip=resolver_subnet.network_address + 10,
        router_resolver_ip=resolver_subnet.network_address + 20,
        authority_ip=authority_subnet.network_address + 10,
        router_authority_ip=authority_subnet.network_address + 20,
        publisher_ip=authority_subnet.network_address + 30,
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
            (topology.resolver_network, topology.resolver_subnet),
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
            topology.resolver_network,
            "--ip",
            str(topology.router_resolver_ip),
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


def routed_container_prefix(
    config: RunConfig,
    topology: Topology,
    *,
    name: str,
    network: str,
    address: ipaddress.IPv4Address,
) -> list[str]:
    return [
        config.podman,
        "run",
        "--detach",
        "--name",
        name,
        "--label",
        topology.label,
        "--cap-add",
        "NET_ADMIN",
        "--network",
        network,
        "--ip",
        str(address),
    ]


def route_wrapper(remote: object, router: object) -> list[str]:
    return [
        "/bin/bash",
        "-euc",
        'remote="$1"; router="$2"; shift 2; '
        'ip route add "$remote" via "$router"; exec "$@"',
        "lookup-evidence-route",
        str(remote),
        str(router),
    ]


def authority_command(
    config: RunConfig, topology: Topology, state_dir: Path, node_id: str
) -> list[str]:
    if NODE_ID_RE.fullmatch(node_id) is None:
        fail("authority admission requires one canonical NodeId")
    return [
        *routed_container_prefix(
            config,
            topology,
            name=topology.authority,
            network=topology.authority_network,
            address=topology.authority_ip,
        ),
        "--volume",
        f"{state_dir.resolve()}:/state:Z",
        config.image,
        *route_wrapper(topology.resolver_subnet, topology.router_authority_ip),
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
        node_id,
    ]


def publisher_command(
    config: RunConfig,
    topology: Topology,
    state_dir: Path,
    *,
    name: str,
    publication_enabled: bool,
    ttl_seconds: int = REAL_RECORD_TTL_SECONDS,
    refresh_seconds: int = REAL_RECORD_REFRESH_SECONDS,
) -> list[str]:
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
        f"lan:{topology.publisher_ip}",
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
                str(ttl_seconds),
                "--iroh-publication-refresh-seconds",
                str(refresh_seconds),
            ]
        )
    return [
        *routed_container_prefix(
            config,
            topology,
            name=name,
            network=topology.authority_network,
            address=topology.publisher_ip,
        ),
        "--volume",
        f"{state_dir.resolve()}:/state:Z",
        config.image,
        *route_wrapper(topology.resolver_subnet, topology.router_authority_ip),
        *daemon_args,
    ]


def fixture_command(
    config: RunConfig,
    topology: Topology,
    scenario: str,
    image_revision: str,
) -> list[str]:
    if scenario not in FIXTURE_EXPECTATIONS:
        fail(f"fixture scenario {scenario!r} is not closed over the evidence matrix")
    return [
        *routed_container_prefix(
            config,
            topology,
            name=topology.fixture(scenario),
            network=topology.authority_network,
            address=topology.authority_ip,
        ),
        config.image,
        *route_wrapper(topology.resolver_subnet, topology.router_authority_ip),
        "/bin/iroh-node-lookup-fixture",
        "--listen",
        f"{topology.authority_ip}:{AUTHORITY_PORT}",
        "--namespace",
        f"{config.namespace}-{topology.run_id}",
        "--recipient",
        config.recipient,
        "--expected-host",
        config.authority_host,
        "--scenario",
        scenario,
        "--run-id",
        topology.run_id,
        "--owner",
        config.owner,
        "--image-revision",
        image_revision,
    ]


def inert_refusal_command(config: RunConfig, topology: Topology) -> list[str]:
    """Run a no-listener authority-IP owner whose PID 1 handles shutdown."""

    return [
        *routed_container_prefix(
            config,
            topology,
            name=topology.fixture("refused"),
            network=topology.authority_network,
            address=topology.authority_ip,
        ),
        config.image,
        *route_wrapper(topology.resolver_subnet, topology.router_authority_ip),
        "/bin/bash",
        "-euc",
        'child=; trap \'test -z "$child" || '
        'kill "$child" 2>/dev/null || true; exit 0\' TERM INT; '
        'while :; do /bin/sleep 3600 & child=$!; wait "$child" || true; done',
    ]


def resolver_command(
    config: RunConfig,
    topology: Topology,
    scenario: str,
    node_id: str,
    attempts: int,
    state_dir: Path,
    control_dir: Path,
) -> list[str]:
    if NODE_ID_RE.fullmatch(node_id) is None or attempts not in (1, 2):
        fail("resolver evidence accepts one canonical NodeId and one or two attempts")
    return [
        *routed_container_prefix(
            config,
            topology,
            name=topology.resolver(scenario),
            network=topology.resolver_network,
            address=topology.resolver_ip,
        ),
        "--volume",
        f"{state_dir.resolve()}:/state:Z",
        "--volume",
        f"{control_dir.resolve()}:/control:ro,Z",
        config.image,
        "/bin/bash",
        "-euc",
        'remote="$1"; router="$2"; shift 2; '
        'ip route add "$remote" via "$router"; '
        'while test ! -e /control/start; do sleep 0.02; done; exec "$@"',
        "lookup-evidence-resolver",
        str(topology.authority_subnet),
        str(topology.router_resolver_ip),
        "/bin/iroh-node-lookup",
        "--node-id",
        node_id,
        "--attempts",
        str(attempts),
        "--state-dir",
        "/state",
        "--iroh-port",
        str(IROH_PORT),
        "--namespace",
        f"{config.namespace}-{topology.run_id}",
        "--recipient",
        config.recipient,
        "--authority-socket",
        f"{topology.authority_ip}:{AUTHORITY_PORT}",
        "--authority-host",
        config.authority_host,
        "--owner",
        config.owner,
    ]


def control_command(
    config: RunConfig,
    topology: Topology,
    scenario: str,
    state_dir: Path,
    control_dir: Path,
) -> list[str]:
    if scenario not in CONTROL_SCENARIOS:
        fail(f"unknown zero-packet control {scenario!r}")
    offline = scenario != "default-off"
    lookup_enabled = scenario == "offline-enabled"
    daemon_args = [
        "/bin/daemon",
        "--listen",
        f"0.0.0.0:{DAEMON_HTTP_PORT}",
        "--upstream",
        "http://127.0.0.1:9",
        "--iroh-provider",
        "--iroh-state-dir",
        "/state/iroh",
        "--iroh-endpoint-scope",
        "offline-test" if offline else "global",
        "--iroh-port",
        str(IROH_PORT),
    ]
    if lookup_enabled:
        daemon_args.extend(
            [
                "--iroh-enable-node-lookup",
                "--iroh-lookup-namespace",
                f"{config.namespace}-{topology.run_id}",
                "--iroh-lookup-recipient",
                config.recipient,
                "--iroh-lookup-authority-socket",
                f"{topology.authority_ip}:{AUTHORITY_PORT}",
                "--iroh-lookup-authority-host",
                config.authority_host,
                "--iroh-lookup-owner",
                config.owner,
            ]
        )
    return [
        *routed_container_prefix(
            config,
            topology,
            name=topology.resolver(scenario),
            network=topology.resolver_network,
            address=topology.resolver_ip,
        ),
        "--volume",
        f"{state_dir.resolve()}:/state:Z",
        "--volume",
        f"{control_dir.resolve()}:/control:ro,Z",
        config.image,
        "/bin/bash",
        "-euc",
        'remote="$1"; router="$2"; shift 2; '
        'ip route add "$remote" via "$router"; '
        'while test ! -e /control/start; do sleep 0.02; done; exec "$@"',
        "lookup-evidence-zero-control",
        str(topology.authority_subnet),
        str(topology.router_resolver_ip),
        *daemon_args,
    ]


def capture_command(
    config: RunConfig, topology: Topology, scenario: str, output: Path
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
        f"container:{topology.resolver(scenario)}",
        "--volume",
        f"{output.resolve()}:/evidence:Z",
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


def pcap_read_command(
    config: RunConfig, topology: Topology, scenario: str, output: Path
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
        f"{output.resolve()}:/evidence:ro,Z",
        config.image,
        "/bin/tcpdump",
        "-nn",
        "-tt",
        "-r",
        f"/evidence/{scenario}.pcap",
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
        "test -x /bin/iroh-node-lookup; "
        "test -x /bin/iroh-node-lookup-fixture; "
        "test -x /bin/tcpdump; test -x /bin/ip",
    ]


def exact_targets(config: RunConfig, topology: Topology) -> list[tuple[str, str]]:
    return [
        *(("container", name) for name in topology.containers()),
        *(("network", name) for name in reversed(topology.networks())),
    ]


def cleanup_exact(runner: Runner, config: RunConfig, topology: Topology) -> None:
    for kind, name in exact_targets(config, topology):
        if name not in (*topology.containers(), *topology.networks()):
            fail(f"refusing cleanup of unregistered {kind} {name!r}")
        if kind == "container":
            exists = runner.run(
                [config.podman, "container", "exists", name], check=False
            )
            inspect = [
                config.podman,
                "inspect",
                "--format",
                f'{{{{ index .Config.Labels "{LABEL_KEY}" }}}}',
                name,
            ]
            remove = [config.podman, "rm", "--force", "--ignore", name]
        else:
            exists = runner.run([config.podman, "network", "exists", name], check=False)
            inspect = [
                config.podman,
                "network",
                "inspect",
                "--format",
                f'{{{{ index .Labels "{LABEL_KEY}" }}}}',
                name,
            ]
            remove = [config.podman, "network", "rm", name]
        if exists.returncode == 1:
            continue
        if exists.returncode != 0:
            fail(f"cannot establish whether {kind} {name!r} exists")
        observed = runner.run(inspect).stdout.decode().strip()
        if observed != topology.run_id:
            fail(
                f"refusing cleanup of {kind} {name!r}: label is {observed!r}, "
                f"expected {topology.run_id!r}"
            )
        runner.run(remove)


def cleanup_container(
    runner: Runner, config: RunConfig, topology: Topology, name: str
) -> None:
    if name not in topology.containers():
        fail(f"refusing cleanup of unregistered container {name!r}")
    exists = runner.run([config.podman, "container", "exists", name], check=False)
    if exists.returncode == 1:
        return
    if exists.returncode != 0:
        fail(f"cannot establish whether container {name!r} exists")
    observed = (
        runner.run(
            [
                config.podman,
                "inspect",
                "--format",
                f'{{{{ index .Config.Labels "{LABEL_KEY}" }}}}',
                name,
            ]
        )
        .stdout.decode()
        .strip()
    )
    if observed != topology.run_id:
        fail(f"refusing cleanup of container {name!r} with label {observed!r}")
    runner.run([config.podman, "rm", "--force", "--ignore", name])


def container_exists(runner: Runner, config: RunConfig, name: str) -> bool:
    result = runner.run([config.podman, "container", "exists", name], check=False)
    if result.returncode not in (0, 1):
        fail(f"cannot establish whether container {name!r} exists")
    return result.returncode == 0


def stop_container(
    runner: Runner,
    config: RunConfig,
    name: str,
    signal: str,
    *,
    timeout: float = 20.0,
) -> int:
    running, exit_code = publication.container_state(runner, config.podman, name)
    if not running:
        return exit_code
    return publication.signal_and_wait(runner, config.podman, name, signal, timeout)


def save_container_log(
    runner: Runner, config: RunConfig, name: str, path: Path
) -> bytes:
    log = publication.container_logs(runner, config.podman, name)
    write_new(path, log)
    return log


def parse_diagnostic(log: bytes) -> dict[str, object]:
    documents: list[dict[str, object]] = []
    for line in log.splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and value.get("schema") == "iroh-node-lookup-v1":
            documents.append(value)
    if len(documents) != 1:
        fail(f"resolver log contains {len(documents)} canonical lookup documents")
    return documents[0]


def parse_fixture_plan(
    log: bytes,
    *,
    config: RunConfig,
    topology: Topology,
    scenario: str,
    node_id: str,
    image_revision: str,
) -> dict[str, object]:
    plans: list[dict[str, object]] = []
    for line in log.splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and value.get("schema") == (
            "iroh-node-lookup-fixture-plan-v1"
        ):
            plans.append(value)
    if len(plans) != 1:
        fail(f"{scenario} fixture emitted {len(plans)} structured response plans")
    plan = plans[0]
    expected = {
        "run_id": topology.run_id,
        "owner": config.owner,
        "image_revision": image_revision,
        "namespace": f"{config.namespace}-{topology.run_id}",
        "recipient": config.recipient,
        "expected_host": config.authority_host,
        "scenario": scenario,
        "node_id": node_id,
    }
    for key, value in expected.items():
        if plan.get(key) != value:
            fail(f"{scenario} fixture plan {key} is not bound to this run")
    responses = plan.get("responses")
    expected_count = FIXTURE_EXPECTATIONS[scenario][0]
    if not isinstance(responses, list) or len(responses) != expected_count:
        fail(f"{scenario} fixture response plan cardinality is not exact")
    for ordinal, response in enumerate(responses, start=1):
        if not isinstance(response, dict) or response.get("ordinal") != ordinal:
            fail(f"{scenario} fixture response ordinal is not canonical")
        raw_hex = response.get("relay_payload_hex")
        digest = response.get("relay_payload_blake3_hex")
        size = response.get("relay_payload_bytes")
        if raw_hex is None:
            if scenario != "hanging" or digest is not None or size is not None:
                fail(f"{scenario} fixture omitted a non-hanging response payload")
            continue
        if not isinstance(raw_hex, str) or re.fullmatch(r"[0-9a-f]*", raw_hex) is None:
            fail(f"{scenario} fixture payload is not canonical lowercase hex")
        raw = bytes.fromhex(raw_hex)
        if size != len(raw) or digest != blake3.blake3(raw).hexdigest():
            fail(f"{scenario} fixture payload hash/size does not bind exact bytes")
    return plan


def validate_outcome(
    scenario: str,
    outcome: dict[str, object],
    *,
    node_id: str,
    expected_candidate: str | None = None,
) -> None:
    if outcome.get("node_id") != node_id or outcome.get("shutdown") != "graceful":
        fail(f"{scenario} did not retain the exact requested NodeId/graceful shutdown")
    attempts = outcome.get("attempts")
    if not isinstance(attempts, list):
        fail(f"{scenario} outcome has no bounded attempts array")
    expected_attempts = (
        1 if scenario in ("live", "refused") else UNAVAILABLE_EXPECTATIONS[scenario][0]
    )
    if (
        outcome.get("attempt_count") != expected_attempts
        or len(attempts) != expected_attempts
    ):
        fail(f"{scenario} attempt count is not exactly {expected_attempts}")
    for attempt in attempts:
        if not isinstance(attempt, dict):
            fail(f"{scenario} attempt is not an object")
        elapsed = attempt.get("elapsed_micros")
        if not isinstance(elapsed, int) or not 0 <= elapsed <= 11_000_000:
            fail(
                f"{scenario} lookup exceeded the 10s deadline plus scheduler grace: "
                f"{elapsed!r}us"
            )
    if scenario == "live":
        if outcome.get("verdict") != "pass":
            fail("positive production-authority lookup did not pass")
        attempt = attempts[0]
        required = {
            "verdict": "pass",
            "lookup_schema": "iroh-node-lookup-v1",
            "record_schema": "iroh-node-publication-v1",
            "source": "pinned-pkarr-http",
            "provenance": "network_validated",
            "node_id": node_id,
        }
        for key, value in required.items():
            if attempt.get(key) != value:
                fail(
                    f"positive lookup {key} is {attempt.get(key)!r}, expected {value!r}"
                )
        candidates = attempt.get("candidates")
        if candidates != [{"kind": "direct", "value": expected_candidate}]:
            fail(
                f"positive candidates are not the exact signed direct address: {candidates!r}"
            )
        return
    expected_reason = (
        "authority_connection_refused"
        if scenario == "refused"
        else UNAVAILABLE_EXPECTATIONS[scenario][1]
    )
    if outcome.get("verdict") != "unavailable":
        fail(f"{scenario} was mislabeled as a successful lookup")
    final = attempts[-1]
    if not isinstance(final, dict) or final.get("reason") != expected_reason:
        fail(f"{scenario} final reason is not {expected_reason!r}")
    for index, attempt in enumerate(attempts, start=1):
        if not isinstance(attempt, dict) or attempt.get("attempt") != index:
            fail(f"{scenario} attempt order is not exact")
    if scenario in ("stale", "equal-conflict", "expired", "withdrawal"):
        if (
            final.get("provenance") != "network_validated"
            or final.get("source") != "pinned-pkarr-http"
            or not isinstance(final.get("sequence"), int)
            or re.fullmatch(r"[0-9a-f]{64}", str(final.get("signed_packet_blake3_hex")))
            is None
        ):
            fail(f"{scenario} rejected packet lacks exact network provenance")
    if expected_attempts == 2:
        first = attempts[0]
        if (
            first.get("verdict") != "pass"
            or first.get("provenance") != "network_validated"
        ):
            fail(f"{scenario} first response lacks real network provenance")
    if scenario == "hanging":
        elapsed = final.get("elapsed_micros")
        if not isinstance(elapsed, int) or not 9_000_000 <= elapsed <= 11_000_000:
            fail(f"hanging lookup did not enforce the 10s deadline: {elapsed!r}us")


def run_zero_control(
    runner: Runner,
    config: RunConfig,
    topology: Topology,
    scratch: Path,
    output: Path,
    scenario: str,
) -> dict[str, object]:
    process = topology.resolver(scenario)
    capture = topology.capture(scenario)
    state_dir = scratch / f"control-state-{scenario}"
    control_dir = scratch / f"control-gate-{scenario}"
    create_private_directory(state_dir)
    create_private_directory(control_dir)
    runner.run(control_command(config, topology, scenario, state_dir, control_dir))
    runner.run(capture_command(config, topology, scenario, output))
    publication.wait_for_capture_ready(
        runner, config.podman, capture, output / f"{scenario}.pcap", 5.0
    )
    released_unix_ns = time.time_ns()
    released_monotonic_ns = time.monotonic_ns()
    (control_dir / "start").touch(mode=0o600)
    if scenario == "offline-enabled":
        process_exit = publication.wait_for_exit(runner, config.podman, process, 5.0)
        completed_monotonic_ns = time.monotonic_ns()
    else:
        publication.wait_for_log(
            runner,
            config.podman,
            process,
            re.compile(r"daemon: listening on\b"),
            15.0,
        )
        time.sleep(1.1)
        completed_monotonic_ns = time.monotonic_ns()
        process_exit = stop_container(runner, config, process, "TERM")
    capture_exit = stop_container(runner, config, capture, "INT")
    process_log = save_container_log(
        runner, config, process, output / f"{scenario}.control.log"
    )
    capture_log = save_container_log(
        runner, config, capture, output / f"{scenario}.capture.log"
    )
    result = runner.run(pcap_read_command(config, topology, scenario, output))
    write_new(output / f"{scenario}.packets.log", result.stdout)
    write_new(output / f"{scenario}.pcap-read.log", result.stderr)
    packet_count = sum(1 for line in result.stdout.splitlines() if line.strip())
    publication.validate_complete_capture(scenario, capture_log, packet_count)
    if packet_count != 0 or capture_exit != 0:
        fail(f"{scenario} emitted {packet_count} TCP/UDP packet(s) or lost capture")
    if scenario == "offline-enabled":
        if (
            process_exit != 1
            or b"offline-test rejects address-lookup capability injection"
            not in process_log
        ):
            fail("offline-enabled did not fail before endpoint/network activation")
    elif process_exit != 0:
        fail(f"{scenario} did not hold inert and shut down gracefully")
    for name in (capture, process):
        cleanup_container(runner, config, topology, name)
    return {
        "scenario": scenario,
        "lookup_enabled": scenario == "offline-enabled",
        "offline": scenario != "default-off",
        "expected_fail_closed": scenario == "offline-enabled",
        "gate_release_unix_ns": released_unix_ns,
        "gate_release_monotonic_ns": released_monotonic_ns,
        "process_completed_monotonic_ns": completed_monotonic_ns,
        "process_elapsed_ns": completed_monotonic_ns - released_monotonic_ns,
        "process_exit_code": process_exit,
        "capture_exit_code": capture_exit,
        "captured_transport_packet_count": packet_count,
        "outcome": "fail-before-bind"
        if scenario == "offline-enabled"
        else "inert-no-query",
    }


def capture_and_resolve(
    runner: Runner,
    config: RunConfig,
    topology: Topology,
    scratch: Path,
    output: Path,
    *,
    scenario: str,
    node_id: str,
    attempts: int,
    expected_candidate: str | None = None,
) -> tuple[dict[str, object], dict[str, object]]:
    resolver = topology.resolver(scenario)
    capture = topology.capture(scenario)
    resolver_state = scratch / f"resolver-state-{scenario}"
    control = scratch / f"resolver-control-{scenario}"
    create_private_directory(resolver_state)
    create_private_directory(control)
    capture_log = b""
    resolver_log = b""
    resolver_exit: int | None = None
    resolver_completed_monotonic_ns: int | None = None
    capture_exit: int | None = None
    released_unix_ns = 0
    released_monotonic_ns = 0
    primary: BaseException | None = None
    cleanup_errors: list[str] = []
    try:
        runner.run(
            resolver_command(
                config,
                topology,
                scenario,
                node_id,
                attempts,
                resolver_state,
                control,
            )
        )
        runner.run(capture_command(config, topology, scenario, output))
        publication.wait_for_capture_ready(
            runner,
            config.podman,
            capture,
            output / f"{scenario}.pcap",
            5.0,
        )
        released_unix_ns = time.time_ns()
        released_monotonic_ns = time.monotonic_ns()
        (control / "start").touch(mode=0o600)
        resolver_exit = publication.wait_for_exit(runner, config.podman, resolver, 13.0)
        resolver_completed_monotonic_ns = time.monotonic_ns()
        resolver_log = publication.container_logs(runner, config.podman, resolver)
        expected_exit = 0 if scenario == "live" else 4
        if resolver_exit != expected_exit:
            fail(
                f"{scenario} resolver exited {resolver_exit}, expected {expected_exit}"
            )
    except BaseException as error:
        primary = error
    for name, signal in ((resolver, "TERM"), (capture, "INT")):
        if not container_exists(runner, config, name):
            continue
        try:
            observed = stop_container(runner, config, name, signal)
            if name == resolver:
                resolver_exit = observed
            else:
                capture_exit = observed
        except Exception as error:
            cleanup_errors.append(f"stopping {name}: {error}")
    for name, suffix in ((resolver, "resolver.log"), (capture, "capture.log")):
        if not container_exists(runner, config, name):
            continue
        try:
            observed = save_container_log(
                runner, config, name, output / f"{scenario}.{suffix}"
            )
            if name == resolver:
                resolver_log = observed
            else:
                capture_log = observed
        except Exception as error:
            cleanup_errors.append(f"saving {name}: {error}")
    packet_count: int | None = None
    outcome: dict[str, object] = {}
    if primary is None and not cleanup_errors:
        try:
            if capture_exit != 0:
                fail(f"{scenario} capture exited {capture_exit}, expected 0")
            result = runner.run(pcap_read_command(config, topology, scenario, output))
            write_new(output / f"{scenario}.packets.log", result.stdout)
            write_new(output / f"{scenario}.pcap-read.log", result.stderr)
            packet_count = sum(1 for line in result.stdout.splitlines() if line.strip())
            publication.validate_complete_capture(scenario, capture_log, packet_count)
            if packet_count <= 0:
                fail(f"{scenario} captured no routed authority traffic")
            outcome = parse_diagnostic(resolver_log)
            validate_outcome(
                scenario,
                outcome,
                node_id=node_id,
                expected_candidate=expected_candidate,
            )
        except BaseException as error:
            primary = error
    for name in (capture, resolver):
        try:
            cleanup_container(runner, config, topology, name)
        except Exception as error:
            cleanup_errors.append(f"removing {name}: {error}")
    if primary is not None:
        if cleanup_errors:
            raise EvidenceFailure(
                f"{primary}; cleanup errors: {cleanup_errors}"
            ) from primary
        raise primary
    if cleanup_errors:
        fail(f"{scenario} cleanup failed: {cleanup_errors}")
    assert resolver_completed_monotonic_ns is not None
    return outcome, {
        "scenario": scenario,
        "node_id": node_id,
        "attempts": attempts,
        "expected_candidate": expected_candidate,
        "gate_release_unix_ns": released_unix_ns,
        "gate_release_monotonic_ns": released_monotonic_ns,
        "resolver_completed_monotonic_ns": resolver_completed_monotonic_ns,
        "resolver_elapsed_ns": resolver_completed_monotonic_ns - released_monotonic_ns,
        "postprocessing_completed_monotonic_ns": time.monotonic_ns(),
        "resolver_exit_code": resolver_exit,
        "capture_exit_code": capture_exit,
        "captured_transport_packet_count": packet_count,
        "outcome": outcome,
    }


def bootstrap_node_id(
    runner: Runner,
    config: RunConfig,
    topology: Topology,
    state_dir: Path,
    output: Path,
    log_name: str,
) -> str:
    runner.run(
        publisher_command(
            config,
            topology,
            state_dir,
            name=topology.bootstrap,
            publication_enabled=False,
        )
    )
    match, _, _ = publication.wait_for_log(
        runner, config.podman, topology.bootstrap, PROVIDER_NODE_RE, 15.0
    )
    node_id = match.group(1)
    exit_code = stop_container(runner, config, topology.bootstrap, "TERM")
    log = save_container_log(runner, config, topology.bootstrap, output / log_name)
    if exit_code != 0 or set(
        PROVIDER_NODE_RE.findall(log.decode(errors="replace"))
    ) != {node_id}:
        fail("publisher identity bootstrap was not stable and graceful")
    cleanup_container(runner, config, topology, topology.bootstrap)
    return node_id


def run_live(
    runner: Runner,
    config: RunConfig,
    topology: Topology,
    scratch: Path,
    output: Path,
) -> dict[str, object]:
    publisher_state = scratch / "publisher-state"
    authority_state = scratch / "authority-state-live"
    create_private_directory(publisher_state)
    create_private_directory(authority_state)
    node_id = bootstrap_node_id(
        runner,
        config,
        topology,
        publisher_state,
        output,
        "live.bootstrap.publisher.log",
    )
    runner.run(authority_command(config, topology, authority_state, node_id))
    publication.wait_for_log(
        runner, config.podman, topology.authority, AUTHORITY_READY_RE, 5.0
    )
    runner.run(
        publisher_command(
            config,
            topology,
            publisher_state,
            name=topology.publisher,
            publication_enabled=True,
            ttl_seconds=REAL_RECORD_TTL_SECONDS,
            refresh_seconds=REAL_RECORD_REFRESH_SECONDS,
        )
    )
    publication.wait_for_log(
        runner, config.podman, topology.publisher, PUBLICATION_LIVE_RE, 12.0
    )
    live_snapshot, live_raw, _ = publication.wait_for_authority_snapshot(
        authority_state,
        node_id=node_id,
        namespace=f"{config.namespace}-{topology.run_id}",
        recipient=config.recipient,
        expected_address=f"{topology.publisher_ip}:{IROH_PORT}",
        expected_state="live",
        minimum_sequence_exclusive=-1,
        deadline_monotonic_ns=time.monotonic_ns() + 11_000_000_000,
        expected_ttl_seconds=REAL_RECORD_TTL_SECONDS,
    )
    publication.preserve_authority_snapshot(
        output, "live-seeded", live_snapshot, live_raw
    )
    live_hash, live_sequence = authority_packet_binding(
        live_raw, node_id, context="live"
    )
    # Freeze the signed live record before lookup. A graceful publisher stop
    # emits a withdrawal, so this evidence-only crash boundary deliberately
    # kills the seed after the authority has confirmed its live PUT+GET.
    publisher_exit = stop_container(runner, config, topology.publisher, "KILL")
    if publisher_exit != 137:
        fail(f"live seed publisher exited {publisher_exit}, expected KILL status 137")
    publisher_log = save_container_log(
        runner, config, topology.publisher, output / "live.publisher.log"
    )
    if b"IROH-NODE-PUBLICATION state=Live" not in publisher_log:
        fail("real publisher live publication is absent from live log")
    cleanup_container(runner, config, topology, topology.publisher)
    outcome, observation = capture_and_resolve(
        runner,
        config,
        topology,
        scratch,
        output,
        scenario="live",
        node_id=node_id,
        attempts=1,
        expected_candidate=f"{topology.publisher_ip}:{IROH_PORT}",
    )
    live_attempt = outcome["attempts"][0]
    if (
        live_attempt.get("sequence") != live_sequence
        or live_attempt.get("signed_packet_blake3_hex") != live_hash
    ):
        fail("live lookup is not bound to the exact preserved production packet")
    stop_errors: list[str] = []
    for name in (topology.authority,):
        try:
            exit_code = stop_container(runner, config, name, "TERM")
            if exit_code != 0:
                fail(f"{name} exited {exit_code}, expected 0")
        except Exception as error:
            stop_errors.append(f"stopping {name}: {error}")
    authority_log = save_container_log(
        runner, config, topology.authority, output / "live.authority.log"
    )
    if b"iroh_node_authority_ready" not in authority_log:
        stop_errors.append("real authority readiness is absent from live log")
    authority_requests = publication.authority_request_count(authority_log)
    if authority_requests != 3:
        stop_errors.append(
            f"live authority observed {authority_requests} requests, expected "
            "publisher PUT+visibility GET plus resolver GET"
        )
    for name in (topology.authority,):
        try:
            cleanup_container(runner, config, topology, name)
        except Exception as error:
            stop_errors.append(f"removing {name}: {error}")
    if stop_errors:
        fail(f"live authority/publisher cleanup failed: {stop_errors}")
    observation["authority_kind"] = "production-task137"
    observation["publisher_freeze_exit_code"] = publisher_exit
    observation["authority_request_count"] = authority_requests
    observation["live_signed_packet_blake3_hex"] = live_hash
    observation["live_sequence"] = live_sequence
    observation["outcome"] = outcome
    return observation


def run_not_found_arm(
    runner: Runner,
    config: RunConfig,
    topology: Topology,
    scratch: Path,
    output: Path,
) -> dict[str, object]:
    target_state = scratch / "not-found-target-state"
    authority_state = scratch / "not-found-authority-state"
    create_private_directory(target_state)
    create_private_directory(authority_state)
    node_id = bootstrap_node_id(
        runner,
        config,
        topology,
        target_state,
        output,
        "not-found.bootstrap.publisher.log",
    )
    publication.assert_empty_authority_state(authority_state)
    runner.run(authority_command(config, topology, authority_state, node_id))
    publication.wait_for_log(
        runner, config.podman, topology.authority, AUTHORITY_READY_RE, 5.0
    )
    outcome, observation = capture_and_resolve(
        runner,
        config,
        topology,
        scratch,
        output,
        scenario="not-found",
        node_id=node_id,
        attempts=1,
    )
    authority_exit = stop_container(runner, config, topology.authority, "TERM")
    authority_log = save_container_log(
        runner, config, topology.authority, output / "not-found.authority.log"
    )
    requests = publication.authority_request_count(authority_log)
    publication.assert_empty_authority_state(authority_state)
    if authority_exit != 0 or requests != 1:
        fail(
            f"not-found production authority exit/requests were "
            f"{authority_exit}/{requests}, expected 0/1"
        )
    publication.preserve_final_authority_files(authority_state, output, "not-found")
    cleanup_container(runner, config, topology, topology.authority)
    observation.update(
        {
            "authority_kind": "production-task137-empty-state",
            "authority_exit_code": authority_exit,
            "authority_request_count": requests,
            "outcome": outcome,
        }
    )
    return observation


def authority_packet_binding(
    raw_state: bytes, node_id: str, *, context: str
) -> tuple[str, int]:
    try:
        envelope = json.loads(raw_state)
        records = envelope["body"]["records"]
        entry = records[publication.signer_z32(node_id)]
        packet = bytes.fromhex(entry["packet_hex"])
        sequence = entry["high_water_sequence"]
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        fail(f"{context} authority state cannot bind its signed packet: {error}")
    if not isinstance(sequence, int):
        fail(f"{context} authority high-water sequence is not an integer")
    return blake3.blake3(packet).hexdigest(), sequence


def run_withdrawal_arm(
    runner: Runner,
    config: RunConfig,
    topology: Topology,
    scratch: Path,
    output: Path,
) -> dict[str, object]:
    publisher_state = scratch / "withdrawal-publisher-state"
    authority_state = scratch / "withdrawal-authority-state"
    create_private_directory(publisher_state)
    create_private_directory(authority_state)
    node_id = bootstrap_node_id(
        runner,
        config,
        topology,
        publisher_state,
        output,
        "withdrawal.bootstrap.publisher.log",
    )
    namespace = f"{config.namespace}-{topology.run_id}"
    expected_address = f"{topology.publisher_ip}:{IROH_PORT}"
    runner.run(authority_command(config, topology, authority_state, node_id))
    publication.wait_for_log(
        runner, config.podman, topology.authority, AUTHORITY_READY_RE, 5.0
    )
    runner.run(
        publisher_command(
            config,
            topology,
            publisher_state,
            name=topology.publisher,
            publication_enabled=True,
            ttl_seconds=REAL_RECORD_TTL_SECONDS,
            refresh_seconds=REAL_RECORD_REFRESH_SECONDS,
        )
    )
    live, _, _ = publication.wait_for_authority_snapshot(
        authority_state,
        node_id=node_id,
        namespace=namespace,
        recipient=config.recipient,
        expected_address=expected_address,
        expected_state="live",
        minimum_sequence_exclusive=-1,
        deadline_monotonic_ns=time.monotonic_ns() + 11_000_000_000,
        expected_ttl_seconds=REAL_RECORD_TTL_SECONDS,
    )
    live_sequence = live["sequence"]
    assert isinstance(live_sequence, int)
    publication.wait_for_log(
        runner,
        config.podman,
        topology.publisher,
        re.compile(rf"IROH-NODE-PUBLICATION state=Live sequence={live_sequence}\b"),
        5.0,
    )
    publisher_exit = stop_container(runner, config, topology.publisher, "TERM")
    withdrawn, withdrawn_raw, _ = publication.wait_for_authority_snapshot(
        authority_state,
        node_id=node_id,
        namespace=namespace,
        recipient=config.recipient,
        expected_address=expected_address,
        expected_state="withdrawn",
        minimum_sequence_exclusive=live_sequence,
        deadline_monotonic_ns=time.monotonic_ns() + 6_000_000_000,
        expected_ttl_seconds=REAL_RECORD_TTL_SECONDS,
    )
    publisher_log = save_container_log(
        runner, config, topology.publisher, output / "withdrawal.publisher.log"
    )
    if publisher_exit != 0 or b"IROH-NODE-PUBLICATION-WITHDRAWN" not in publisher_log:
        fail("withdrawal publisher did not publish a higher tombstone and exit cleanly")
    preparation_authority_exit = stop_container(
        runner, config, topology.authority, "TERM"
    )
    preparation_authority_log = save_container_log(
        runner,
        config,
        topology.authority,
        output / "withdrawal.preparation.authority.log",
    )
    if preparation_authority_exit != 0:
        fail("withdrawal preparation authority did not stop cleanly")
    write_new(output / "withdrawal.tombstone.authority-state.json", withdrawn_raw)
    write_new(output / "withdrawal.tombstone.record.json", canonical_json(withdrawn))
    tombstone_hash, tombstone_sequence = authority_packet_binding(
        withdrawn_raw, node_id, context="withdrawal"
    )
    preparation_requests = publication.authority_request_count(
        preparation_authority_log
    )
    if preparation_requests != 4:
        fail(
            "withdrawal preparation authority observed "
            f"{preparation_requests} requests, expected live PUT+GET and "
            "withdrawal PUT+GET"
        )
    cleanup_container(runner, config, topology, topology.publisher)
    cleanup_container(runner, config, topology, topology.authority)

    # Restart the same durable production authority to reset its process-local
    # request counter. No publisher exists while resolver capture is active.
    runner.run(authority_command(config, topology, authority_state, node_id))
    publication.wait_for_log(
        runner, config.podman, topology.authority, AUTHORITY_READY_RE, 5.0
    )
    outcome, observation = capture_and_resolve(
        runner,
        config,
        topology,
        scratch,
        output,
        scenario="withdrawal",
        node_id=node_id,
        attempts=1,
    )
    authority_exit = stop_container(runner, config, topology.authority, "TERM")
    authority_log = save_container_log(
        runner, config, topology.authority, output / "withdrawal.authority.log"
    )
    requests = publication.authority_request_count(authority_log)
    final_attempt = outcome["attempts"][0]
    if (
        authority_exit != 0
        or requests != 1
        or final_attempt.get("provenance") != "network_validated"
        or final_attempt.get("signed_packet_blake3_hex") != tombstone_hash
        or final_attempt.get("sequence") != tombstone_sequence
    ):
        fail(
            "withdrawal lookup is not bound to the exact persisted production tombstone"
        )
    publication.preserve_final_authority_files(authority_state, output, "withdrawal")
    cleanup_container(runner, config, topology, topology.authority)
    observation.update(
        {
            "authority_kind": "production-task137-persisted-withdrawal",
            "authority_exit_code": authority_exit,
            "authority_request_count": requests,
            "preparation_authority_request_count": preparation_requests,
            "publisher_exit_code": publisher_exit,
            "tombstone_blake3_hex": tombstone_hash,
            "tombstone_sequence": tombstone_sequence,
            "outcome": outcome,
        }
    )
    return observation


def run_fixture_arm(
    runner: Runner,
    config: RunConfig,
    topology: Topology,
    scratch: Path,
    output: Path,
    scenario: str,
    image_revision: str,
) -> dict[str, object]:
    fixture = topology.fixture(scenario)
    runner.run(fixture_command(config, topology, scenario, image_revision))
    match, _, _ = publication.wait_for_log(
        runner, config.podman, fixture, FIXTURE_READY_RE, 5.0
    )
    if match.group(1) != scenario:
        fail(f"fixture announced scenario {match.group(1)!r}, expected {scenario!r}")
    node_id = match.group(2)
    expected_requests = FIXTURE_EXPECTATIONS[scenario][0]
    if int(match.group(4)) != expected_requests:
        fail(f"fixture request plan for {scenario} is not exact")
    outcome, observation = capture_and_resolve(
        runner,
        config,
        topology,
        scratch,
        output,
        scenario=scenario,
        node_id=node_id,
        attempts=expected_requests,
    )
    if scenario == "hanging":
        publication.wait_for_log(
            runner,
            config.podman,
            fixture,
            re.compile(
                r"iroh_node_lookup_fixture_cancelled scenario=hanging attempt=1 "
                r"observed_after_ms=\d+"
            ),
            3.0,
        )
    completion = (
        rf"iroh_node_lookup_fixture_complete scenario={re.escape(scenario)} "
        rf"observed_requests={expected_requests} expected_requests={expected_requests} "
        r"surplus_observation_ms=250"
    )
    publication.wait_for_log(
        runner, config.podman, fixture, re.compile(completion), 3.0
    )
    fixture_exit = publication.wait_for_exit(runner, config.podman, fixture, 3.0)
    fixture_log = save_container_log(
        runner, config, fixture, output / f"{scenario}.authority.log"
    )
    fixture_plan = parse_fixture_plan(
        fixture_log,
        config=config,
        topology=topology,
        scenario=scenario,
        node_id=node_id,
        image_revision=image_revision,
    )
    request_lines = re.findall(
        rb"(?m)^iroh_node_lookup_fixture_request scenario=[a-z-]+ attempt=\d+\r?$",
        fixture_log,
    )
    if len(request_lines) != expected_requests:
        fail(
            f"{scenario} fixture observed {len(request_lines)} canonical GETs, "
            f"expected {expected_requests}"
        )
    if scenario == "hanging":
        cancellations = re.findall(
            rb"(?m)^iroh_node_lookup_fixture_cancelled scenario=hanging "
            rb"attempt=1 observed_after_ms=(\d+)\r?$",
            fixture_log,
        )
        if (
            fixture_exit != 0
            or len(cancellations) != 1
            or not 9_000 <= int(cancellations[0]) <= 11_000
        ):
            fail(
                "hanging fixture did not positively observe client deadline cancellation"
            )
    elif fixture_exit != 0:
        fail(f"{scenario} fixture exited {fixture_exit}, expected 0")
    elif (
        f"iroh_node_lookup_fixture_complete scenario={scenario} "
        f"observed_requests={expected_requests} expected_requests={expected_requests} "
        "surplus_observation_ms=250"
    ).encode() not in fixture_log:
        fail(f"{scenario} fixture did not prove exact observed/no-surplus requests")
    cleanup_container(runner, config, topology, fixture)
    observation["authority_kind"] = "feature-gated-adversarial-fixture"
    observation["authority_exit_code"] = fixture_exit
    observation["fixture_plan_blake3_hex"] = blake3.blake3(
        canonical_json(fixture_plan)
    ).hexdigest()
    observation["outcome"] = outcome
    return observation


def run_refused_arm(
    runner: Runner,
    config: RunConfig,
    topology: Topology,
    scratch: Path,
    output: Path,
    node_id: str,
) -> dict[str, object]:
    inert = topology.fixture("refused")
    runner.run(inert_refusal_command(config, topology))
    outcome, observation = capture_and_resolve(
        runner,
        config,
        topology,
        scratch,
        output,
        scenario="refused",
        node_id=node_id,
        attempts=1,
    )
    inert_exit = stop_container(runner, config, inert, "TERM")
    if inert_exit not in (0, 143):
        fail(f"inert refusal control exited {inert_exit}")
    cleanup_container(runner, config, topology, inert)
    write_new(
        output / "refused.authority.log",
        b"inert routed authority-IP owner ran with no TCP listener; refused.pcap records the kernel RST\n",
    )
    observation["authority_kind"] = "inert-rst-control"
    observation["authority_exit_code"] = inert_exit
    observation["outcome"] = outcome
    return observation


def verify_image(
    runner: Runner, config: RunConfig, topology: Topology
) -> dict[str, object]:
    publication.validate_immutable_image_reference(config.image)
    identity = publication.immutable_image_identity(runner, config)  # type: ignore[arg-type]
    rootless = (
        runner.run([config.podman, "info", "--format", "{{.Host.Security.Rootless}}"])
        .stdout.decode()
        .strip()
    )
    if rootless != "true":
        fail(f"lookup evidence requires rootless Podman, observed {rootless!r}")
    runner.run(image_preflight_command(config, topology), timeout=30.0)
    return identity


def build_manifest(output: Path) -> dict[str, object]:
    files = []
    for path in sorted(output.iterdir(), key=lambda candidate: candidate.name):
        if path.name == "manifest.json":
            continue
        if path.is_symlink() or not path.is_file():
            fail(f"raw evidence entry {path.name!r} is not a regular file")
        data = path.read_bytes()
        files.append(
            {
                "path": path.name,
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )
    return {"schema": MANIFEST_SCHEMA, "files": files}


def run_evidence(config: RunConfig) -> None:
    if config.output.exists() or config.output.is_symlink():
        fail(f"refusing to overwrite output {config.output}")
    runner = Runner()
    occupied = publication.occupied_ipv4_networks(runner, config.podman)
    topology = make_topology(new_run_id(), occupied)
    create_private_directory(config.output)
    observations: list[dict[str, object]] = []
    primary: BaseException | None = None
    cleanup_error: BaseException | None = None
    started_unix_ns = time.time_ns()
    with tempfile.TemporaryDirectory(prefix="nix-p2p-task138-") as raw:
        scratch = Path(raw)
        try:
            image = verify_image(runner, config, topology)
            for command in network_commands(config, topology):
                runner.run(command)
            for command in router_commands(config, topology):
                runner.run(command)
            for scenario in CONTROL_SCENARIOS:
                observations.append(
                    run_zero_control(
                        runner,
                        config,
                        topology,
                        scratch,
                        config.output,
                        scenario,
                    )
                )
            observations.append(
                run_live(runner, config, topology, scratch, config.output)
            )
            not_found = run_not_found_arm(
                runner, config, topology, scratch, config.output
            )
            observations.append(not_found)
            observations.append(
                run_withdrawal_arm(runner, config, topology, scratch, config.output)
            )
            implementation_revision = image["implementation_revision"]
            if not isinstance(implementation_revision, str):
                fail("image implementation revision is not a string")
            for scenario in FIXTURE_EXPECTATIONS:
                observation = run_fixture_arm(
                    runner,
                    config,
                    topology,
                    scratch,
                    config.output,
                    scenario,
                    implementation_revision,
                )
                observations.append(observation)
            refused_node = str(not_found["node_id"])
            if NODE_ID_RE.fullmatch(refused_node) is None:
                fail("not-found arm did not yield a reusable valid NodeId")
            observations.append(
                run_refused_arm(
                    runner,
                    config,
                    topology,
                    scratch,
                    config.output,
                    refused_node,
                )
            )
            ending_image = publication.immutable_image_identity(  # type: ignore[arg-type]
                runner, config
            )
            if ending_image != image:
                fail("evidence image identity changed during the run")
            run = {
                "schema": SCHEMA,
                "profile": "production-shaped-local",
                "capture_scope": "all-tcp-udp-in-resolver-netns-v1",
                "capture_filter": CAPTURE_FILTER,
                "capture_interface": CAPTURE_INTERFACE,
                "dns_enabled": False,
                "relay_enabled": False,
                "content_discovery_enabled": False,
                "publication_from_resolver_enabled": False,
                "external_authority_contact_authorized": False,
                "lookup_deadline_ns": DEADLINE_NS,
                "observer_grace_ns": OBSERVER_GRACE_NS,
                "started_unix_ns": started_unix_ns,
                "completed_unix_ns": time.time_ns(),
                "image": image,
                "topology": {
                    "run_id": topology.run_id,
                    "resolver_network": topology.resolver_network,
                    "authority_network": topology.authority_network,
                    "resolver_subnet": str(topology.resolver_subnet),
                    "authority_subnet": str(topology.authority_subnet),
                    "resolver_ip": str(topology.resolver_ip),
                    "router_resolver_ip": str(topology.router_resolver_ip),
                    "authority_ip": str(topology.authority_ip),
                    "router_authority_ip": str(topology.router_authority_ip),
                    "publisher_ip": str(topology.publisher_ip),
                    "authority_port": AUTHORITY_PORT,
                },
                "observations": observations,
            }
            write_new(config.output / "run.json", canonical_json(run))
            write_new(
                config.output / "manifest.json",
                canonical_json(build_manifest(config.output)),
            )
        except BaseException as error:
            primary = error
        try:
            cleanup_exact(runner, config, topology)
        except BaseException as error:
            cleanup_error = error
    if primary is not None:
        if cleanup_error is not None:
            raise EvidenceFailure(
                f"{primary}; cleanup failed: {cleanup_error}"
            ) from primary
        raise primary
    if cleanup_error is not None:
        raise cleanup_error
    print(f"iroh-node-lookup routed evidence: PASS output={config.output}")


def command_plan(
    config: RunConfig, topology: Topology, root: Path
) -> dict[str, list[str]]:
    node_id = "11" * 32
    return {
        "network_resolver": network_commands(config, topology)[0],
        "network_authority": network_commands(config, topology)[1],
        "router": router_commands(config, topology)[0],
        "router_connect": router_commands(config, topology)[1],
        "authority": authority_command(config, topology, root, node_id),
        "publisher": publisher_command(
            config,
            topology,
            root,
            name=topology.publisher,
            publication_enabled=True,
        ),
        "fixture": fixture_command(config, topology, "bad-signature", "1" * 40),
        "inert_refusal": inert_refusal_command(config, topology),
        "control_default_off": control_command(
            config, topology, "default-off", root, root
        ),
        "control_offline_disabled": control_command(
            config, topology, "offline-disabled", root, root
        ),
        "control_offline_enabled": control_command(
            config, topology, "offline-enabled", root, root
        ),
        "resolver": resolver_command(
            config,
            topology,
            "bad-signature",
            node_id,
            1,
            root,
            root,
        ),
        "capture": capture_command(config, topology, "bad-signature", root),
        "preflight": image_preflight_command(config, topology),
    }


def sample_outcome(scenario: str, node_id: str) -> dict[str, object]:
    if scenario == "live":
        attempts = [
            {
                "attempt": 1,
                "verdict": "pass",
                "lookup_schema": "iroh-node-lookup-v1",
                "record_schema": "iroh-node-publication-v1",
                "source": "pinned-pkarr-http",
                "provenance": "network_validated",
                "elapsed_micros": 100,
                "node_id": node_id,
                "candidates": [{"kind": "direct", "value": "10.1.2.30:44330"}],
            }
        ]
        return {
            "schema": "iroh-node-lookup-v1",
            "verdict": "pass",
            "node_id": node_id,
            "attempt_count": 1,
            "attempts": attempts,
            "shutdown": "graceful",
        }
    count, reason = UNAVAILABLE_EXPECTATIONS.get(
        scenario, (1, "authority_connection_refused")
    )
    attempts: list[dict[str, object]] = []
    if count == 2:
        attempts.append(
            {
                "attempt": 1,
                "verdict": "pass",
                "provenance": "network_validated",
                "elapsed_micros": 100,
            }
        )
    attempts.append(
        {
            "attempt": count,
            "verdict": "unavailable",
            "reason": reason,
            "elapsed_micros": 10_000_000 if scenario == "hanging" else 100,
        }
    )
    if scenario in ("stale", "equal-conflict", "expired", "withdrawal"):
        attempts[-1].update(
            {
                "source": "pinned-pkarr-http",
                "provenance": "network_validated",
                "sequence": 42,
                "signed_packet_blake3_hex": "3" * 64,
            }
        )
    return {
        "schema": "iroh-node-lookup-v1",
        "verdict": "unavailable",
        "node_id": node_id,
        "attempt_count": count,
        "attempts": attempts,
        "shutdown": "graceful",
    }


def self_test() -> None:
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        topology = make_topology("r1234567-test")
        config = RunConfig(
            root / "out", "localhost/nix-p2p-task138:0123456789abcdefghijkl"
        )
        commands = command_plan(config, topology, root)
        for label in ("network_resolver", "network_authority"):
            assert "--internal" in commands[label]
            assert "--disable-dns" in commands[label]
        assert commands["capture"][-1] == "tcp or udp"
        assert f"container:{topology.resolver('bad-signature')}" in commands["capture"]
        resolver = commands["resolver"]
        assert resolver.count("--node-id") == 1
        assert "/bin/iroh-node-lookup" in resolver
        assert "--iroh-publish-node" not in resolver
        assert "--iroh-publication-address" not in resolver
        assert topology.authority_network not in resolver
        assert str(topology.authority_subnet) in resolver
        assert str(topology.router_resolver_ip) in resolver
        assert "/bin/iroh-node-lookup-fixture" in commands["fixture"]
        assert "--run-id" in commands["fixture"]
        assert "--image-revision" in commands["fixture"]
        assert "/bin/bash" in commands["inert_refusal"]
        assert "TERM INT" in commands["inert_refusal"][-1]
        assert "sleep infinity" not in commands["inert_refusal"][-1]
        assert "--iroh-enable-node-lookup" not in commands["control_default_off"]
        assert "offline-test" in commands["control_offline_disabled"]
        assert "--iroh-enable-node-lookup" in commands["control_offline_enabled"]
        assert all(
            binary in " ".join(commands["preflight"])
            for binary in (
                "daemon",
                "iroh-node-authority",
                "iroh-node-lookup",
                "iroh-node-lookup-fixture",
                "tcpdump",
                "ip",
            )
        )
        assert topology.resolver_subnet != topology.authority_subnet
        publication.validate_immutable_image_reference(config.image)
        try:
            publication.validate_immutable_image_reference(
                "example.invalid/lookup:latest"
            )
        except RuntimeError:
            pass
        else:
            raise AssertionError("mutable image reference was accepted")

        node_id = "22" * 32
        positive = sample_outcome("live", node_id)
        validate_outcome(
            "live",
            positive,
            node_id=node_id,
            expected_candidate="10.1.2.30:44330",
        )
        mutated = json.loads(json.dumps(positive))
        mutated["attempts"][0]["provenance"] = "cache"
        try:
            validate_outcome(
                "live",
                mutated,
                node_id=node_id,
                expected_candidate="10.1.2.30:44330",
            )
        except EvidenceFailure:
            pass
        else:
            raise AssertionError("fake positive provenance was accepted")
        for scenario in (*UNAVAILABLE_EXPECTATIONS, "refused"):
            value = sample_outcome(scenario, node_id)
            validate_outcome(scenario, value, node_id=node_id)
            broken = json.loads(json.dumps(value))
            broken["attempts"][-1]["reason"] = "content_miss"
            try:
                validate_outcome(scenario, broken, node_id=node_id)
            except EvidenceFailure:
                pass
            else:
                raise AssertionError(f"{scenario} accepted a content MISS reason")
        slow = sample_outcome("hanging", node_id)
        slow["attempts"][-1]["elapsed_micros"] = 12_000_000
        try:
            validate_outcome("hanging", slow, node_id=node_id)
        except EvidenceFailure:
            pass
        else:
            raise AssertionError("deadline overrun was accepted")

        output = root / "manifest"
        output.mkdir()
        (output / "run.json").write_bytes(b"{}\n")
        manifest = build_manifest(output)
        assert manifest["files"][0]["sha256"] == hashlib.sha256(b"{}\n").hexdigest()
    print("iroh-node-lookup evidence self-test: PASS")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="nix-p2p-iroh-lookup-evidence:latest")
    parser.add_argument("--output", type=Path, default=Path("artifacts/iroh-lookup"))
    parser.add_argument("--podman", default="podman")
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.self_test:
            self_test()
        else:
            run_evidence(RunConfig(args.output, args.image, args.podman))
    except (EvidenceFailure, CommandFailure, OSError, ValueError) as error:
        print(f"iroh-node-lookup evidence: FATAL - {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
