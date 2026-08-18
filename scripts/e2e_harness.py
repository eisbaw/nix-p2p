#!/usr/bin/env python3
"""E2E container harness: the canonical `just e2e` (task-5).

Drives the real chain under test - client(real nix) -> daemon -> testproxy ->
mock-origin - inside a rootless podman POD (host-verified: no Docker daemon;
podman-compose too partial to trust), and asserts the TESTING.md oracles. One
image, four roles (see flake `e2e-image`), selected by the command each
container runs; all roles share the pod's loopback so the binary defaults
(daemon 8082 <- testproxy 8081 <- origin 8080) chain with no reconfiguration.

Reusability (this is FOUNDATIONAL infra - tasks 6/7/9/11 build on it):
  * `Pod` is a context manager that stands up origin+testproxy+(daemon),
    publishes their ports to the host for host-side oracles, and exposes
    `client_run` / `client_daemon_run` / `proxy_reset` / `proxy_stats` /
    `proxy_faults` / `kill` / `exec`. A scenario is a plain function that takes
    a `Ctx` and an `expect` callback.
  * task-6 (operator journey): call `Pod(...).client_run(...)` and narrate.
  * task-7 (crash injection): `Pod.kill("daemon")` mid-transfer; see NOTE there.
  * task-9 (egress/gap oracles): `Pod.proxy_stats()` / `proxy_log()` are the
    ground-truth counters; `record['gap_ms']` is the narinfo->nar gap.
  * task-11 (chain N daemons): `Pod(..., daemon_chain=N)` runs
    client -> daemon-1 -> daemon-2 -> ... -> daemon-N -> testproxy -> origin,
    each daemon on its own in-pod port (8082, 8083, ...) with a host port
    published per hop (18082, 18083, ...) so per-entry-point oracles run
    host-side. The long-chain scenarios assert S1 at depth, per-hop request
    counts, the timeout invariant, and middle-daemon-kill recovery. task-13
    (fault x depth matrix) and task-15 (p2p multi-hop) reuse this seam.

Fixture handling (AC#5, task-3 deep-gate): we resolve the IMMUTABLE generation
(`readlink -f fixtures/out/current`), bind-mount ONLY its `cache/` subdir into
the origin - never the generation root, which holds the *.sec signing key. The
generation is immutable by contract and its manifest-sha is in its own name, so
no per-run copy is needed for pristine scenarios (the tree provably cannot
change under the container). Tamper/absent scenarios serve a scratch tree we
build from the cache with fixturelib - also key-free. `check-fixtures.py` (the
fail-closed gate) runs BEFORE anything is served (round-2 deep-gate finding).

Exit 0 iff every scenario's every oracle held; 1 if any failed; 2 on a
preflight/environment failure (nothing was proven).
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import json
import lzma
import os
import re
import shlex
import shutil
import socket
import statistics
import subprocess
import sys
import time
import types
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

import fixturelib as fx

# ---- constants -------------------------------------------------------------

# A label stamped on every pod/container we create, so `e2e-clean` can find and
# remove exactly our objects and nothing else on the host.
PROJECT_LABEL = "nix-p2p-e2e=1"
POD_PREFIX = "nix-p2p-e2e"

# In-pod ports (binary defaults, so the chain needs no reconfiguration).
ORIGIN_PORT = 8080
PROXY_PORT = 8081
DAEMON_PORT = 8082
# Host-published ports for host-side oracles (proxy admin, daemon cache-info).
HOST_ORIGIN = 18080
HOST_PROXY = 18081
HOST_DAEMON = 18082
# Ceiling on `daemon_chain=N` (task-11): daemon i takes in-pod port DAEMON_PORT+i
# and host port HOST_DAEMON+i, so an unbounded N would eventually collide with
# other host services. Depth-3 is the standing test; 32 is a generous band
# (8082..8113 / 18082..18113) that fails fast on an absurd value.
MAX_DAEMON_CHAIN = 32

# Ceiling on `p2p_holders=N` (task-42 swarm profiling): a p2p pod takes in-pod
# port DAEMON_PORT+i and host port HOST_DAEMON+i for node-a plus each holder, so
# N holders occupy N+1 ports. 30 keeps the whole swarm inside the same
# 8082..8113 / 18082..18113 band MAX_DAEMON_CHAIN reserves, and matches the
# TESTING.md S5 "target 1..30 nodes" range - above that the sweep would silently
# collide with whatever else the host published.
MAX_P2P_HOLDERS = 30

# Where a daemon's on-disk state (its narinfo disk cache) is mounted inside the
# container when a pod is given a `state_root`. The HOST side of that mount is
# what task-42 walks to measure disk footprint: host-side on purpose, because
# `du`/`find` are NOT in this image and an in-container probe would return
# rc=127 and pass unconditionally (the dead-oracle trap this repo has hit).
DAEMON_STATE_MOUNT = "/srv/state"

# The DoD honesty marker (Justfile `stub_marker`). A real harness with zero
# scenarios registered is a stub pretending to pass; we print this and fail
# closed if that ever happens, and `just e2e` succeeding proves it absent.
STUB_MARKER = "0 scenarios registered - NOT a pass"

# The four fixture payloads (task-3 workload v1); the closure `app -> lib`
# exercises signed References.
ALL_ATTRS = ("lib", "app", "zstd", "big")

# TASK-29: the narinfo-offload scenario's target set. A big-free subset (lib+app+
# zstd, all <=512 KiB) - narinfo is tiny, so the 110 MiB `big` payload adds cold-
# pull seconds without strengthening a narinfo-count oracle. `app` references `lib`,
# so the closure still exercises a dependency edge, not just leaf paths.
NARINFO_ATTRS = ("lib", "app", "zstd")

READY_TIMEOUT_S = 45.0

# --- libp2p (S7, TASK-161) ----------------------------------------------------
# The kad/identify network scope every libp2p node in an S7 pod shares (mismatched
# scopes give distinct kad protocol names, so the nodes never meet). Distinct from
# the iroh "offline-test" endpoint scope; the two backends are independent.
LIBP2P_SCOPE = "e2e-s7"
# Container mount for the TASK-103 public-NAR allowlist (a dedicated NON-world-writable
# writable dir; the store refuses a 0777 parent like /tmp). The host side is created 0755
# and rootless-podman maps it to container-root, satisfying the store's euid/ownership check.
LIBP2P_ALLOWLIST_MOUNT = "/var/lib/nix-p2p"
# Base TCP port for the in-pod libp2p listeners; role i (in `_daemon_roles` order)
# listens on LIBP2P_BASE_PORT + i. Deliberately far from the HTTP 808x band.
LIBP2P_BASE_PORT = 37000
# The operator admin (`--status-listen`) loopback port inside the consumer container (TASK-242).
# Loopback-only + queried via `podman exec` from inside the container (never host-published), so it
# only needs to avoid the in-container HTTP/libp2p bands above. Used by the containerized
# dependency-outage drill (`scenario_libp2p_bootstrap_outage`).
LIBP2P_STATUS_PORT = 39100
# A syntactically valid but UNREACHABLE ed25519 PeerId used as the GENESIS (BOOT)
# node's `--libp2p-bootstrap` entry. Every libp2p daemon requires a bootstrap peer, but
# the first node has no one to point at; kad's self-lookup against an unreachable entry
# fails best-effort (source_libp2p.rs), so the node still binds and joins as a lone kad
# router. Computed once from a fixed seed (identity-multihash of an ed25519 pubkey ->
# base58btc); it only needs to PARSE, never to answer. If a libp2p version bump ever
# rejects it, BOOT fails LOUD at CLI parse (not silently), so this cannot rot unnoticed.
LIBP2P_DUMMY_PEER = "12D3KooWPMRVzCGYHwfnPZAWzDX2A7YvyESXGYZx5WrBvc4vgsze"
# The dedicated BOOTSTRAP node's FIXED identity: a PURE kad router (NOT a provider, so
# it never announces and never hits the put-provider quorum a lone genesis provider
# cannot satisfy). Its identity seed is fixed so its PeerId is DERIVABLE offline - the
# provider and consumer bootstrap to `<LIBP2P_BOOT_PEER_ID>@/ip4/127.0.0.1/tcp/<port>`
# with no printed-address round-trip (a non-provider node cannot print its address).
# PeerId is the identity-multihash base58btc of the ed25519 pubkey of the seed; a drift
# between the two is caught at the first S7 run (P cannot reach BOOT -> announce fails).
LIBP2P_BOOT_SEED_HEX = "1b" * 32
LIBP2P_BOOT_PEER_ID = "12D3KooWBr7cTGxmMhdiGNcbesEusWMR1VG26jEQQgFr6wwZkNNf"
# Seconds to let the 3-node kad DHT converge (BOOT<->P<->C identify + routing) AFTER
# the consumer is up, BEFORE the measured build. A per-NAR `find_providers` that races
# an unconverged DHT would miss -> upstream fallback and a FALSE negative on the
# 0-egress oracle; this bounded settle makes the positive arm deterministic. Bounded
# (not a retry loop) so a genuinely broken discovery still fails the oracle, not hides.
LIBP2P_CONVERGE_S = 12.0
# The separate-netns S7 (TASK-179) adds a routed inter-network hop (C on net-c ->
# podman host routing -> BOOT/P on net-p, SNAT'd), so give the DHT a slightly larger
# bounded settle than the shared-pod path. Still bounded (not a retry loop).
LIBP2P_NETNS_CONVERGE_S = 16.0
# TASK-257: mDNS query cadence + kad convergence on a fresh two-node LAN. mDNS emits its
# first query at startup, but discovery + routing-table population + a put/get round can take
# a little longer than the routed-bootstrap S7, so give the zero-bootstrap DHT a bit more.
LIBP2P_MDNS_CONVERGE_S = 22.0


def die(message: str, code: int = 2) -> None:
    print(f"e2e: FATAL - {message}", file=sys.stderr)
    raise SystemExit(code)


# ---- podman plumbing -------------------------------------------------------


def podman() -> str:
    found = shutil.which("podman")
    if not found:
        die(
            "podman not found on PATH. The e2e harness needs rootless podman "
            "(host-verified: no Docker daemon). Install it or add it to the "
            "devshell; see task-5 notes."
        )
    return found


def run(argv: list[str], *, check: bool = True, timeout: float | None = None):
    """Run a command, capturing output. Fails loudly with the stderr."""
    result = subprocess.run(
        argv, capture_output=True, text=True, timeout=timeout, check=False
    )
    if check and result.returncode != 0:
        die(
            f"command failed ({result.returncode}): {' '.join(argv)}\n"
            f"stdout: {result.stdout.strip()}\nstderr: {result.stderr.strip()}"
        )
    return result


def http_get(url: str, timeout: float = 10.0) -> tuple[int, bytes]:
    """GET a URL, returning (status, body). A non-2xx is returned, not raised,
    because several oracles assert on the status itself (e.g. 404-fidelity)."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def http_post(url: str, timeout: float = 10.0) -> tuple[int, bytes]:
    request = urllib.request.Request(url, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def daemon_reachable(timeout: float = 1.0) -> bool:
    """True iff the daemon answers /nix-cache-info on its published host port.

    A killed (or never-started) daemon's forwarded port yields connection-
    refused - an OSError, which `urllib.error.URLError` subclasses - so this is
    the single 'is the daemon still there' probe shared by the s2 scenario and
    the J1 journey (task-6), rather than each re-implementing the try/except.
    """
    try:
        status, _ = http_get(f"http://127.0.0.1:{HOST_DAEMON}/nix-cache-info", timeout)
    except OSError:
        return False
    return status == 200


# ---- fixture + tamper trees ------------------------------------------------


@dataclass
class Fixtures:
    """The resolved immutable generation and its manifest."""

    generation: Path
    cache: Path  # generation/cache - the ONLY thing mounted into a container
    manifest: dict
    public_key: str

    def entry(self, attr: str) -> dict:
        for path in self.manifest["paths"]:
            if path["attr"] == attr:
                return path
        die(f"fixture manifest has no payload {attr!r}")
        raise AssertionError  # unreachable, satisfies type checkers

    def store_path(self, attr: str) -> str:
        return self.entry(attr)["store_path"]

    def nar_hash(self, attr: str) -> str:
        return self.entry(attr)["nar_hash"]


def resolve_fixtures(out_root: Path) -> Fixtures:
    generation = fx.resolve_current(out_root)
    if generation is None:
        die(
            f"no published fixture generation under {out_root}/current. Run "
            "`nix develop -c just fixtures-large` first."
        )
    manifest = json.loads((generation / "manifest.json").read_text())
    return Fixtures(
        generation=generation,
        cache=generation / "cache",
        manifest=manifest,
        public_key=manifest["public_key"],
    )


def _minimal_cache(fixtures: Fixtures, dst_cache: Path, attrs: list[str]) -> None:
    """Copy just the files needed to serve `attrs` into a fresh scratch cache.

    Mirrors check-fixtures.minimal_cache: keeps tamper scratch trees small and,
    crucially, key-free (no *.sec is ever copied - AC#5 holds by construction).
    """
    dst_cache.mkdir(parents=True)
    wanted = ["nix-cache-info"]
    for attr in attrs:
        entry = fixtures.entry(attr)
        wanted.append(fx.narinfo_name(entry["store_path"]))
        wanted.append(entry["url"])
    for relative in wanted:
        source = fixtures.cache / relative
        if not source.is_file():
            die(f"fixture is incomplete: {source} listed in manifest but absent")
        destination = dst_cache / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def _narinfo_path(cache: Path, fixtures: Fixtures, attr: str) -> Path:
    return cache / fx.narinfo_name(fixtures.store_path(attr))


def secret_key_problems(served_cache: Path) -> list[str]:
    """Every *.sec anywhere under the tree that will be bind-mounted into a
    container. Empty list == AC#5 holds. A module function so the mutation test
    (inject a .sec, expect non-empty) can exercise it without a running pod.
    """
    root = Path(served_cache)
    return sorted(str(p.relative_to(root)) for p in root.rglob("*.sec"))


def build_tamper_tree(fixtures: Fixtures, scratch: Path, kind: str) -> Path:
    """Build a key-free scratch cache serving a tampered `app` (refs `lib`).

    The three tampers are the fixturelib reference implementation (check-
    fixtures.py's bites), but here they are served to a real nix-DAEMON, which
    enforces require-sigs daemon-side and ignores the caller's keys - a
    different proof from check-fixtures' direct-store mode (task-3 SCOPE note).
    """
    cache = scratch / "cache"
    _minimal_cache(fixtures, cache, ["app", "lib"])
    target = _narinfo_path(cache, fixtures, "app")
    pairs = fx.parse_narinfo(target.read_text())

    if kind == "corrupt-sig":
        name, _, b64 = fx.field(pairs, "Sig").partition(":")
        flipped = ("B" if b64[0] != "B" else "C") + b64[1:]
        pairs = fx.replace_field(pairs, "Sig", f"{name}:{flipped}")
    elif kind == "foreign-key":
        _n, foreign_private, _s, _p = fx.keypair(
            fx.FOREIGN_SEED_PHRASE, fx.FOREIGN_KEY_NAME
        )
        pairs = fx.sign_narinfo(pairs, foreign_private, fx.FOREIGN_KEY_NAME)
    elif kind == "narhash":
        _n, private, _s, _p = fx.keypair()
        alg, _, digest = fx.field(pairs, "NarHash").partition(":")
        chars = list(digest)
        chars[25] = "z" if chars[25] != "z" else "y"
        pairs = fx.replace_field(pairs, "NarHash", f"{alg}:{''.join(chars)}")
        pairs = fx.sign_narinfo(pairs, private, fx.KEY_NAME)
    else:
        die(f"unknown tamper kind {kind!r}")

    target.write_text(fx.format_narinfo(pairs))
    return cache


@dataclass
class P2pSeed:
    """One raw NAR node B will seed into its iroh provider, plus the NarHash it
    backs. `filename` is the file's in-mount name (/srv/seed/<filename>);
    `nar_hash` is the full `sha256:<base32>` the narinfo carries; `nar_size` is the
    uncompressed byte length node B's provider counter should report per serve."""

    filename: str
    nar_hash: str
    nar_size: int
    store_path: str


def build_p2p_seed_dir(
    fixtures: Fixtures, scratch: Path, attrs: list[str]
) -> tuple[Path, list[P2pSeed]]:
    """Materialise the RAW (uncompressed) NAR for each `attr` into a fresh scratch
    dir node B mounts and seeds. Already-raw NARs are copied; xz NARs are
    decompressed with stdlib `lzma` - so an `xz` fixture exercises the task-49
    compressed->raw narinfo rewrite while node B still serves the raw bytes whose
    sha256 is the signed NarHash (Nix's gate 2 re-checks that on the client, so a
    wrong decompression fails LOUD rather than silently). zstd is unsupported here
    (no stdlib codec); pick raw/xz attrs for S6.
    """
    seed_dir = scratch / "seed"
    seed_dir.mkdir(parents=True)
    seeds: list[P2pSeed] = []
    for attr in attrs:
        entry = fixtures.entry(attr)
        url = entry["url"]  # nar/<f>.nar[.xz|.zst]
        src = fixtures.cache / url
        nar_hash = entry["nar_hash"]  # sha256:<base32>
        digest = nar_hash.split(":", 1)[1]
        filename = f"{digest}.nar"
        dst = seed_dir / filename
        if url.endswith(".nar"):
            shutil.copy2(src, dst)
        elif url.endswith(".nar.xz"):
            dst.write_bytes(lzma.decompress(src.read_bytes()))
        else:
            die(f"build_p2p_seed_dir: no stdlib raw-NAR codec for {url!r} (use raw/xz)")
        actual = dst.stat().st_size
        if actual != entry["nar_size"]:
            die(
                f"raw NAR for {attr} is {actual} B but manifest NarSize is "
                f"{entry['nar_size']} B (decompression produced wrong bytes)"
            )
        seeds.append(
            P2pSeed(filename, nar_hash, entry["nar_size"], entry["store_path"])
        )
    return seed_dir, seeds


def libp2p_allowlist_volume(scratch: Path, tag: str) -> list[str]:
    """Create a PRIVATE (0755, NOT group/other-writable) host dir and return the podman
    `--volume` args mounting it writable at `LIBP2P_ALLOWLIST_MOUNT` for the provider's on-disk
    public-NAR allowlist (TASK-103). Rootless podman maps the host dir (owned by the runner) to
    container-root, so the store's euid-ownership + not-group/other-writable parent-dir checks
    both pass - unlike a shared 0777 /tmp, which the store rightly refuses as tamper-prone."""
    host_dir = (scratch / f"{tag}-allowlist").resolve()
    host_dir.mkdir(parents=True, exist_ok=True)
    host_dir.chmod(0o755)
    return ["--volume", f"{host_dir}:{LIBP2P_ALLOWLIST_MOUNT}"]


def build_corrupt_nar_tree(fixtures: Fixtures, scratch: Path) -> Path:
    """Build a key-free scratch cache serving `lib` with a PRISTINE, validly
    signed narinfo but a NAR whose content bytes are corrupted - so only the
    CONTENT-HASH gate can catch it (the signature still verifies).

    A byte is flipped DEEP in the payload region, not at offset 0. Flipping the
    archive magic (what testproxy's corrupt_nar fault does) makes nix fail with
    "input doesn't look like a Nix archive" - a NAR-PARSE error that proves
    nothing about the hash gate. `lib` is a 64 KiB uncompressed NAR, so a
    mid-file flip stays inside the file contents: the archive still parses and
    only the NarHash differs, yielding "hash mismatch importing path".
    """
    cache = scratch / "cache"
    _minimal_cache(fixtures, cache, ["lib"])
    nar = cache / fixtures.entry("lib")["url"]
    data = bytearray(nar.read_bytes())
    data[len(data) // 2] ^= 0xFF
    nar.write_bytes(bytes(data))
    return cache


# TASK-194 (191 AC#3): the STORE-supply provider's boot wrapper. It REALISES the real
# /nix/store path(s) into the provider's own store from the ORIGIN cache (require-sigs
# verified against the fixture key), asserts each is now a valid, dumpable store object,
# then `exec`s the daemon so the daemon becomes the container's main process (podman
# logs/kill still target it). The provider thus holds each path as UNPACKED FILES that nix
# manages - it never keeps a .nar at rest and regenerates the .nar on demand via
# `nix-store --dump` to serve peers. `set -euo pipefail` makes a failed realise or an
# un-dumpable path a LOUD abort BEFORE the daemon announces (never announce-then-decline).
_LIBP2P_PROVIDER_STORE_REALISE = r"""
set -euo pipefail
echo "STORE-SUPPLY: realising {store_paths} from {origin}"
nix-store --realise {store_paths} \
  --option substituters "{origin}" \
  --option trusted-public-keys "{key}" \
  --option require-sigs true \
  --option substitute true
for p in {store_paths}; do
  nix-store --dump "$p" >/dev/null
done
echo "STORE-SUPPLY: realised + dumpable; starting daemon"
exec {exec_cmd}
"""


# ---- the pod ---------------------------------------------------------------


def _canonical_narhash(value: str | None) -> str | None:
    """Normalise a NarHash to `sha256:<nix-base32>` (the manifest form).

    Accepts either that form (already canonical) or SRI `sha256-<base64>` as
    emitted by modern `nix path-info --json`. NarHash is sha256 of the NAR
    byte stream (`nix-store --dump`), so equality of the canonical value IS the
    bit-for-bit identity S1 requires.
    """
    if value is None:
        return None
    if ":" in value:  # already sha256:<nix-base32>
        return value
    if "-" in value:  # SRI: sha256-<base64>
        algo, _, b64 = value.partition("-")
        return f"{algo}:{fx.nix_base32(base64.b64decode(b64))}"
    return value


@dataclass
class ClientResult:
    exit_code: int
    stdout: str
    stderr: str
    path_info: dict = field(default_factory=dict)

    def narhash(self, store_path: str) -> str | None:
        """NarHash for a realised path in the manifest's `sha256:<nix-base32>`
        form, or None. Modern `nix path-info --json` keys by store path and
        reports SRI `sha256-<base64>`; we canonicalise so the byte oracle can
        compare against the signed manifest hash regardless of nix's encoding.
        """
        info = self.path_info
        raw = None
        if isinstance(info, dict):
            entry = info.get(store_path)
            if isinstance(entry, dict):
                raw = entry.get("narHash")
            if raw is None:
                for value in info.values():
                    if isinstance(value, dict) and value.get("path") == store_path:
                        raw = value.get("narHash")
                        break
        elif isinstance(info, list):
            for value in info:
                if isinstance(value, dict) and value.get("path") == store_path:
                    raw = value.get("narHash")
                    break
        return _canonical_narhash(raw)


class Pod:
    """A running scenario topology in one rootless podman pod.

    origin (serves `served_cache` over HTTP) + testproxy + optionally daemon.
    Ports are published to the host so oracles run host-side. Use as a context
    manager so teardown is guaranteed even on an assertion failure.
    """

    def __init__(
        self,
        ctx: Ctx,
        name: str,
        served_cache: Path,
        with_daemon: bool,
        expect,
        daemon_extra_args: tuple[str, ...] = (),
        daemon_chain: int = 0,
        p2p_seed_dir: Path | None = None,
        p2p_seeds: tuple[P2pSeed, ...] = (),
        p2p_claim_overrides: dict[str, str] | None = None,
        p2p_holders: int = 1,
        state_root: Path | None = None,
        libp2p_seed_dir: Path | None = None,
        libp2p_provider_seeds: tuple[P2pSeed, ...] = (),
        libp2p_trusted_key: str | None = None,
        libp2p_store_supply: bool = False,
        libp2p_announce_after_fetch: bool = False,
        libp2p_announce_budget: int = 256,
        libp2p_leech: bool = False,
        libp2p_consumer_status_port: int | None = None,
    ):
        self.ctx = ctx
        self.pod = f"{POD_PREFIX}-{name}"
        self.served_cache = served_cache
        # p2p (task-41, S6): a TWO-NODE topology - node B runs an iroh provider
        # seeded from `p2p_seed_dir`, node A is wired to fetch those NARs from B
        # over iroh. Mutually exclusive with the single-daemon / chain paths. The
        # two nodes share the pod's loopback netns, so node A dials node B's iroh
        # endpoint on 127.0.0.1 (verified this crosses the container sandbox netns).
        self.p2p = bool(p2p_seeds)
        self.p2p_seed_dir = p2p_seed_dir
        self.p2p_seeds = tuple(p2p_seeds)
        # Optional per-NarHash blake3 override (the corruption bite): serve a claim
        # whose content id points at a DIFFERENT seeded file, so node A fetches a
        # valid-but-wrong NAR that passes the transport gate yet fails Nix's
        # sha256==NarHash gate. Maps nar_hash -> the filename whose blake3 to use.
        self.p2p_claim_overrides = dict(p2p_claim_overrides or {})
        # SWARM (task-42): how many HOLDER peers this p2p pod runs. 1 is the
        # task-41 two-node S6 topology and is what every existing scenario gets,
        # byte-for-byte unchanged. N > 1 adds node-b2..node-bN, each a real,
        # independently-seeded iroh provider process, so a resource sweep has a
        # peer-count axis with REAL points instead of extrapolating from 2.
        #
        # HONEST LIMITATION, stated where it is created rather than discovered in
        # the report: node A's claims all name holder `node-b`. `InMemoryDiscovery
        # ::announce` REPLACES on key, so a multi-holder claim cannot be expressed
        # through `--p2p-claim` today (last write wins) - the swarm therefore
        # measures what N peer PROCESSES plus an N-entry peer address book cost,
        # NOT holder-selection or dial fan-out across N candidates. Multi-holder
        # claims are TASK-43/47 territory.
        self.p2p_holders = int(p2p_holders)
        if self.p2p and not (1 <= self.p2p_holders <= MAX_P2P_HOLDERS):
            die(
                f"Pod: p2p_holders={self.p2p_holders} outside 1..{MAX_P2P_HOLDERS} "
                "(higher counts collide with other published host ports)"
            )
        # libp2p (S7, TASK-161): a THREE-daemon decentralized topology - a dedicated
        # BOOT node (a PURE kad router, FIXED identity, holds NO content and never
        # announces), a PROVIDER `P` that seeds the real target NAR and joins the DHT
        # through BOOT (so its put-provider reaches quorum against a reachable BOOT -
        # a lone genesis provider cannot), and a CONSUMER `C` wired to bootstrap off
        # BOOT ALONE - never told P's dial address. C discovers P via libp2p-kad
        # get_providers and resolves P's dial address via kad peer-routing (both inside
        # the fabric, TASK-159/169). Mutually exclusive with the iroh p2p and the plain
        # daemon/chain paths. All three share the pod's loopback netns (an HONEST scope
        # limit vs a separate-netns routed network - see `_create_libp2p`). BOOT (C's
        # only direct peer) holding NO content is what makes the F1 load-bearing
        # control clean: peer-served target bytes can ONLY have come from a
        # DHT-discovered+resolved dial to P.
        self.libp2p = bool(libp2p_provider_seeds)
        self.libp2p_seed_dir = libp2p_seed_dir
        self.libp2p_provider_seeds = tuple(libp2p_provider_seeds)
        # TASK-103: the trusted narinfo-signing key (the fixture cache key) the PROVIDER
        # must be handed so it can PROVE each seeded NAR public before announcing it over the
        # bootstrapped (public) DHT. When set, `_create_libp2p` opens a real public-NAR
        # allowlist on P, proves each seed's narinfo (mounted read-only under the seed dir)
        # public, and routes the announce through the allowlist gate - the LEGITIMATE
        # public-participation path that replaces the isolated-LAN refusal stopgap.
        self.libp2p_trusted_key = libp2p_trusted_key
        # TASK-194 (191 AC#3): STORE-supply provider mode. When True the provider does NOT
        # mount any .nar file; instead it REALISES the real /nix/store path(s) from the origin
        # cache at boot and serves each on demand via `nix-store --dump` (holding NO .nar at
        # rest), announced through the SAME verification-gated store path as the shipped daemon
        # (`--libp2p-provide-store`). `libp2p_seed_dir` then carries ONLY the signed narinfos
        # (mounted under /srv/seed/narinfos/) needed to prove each path public - never a .nar.
        self.libp2p_store_supply = bool(libp2p_store_supply)
        if self.libp2p_store_supply and not libp2p_trusted_key:
            die(
                "Pod: libp2p_store_supply requires libp2p_trusted_key (public-narinfo proof)"
            )
        # TASK-77 (announce-after-fetch): the provider `A` starts with NO static supply set +
        # `--libp2p-announce-after-fetch`. It holds nothing at boot; a scenario drives A's OWN
        # daemon to fetch the target from upstream (which materialises the path into A's store and
        # fires the announce), so a second consumer `B` can then discover A via kad and fetch from
        # it - the swarm GROWS. A learns the public allowlist DYNAMICALLY from the narinfo it
        # fetches (no `--libp2p-prove-public-narinfo` staging), so it still requires the trusted key.
        self.libp2p_announce_after_fetch = bool(libp2p_announce_after_fetch)
        self.libp2p_announce_budget = int(libp2p_announce_budget)
        # TASK-78 (leech / consume-only): the node in the PROVIDER slot `A` is instead launched as a
        # `--libp2p-leech` CONSUMER - it fetches the target through its own daemon (so it HOLDS the
        # path in its store) but its fabric is wrapped in a LeechFabric, so it SERVES nothing and
        # ANNOUNCES nothing. The second consumer `B` therefore finds NO provider record for the
        # target (A, the only holder, is a leech) and must fall back to upstream. This is the
        # peer-side proof that a leech gives nothing back; the mutation is running the SAME topology
        # with A as an announce-after-fetch provider (0 upstream on B instead of >=1). A leech needs
        # no trusted key / allowlist (it never announces), so those are not required here.
        self.libp2p_leech = bool(libp2p_leech)
        # TASK-242 item 3: when set, the CONSUMER runs the primary `/bin/daemon-libp2p` binary (the
        # one carrying the operator observability surface) with `--status-listen 127.0.0.1:<port>`,
        # so the containerized dependency-outage drill can read the LIVE `/nix-p2p/status` surface
        # from inside the consumer container (via `podman exec`) and watch bootstrap health flip when
        # BOOT is killed. `None` (every existing scenario) leaves the consumer on `/bin/daemon` with
        # no admin surface — byte-identical to before.
        self.libp2p_consumer_status_port = (
            int(libp2p_consumer_status_port)
            if libp2p_consumer_status_port is not None
            else None
        )
        if self.libp2p_consumer_status_port is not None and not self.libp2p:
            die("Pod: libp2p_consumer_status_port requires a libp2p provider topology")
        if self.libp2p_leech and (
            self.libp2p_announce_after_fetch or self.libp2p_store_supply
        ):
            die(
                "Pod: libp2p_leech (consume-only) is mutually exclusive with the "
                "announce-after-fetch / store-supply provider modes"
            )
        if self.libp2p_announce_after_fetch and not libp2p_trusted_key:
            die(
                "Pod: libp2p_announce_after_fetch requires libp2p_trusted_key (the public-announce "
                "door proves each fetched path public via a trusted narinfo signature)"
            )
        # Parsed once the provider announces; the positive oracle reads it to assert C
        # was NEVER configured with it (no-injection).
        self.libp2p_provider_identity: tuple[str, str] | None = None
        # The EXACT bootstrap entry (`<PeerId>@<multiaddr>`) the consumer is supposed to
        # be given - the real BOOT node and nothing else - recorded when the topology is
        # launched so the strengthened no-injection oracle can assert the consumer's
        # `--libp2p-bootstrap` set is EXACTLY this (no provider addr smuggled in as a
        # second bootstrap entry under a decoy PeerId).
        self.libp2p_boot_peer_entry: str | None = None
        # Every dial address the provider actually listens on (its configured
        # `--libp2p-listen` AND the address it announces/resolves to). The oracle asserts
        # NO consumer bootstrap entry resolves to any of these (out-of-band injection).
        self.libp2p_provider_listen_addrs: set[str] = set()
        if self.libp2p and (with_daemon or daemon_chain or bool(p2p_seeds)):
            die("Pod: libp2p is mutually exclusive with with_daemon/daemon_chain/p2p")
        # Optional HOST directory under which each daemon role gets its own
        # bind-mounted state dir (used as `--narinfo-cache-dir`). Present so
        # task-42 can measure a node's on-disk footprint by walking the host side
        # of the mount - the only observation point that needs no binary inside
        # the image. None means there is no host-persisted state mount; the daemon
        # may still keep pod-local state for the lifetime of its container.
        self.state_root = Path(state_root).resolve() if state_root else None
        # Parsed once node B announces (node_id, sockets); oracles read it.
        self.iroh_identity: tuple[str, str] | None = None
        if self.p2p and (with_daemon or daemon_chain):
            die("Pod: p2p is mutually exclusive with with_daemon / daemon_chain")
        # `daemon_chain=N` (task-11) runs N product daemons in series:
        # client -> daemon-1 -> ... -> daemon-N -> testproxy. It is mutually
        # exclusive with the single-daemon `with_daemon` path so the 15 existing
        # scenarios keep starting the daemon exactly as before (role "daemon"),
        # while chain scenarios opt in explicitly (roles "daemon-1".."daemon-N").
        self.daemon_chain = int(daemon_chain)
        if self.daemon_chain and with_daemon:
            die("Pod: pass either with_daemon or daemon_chain=N, not both")
        if self.daemon_chain < 0:
            die(f"Pod: daemon_chain must be >= 0, got {self.daemon_chain}")
        if self.daemon_chain > MAX_DAEMON_CHAIN:
            die(
                f"Pod: daemon_chain={self.daemon_chain} exceeds MAX_DAEMON_CHAIN "
                f"({MAX_DAEMON_CHAIN}); higher hop counts collide with other host ports"
            )
        self.with_daemon = with_daemon
        # Extra daemon CLI flags (task-9 product-side bite passes
        # --narinfo-cache-dir to toggle task-8's narinfo cache). Empty by default
        # so every existing scenario starts the daemon exactly as before.
        self.daemon_extra_args = tuple(daemon_extra_args)
        self._pm = ctx.podman
        # Every pod that mounts a cache asserts AC#5, so the key-exclusion oracle
        # covers all 8 scenarios, not a hand-picked few.
        self._expect = expect

    def __enter__(self) -> Pod:
        self._assert_no_secret_key_served()
        self._create()
        return self

    def __exit__(self, *_exc) -> None:
        self.stop()

    def _c(self, role: str) -> str:
        return f"{self.pod}-{role}"

    def container(self, role: str) -> str:
        """The podman container name for `role`. Public because the task-18
        scale sweep resolves each node's HOST pid from it; reaching into `_c`
        from another module would make a private name load-bearing."""
        return self._c(role)

    def roles(self) -> list[str]:
        """Every long-lived role in this pod, in topology order. Clients are
        NOT here: they are ephemeral `--rm` containers, not pod members."""
        return ["origin", "proxy", *self._daemon_roles()]

    def daemon_roles(self) -> list[str]:
        """The product-daemon roles only (public view of `_daemon_roles`), so a
        resource sweep can tell a daemon apart from the fixture infrastructure
        it is measured against."""
        return self._daemon_roles()

    def host_pid(self, role: str) -> int:
        """The HOST pid of `role`'s init process (rootless podman runs it as our
        own uid, so /proc/<pid>/status and /proc/<pid>/fd are readable directly -
        no binary needs to exist inside the image, which is what killed an
        earlier in-container oracle that silently returned rc=127).

        FAIL-CLOSED: a missing or zero pid raises. 'Could not observe' must never
        be reportable as a resource sample."""
        result = run(
            [self._pm, "inspect", "-f", "{{.State.Pid}}", self._c(role)], check=False
        )
        raw = (result.stdout or "").strip()
        try:
            pid = int(raw)
        except ValueError:
            raise RuntimeError(
                f"host_pid({role!r}): podman inspect returned {raw!r} "
                f"(rc={result.returncode}, stderr={result.stderr.strip()!r})"
            ) from None
        if pid <= 0:
            raise RuntimeError(
                f"host_pid({role!r}): pid {pid} - the container is not running"
            )
        return pid

    def _daemon_roles(self) -> list[str]:
        """The daemon container roles this pod runs, in chain order (the FIRST
        is the chain head the client substitutes against). One "daemon" for the
        single-daemon path; "daemon-1".."daemon-N" for a `daemon_chain=N` pod."""
        if self.libp2p:
            # lp-consumer (index 0 -> DAEMON_PORT) is the client's substituter, so the
            # generic publish/await/HTTP loops map it to the standard daemon ports.
            # lp-provider (+1) holds the target NAR; lp-boot (+2) is the dedicated
            # bootstrap (a pure kad router, no content). Bring-up order (BOOT, then P,
            # then C) is handled in `_create_libp2p`; this list is the PORT/HTTP order.
            return ["lp-consumer", "lp-provider", "lp-boot"]
        if self.p2p:
            # node-a (index 0 -> DAEMON_PORT, the client's substituter) first so
            # the generic publish/await loops map it to the standard daemon ports;
            # node-b (index 1 -> DAEMON_PORT+1) is the iroh provider that every
            # claim names. node-b2..node-bN (task-42 swarm) are additional real
            # provider processes at DAEMON_PORT+2.. - the peer-count axis.
            return ["node-a", "node-b"] + [
                f"node-b{i}" for i in range(2, self.p2p_holders + 1)
            ]
        if self.daemon_chain:
            return [f"daemon-{i}" for i in range(1, self.daemon_chain + 1)]
        if self.with_daemon:
            return ["daemon"]
        return []

    def daemon_host_port(self, index: int = 1) -> int:
        """Host-published port forwarding to daemon #index (1-based), for
        host-side oracles that time or probe a specific entry point. Entering
        the chain at daemon #i traverses (len(chain) - i + 1) hops, so daemon-1
        is the DEEPEST entry (full depth) and daemon-N is a single hop - the
        seam the timeout-invariant oracle uses to isolate the per-hop latency."""
        return HOST_DAEMON + (index - 1)

    def state_dir(self, role: str) -> Path:
        """HOST path backing `role`'s in-container state mount. Raises when the
        pod has no `state_root` - a caller asking for a footprint the pod was
        never configured to keep must fail loudly, not receive an empty dir that
        would measure as a comfortable 0 bytes."""
        if self.state_root is None:
            raise RuntimeError(
                f"state_dir({role!r}): this pod was created without state_root, "
                "so it has no on-disk state to measure (0 would be a lie)"
            )
        return self.state_root / role

    def _state_args(self, role: str) -> list[str]:
        """`podman run` fragments giving `role` its own host-backed state dir.

        Empty for a pod without `state_root`, so no daemon state is persisted or
        measured on the host. This does not make the daemon stateless inside its
        container."""
        if self.state_root is None:
            return []
        host_dir = self.state_dir(role)
        host_dir.mkdir(parents=True, exist_ok=True)
        return ["--volume", f"{host_dir}:{DAEMON_STATE_MOUNT}"]

    def _libp2p_allowlist_args(self) -> list[str]:
        """Podman `--volume` args mounting a private host dir for P's public-NAR allowlist
        (TASK-103). Delegates to the shared `libp2p_allowlist_volume` so the shared-pod and
        separate-netns topologies stage it identically."""
        return libp2p_allowlist_volume(self.ctx.scratch, self.pod)

    def _daemon_state_flags(self) -> list[str]:
        """Daemon CLI flags matching `_state_args`'s mount. Kept beside it so the
        mount and the flag that uses it cannot drift apart."""
        if self.state_root is None:
            return []
        return ["--narinfo-cache-dir", DAEMON_STATE_MOUNT]

    def _iroh_runtime_flags(self, role: str) -> list[str]:
        """Hermetic Iroh runtime inputs for p2p scenarios.

        Each daemon container has its own filesystem/state mount, so the same
        in-container path is node-local. The explicit offline scope is part of
        the test contract: no relay, address lookup, port mapping or public bind.
        """
        parent = DAEMON_STATE_MOUNT if self.state_root is not None else "/tmp"
        try:
            role_offset = self._daemon_roles().index(role)
        except ValueError as error:
            raise RuntimeError(
                f"unknown daemon role for Iroh port: {role!r}"
            ) from error
        return [
            "--iroh-state-dir",
            f"{parent}/iroh",
            "--iroh-endpoint-scope",
            "offline-test",
            "--iroh-port",
            str(36000 + role_offset),
        ]

    def _assert_no_secret_key_served(self) -> None:
        """AC#5, observed at the RIGHT boundary: walk the exact host tree that
        gets bind-mounted into the origin and assert no *.sec is under it.

        HOST-SIDE on purpose. The previous version shelled `find` INSIDE the
        container, but findutils is not in the image (buildEnv ships coreutils),
        so `podman exec ... find` returned rc=127 with empty stdout and the
        check passed unconditionally - a dead oracle that stayed green even with
        a real .sec injected into the served cache. We already hold the resolved
        host path (`served_cache`); walking it needs no container binary and
        observes precisely the bytes the origin will serve.
        """
        leaked = secret_key_problems(self.served_cache)
        self._expect(
            not leaked,
            "AC#5: no *.sec under the served cache tree (host-side walk)",
            f"leaked: {leaked}",
        )
        if leaked:
            # Trust invariant: a DETECTED secret must NEVER be mounted. Abort
            # before _create() rather than record-and-continue - the previous
            # version recorded the failing check but still called _create(), so
            # the injected key was bind-mounted and served at HTTP 200 (codex
            # re-gate finding). run_scenarios turns this raise into a failing
            # scenario; the key never enters a container.
            raise RuntimeError(
                f"AC#5 abort: secret key(s) {leaked} present in the served "
                "cache tree; refusing to mount"
            )
        # Meaningful only because the key really exists beside the cache: assert
        # that too, so this proves absence-FROM-THE-SERVED-TREE, not that no key
        # exists anywhere.
        gen_secrets = sorted(p.name for p in self.ctx.fixtures.generation.glob("*.sec"))
        self._expect(
            len(gen_secrets) >= 1,
            "AC#5 precondition: the signing key exists in the generation root",
            f"found {gen_secrets}",
        )

    def _create(self) -> None:
        # Remove a stale pod of the same name first (a previous crashed run).
        run([self._pm, "pod", "rm", "-f", "--ignore", self.pod], check=False)
        # Publish origin + proxy, plus one host port per daemon hop so a
        # per-entry-point oracle can probe any hop directly (host-side). The
        # single-daemon path publishes exactly 18082->8082 as before.
        publish = [
            "-p",
            f"127.0.0.1:{HOST_ORIGIN}:{ORIGIN_PORT}",
            "-p",
            f"127.0.0.1:{HOST_PROXY}:{PROXY_PORT}",
        ]
        for i, _role in enumerate(self._daemon_roles()):
            publish += ["-p", f"127.0.0.1:{HOST_DAEMON + i}:{DAEMON_PORT + i}"]
        run(
            [
                self._pm,
                "pod",
                "create",
                "--name",
                self.pod,
                "--label",
                PROJECT_LABEL,
                *publish,
            ]
        )
        # origin: static file server over the served cache (bind-mount, :ro).
        run(
            [
                self._pm,
                "run",
                "-d",
                "--pod",
                self.pod,
                "--name",
                self._c("origin"),
                "--label",
                PROJECT_LABEL,
                "--volume",
                f"{self.served_cache}:/srv/cache:ro",
                self.ctx.image,
                "python3",
                "-m",
                "http.server",
                str(ORIGIN_PORT),
                # 0.0.0.0, not loopback: rootless podman forwards a published
                # port to the container over a NON-loopback address, so a
                # loopback-only bind is unreachable from the host (host-verified).
                # Siblings still reach it on 127.0.0.1 - 0.0.0.0 covers loopback.
                "--bind",
                "0.0.0.0",
                "--directory",
                "/srv/cache",
            ]
        )
        # testproxy: caching proxy fronting origin; its request log is the oracle.
        run(
            [
                self._pm,
                "run",
                "-d",
                "--pod",
                self.pod,
                "--name",
                self._c("proxy"),
                "--label",
                PROJECT_LABEL,
                self.ctx.image,
                "/bin/testproxy",
                "--listen",
                f"0.0.0.0:{PROXY_PORT}",
                "--upstream",
                f"http://127.0.0.1:{ORIGIN_PORT}",
                "--cache-dir",
                "/tmp/proxy-cache",
            ]
        )
        # Daemons, in chain order. Each hop's upstream is the NEXT daemon in the
        # chain; the LAST hop's upstream is the testproxy. So the client enters
        # at daemon-1 and its request threads every daemon before reaching the
        # cache boundary (the only route from client to testproxy) - which is
        # exactly why the testproxy request count at depth-N proves the whole
        # chain carried the payload, no hop skipped.
        if self.libp2p:
            self._create_libp2p()
        elif self.p2p:
            self._create_p2p()
        else:
            roles = self._daemon_roles()
            for i, role in enumerate(roles):
                in_port = DAEMON_PORT + i
                if i + 1 < len(roles):
                    upstream = f"http://127.0.0.1:{DAEMON_PORT + i + 1}"
                else:
                    upstream = f"http://127.0.0.1:{PROXY_PORT}"
                run(
                    [
                        self._pm,
                        "run",
                        "-d",
                        "--pod",
                        self.pod,
                        "--name",
                        self._c(role),
                        "--label",
                        PROJECT_LABEL,
                        *self._state_args(role),
                        self.ctx.image,
                        "/bin/daemon",
                        "--listen",
                        f"0.0.0.0:{in_port}",
                        "--upstream",
                        upstream,
                        *self._daemon_state_flags(),
                        *self.daemon_extra_args,
                    ]
                )
        self._await_ready()

    def _create_p2p(self) -> None:
        """Two-phase p2p bring-up (S6, swarm-capable): start every HOLDER node
        (iroh provider, seeded), read each announced iroh identity + per-blob
        content ids from its log, then start node A wired to dial ALL of them and
        to claim each NarHash from `node-b`. Node A can only be configured AFTER
        the holders announce, so this cannot use the single-shot loop.

        With `p2p_holders=1` this is exactly the task-41 two-node S6 topology.
        With N > 1 it is a swarm of N independent provider PROCESSES - the
        peer-count axis task-42 fits. Every holder seeds the SAME NARs, so the
        per-node cost is comparable across the swarm; only node-b is claimed
        (see `p2p_holders` for why a multi-holder claim is not expressible yet).
        """
        node_a_port = DAEMON_PORT  # index 0: the client's substituter target
        proxy = f"http://127.0.0.1:{PROXY_PORT}"

        # -- holders: provider + HTTP daemon, each seeded with every raw NAR --
        seed_args: list[str] = []
        for seed in self.p2p_seeds:
            seed_args += ["--iroh-seed-nar", f"/srv/seed/{seed.filename}"]
        if self.p2p_seed_dir is None:
            die("Pod: p2p_seeds given without p2p_seed_dir")
        holder_roles = self._daemon_roles()[1:]
        for offset, role in enumerate(holder_roles):
            run(
                [
                    self._pm,
                    "run",
                    "-d",
                    "--pod",
                    self.pod,
                    "--name",
                    self._c(role),
                    "--label",
                    PROJECT_LABEL,
                    "--volume",
                    f"{self.p2p_seed_dir}:/srv/seed:ro",
                    *self._state_args(role),
                    self.ctx.image,
                    "/bin/daemon",
                    "--listen",
                    f"0.0.0.0:{DAEMON_PORT + 1 + offset}",
                    "--upstream",
                    proxy,
                    "--iroh-provider",
                    "--iroh-print-peer-address",
                    *self._iroh_runtime_flags(role),
                    *self._daemon_state_flags(),
                    *seed_args,
                ]
            )
        # Await each holder's identity SEPARATELY. Fail-closed by construction:
        # `_await_iroh_identity` dies if a holder never announces, so a swarm
        # point can never be recorded with a node that silently failed to come up.
        holders: list[tuple[str, str, dict[str, str]]] = [
            self._await_iroh_identity(role, len(self.p2p_seeds))
            for role in holder_roles
        ]
        node_id, sockets, blake3_by_path = holders[0]
        self.iroh_identity = (node_id, sockets)

        # -- node A: iroh client wired to EVERY holder's identity + one claim per
        # seed (all naming holder 0, `node-b`) --
        peer_args: list[str] = []
        for holder_id, holder_sockets, _ in holders:
            peer_args += ["--iroh-peer", f"{holder_id}@{holder_sockets}"]
        claim_args: list[str] = []
        for seed in self.p2p_seeds:
            # The corruption bite points a NarHash at a DIFFERENT file's blake3.
            src_file = self.p2p_claim_overrides.get(seed.nar_hash, seed.filename)
            blake3 = blake3_by_path.get(f"/srv/seed/{src_file}")
            if blake3 is None:
                self._dump_logs()
                die(f"node B never announced a blake3 for /srv/seed/{src_file}")
            claim_args += ["--p2p-claim", f"{seed.nar_hash}={blake3}@{node_id}"]
        run(
            [
                self._pm,
                "run",
                "-d",
                "--pod",
                self.pod,
                "--name",
                self._c("node-a"),
                "--label",
                PROJECT_LABEL,
                *self._state_args("node-a"),
                self.ctx.image,
                "/bin/daemon",
                "--listen",
                f"0.0.0.0:{node_a_port}",
                "--upstream",
                proxy,
                *self._iroh_runtime_flags("node-a"),
                *peer_args,
                *claim_args,
                *self._daemon_state_flags(),
                *self.daemon_extra_args,
            ]
        )

    def _create_libp2p(self) -> None:
        """Three-daemon decentralized libp2p bring-up (S7, TASK-161).

        Order matters: P (and C) must bootstrap to a REACHABLE BOOT, or P's
        put-provider announce cannot reach quorum (a lone genesis provider fails with
        "the quorum failed; needed 1 peers").

          1. BOOT: a PURE kad router - a consumer-shaped daemon (NOT a provider, so it
             never announces) with the FIXED LIBP2P_BOOT_SEED_HEX identity, so its
             PeerId (LIBP2P_BOOT_PEER_ID) is known offline without a printed-address
             round-trip. It requires a bootstrap peer like any libp2p daemon, so it
             points at LIBP2P_DUMMY_PEER (valid format, unreachable); its self-lookup
             fails best-effort and it still binds as a lone router. We wait for its HTTP
             readiness (a proxy for "kad listener bound") BEFORE starting P.
          2. P (provider): seeds the REAL target NAR, bootstraps to BOOT, joins the DHT
             and ANNOUNCES (quorum satisfied by the reachable BOOT). identify tells BOOT
             P's dial address - the address C later resolves via kad peer-routing. We
             read P's LIBP2P-PROVIDER-ADDR and stash it so the oracle can assert C was
             NEVER configured with it.
          3. C (consumer): bootstraps to BOOT ALONE. NO --libp2p-provider-addr. Its
             libp2p NarSource discovers P (get_providers) and resolves P's dial address
             (peer-routing) with zero injection.

        HONEST SCOPE (stated here, not discovered in the report): all three share the
        pod's loopback netns, so dial addresses are 127.0.0.1:<port>. This is NOT a
        separate-netns routed network; it proves the multi-PROCESS decentralized
        discover->resolve->fetch->serve path and the no-injection wiring, but it does
        not exercise NAT/routable-address handling, and it cannot fully isolate the
        peer-ROUTING (address-resolution) leg from an address an earlier kad query may
        have populated in the shared routing table (transport.rs's stated limit). The
        F1 load-bearing arm is discharged by BOOT holding NO content: peer-served target
        bytes can only have come from a DHT-mediated dial to P.
        """
        if self.libp2p_seed_dir is None:
            die("Pod: libp2p topology given seeds without libp2p_seed_dir")
        proxy = f"http://127.0.0.1:{PROXY_PORT}"
        boot_peer = f"{LIBP2P_BOOT_PEER_ID}@/ip4/127.0.0.1/tcp/{LIBP2P_BASE_PORT + 2}"
        # SSOT for the no-injection oracle: the ONE bootstrap entry the consumer is
        # allowed to carry, and the provider's dial address it must never carry.
        self.libp2p_boot_peer_entry = boot_peer
        self.libp2p_provider_listen_addrs = {
            f"/ip4/127.0.0.1/tcp/{LIBP2P_BASE_PORT + 1}"
        }

        # 1. BOOT: a pure kad router (fixed identity, no provider, no announce).
        run(
            [
                self._pm,
                "run",
                "-d",
                "--pod",
                self.pod,
                "--name",
                self._c("lp-boot"),
                "--label",
                PROJECT_LABEL,
                *self._state_args("lp-boot"),
                self.ctx.image,
                "/bin/daemon",
                "--listen",
                f"0.0.0.0:{DAEMON_PORT + 2}",
                "--upstream",
                proxy,
                "--libp2p-listen",
                f"/ip4/127.0.0.1/tcp/{LIBP2P_BASE_PORT + 2}",
                "--libp2p-bootstrap",
                f"{LIBP2P_DUMMY_PEER}@/ip4/127.0.0.1/tcp/1",
                "--libp2p-identity-seed",
                LIBP2P_BOOT_SEED_HEX,
                "--libp2p-scope",
                LIBP2P_SCOPE,
                *self._daemon_state_flags(),
            ]
        )
        # BOOT must be reachable before P announces; its HTTP readiness is our gate.
        self._await_http_ready("lp-boot", 2)

        # TASK-78: in LEECH mode the node in the provider slot `A` is a consume-only leech, launched
        # by a dedicated path that keeps the non-leech provider topology below byte-identical.
        if self.libp2p_leech:
            self._create_libp2p_leech(boot_peer, proxy)
            return

        # 2. P (provider): seeds the real target, bootstraps to BOOT, announces.
        seed_args: list[str] = []
        if self.libp2p_announce_after_fetch:
            # TASK-77: node A holds NOTHING at boot; it becomes a holder by FETCHING. It runs in
            # public-announce mode (trusted key + a writable allowlist file) but learns the
            # allowlist DYNAMICALLY from the narinfo it fetches, so NO `--libp2p-prove-public-narinfo`
            # staging and NO seed/provide-store args. The scenario drives A's own daemon to fetch.
            seed_args += [
                "--libp2p-announce-after-fetch",
                "--libp2p-announce-budget",
                str(self.libp2p_announce_budget),
            ]
        elif self.libp2p_store_supply:
            # STORE-supply (TASK-194): serve the REAL realised /nix/store path via
            # `nix-store --dump` on demand - NO .nar mounted, nothing at rest. The narhash
            # binds the announce to the signed NarHash exactly as the seed path does.
            for s in self.libp2p_provider_seeds:
                seed_args += ["--libp2p-provide-store", f"{s.nar_hash}={s.store_path}"]
        else:
            for s in self.libp2p_provider_seeds:
                seed_args += [
                    "--libp2p-seed-nar",
                    f"{s.nar_hash}=/srv/seed/{s.filename}",
                ]
        # TASK-103 PUBLIC-announce door: hand P the trusted narinfo-signing key + an on-disk
        # allowlist, and PROVE each seeded NAR public through its signed narinfo. Only then does P
        # legitimately announce over the bootstrapped (public) DHT - the allowlist gate replaces
        # the isolated-LAN refusal. The allowlist lives on a DEDICATED writable mount (NOT /tmp:
        # the store refuses a world-writable parent dir, a real anti-tamper check); the host dir is
        # created 0755 and rootless-podman maps it to container-root, satisfying the euid check.
        allowlist_mount = (
            self._libp2p_allowlist_args() if self.libp2p_trusted_key else []
        )
        if self.libp2p_trusted_key:
            seed_args += [
                "--libp2p-trusted-public-key",
                self.libp2p_trusted_key,
                "--libp2p-public-allowlist-path",
                f"{LIBP2P_ALLOWLIST_MOUNT}/allowlist",
            ]
            # Announce-after-fetch (TASK-77) learns the allowlist from the narinfo it FETCHES at
            # runtime, so it stages NO prove-public-narinfo files; the static providers do.
            if not self.libp2p_announce_after_fetch:
                for s in self.libp2p_provider_seeds:
                    sh = libp2p_store_hash(s.store_path)
                    seed_args += [
                        "--libp2p-prove-public-narinfo",
                        f"{sh}=/srv/seed/narinfos/{sh}.narinfo",
                    ]
        # TASK-77: an announce-after-fetch node A fetches its content THROUGH ITS OWN DAEMON. If
        # that daemon's upstream were the testproxy, A's first fetch would WARM the proxy's NAR
        # cache, so a later consumer B could be served by the warm cache rather than by A - and the
        # kill-A control could no longer force an origin miss (the growth would be un-attributable).
        # So A's daemon fetches DIRECTLY from the ORIGIN (bypassing the proxy), keeping the proxy
        # cache COLD, exactly as the S8 store-supply provider realises from the origin. B's daemon
        # still fronts the proxy, so B's serve is cleanly attributable: 0 proxy egress <=> A served.
        provider_upstream = (
            f"http://127.0.0.1:{ORIGIN_PORT}"
            if self.libp2p_announce_after_fetch
            else proxy
        )
        daemon_argv = [
            "/bin/daemon",
            "--listen",
            f"0.0.0.0:{DAEMON_PORT + 1}",
            "--upstream",
            provider_upstream,
            "--libp2p-provider",
            "--libp2p-listen",
            f"/ip4/127.0.0.1/tcp/{LIBP2P_BASE_PORT + 1}",
            "--libp2p-bootstrap",
            boot_peer,
            "--libp2p-scope",
            LIBP2P_SCOPE,
            "--libp2p-print-peer-address",
            *seed_args,
            *self._daemon_state_flags(),
        ]
        # STORE-supply (TASK-194): before the daemon starts, REALISE the real store path(s)
        # into THIS provider's /nix/store from the ORIGIN (not the proxy - keeps the proxy's
        # NAR cache cold so the kill-P control below is a true upstream miss). Then `exec` the
        # daemon, which serves each path via `nix-store --dump` on demand and holds NO .nar.
        # Fail-loud: a failed realise or an un-dumpable path aborts before any announce.
        if self.libp2p_store_supply:
            store_paths = " ".join(
                shlex.quote(s.store_path) for s in self.libp2p_provider_seeds
            )
            realise_script = _LIBP2P_PROVIDER_STORE_REALISE.format(
                store_paths=store_paths,
                origin=f"http://127.0.0.1:{ORIGIN_PORT}",
                key=self.libp2p_trusted_key,
                exec_cmd=" ".join(shlex.quote(a) for a in daemon_argv),
            )
            container_cmd = ["bash", "-c", realise_script]
        else:
            container_cmd = daemon_argv
        run(
            [
                self._pm,
                "run",
                "-d",
                "--pod",
                self.pod,
                "--name",
                self._c("lp-provider"),
                "--label",
                PROJECT_LABEL,
                "--volume",
                f"{self.libp2p_seed_dir}:/srv/seed:ro",
                *allowlist_mount,
                *self._state_args("lp-provider"),
                self.ctx.image,
                *container_cmd,
            ]
        )
        # Announce-after-fetch node A prints NO seed/provide-store lines at boot (it holds nothing
        # yet), so await only its LIBP2P-PROVIDER-ADDR; a static provider awaits its N seed lines.
        n_startup_seeds = (
            0 if self.libp2p_announce_after_fetch else len(self.libp2p_provider_seeds)
        )
        prov_id, prov_listen = self._await_libp2p_identity(
            "lp-provider", n_startup_seeds
        )
        self.libp2p_provider_identity = (prov_id, prov_listen)
        # Fold the RESOLVED announce address in beside the configured one, so the oracle
        # rejects an injected bootstrap entry regardless of which form P's address took.
        self.libp2p_provider_listen_addrs.add(prov_listen)

        # 3. C (consumer): bootstraps to BOOT ALONE. NO provider-addr injection.
        # TASK-242: the dependency-outage drill runs C on the PRIMARY /bin/daemon-libp2p binary (the
        # one carrying the operator --status surface) + a loopback --status-listen, so the drill can
        # read live bootstrap health from inside the container. Every other libp2p scenario keeps C
        # on /bin/daemon (no admin surface) byte-identical to before.
        consumer_binary = (
            "/bin/daemon-libp2p"
            if self.libp2p_consumer_status_port is not None
            else "/bin/daemon"
        )
        status_flags = (
            ["--status-listen", f"127.0.0.1:{self.libp2p_consumer_status_port}"]
            if self.libp2p_consumer_status_port is not None
            else []
        )
        run(
            [
                self._pm,
                "run",
                "-d",
                "--pod",
                self.pod,
                "--name",
                self._c("lp-consumer"),
                "--label",
                PROJECT_LABEL,
                *self._state_args("lp-consumer"),
                self.ctx.image,
                consumer_binary,
                "--listen",
                f"0.0.0.0:{DAEMON_PORT}",
                "--upstream",
                proxy,
                "--libp2p-listen",
                f"/ip4/127.0.0.1/tcp/{LIBP2P_BASE_PORT}",
                "--libp2p-bootstrap",
                boot_peer,
                "--libp2p-scope",
                LIBP2P_SCOPE,
                *status_flags,
                *self._daemon_state_flags(),
                *self.daemon_extra_args,
            ]
        )

    def _create_libp2p_leech(self, boot_peer: str, proxy: str) -> None:
        """TASK-78 leech topology: BOOT is already up. Launch A as a CONSUME-ONLY leech in the
        provider slot (port+1) and B as the second consumer (port+0, the client's substituter).

        A (leech): `--libp2p-leech`, bootstraps to BOOT, and fetches the target through its OWN
        daemon (ORIGIN-DIRECT upstream, so the proxy NAR cache stays COLD - B's later fallback is a
        true origin miss, not a warm-cache confound, exactly as the announce-after-fetch provider
        does). Its fabric is LeechFabric-wrapped, so it announces NOTHING and serves NOTHING: it
        never prints a provider identity, so this path awaits its HTTP readiness instead. A holds no
        content at boot; the scenario drives its fetch.

        B (consumer): identical to the non-leech consumer - bootstraps to BOOT ALONE, fronts the
        proxy. Because A (the only holder after it fetches) is a leech, B's `find_providers` MISSES
        and B falls back to upstream. The mutation (A as an announce-after-fetch provider) makes B's
        egress 0 instead.
        """
        # A leech never announces an identity/seed line, so there is nothing to await here and no
        # provider dial address to record for the no-injection oracle.
        self.libp2p_provider_identity = None
        origin = f"http://127.0.0.1:{ORIGIN_PORT}"

        # A: the leech in the provider slot (port+1). Origin-direct upstream keeps the proxy cold.
        # TASK-78 (fix): the leech node runs the PRIMARY /bin/daemon-libp2p binary, whose --libp2p-leech
        # wraps the fabric in peer_fabric::LeechFabric and threads it into daemon_core::run - so this
        # scenario exercises the CAPABILITY-SEAM mask end to end (not the composite daemon's separate
        # consume-only NarSource path).
        run(
            [
                self._pm,
                "run",
                "-d",
                "--pod",
                self.pod,
                "--name",
                self._c("lp-provider"),
                "--label",
                PROJECT_LABEL,
                *self._state_args("lp-provider"),
                self.ctx.image,
                "/bin/daemon-libp2p",
                "--listen",
                f"0.0.0.0:{DAEMON_PORT + 1}",
                "--upstream",
                origin,
                "--libp2p-leech",
                "--libp2p-listen",
                f"/ip4/127.0.0.1/tcp/{LIBP2P_BASE_PORT + 1}",
                "--libp2p-bootstrap",
                boot_peer,
                "--libp2p-scope",
                LIBP2P_SCOPE,
                *self._daemon_state_flags(),
            ]
        )
        # The leech binds its libp2p listener before HTTP; a 200 here means it is a live swarm peer.
        self._await_http_ready("lp-provider", 1)

        # B: the second consumer (port+0), bootstraps to BOOT ALONE, fronts the proxy.
        run(
            [
                self._pm,
                "run",
                "-d",
                "--pod",
                self.pod,
                "--name",
                self._c("lp-consumer"),
                "--label",
                PROJECT_LABEL,
                *self._state_args("lp-consumer"),
                self.ctx.image,
                "/bin/daemon",
                "--listen",
                f"0.0.0.0:{DAEMON_PORT}",
                "--upstream",
                proxy,
                "--libp2p-listen",
                f"/ip4/127.0.0.1/tcp/{LIBP2P_BASE_PORT}",
                "--libp2p-bootstrap",
                boot_peer,
                "--libp2p-scope",
                LIBP2P_SCOPE,
                *self._daemon_state_flags(),
                *self.daemon_extra_args,
            ]
        )

    def _await_libp2p_identity(self, role: str, n_seeds: int) -> tuple[str, str]:
        """Poll `role`'s log for its LIBP2P-PROVIDER-ADDR + `n_seeds` LIBP2P-SEED lines.

        Returns (peer_id, dialable_multiaddr). Filters the announced listen addrs to a
        /ip4/127.0.0.1/ one (the in-pod loopback the harness dials) and strips any
        trailing /p2p/<id> component so the result is a bare multiaddr the daemon's
        `--libp2p-bootstrap <PeerId>@<multiaddr>` parser accepts. Fail-closed: dies if
        the node never announces within the readiness window (never wires a dead peer).
        """
        deadline = time.time() + READY_TIMEOUT_S
        addr_re = re.compile(r"LIBP2P-PROVIDER-ADDR peer_id=(\S+) listen=(\S+)")
        # Matches BOTH the seed-nar announce (`LIBP2P-SEED`) and the STORE-supply announce
        # (`LIBP2P-PROVIDE-STORE`, TASK-194), so identity-await works in either provider mode.
        seed_re = re.compile(r"LIBP2P-(?:SEED|PROVIDE-STORE) narhash=(\S+) ")
        while True:
            log = self.logs(role)
            addr = addr_re.search(log)
            seeds = seed_re.findall(log)
            if addr and len(seeds) >= n_seeds:
                peer_id, listen_csv = addr.group(1), addr.group(2)
                candidates = [
                    a for a in listen_csv.split(",") if a.startswith("/ip4/127.0.0.1/")
                ]
                candidates = candidates or listen_csv.split(",")
                addr_str = candidates[0]
                # Strip a trailing /p2p/<peerid> so the multiaddr is bare.
                if "/p2p/" in addr_str:
                    addr_str = addr_str.split("/p2p/", 1)[0]
                return peer_id, addr_str
            if time.time() > deadline:
                self._dump_logs()
                die(f"{role} never announced its libp2p identity + {n_seeds} seed(s)")
            time.sleep(0.25)

    def _await_http_ready(self, role: str, http_index: int) -> None:
        """Block until `role`'s HTTP daemon answers /nix-cache-info on its host port.

        Used to gate BOOT before the provider starts: the daemon binds its libp2p
        listener before it serves HTTP, so a 200 here means BOOT is dialable and P's
        announce can reach quorum against it. Fail-closed: dies if `role` never becomes
        ready (a provider that then fails announce would be the misleading symptom)."""
        url = f"http://127.0.0.1:{HOST_DAEMON + http_index}/nix-cache-info"
        deadline = time.time() + READY_TIMEOUT_S
        while True:
            try:
                status, _ = http_get(url, timeout=2.0)
                if status == 200:
                    return
            except OSError:
                pass
            if time.time() > deadline:
                self._dump_logs()
                die(f"{role} did not become HTTP-ready at {url}")
            time.sleep(0.25)

    def _await_iroh_identity(
        self, role: str, n_seeds: int
    ) -> tuple[str, str, dict[str, str]]:
        """Poll `role`'s log for the provider's announced identity + seed content
        ids. Returns (node_id, dialable_sockets_csv, {seed_path: blake3}). Filters
        the announced sockets to loopback IPv4 because the harness' peer format
        uses that deterministic in-pod address; the offline profile's IPv6
        loopback address is intentionally not needed here."""
        deadline = time.time() + READY_TIMEOUT_S
        addr_re = re.compile(r"IROH-PROVIDER-ADDR node_id=(\S+) sockets=(\S+)")
        seed_re = re.compile(r"IROH-SEED path=(\S+) bytes=\d+ blake3=(\S+)")
        while True:
            log = self.logs(role)
            addr = addr_re.search(log)
            seeds = dict(seed_re.findall(log))
            if addr and len(seeds) >= n_seeds:
                node_id, sockets_csv = addr.group(1), addr.group(2)
                socks = [
                    s for s in sockets_csv.split(",") if s.startswith("127.0.0.1:")
                ]
                socks = socks or sockets_csv.split(",")
                return node_id, ",".join(socks), seeds
            if time.time() > deadline:
                self._dump_logs()
                die(f"{role} never announced its iroh identity + {n_seeds} seed(s)")
            time.sleep(0.25)

    def node_b_served_bytes(
        self, want_at_least: int = 1, timeout_s: float = 5.0
    ) -> int:
        """The GROUND-TRUTH peer-served byte count: the max `IROH-SERVED-TOTAL
        bytes=N` node B has logged (from its own iroh provider counter, NOT node
        A's self-report). Polls up to `timeout_s` for the counter to reach
        `want_at_least`, since node B's monitor logs it slightly after a fetch."""
        served_re = re.compile(r"IROH-SERVED-TOTAL bytes=(\d+)")
        deadline = time.time() + timeout_s
        best = 0
        while True:
            vals = [int(m) for m in served_re.findall(self.logs("node-b"))]
            best = max([best, *vals])
            if best >= want_at_least or time.time() > deadline:
                return best
            time.sleep(0.2)

    def libp2p_consumer_argv(self) -> list[str]:
        """The exact argv the consumer (`lp-consumer`) container was launched with,
        read back host-side via `podman inspect`. The no-injection oracle asserts the
        provider's PeerId and `--libp2p-provider-addr` are ABSENT from it, so a green
        S7 cannot be quietly explained by a hand-fed dial address."""
        result = run(
            [self._pm, "inspect", "-f", "{{json .Config.Cmd}}", self._c("lp-consumer")],
            check=False,
        )
        raw = (result.stdout or "").strip()
        try:
            argv = json.loads(raw)
        except json.JSONDecodeError:
            raise RuntimeError(
                f"libp2p_consumer_argv: podman inspect returned non-JSON {raw!r} "
                f"(rc={result.returncode}, stderr={result.stderr.strip()!r})"
            ) from None
        if not isinstance(argv, list):
            raise RuntimeError(f"libp2p_consumer_argv: expected a list, got {argv!r}")
        return [str(a) for a in argv]

    def _await_ready(self) -> None:
        targets = [
            (f"http://127.0.0.1:{HOST_ORIGIN}/nix-cache-info", "origin"),
            (f"http://127.0.0.1:{HOST_PROXY}/nix-cache-info", "testproxy"),
        ]
        for i, role in enumerate(self._daemon_roles()):
            targets.append((f"http://127.0.0.1:{HOST_DAEMON + i}/nix-cache-info", role))
        deadline = time.time() + READY_TIMEOUT_S
        for url, role in targets:
            while True:
                try:
                    status, _ = http_get(url, timeout=2.0)
                    if status == 200:
                        break
                except OSError:
                    pass
                if time.time() > deadline:
                    self._dump_logs()
                    die(f"{role} did not become ready at {url}")
                time.sleep(0.25)

    def _dump_logs(self) -> None:
        for role in ["origin", "proxy", *self._daemon_roles()]:
            result = run([self._pm, "logs", self._c(role)], check=False)
            if result.stdout or result.stderr:
                print(f"--- logs {self._c(role)} ---", file=sys.stderr)
                print(result.stdout, result.stderr, file=sys.stderr)

    def stop(self) -> None:
        run([self._pm, "pod", "rm", "-f", "--ignore", self.pod], check=False)

    def kill(self, role: str) -> None:
        """Kill one role's container (task-7 crash-injection entry point).

        NOTE for task-7: to kill the daemon MID-NAR-transfer, start a
        `client_run` in the background (subprocess without wait), poll
        `proxy_stats()` until the NAR request appears, then call this. The
        truncated-transfer event is then visible in `proxy_log()`.
        """
        run([self._pm, "kill", self._c(role)], check=False)

    def logs(self, role: str) -> str:
        """The combined stdout+stderr a role's container has emitted, host-side
        via `podman logs`. task-6 (journey) reads the daemon's log to assert the
        operator-facing substitution story; task-7/9 reuse it for crash and
        counter narration. Returns "" for a role that never started."""
        result = run([self._pm, "logs", self._c(role)], check=False)
        return result.stdout + result.stderr

    # -- oracles (host-side) --

    def proxy_reset(self) -> None:
        status, _ = http_post(f"http://127.0.0.1:{HOST_PROXY}/__testproxy/reset")
        if status != 200:
            die(f"proxy reset returned {status}")

    def proxy_stats(self) -> dict:
        status, body = http_get(f"http://127.0.0.1:{HOST_PROXY}/__testproxy/stats")
        if status != 200:
            die(f"proxy stats returned {status}")
        return json.loads(body)

    def proxy_log(self) -> list[dict]:
        status, body = http_get(f"http://127.0.0.1:{HOST_PROXY}/__testproxy/log")
        if status != 200:
            die(f"proxy log returned {status}")
        return json.loads(body)

    def proxy_in_flight(self) -> int:
        status, body = http_get(f"http://127.0.0.1:{HOST_PROXY}/__testproxy/in-flight")
        if status != 200:
            die(f"proxy in-flight returned {status}")
        value = json.loads(body).get("in_flight")
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            die(f"proxy in-flight returned invalid count: {body!r}")
        return value

    def proxy_faults(self, params: str) -> None:
        status, body = http_post(
            f"http://127.0.0.1:{HOST_PROXY}/__testproxy/faults?{params}"
        )
        if status != 200:
            die(f"proxy faults?{params} returned {status}: {body!r}")

    # -- client invocations (inside the pod netns) --

    def client_run(
        self,
        targets: list[str],
        substituters: str,
        keys: str,
        *,
        jobs: int = 1,
        conns: int = 1,
        start_at_ns: int = 0,
    ) -> ClientResult:
        """Substitute `targets` with a FRESH client (empty store + wiped
        narinfo cache, per the oracle-pairing rule) in single-user root nix.

        A fresh `podman run` container gives a clean /nix/store (image paths
        only, no fixtures) and an empty XDG cache, so counting is not made
        vacuous by a warm client. `jobs`/`conns` are max-substitution-jobs /
        http-connections; they DEFAULT to 1 because every counting scenario
        needs them pinned there (TESTING.md oracle-pairing rule). Only the
        task-18 scale sweep, which asserts no exact counts, moves them.
        `start_at_ns` is the concurrency barrier (0 = start immediately).
        """
        script = _CLIENT_SCRIPT.format(
            subs=substituters,
            keys=keys,
            targets=" ".join(targets),
            jobs=jobs,
            conns=conns,
            start_at_ns=int(start_at_ns),
        )
        result = run(
            [
                self._pm,
                "run",
                "--rm",
                "--pod",
                self.pod,
                "--label",
                PROJECT_LABEL,
                self.ctx.image,
                "bash",
                "-c",
                script,
            ],
            check=False,
            timeout=300,
        )
        return _parse_client(result)

    def client_daemon_run(
        self, target: str, substituters: str, sys_keys: str, caller_keys: str
    ) -> ClientResult:
        """Substitute `target` through a real nix-DAEMON as an UNTRUSTED user.

        This is the AC#3 enforcement path: the daemon (container root) enforces
        require-sigs and trusts only `sys_keys` from its own config; the client
        (uid 1000) passes `caller_keys`, which the daemon IGNORES. Same tampered
        inputs as check-fixtures, different enforcement point.
        """
        script = _CLIENT_DAEMON_SCRIPT.format(
            subs=substituters,
            sys_keys=sys_keys,
            caller_keys=caller_keys,
            target=target,
        )
        result = run(
            [
                self._pm,
                "run",
                "--rm",
                "--pod",
                self.pod,
                "--label",
                PROJECT_LABEL,
                self.ctx.image,
                "bash",
                "-c",
                script,
            ],
            check=False,
            timeout=300,
        )
        return _parse_client(result)

    def client_run_bg(
        self,
        targets: list[str],
        substituters: str,
        keys: str,
        *,
        jobs: int = 1,
        conns: int = 1,
        start_at_ns: int = 0,
    ) -> BackgroundClient:
        """`client_run` started WITHOUT waiting, so N of them can be in flight at
        once (the task-18 concurrent-client sweep axis). Deliberately the SAME
        `_CLIENT_SCRIPT` as the synchronous path - a sweep that measured a
        different client script from the one the scenarios use would be
        measuring the harness, not the product. Distinct from
        `client_run_async`, which runs the crash-suite script (orphan scan,
        crash-specific option slot) and belongs to task-7.

        `start_at_ns` is the shared start instant (host epoch ns) that makes N
        clients actually overlap; the caller must still VERIFY the overlap from
        the reported REALISE_T0_NS/REALISE_T1_NS rather than assume it."""
        script = _CLIENT_SCRIPT.format(
            subs=substituters,
            keys=keys,
            targets=" ".join(targets),
            jobs=jobs,
            conns=conns,
            start_at_ns=int(start_at_ns),
        )
        popen = subprocess.Popen(
            [
                self._pm,
                "run",
                "--rm",
                "--pod",
                self.pod,
                "--label",
                PROJECT_LABEL,
                self.ctx.image,
                "bash",
                "-c",
                script,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return BackgroundClient(popen)

    def exec(self, role: str, argv: list[str], check: bool = False):
        return run([self._pm, "exec", self._c(role), *argv], check=check)

    def libp2p_consumer_status(self) -> str:
        """Read the LIVE operator `/nix-p2p/status` surface from INSIDE the consumer container
        (TASK-242 drill). Uses the SHIPPED admin-query client mode (`daemon-libp2p --status <addr>`)
        against the consumer's own loopback `--status-listen`, so the real client + surface path is
        exercised, not a hand-rolled GET. Returns the (already privacy-redacted) status body on
        success, or the client's stderr (an "ERR"/refusal) otherwise — the caller asserts on tokens.
        Requires the pod to have been built with `libp2p_consumer_status_port`."""
        if self.libp2p_consumer_status_port is None:
            die("libp2p_consumer_status: pod lacks libp2p_consumer_status_port")
        res = self.exec(
            "lp-consumer",
            [
                "/bin/daemon-libp2p",
                "--status",
                f"127.0.0.1:{self.libp2p_consumer_status_port}",
            ],
            check=False,
        )
        return res.stdout if res.stdout.strip() else res.stderr

    # -- crash-suite additions (task-7) --

    def client_run_async(
        self,
        targets: list[str],
        substituters: str,
        keys: str,
        *,
        extra_options: str = "",
        integrity: bool = False,
    ) -> BackgroundClient:
        """Start a `client_run` WITHOUT waiting, so the daemon can be killed or
        frozen mid-build (task-7). Same fresh-client discipline as `client_run`
        (clean store, wiped narinfo cache, max-substitution-jobs=1). `integrity`
        appends the post-crash store-integrity + orphan scan + verify/corrupt
        bite trailer (AC#3). Returns a handle whose `wait_result()` yields the
        same `ClientResult` a synchronous run would.
        """
        script = _CRASH_CLIENT_SCRIPT.format(
            subs=substituters,
            keys=keys,
            extra_opts=extra_options,
            targets=" ".join(targets),
        )
        if integrity:
            script += _INTEGRITY_TRAILER.format(targets=" ".join(targets))
        popen = subprocess.Popen(
            [
                self._pm,
                "run",
                "--rm",
                "--pod",
                self.pod,
                "--label",
                PROJECT_LABEL,
                self.ctx.image,
                "bash",
                "-c",
                script,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return BackgroundClient(popen)

    def pause(self, role: str) -> None:
        """Freeze a role via the cgroup freezer (`podman pause`). This models a
        SIGSTOP stall: the process stops WITHOUT closing its sockets, so peers
        see no RST/FIN - the connection just goes silent (task-7 SIGSTOP case)."""
        run([self._pm, "pause", self._c(role)], check=False)

    def unpause(self, role: str) -> None:
        run([self._pm, "unpause", self._c(role)], check=False)

    def nar_tmp_bytes(self) -> int:
        """Bytes the proxy has streamed into its in-progress NAR cache tmp file.

        The proxy streams a NAR miss origin->cache->client in one loop, so the
        tmp file size tracks how far the transfer has progressed. Because that
        loop is flow-controlled by the proxy->daemon egress (one hop upstream of
        nix), this is a faithful gauge of 'bytes the proxy has pushed toward the
        daemon' - close enough to mid-transfer progress for the BYTES-OBSERVED
        kill trigger (AC#1(b)), and necessary because the request record itself
        is only logged on COMPLETION, so the log cannot report in-flight bytes.

        Sums ALL `.tmp/*` files, which is unambiguous ONLY because the crash
        client pins `max-substitution-jobs=1` + `http-connections=1` (exactly one
        NAR in flight). Returns 0 when no NAR is in flight (glob empty).

        FAIL-CLOSED: a failed `podman exec` (proxy dead/gone) must NOT read as
        '0 bytes in flight' - that would spin the kill loop to its deadline and
        then fail with a misleading observed=0. A nonzero exec is fatal."""
        result = self.exec("proxy", ["bash", "-c", _TMP_SIZE_SNIPPET])
        if result.returncode != 0:
            die(
                "proxy tmp-byte probe failed "
                f"(rc={result.returncode}): {result.stderr.strip()!r}. "
                "The proxy container is unreachable; the kill trigger cannot observe bytes."
            )
        try:
            return int((result.stdout or "0").strip() or "0")
        except ValueError:
            die(f"proxy tmp-byte probe returned non-integer: {result.stdout!r}")
            raise AssertionError  # unreachable; satisfies type checkers


class Libp2pNetnsTopology:
    """S7 SEPARATE-NETNS libp2p topology (TASK-179): the F1 discharge.

    Unlike the shared-loopback `Pod._create_libp2p` (all daemons in one pod netns),
    every daemon here runs as its OWN standalone `--network` container, so each has
    its OWN network namespace and therefore its OWN `127.0.0.1`. Consumer C sits on a
    DIFFERENT podman bridge network (`net-c`) from provider P / bootstrap BOOT /
    proxy / origin (`net-p`); rootless podman's host routing joins the two /24s (the
    e2e image ships NO iproute2, so there is no in-container `ip route` L3 router -
    inter-network reachability is podman's, verified by probe). The routed hop is
    real: C reaches P by P's ROUTABLE net-p IP, never a shared loopback.

    Separate loopbacks are exactly what let the address-RESOLUTION leg be isolated
    (the F1 caveat TASK-161 could not discharge on a shared pod netns). Two arms,
    a MINIMAL PAIR differing only in P's `--libp2p-listen`:

      * positive (`provider_loopback_only=False`): P listens on its routable net-p
        IP, so kad peer-routing resolves a DIALABLE address; C fetches from P; 0
        upstream NAR egress.
      * resolution-only-broken control (`provider_loopback_only=True`): P listens on
        `/ip4/127.0.0.1/tcp/<port>` ONLY. P is alive, announces the same content,
        and is reachable at its routable net-p IP (proven by an HTTP probe from
        INSIDE C's netns). But the address C RESOLVES for P via kad is `127.0.0.1`,
        which in C's own separate netns is C's empty loopback - the dial fails and C
        falls back to upstream (`upstream.nar>=1`). On a shared-loopback pod that
        very address would have reached P; here it cannot, so the peer-serve failure
        is attributable to RESOLUTION specifically - not to P being down, and not to
        an unroutable network path.
    """

    NET_C = f"{POD_PREFIX}-netns-c"
    NET_P = f"{POD_PREFIX}-netns-p"
    # Fixed /24s + IPs. The e2e runner is serialised (the Justfile warns against
    # running e2e/measure concurrently), so fixed names + a rm-first are
    # collision-safe; a stale network from a crashed run is torn down in `_create`.
    SUBNET_C = "10.211.31.0/24"
    SUBNET_P = "10.211.32.0/24"
    IP_CONSUMER = "10.211.31.10"
    IP_BOOT = "10.211.32.10"
    IP_PROVIDER = "10.211.32.11"
    IP_PROXY = "10.211.32.12"
    IP_ORIGIN = "10.211.32.13"

    def __init__(
        self,
        ctx: Ctx,
        name: str,
        served_cache: Path,
        seed_dir: Path,
        provider_seeds: tuple[P2pSeed, ...],
        expect,
        *,
        provider_loopback_only: bool = False,
        libp2p_trusted_key: str | None = None,
    ):
        self.ctx = ctx
        self._pm = ctx.podman
        self.prefix = f"{POD_PREFIX}-{name}"
        self.served_cache = served_cache
        self.seed_dir = seed_dir
        self.provider_seeds = tuple(provider_seeds)
        self._expect = expect
        self.provider_loopback_only = provider_loopback_only
        # TASK-103: the trusted narinfo-signing key so P can prove its seed public and announce
        # over the bootstrapped DHT through the allowlist gate (mirrors the shared-pod path).
        self.libp2p_trusted_key = libp2p_trusted_key
        self.provider_identity: tuple[str, str] | None = None

    def __enter__(self) -> "Libp2pNetnsTopology":
        # AC#5, observed at the boundary the origin serves (host-side walk), same
        # invariant every `Pod` asserts - a separate topology must not become a hole.
        leaked = secret_key_problems(self.served_cache)
        self._expect(
            not leaked,
            "AC#5 (netns): no *.sec under the served cache tree (host-side walk)",
            f"leaked: {leaked}",
        )
        if leaked:
            raise RuntimeError(f"AC#5 abort (netns): secret key(s) {leaked} present")
        self._create()
        return self

    def __exit__(self, *_exc) -> None:
        self.stop()

    def _c(self, role: str) -> str:
        return f"{self.prefix}-{role}"

    def roles(self) -> list[str]:
        return ["origin", "proxy", "lp-boot", "lp-provider", "lp-consumer"]

    def _create(self) -> None:
        pm = self._pm
        # Tear down any stragglers from a crashed prior run (containers BEFORE the
        # networks they attach to, or the network rm fails on an in-use network).
        for role in self.roles():
            run([pm, "rm", "-f", "--ignore", self._c(role)], check=False)
        for net in (self.NET_C, self.NET_P):
            run([pm, "network", "rm", "-f", net], check=False)
        for subnet, net in ((self.SUBNET_C, self.NET_C), (self.SUBNET_P, self.NET_P)):
            run(
                [
                    pm,
                    "network",
                    "create",
                    "--label",
                    PROJECT_LABEL,
                    "--subnet",
                    subnet,
                    net,
                ]
            )

        proxy_upstream = f"http://{self.IP_ORIGIN}:{ORIGIN_PORT}"
        proxy_url = f"http://{self.IP_PROXY}:{PROXY_PORT}"
        boot_peer = (
            f"{LIBP2P_BOOT_PEER_ID}@/ip4/{self.IP_BOOT}/tcp/{LIBP2P_BASE_PORT + 2}"
        )

        # origin: static file server over the served cache, on net-p.
        run(
            [
                pm,
                "run",
                "-d",
                "--label",
                PROJECT_LABEL,
                "--name",
                self._c("origin"),
                "--network",
                self.NET_P,
                "--ip",
                self.IP_ORIGIN,
                "--volume",
                f"{self.served_cache}:/srv/cache:ro",
                self.ctx.image,
                "python3",
                "-m",
                "http.server",
                str(ORIGIN_PORT),
                "--bind",
                "0.0.0.0",
                "--directory",
                "/srv/cache",
            ]
        )
        # testproxy: caching proxy fronting origin; its request log is the oracle.
        run(
            [
                pm,
                "run",
                "-d",
                "--label",
                PROJECT_LABEL,
                "--name",
                self._c("proxy"),
                "--network",
                self.NET_P,
                "--ip",
                self.IP_PROXY,
                self.ctx.image,
                "/bin/testproxy",
                "--listen",
                f"0.0.0.0:{PROXY_PORT}",
                "--upstream",
                proxy_upstream,
                "--cache-dir",
                "/tmp/proxy-cache",
            ]
        )
        # BOOT: a pure kad router (fixed identity, no provider, no announce), on net-p.
        run(
            [
                pm,
                "run",
                "-d",
                "--label",
                PROJECT_LABEL,
                "--name",
                self._c("lp-boot"),
                "--network",
                self.NET_P,
                "--ip",
                self.IP_BOOT,
                self.ctx.image,
                "/bin/daemon",
                "--listen",
                f"0.0.0.0:{DAEMON_PORT}",
                "--upstream",
                proxy_url,
                "--libp2p-listen",
                f"/ip4/{self.IP_BOOT}/tcp/{LIBP2P_BASE_PORT + 2}",
                "--libp2p-bootstrap",
                f"{LIBP2P_DUMMY_PEER}@/ip4/127.0.0.1/tcp/1",
                "--libp2p-identity-seed",
                LIBP2P_BOOT_SEED_HEX,
                "--libp2p-scope",
                LIBP2P_SCOPE,
            ]
        )
        self._await_http_ready("origin", self.IP_ORIGIN)
        self._await_http_ready("proxy", self.IP_PROXY)
        # BOOT must be dialable before P announces (a lone genesis provider cannot
        # reach put-provider quorum); HTTP readiness is the proxy for "kad bound".
        self._await_http_ready("lp-boot", self.IP_BOOT)

        # P (provider): seeds the target, bootstraps to BOOT, announces. The SINGLE
        # knob between the two arms: a routable listen (resolution SUCCEEDS) vs a
        # loopback-only listen (resolution yields a non-dialable address).
        prov_listen = (
            f"/ip4/127.0.0.1/tcp/{LIBP2P_BASE_PORT + 1}"
            if self.provider_loopback_only
            else f"/ip4/{self.IP_PROVIDER}/tcp/{LIBP2P_BASE_PORT + 1}"
        )
        seed_args: list[str] = []
        for s in self.provider_seeds:
            seed_args += ["--libp2p-seed-nar", f"{s.nar_hash}=/srv/seed/{s.filename}"]
        # TASK-103 PUBLIC-announce door (mirrors Pod._create_libp2p): prove each seed public via
        # its signed narinfo (staged under /srv/seed/narinfos by _s7_seeds) before P announces.
        # The allowlist lives on a dedicated non-world-writable mount, not /tmp.
        allowlist_mount = (
            libp2p_allowlist_volume(self.ctx.scratch, self.prefix)
            if self.libp2p_trusted_key
            else []
        )
        if self.libp2p_trusted_key:
            seed_args += [
                "--libp2p-trusted-public-key",
                self.libp2p_trusted_key,
                "--libp2p-public-allowlist-path",
                f"{LIBP2P_ALLOWLIST_MOUNT}/allowlist",
            ]
            for s in self.provider_seeds:
                sh = libp2p_store_hash(s.store_path)
                seed_args += [
                    "--libp2p-prove-public-narinfo",
                    f"{sh}=/srv/seed/narinfos/{sh}.narinfo",
                ]
        run(
            [
                pm,
                "run",
                "-d",
                "--label",
                PROJECT_LABEL,
                "--name",
                self._c("lp-provider"),
                "--network",
                self.NET_P,
                "--ip",
                self.IP_PROVIDER,
                "--volume",
                f"{self.seed_dir}:/srv/seed:ro",
                *allowlist_mount,
                self.ctx.image,
                "/bin/daemon",
                "--listen",
                f"0.0.0.0:{DAEMON_PORT}",
                "--upstream",
                proxy_url,
                "--libp2p-provider",
                "--libp2p-listen",
                prov_listen,
                "--libp2p-bootstrap",
                boot_peer,
                "--libp2p-scope",
                LIBP2P_SCOPE,
                "--libp2p-print-peer-address",
                *seed_args,
            ]
        )
        self.provider_identity = self._await_provider_identity(
            "lp-provider", len(self.provider_seeds)
        )
        # C (consumer): on net-c, bootstraps to BOOT ALONE (no --libp2p-provider-addr).
        run(
            [
                pm,
                "run",
                "-d",
                "--label",
                PROJECT_LABEL,
                "--name",
                self._c("lp-consumer"),
                "--network",
                self.NET_C,
                "--ip",
                self.IP_CONSUMER,
                self.ctx.image,
                "/bin/daemon",
                "--listen",
                f"0.0.0.0:{DAEMON_PORT}",
                "--upstream",
                proxy_url,
                "--libp2p-listen",
                f"/ip4/{self.IP_CONSUMER}/tcp/{LIBP2P_BASE_PORT}",
                "--libp2p-bootstrap",
                boot_peer,
                "--libp2p-scope",
                LIBP2P_SCOPE,
            ]
        )
        self._await_http_ready("lp-consumer", self.IP_CONSUMER, network=self.NET_C)

    def _exec_get(self, container: str, url: str, timeout: float = 5.0):
        """HTTP GET `url` from INSIDE `container`'s netns via python3 (the image has
        no curl). Returns (status:int|None, body:str). status None = the request
        never completed (connection refused / timeout / unreachable)."""
        py = (
            "import sys,urllib.request\n"
            "try:\n"
            f"    r=urllib.request.urlopen('{url}',timeout={timeout})\n"
            "    sys.stdout.write(str(r.status)+'\\n'+r.read().decode('utf-8','replace'))\n"
            "except Exception as e:\n"
            "    sys.stdout.write('ERR '+type(e).__name__+' '+str(e))\n"
        )
        res = run([self._pm, "exec", container, "python3", "-c", py], check=False)
        out = res.stdout or ""
        first, _, rest = out.partition("\n")
        try:
            return int(first.strip()), rest
        except ValueError:
            return None, out

    def _post(self, container: str, url: str, timeout: float = 5.0):
        py = (
            "import sys,urllib.request\n"
            f"req=urllib.request.Request('{url}',method='POST',data=b'')\n"
            f"r=urllib.request.urlopen(req,timeout={timeout})\n"
            "sys.stdout.write(str(r.status))\n"
        )
        res = run([self._pm, "exec", container, "python3", "-c", py], check=False)
        try:
            return int((res.stdout or "").strip())
        except ValueError:
            return None

    def _await_http_ready(self, role: str, ip: str, network: str | None = None) -> None:
        """Block until `role`'s HTTP daemon answers /nix-cache-info. Probed from a
        throwaway container ON THE SAME network as `role` (default net-p) - the
        container's port is not host-published, so the probe runs in-network."""
        net = network or self.NET_P
        url = f"http://{ip}:{ORIGIN_PORT if role == 'origin' else PROXY_PORT if role == 'proxy' else DAEMON_PORT}/nix-cache-info"
        deadline = time.time() + READY_TIMEOUT_S
        while True:
            res = run(
                [
                    self._pm,
                    "run",
                    "--rm",
                    "--label",
                    PROJECT_LABEL,
                    "--network",
                    net,
                    self.ctx.image,
                    "python3",
                    "-c",
                    f"import urllib.request;print(urllib.request.urlopen('{url}',timeout=2).status)",
                ],
                check=False,
            )
            if (res.stdout or "").strip() == "200":
                return
            if time.time() > deadline:
                self._dump_logs()
                die(f"netns {role} did not become HTTP-ready at {url}")
            time.sleep(0.4)

    def _await_provider_identity(self, role: str, n_seeds: int) -> tuple[str, str]:
        """Poll `role`'s log for LIBP2P-PROVIDER-ADDR + `n_seeds` LIBP2P-SEED lines;
        return (peer_id, announced_listen_csv). Fail-closed: dies if it never
        announces (never wires a dead peer)."""
        deadline = time.time() + READY_TIMEOUT_S
        addr_re = re.compile(r"LIBP2P-PROVIDER-ADDR peer_id=(\S+) listen=(\S+)")
        # Matches BOTH the seed-nar announce (`LIBP2P-SEED`) and the STORE-supply announce
        # (`LIBP2P-PROVIDE-STORE`, TASK-194), so identity-await works in either provider mode.
        seed_re = re.compile(r"LIBP2P-(?:SEED|PROVIDE-STORE) narhash=(\S+) ")
        while True:
            log = self.logs(role)
            addr = addr_re.search(log)
            seeds = seed_re.findall(log)
            if addr and len(seeds) >= n_seeds:
                return addr.group(1), addr.group(2)
            if time.time() > deadline:
                self._dump_logs()
                die(
                    f"netns {role} never announced its libp2p identity + {n_seeds} seed(s)"
                )
            time.sleep(0.25)

    def logs(self, role: str) -> str:
        res = run([self._pm, "logs", self._c(role)], check=False)
        return res.stdout + res.stderr

    def _dump_logs(self) -> None:
        for role in self.roles():
            res = run([self._pm, "logs", self._c(role)], check=False)
            if res.stdout or res.stderr:
                print(f"--- logs {self._c(role)} ---", file=sys.stderr)
                print(res.stdout, res.stderr, file=sys.stderr)

    def consumer_argv(self) -> list[str]:
        """The exact argv `lp-consumer` was launched with (the no-injection oracle)."""
        res = run(
            [self._pm, "inspect", "-f", "{{json .Config.Cmd}}", self._c("lp-consumer")],
            check=False,
        )
        raw = (res.stdout or "").strip()
        try:
            argv = json.loads(raw)
        except json.JSONDecodeError:
            raise RuntimeError(f"consumer_argv: non-JSON {raw!r}") from None
        return [str(a) for a in argv]

    def proxy_reset(self) -> None:
        status = self._post(
            self._c("proxy"), f"http://127.0.0.1:{PROXY_PORT}/__testproxy/reset"
        )
        if status != 200:
            die(f"netns proxy reset returned {status}")

    def proxy_stats(self) -> dict:
        status, body = self._exec_get(
            self._c("proxy"), f"http://127.0.0.1:{PROXY_PORT}/__testproxy/stats"
        )
        if status != 200:
            die(f"netns proxy stats returned {status}: {body!r}")
        return json.loads(body)

    def provider_reachable_from_consumer(self) -> tuple[int | None, str]:
        """Prove, FROM INSIDE C's netns, that P is alive and its routable net-p IP is
        reachable - an HTTP GET of P's /nix-cache-info at its ROUTABLE address. This
        is the control arm's load-bearing evidence: the peer-serve failed while P was
        up and the path existed, so RESOLUTION (not liveness/reachability) is what
        broke."""
        return self._exec_get(
            self._c("lp-consumer"),
            f"http://{self.IP_PROVIDER}:{DAEMON_PORT}/nix-cache-info",
        )

    def client_run(self, targets: list[str], keys: str) -> "ClientResult":
        """Realise `targets` with a FRESH client on net-c, substituting ONLY from C's
        daemon (at C's routable net-c IP). Same `_CLIENT_SCRIPT` + `_parse_client` the
        pod path uses, so the byte oracle is identical."""
        subs = f"http://{self.IP_CONSUMER}:{DAEMON_PORT}?priority=10"
        script = _CLIENT_SCRIPT.format(
            subs=subs,
            keys=keys,
            targets=" ".join(targets),
            jobs=1,
            conns=1,
            start_at_ns=0,
        )
        res = run(
            [
                self._pm,
                "run",
                "--rm",
                "--label",
                PROJECT_LABEL,
                "--network",
                self.NET_C,
                self.ctx.image,
                "bash",
                "-c",
                script,
            ],
            check=False,
            timeout=300,
        )
        return _parse_client(res)

    def kill(self, role: str) -> None:
        run([self._pm, "kill", self._c(role)], check=False)

    def stop(self) -> None:
        for role in self.roles():
            run([self._pm, "rm", "-f", "--ignore", self._c(role)], check=False)
        for net in (self.NET_C, self.NET_P):
            run([self._pm, "network", "rm", "-f", net], check=False)


class Libp2pMdnsTopology:
    """TASK-257 mDNS bootstrap topology: the ZERO-BOOTSTRAP LAN proof.

    Every daemon runs as its OWN `--network` container (own netns, own 127.0.0.1) but ALL
    share ONE podman bridge network (a single multicast-capable L2 segment), because mDNS is
    link-local MULTICAST and would NOT cross the isolated per-role netns the routed S7 uses.
    NO node is EVER given `--libp2p-bootstrap`: a same-scope neighbour is discovered purely
    over mDNS, its ADDRESS is fed into kad's routing/bootstrap path (`add_address`), and the
    consumer then discovers WHO holds the content via kad get_providers and fetches it. The
    ONLY way any node learns a peer's address is mDNS - proven by the no-injection argv
    oracle (no bootstrap, no provider-addr) AND by the mutation the caller runs (different
    `--libp2p-scope` => the scoped kad protocol refuses the join => upstream fallback).

    Consumers are launched with `--libp2p-leech` (honest consume-only) but the COMPOSITE
    `/bin/daemon` runs kad in SERVER mode (flag-authoritative, TASK-120 fix-C deferred), so a
    consumer STORES the provider's put-record and satisfies the lone provider's put-quorum -
    which is why a two-node P+C topology can bootstrap with no dedicated router.
    """

    SUBNET = "10.211.33.0/24"
    IP_ORIGIN = "10.211.33.13"
    IP_PROXY = "10.211.33.12"
    IP_PROVIDER = "10.211.33.11"
    # Consumer-like roles get their own IPs; the provider always discovers them via mDNS.
    ROLE_IPS = {"lp-consumer": "10.211.33.10", "lp-helper": "10.211.33.14"}

    def __init__(
        self,
        ctx: Ctx,
        name: str,
        served_cache: Path,
        seed_dir: Path,
        provider_seeds: tuple[P2pSeed, ...],
        expect,
        *,
        provider_scope: str,
        # role -> scope for each consumer-like daemon (a leech that fetches). Same scope as
        # the provider => it can resolve; a different scope => scope isolation must block it.
        consumers: tuple[tuple[str, str], ...],
        libp2p_trusted_key: str,
    ):
        self.ctx = ctx
        self._pm = ctx.podman
        self.prefix = f"{POD_PREFIX}-{name}"
        self.served_cache = served_cache
        self.seed_dir = seed_dir
        self.provider_seeds = tuple(provider_seeds)
        self._expect = expect
        self.provider_scope = provider_scope
        self.consumers = tuple(consumers)
        self.libp2p_trusted_key = libp2p_trusted_key
        self.provider_identity: tuple[str, str] | None = None
        self.NET = f"{self.prefix}-net"

    def __enter__(self) -> "Libp2pMdnsTopology":
        leaked = secret_key_problems(self.served_cache)
        self._expect(
            not leaked,
            "AC#5 (mdns): no *.sec under the served cache tree (host-side walk)",
            f"leaked: {leaked}",
        )
        if leaked:
            raise RuntimeError(f"AC#5 abort (mdns): secret key(s) {leaked} present")
        self._create()
        return self

    def __exit__(self, *_exc) -> None:
        self.stop()

    def _c(self, role: str) -> str:
        return f"{self.prefix}-{role}"

    def roles(self) -> list[str]:
        return ["origin", "proxy", "lp-provider", *[r for r, _ in self.consumers]]

    def _create(self) -> None:
        pm = self._pm
        for role in self.roles():
            run([pm, "rm", "-f", "--ignore", self._c(role)], check=False)
        run([pm, "network", "rm", "-f", self.NET], check=False)
        # A dedicated bridge = ONE multicast-capable L2 segment all nodes share.
        run(
            [pm, "network", "create", "--label", PROJECT_LABEL, "--subnet", self.SUBNET, self.NET]
        )

        proxy_url = f"http://{self.IP_PROXY}:{PROXY_PORT}"
        # origin: static file server over the served cache.
        run(
            [pm, "run", "-d", "--label", PROJECT_LABEL, "--name", self._c("origin"),
             "--network", self.NET, "--ip", self.IP_ORIGIN,
             "--volume", f"{self.served_cache}:/srv/cache:ro", self.ctx.image,
             "python3", "-m", "http.server", str(ORIGIN_PORT), "--bind", "0.0.0.0",
             "--directory", "/srv/cache"]
        )
        # testproxy: caching proxy fronting origin; its request log is the egress oracle.
        run(
            [pm, "run", "-d", "--label", PROJECT_LABEL, "--name", self._c("proxy"),
             "--network", self.NET, "--ip", self.IP_PROXY, self.ctx.image,
             "/bin/testproxy", "--listen", f"0.0.0.0:{PROXY_PORT}",
             "--upstream", f"http://{self.IP_ORIGIN}:{ORIGIN_PORT}",
             "--cache-dir", "/tmp/proxy-cache"]
        )
        self._await_http_ready("origin", self.IP_ORIGIN)
        self._await_http_ready("proxy", self.IP_PROXY)

        # CONSUMERS FIRST: they come up mDNS-live so that when the provider announces (a lone
        # genesis provider needs a put-quorum peer), a same-scope consumer is already
        # discoverable. NO --libp2p-bootstrap on ANY of them - mDNS is the only entry path.
        for role, scope in self.consumers:
            ip = self.ROLE_IPS[role]
            run(
                [pm, "run", "-d", "--label", PROJECT_LABEL, "--name", self._c(role),
                 "--network", self.NET, "--ip", ip, self.ctx.image,
                 "/bin/daemon", "--listen", f"0.0.0.0:{DAEMON_PORT}", "--upstream", proxy_url,
                 "--libp2p-leech", "--libp2p-mdns",
                 "--libp2p-listen", f"/ip4/{ip}/tcp/{LIBP2P_BASE_PORT}",
                 "--libp2p-scope", scope]
            )
            self._await_http_ready(role, ip)

        # PROVIDER LAST: same-scope, seeds the target, proves each seed public through the
        # trusted-key allowlist door, announces over the mDNS-formed DHT. NO bootstrap. A DURABLE
        # --libp2p-state-dir pins its identity across restarts, which is what makes the put-quorum
        # RETRY below safe: the allowlist file's MAC is keyed by the identity seed, so a restart
        # under a fresh identity would fail to reopen its own allowlist - the durable seed keeps the
        # PeerId (and thus the MAC key) stable so a retried announce reopens the SAME allowlist.
        allowlist_mount = libp2p_allowlist_volume(self.ctx.scratch, self.prefix)
        state_host = self.ctx.scratch / f"{self.prefix}-provider-state"
        state_host.mkdir(parents=True, exist_ok=True)
        seed_args: list[str] = []
        for s in self.provider_seeds:
            seed_args += ["--libp2p-seed-nar", f"{s.nar_hash}=/srv/seed/{s.filename}"]
        seed_args += ["--libp2p-trusted-public-key", self.libp2p_trusted_key,
                      "--libp2p-public-allowlist-path", f"{LIBP2P_ALLOWLIST_MOUNT}/allowlist",
                      "--libp2p-state-dir", "/srv/state"]
        for s in self.provider_seeds:
            sh = libp2p_store_hash(s.store_path)
            seed_args += ["--libp2p-prove-public-narinfo",
                          f"{sh}=/srv/seed/narinfos/{sh}.narinfo"]
        provider_argv = [
            "run", "-d", "--label", PROJECT_LABEL, "--name", self._c("lp-provider"),
            "--network", self.NET, "--ip", self.IP_PROVIDER,
            "--volume", f"{self.seed_dir}:/srv/seed:ro",
            "--volume", f"{state_host}:/srv/state", *allowlist_mount, self.ctx.image,
            "/bin/daemon", "--listen", f"0.0.0.0:{DAEMON_PORT}", "--upstream", proxy_url,
            "--libp2p-provider", "--libp2p-mdns",
            "--libp2p-listen", f"/ip4/{self.IP_PROVIDER}/tcp/{LIBP2P_BASE_PORT + 1}",
            "--libp2p-scope", self.provider_scope, "--libp2p-print-peer-address", *seed_args,
        ]
        run([pm, *provider_argv])
        # A lone genesis provider's startup put-quorum can lose a race with mDNS discovery settling
        # (the daemon's initial announce is one-shot). If it exits before announcing, settle briefly
        # so both nodes are steadily multicasting, then RESTART it under its DURABLE identity - the
        # consumers are already up, so a retried announce discovers a quorum peer. Bounded, fail-loud.
        # HONEST NOTE: this restart is a TEST-HARNESS scaffold for the lone-genesis race; a future
        # production improvement is a bounded in-daemon announce retry for the zero-bootstrap case.
        for attempt in range(6):
            ident = self._try_await_provider_identity("lp-provider", len(self.provider_seeds))
            if ident:
                self.provider_identity = ident
                return
            state = run(
                [pm, "inspect", "-f", "{{.State.Status}}", self._c("lp-provider")], check=False
            ).stdout.strip()
            print(f"mdns provider not yet announced (state={state!r}); settle+restart "
                  f"{attempt + 1}/6", file=sys.stderr)
            time.sleep(5.0)
            run([pm, "restart", self._c("lp-provider")], check=False)
        self._dump_logs()
        die("mdns provider never announced its identity + seed(s) after retries")

    def _await_http_ready(self, role: str, ip: str) -> None:
        port = ORIGIN_PORT if role == "origin" else PROXY_PORT if role == "proxy" else DAEMON_PORT
        url = f"http://{ip}:{port}/nix-cache-info"
        deadline = time.time() + READY_TIMEOUT_S
        while True:
            res = run(
                [self._pm, "run", "--rm", "--label", PROJECT_LABEL, "--network", self.NET,
                 self.ctx.image, "python3", "-c",
                 f"import urllib.request;print(urllib.request.urlopen('{url}',timeout=2).status)"],
                check=False,
            )
            if (res.stdout or "").strip() == "200":
                return
            if time.time() > deadline:
                self._dump_logs()
                die(f"mdns {role} did not become HTTP-ready at {url}")
            time.sleep(0.4)

    def _try_await_provider_identity(self, role: str, n_seeds: int):
        """Poll for LIBP2P-PROVIDER-ADDR + n_seeds seed announce lines (printed only AFTER a
        successful announce). Returns (peer_id, listen) or None on timeout/provider-exit."""
        deadline = time.time() + 30.0
        addr_re = re.compile(r"LIBP2P-PROVIDER-ADDR peer_id=(\S+) listen=(\S+)")
        seed_re = re.compile(r"LIBP2P-(?:SEED|PROVIDE-STORE) narhash=(\S+) ")
        while time.time() < deadline:
            log = self.logs(role)
            addr = addr_re.search(log)
            seeds = seed_re.findall(log)
            if addr and len(seeds) >= n_seeds:
                return addr.group(1), addr.group(2)
            state = run(
                [self._pm, "inspect", "-f", "{{.State.Status}}", self._c(role)], check=False
            ).stdout.strip()
            if state == "exited":
                return None
            time.sleep(0.3)
        return None

    def logs(self, role: str) -> str:
        res = run([self._pm, "logs", self._c(role)], check=False)
        return res.stdout + res.stderr

    def _dump_logs(self) -> None:
        for role in self.roles():
            res = run([self._pm, "logs", self._c(role)], check=False)
            if res.stdout or res.stderr:
                print(f"--- logs {self._c(role)} ---", file=sys.stderr)
                print(res.stdout, res.stderr, file=sys.stderr)

    def consumer_argv(self, role: str = "lp-consumer") -> list[str]:
        res = run(
            [self._pm, "inspect", "-f", "{{json .Config.Cmd}}", self._c(role)], check=False
        )
        raw = (res.stdout or "").strip()
        try:
            argv = json.loads(raw)
        except json.JSONDecodeError:
            raise RuntimeError(f"consumer_argv: non-JSON {raw!r}") from None
        return [str(a) for a in argv]

    def provider_reachable_from(self, role: str) -> tuple[int | None, str]:
        """From INSIDE `role`'s netns, GET the provider's /nix-cache-info at its routable IP -
        proves the provider is ALIVE and the L2 path exists, so a fallback isolates SCOPE, not
        liveness."""
        py = (
            "import sys,urllib.request\n"
            f"try:\n    r=urllib.request.urlopen('http://{self.IP_PROVIDER}:{DAEMON_PORT}/nix-cache-info',timeout=3)\n"
            "    sys.stdout.write(str(r.status))\n"
            "except Exception as e:\n    sys.stdout.write('ERR '+type(e).__name__)\n"
        )
        res = run([self._pm, "exec", self._c(role), "python3", "-c", py], check=False)
        out = (res.stdout or "").strip()
        try:
            return int(out), out
        except ValueError:
            return None, out

    def proxy_reset(self) -> None:
        status = self._post(self._c("proxy"), f"http://127.0.0.1:{PROXY_PORT}/__testproxy/reset")
        if status != 200:
            die(f"mdns proxy reset returned {status}")

    def _post(self, container: str, url: str):
        py = (
            "import sys,urllib.request\n"
            f"req=urllib.request.Request('{url}',method='POST',data=b'')\n"
            "sys.stdout.write(str(urllib.request.urlopen(req,timeout=5).status))\n"
        )
        res = run([self._pm, "exec", container, "python3", "-c", py], check=False)
        try:
            return int((res.stdout or "").strip())
        except ValueError:
            return None

    def proxy_stats(self) -> dict:
        py = (
            "import sys,urllib.request\n"
            f"sys.stdout.write(urllib.request.urlopen('http://127.0.0.1:{PROXY_PORT}/__testproxy/stats',timeout=5).read().decode())\n"
        )
        res = run([self._pm, "exec", self._c("proxy"), "python3", "-c", py], check=False)
        return json.loads(res.stdout)

    def client_run(self, role: str, targets: list[str], keys: str) -> "ClientResult":
        """Realise `targets` with a FRESH client substituting ONLY from `role`'s daemon (its
        routable IP), the SAME `_CLIENT_SCRIPT`/`_parse_client` the pod path uses."""
        ip = self.ROLE_IPS[role]
        subs = f"http://{ip}:{DAEMON_PORT}?priority=10"
        script = _CLIENT_SCRIPT.format(
            subs=subs, keys=keys, targets=" ".join(targets), jobs=1, conns=1, start_at_ns=0
        )
        res = run(
            [self._pm, "run", "--rm", "--label", PROJECT_LABEL, "--network", self.NET,
             self.ctx.image, "bash", "-c", script],
            check=False, timeout=300,
        )
        return _parse_client(res)

    def stop(self) -> None:
        for role in self.roles():
            run([self._pm, "rm", "-f", "--ignore", self._c(role)], check=False)
        run([self._pm, "network", "rm", "-f", self.NET], check=False)


# Single-user client: realise into the container's own store, then report
# NarHash for the byte oracle. Markers delimit machine-readable output.
_CLIENT_SCRIPT = r"""
set -uo pipefail
export XDG_CACHE_HOME=/tmp/nixcache
rm -rf "$XDG_CACHE_HOME"; mkdir -p "$XDG_CACHE_HOME"
common=(
  --option substituters "{subs}"
  --option trusted-public-keys "{keys}"
  --option require-sigs true
  --option max-substitution-jobs {jobs}
  --option http-connections {conns}
  --option narinfo-cache-positive-ttl 0
  --option narinfo-cache-negative-ttl 0
  --option substitute true
)
# CONCURRENCY BARRIER (task-18). Every client of one sweep point waits for the
# same host wall-clock instant before realising. MEASURED rationale, not an
# assumed one: launching the fleet is already asynchronous, and a mutation run
# with the barrier disabled still saw full overlap at N=6 - so the barrier is
# JITTER insurance, not a fix for serialised launches. It matters because the
# workload itself is ~150 ms while container start varies by hundreds of ms, so
# without a shared instant a slow-starting container can miss the window
# entirely. What actually GUARANTEES the concurrency is the sweep's measured
# overlap of the T0/T1 epochs below (all containers share the host clock), which
# invalidates the point when the fleet did not really run at once.
# `{start_at_ns}` = 0 (every non-sweep caller) exits the loop immediately, so
# existing scenarios are untouched.
while [ {start_at_ns} -gt "$(date +%s%N)" ]; do sleep 0.02; done
T0=$(date +%s%N)
nix-store --realise "${{common[@]}}" {targets} >/tmp/realised 2>/tmp/err
RC=$?
T1=$(date +%s%N)
echo "REALISE_RC=$RC"
# IN-CONTAINER realise duration. The host-side wall clock of `podman run`
# includes container create/start/teardown (~0.5-1 s, and it grows with how
# many containers are starting at once) - folding that into a latency-vs-N
# scaling law would fit the CONTAINER RUNTIME's scaling, not the product's.
# task-18 fits this number and reports the host-side one beside it. T0/T1 are
# absolute so overlap between concurrent clients is computable host-side.
echo "REALISE_NS=$((T1-T0))"
echo "REALISE_T0_NS=$T0"
echo "REALISE_T1_NS=$T1"
cat /tmp/err >&2
# The knobs nix ACTUALLY resolved, not the ones we passed (TESTING.md
# client-knobs rule: a knob sweep whose knob never landed is a vacuous sweep,
# so task-18 asserts this section as the axis PRECONDITION). One `config show
# <name>` per knob, filtered by NOTHING: `grep` is NOT in this image (the same
# missing-binary trap that made an earlier in-container oracle return rc=127 and
# pass unconditionally), so the selection happens through nix itself and the
# parsing happens host-side. A failed query yields an empty value, which the
# sweep reads as UNCONFIRMED - never as "the knob took".
echo "===KNOBS_BEGIN==="
echo "max-substitution-jobs = $(nix --extra-experimental-features nix-command \
  config show max-substitution-jobs "${{common[@]}}" 2>/dev/null)"
echo "http-connections = $(nix --extra-experimental-features nix-command \
  config show http-connections "${{common[@]}}" 2>/dev/null)"
echo "===KNOBS_END==="
# path-info per target, tolerating the ones that did NOT realise (the absent
# path in the 404 scenario): a realised sibling must still be measurable even
# when the overall realise exits nonzero. Local paths need no substituter opts.
echo "===PATHINFO_BEGIN==="
python3 - {targets} <<'PY'
import json, subprocess, sys

merged = {{}}
for path in sys.argv[1:]:
    result = subprocess.run(
        ["nix", "path-info", "--json", path], capture_output=True, text=True
    )
    if result.returncode == 0:
        try:
            merged.update(json.loads(result.stdout))
        except ValueError:
            pass
print(json.dumps(merged))
PY
echo "===PATHINFO_END==="
"""

# Daemon-enforcement client: start nix-daemon as root with a per-scenario
# system config, then realise as the untrusted `client` user via NIX_REMOTE.
_CLIENT_DAEMON_SCRIPT = r"""
set -uo pipefail
export NIX_CONF_DIR=/run/nixconf
mkdir -p "$NIX_CONF_DIR" /nix/var/nix/daemon-socket
cat > "$NIX_CONF_DIR/nix.conf" <<EOF
experimental-features = nix-command flakes
sandbox = false
build-users-group =
require-sigs = true
trusted-users = root
trusted-public-keys = {sys_keys}
substituters = {subs}
EOF
nix-daemon >/tmp/daemon.log 2>&1 &
for _ in $(seq 1 200); do
  [ -S /nix/var/nix/daemon-socket/socket ] && break
  sleep 0.05
done
mkdir -p /tmp/ch/cache && chmod -R 1777 /tmp/ch
set +e
# setpriv, NOT runuser/su: those pull in PAM, which aborts ("Critical error -
# immediate abort") with no PAM stack in this minimal image. setpriv drops to
# the UNTRUSTED uid 1000 with no PAM. The daemon (container root) enforces its
# own require-sigs/trusted-public-keys and ignores this caller's keys.
env NIX_REMOTE=daemon HOME=/tmp/ch XDG_CACHE_HOME=/tmp/ch/cache \
  setpriv --reuid 1000 --regid 1000 --clear-groups \
  nix-store --realise {target} \
    --option trusted-public-keys "{caller_keys}" \
    --option require-sigs true >/tmp/out 2>/tmp/err
RC=$?
set -e
echo "REALISE_RC=$RC"
cat /tmp/err >&2
echo "===PATHINFO_BEGIN==="
echo '[]'
echo "===PATHINFO_END==="
"""


def _parse_client(result) -> ClientResult:
    stdout = result.stdout
    # Fail-closed: 'unknown' must NEVER read as success. The client script echoes
    # REALISE_RC=<n> after its `nix build`; if that marker is absent the client
    # exited before it ran (codex re-gate: a client exiting 99 before nix-daemon
    # started left exit_code defaulting to 0, so the positive-control scenario
    # stayed green while the build never happened). A missing marker, or a podman
    # outer failure overriding a claimed success, both resolve to failure.
    realise_rc = None
    for line in stdout.splitlines():
        if line.startswith("REALISE_RC="):
            with contextlib.suppress(ValueError):
                realise_rc = int(line.split("=", 1)[1])
    outer_rc = getattr(result, "returncode", 0)
    if realise_rc is None:
        # No marker: cannot prove success. Trust an outer failure; a 0 outer rc
        # without the marker is still unproven -> sentinel failure (111).
        exit_code = outer_rc if outer_rc != 0 else 111
    elif outer_rc != 0 and realise_rc == 0:
        # Client claimed success but podman itself failed -> the failure wins.
        exit_code = outer_rc
    else:
        exit_code = realise_rc
    path_info: dict = {}
    begin = stdout.find("===PATHINFO_BEGIN===")
    end = stdout.find("===PATHINFO_END===")
    if begin != -1 and end != -1:
        blob = stdout[begin + len("===PATHINFO_BEGIN===") : end].strip()
        with contextlib.suppress(ValueError):
            path_info = json.loads(blob)
    return ClientResult(
        exit_code=exit_code,
        stdout=stdout,
        stderr=result.stderr,
        path_info=path_info,
    )


# ---- crash-suite driver additions (task-7) ---------------------------------
#
# A background client (so the daemon can be killed/frozen mid-build), a
# proxy-tmp byte gauge for the BYTES-OBSERVED kill trigger, and the crash
# client script (base realise + optional post-crash integrity/orphan/verify
# trailer). The scenarios themselves live in the SCENARIOS block below.

# Sum every regular in-progress cache file without a shell test/stat race.
# ENOENT between directory enumeration and stat is benign (the proxy completed
# or discarded that file); every other metadata error is fatal and contextual.
_TMP_SIZE_SNIPPET = r"""python3 - <<'PY'
import os
import stat
import sys

root = os.environ.get("NIX_P2P_TMP_PROBE_ROOT", "/tmp/proxy-cache/.tmp")
test_mode = os.environ.get("NIX_P2P_TMP_PROBE_TEST", "")
try:
    entries = list(os.scandir(root))
except FileNotFoundError:
    entries = []
except OSError as error:
    print(f"tmp-byte probe cannot scan {root!r}: {error}", file=sys.stderr)
    raise SystemExit(2)

total = 0
for entry in entries:
    try:
        if test_mode == "disappear":
            os.unlink(entry.path)
        elif test_mode == "permission":
            raise PermissionError("injected metadata denial")
        metadata = entry.stat(follow_symlinks=False)
    except FileNotFoundError:
        continue
    except OSError as error:
        print(f"tmp-byte probe cannot stat {entry.path!r}: {error}", file=sys.stderr)
        raise SystemExit(2)
    if stat.S_ISREG(metadata.st_mode):
        total += metadata.st_size
print(total)
PY
"""


def _self_test_tmp_size_snippet() -> None:
    """Exercise the exact production snippet's normal, ENOENT and hard-error paths."""
    root = Path(os.environ.get("TMPDIR", "/tmp")) / (
        f"nix-p2p-tmp-probe-selftest-{os.getpid()}"
    )
    with contextlib.suppress(FileNotFoundError):
        shutil.rmtree(root)
    root.mkdir(parents=True)

    def probe(mode: str = "") -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["NIX_P2P_TMP_PROBE_ROOT"] = str(root)
        if mode:
            environment["NIX_P2P_TMP_PROBE_TEST"] = mode
        else:
            environment.pop("NIX_P2P_TMP_PROBE_TEST", None)
        return subprocess.run(
            ["bash", "-c", _TMP_SIZE_SNIPPET],
            text=True,
            capture_output=True,
            check=False,
            env=environment,
        )

    try:
        (root / "normal.tmp").write_bytes(b"abc")
        normal = probe()
        if normal.returncode != 0 or normal.stdout.strip() != "3":
            die(
                "tmp-byte probe self-test normal path failed: "
                f"rc={normal.returncode} stdout={normal.stdout!r} stderr={normal.stderr!r}"
            )

        disappearing = probe("disappear")
        if disappearing.returncode != 0 or disappearing.stdout.strip() != "0":
            die(
                "tmp-byte probe self-test ENOENT path failed: "
                f"rc={disappearing.returncode} stdout={disappearing.stdout!r} "
                f"stderr={disappearing.stderr!r}"
            )

        (root / "denied.tmp").write_bytes(b"x")
        denied = probe("permission")
        if denied.returncode == 0 or "injected metadata denial" not in denied.stderr:
            die(
                "tmp-byte probe self-test hard-error path did not fail closed: "
                f"rc={denied.returncode} stdout={denied.stdout!r} stderr={denied.stderr!r}"
            )
    finally:
        with contextlib.suppress(FileNotFoundError):
            shutil.rmtree(root)


# The crash client: same knobs as `_CLIENT_SCRIPT` plus a per-scenario
# `{extra_opts}` slot (e.g. a pinned `stalled-download-timeout`), and an ORPHANS
# scan so every crash run can be checked for store residue. Kept SEPARATE from
# `_CLIENT_SCRIPT` so the crash-specific slots never perturb the base scenarios.
_CRASH_CLIENT_SCRIPT = r"""
set -uo pipefail
export XDG_CACHE_HOME=/tmp/nixcache
rm -rf "$XDG_CACHE_HOME"; mkdir -p "$XDG_CACHE_HOME"
common=(
  --option substituters "{subs}"
  --option trusted-public-keys "{keys}"
  --option require-sigs true
  --option max-substitution-jobs 1
  --option http-connections 1
  --option narinfo-cache-positive-ttl 0
  --option narinfo-cache-negative-ttl 0
  --option substitute true
  {extra_opts}
)
nix-store --realise "${{common[@]}}" {targets} >/tmp/realised 2>/tmp/err
RC=$?
echo "REALISE_RC=$RC"
cat /tmp/err >&2
echo "===PATHINFO_BEGIN==="
python3 - {targets} <<'PY'
import json, subprocess, sys

merged = {{}}
for path in sys.argv[1:]:
    result = subprocess.run(
        ["nix", "path-info", "--json", path], capture_output=True, text=True
    )
    if result.returncode == 0:
        try:
            merged.update(json.loads(result.stdout))
        except ValueError:
            pass
print(json.dumps(merged))
PY
echo "===PATHINFO_END==="
echo "===ORPHANS_BEGIN==="
# Store residue an interrupted import could leave: in-progress `.tmp*` additions
# and the trash dir. A clean run leaves neither. `ls` (coreutils) only.
ls -1d /nix/store/.tmp* 2>/dev/null || true
ls -1 /nix/store/trash 2>/dev/null || true
echo "===ORPHANS_END==="
"""

# Appended when `integrity=True`: prove the surviving store path is intact via
# Nix's OWN content check (`nix-store --verify-path` recomputes the NAR hash and
# compares it to the registered one), THEN corrupt a byte and show the same
# check goes RED - the AC#3 bite, self-contained in one container run.
_INTEGRITY_TRAILER = r"""
echo "===VERIFY_CLEAN_BEGIN==="
nix-store --verify-path {targets} 2>&1
echo "VERIFY_CLEAN_RC=$?"
echo "===VERIFY_CLEAN_END==="
echo "===VERIFY_CORRUPT_BEGIN==="
python3 - {targets} <<'PY'
import os, sys
# Corrupt ONE byte inside the first realised path so the on-disk content no
# longer matches its registered NarHash. Runs as container root, which may write
# read-only store files; chmod first anyway so the intent is explicit.
for path in sys.argv[1:]:
    target = path if os.path.isfile(path) else None
    if target is None:
        for root, _dirs, files in os.walk(path):
            if files:
                target = os.path.join(root, files[0])
                break
    if target is None:
        print("NO_FILE_TO_CORRUPT", path)
        continue
    try:
        os.chmod(target, 0o644)
    except OSError:
        pass
    with open(target, "ab") as handle:
        handle.write(b"\xff")
    print("CORRUPTED", target)
    break
PY
nix-store --verify-path {targets} 2>&1
echo "VERIFY_CORRUPT_RC=$?"
echo "===VERIFY_CORRUPT_END==="
"""


class BackgroundClient:
    """A `client_run` in flight. `wait_result` blocks for completion and parses
    the same `ClientResult` the synchronous path returns, so a crash scenario
    reads the outcome identically - only the KILL happens in between."""

    def __init__(self, popen: subprocess.Popen):
        self._popen = popen

    def running(self) -> bool:
        return self._popen.poll() is None

    def wait_result(self, timeout: float = 300.0) -> ClientResult:
        try:
            stdout, stderr = self._popen.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            self._popen.kill()
            stdout, stderr = self._popen.communicate()
            # Fail-closed: a timed-out background client proved nothing.
            faux = types.SimpleNamespace(
                stdout=stdout or "",
                stderr=(stderr or "") + "\n[harness: client timed out]",
                returncode=124,
            )
            return _parse_client(faux)
        faux = types.SimpleNamespace(
            stdout=stdout or "", stderr=stderr or "", returncode=self._popen.returncode
        )
        return _parse_client(faux)


def _host_nar_size(fixtures: Fixtures, attr: str) -> int:
    """The on-disk NAR file size at the origin = the wire bytes for an
    UNCOMPRESSED payload (`big` is uncompressed by fixture design), so it is both
    the Content-Length the client sees and the 100%-of-transfer mark."""
    return (fixtures.cache / fixtures.entry(attr)["url"]).stat().st_size


def _daemon_action_at_bytes(
    pod: Pod,
    threshold: int,
    action: str,
    *,
    role: str = "daemon",
    deadline_s: float = 180.0,
) -> int:
    """Poll the proxy's in-flight NAR byte gauge and fire `action` ("kill" or
    "pause") on daemon `role` the instant the transfer crosses `threshold`
    bytes. `role` is "daemon" for the single-daemon crash suite (task-7) and
    "daemon-2" (etc.) for a middle-of-chain kill (task-11). Returns the observed
    byte count at the moment of action (or the last reading if the deadline
    passed without crossing - the caller asserts the crossing, so a miss fails
    loudly, and `nar_tmp_bytes` dies on a broken probe)."""
    fire = {"kill": pod.kill, "pause": pod.pause}[action]
    deadline = time.time() + deadline_s
    observed = 0
    while time.time() < deadline:
        observed = pod.nar_tmp_bytes()
        if observed >= threshold:
            fire(role)
            return observed
        time.sleep(0.02)
    return observed


def _daemon_reachable_at(index: int, timeout: float = 1.0) -> bool:
    """True iff daemon #index (1-based) answers /nix-cache-info on its host
    port - the chain counterpart of `daemon_reachable`, used to confirm a
    middle daemon really died after a kill."""
    port = HOST_DAEMON + (index - 1)
    try:
        status, _ = http_get(f"http://127.0.0.1:{port}/nix-cache-info", timeout)
    except OSError:
        return False
    return status == 200


def _kill_daemon_at_bytes(pod: Pod, threshold: int, deadline_s: float = 180.0) -> int:
    """SIGKILL the daemon once the NAR transfer crosses `threshold` bytes."""
    return _daemon_action_at_bytes(pod, threshold, "kill", deadline_s=deadline_s)


def _stall_daemon_at_bytes(pod: Pod, threshold: int, deadline_s: float = 180.0) -> int:
    """FREEZE (pause) the daemon once the NAR crosses `threshold` - the SIGSTOP
    stall (no RST/FIN)."""
    return _daemon_action_at_bytes(pod, threshold, "pause", deadline_s=deadline_s)


def _wait_proxy_activity(pod: Pod, deadline_s: float = 20.0) -> bool:
    """Block until the proxy has logged at least one request - the observable
    signal that the client has begun contacting substituters (it queries the
    testproxy's /nix-cache-info at startup). Lets the narinfo-phase kill trigger
    on real activity rather than a blind sleep."""
    deadline = time.time() + deadline_s
    while time.time() < deadline:
        if pod.proxy_log():
            return True
        time.sleep(0.02)
    return False


def _wait_for_proxy_record(
    pod: Pod, kind: str, needle: str, deadline_s: float = 45.0
) -> bool:
    """Block until a proxy log record of `kind` whose path contains `needle`
    appears (logged on completion). This is the observable trigger for the
    kill-between-narinfo-and-NAR case: the narinfo record appearing means the
    client has (just) received the narinfo."""
    deadline = time.time() + deadline_s
    while time.time() < deadline:
        for record in pod.proxy_log():
            if record.get("kind") == kind and needle in record.get("path", ""):
                return True
        time.sleep(0.02)
    return False


def _expect_exact_proxy_fault_count(
    pod: Pod,
    fault: str,
    expected: int,
    expect,
    assertion: str,
    *,
    deadline_s: float = 3.0,
) -> None:
    """Wait for completed proxy handlers, then require one exact fault count.

    A daemon header timeout can return 502 before testproxy's delayed handler
    appends its completion record. Polling observable activity and then the
    ground-truth log is readiness synchronization. Zero activity means every
    started handler has appended its record, so the exact final count rejects
    both missing and duplicated upstream attempts.
    """
    deadline = time.monotonic() + deadline_s
    in_flight = -1
    records = []
    while True:
        in_flight = pod.proxy_in_flight()
        records = [record for record in pod.proxy_log() if record.get("fault") == fault]
        if (
            in_flight == 0 and len(records) == expected
        ) or time.monotonic() >= deadline:
            break
        time.sleep(0.02)
    expect(
        in_flight == 0 and len(records) == expected,
        assertion,
        f"fault={fault!r} expected={expected} observed={len(records)} "
        f"in_flight={in_flight} "
        f"records={[(r.get('kind'), r.get('path'), r.get('status')) for r in records]}",
    )


def _section(stdout: str, name: str) -> str | None:
    """Extract a `===NAME_BEGIN=== ... ===NAME_END===` block from client output."""
    begin_marker = f"==={name}_BEGIN==="
    end_marker = f"==={name}_END==="
    begin = stdout.find(begin_marker)
    end = stdout.find(end_marker)
    if begin == -1 or end == -1:
        return None
    return stdout[begin + len(begin_marker) : end].strip()


def _rc_in_section(stdout: str, name: str, rc_key: str) -> int | None:
    section = _section(stdout, name)
    if section is None:
        return None
    for line in section.splitlines():
        if line.startswith(f"{rc_key}="):
            with contextlib.suppress(ValueError):
                return int(line.split("=", 1)[1])
    return None


def _looks_like_http_response(data: bytes) -> bool:
    """True iff `data` begins a valid HTTP response. The keep-alive desync oracle
    (AC#4) is exactly `not this` on the SECOND response: if a reused connection
    ever handed back NAR-tail bytes as the next 'response', they would NOT start
    with `HTTP/`. Defined as a function so the bite can exercise it directly."""
    return data.startswith(b"HTTP/")


def _raw_read_response(
    sock: socket.socket, timeout: float = 8.0
) -> tuple[bytes, bytes, bool]:
    """Read one HTTP/1.1 response from a raw socket. Returns
    (head_bytes, body_bytes, closed). Handles a SHORT body (fewer bytes than
    Content-Length, then the peer closes) - which is the truncation case - by
    returning what arrived and closed=True. Does not assume keep-alive framing."""
    sock.settimeout(timeout)
    buf = b""
    # Read until end of headers.
    while b"\r\n\r\n" not in buf:
        try:
            chunk = sock.recv(4096)
        except (TimeoutError, socket.timeout, OSError):
            return buf, b"", True
        if not chunk:
            return buf, b"", True
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    content_length = None
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            with contextlib.suppress(ValueError):
                content_length = int(line.split(b":", 1)[1].strip())
    body = rest
    closed = False
    if content_length is not None:
        while len(body) < content_length:
            try:
                chunk = sock.recv(4096)
            except (TimeoutError, socket.timeout, OSError):
                closed = True
                break
            if not chunk:
                closed = True  # peer closed before Content-Length: truncated
                break
            body += chunk
    return head, body, closed


# ---- scenario context + reporting ------------------------------------------


@dataclass
class Check:
    ok: bool
    name: str
    detail: str = ""


@dataclass
class Ctx:
    podman: str
    image: str
    fixtures: Fixtures
    scratch: Path

    def substituter_daemon_only(self) -> str:
        return f"http://127.0.0.1:{DAEMON_PORT}?priority=10"

    def substituter_daemon_and_fallback(self) -> str:
        # daemon preferred (priority 10), testproxy the explicit direct fallback
        # (priority 50) - S2 needs a real fallback target (AC#2).
        return (
            f"http://127.0.0.1:{DAEMON_PORT}?priority=10 "
            f"http://127.0.0.1:{PROXY_PORT}?priority=50"
        )

    def substituter_origin_only(self) -> str:
        return f"http://127.0.0.1:{ORIGIN_PORT}"


Expect = "callable expecting (ok, name, detail='')"


def make_expect(checks: list[Check]):
    def expect(ok: bool, name: str, detail: str = "") -> bool:
        checks.append(Check(bool(ok), name, detail))
        return bool(ok)

    return expect


# ---- scenarios -------------------------------------------------------------
#
# Each scenario is `fn(ctx, expect)`; it appends Checks. A scenario passes iff
# all its checks pass. Registered in SCENARIOS below.


def scenario_topology(ctx: Ctx, expect) -> None:
    """AC#2: nix.conf topology is pinnable - the daemon advertises a preferred
    priority (< 40) and WantMassQuery, so Nix orders it ahead of a real cache.
    """
    with Pod(ctx, "topology", ctx.fixtures.cache, with_daemon=True, expect=expect):
        status, body = http_get(f"http://127.0.0.1:{HOST_DAEMON}/nix-cache-info")
        text = body.decode()
        fields = dict(line.split(": ", 1) for line in text.splitlines() if ": " in line)
        priority = int(fields.get("Priority", "999"))
        expect(status == 200, "daemon serves nix-cache-info", f"status={status}")
        expect(
            priority < 40,
            "daemon advertises Priority < 40 (ordered ahead of cache.nixos.org)",
            f"Priority={priority}",
        )
        expect(
            fields.get("WantMassQuery") == "1",
            "daemon advertises WantMassQuery: 1",
            f"got {fields.get('WantMassQuery')!r}",
        )


def scenario_s1_byte_and_counts(ctx: Ctx, expect) -> None:
    """AC#1: S1 byte oracle + exact per-layer request counts through the chain.

    Cold: every NAR is fetched upstream exactly once. Warm repeat (fresh client,
    proxy COUNTERS reset but its disk cache kept): 0 upstream NAR hits paired
    with a nonzero received count - the oracle-pairing rule made concrete.
    """
    fixtures = ctx.fixtures
    targets = [fixtures.store_path(a) for a in ALL_ATTRS]
    with Pod(ctx, "s1", fixtures.cache, with_daemon=True, expect=expect) as pod:
        # -- cold --
        pod.proxy_reset()
        cold = pod.client_run(
            targets, ctx.substituter_daemon_only(), fixtures.public_key
        )
        expect(
            cold.exit_code == 0,
            "cold: realise through daemon succeeds",
            cold.stderr[-400:],
        )

        # Byte oracle: NarHash reported by the client == the signed manifest
        # hash for EVERY path. NarHash IS sha256 of `nix-store --dump`, so
        # equality is the bit-for-bit identity S1 requires.
        for attr in ALL_ATTRS:
            store_path = fixtures.store_path(attr)
            got = cold.narhash(store_path)
            expect(
                got == fixtures.nar_hash(attr),
                f"S1 byte oracle: {attr} NarHash matches signed upstream",
                f"got={got} want={fixtures.nar_hash(attr)}",
            )

        stats = pod.proxy_stats()
        nar_up = stats["upstream"].get("nar", 0)
        nar_rx = stats["received"].get("nar", 0)
        expect(
            nar_up == len(ALL_ATTRS),
            "cold count: exactly one upstream NAR fetch per payload",
            f"upstream nar={nar_up} want={len(ALL_ATTRS)}",
        )
        expect(
            nar_rx == len(ALL_ATTRS),
            "cold count: exactly one NAR served per payload (all misses)",
            f"received nar={nar_rx}",
        )

        # -- warm repeat: reset COUNTERS only (disk cache kept), fresh client --
        pod.proxy_reset()
        warm = pod.client_run(
            targets, ctx.substituter_daemon_only(), fixtures.public_key
        )
        expect(
            warm.exit_code == 0,
            "warm: realise through daemon succeeds",
            warm.stderr[-400:],
        )
        wstats = pod.proxy_stats()
        w_up = wstats["upstream"].get("nar", 0)
        w_rx = wstats["received"].get("nar", 0)
        expect(
            w_up == 0 and w_rx > 0,
            "warm count: 0 upstream NAR hits PAIRED with nonzero received (cache layer)",
            f"upstream nar={w_up} received nar={w_rx}",
        )


def scenario_s2_fallback(ctx: Ctx, expect) -> None:
    """AC#2: with the daemon absent, the build still succeeds via the explicit
    direct fallback, and the fallback ACTUALLY SERVED the bytes (request counts,
    not merely exit 0)."""
    fixtures = ctx.fixtures
    targets = [fixtures.store_path(a) for a in ALL_ATTRS]
    with Pod(ctx, "s2", fixtures.cache, with_daemon=False, expect=expect) as pod:
        # Sanity: the preferred substituter really is down.
        expect(not daemon_reachable(), "S2 precondition: daemon is not running", "")

        pod.proxy_reset()
        result = pod.client_run(
            targets, ctx.substituter_daemon_and_fallback(), fixtures.public_key
        )
        expect(
            result.exit_code == 0,
            "S2: build succeeds via fallback despite daemon down",
            result.stderr[-500:],
        )
        stats = pod.proxy_stats()
        rx = stats["received"].get("nar", 0)
        expect(
            rx == len(ALL_ATTRS),
            "S2: the fallback (testproxy) actually served the NAR bytes",
            f"received nar={rx} want={len(ALL_ATTRS)}",
        )
        # Byte oracle still holds on the fallback path.
        for attr in ALL_ATTRS:
            got = result.narhash(fixtures.store_path(attr))
            expect(
                got == fixtures.nar_hash(attr),
                f"S2 byte oracle: {attr} NarHash matches upstream via fallback",
                f"got={got}",
            )


def _tamper_scenario(ctx: Ctx, expect, kind: str, needle: str) -> None:
    fixtures = ctx.fixtures
    scratch = ctx.scratch / f"tamper-{kind}"
    if scratch.exists():
        shutil.rmtree(scratch)
    cache = build_tamper_tree(fixtures, scratch, kind)
    app_path = fixtures.store_path("app")
    with Pod(ctx, f"tamper-{kind}", cache, with_daemon=False, expect=expect) as pod:
        # Caller passes the FOREIGN key to prove the daemon ignores it.
        _n, _p, _s, foreign_pub = fx.keypair(
            fx.FOREIGN_SEED_PHRASE, fx.FOREIGN_KEY_NAME
        )
        result = pod.client_daemon_run(
            target=app_path,
            substituters=ctx.substituter_origin_only(),
            sys_keys=fixtures.public_key,
            caller_keys=foreign_pub,
        )
        expect(
            result.exit_code != 0,
            f"AC#3 [{kind}]: nix-daemon REJECTS the tampered path",
            f"exit={result.exit_code}",
        )
        expect(
            needle in result.stderr,
            f"AC#3 [{kind}]: rejection reason is {needle!r}",
            f"stderr tail: {result.stderr[-500:]}",
        )


# The DAEMON-side enforcement message differs from Nix's direct-store mode
# (check-fixtures.py). In direct mode the client says "lacks a signature by a
# trusted key"; substituting THROUGH nix-daemon, the untrusted caller's keys are
# ignored and the rejection reads "not signed by any of the keys in
# 'trusted-public-keys'" (empirically observed here - this IS the different proof
# AC#3 asks for, not a repeat of the direct-mode string).
SIG_REJECT_NEEDLE = "not signed by any of the keys in 'trusted-public-keys'"
# Content-integrity rejection: sig is valid (re-signed by the trusted test key),
# so only the NAR's actual hash can catch it.
HASH_REJECT_NEEDLE = "hash mismatch importing path"


def scenario_tamper_corrupt_sig(ctx: Ctx, expect) -> None:
    _tamper_scenario(ctx, expect, "corrupt-sig", SIG_REJECT_NEEDLE)


def scenario_tamper_foreign_key(ctx: Ctx, expect) -> None:
    _tamper_scenario(ctx, expect, "foreign-key", SIG_REJECT_NEEDLE)


def scenario_tamper_narhash(ctx: Ctx, expect) -> None:
    _tamper_scenario(ctx, expect, "narhash", HASH_REJECT_NEEDLE)


def scenario_daemon_positive_control(ctx: Ctx, expect) -> None:
    """Positive control for the three AC#3 daemon-path rejections: a PRISTINE
    `app` (refs `lib`) imports SUCCESSFULLY through the nix-daemon path as the
    untrusted uid 1000. Without this, the rejections could be passing because
    the client/daemon path is simply broken (wrong socket, unresolved user,
    dead substituter) rather than because of the tampering. The caller still
    passes the foreign key, which the daemon still ignores - it accepts here
    because the narinfo is validly signed by the trusted test key.
    """
    fixtures = ctx.fixtures
    app = fixtures.store_path("app")
    with Pod(
        ctx, "daemon-pos", fixtures.cache, with_daemon=False, expect=expect
    ) as pod:
        _n, _p, _s, foreign_pub = fx.keypair(
            fx.FOREIGN_SEED_PHRASE, fx.FOREIGN_KEY_NAME
        )
        result = pod.client_daemon_run(
            target=app,
            substituters=ctx.substituter_origin_only(),
            sys_keys=fixtures.public_key,
            caller_keys=foreign_pub,
        )
        expect(
            result.exit_code == 0,
            "daemon-path positive control: a pristine app imports as the untrusted user",
            f"exit={result.exit_code} stderr={result.stderr[-400:]}",
        )


def scenario_corrupt_nar(ctx: Ctx, expect) -> None:
    """AC#3 / TESTING.md prove-the-check-bites: the HASH gate catches NAR
    CONTENT corruption. Serves `lib` with a pristine, validly signed narinfo but
    a NAR whose content bytes are corrupted (a mid-payload flip that survives
    framing) - so the signature passes and only the content hash can catch it.
    Routed through the daemon, proving the daemon passes corruption through
    rather than masking it. Distinct from tamper-narhash (which mutates the
    narinfo): here the narinfo is untouched and the BYTES are wrong.
    """
    fixtures = ctx.fixtures
    scratch = ctx.scratch / "corrupt-nar"
    if scratch.exists():
        shutil.rmtree(scratch)
    cache = build_corrupt_nar_tree(fixtures, scratch)
    lib = fixtures.store_path("lib")
    with Pod(ctx, "corrupt-nar", cache, with_daemon=True, expect=expect) as pod:
        result = pod.client_run(
            [lib], ctx.substituter_daemon_only(), fixtures.public_key
        )
        expect(
            result.exit_code != 0,
            "corrupt-NAR: build FAILS (corruption is never silently accepted)",
            f"exit={result.exit_code}",
        )
        expect(
            result.narhash(lib) is None,
            "corrupt-NAR: the corrupt path was NOT imported into the store",
            "",
        )
        # SPECIFICALLY the hash gate, not any failure: a NAR-parse error would
        # prove nix rejects garbage, not that it verifies content.
        expect(
            HASH_REJECT_NEEDLE in result.stderr,
            f"corrupt-NAR: rejected as {HASH_REJECT_NEEDLE!r} (the content-hash "
            "gate, not a NAR-parse error)",
            f"stderr tail: {result.stderr[-400:]}",
        )


def scenario_absent_404(ctx: Ctx, expect) -> None:
    """AC#3 404-fidelity: an absent path -> 404 AT THE DAEMON (not turned into a
    502), the build proceeds (a sibling present path is still served), and the
    substituter is NOT marked failed.

    The oracle observes the DAEMON's own HTTP response - the boundary the
    property is about. The earlier version inspected the testproxy log, which is
    the wrong boundary: a daemon regression turning upstream 404 into 502 leaves
    the upstream log identical and would have passed. Here we query the daemon
    directly and read its status.
    """
    fixtures = ctx.fixtures
    present = fixtures.store_path("lib")
    absent = "/nix/store/00000000000000000000000000000000-nix-p2p-absent"
    absent_narinfo = fx.narinfo_name(absent)
    present_narinfo = fx.narinfo_name(present)
    with Pod(ctx, "absent", fixtures.cache, with_daemon=True, expect=expect) as pod:
        # Boundary observation: the DAEMON returns 404 for the absent path...
        status_absent, _ = http_get(f"http://127.0.0.1:{HOST_DAEMON}/{absent_narinfo}")
        expect(
            status_absent == 404,
            "404-fidelity: the daemon returns 404 for the absent path (not a 502)",
            f"daemon status={status_absent}",
        )
        # ...and still serves a present narinfo (it was not marked failed).
        status_present, _ = http_get(
            f"http://127.0.0.1:{HOST_DAEMON}/{present_narinfo}"
        )
        expect(
            status_present == 200,
            "404-fidelity: the daemon still serves the present narinfo (200)",
            f"daemon status={status_present}",
        )
        # And the build PROCEEDS: the present sibling still substitutes in a run
        # that also asks for the absent path. Asserted AFTER the 404 checks, so
        # the sibling-served proof cannot pass unless the 404 was truly benign.
        pod.proxy_reset()
        result = pod.client_run(
            [absent, present], ctx.substituter_daemon_only(), fixtures.public_key
        )
        got = result.narhash(present)
        expect(
            got == fixtures.nar_hash("lib"),
            "404-fidelity: the present sibling still substitutes despite the "
            "absent path's 404 (build proceeds, substituter not marked failed)",
            f"got={got} stderr={result.stderr[-300:]}",
        )


# ---- crash suite (task-7): S2 additive invariant under daemon crashes -------
#
# Every scenario asserts fallback ACTUALLY SERVED the bytes (proxy request
# counts / byte oracle), never exit 0 alone. The kill point is chosen by BYTES
# OBSERVED at the proxy or by an OBSERVED proxy log record - never a blind sleep.
# `big` (>=100 MiB, uncompressed) is the kill target: its transfer window is
# wide and its wire bytes equal its NAR bytes.

BIG_ATTR = "big"

# NAR throttle for the mid-transfer crash cases (proxy fault `throttle_nar_bps`).
# 8 MiB/s turns the 110 MiB `big` transfer into a ~14 s window - wide enough for
# an out-of-process observer to catch 50% and kill/freeze, short enough to keep
# the scenario in the SLOW tier's budget.
THROTTLE_BPS = 8 * 1024 * 1024


def _assert_fallback_served_big(
    pod: Pod, fixtures: Fixtures, expect, label: str
) -> None:
    """Shared oracle: the proxy served at least one FULL `big` NAR (bytes_sent ==
    file_size) to a client - the request-count proof that the fallback truly
    delivered the payload, not merely that the build exited 0."""
    big_size = _host_nar_size(fixtures, BIG_ATTR)
    big_url = fixtures.entry(BIG_ATTR)["url"]
    full = [
        record
        for record in pod.proxy_log()
        if record.get("kind") == "nar"
        and big_url in record.get("path", "")
        and record.get("bytes_sent") == big_size
    ]
    expect(
        len(full) >= 1,
        f"{label}: the fallback ACTUALLY served the full NAR (bytes_sent == file_size)",
        f"full-NAR records={len(full)} want>=1 (file_size={big_size})",
    )


def _wait_for_short_nar(
    pod: Pod, nar_url: str, file_size: int, deadline_s: float = 30.0
) -> tuple[list[dict], list[dict]]:
    """Poll the proxy log until a truncated NAR record (0 < bytes_sent <
    file_size) for `nar_url` appears, or the deadline passes. Returns
    (short_records, all_matching_records). The truncated record trails the kill
    because the proxy keeps draining origin->cache after the client vanished."""
    deadline = time.time() + deadline_s
    nar_records: list[dict] = []
    while time.time() < deadline:
        nar_records = [
            record
            for record in pod.proxy_log()
            if record.get("kind") == "nar" and nar_url in record.get("path", "")
        ]
        short = [r for r in nar_records if 0 < r.get("bytes_sent", 0) < file_size]
        if short:
            return short, nar_records
        time.sleep(0.1)
    return [], nar_records


def scenario_crash_daemon_absent(ctx: Ctx, expect) -> None:
    """AC#1(a): the daemon is ABSENT at nix-daemon store-open. The build must
    still succeed via the explicit direct fallback, which serves the bytes."""
    fixtures = ctx.fixtures
    big = fixtures.store_path(BIG_ATTR)
    with Pod(
        ctx, "crash-absent", fixtures.cache, with_daemon=False, expect=expect
    ) as pod:
        expect(not daemon_reachable(), "crash(a): daemon is absent at store-open", "")
        pod.proxy_reset()
        result = pod.client_run(
            [big], ctx.substituter_daemon_and_fallback(), fixtures.public_key
        )
        expect(
            result.exit_code == 0,
            "crash(a): build succeeds via fallback with the daemon absent",
            result.stderr[-400:],
        )
        _assert_fallback_served_big(pod, fixtures, expect, "crash(a)")
        got = result.narhash(big)
        expect(
            got == fixtures.nar_hash(BIG_ATTR),
            "crash(a): byte oracle - big NarHash matches upstream via fallback",
            f"got={got}",
        )


def scenario_crash_kill_mid_nar(ctx: Ctx, expect) -> None:
    """AC#1(b) + AC#3: SIGKILL the daemon at ~50% of the `big` NAR - triggered by
    BYTES OBSERVED at the proxy, not a sleep - then prove (1) a truncated-transfer
    event is visible in the proxy log AND the fallback served the full bytes
    (both, per TESTING.md), and (2) the surviving store is intact by Nix's own
    view with no orphaned tmp/lock residue; the corrupt-path bite shows the
    integrity check goes RED."""
    fixtures = ctx.fixtures
    big = fixtures.store_path(BIG_ATTR)
    big_size = _host_nar_size(fixtures, BIG_ATTR)
    big_url = fixtures.entry(BIG_ATTR)["url"]
    with Pod(
        ctx, "crash-midnar", fixtures.cache, with_daemon=True, expect=expect
    ) as pod:
        pod.proxy_reset()
        # Throttle the NAR so the transfer window is WIDE and deterministic: a
        # 110 MiB pod-loopback transfer otherwise completes before an
        # out-of-process kill can land mid-stream (measured: both records full).
        pod.proxy_faults(f"throttle_nar_bps={THROTTLE_BPS}")
        client = pod.client_run_async(
            [big],
            ctx.substituter_daemon_and_fallback(),
            fixtures.public_key,
            integrity=True,
        )
        observed = _kill_daemon_at_bytes(pod, big_size // 2)
        pct = (100 * observed // big_size) if big_size else 0
        pod.proxy_faults("")  # unthrottle so the fallback path serves at full speed
        expect(
            observed >= big_size // 2,
            "crash(b): kill fired at >=50% of the NAR by BYTES OBSERVED at the proxy",
            f"observed={observed}/{big_size} ({pct}%)",
        )
        expect(not daemon_reachable(), "crash(b): daemon is gone after the kill", "")
        result = client.wait_result(timeout=300)
        expect(
            result.exit_code == 0,
            "crash(b): build succeeds via fallback despite the mid-NAR kill",
            result.stderr[-600:],
        )
        got = result.narhash(big)
        expect(
            got == fixtures.nar_hash(BIG_ATTR),
            "crash(b): byte oracle - big NarHash matches upstream via fallback",
            f"got={got}",
        )
        # The truncated-transfer event: the daemon's NAR request to the proxy was
        # cut mid-stream, so its record shows bytes_sent short of file_size. That
        # record is only logged once the proxy finishes draining origin->cache
        # (it keeps caching the correct bytes after the client vanished), which
        # can trail the fallback's completion - so poll for it, bounded.
        short, nar_records = _wait_for_short_nar(pod, big_url, big_size)
        expect(
            len(short) >= 1,
            "crash(b): proxy log shows a truncated-transfer event (bytes_sent < file_size)",
            f"nar records (bytes_sent,status)="
            f"{[(r.get('bytes_sent'), r.get('status')) for r in nar_records]}",
        )
        _assert_fallback_served_big(pod, fixtures, expect, "crash(b)")

        # -- AC#3 post-crash store integrity, from the client's own output --
        clean_rc = _rc_in_section(result.stdout, "VERIFY_CLEAN", "VERIFY_CLEAN_RC")
        corrupt_rc = _rc_in_section(
            result.stdout, "VERIFY_CORRUPT", "VERIFY_CORRUPT_RC"
        )
        orphans = _section(result.stdout, "ORPHANS") or ""
        expect(
            clean_rc == 0,
            "crash(b)/AC#3: nix-store --verify-path passes on the surviving path",
            f"verify-clean rc={clean_rc}",
        )
        expect(
            orphans.strip() == "",
            "crash(b)/AC#3: no orphaned tmp/lock residue in the store after the crash",
            f"orphans={orphans!r}",
        )
        # BITE: the same integrity check MUST go RED once a store byte is flipped.
        expect(
            corrupt_rc is not None and corrupt_rc != 0,
            "crash(b)/AC#3 BITE: verify-path FAILS on an injected corrupt store path",
            f"verify-corrupt rc={corrupt_rc} (expected nonzero)",
        )


def scenario_crash_kill_during_narinfo(ctx: Ctx, expect) -> None:
    """AC#1(c): lose the daemon in the narinfo phase - before it ever delivers a
    complete narinfo, and before any NAR.

    OBSERVABILITY LIMIT (honest): the daemon serves /nix-cache-info LOCALLY
    (daemon/src/cacheinfo.rs), so the proxy never sees a daemon cache-info, and a
    narinfo only hits the proxy log on COMPLETION. There is thus no proxy event
    that means 'the daemon is mid-narinfo'. So this scenario does not claim a
    microsecond-precise 'during the response' hit; it ENFORCES the property that
    matters: two independent faults make it impossible for the daemon to have
    delivered a NAR when killed - `latency_narinfo_ms` holds the narinfo open for
    3 s, and `throttle_nar_bps` makes any NAR that somehow started far too slow to
    finish - and the kill fires on the first OBSERVED proxy activity (no blind
    sleep). The oracle then proves the daemon served NO NAR (from its own log)
    and the build recovered via fallback. If nix's probe ordering ever let a NAR
    complete first, the throttle+latency would still prevent it, and the no-NAR
    oracle would catch a regression rather than pass vacuously."""
    fixtures = ctx.fixtures
    big = fixtures.store_path(BIG_ATTR)
    big_url = fixtures.entry(BIG_ATTR)["url"]
    with Pod(
        ctx, "crash-narinfo", fixtures.cache, with_daemon=True, expect=expect
    ) as pod:
        pod.proxy_reset()
        # Widen the narinfo phase AND throttle any NAR, so a mistimed kill cannot
        # be beaten by a fast unthrottled NAR completing (review finding #1).
        pod.proxy_faults(f"latency_narinfo_ms=3000&throttle_nar_bps={THROTTLE_BPS}")
        client = pod.client_run_async(
            [big], ctx.substituter_daemon_and_fallback(), fixtures.public_key
        )
        expect(
            _wait_proxy_activity(pod),
            "crash(c): observed client activity at the proxy (narinfo phase open)",
            "",
        )
        pod.kill("daemon")  # fire on the OBSERVED activity, not a blind sleep
        pod.proxy_faults("")  # clear faults so the fallback path is not delayed
        expect(
            not daemon_reachable(),
            "crash(c): daemon killed in the narinfo phase",
            "",
        )
        # The ENFORCED invariant: the daemon served no NAR before dying. Its
        # per-substitution log line (server.rs) is emitted only on a 200 NAR, so
        # its absence proves no NAR was delivered - this is what makes 'lost
        # before the NAR' a real, biting assertion rather than a timing hope.
        daemon_log = pod.logs("daemon")
        expect(
            big_url not in daemon_log,
            "crash(c): the daemon served NO NAR before dying (kill was pre-NAR)",
            f"daemon log tail: {daemon_log[-300:]!r}",
        )
        result = client.wait_result(timeout=300)
        expect(
            result.exit_code == 0,
            "crash(c): build succeeds via fallback despite the narinfo-phase kill",
            result.stderr[-600:],
        )
        got = result.narhash(big)
        expect(
            got == fixtures.nar_hash(BIG_ATTR),
            "crash(c): byte oracle - big NarHash matches upstream via fallback",
            f"got={got}",
        )
        _assert_fallback_served_big(pod, fixtures, expect, "crash(c)")


def scenario_crash_kill_between_narinfo_and_nar(ctx: Ctx, expect) -> None:
    """AC#1(d) - THE S2 claim: kill the daemon BETWEEN the narinfo 200 and the
    NAR GET. A proxy latency fault on the NAR widens that phase so the kill lands
    before any NAR bytes reach the client; the trigger is the OBSERVED narinfo
    record. The question this answers: after losing the substituter it got the
    narinfo from, does nix recover via the next substituter, or fail? We assert
    recovery (build + fallback served) and REPORT whether nix re-queried the
    fallback's narinfo (an observation, not a pass/fail criterion)."""
    fixtures = ctx.fixtures
    big = fixtures.store_path(BIG_ATTR)
    big_narinfo = fx.narinfo_name(big)
    with Pod(
        ctx, "crash-between", fixtures.cache, with_daemon=True, expect=expect
    ) as pod:
        pod.proxy_reset()
        pod.proxy_faults("latency_nar_ms=3000")
        client = pod.client_run_async(
            [big], ctx.substituter_daemon_and_fallback(), fixtures.public_key
        )
        saw_narinfo = _wait_for_proxy_record(pod, "narinfo", big_narinfo)
        expect(
            saw_narinfo,
            "crash(d): observed the narinfo served (client has the narinfo)",
            "",
        )
        pod.kill("daemon")
        pod.proxy_faults("")  # clear latency so the fallback path is prompt
        expect(
            not daemon_reachable(),
            "crash(d): daemon killed after narinfo, before NAR",
            "",
        )
        result = client.wait_result(timeout=300)
        expect(
            result.exit_code == 0,
            "crash(d): build recovers via fallback after losing the daemon post-narinfo",
            result.stderr[-600:],
        )
        got = result.narhash(big)
        expect(
            got == fixtures.nar_hash(BIG_ATTR),
            "crash(d): byte oracle - big NarHash matches upstream via fallback",
            f"got={got}",
        )
        _assert_fallback_served_big(pod, fixtures, expect, "crash(d)")
        # Observation (not asserted): how nix recovered - re-query vs reuse.
        narinfo_count = sum(
            1
            for r in pod.proxy_log()
            if r.get("kind") == "narinfo" and big_narinfo in r.get("path", "")
        )
        recovery = (
            "re-queried fallback narinfo"
            if narinfo_count >= 2
            else "reused daemon narinfo"
        )
        print(
            f"  crash(d) OBSERVATION: nix {recovery} "
            f"(proxy saw {narinfo_count} big.narinfo request(s))"
        )


def scenario_crash_sigstop_stall(ctx: Ctx, expect) -> None:
    """AC#2: SIGSTOP-style stall (cgroup freeze: no RST/FIN). The DAEMON ITSELF is
    FROZEN mid-NAR, so the client's connection to it goes silent. TASK-25 landed a
    daemon body-idle timeout, but it does NOT govern THIS scenario by construction:
    the frozen party is the daemon, and a cgroup-frozen process cannot run its own
    tokio timer - so recovery here still relies entirely on nix's client-side
    `stalled-download-timeout`, which we pin low for a bounded test and MEASURE. (The
    daemon body-idle timeout bounds a DIFFERENT fault - daemon ALIVE, its UPSTREAM
    silent mid-body - which cannot be isolated in this topology because every e2e
    stall point is shared with the fallback route; it is proven at the daemon boundary
    by daemon-core `upstream::streaming_bounds_tests` instead.) The build must still
    complete via fallback within the bound."""
    fixtures = ctx.fixtures
    big = fixtures.store_path(BIG_ATTR)
    big_size = _host_nar_size(fixtures, BIG_ATTR)
    pinned_timeout_s = 8
    bound_s = pinned_timeout_s * 4  # generous upper bound for the pinned test
    with Pod(
        ctx, "crash-sigstop", fixtures.cache, with_daemon=True, expect=expect
    ) as pod:
        pod.proxy_reset()
        # Throttle the NAR so the freeze reliably lands mid-body (same rationale
        # as crash(b)). It is NOT cleared here: the frozen daemon's proxy thread
        # holds the throttled clone and stays blocked anyway, and the fallback
        # request is a fresh cache miss served from origin - a separate thread we
        # do want prompt, so we clear once the freeze is in place, below.
        pod.proxy_faults(f"throttle_nar_bps={THROTTLE_BPS}")
        # `download-attempts 1` is load-bearing (review finding #2): with nix's
        # default of 5, nix would RETRY the frozen daemon several times before
        # failing over, so `elapsed` would be several x the timeout and the bound
        # check below would flake RED on a nix retry policy, not a daemon defect.
        # Pinned to 1, the failover is deterministic: one stall, then fallback.
        extra = (
            f"--option stalled-download-timeout {pinned_timeout_s} "
            "--option connect-timeout 5 "
            "--option download-attempts 1"
        )
        client = pod.client_run_async(
            [big],
            ctx.substituter_daemon_and_fallback(),
            fixtures.public_key,
            extra_options=extra,
        )
        observed = _stall_daemon_at_bytes(pod, big_size // 4)
        pod.proxy_faults("")  # unthrottle so the fallback serves promptly
        expect(
            observed >= big_size // 4,
            "sigstop: daemon frozen mid-NAR by BYTES OBSERVED (no RST/FIN)",
            f"observed={observed}/{big_size}",
        )
        frozen_at = time.time()
        try:
            result = client.wait_result(timeout=300)
        finally:
            pod.unpause("daemon")  # let teardown proceed cleanly
        elapsed = time.time() - frozen_at
        expect(
            result.exit_code == 0,
            "sigstop: build eventually succeeds via fallback despite the frozen daemon",
            result.stderr[-600:],
        )
        got = result.narhash(big)
        expect(
            got == fixtures.nar_hash(BIG_ATTR),
            "sigstop: byte oracle - big NarHash matches upstream via fallback",
            f"got={got}",
        )
        _assert_fallback_served_big(pod, fixtures, expect, "sigstop")
        expect(
            elapsed <= bound_s,
            f"sigstop: recovered within {bound_s}s of the freeze "
            f"(nix-client-bounded: a cgroup-frozen daemon cannot run its own idle timer)",
            f"measured {elapsed:.1f}s (pinned stalled-download-timeout={pinned_timeout_s}s)",
        )
        print(
            f"  sigstop MEASURED: fallback completed {elapsed:.1f}s after the freeze; "
            f"nix stalled-download-timeout pinned to {pinned_timeout_s}s "
            "(the frozen DAEMON is nix-bounded here; the daemon body-idle timeout - "
            "TASK-25 - bounds a live daemon whose UPSTREAM stalls, proven in "
            "daemon-core upstream::streaming_bounds_tests)"
        )


def scenario_crash_keepalive_desync(ctx: Ctx, expect) -> None:
    """AC#4: an upstream truncation while the daemon SURVIVES must never let the
    next request on a reused keep-alive connection read NAR-tail-as-narinfo. We
    drive the daemon with a raw HTTP/1.1 client: first prove keep-alive reuse
    really happens (else the test is vacuous), then truncate a NAR mid-body and
    show the reused connection either closes or returns a valid response - never
    leftover NAR bytes. The oracle's discriminator is bite-checked directly."""
    fixtures = ctx.fixtures
    lib_size = _host_nar_size(fixtures, "lib")
    lib_url = fixtures.entry("lib")["url"]  # nar/<hash>.nar
    lib_narinfo = fx.narinfo_name(fixtures.store_path("lib"))  # <hash>.narinfo
    addr = ("127.0.0.1", HOST_DAEMON)
    with Pod(
        ctx, "crash-keepalive", fixtures.cache, with_daemon=True, expect=expect
    ) as pod:
        pod.proxy_reset()

        # (1) Keep-alive reuse really works: two cache-info GETs on one socket.
        with contextlib.closing(socket.create_connection(addr, timeout=8)) as sock:
            sock.sendall(
                b"GET /nix-cache-info HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                b"Connection: keep-alive\r\n\r\n"
            )
            head1, _body1, _closed1 = _raw_read_response(sock)
            sock.sendall(
                b"GET /nix-cache-info HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                b"Connection: keep-alive\r\n\r\n"
            )
            head2, _body2, _closed2 = _raw_read_response(sock)
        reuse_works = head1.startswith(b"HTTP/1.1 200") and head2.startswith(
            b"HTTP/1.1 200"
        )
        expect(
            reuse_works,
            "keepalive: the daemon reuses a keep-alive connection (test is not vacuous)",
            f"head1={head1[:20]!r} head2={head2[:20]!r}",
        )

        # (2) Truncate the NAR mid-body while the daemon survives, then issue a
        # narinfo GET on the SAME connection. `truncate_pct` (not
        # `connection_reset`) is used deliberately: we need a SHORT BODY under a
        # full Content-Length, which is what can desync framing - a reset would
        # give no response to reuse at all.
        pod.proxy_faults("truncate_pct=50")
        resp2_head = b""
        first_body_len = 0
        with contextlib.closing(socket.create_connection(addr, timeout=8)) as sock:
            sock.sendall(
                f"GET /{lib_url} HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                "Connection: keep-alive\r\n\r\n".encode()
            )
            _nhead, nbody, _nclosed = _raw_read_response(sock)
            first_body_len = len(nbody)
            with contextlib.suppress(OSError):
                sock.sendall(
                    f"GET /{lib_narinfo} HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                    "Connection: keep-alive\r\n\r\n".encode()
                )
                resp2_head, _rb, _rc = _raw_read_response(sock)
        pod.proxy_faults("")  # clear the fault

        expect(
            0 < first_body_len < lib_size,
            "keepalive: the first NAR was truncated (fault fired, not vacuous)",
            f"first body {first_body_len} of {lib_size}",
        )
        # THE property: the second read is never NAR-tail masquerading as a
        # response. Either the connection closed (empty) or a real HTTP response.
        desync = bool(resp2_head) and not _looks_like_http_response(resp2_head)
        expect(
            not desync,
            "keepalive: reused connection never returns NAR-tail-as-narinfo "
            "(closed, or a valid HTTP response)",
            f"second-response head={resp2_head[:40]!r}",
        )

        # BITE: the discriminator MUST reject NAR bytes and accept a real
        # response - otherwise the check above could pass on anything.
        nar_magic = b"\x0d\x00\x00\x00\x00\x00\x00\x00nix-archive-1"
        expect(
            (not _looks_like_http_response(nar_magic))
            and _looks_like_http_response(b"HTTP/1.1 200 OK\r\n"),
            "keepalive BITE: the desync discriminator flags NAR-tail and accepts HTTP",
            "",
        )


# ---- long-chain suite (task-11): depth-3 proxy composition ------------------
#
# Topology: client -> daemon-1 -> daemon-2 -> daemon-3 -> testproxy -> origin.
# The client's ONLY preferred substituter is daemon-1 (chain head) and each
# daemon's ONLY upstream is the next hop, so the testproxy receiving a request
# at all proves the whole chain carried it (the boundary oracle for "no hop
# skipped"). Byte identity is read at the CLIENT; request counts at the
# TESTPROXY - never a daemon's self-narration (per-hop daemon logs are used only
# as corroboration, anchored on the boundary count).

CHAIN_DEPTH = 3

# Per-hop added-latency bound, FIXED BEFORE IMPLEMENTATION (AC#2). On pod
# loopback a transparent-passthrough hop adds sub-millisecond forwarding; 50 ms
# is a generous ceiling. This number is a contract: change it ONLY by a recorded
# review note, never post-hoc to fit a measurement (task-11 AC#2).
PER_HOP_LATENCY_BOUND_MS = 50.0


def _time_get_median_ms(
    url: str, samples: int, *, warm: int = 1, timeout: float = 60.0
) -> tuple[float, int]:
    """Median wall time (ms) of `samples` GETs of `url`, after `warm` warm-up
    GETs so a first-fetch origin miss / TCP warmup does not skew the median.
    Returns (median_ms, last_status). Median (not mean) so a single scheduler
    hiccup does not move the number."""
    status = 0
    for _ in range(warm):
        status, _ = http_get(url, timeout=timeout)
    timings = []
    for _ in range(samples):
        start = time.perf_counter()
        status, _ = http_get(url, timeout=timeout)
        timings.append((time.perf_counter() - start) * 1000.0)
    return statistics.median(timings), status


def _latency_scales_with_depth(
    t_shallow_ms: float,
    t_deep_ms: float,
    shallow_hops: int,
    deep_hops: int,
    rel_tol: float = 0.25,
) -> bool:
    """True iff the deep-chain time looks like the shallow time SCALED by the
    hop-count ratio - the signature of a per-hop MULTIPLYING timeout. The
    correct (streamed/additive) model gives t_deep ~= t_shallow + small; a
    multiplying model gives t_deep ~= t_shallow * (deep_hops/shallow_hops). A
    pure function so the AC#2 bite exercises it directly on a synthetic
    multiplied sample, without building a broken daemon."""
    if t_shallow_ms <= 0 or shallow_hops <= 0:
        return False
    expected_if_multiplying = t_shallow_ms * (deep_hops / shallow_hops)
    return t_deep_ms >= expected_if_multiplying * (1.0 - rel_tol)


def scenario_chain_s1_and_counts(ctx: Ctx, expect) -> None:
    """AC#1: depth-3 chain - S1 byte identity + exact per-hop request counts.
    The `app` closure refs `lib`, so ONE realise exercises BOTH compression
    encodings (app=xz, lib=none) through all three hops."""
    fixtures = ctx.fixtures
    payload_attrs = ["app", "lib"]  # xz + none, one closure (app refs lib)
    # Name BOTH paths as realise targets: `app` alone pulls `lib` through its
    # closure, but the client script only collects `nix path-info` for the paths
    # it is handed, so the S1 byte oracle needs `lib` named to read its NarHash.
    targets = [fixtures.store_path(attr) for attr in payload_attrs]
    with Pod(
        ctx,
        "chain-s1",
        fixtures.cache,
        with_daemon=False,
        expect=expect,
        daemon_chain=CHAIN_DEPTH,
    ) as pod:
        pod.proxy_reset()
        cold = pod.client_run(
            targets, ctx.substituter_daemon_only(), fixtures.public_key
        )
        expect(
            cold.exit_code == 0,
            f"chain(depth-{CHAIN_DEPTH}): realise app closure through the chain succeeds",
            cold.stderr[-400:],
        )
        # S1 byte oracle at the CLIENT boundary, both compression encodings.
        for attr in payload_attrs:
            store_path = fixtures.store_path(attr)
            got = cold.narhash(store_path)
            comp = fixtures.entry(attr).get("compression", "?")
            expect(
                got == fixtures.nar_hash(attr),
                f"chain S1 byte oracle [{attr}/{comp}]: NarHash matches signed "
                f"manifest through {CHAIN_DEPTH} hops",
                f"got={got} want={fixtures.nar_hash(attr)}",
            )
        # Per-hop request counts, BOUNDARY oracle: the testproxy saw exactly one
        # upstream NAR fetch and served exactly one NAR per payload. A hop that
        # double-counted pushes these > len; a skipped hop severs the only route
        # to the testproxy, so the realise above would have failed.
        stats = pod.proxy_stats()
        nar_up = stats["upstream"].get("nar", 0)
        nar_rx = stats["received"].get("nar", 0)
        expect(
            nar_up == len(payload_attrs),
            "chain count (boundary): testproxy saw exactly one upstream NAR "
            "fetch per payload (no multiplication across hops)",
            f"upstream nar={nar_up} want={len(payload_attrs)}",
        )
        expect(
            nar_rx == len(payload_attrs),
            "chain count (boundary): testproxy served exactly one NAR per payload",
            f"received nar={nar_rx}",
        )
        # Per-hop corroboration: each daemon served each payload NAR exactly once
        # (localizes a skip/double-count to a hop; anchored on the boundary count
        # above, not a substitute for it).
        for idx in range(1, CHAIN_DEPTH + 1):
            log = pod.logs(f"daemon-{idx}")
            for attr in payload_attrs:
                url = fixtures.entry(attr)["url"]
                count = log.count(url)
                expect(
                    count == 1,
                    f"chain per-hop count: daemon-{idx} served {attr} NAR exactly once",
                    f"count={count}",
                )


def scenario_chain_corrupt_bite(ctx: Ctx, expect) -> None:
    """AC#1 BITE: prove the depth-3 S1 oracle catches a corrupted byte AT DEPTH.
    Serves `lib` with a pristine, validly-signed narinfo but a mid-payload
    corrupt NAR (the corrupt-nar fault at the origin) through all three hops -
    the build must FAIL with a content-hash error, never accept corruption
    because it crossed extra hops."""
    fixtures = ctx.fixtures
    scratch = ctx.scratch / "chain-corrupt-nar"
    if scratch.exists():
        shutil.rmtree(scratch)
    cache = build_corrupt_nar_tree(fixtures, scratch)
    lib = fixtures.store_path("lib")
    with Pod(
        ctx,
        "chain-corrupt",
        cache,
        with_daemon=False,
        expect=expect,
        daemon_chain=CHAIN_DEPTH,
    ) as pod:
        result = pod.client_run(
            [lib], ctx.substituter_daemon_only(), fixtures.public_key
        )
        expect(
            result.exit_code != 0,
            f"chain S1 BITE: corrupt NAR FAILS the build through {CHAIN_DEPTH} "
            "hops (corruption never accepted at depth)",
            f"exit={result.exit_code}",
        )
        expect(
            result.narhash(lib) is None,
            "chain S1 BITE: the corrupt path was NOT imported at depth",
            "",
        )
        expect(
            HASH_REJECT_NEEDLE in result.stderr,
            f"chain S1 BITE: rejected as {HASH_REJECT_NEEDLE!r} (content-hash "
            "gate holds at depth, not a NAR-parse error)",
            f"stderr tail: {result.stderr[-400:]}",
        )


def scenario_chain_absent_404(ctx: Ctx, expect) -> None:
    """AC#1 404-fidelity AT DEPTH: an absent path 404s cleanly through all three
    hops (never a 502 at any hop), the present sibling still serves, and the
    build proceeds. Observed at the chain HEAD's own HTTP response - the
    boundary the property is about."""
    fixtures = ctx.fixtures
    present = fixtures.store_path("lib")
    absent = "/nix/store/00000000000000000000000000000000-nix-p2p-absent"
    absent_narinfo = fx.narinfo_name(absent)
    present_narinfo = fx.narinfo_name(present)
    head = HOST_DAEMON  # daemon-1 (chain head) host port
    with Pod(
        ctx,
        "chain-absent",
        fixtures.cache,
        with_daemon=False,
        expect=expect,
        daemon_chain=CHAIN_DEPTH,
    ) as pod:
        status_absent, _ = http_get(f"http://127.0.0.1:{head}/{absent_narinfo}")
        expect(
            status_absent == 404,
            f"chain 404-fidelity: chain head returns 404 for the absent path "
            f"through {CHAIN_DEPTH} hops (not a 502)",
            f"status={status_absent}",
        )
        status_present, _ = http_get(f"http://127.0.0.1:{head}/{present_narinfo}")
        expect(
            status_present == 200,
            "chain 404-fidelity: chain head still serves the present narinfo (200)",
            f"status={status_present}",
        )
        pod.proxy_reset()
        result = pod.client_run(
            [absent, present], ctx.substituter_daemon_only(), fixtures.public_key
        )
        got = result.narhash(present)
        expect(
            got == fixtures.nar_hash("lib"),
            "chain 404-fidelity: present sibling still substitutes at depth "
            "(build proceeds, chain head not marked failed)",
            f"got={got} stderr={result.stderr[-300:]}",
        )


def scenario_chain_timeout_invariant(ctx: Ctx, expect) -> None:
    """AC#2: client-visible latency at depth 3 must NOT scale with depth.
    Measured on ONE pod by entering the SAME chain at different hops - daemon-N
    (1 hop, shallow) vs daemon-1 (CHAIN_DEPTH hops, deep) - which holds
    origin/proxy/host noise constant and isolates the added daemon hops.

    Two assertions, per the AC:
      (1) added latency < bound: (t_deep - t_shallow) / extra_hops < 50 ms/hop
          (PER_HOP_LATENCY_BOUND_MS, fixed before implementation);
      (2) total timeout does not multiply per hop: under a FIXED delay injected
          ONCE at the testproxy, the deep-chain time stays ~= the shallow time
          (both ~= the delay), NOT depth x the delay."""
    fixtures = ctx.fixtures
    present_narinfo = fx.narinfo_name(fixtures.store_path("lib"))
    with Pod(
        ctx,
        "chain-timeout",
        fixtures.cache,
        with_daemon=False,
        expect=expect,
        daemon_chain=CHAIN_DEPTH,
        daemon_extra_args=("--no-narinfo-cache",),
    ) as pod:
        shallow_url = (
            f"http://127.0.0.1:{pod.daemon_host_port(CHAIN_DEPTH)}/{present_narinfo}"
        )
        deep_url = f"http://127.0.0.1:{pod.daemon_host_port(1)}/{present_narinfo}"

        # (1) No-fault per-hop added latency (median of many small narinfo GETs).
        # WEAK GUARD by design: on pod loopback there is no real latency to
        # multiply, so this delta is sub-millisecond noise (it can even go
        # negative) and passes almost regardless of the design. It is a coarse
        # regression tripwire; the REAL non-multiplication oracle is part (2)
        # plus the synthetic BITE below, where a fixed delay makes the two
        # entry points diverge only if a hop re-incurs it.
        t_shallow, shallow_status = _time_get_median_ms(shallow_url, samples=25)
        t_deep, deep_status = _time_get_median_ms(deep_url, samples=25)
        expect(
            shallow_status == 200 and deep_status == 200,
            "chain timeout: narinfo probes served 200 at both entry points",
            f"shallow={shallow_status} deep={deep_status}",
        )
        extra_hops = CHAIN_DEPTH - 1
        per_hop = (t_deep - t_shallow) / extra_hops
        expect(
            per_hop < PER_HOP_LATENCY_BOUND_MS,
            f"chain AC#2: per-hop added latency < {PER_HOP_LATENCY_BOUND_MS:.0f} "
            "ms (bound fixed before implementation)",
            f"per_hop={per_hop:.2f} ms (deep={t_deep:.2f} shallow={t_shallow:.2f}, "
            f"{extra_hops} extra hops)",
        )
        print(
            f"  chain AC#2 MEASURED (no fault): shallow(1 hop)={t_shallow:.2f}ms "
            f"deep({CHAIN_DEPTH} hops)={t_deep:.2f}ms -> {per_hop:.2f}ms/hop "
            f"(bound {PER_HOP_LATENCY_BOUND_MS:.0f})"
        )

        # (2) Fixed delay injected ONCE at the testproxy. A correct streamed
        # passthrough incurs it once regardless of depth; a per-hop multiplying
        # design would incur it at every hop.
        #
        # The delay is kept WELL BELOW the daemon's default 15000ms header budget
        # (`daemon_core::HEADER_TIMEOUT_MS`). TASK-33 replaced the wave-1
        # FIXED per-hop timeout with a COMPOSING budget: the entry hop seeds an
        # end-to-end budget from its header_timeout and propagates a shrinking
        # remaining-budget (`x-nix-p2p-hop-budget-ms`) down the chain, so the whole
        # chain shares ONE deadline instead of each hop re-granting a fresh timeout.
        # The inherent serial-chain admission ceiling remains (an upstream of header
        # latency L is served iff L + (depth-1)*per_hop_overhead < budget, the
        # OUTERMOST hop 502ing first); on loopback per_hop_overhead is sub-ms, so the
        # flip is governed by L vs the budget and the depth term is WAN-scale
        # (TASK-35/TASK-111). This oracle stays below the budget to measure the
        # non-multiplication property it names.
        delay_ms = 300
        pod.proxy_reset()
        pod.proxy_faults(f"latency_narinfo_ms={delay_ms}")
        t_shallow_d, shallow_d_status = _time_get_median_ms(
            shallow_url, samples=3, warm=0
        )
        t_deep_d, deep_d_status = _time_get_median_ms(deep_url, samples=3, warm=0)
        pod.proxy_faults("")
        _expect_exact_proxy_fault_count(
            pod,
            "latency-narinfo",
            6,
            expect,
            "chain AC#2 proxy bite: all 3 shallow + 3 deep delayed probes reached the armed fault exactly once",
        )
        # Fail-fast: the whole invariant is vacuous if the delay never registered
        # (a degenerate ~0ms shallow would make the ratio predicate pass on
        # anything). Assert both probes were 200 AND the shallow entry actually
        # incurred most of the injected delay before trusting the ratio.
        expect(
            shallow_d_status == 200 and deep_d_status == 200,
            "chain AC#2: delayed narinfo probes served 200 at both entry points",
            f"shallow={shallow_d_status} deep={deep_d_status}",
        )
        expect(
            t_shallow_d >= 0.5 * delay_ms,
            f"chain AC#2 precondition: the injected {delay_ms}ms delay registered "
            "at the shallow entry (invariant is not vacuous)",
            f"shallow={t_shallow_d:.1f}ms want>={0.5 * delay_ms:.0f}ms",
        )
        multiplies = _latency_scales_with_depth(t_shallow_d, t_deep_d, 1, CHAIN_DEPTH)
        expect(
            not multiplies,
            f"chain AC#2: a fixed {delay_ms}ms upstream delay does NOT multiply "
            f"per hop (deep ~= shallow, not {CHAIN_DEPTH}x)",
            f"shallow={t_shallow_d:.1f}ms deep={t_deep_d:.1f}ms",
        )
        expect(
            (t_deep_d - t_shallow_d) < extra_hops * PER_HOP_LATENCY_BOUND_MS,
            "chain AC#2: even under the fixed delay the deep-vs-shallow gap stays "
            "within the per-hop bound (the delay is incurred once, not per hop)",
            f"gap={t_deep_d - t_shallow_d:.1f}ms "
            f"bound={extra_hops * PER_HOP_LATENCY_BOUND_MS:.0f}ms",
        )
        print(
            f"  chain AC#2 MEASURED (fixed {delay_ms}ms delay): "
            f"shallow={t_shallow_d:.1f}ms deep={t_deep_d:.1f}ms "
            f"(a multiplying design would give deep~={delay_ms * CHAIN_DEPTH}ms)"
        )

        # BITE: the non-multiplication predicate MUST flag a synthetic per-hop
        # multiplied sample - else the check above could pass on anything.
        synthetic_deep = t_shallow_d * CHAIN_DEPTH
        expect(
            _latency_scales_with_depth(t_shallow_d, synthetic_deep, 1, CHAIN_DEPTH),
            "chain AC#2 BITE: the invariant goes RED on a synthetic per-hop-"
            "multiplied latency sample",
            f"synthetic deep={synthetic_deep:.1f}ms from shallow={t_shallow_d:.1f}ms",
        )


def scenario_chain_kill_middle_daemon(ctx: Ctx, expect) -> None:
    """AC#3: kill the MIDDLE daemon mid-NAR; the client build still succeeds via
    the explicit direct fallback (not merely the next daemon), and the failure
    mode is visible in the logs. A companion control then proves the recovery is
    REAL: with the middle hop still dead and NO fallback, the chain build FAILS -
    the middle hop is load-bearing, so a skipped hop goes red."""
    fixtures = ctx.fixtures
    big = fixtures.store_path(BIG_ATTR)
    big_size = _host_nar_size(fixtures, BIG_ATTR)
    big_url = fixtures.entry(BIG_ATTR)["url"]
    lib = fixtures.store_path("lib")
    middle = 2  # of a depth-3 chain, daemon-2 is the middle hop
    with Pod(
        ctx,
        "chain-killmid",
        fixtures.cache,
        with_daemon=False,
        expect=expect,
        daemon_chain=CHAIN_DEPTH,
    ) as pod:
        pod.proxy_reset()
        # Throttle the NAR so the transfer window is wide and the mid-stream kill
        # lands deterministically (same rationale as task-7 crash(b)).
        pod.proxy_faults(f"throttle_nar_bps={THROTTLE_BPS}")
        client = pod.client_run_async(
            [big], ctx.substituter_daemon_and_fallback(), fixtures.public_key
        )
        observed = _daemon_action_at_bytes(
            pod, big_size // 2, "kill", role=f"daemon-{middle}"
        )
        pct = (100 * observed // big_size) if big_size else 0
        pod.proxy_faults("")  # unthrottle so the fallback serves at full speed
        expect(
            observed >= big_size // 2,
            f"chain AC#3: killed daemon-{middle} (middle) at >=50% of the NAR by "
            "BYTES OBSERVED at the proxy",
            f"observed={observed}/{big_size} ({pct}%)",
        )
        expect(
            not _daemon_reachable_at(middle),
            f"chain AC#3: daemon-{middle} (middle) is gone after the kill",
            "",
        )
        expect(
            _daemon_reachable_at(1),
            "chain AC#3: the chain head (daemon-1) survived - only the middle died",
            "",
        )
        result = client.wait_result(timeout=300)
        expect(
            result.exit_code == 0,
            "chain AC#3: build succeeds via fallback despite the middle-daemon kill",
            result.stderr[-600:],
        )
        got = result.narhash(big)
        expect(
            got == fixtures.nar_hash(BIG_ATTR),
            "chain AC#3: byte oracle - big NarHash matches upstream via fallback",
            f"got={got}",
        )
        _assert_fallback_served_big(pod, fixtures, expect, "chain AC#3")
        # Failure mode visible in logs: the middle-daemon death cut the in-flight
        # transfer, so the proxy log shows a truncated-transfer event.
        short, nar_records = _wait_for_short_nar(pod, big_url, big_size)
        expect(
            len(short) >= 1,
            "chain AC#3: failure mode visible - proxy log shows a truncated-"
            "transfer event (bytes_sent < file_size)",
            f"nar records (bytes_sent,status)="
            f"{[(r.get('bytes_sent'), r.get('status')) for r in nar_records]}",
        )

        # Companion control (recovery is REAL / skip-bite): daemon-2 is still
        # dead. With daemon-1 ONLY (no fallback) a FRESH client cannot deliver -
        # the middle hop is load-bearing, so the build FAILS. This proves the
        # success above came from the fallback, not the chain limping on.
        expect(
            not _daemon_reachable_at(middle),
            "chain AC#3 control: middle daemon still dead for the no-fallback probe",
            "",
        )
        no_fallback = pod.client_run(
            [lib], ctx.substituter_daemon_only(), fixtures.public_key
        )
        expect(
            no_fallback.exit_code != 0,
            "chain AC#3 BITE: with the middle hop dead and NO fallback, the chain "
            "build FAILS (middle hop is load-bearing; a skipped hop goes red)",
            f"exit={no_fallback.exit_code}",
        )


def _raw_get(port: int, path: str, timeout: float = 30.0) -> dict:
    """Raw HTTP/1.1 GET against a host-published port, returning a dict with
    `status`, `content_length`, `body` (bytes) and `complete` (body length ==
    advertised Content-Length). Raw (not urllib) so a TRUNCATED transfer - the
    body ending short of Content-Length, which urllib raises on - is an
    observation here, not an exception. `status=None` means the peer produced no
    valid HTTP response (a reset)."""
    if not path.startswith("/"):
        path = "/" + path
    try:
        sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    except OSError:
        return {"status": None, "content_length": None, "body": b"", "complete": False}
    sock.settimeout(timeout)
    raw = b""
    try:
        sock.sendall(
            f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
            f"Connection: close\r\n\r\n".encode()
        )
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            raw += chunk
    except OSError:
        # A reset mid-exchange: treat what we have as the (possibly empty)
        # response, flagged incomplete below.
        pass
    finally:
        sock.close()

    split = raw.find(b"\r\n\r\n")
    if split < 0:
        return {"status": None, "content_length": None, "body": b"", "complete": False}
    head = raw[:split].decode("latin1")
    lines = head.split("\r\n")
    status = None
    parts = lines[0].split(" ")
    if len(parts) >= 2 and parts[1].isdigit():
        status = int(parts[1])
    content_length = None
    for line in lines[1:]:
        if ":" in line:
            name, _, value = line.partition(":")
            if name.strip().lower() == "content-length" and value.strip().isdigit():
                content_length = int(value.strip())
    body = raw[split + 4 :]
    complete = (content_length is None) or (len(body) == content_length)
    return {
        "status": status,
        "content_length": content_length,
        "body": body,
        "complete": complete,
    }


def _matrix_depth_port(pod: Pod, depth: int) -> int:
    """Host port whose chain-entry traverses exactly `depth` hops. daemon #index
    traverses (CHAIN_DEPTH - index + 1) hops, so depth `d` enters at index
    CHAIN_DEPTH - d + 1: depth 1 = daemon-3 (shallow), depth 3 = daemon-1 (deep)."""
    index = CHAIN_DEPTH - depth + 1
    return pod.daemon_host_port(index)


def scenario_fault_depth_matrix(ctx: Ctx, expect) -> None:
    """AC#1: the FULL fault x depth matrix - each of the 7 testproxy fault modes
    (mode 8 throttle is a crash-window aid, not an adversarial fault, and is
    exercised by the crash suite) injected at the origin boundary and observed at
    chain depths 1, 2 and 3 on ONE depth-3 pod (entering at daemon-3/-2/-1).

    Observed at the RIGHT boundary - the CLIENT view (raw HTTP status/bytes) and
    the testproxy - never daemon self-narration. Each fault's assertion CONTRASTS
    with the fault-off baseline captured first, so a cell that could not tell
    faulted from clean is not a passing cell (oracle-bite by construction)."""
    fixtures = ctx.fixtures
    present_narinfo = fx.narinfo_name(fixtures.store_path("lib"))
    nar_url = fixtures.entry("lib")["url"]
    depths = (1, 2, 3)

    with Pod(
        ctx,
        "fault-matrix",
        fixtures.cache,
        with_daemon=False,
        expect=expect,
        daemon_chain=CHAIN_DEPTH,
        daemon_extra_args=("--no-narinfo-cache",),
    ) as pod:
        ports = {d: _matrix_depth_port(pod, d) for d in depths}

        # -- fault-off baseline (the contrast every cell is measured against) --
        pod.proxy_faults("")
        pod.proxy_reset()

        def _timed_get(port: int, path: str) -> tuple[dict, float]:
            start = time.perf_counter()
            resp = _raw_get(port, path)
            return resp, (time.perf_counter() - start) * 1000.0

        # Median of a few warm fault-off narinfo GETs per depth, so the mode1
        # DELTA below is against a real baseline (not a fixed threshold a slow
        # no-op could clear).
        base_ms = {}
        for d in depths:
            samples = sorted(_timed_get(ports[d], present_narinfo)[1] for _ in range(5))
            base_ms[d] = samples[len(samples) // 2]
        clean_info = {d: _raw_get(ports[d], present_narinfo) for d in depths}
        clean_nar = {d: _raw_get(ports[d], nar_url) for d in depths}
        for d in depths:
            expect(
                clean_info[d]["status"] == 200 and clean_nar[d]["status"] == 200,
                f"matrix baseline depth {d}: narinfo+nar both 200 fault-off",
                f"info={clean_info[d]['status']} nar={clean_nar[d]['status']}",
            )
            expect(
                clean_nar[d]["complete"] and len(clean_nar[d]["body"]) > 0,
                f"matrix baseline depth {d}: NAR is a complete non-empty body",
                f"len={len(clean_nar[d]['body'])} cl={clean_nar[d]['content_length']}",
            )
        clean_nar_bytes = clean_nar[1]["body"]
        clean_info_bytes = clean_info[1]["body"]

        # -- mode 1: added latency (sub-timeout) - tolerated, and ACTUALLY felt --
        # Timing evidence as a real DELTA (codex re-gate #4): fault-on elapsed
        # MINUS the fault-off baseline must recover most of the injected latency.
        # A no-op fault gives ~0 delta and FAILS this cell (not a fixed threshold a
        # slow baseline could clear). Tolerance 0.6x absorbs scheduling jitter.
        injected_ms = 200
        pod.proxy_reset()
        pod.proxy_faults(f"latency_narinfo_ms={injected_ms}")
        for d in depths:
            r, on_ms = _timed_get(ports[d], present_narinfo)
            delta_ms = on_ms - base_ms[d]
            expect(
                r["status"] == 200 and delta_ms >= 0.6 * injected_ms,
                f"matrix mode1 latency depth {d}: served 200 AND the {injected_ms}ms "
                f"injection shows up as a real delta over the fault-off baseline",
                f"status={r['status']} on={on_ms:.0f}ms base={base_ms[d]:.0f}ms "
                f"delta={delta_ms:.0f}ms want>={0.6 * injected_ms:.0f}ms",
            )
        pod.proxy_faults("")
        _expect_exact_proxy_fault_count(
            pod,
            "latency-narinfo",
            len(depths),
            expect,
            "matrix mode1 proxy bite: every depth reached the latency fault exactly once",
        )

        # -- mode 2: HTTP 503 - forwarded verbatim (status fidelity) ----------
        pod.proxy_reset()
        pod.proxy_faults("http_error=503&http_error_kind=narinfo")
        for d in depths:
            r = _raw_get(ports[d], present_narinfo)
            expect(
                r["status"] == 503,
                f"matrix mode2 http-503 depth {d}: upstream 503 forwarded verbatim",
                f"status={r['status']}",
            )
        pod.proxy_faults("")
        _expect_exact_proxy_fault_count(
            pod,
            "http-error-503",
            len(depths),
            expect,
            "matrix mode2 proxy bite: every depth reached the HTTP 503 fault exactly once",
        )

        # -- mode 3: connection reset - fast, clean 502 to the client ---------
        pod.proxy_reset()
        pod.proxy_faults("connection_reset=narinfo")
        for d in depths:
            r = _raw_get(ports[d], present_narinfo)
            expect(
                r["status"] == 502,
                f"matrix mode3 reset depth {d}: transport reset -> clean 502",
                f"status={r['status']}",
            )
        pod.proxy_faults("")
        _expect_exact_proxy_fault_count(
            pod,
            "connection-reset",
            len(depths),
            expect,
            "matrix mode3 proxy bite: every depth reached the reset fault exactly once",
        )

        # -- mode 4: truncated NAR - short body survives the chain ------------
        pod.proxy_faults("truncate_pct=50")
        for d in depths:
            r = _raw_get(ports[d], nar_url)
            expect(
                (not r["complete"]) and 0 < len(r["body"]) < len(clean_nar_bytes),
                f"matrix mode4 truncate depth {d}: client sees a SHORT NAR body "
                "(Content-Length full, bytes fewer) through the chain",
                f"len={len(r['body'])} full={len(clean_nar_bytes)} "
                f"complete={r['complete']}",
            )
        pod.proxy_faults("")
        pod.proxy_reset()  # drop any short cache residue before the next mode

        # -- mode 5: corrupted NAR - bytes differ, length preserved -----------
        pod.proxy_faults("corrupt_nar=1")
        for d in depths:
            r = _raw_get(ports[d], nar_url)
            expect(
                r["status"] == 200
                and len(r["body"]) == len(clean_nar_bytes)
                and r["body"] != clean_nar_bytes,
                f"matrix mode5 corrupt depth {d}: same-length DIFFERENT bytes "
                "reach the client (daemon does not mask corruption; nix is the arbiter)",
                f"status={r['status']} len={len(r['body'])} "
                f"differs={r['body'] != clean_nar_bytes}",
            )
        pod.proxy_faults("")

        # -- mode 6: wrong/stale narinfo - mutated metadata survives ----------
        pod.proxy_reset()
        pod.proxy_faults("wrong_narinfo=1")
        for d in depths:
            r = _raw_get(ports[d], present_narinfo)
            expect(
                r["status"] == 200 and r["body"] != clean_info_bytes,
                f"matrix mode6 wrong-narinfo depth {d}: mutated narinfo forwarded "
                "verbatim (differs from clean; nix rejects on sig/hash)",
                f"status={r['status']} differs={r['body'] != clean_info_bytes}",
            )
        pod.proxy_faults("")
        _expect_exact_proxy_fault_count(
            pod,
            "wrong-narinfo",
            len(depths),
            expect,
            "matrix mode6 proxy bite: every depth reached the wrong-narinfo fault exactly once",
        )

        # -- mode 7: upstream unreachable - fast, clean 502 at every depth ----
        pod.proxy_reset()
        pod.proxy_faults("unreachable=1")
        for d in depths:
            start = time.perf_counter()
            r = _raw_get(ports[d], present_narinfo)
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            expect(
                r["status"] == 502 and elapsed_ms < 5000,
                f"matrix mode7 unreachable depth {d}: fast clean 502 "
                f"({elapsed_ms:.0f}ms < 5000)",
                f"status={r['status']} elapsed={elapsed_ms:.0f}ms",
            )
        pod.proxy_faults("")
        _expect_exact_proxy_fault_count(
            pod,
            "unreachable",
            len(depths),
            expect,
            "matrix mode7 proxy bite: every depth reached the unreachable fault exactly once",
        )


def scenario_chain_timeout_boundary(ctx: Ctx, expect) -> None:
    """TASK-33: pin the upstream-latency (L) vs end-to-end header BUDGET (T)
    boundary that flips a narinfo GET 200 -> 502 at FULL chain depth, and PROVE it
    MOVES when the budget changes. The daemon's `--header-timeout-ms` seeds the
    chain's shared end-to-end budget (TASK-33 composing budget), so it is the
    controllable lever here.

    HONEST SCOPE (the reopened codex NO-GO lesson - do NOT regress it): this does
    NOT pin a *depth*-dependent boundary, and the composing budget does NOT claim
    to remove the depth term. The entry hop is always the binding constraint at its
    own budget, and on pod loopback the per-hop connect/send overhead is sub-ms, so
    the depth-composition term (L + (depth-1)*overhead) is below the noise floor:
    depth 1 and depth 3 flip TOGETHER at L~=T and cannot be honestly separated
    here. So the asserted CLAIM is only: at FULL chain depth (depth-3 entry, worst
    case) the flip is governed by L vs the budget and moves with the budget. The
    all-depths statuses are PRINTED as an observation (they agree), never asserted
    as a depth boundary. The composing-budget MECHANISM itself (propagation +
    a tighter downstream budget bounding a hop's wait) is unit/integration-pinned
    in daemon-core `upstream::budget_tests`; the raw depth term's real-WAN
    validation is deferred to TASK-35 / TASK-111 (loopback cannot do WAN RTT).

    FALSIFIABILITY (qa N1): the bite is the PAIR, not either assertion alone -
    'L=900 -> 502 at T=500' AND 'L=900 -> 200 at T=1200' TOGETHER require the flip
    to depend on T (T=500 < 900 < T=1200). Either alone could pass on a broken
    daemon (always-502 or always-200)."""
    fixtures = ctx.fixtures
    present_narinfo = fx.narinfo_name(fixtures.store_path("lib"))
    depths = (1, 2, 3)
    deep = CHAIN_DEPTH  # depth-3 entry (daemon-1): worst case, the full chain

    def status_at_depth(pod: Pod, depth: int, latency_ms: int) -> int:
        pod.proxy_reset()
        pod.proxy_faults(f"latency_narinfo_ms={latency_ms}")
        st = _raw_get(_matrix_depth_port(pod, depth), present_narinfo, timeout=15.0)[
            "status"
        ]
        pod.proxy_faults("")
        _expect_exact_proxy_fault_count(
            pod,
            "latency-narinfo",
            1,
            expect,
            f"timeout boundary proxy bite: the L={latency_ms}ms depth-{depth} probe reached the latency fault exactly once",
        )
        return st

    def observe_all(pod: Pod, latency_ms: int) -> dict:
        pod.proxy_reset()
        pod.proxy_faults(f"latency_narinfo_ms={latency_ms}")
        out = {
            d: _raw_get(_matrix_depth_port(pod, d), present_narinfo, timeout=15.0)[
                "status"
            ]
            for d in depths
        }
        pod.proxy_faults("")
        _expect_exact_proxy_fault_count(
            pod,
            "latency-narinfo",
            len(depths),
            expect,
            f"timeout boundary observation: L={latency_ms}ms reached the latency fault exactly once at every depth",
        )
        return out

    # Pod A: tight per-hop timeout T=500ms. Assert the L-vs-T flip at FULL depth.
    with Pod(
        ctx,
        "timeout-boundary-a",
        fixtures.cache,
        with_daemon=False,
        expect=expect,
        daemon_chain=CHAIN_DEPTH,
        daemon_extra_args=("--no-narinfo-cache", "--header-timeout-ms", "500"),
    ) as pod:
        below = status_at_depth(pod, deep, 250)  # L < T -> served
        above = status_at_depth(pod, deep, 900)  # L > T -> timed out
        expect(
            below == 200,
            "timeout boundary T=500 (full depth-3): L=250ms (<T) serves 200",
            f"status={below}",
        )
        expect(
            above == 502,
            "timeout boundary T=500 (full depth-3): L=900ms (>T) flips to 502",
            f"status={above}",
        )
        print(
            f"  TASK-33 L-vs-T at T=500ms: L=250->{observe_all(pod, 250)}; "
            f"L=900->{observe_all(pod, 900)} (all-depths OBSERVATION, loopback: "
            "no depth separation - the honest limit)"
        )

    # Pod B: wider per-hop timeout T=1200ms. The SAME L=900ms that 502'd at T=500
    # now serves 200 at full depth - the boundary MOVED with the timeout (the
    # bite; falsifiability is this paired with the T=500 L=900->502 above).
    with Pod(
        ctx,
        "timeout-boundary-b",
        fixtures.cache,
        with_daemon=False,
        expect=expect,
        daemon_chain=CHAIN_DEPTH,
        daemon_extra_args=("--no-narinfo-cache", "--header-timeout-ms", "1200"),
    ) as pod:
        moved = status_at_depth(pod, deep, 900)  # L < new T -> served again
        expect(
            moved == 200,
            "TASK-33 BITE (full depth-3): L=900ms that flipped 502 at T=500 now "
            "serves 200 at T=1200 - the 200->502 boundary MOVES with the timeout",
            f"status={moved}",
        )
        print(
            f"  TASK-33 boundary MOVED: L=900 at T=1200 (full depth) -> {moved} "
            "(was 502 at T=500)"
        )


# ---- S6: peer-served NAR over iroh (task-41, the wave-2 acceptance signal) --
#
# Topology: node B seeds the raw NARs into an iroh provider; node A resolves each
# NarHash via a configured claim and fetches the NAR from B over iroh (whole-blob,
# BLAKE3-gated), rewrites the narinfo to raw (task-49), and a REAL nix client
# accepts the peer-served bytes. The oracle is hardened per the wave-2 review:
#   - the peer-served count is node B's PROVIDER byte counter (ground truth), not
#     node A's self-report;
#   - 0 upstream NAR egress is non-vacuous because the client store is absent-
#     before (a fresh --rm container) and a peers-OFF contrast arm proves the same
#     build pulls the FULL NAR from upstream (the egress channel is not dead);
#   - "cache untouched" is scoped honestly: NAR-payload egress == 0, while narinfo
#     egress is asserted NONZERO as context (narinfo still comes from upstream in
#     wave-2a - claiming otherwise would be an overclaim).

# app (xz upstream -> exercises the compressed->raw rewrite) references lib (raw);
# both are peer-served so upstream NAR egress is a clean 0 for the whole closure.
S6_ATTRS = ["app", "lib"]


def scenario_s6_p2p(ctx: Ctx, expect) -> None:
    """S6 core: a real nix build served from a peer over iroh, byte-identical,
    with the hardened 0-egress oracle + the peers-OFF contrast arm."""
    fixtures = ctx.fixtures
    seed_dir, seeds = build_p2p_seed_dir(fixtures, ctx.scratch / "s6-seed", S6_ATTRS)
    # Realise BOTH paths explicitly (app pulls lib transitively anyway) so
    # `nix path-info` reports a NarHash for each and the byte oracle can check
    # both - a transitive-only path is substituted correctly but not queryable.
    targets = [fixtures.store_path(a) for a in S6_ATTRS]
    expected_served = sum(s.nar_size for s in seeds)

    # -- peers ON: the peer serves the whole closure --
    with Pod(
        ctx,
        "s6",
        fixtures.cache,
        with_daemon=False,
        expect=expect,
        p2p_seed_dir=seed_dir,
        p2p_seeds=seeds,
    ) as pod:
        # absent-before: a fresh --rm client container has only the image closure
        # in its store, so app+lib are absent before this build (the 0-egress is
        # therefore about THIS acquisition, not a warm store).
        pod.proxy_reset()
        res = pod.client_run(
            targets, ctx.substituter_daemon_only(), fixtures.public_key
        )
        expect(
            res.exit_code == 0,
            "S6: real nix build completes with the NAR served by node B over iroh",
            res.stderr[-600:],
        )
        for attr in S6_ATTRS:
            sp = fixtures.store_path(attr)
            got = res.narhash(sp)
            expect(
                got == fixtures.nar_hash(attr),
                f"S6 S1 byte-identity: {attr} NarHash matches signed upstream",
                f"got={got} want={fixtures.nar_hash(attr)}",
            )

        stats = pod.proxy_stats()
        nar_up = stats["upstream"].get("nar", 0)
        ninfo_up = stats["upstream"].get("narinfo", 0)
        served = pod.node_b_served_bytes(want_at_least=expected_served)
        # THE oracle: 0 NAR-payload egress PAIRED with node B's ground-truth
        # provider byte counter (not node A's self-report).
        expect(
            nar_up == 0 and served >= expected_served,
            "S6 oracle: 0 upstream NAR egress PAIRED with node B provider-counted "
            "peer-served bytes",
            f"upstream.nar={nar_up} node_b_served={served} want>={expected_served}",
        )
        # honest scope: narinfo STILL comes from upstream in wave-2a (context, not
        # an overclaim of 'cache untouched').
        expect(
            ninfo_up > 0,
            "S6 context: narinfo egress is NONZERO (wave-2a serves narinfo upstream)",
            f"upstream.narinfo={ninfo_up}",
        )

    # -- peers OFF contrast: the SAME build pulls the full NAR from upstream --
    with Pod(ctx, "s6-off", fixtures.cache, with_daemon=True, expect=expect) as pod:
        pod.proxy_reset()
        res = pod.client_run(
            targets, ctx.substituter_daemon_only(), fixtures.public_key
        )
        expect(
            res.exit_code == 0,
            "S6 contrast: peers-off build still succeeds (via upstream)",
            res.stderr[-600:],
        )
        nar_up = pod.proxy_stats()["upstream"].get("nar", 0)
        expect(
            nar_up >= 1,
            "S6 contrast: peers-off pulls the FULL NAR from upstream (falsifies "
            "the 0-egress - the channel is live)",
            f"upstream.nar={nar_up}",
        )


def scenario_s6_corrupt_bite(ctx: Ctx, expect) -> None:
    """S6 bite: a peer serving a DIFFERENT valid NAR (passes the BLAKE3 transport
    gate) is caught by Nix's sha256==NarHash gate; the build FAILS and no wrong
    bytes are stored. We point `lib`'s claim at `app`'s (smaller) blake3, so the
    substituted NAR passes the signed-NarSize cap and reaches the NarHash gate."""
    fixtures = ctx.fixtures
    seed_dir, seeds = build_p2p_seed_dir(
        fixtures, ctx.scratch / "s6-bite-seed", S6_ATTRS
    )
    lib_hash = fixtures.nar_hash("lib")
    app_seed = next(s for s in seeds if s.store_path == fixtures.store_path("app"))
    lib_path = fixtures.store_path("lib")
    # This bite RELIES on app's NAR being smaller than lib's signed NarSize: only
    # then does the substituted (app) NAR pass the task-51 NarSize cap and reach
    # Nix's hash gate. Guard it, so a fixture regeneration that inverted the sizes
    # fails LOUD here instead of silently moving the bite to the size-abort path.
    expect(
        fixtures.entry("app")["nar_size"] < fixtures.entry("lib")["nar_size"],
        "S6 bite precondition: app NarSize < lib NarSize (bite hits the hash gate, "
        "not the size cap)",
        f"app={fixtures.entry('app')['nar_size']} lib={fixtures.entry('lib')['nar_size']}",
    )

    with Pod(
        ctx,
        "s6-bite",
        fixtures.cache,
        with_daemon=False,
        expect=expect,
        p2p_seed_dir=seed_dir,
        p2p_seeds=seeds,
        # lib's NarHash now points at app's blake3 -> a valid-but-wrong NAR.
        p2p_claim_overrides={lib_hash: app_seed.filename},
    ) as pod:
        res = pod.client_run(
            [lib_path], ctx.substituter_daemon_only(), fixtures.public_key
        )
        expect(
            res.exit_code != 0,
            "S6 bite: build FAILS when the peer serves a valid-but-wrong NAR",
            f"exit={res.exit_code}",
        )
        expect(
            HASH_REJECT_NEEDLE in (res.stderr + res.stdout),
            "S6 bite: failure is the sha256==NarHash gate (no wrong bytes stored)",
            res.stderr[-600:],
        )


def scenario_s6_fallback(ctx: Ctx, expect) -> None:
    """S6 through S2: node B dies -> node A's p2p primary fails and it falls back
    to upstream, so the build still succeeds (the task-51 safety envelope bounds
    the dead holder, FallbackNarSource routes to the cache).

    Uses `lib`, an ALREADY-RAW upstream path. A REAL wave-2a limitation this
    surfaces: for a COMPRESSED-upstream path the daemon rewrote to raw (e.g.
    `app`), upstream has no raw NAR under the rewritten token, so a dead peer is
    NOT recoverable from upstream - the build fails FAIL-CLOSED (no wrong bytes),
    it does not fail OVER. Upstream fallback of a peer-served path therefore holds
    only where upstream can also serve the raw NAR (already-raw paths). Making
    raw-serve health-aware (don't rewrite when no live raw source) is deferred to
    the task-43/44 policy work. We kill node B before the build (dead-holder); a
    killed-MID-115MB-transfer variant extends this in the task-43 suite."""
    fixtures = ctx.fixtures
    seed_dir, seeds = build_p2p_seed_dir(fixtures, ctx.scratch / "s6-fb-seed", ["lib"])
    lib_path = fixtures.store_path("lib")
    with Pod(
        ctx,
        "s6-fb",
        fixtures.cache,
        with_daemon=False,
        expect=expect,
        p2p_seed_dir=seed_dir,
        p2p_seeds=seeds,
    ) as pod:
        pod.kill("node-b")
        pod.proxy_reset()
        res = pod.client_run(
            [lib_path], ctx.substituter_daemon_only(), fixtures.public_key
        )
        expect(
            res.exit_code == 0,
            "S6 fallback: peer-served path builds despite node B dead (p2p miss -> upstream)",
            res.stderr[-600:],
        )
        got = res.narhash(lib_path)
        expect(
            got == fixtures.nar_hash("lib"),
            "S6 fallback: lib still byte-identical (served by upstream after failover)",
            f"got={got}",
        )
        nar_up = pod.proxy_stats()["upstream"].get("nar", 0)
        expect(
            nar_up >= 1,
            "S6 fallback: upstream actually served the NAR (fallback engaged, not "
            "a silent local hit)",
            f"upstream.nar={nar_up}",
        )


def scenario_s6_compressed_fail_closed(ctx: Ctx, expect) -> None:
    """S6 bite (the fail-CLOSED limitation, GROUNDED, not just documented): a
    COMPRESSED-upstream path (`app`, xz) whose narinfo node A rewrote to raw has no
    raw NAR upstream under the rewritten token, so when the peer dies the p2p miss
    CANNOT fail over - the build must fail CLEANLY (bounded, no wrong bytes, no
    hang), NOT hang and NOT poison the store. This is the negative-feedback the
    mped review flagged as missing for the milestone's core safety claim. The
    proper fail-OVER fix (preserve the compressed token + decompress-on-fallback)
    is task-43/44; here we prove the current behaviour is fail-closed, not unsafe."""
    fixtures = ctx.fixtures
    # Seed + claim ONLY app (compressed): app is rewritten to raw, lib (app's dep,
    # unclaimed) is served normally from upstream, so any failure is app's raw path.
    seed_dir, seeds = build_p2p_seed_dir(fixtures, ctx.scratch / "s6-fc-seed", ["app"])
    app_path = fixtures.store_path("app")
    with Pod(
        ctx,
        "s6-fc",
        fixtures.cache,
        with_daemon=False,
        expect=expect,
        p2p_seed_dir=seed_dir,
        p2p_seeds=seeds,
    ) as pod:
        pod.kill("node-b")
        pod.proxy_reset()
        # client_run has a 300s subprocess timeout; a genuine hang would raise
        # TimeoutExpired -> a FAILING scenario, so a PASS here already means bounded.
        res = pod.client_run(
            [app_path], ctx.substituter_daemon_only(), fixtures.public_key
        )
        expect(
            res.exit_code != 0,
            "S6 fail-closed: compressed-rewritten path FAILS when the peer is dead "
            "(no raw NAR upstream to fail over to)",
            f"exit={res.exit_code}",
        )
        # No wrong bytes: app was never materialised (fail-closed, not poisoned).
        expect(
            res.narhash(app_path) is None,
            "S6 fail-closed: app NOT stored (no wrong/partial bytes imported)",
            f"narhash={res.narhash(app_path)}",
        )
        # The failure is a clean 'no substituter'/'missing in cache', NOT a hash
        # mismatch (which would mean bytes were fetched) or a hang.
        out = res.stderr + res.stdout
        clean = ("no substituter" in out) or ("does not exist in binary cache" in out)
        expect(
            clean,
            "S6 fail-closed: failure is a clean bounded gateway/absent error",
            out[-600:],
        )


# S7 (task-161): the libp2p arm - a real 3-daemon decentralized discover->resolve->
# fetch->serve across containers. The target NAR is `lib` (an ALREADY-RAW upstream
# path), so byte-identity is proven without the compressed->raw narinfo rewrite (that
# path is exercised by S6's `app`; a libp2p xz target is a documented follow-up). The
# dedicated BOOT node holds NO content, so target bytes can only reach C via a
# DHT-resolved dial to the provider - the F1 load-bearing lever. `app` is the MISS-arm
# decoy the provider seeds while C builds `lib` (which no peer announces).
S7_TARGET = "lib"
S7_DECOY = "app"


def libp2p_store_hash(store_path: str) -> str:
    """The nixbase32 store-hash component (`<hash>` in `/nix/store/<hash>-<name>`) - the
    `<hash>.narinfo` key a provider proves public against and correlates its narinfo to."""
    return store_path.rsplit("/", 1)[-1].split("-", 1)[0]


def _bootstrap_entries(argv: list[str]) -> list[str]:
    """Every value passed to a `--libp2p-bootstrap` flag in argv, in order."""
    entries: list[str] = []
    for i, tok in enumerate(argv):
        if tok == "--libp2p-bootstrap" and i + 1 < len(argv):
            entries.append(argv[i + 1])
    return entries


def _split_bootstrap(entry: str) -> tuple[str, str]:
    """(peer_id, multiaddr) of a `<PeerId>@<multiaddr>` bootstrap entry; any trailing
    `/p2p/<id>` on the multiaddr is stripped so it compares equal to a bare listen addr."""
    peer_id, _, multiaddr = entry.partition("@")
    if "/p2p/" in multiaddr:
        multiaddr = multiaddr.split("/p2p/", 1)[0]
    return peer_id.strip(), multiaddr.strip()


def check_libp2p_no_injection(
    argv: list[str],
    expected_boot_peer: str,
    provider_peer_id: str,
    provider_listen_addrs: set[str],
) -> list[str]:
    """PURE no-injection oracle (AC#9 runtime half). Returns a list of problems; empty
    == clean, non-empty == the oracle BITES.

    STRENGTHENED beyond the original `provider PeerId absent + --libp2p-provider-addr
    absent` pair, which had a bypass: a consumer handed
    `--libp2p-bootstrap <decoy-peerid>@<P's listen multiaddr>` would DIAL P directly
    (daemon-libp2p lib.rs:1215 -> fabric-libp2p swarm.rs:547) and Identify would then
    learn P's REAL id (swarm.rs:645) - so the address-resolution leg LOOKS
    kad-discovered while P's address was actually injected out of band under a decoy id.

    So this also asserts the consumer's `--libp2p-bootstrap` set is EXACTLY the real
    BOOT node, and that NO bootstrap entry resolves to the provider's listen address OR
    PeerId. The check compares against P's KNOWN listen multiaddr(s) + PeerId, not merely
    'absent'."""
    problems: list[str] = []
    joined = " ".join(argv)

    # (kept) the provider's PeerId must not appear ANYWHERE in argv.
    if provider_peer_id and provider_peer_id in joined:
        problems.append(
            f"provider PeerId {provider_peer_id!r} present in consumer argv"
        )

    # (kept) no hand-fed dial address flag.
    if "--libp2p-provider-addr" in argv:
        problems.append(
            "consumer argv contains --libp2p-provider-addr (hand-fed dial address)"
        )

    entries = _bootstrap_entries(argv)
    if not entries:
        problems.append(
            "consumer argv has NO --libp2p-bootstrap (cannot be a kad node at all)"
        )

    for entry in entries:
        pid, addr = _split_bootstrap(entry)
        # STRENGTHENED: the bootstrap set must be EXACTLY the real BOOT node.
        if entry != expected_boot_peer:
            problems.append(
                f"consumer --libp2p-bootstrap {entry!r} is not the sole real BOOT "
                f"node {expected_boot_peer!r}"
            )
        # Explicit provider-injection bites (a clearer failure than the set-mismatch
        # alone, and the load-bearing close of the decoy-PeerId bypass).
        if provider_peer_id and pid == provider_peer_id:
            problems.append(
                f"consumer --libp2p-bootstrap entry {entry!r} resolves to the "
                f"provider's PeerId {pid!r}"
            )
        if addr in provider_listen_addrs:
            problems.append(
                f"consumer --libp2p-bootstrap entry {entry!r} resolves to the "
                f"provider's listen address {addr!r} (out-of-band injection)"
            )
    return problems


def no_injection_self_test() -> int:
    """AC#9 BITE: prove the strengthened no-injection oracle actually FAILS an injected
    provider address. Before/after in one place: a CLEAN consumer argv (bootstraps to
    the real BOOT alone) must pass; the SAME argv with P's listen address added as a
    second bootstrap entry under a DECOY PeerId must BITE; and P's real PeerId as a
    bootstrap entry must BITE. A guard that cannot be shown to fail proves nothing.

    Returns 0 on success (all cases behave), 2 if any case misbehaves."""
    boot = f"{LIBP2P_BOOT_PEER_ID}@/ip4/127.0.0.1/tcp/{LIBP2P_BASE_PORT + 2}"
    prov_id = "12D3KooWProviderRealIdAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    prov_listen = f"/ip4/127.0.0.1/tcp/{LIBP2P_BASE_PORT + 1}"
    prov_addrs = {prov_listen}
    decoy_id = "12D3KooWDecoyBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

    clean_argv = [
        "/bin/daemon",
        "--listen",
        f"0.0.0.0:{DAEMON_PORT}",
        "--upstream",
        "http://127.0.0.1:9",
        "--libp2p-listen",
        f"/ip4/127.0.0.1/tcp/{LIBP2P_BASE_PORT}",
        "--libp2p-bootstrap",
        boot,
        "--libp2p-scope",
        LIBP2P_SCOPE,
    ]

    # BEFORE (clean): the oracle must NOT bite the legitimate consumer argv.
    clean_problems = check_libp2p_no_injection(clean_argv, boot, prov_id, prov_addrs)
    if clean_problems:
        print(
            f"no-injection self-test FAILED: clean consumer argv wrongly flagged: "
            f"{clean_problems}",
            file=sys.stderr,
        )
        return 2

    # AFTER (the bypass): inject P's LISTEN ADDRESS as a 2nd bootstrap entry under a
    # decoy PeerId. The old oracle (PeerId-absent + no --libp2p-provider-addr) would NOT
    # bite this; the strengthened one MUST - specifically on the provider listen addr.
    injected_addr_argv = clean_argv + [
        "--libp2p-bootstrap",
        f"{decoy_id}@{prov_listen}",
    ]
    addr_problems = check_libp2p_no_injection(
        injected_addr_argv, boot, prov_id, prov_addrs
    )
    if not any(prov_listen in p for p in addr_problems):
        print(
            "no-injection self-test FAILED: injecting P's listen address as a decoy-id "
            f"bootstrap entry did NOT bite the oracle (problems={addr_problems}) - the "
            "bypass is still open",
            file=sys.stderr,
        )
        return 2

    # AFTER (direct id): inject P's REAL PeerId as a bootstrap entry - must also bite.
    injected_id_argv = clean_argv + [
        "--libp2p-bootstrap",
        f"{prov_id}@/ip4/127.0.0.1/tcp/1",
    ]
    id_problems = check_libp2p_no_injection(injected_id_argv, boot, prov_id, prov_addrs)
    if not any(prov_id in p for p in id_problems):
        print(
            "no-injection self-test FAILED: injecting P's PeerId as a bootstrap entry "
            f"did NOT bite the oracle (problems={id_problems})",
            file=sys.stderr,
        )
        return 2

    # AFTER (--libp2p-provider-addr): the legacy hand-fed dial flag must still bite.
    flag_argv = clean_argv + ["--libp2p-provider-addr", f"{prov_id}@{prov_listen}"]
    flag_problems = check_libp2p_no_injection(flag_argv, boot, prov_id, prov_addrs)
    if not flag_problems:
        print(
            "no-injection self-test FAILED: --libp2p-provider-addr injection not caught",
            file=sys.stderr,
        )
        return 2

    print(
        "e2e: no-injection oracle self-test passed - clean consumer argv is clean; "
        "injecting P's listen address under a decoy PeerId BITES; P's PeerId BITES; "
        "--libp2p-provider-addr BITES (AC#9 bypass closed)"
    )
    return 0


def _copy_seed_narinfos(fixtures: Fixtures, seed_dir: Path, seeds) -> None:
    """Copy each seed's SIGNED narinfo (fixture cache key) beside the raw NAR, under
    `<seed_dir>/narinfos/<store_hash>.narinfo`, so the PROVIDER container can PROVE each
    seeded NAR public through the trusted-key signature gate (TASK-103) before it announces
    over the bootstrapped DHT. The operator naming a seed does NOT make it public - only this
    trusted narinfo signature does, so the provider is handed the exact narinfo, not a
    blanket 'trust my paths' flag."""
    narinfos = seed_dir / "narinfos"
    narinfos.mkdir(parents=True, exist_ok=True)
    for s in seeds:
        store_hash = libp2p_store_hash(s.store_path)
        src = fixtures.cache / fx.narinfo_name(s.store_path)
        if not src.is_file():
            die(
                f"_copy_seed_narinfos: no signed narinfo at {src} for seed {s.store_path}"
            )
        shutil.copy2(src, narinfos / f"{store_hash}.narinfo")


def _s7_seeds(ctx: Ctx, tag: str, attr: str):
    """Materialise `attr`'s raw NAR into a fresh seed dir; return
    (seed_dir, (that_seed,), target_store_path). The provider is given exactly this
    seed. The dedicated BOOT node holds NO content in either arm, so a peer-served
    target can only have come from a DHT-resolved dial to the provider."""
    seed_dir, seeds = build_p2p_seed_dir(
        ctx.fixtures, ctx.scratch / f"s7-{tag}-seed", [attr]
    )
    # TASK-103: also stage the seed's SIGNED narinfo so the provider can prove it public.
    _copy_seed_narinfos(ctx.fixtures, seed_dir, seeds)
    return seed_dir, (seeds[0],), ctx.fixtures.store_path(S7_TARGET)


def scenario_s7_libp2p(ctx: Ctx, expect) -> None:
    """S7 core: a real nix build served from a peer over libp2p, discovered via kad
    (NOT injected), byte-identical, with 0 upstream NAR egress; PLUS the F1
    load-bearing control (kill the provider -> the DHT-mediated peer path is the only
    route to the target -> the build falls back to upstream).

    Topology (3 real daemon containers): BOOT (a pure kad router holding NO content),
    PROVIDER P (seeds the target), CONSUMER C (bootstraps to BOOT ALONE). C is NEVER
    told P's dial address; it discovers P via kad get_providers and resolves P's
    address via kad peer-routing (inside the fabric).
    """
    fixtures = ctx.fixtures
    seed_dir, prov_seeds, target_sp = _s7_seeds(ctx, "core", S7_TARGET)
    target_size = prov_seeds[0].nar_size

    with Pod(
        ctx,
        "s7",
        fixtures.cache,
        with_daemon=False,
        expect=expect,
        libp2p_seed_dir=seed_dir,
        libp2p_provider_seeds=prov_seeds,
        libp2p_trusted_key=fixtures.public_key,
    ) as pod:
        # -- no-injection oracle: C's argv proves it was never handed P's address --
        prov_id = (
            pod.libp2p_provider_identity[0] if pod.libp2p_provider_identity else ""
        )
        argv = pod.libp2p_consumer_argv()
        joined = " ".join(argv)
        expect(
            bool(prov_id) and prov_id not in joined,
            "S7 no-injection: consumer argv does NOT contain the provider's PeerId",
            f"prov_id={prov_id!r} argv={joined!r}",
        )
        expect(
            "--libp2p-provider-addr" not in argv,
            "S7 no-injection: consumer has NO --libp2p-provider-addr (dial resolved via kad)",
            f"argv={joined!r}",
        )
        # STRENGTHENED oracle (closes the decoy-PeerId bootstrap-injection bypass): the
        # consumer's --libp2p-bootstrap set must be EXACTLY the real BOOT node, and no
        # entry may resolve to P's listen address or PeerId. Without this, a consumer
        # given `--libp2p-bootstrap <decoy>@<P's listen>` would dial P directly and the
        # leg would LOOK kad-discovered. Proven to BITE by `e2e_harness.py --self-test`.
        boot_peer = pod.libp2p_boot_peer_entry or ""
        prov_addrs = set(pod.libp2p_provider_listen_addrs)
        injection_problems = check_libp2p_no_injection(
            argv, boot_peer, prov_id, prov_addrs
        )
        expect(
            not injection_problems,
            "S7 no-injection: consumer --libp2p-bootstrap is EXACTLY the real BOOT node "
            "(no provider listen-addr or PeerId injected out-of-band)",
            f"problems={injection_problems!r} boot={boot_peer!r} "
            f"prov_addrs={sorted(prov_addrs)!r} argv={joined!r}",
        )

        # -- ARM A (positive): C discovers+resolves+fetches the target from P --
        time.sleep(LIBP2P_CONVERGE_S)  # bounded kad settle (see LIBP2P_CONVERGE_S)
        pod.proxy_reset()
        res = pod.client_run(
            [target_sp], ctx.substituter_daemon_only(), fixtures.public_key
        )
        expect(
            res.exit_code == 0,
            "S7: real nix build completes with the NAR served by P over libp2p",
            res.stderr[-800:],
        )
        got = res.narhash(target_sp)
        expect(
            got == fixtures.nar_hash(S7_TARGET),
            f"S7 S1 byte-identity: {S7_TARGET} NarHash matches the signed upstream",
            f"got={got} want={fixtures.nar_hash(S7_TARGET)}",
        )
        stats = pod.proxy_stats()
        nar_up = stats["upstream"].get("nar", 0)
        ninfo_up = stats["upstream"].get("narinfo", 0)
        # THE oracle: 0 upstream NAR egress. Attribution to the peer is by construction
        # here - BOOT (C's only direct peer) holds NO content, so target bytes could
        # only have come from a DHT-discovered+resolved dial to P. (There is no libp2p
        # provider-side served-bytes counter yet - the LIBP2P-SERVED-TOTAL analogue of
        # IROH-SERVED-TOTAL is a follow-up; the proxy egress ledger is the ground truth.)
        expect(
            nar_up == 0,
            "S7 oracle: 0 upstream NAR egress (the target was peer-served, not fetched "
            "from the cache) - want target_size>0",
            f"upstream.nar={nar_up} target_size={target_size}",
        )
        expect(
            ninfo_up > 0,
            "S7 context: narinfo egress is NONZERO (wave-2a serves narinfo upstream)",
            f"upstream.narinfo={ninfo_up}",
        )

        # -- ARM B (F1 load-bearing control): kill P; the target is now unreachable via
        # any peer (BOOT holds no content), so C must fall back to upstream. This
        # proves the DHT-mediated peer path (discover P -> resolve P's address -> dial P)
        # is LOAD-BEARING: remove P and the same build's NAR comes from the cache. --
        pod.kill("lp-provider")
        pod.proxy_reset()
        res2 = pod.client_run(
            [target_sp], ctx.substituter_daemon_only(), fixtures.public_key
        )
        expect(
            res2.exit_code == 0,
            "S7 load-bearing control: build still succeeds via upstream when P is dead",
            res2.stderr[-800:],
        )
        got2 = res2.narhash(target_sp)
        expect(
            got2 == fixtures.nar_hash(S7_TARGET),
            "S7 load-bearing control: still byte-identical (served by upstream fallback)",
            f"got={got2}",
        )
        nar_up2 = pod.proxy_stats()["upstream"].get("nar", 0)
        expect(
            nar_up2 >= 1,
            "S7 load-bearing control: upstream served the FULL NAR once P is dead "
            "(falsifies the 0-egress - the peer path to P was load-bearing, not a "
            "pre-open/local shortcut)",
            f"upstream.nar={nar_up2}",
        )


def scenario_libp2p_bootstrap_outage(ctx: Ctx, expect) -> None:
    """TASK-242 item 3: the dependency-outage DRILL promoted from the in-process observability seam
    (TASK-240 drill 2) to a REAL container/network fault.

    A 3-daemon libp2p topology (BOOT + provider P + consumer C), with C running the PRIMARY
    /bin/daemon-libp2p binary — the one carrying the operator surface — on a loopback
    `--status-listen`. The drill:

      1. converged + healthy: the LIVE `--status` (read via the SHIPPED admin client from inside C's
         container) reports `bootstrap_healthy=1/1`, `fallback_reason=none`, and `peer_path=direct`
         (C dials its sole bootstrap BOOT directly — this exercises the TASK-242 live direct/relay
         detection end to end in a container, not just the unit bite);
      2. INJECT the outage at the CONTAINER level: `podman kill` the BOOT process;
      3. the live status flips to `bootstrap_healthy=0/1` + `fallback_reason=bootstrap-outage`, read
         from the ACTUAL swarm `is_connected` state (not a mocked snapshot);
      4. the S2 ADDITIVE INVARIANT holds THROUGH the outage: a real `nix build` still succeeds via
         the daemon's HTTP-upstream fallback — the store is never blocked.

    MUTATION: a surface not reading live `is_connected` keeps `1/1` after the kill (reddens step 3);
    a `peer_path` hardcoded to none/unknown reddens the step-1 `direct` assertion; a broken fallback
    reddens step 4.

    HONEST SCOPE: the other three TASK-240 drills stay IN-PROCESS. Restart-identity and
    exhausted-budget inject at seams with no natural container/network analogue (a durable-seed
    restart; an in-memory announce ledger), and kill-switch is a static profile assertion the
    `libp2p-leech` scenario already proves peer-side; this drill containerizes the one whose fault IS
    a network/process event (a bootstrap dying).
    """
    fixtures = ctx.fixtures
    seed_dir, prov_seeds, target_sp = _s7_seeds(ctx, "outage", S7_TARGET)
    with Pod(
        ctx,
        "lp-outage",
        fixtures.cache,
        with_daemon=False,
        expect=expect,
        libp2p_seed_dir=seed_dir,
        libp2p_provider_seeds=prov_seeds,
        libp2p_trusted_key=fixtures.public_key,
        libp2p_consumer_status_port=LIBP2P_STATUS_PORT,
    ) as pod:
        time.sleep(LIBP2P_CONVERGE_S)

        # 1. Converged + healthy: the sole bootstrap is connected, over a DIRECT path.
        healthy = pod.libp2p_consumer_status()
        expect(
            "bootstrap_healthy=1/1" in healthy,
            "TASK-242 drill: converged consumer reports its sole bootstrap healthy (live is_connected)",
            f"status={healthy!r}",
        )
        expect(
            "peer_path=direct" in healthy,
            "TASK-242 drill: live peer_path is DIRECT (C dials BOOT directly) - direct/relay "
            "detection wired end to end, not a hardcoded placeholder",
            f"status={healthy!r}",
        )
        expect(
            "fallback_reason=none" in healthy,
            "TASK-242 drill: no fallback reason while the bootstrap is healthy",
            f"status={healthy!r}",
        )

        # 2. INJECT the outage at the container level: kill BOOT.
        pod.kill("lp-boot")

        # 3. Poll the LIVE surface until bootstrap health degrades. Bounded (~60s) so a genuinely
        #    stuck flip FAILS rather than hangs; the flip is the swarm's real ConnectionClosed once
        #    BOOT's container (and its TCP endpoint) is gone.
        outaged = ""
        for _ in range(120):
            outaged = pod.libp2p_consumer_status()
            if "bootstrap_healthy=0/1" in outaged:
                break
            time.sleep(0.5)
        expect(
            "bootstrap_healthy=0/1" in outaged,
            "TASK-242 drill: killing BOOT flips the LIVE status to 0/1 healthy (real is_connected, "
            "not a mocked snapshot)",
            f"status={outaged!r}",
        )
        expect(
            "fallback_reason=bootstrap-outage" in outaged,
            "TASK-242 drill: the surface ATTRIBUTES the fallback to the bootstrap outage",
            f"status={outaged!r}",
        )

        # 4. S2 additive invariant: a real nix build STILL succeeds via the HTTP upstream fallback.
        res = pod.client_run(
            [target_sp], ctx.substituter_daemon_only(), fixtures.public_key
        )
        expect(
            res.exit_code == 0,
            "TASK-242 drill S2 additive invariant: a nix build still succeeds with BOOT dead "
            "(the fetch folds to the HTTP upstream; the store is never blocked)",
            res.stderr[-800:],
        )
        got = res.narhash(target_sp)
        expect(
            got == fixtures.nar_hash(S7_TARGET),
            "TASK-242 drill S2: the fallback-served NAR is byte-identical to the signed upstream",
            f"got={got} want={fixtures.nar_hash(S7_TARGET)}",
        )


def scenario_s7_libp2p_miss(ctx: Ctx, expect) -> None:
    """S7 MISS arm: a NAR that NO peer announces -> a clean libp2p kad miss -> upstream
    fallback, build still succeeds. The provider seeds only the DECOY (`app`); the
    consumer builds the target (`lib`), which no provider holds, so `find_providers`
    misses and the daemon serves it from the cache."""
    fixtures = ctx.fixtures
    # The provider seeds the DECOY only; neither it nor BOOT announces the target.
    seed_dir, decoy_seeds, target_sp = _s7_seeds(ctx, "miss", S7_DECOY)
    with Pod(
        ctx,
        "s7-miss",
        fixtures.cache,
        with_daemon=False,
        expect=expect,
        libp2p_seed_dir=seed_dir,
        libp2p_provider_seeds=decoy_seeds,
        libp2p_trusted_key=fixtures.public_key,
    ) as pod:
        time.sleep(LIBP2P_CONVERGE_S)
        pod.proxy_reset()
        res = pod.client_run(
            [target_sp], ctx.substituter_daemon_only(), fixtures.public_key
        )
        expect(
            res.exit_code == 0,
            "S7 miss: build succeeds via upstream when no peer announces the target",
            res.stderr[-800:],
        )
        got = res.narhash(target_sp)
        expect(
            got == fixtures.nar_hash(S7_TARGET),
            "S7 miss: byte-identical (served by upstream after the kad miss)",
            f"got={got}",
        )
        nar_up = pod.proxy_stats()["upstream"].get("nar", 0)
        expect(
            nar_up >= 1,
            "S7 miss: upstream actually served the NAR (kad miss -> fallback engaged, "
            "not a silent local hit)",
            f"upstream.nar={nar_up}",
        )


def scenario_s7_libp2p_netns(ctx: Ctx, expect) -> None:
    """S7 on a SEPARATE-NETNS routed topology - fully discharge the F1 caveat that
    the shared-pod S7 (scenario_s7_libp2p) could not: that address-RESOLUTION (kad
    peer-routing) is load-bearing INDEPENDENTLY of a shared-loopback shortcut / a
    kad-query pre-open.

    Each daemon is its OWN `--network` container (own netns, own 127.0.0.1); C sits
    on net-c, P/BOOT/proxy/origin on net-p, joined by podman host routing. Two arms,
    a MINIMAL PAIR whose ONLY difference is P's `--libp2p-listen`:

      * POSITIVE: P announces its ROUTABLE net-p IP. C - told ONLY BOOT - discovers P
        via kad get_providers and RESOLVES P's dial address via kad peer-routing, then
        fetches the NAR byte-identical with 0 upstream NAR egress.
      * RESOLUTION-ONLY-BROKEN CONTROL: P announces ONLY `/ip4/127.0.0.1`. P is alive,
        announces the SAME content, and is reachable at its routable net-p IP (PROVEN
        by an HTTP probe from inside C's netns). But the address C resolves for P is
        `127.0.0.1`, which in C's own separate netns is C's empty loopback -> the dial
        fails -> upstream fallback (`upstream.nar>=1`). RESOLUTION was load-bearing:
        break only it, with P up and the path present, and the peer-serve vanishes.

    The oracle BITES: positive 0-egress vs control >=1 egress, the sole delta being
    which address P published for C to resolve.
    """
    fixtures = ctx.fixtures

    # -- ARM A (positive): resolution succeeds, peer serves, 0 upstream NAR egress --
    seed_dir, prov_seeds, target_sp = _s7_seeds(ctx, "netns", S7_TARGET)
    with Libp2pNetnsTopology(
        ctx,
        "s7netns",
        fixtures.cache,
        seed_dir,
        prov_seeds,
        expect,
        provider_loopback_only=False,
        libp2p_trusted_key=fixtures.public_key,
    ) as topo:
        prov_id = topo.provider_identity[0] if topo.provider_identity else ""
        prov_listen = topo.provider_identity[1] if topo.provider_identity else ""
        argv = topo.consumer_argv()
        joined = " ".join(argv)
        expect(
            bool(prov_id) and prov_id not in joined,
            "S7-netns no-injection: consumer argv omits the provider's PeerId",
            f"prov_id={prov_id!r} argv={joined!r}",
        )
        expect(
            "--libp2p-provider-addr" not in argv,
            "S7-netns no-injection: consumer has NO --libp2p-provider-addr",
            f"argv={joined!r}",
        )
        # The positive arm's provider announced a ROUTABLE (non-loopback) address -
        # the very thing the control withholds. Pin it so the minimal pair is honest.
        expect(
            "/ip4/127.0.0.1/" not in prov_listen
            and Libp2pNetnsTopology.IP_PROVIDER in prov_listen,
            "S7-netns positive: provider announced its ROUTABLE net-p address",
            f"listen={prov_listen!r}",
        )

        time.sleep(LIBP2P_NETNS_CONVERGE_S)
        topo.proxy_reset()
        res = topo.client_run([target_sp], fixtures.public_key)
        expect(
            res.exit_code == 0,
            "S7-netns positive: nix build completes with the NAR served by P over libp2p",
            res.stderr[-800:],
        )
        got = res.narhash(target_sp)
        expect(
            got == fixtures.nar_hash(S7_TARGET),
            "S7-netns positive byte-identity: NarHash matches the signed upstream",
            f"got={got} want={fixtures.nar_hash(S7_TARGET)}",
        )
        stats = topo.proxy_stats()
        nar_up = stats["upstream"].get("nar", 0)
        ninfo_up = stats["upstream"].get("narinfo", 0)
        expect(
            nar_up == 0,
            "S7-netns positive oracle: 0 upstream NAR egress (peer-served across the "
            "routed netns via a kad-RESOLVED routable address)",
            f"upstream.nar={nar_up}",
        )
        expect(
            ninfo_up > 0,
            "S7-netns positive context: narinfo egress is NONZERO (served upstream)",
            f"upstream.narinfo={ninfo_up}",
        )

    # -- ARM B (resolution-only-broken control): P alive + reachable, but publishes a
    # non-routable loopback address -> C cannot resolve a dialable address -> fallback.
    seed_dir2, prov_seeds2, target_sp2 = _s7_seeds(ctx, "netns-ctl", S7_TARGET)
    with Libp2pNetnsTopology(
        ctx,
        "s7netnsctl",
        fixtures.cache,
        seed_dir2,
        prov_seeds2,
        expect,
        provider_loopback_only=True,
        libp2p_trusted_key=fixtures.public_key,
    ) as topo:
        prov_listen = topo.provider_identity[1] if topo.provider_identity else ""
        # The control's SINGLE knob: P published ONLY a loopback address.
        expect(
            "/ip4/127.0.0.1/" in prov_listen
            and Libp2pNetnsTopology.IP_PROVIDER not in prov_listen,
            "S7-netns control: provider announced ONLY a non-routable loopback address "
            "(the resolution leg's input is now unusable from C's separate netns)",
            f"listen={prov_listen!r}",
        )
        # LOAD-BEARING EVIDENCE: from INSIDE C's netns, P's ROUTABLE net-p IP answers
        # HTTP. So P is UP and the net-c -> net-p path EXISTS; only the RESOLVED libp2p
        # address is broken. Without this, a fallback could be blamed on P being down.
        status, body = topo.provider_reachable_from_consumer()
        expect(
            status == 200,
            "S7-netns control: P is ALIVE + REACHABLE from C's netns at its routable "
            "net-p IP (so the fallback below isolates RESOLUTION, not liveness/path)",
            f"status={status} body={body[:200]!r}",
        )

        time.sleep(LIBP2P_NETNS_CONVERGE_S)
        topo.proxy_reset()
        res = topo.client_run([target_sp2], fixtures.public_key)
        expect(
            res.exit_code == 0,
            "S7-netns control: build still succeeds via upstream fallback",
            res.stderr[-800:],
        )
        got = res.narhash(target_sp2)
        expect(
            got == fixtures.nar_hash(S7_TARGET),
            "S7-netns control: still byte-identical (served by upstream fallback)",
            f"got={got}",
        )
        nar_up = topo.proxy_stats()["upstream"].get("nar", 0)
        expect(
            nar_up >= 1,
            "S7-netns control ORACLE BITE: upstream served the FULL NAR because C could "
            "not RESOLVE a dialable address for P (P alive + reachable) - resolution is "
            "load-bearing, discharging the F1 caveat that the shared-pod S7 could not",
            f"upstream.nar={nar_up}",
        )
        # Corroboration that the fallback isolates RESOLUTION, not DISCOVERY: C's daemon
        # log shows it DISCOVERED provider record(s) via kad but none yielded bytes
        # (the dial to the loopback-resolved address failed) - NOT the "libp2p-kad miss"
        # that a discovery failure would log. So get_providers (discovery) succeeded and
        # only the address-resolution/dial leg broke. (Distinct code paths in
        # daemon/src/source_libp2p.rs: Lookup::Miss vs the "discovered ... but none
        # yielded verified bytes" per-offer-failure return.)
        clog = topo.logs("lp-consumer")
        expect(
            "provider record(s) for" in clog
            and "none yielded verified bytes" in clog
            and "libp2p-kad miss" not in clog,
            "S7-netns control: consumer DISCOVERED P via kad (found provider record(s)) "
            "but could not resolve a dialable address - the fallback is a RESOLUTION "
            "failure, NOT a discovery miss",
            f"consumer log tail: {clog[-700:]!r}",
        )


def _s8_store_seeds(ctx: Ctx):
    """STORE-supply provider inputs (TASK-194): stage NO .nar. Return
    (narinfo_dir, (that_seed,), target_store_path). `narinfo_dir` carries ONLY the seed's
    SIGNED narinfo under narinfos/<store_hash>.narinfo, so the provider can prove the path
    PUBLIC before announcing it; the provider realises the REAL /nix/store path itself and
    serves it via `nix-store --dump`. The provider container thus holds no .nar file at all,
    which is the property under test."""
    fixtures = ctx.fixtures
    entry = fixtures.entry(S7_TARGET)
    seed = P2pSeed(
        # `filename` is NEVER materialised in store mode (no .nar is mounted); it exists only
        # to satisfy the P2pSeed shape the identity-await + announce line read.
        filename=f"{entry['nar_hash'].split(':', 1)[1]}.nar",
        nar_hash=entry["nar_hash"],
        nar_size=entry["nar_size"],
        store_path=entry["store_path"],
    )
    narinfo_dir = ctx.scratch / "s8-store-narinfos"
    narinfo_dir.mkdir(parents=True)
    _copy_seed_narinfos(fixtures, narinfo_dir, [seed])
    return narinfo_dir, (seed,), fixtures.store_path(S7_TARGET)


def scenario_s8_libp2p_store(ctx: Ctx, expect) -> None:
    """S8 (TASK-194 / TASK-191 AC#3): a libp2p provider serves a REAL /nix/store path it
    realised but NEVER held as a .nar file. It regenerates the NAR on demand via
    `nix-store --dump` (store-supply mode, `--libp2p-provide-store`), announces it through
    the SAME verification-gated public door as S7, and a consumer - told ONLY BOOT -
    discovers it via kad and fetches it BYTE-IDENTICAL with 0 upstream NAR egress. The
    kill-P control (upstream fallback serves the full NAR) keeps the peer path load-bearing.

    STORE-supply DELTA from S7: the provider mounts NO .nar (only the signed narinfo, to
    prove the path public); it realises the store path from the origin at boot and holds it
    as unpacked files nix manages. Proven at the boundary by the provider's OWN log - it
    announces via LIBP2P-PROVIDE-STORE (the store-dump path) and NEVER via LIBP2P-SEED.
    """
    fixtures = ctx.fixtures
    narinfo_dir, prov_seeds, target_sp = _s8_store_seeds(ctx)
    target_size = prov_seeds[0].nar_size

    # HOST-side no-.nar oracle: the ONLY thing the provider mounts is signed narinfo(s) -
    # not a single .nar file. (Its /nix/store copy of the path is realised in-container.)
    staged = sorted(p.name for p in narinfo_dir.rglob("*") if p.is_file())
    expect(
        bool(staged) and not any(n.endswith(".nar") for n in staged),
        "S8 no-.nar: the provider's mount stages ONLY signed narinfo(s), never a .nar",
        f"staged={staged!r}",
    )

    with Pod(
        ctx,
        "s8",
        fixtures.cache,
        with_daemon=False,
        expect=expect,
        libp2p_seed_dir=narinfo_dir,
        libp2p_provider_seeds=prov_seeds,
        libp2p_trusted_key=fixtures.public_key,
        libp2p_store_supply=True,
    ) as pod:
        # -- store-supply path exercised: provider realised the path + announced via
        # nix-store --dump (LIBP2P-PROVIDE-STORE), NOT the seed-nar path (LIBP2P-SEED) --
        plog = pod.logs("lp-provider")
        expect(
            "STORE-SUPPLY: realised + dumpable" in plog,
            "S8 store-supply: provider REALISED the store path and proved it dumpable at boot",
            f"provider log tail: {plog[-700:]!r}",
        )
        expect(
            "LIBP2P-PROVIDE-STORE narhash=" in plog
            and "LIBP2P-SEED narhash=" not in plog,
            "S8 store-supply: provider announced via the STORE-DUMP path "
            "(LIBP2P-PROVIDE-STORE), never the seed-nar path (LIBP2P-SEED) - no .nar at rest",
            f"provider log tail: {plog[-700:]!r}",
        )

        # -- no-injection oracle (the hardened AC#9 guard, identical to S7): C's argv proves
        # it was NEVER handed P's address; discovery is genuinely via kad from BOOT alone. --
        prov_id = (
            pod.libp2p_provider_identity[0] if pod.libp2p_provider_identity else ""
        )
        argv = pod.libp2p_consumer_argv()
        joined = " ".join(argv)
        boot_peer = pod.libp2p_boot_peer_entry or ""
        prov_addrs = set(pod.libp2p_provider_listen_addrs)
        injection_problems = check_libp2p_no_injection(
            argv, boot_peer, prov_id, prov_addrs
        )
        expect(
            not injection_problems,
            "S8 no-injection: consumer --libp2p-bootstrap is EXACTLY the real BOOT node "
            "(no provider addr/PeerId injected out-of-band)",
            f"problems={injection_problems!r} boot={boot_peer!r} "
            f"prov_addrs={sorted(prov_addrs)!r} argv={joined!r}",
        )

        # -- ARM A (positive): C discovers+resolves+fetches the store-dumped NAR from P --
        time.sleep(LIBP2P_CONVERGE_S)
        pod.proxy_reset()
        res = pod.client_run(
            [target_sp], ctx.substituter_daemon_only(), fixtures.public_key
        )
        expect(
            res.exit_code == 0,
            "S8: nix build completes with the NAR store-dumped + served by P over libp2p",
            res.stderr[-800:],
        )
        got = res.narhash(target_sp)
        expect(
            got == fixtures.nar_hash(S7_TARGET),
            f"S8 byte-identity: {S7_TARGET} NarHash matches the signed upstream (the "
            "nix-store --dump bytes BLAKE3-match the announced content)",
            f"got={got} want={fixtures.nar_hash(S7_TARGET)}",
        )
        stats = pod.proxy_stats()
        nar_up = stats["upstream"].get("nar", 0)
        ninfo_up = stats["upstream"].get("narinfo", 0)
        expect(
            nar_up == 0,
            "S8 oracle: 0 upstream NAR egress (the target was store-dumped + peer-served, "
            "not fetched from the cache) - want target_size>0",
            f"upstream.nar={nar_up} target_size={target_size}",
        )
        expect(
            ninfo_up > 0,
            "S8 context: narinfo egress is NONZERO (served upstream)",
            f"upstream.narinfo={ninfo_up}",
        )

        # -- ARM B (kill-P control): remove P -> the DHT-mediated peer path is the only route
        # to the target (BOOT holds no content), so C must fall back to upstream, which serves
        # the FULL NAR. Falsifies the 0-egress: the store-dumped peer serve was load-bearing. --
        pod.kill("lp-provider")
        pod.proxy_reset()
        res2 = pod.client_run(
            [target_sp], ctx.substituter_daemon_only(), fixtures.public_key
        )
        expect(
            res2.exit_code == 0,
            "S8 kill-P control: build still succeeds via upstream when P is dead",
            res2.stderr[-800:],
        )
        got2 = res2.narhash(target_sp)
        expect(
            got2 == fixtures.nar_hash(S7_TARGET),
            "S8 kill-P control: still byte-identical (served by upstream fallback)",
            f"got={got2}",
        )
        nar_up2 = pod.proxy_stats()["upstream"].get("nar", 0)
        expect(
            nar_up2 >= 1,
            "S8 kill-P control: upstream served the FULL NAR once P is dead (the store-dumped "
            "peer serve was load-bearing, not a pre-open/local shortcut)",
            f"upstream.nar={nar_up2}",
        )


def scenario_s9_libp2p_grow(ctx: Ctx, expect) -> None:
    """S9 (TASK-77 announce-after-fetch): the swarm GROWS. Node A holds NOTHING at boot; it
    FETCHES the target from UPSTREAM through its OWN daemon, becomes a discoverable HOLDER
    (announce-after-fetch: it registers the realised /nix/store path + announces it through the
    verification-gated public door), and a SECOND consumer B - told ONLY BOOT - then discovers A
    via kad and fetches the target FROM A with 0 upstream NAR egress.

    Topology (3 real daemon containers): BOOT (pure kad router, no content), A (a
    `--libp2p-announce-after-fetch` provider with an EMPTY initial supply set), B (a plain
    consumer). The growth is attributed by construction: A's first fetch came from UPSTREAM
    (proxy NAR egress > 0), and B's fetch came from A (proxy NAR egress == 0, and BOOT holds
    nothing, so A is the only possible source). The kill-A control proves A was load-bearing.

    This is the swarm-GROWTH delta from S7/S8, where the provider is PRE-SEEDED: here A acquires
    the content by fetching and then propagates it, so popular paths gain holders naturally.
    """
    fixtures = ctx.fixtures
    seed_dir, prov_seeds, target_sp = _s7_seeds(ctx, "grow", S7_TARGET)
    target_nar_hash = fixtures.nar_hash(S7_TARGET)
    a_daemon = f"http://127.0.0.1:{DAEMON_PORT + 1}"

    with Pod(
        ctx,
        "s9",
        fixtures.cache,
        with_daemon=False,
        expect=expect,
        libp2p_seed_dir=seed_dir,
        libp2p_provider_seeds=prov_seeds,
        libp2p_trusted_key=fixtures.public_key,
        libp2p_announce_after_fetch=True,
    ) as pod:
        # -- A boots holding NOTHING: announce-after-fetch enabled, no static supply announced --
        plog = pod.logs("lp-provider")
        expect(
            "LIBP2P-ANNOUNCE-AFTER-FETCH enabled budget=" in plog,
            "S9: A boots in announce-after-fetch mode",
            f"provider log tail: {plog[-700:]!r}",
        )
        expect(
            "LIBP2P-PROVIDE-STORE narhash=" not in plog
            and "LIBP2P-SEED narhash=" not in plog
            and "LIBP2P-ANNOUNCE-AFTER-FETCH narhash=" not in plog,
            "S9: A announces NOTHING at boot (it holds no content until it fetches)",
            f"provider log tail: {plog[-700:]!r}",
        )

        # -- no-injection oracle (identical to S7/S8): B was NEVER handed A's address --
        prov_id = (
            pod.libp2p_provider_identity[0] if pod.libp2p_provider_identity else ""
        )
        argv = pod.libp2p_consumer_argv()
        joined = " ".join(argv)
        boot_peer = pod.libp2p_boot_peer_entry or ""
        prov_addrs = set(pod.libp2p_provider_listen_addrs)
        injection_problems = check_libp2p_no_injection(
            argv, boot_peer, prov_id, prov_addrs
        )
        expect(
            not injection_problems,
            "S9 no-injection: B's --libp2p-bootstrap is EXACTLY the real BOOT node "
            "(no provider addr/PeerId injected out-of-band)",
            f"problems={injection_problems!r} boot={boot_peer!r} argv={joined!r}",
        )

        time.sleep(LIBP2P_CONVERGE_S)  # bounded kad settle

        # -- STEP 1: A FETCHES the target from UPSTREAM through its OWN daemon, materialising the
        # path into A's store and firing announce-after-fetch. --
        pod.proxy_reset()
        realise = pod.exec(
            "lp-provider",
            [
                "bash",
                "-lc",
                (
                    f"nix-store --realise {shlex.quote(target_sp)} "
                    f"--option substituters {shlex.quote(a_daemon)} "
                    f"--option trusted-public-keys {shlex.quote(fixtures.public_key)} "
                    f"--option require-sigs true --option substitute true"
                ),
            ],
            check=False,
        )
        expect(
            realise.returncode == 0,
            "S9 step1: A realises the target through its OWN daemon (fetch from upstream origin) - "
            "A held nothing, so this is the growth SOURCE",
            (realise.stdout + realise.stderr)[-800:],
        )
        stats1 = pod.proxy_stats()
        a_nar_up = stats1["upstream"].get("nar", 0)
        # A fetches DIRECTLY from the origin (its upstream bypasses the proxy), so the proxy NAR
        # cache stays COLD. This is what makes B's serve cleanly attributable to A below and the
        # kill-A control a TRUE origin miss (no warm-cache confound). 0 here PROVES A did not warm
        # the proxy - the mutation that pointed A's upstream at the proxy would redden this AND the
        # kill-A control.
        expect(
            a_nar_up == 0,
            "S9 step1: A's fetch did NOT touch the proxy (A fetches origin-direct, so the proxy "
            "NAR cache stays cold - the growth attribution below is un-confounded)",
            f"proxy upstream.nar={a_nar_up}",
        )

        # -- STEP 2: A becomes a HOLDER - it announces the fetched path (bounded wait for the
        # announce-after-fetch marker naming the target's NarHash). --
        announced = False
        deadline = time.time() + READY_TIMEOUT_S
        while time.time() < deadline:
            plog = pod.logs("lp-provider")
            if (
                "LIBP2P-ANNOUNCE-AFTER-FETCH narhash=" in plog
                and target_nar_hash in plog
            ):
                announced = True
                break
            time.sleep(0.5)
        expect(
            announced,
            "S9 step2: A ANNOUNCED the fetched path (became a discoverable holder for the target "
            "NarHash) via the verification-gated announce-after-fetch door",
            f"want narhash={target_nar_hash}; provider log tail: {pod.logs('lp-provider')[-900:]!r}",
        )
        time.sleep(LIBP2P_CONVERGE_S)  # let A's record propagate on the DHT

        # -- STEP 3 (the growth payoff): B discovers A via kad and fetches the target FROM A, with
        # 0 upstream NAR egress. BOOT holds nothing, so A is the only possible source. --
        pod.proxy_reset()
        res = pod.client_run(
            [target_sp], ctx.substituter_daemon_only(), fixtures.public_key
        )
        expect(
            res.exit_code == 0,
            "S9 step3: B's build completes, served by A over libp2p (A grew the swarm)",
            res.stderr[-800:],
        )
        got = res.narhash(target_sp)
        expect(
            got == target_nar_hash,
            f"S9 S1 byte-identity: {S7_TARGET} NarHash from A matches the signed upstream",
            f"got={got} want={target_nar_hash}",
        )
        b_nar_up = pod.proxy_stats()["upstream"].get("nar", 0)
        expect(
            b_nar_up == 0,
            "S9 GROWTH oracle: 0 upstream NAR egress on B's build - the target was served by A "
            "(a node that had only just FETCHED it), not by the cache",
            f"upstream.nar={b_nar_up}",
        )

        # -- STEP 4 (load-bearing control): kill A -> the only holder is gone (BOOT holds nothing),
        # so B must fall back to UPSTREAM, which serves the full NAR. Falsifies the 0-egress: A's
        # grown holder-serve was load-bearing, not a pre-open/local shortcut. --
        pod.kill("lp-provider")
        pod.proxy_reset()
        res2 = pod.client_run(
            [target_sp], ctx.substituter_daemon_only(), fixtures.public_key
        )
        expect(
            res2.exit_code == 0,
            "S9 kill-A control: B's build still succeeds via upstream when A is dead",
            res2.stderr[-800:],
        )
        got2 = res2.narhash(target_sp)
        expect(
            got2 == target_nar_hash,
            "S9 kill-A control: still byte-identical (served by upstream fallback)",
            f"got={got2}",
        )
        nar_up2 = pod.proxy_stats()["upstream"].get("nar", 0)
        expect(
            nar_up2 >= 1,
            "S9 kill-A control: upstream served the FULL NAR once A is dead (A's grown holder "
            "serve was load-bearing)",
            f"upstream.nar={nar_up2}",
        )


def _leech_drive_a_fetch(pod, ctx, target_sp, a_daemon):
    """Drive A's OWN daemon to realise `target_sp` from its (origin-direct) upstream, so A HOLDS
    the path in its store. Shared by both arms of the leech scenario; returns the realise result."""
    return pod.exec(
        "lp-provider",
        [
            "bash",
            "-lc",
            (
                f"nix-store --realise {shlex.quote(target_sp)} "
                f"--option substituters {shlex.quote(a_daemon)} "
                f"--option trusted-public-keys {shlex.quote(ctx.fixtures.public_key)} "
                f"--option require-sigs true --option substitute true"
            ),
        ],
        check=False,
    )


def scenario_libp2p_leech(ctx: Ctx, expect) -> None:
    """S-LEECH (TASK-78): a CONSUME-ONLY leech gives nothing back, verified FROM THE PEER SIDE.

    A leech fetches from the swarm but SERVES nothing and ANNOUNCES nothing (its fabric is wrapped
    in a `peer_fabric::LeechFabric`, so the serve + announce axes are masked at the capability
    seam). This scenario proves the peer-side consequence with a MINIMAL PAIR whose only delta is
    node A's mode - leech vs announce-after-fetch provider - and reads the SAME oracle (B's upstream
    NAR egress) in both arms:

      * LEECH arm: A is a `--libp2p-leech` consumer. It fetches the target through its OWN daemon
        (so it HOLDS the path in its store), but announces nothing. A second consumer B - which in
        the mutation below discovers A via kad - now finds NO provider record for the target (A, the
        only holder, is a leech), so B falls back to UPSTREAM (upstream.nar >= 1). B got NOTHING
        from the leech: the peer-side proof.

      * SERVING mutation (negative control): the SAME topology with A as an announce-after-fetch
        PROVIDER. A fetches the target, ANNOUNCES it, and B discovers A via kad and fetches the
        target FROM A with 0 upstream NAR egress. This reddens the leech arm's ">= 1": flip A from
        leech to serving and the peer CAN obtain the content - so the leech mask is load-bearing.

    Attribution is clean in the leech arm because A is PROVEN to hold the target (its realise
    succeeds) and PROVEN to be a leech (its log carries the LIBP2P-LEECH marker and NO announce
    marker) - so B's fallback is caused by A giving nothing back, not by A lacking the content or
    being down. The airtight serve-refusal for a DIRECTLY-dialled leech (NotHeld regardless of
    announce) is proven at the fabric layer by fabric-libp2p's `a_leech_serves_nothing_to_a_
    reachable_peer`; here the e2e proves the discovery half end to end through real nix.
    """
    fixtures = ctx.fixtures

    # -- LEECH arm: A is a leech; B gets NOTHING from it and falls back to upstream. --
    seed_dir, prov_seeds, target_sp = _s7_seeds(ctx, "leech", S7_TARGET)
    target_nar_hash = fixtures.nar_hash(S7_TARGET)
    a_daemon = f"http://127.0.0.1:{DAEMON_PORT + 1}"
    with Pod(
        ctx,
        "leech",
        fixtures.cache,
        with_daemon=False,
        expect=expect,
        libp2p_seed_dir=seed_dir,
        libp2p_provider_seeds=prov_seeds,
        libp2p_leech=True,
    ) as pod:
        # A boots as a consume-only leech on the PRIMARY daemon-libp2p binary, whose marker states
        # the serve/announce axes are masked AT THE CAPABILITY SEAM (peer_fabric::LeechFabric) - so
        # this scenario exercises the seam mask end to end, not a separate consume-only path.
        alog = pod.logs("lp-provider")
        expect(
            "daemon-libp2p: LIBP2P-LEECH consume-only" in alog
            and "masked at the capability seam" in alog,
            "S-LEECH: A boots in consume-only leech mode via the daemon-libp2p LeechFabric SEAM mask",
            f"provider log tail: {alog[-900:]!r}",
        )
        # TASK-120 FIX A: a consume-only node runs kad in CLIENT mode (relay server OFF) - it issues
        # queries + fetches but ANSWERS no DHT queries for others and provides no relay, so its swarm
        # participation matches what it reports. A regression to kad-server would redden here.
        expect(
            "kad CLIENT mode, relay OFF" in alog,
            "S-LEECH FIX A: the consume-only leech runs kad CLIENT mode + relay OFF (no DHT infrastructure)",
            f"provider log tail: {alog[-900:]!r}",
        )

        time.sleep(LIBP2P_CONVERGE_S)  # bounded kad settle

        # STEP 1: A FETCHES the target through its OWN daemon (origin-direct), so it HOLDS the path.
        pod.proxy_reset()
        realise = _leech_drive_a_fetch(pod, ctx, target_sp, a_daemon)
        expect(
            realise.returncode == 0,
            "S-LEECH step1: the leech A still FETCHES successfully (it realises the target through "
            "its own daemon) - consume-only does not break consuming",
            (realise.stdout + realise.stderr)[-800:],
        )
        # A announced NOTHING despite now holding the target - the leech mask at work.
        alog = pod.logs("lp-provider")
        expect(
            "LIBP2P-ANNOUNCE-AFTER-FETCH narhash=" not in alog
            and "LIBP2P-PROVIDE-STORE narhash=" not in alog
            and "LIBP2P-SEED narhash=" not in alog,
            "S-LEECH step1: A announces NOTHING even after fetching+holding the target",
            f"provider log tail: {alog[-900:]!r}",
        )
        time.sleep(
            LIBP2P_CONVERGE_S
        )  # give any (absent) record propagation the same window

        # STEP 2 (the peer-side bite): B builds the target. A is the only holder, but it is a leech,
        # so B finds no provider record and falls back to UPSTREAM.
        pod.proxy_reset()
        res = pod.client_run(
            [target_sp], ctx.substituter_daemon_only(), fixtures.public_key
        )
        expect(
            res.exit_code == 0,
            "S-LEECH step2: B's build still completes (via upstream fallback) with A a leech",
            res.stderr[-800:],
        )
        got = res.narhash(target_sp)
        expect(
            got == target_nar_hash,
            f"S-LEECH S1 byte-identity: {S7_TARGET} NarHash matches the signed upstream",
            f"got={got} want={target_nar_hash}",
        )
        b_nar_up = pod.proxy_stats()["upstream"].get("nar", 0)
        expect(
            b_nar_up >= 1,
            "S-LEECH peer-side oracle: B obtained NOTHING from the leech A (which HOLDS the target) "
            "and fell back to upstream (upstream.nar >= 1) - a leech gives nothing back",
            f"upstream.nar={b_nar_up}",
        )

    # -- SERVING mutation (negative control): SAME topology, A is an announce-after-fetch provider; --
    #    B now gets the target FROM A with 0 upstream egress. This reddens the leech arm's ">= 1".
    seed_dir2, prov_seeds2, target_sp2 = _s7_seeds(ctx, "leech-mut", S7_TARGET)
    a_daemon2 = f"http://127.0.0.1:{DAEMON_PORT + 1}"
    with Pod(
        ctx,
        "leech-mut",
        fixtures.cache,
        with_daemon=False,
        expect=expect,
        libp2p_seed_dir=seed_dir2,
        libp2p_provider_seeds=prov_seeds2,
        libp2p_trusted_key=fixtures.public_key,
        libp2p_announce_after_fetch=True,
    ) as pod:
        time.sleep(LIBP2P_CONVERGE_S)
        # A fetches the target (fires announce-after-fetch).
        pod.proxy_reset()
        realise = _leech_drive_a_fetch(pod, ctx, target_sp2, a_daemon2)
        expect(
            realise.returncode == 0,
            "S-LEECH mutation: A (a serving provider) realises the target through its own daemon",
            (realise.stdout + realise.stderr)[-800:],
        )
        # Wait for A to ANNOUNCE the fetched path.
        announced = False
        deadline = time.time() + READY_TIMEOUT_S
        while time.time() < deadline:
            if "LIBP2P-ANNOUNCE-AFTER-FETCH narhash=" in pod.logs(
                "lp-provider"
            ) and target_nar_hash in pod.logs("lp-provider"):
                announced = True
                break
            time.sleep(0.5)
        expect(
            announced,
            "S-LEECH mutation: A ANNOUNCES the fetched path (the delta from the leech arm)",
            f"want narhash={target_nar_hash}; provider log tail: {pod.logs('lp-provider')[-900:]!r}",
        )
        time.sleep(LIBP2P_CONVERGE_S)
        # B discovers A via kad and fetches the target FROM A: 0 upstream egress.
        pod.proxy_reset()
        res = pod.client_run(
            [target_sp2], ctx.substituter_daemon_only(), fixtures.public_key
        )
        expect(
            res.exit_code == 0,
            "S-LEECH mutation: B's build completes, served by A over libp2p",
            res.stderr[-800:],
        )
        got = res.narhash(target_sp2)
        expect(
            got == target_nar_hash,
            "S-LEECH mutation S1 byte-identity: NarHash matches the signed upstream",
            f"got={got} want={target_nar_hash}",
        )
        b_nar_up = pod.proxy_stats()["upstream"].get("nar", 0)
        expect(
            b_nar_up == 0,
            "S-LEECH MUTATION oracle: with A SERVING (not a leech), B obtains the target FROM A "
            "(0 upstream NAR egress) - proving the leech arm's >=1 is load-bearing, not vacuous",
            f"upstream.nar={b_nar_up}",
        )


def scenario_narinfo_default_cache_offload(ctx: Ctx, expect) -> None:
    """TASK-29 AC#1/#2: the daemon narinfo disk cache is ON BY DEFAULT and, on a
    REPEAT build of the same paths, serves narinfo LOCALLY so ZERO narinfo crosses
    the daemon->testproxy (upstream) boundary - the offload oracle, ORACLE-PAIRED
    per scripts/MEASUREMENT_COUNTING_RULE.md: a "0 upstream narinfo" claim is only
    meaningful when the client independently confirms it received those narinfo (a
    zero-crossing is offload iff delivery is confirmed - never a silent miss).

    The daemon does NOT narrate narinfo serves (only NAR substitutions, per the
    counting rule), so the "nonzero served-locally" half is observed as: a FRESH
    client (wiped narinfo cache) realises all N targets and reports all N NarHashes
    on the warm run WHILE received.narinfo == 0 at the boundary - i.e. all N narinfo
    were served from the daemon's own disk cache. The explicit-dir arm additionally
    counts the daemon's persisted `.nic` entries host-side as a direct daemon-side
    integer.

    Scope (stated honestly): a warm HIT reads the `.nic` BODY from disk on every
    request (NarinfoDiskCache holds no in-memory body cache - `read_fresh` does an
    `fs::read`), so these arms genuinely prove a DISK-read serve, not merely an
    in-memory one. What they do NOT exercise is a daemon RESTART: the post-restart
    sidecar warm-up (`load_index`) is covered by daemon-core's own unit tests, not
    re-asserted here.

    THREE arms, so the oracle BITES (the mutation is a PERMANENT negative control):
      * default-on : no cache flag at all -> the daemon defaults the cache on at its
                     XDG state dir (podman sets HOME=/root in the e2e image). Proves
                     AC#1 end-to-end: a fresh daemon with NO flag persists+offloads.
      * explicit   : the harness passes --narinfo-cache-dir via a host-mounted state
                     dir (AC#2 'the harness passes the cache dir') + the `.nic` count.
      * disabled   : --no-narinfo-cache -> the daemon holds NO narinfo cache, so on
                     the REPEAT it RE-FETCHES every narinfo upstream and
                     received.narinfo > 0. THIS is the mutation that reddens the
                     other arms' `== 0`, attributing the offload to the cache.
    """
    fixtures = ctx.fixtures
    attrs = NARINFO_ATTRS
    targets = [fixtures.store_path(a) for a in attrs]
    subst = ctx.substituter_daemon_only()
    keys = fixtures.public_key

    def cold_then_warm(pod):
        """Cold populate, then a warm REPEAT with proxy COUNTERS reset (its disk
        cache kept, exactly like s1) and a FRESH client. Returns the warm proxy
        stats + the warm client result so each arm asserts its own oracle."""
        pod.proxy_reset()
        cold = pod.client_run(targets, subst, keys)
        expect(
            cold.exit_code == 0, f"{pod.pod}: cold realise succeeds", cold.stderr[-400:]
        )
        cold_ninfo = pod.proxy_stats()["received"].get("narinfo", 0)
        expect(
            cold_ninfo >= len(attrs),
            f"{pod.pod}: cold fetches every narinfo upstream (the pre-offload baseline)",
            f"received.narinfo={cold_ninfo} want>={len(attrs)}",
        )
        pod.proxy_reset()
        warm = pod.client_run(targets, subst, keys)
        expect(
            warm.exit_code == 0, f"{pod.pod}: warm repeat succeeds", warm.stderr[-400:]
        )
        return pod.proxy_stats(), warm

    def assert_offload(wstats, warm, label):
        """The oracle-paired AC#1 offload, asserted on the warm REPEAT."""
        w_ninfo = wstats["received"].get("narinfo", 0)
        served_locally = sum(
            1
            for a in attrs
            if warm.narhash(fixtures.store_path(a)) == fixtures.nar_hash(a)
        )
        # HALF A (zero upstream): no narinfo crossed the daemon->testproxy boundary.
        # HALF B (nonzero served locally): the fresh client received all N narinfo,
        # and since zero crossed, the daemon served all N from its own disk cache.
        expect(
            w_ninfo == 0 and served_locally == len(attrs) and len(attrs) > 0,
            f"{label}: warm repeat offloads narinfo - 0 upstream PAIRED with "
            f"{served_locally} narinfo served locally by the daemon cache",
            f"received.narinfo={w_ninfo} served_locally={served_locally}/{len(attrs)}",
        )

    # -- arm 1: DEFAULT ON (no flag). AC#1: a fresh daemon with no flag offloads. --
    with Pod(
        ctx, "narinfo-default", fixtures.cache, with_daemon=True, expect=expect
    ) as pod:
        wstats, warm = cold_then_warm(pod)
        default_line = "narinfo disk cache at /root/.local/state/nix-p2p/narinfo"
        expect(
            default_line in pod.logs("daemon"),
            "default-on: the daemon resolves+logs the DEFAULT XDG cache dir (no flag)",
            f"expected {default_line!r}; daemon log tail: {pod.logs('daemon')[-400:]}",
        )
        assert_offload(wstats, warm, "AC#1 default-on")

    # -- arm 2: EXPLICIT --narinfo-cache-dir via a host-mounted state dir (AC#2:  --
    #    'the harness passes the cache dir') + a direct host-side `.nic` count.
    state_root = ctx.scratch / "narinfo-offload-state"
    if state_root.exists():
        shutil.rmtree(state_root)
    with Pod(
        ctx,
        "narinfo-explicit",
        fixtures.cache,
        with_daemon=True,
        expect=expect,
        state_root=state_root,
    ) as pod:
        wstats, warm = cold_then_warm(pod)
        nic_files = list(pod.state_dir("daemon").glob("*.nic"))
        expect(
            len(nic_files) >= len(attrs),
            "explicit-dir: the daemon persisted narinfo entries on disk (host-side .nic count)",
            f"nic_files={len(nic_files)} want>={len(attrs)}",
        )
        assert_offload(wstats, warm, "AC#2 explicit-dir")

    # -- arm 3: DISABLED (--no-narinfo-cache): the negative control / MUTATION. --
    #    With NO cache the daemon re-fetches every narinfo upstream on the REPEAT,
    #    so received.narinfo > 0 - exactly what reddens the '== 0' arms above.
    with Pod(
        ctx,
        "narinfo-disabled",
        fixtures.cache,
        with_daemon=True,
        expect=expect,
        daemon_extra_args=("--no-narinfo-cache",),
    ) as pod:
        pod.proxy_reset()
        cold = pod.client_run(targets, subst, keys)
        expect(
            cold.exit_code == 0, "disabled: cold realise succeeds", cold.stderr[-400:]
        )
        pod.proxy_reset()
        warm = pod.client_run(targets, subst, keys)
        expect(
            warm.exit_code == 0, "disabled: warm repeat succeeds", warm.stderr[-400:]
        )
        w_ninfo = pod.proxy_stats()["received"].get("narinfo", 0)
        expect(
            "narinfo disk cache disabled (--no-narinfo-cache)" in pod.logs("daemon"),
            "disabled: the daemon logs the cache is OFF (--no-narinfo-cache honoured)",
            f"daemon log tail: {pod.logs('daemon')[-400:]}",
        )
        expect(
            w_ninfo >= 1,
            "MUTATION (negative control): with the cache OFF the REPEAT re-fetches "
            "narinfo upstream (received.narinfo>0), proving the offload oracle above "
            "is load-bearing, not vacuous",
            f"received.narinfo={w_ninfo} want>=1",
        )


def scenario_libp2p_mdns_bootstrap(ctx: Ctx, expect) -> None:
    """TASK-257: two daemons on ONE LAN segment, NEITHER given `--libp2p-bootstrap`, discover
    each other purely via `--libp2p-mdns` and the consumer fetches a byte-identical NAR from the
    provider with 0 upstream NAR egress. This is the zero-config LAN/org-pool proof: mDNS
    supplies the peer ADDRESS (fed to kad's bootstrap path), kad supplies WHO-holds-content, and
    NO address was injected (the consumer argv carries no bootstrap and no provider-addr).
    """
    fixtures = ctx.fixtures
    seed_dir, prov_seeds, target_sp = _s7_seeds(ctx, "mdns", S7_TARGET)
    with Libp2pMdnsTopology(
        ctx, "mdns", fixtures.cache, seed_dir, prov_seeds, expect,
        provider_scope=LIBP2P_SCOPE,
        consumers=(("lp-consumer", LIBP2P_SCOPE),),
        libp2p_trusted_key=fixtures.public_key,
    ) as topo:
        prov_id = topo.provider_identity[0] if topo.provider_identity else ""
        argv = topo.consumer_argv("lp-consumer")
        joined = " ".join(argv)
        # NO-INJECTION oracle: the consumer was NEVER handed a bootstrap or the provider's
        # address; the ONLY path to the provider's dial address is mDNS.
        expect(
            "--libp2p-bootstrap" not in argv,
            "mdns no-injection: consumer has NO --libp2p-bootstrap (mDNS is the only entry path)",
            f"argv={joined!r}",
        )
        expect(
            "--libp2p-provider-addr" not in argv and (not prov_id or prov_id not in joined),
            "mdns no-injection: consumer argv omits the provider's PeerId + any provider-addr",
            f"prov_id={prov_id!r} argv={joined!r}",
        )
        expect(
            "--libp2p-mdns" in argv,
            "mdns: consumer runs with --libp2p-mdns (the sole discovery mechanism here)",
            f"argv={joined!r}",
        )

        time.sleep(LIBP2P_MDNS_CONVERGE_S)
        topo.proxy_reset()
        res = topo.client_run("lp-consumer", [target_sp], fixtures.public_key)
        expect(
            res.exit_code == 0,
            "mdns positive: nix build completes with the NAR served by the mDNS-discovered peer",
            res.stderr[-800:],
        )
        got = res.narhash(target_sp)
        expect(
            got == fixtures.nar_hash(S7_TARGET),
            "mdns positive byte-identity: NarHash matches the signed upstream",
            f"got={got} want={fixtures.nar_hash(S7_TARGET)}",
        )
        stats = topo.proxy_stats()
        nar_up = stats["upstream"].get("nar", 0)
        expect(
            nar_up == 0,
            "mdns positive ORACLE: 0 upstream NAR egress (the target was peer-served over a DHT "
            "the consumer joined with NO bootstrap - only mDNS could have supplied the address)",
            f"upstream.nar={nar_up}",
        )
        # Corroboration: the consumer's log shows it DISCOVERED the provider's record via kad
        # (content discovery stayed kad-exclusive) rather than a bare miss.
        clog = topo.logs("lp-consumer")
        expect(
            "libp2p-kad miss" not in clog,
            "mdns positive: the consumer did not log a kad discovery miss (it resolved the peer)",
            f"consumer log tail: {clog[-500:]!r}",
        )


def scenario_libp2p_mdns_scope_isolation(ctx: Ctx, expect) -> None:
    """TASK-257 negative control (bite #2): mDNS multicasts across the WHOLE LAN, but the scoped
    `/nix-p2p/<scope>/kad` protocol still isolates. Provider P and a same-scope helper H (scope
    A) form a DHT and H fetches the target (0 egress - proving mDNS discovery is live on this
    bridge); a consumer C on a DIFFERENT scope (B), on the SAME bridge with mDNS ON, CANNOT join
    P's DHT and falls back to upstream (>=1 egress). The H-resolves / C-does-not contrast, same
    LAN + same mDNS + same key, attributes the isolation to the SCOPE alone.
    """
    fixtures = ctx.fixtures
    seed_dir, prov_seeds, target_sp = _s7_seeds(ctx, "mdns-scope", S7_TARGET)
    scope_a = f"{LIBP2P_SCOPE}-mdns-a"
    scope_b = f"{LIBP2P_SCOPE}-mdns-b"
    with Libp2pMdnsTopology(
        ctx, "mdnsscope", fixtures.cache, seed_dir, prov_seeds, expect,
        provider_scope=scope_a,
        # H shares the provider's scope (its quorum peer + positive control); C is cross-scope.
        consumers=(("lp-helper", scope_a), ("lp-consumer", scope_b)),
        libp2p_trusted_key=fixtures.public_key,
    ) as topo:
        time.sleep(LIBP2P_MDNS_CONVERGE_S)

        # POSITIVE within the arm: the SAME-scope helper resolves + fetches (0 egress). This
        # proves mDNS discovery works on this bridge, so the negative below is not vacuous.
        topo.proxy_reset()
        res_h = topo.client_run("lp-helper", [target_sp], fixtures.public_key)
        expect(
            res_h.exit_code == 0 and res_h.narhash(target_sp) == fixtures.nar_hash(S7_TARGET),
            "mdns scope positive: the SAME-scope helper fetches the target byte-identically",
            res_h.stderr[-600:],
        )
        expect(
            topo.proxy_stats()["upstream"].get("nar", 0) == 0,
            "mdns scope positive: 0 upstream NAR egress for the same-scope helper (mDNS discovery "
            "is live on this bridge)",
            "",
        )

        # LOAD-BEARING EVIDENCE: from INSIDE C's netns, the provider is ALIVE + reachable at its
        # routable IP - so C's fallback below isolates SCOPE, not liveness or L2 path.
        status, _ = topo.provider_reachable_from("lp-consumer")
        expect(
            status == 200,
            "mdns scope control: the provider is ALIVE + reachable from the cross-scope consumer's "
            "netns (so the fallback isolates SCOPE, not liveness)",
            f"status={status}",
        )

        # NEGATIVE: the DIFFERENT-scope consumer CANNOT join P's DHT -> upstream fallback.
        topo.proxy_reset()
        res_c = topo.client_run("lp-consumer", [target_sp], fixtures.public_key)
        expect(
            res_c.exit_code == 0,
            "mdns scope control: the cross-scope build still succeeds via upstream fallback",
            res_c.stderr[-600:],
        )
        expect(
            res_c.narhash(target_sp) == fixtures.nar_hash(S7_TARGET),
            "mdns scope control: still byte-identical (served by upstream fallback)",
            f"got={res_c.narhash(target_sp)}",
        )
        nar_up = topo.proxy_stats()["upstream"].get("nar", 0)
        expect(
            nar_up >= 1,
            "mdns scope control ORACLE BITE: a DIFFERENT-scope consumer served by upstream (>=1 "
            "NAR) despite mDNS multicasting across the same bridge - the scoped kad protocol "
            "isolates, so mDNS discovery and scope isolation compose",
            f"upstream.nar={nar_up}",
        )


SCENARIOS = [
    ("topology", scenario_topology),
    ("s1-byte-and-counts", scenario_s1_byte_and_counts),
    ("narinfo-default-cache-offload", scenario_narinfo_default_cache_offload),
    ("s2-fallback", scenario_s2_fallback),
    ("daemon-positive-control", scenario_daemon_positive_control),
    ("tamper-corrupt-sig", scenario_tamper_corrupt_sig),
    ("tamper-foreign-key", scenario_tamper_foreign_key),
    ("tamper-narhash", scenario_tamper_narhash),
    ("corrupt-nar", scenario_corrupt_nar),
    ("absent-404", scenario_absent_404),
    # crash suite (task-7): S2 additive invariant under daemon crashes.
    ("crash-daemon-absent", scenario_crash_daemon_absent),
    ("crash-kill-mid-nar", scenario_crash_kill_mid_nar),
    ("crash-kill-during-narinfo", scenario_crash_kill_during_narinfo),
    ("crash-kill-between-narinfo-nar", scenario_crash_kill_between_narinfo_and_nar),
    ("crash-sigstop-stall", scenario_crash_sigstop_stall),
    ("crash-keepalive-desync", scenario_crash_keepalive_desync),
    # long-chain suite (task-11): depth-3 proxy composition must survive depth.
    ("chain-s1-and-counts", scenario_chain_s1_and_counts),
    ("chain-corrupt-bite", scenario_chain_corrupt_bite),
    ("chain-absent-404", scenario_chain_absent_404),
    ("chain-timeout-invariant", scenario_chain_timeout_invariant),
    ("chain-kill-middle-daemon", scenario_chain_kill_middle_daemon),
    # fault x depth matrix (task-13): all 7 fault modes x chain depth 1..3, and
    # the TASK-33 latency-vs-timeout boundary pinned + shown to move.
    ("fault-depth-matrix", scenario_fault_depth_matrix),
    ("chain-timeout-boundary", scenario_chain_timeout_boundary),
    # S6 (task-41): peer-served NAR over iroh - the wave-2 acceptance signal.
    ("s6-p2p", scenario_s6_p2p),
    ("s6-corrupt-bite", scenario_s6_corrupt_bite),
    ("s6-fallback", scenario_s6_fallback),
    ("s6-compressed-fail-closed", scenario_s6_compressed_fail_closed),
    # S7 (task-161): the libp2p arm - real 3-daemon decentralized discover->resolve->
    # fetch->serve across containers, with the F1 load-bearing control + a MISS arm.
    ("s7-libp2p", scenario_s7_libp2p),
    # TASK-242: the containerized dependency-outage drill - kill a REAL bootstrap process and watch
    # the live operator --status surface flip bootstrap health, while a nix build still succeeds.
    ("libp2p-bootstrap-outage", scenario_libp2p_bootstrap_outage),
    ("s7-libp2p-miss", scenario_s7_libp2p_miss),
    ("s7-libp2p-netns", scenario_s7_libp2p_netns),
    # S8 (TASK-194 / 191 AC#3): the libp2p provider serves a REAL /nix/store path it NEVER
    # held as a .nar - regenerated on demand via `nix-store --dump` (store-supply mode) -
    # to a consumer that discovers it via kad, byte-identical, with the kill-P control.
    ("s8-libp2p-store", scenario_s8_libp2p_store),
    # S9 (TASK-77): announce-after-fetch - node A holds nothing, FETCHES the target from upstream
    # through its own daemon, becomes a discoverable holder, and a second consumer B then fetches
    # the target FROM A (0 upstream egress). The swarm GROWS; the kill-A control proves A was
    # load-bearing.
    ("s9-libp2p-grow", scenario_s9_libp2p_grow),
    # S-LEECH (TASK-78): a consume-only leech serves + announces NOTHING, verified from the peer
    # side - a second consumer that WOULD discover A (and does, in the serving mutation) gets
    # nothing from the leech and falls back to upstream. Minimal pair on A's mode (leech vs serving).
    ("libp2p-leech", scenario_libp2p_leech),
    # TASK-257: mDNS zero-bootstrap LAN discovery - two daemons on one shared multicast bridge,
    # NEITHER given --libp2p-bootstrap, discover each other via --libp2p-mdns and the consumer
    # fetches byte-identical with 0 upstream egress; plus the scope-isolation negative control.
    ("libp2p-mdns-bootstrap", scenario_libp2p_mdns_bootstrap),
    ("libp2p-mdns-scope-isolation", scenario_libp2p_mdns_scope_isolation),
]


# ---- preflight, image, runner ----------------------------------------------


def preflight_gate(out_root: Path | None = None) -> None:
    """Run the fail-closed fixture gate BEFORE serving anything (round-2 deep-
    gate finding: never serve an unverified tree). --skip-determinism because
    the blob/sig/bite verification is what "unverified tree" means here;
    regeneration determinism is separately gated by `just fixtures-large`, which
    `just e2e` depends on.

    `out_root` MUST be the SAME publication root the caller then MEASURES/SERVES:
    a report that verifies the default tree but measures a custom `--out` tree is
    a provenance lie (codex finding). When given, it is threaded to
    `check-fixtures --out` so the VERIFIED tree is the MEASURED tree."""
    script = Path(__file__).resolve().parent / "check-fixtures.py"
    argv = [sys.executable, str(script), "--require-tier", "full", "--skip-determinism"]
    if out_root is not None:
        argv += ["--out", str(out_root)]
    result = subprocess.run(argv, check=False)
    if result.returncode != 0:
        die(
            "check-fixtures gate failed - refusing to serve/measure an unverified "
            f"fixture tree at {out_root or 'fixtures/out'} (exit {result.returncode}). "
            "Run `just fixtures-large`."
        )


def load_image() -> str:
    """Build the e2e image and load it into podman, tagged by its store hash so
    reruns skip the load."""
    built = (
        run(["nix", "build", ".#e2e-image", "--no-link", "--print-out-paths"])
        .stdout.strip()
        .splitlines()
    )
    if not built:
        die("nix build .#e2e-image produced no output path")
    tarball = built[-1]
    tag = Path(tarball).name.split("-", 1)[0]
    ref = f"localhost/{POD_PREFIX}:{tag}"
    pm = podman()
    if run([pm, "image", "exists", ref], check=False).returncode == 0:
        return ref
    loaded = run([pm, "load", "-i", tarball])
    # Parse "Loaded image: <name>" to find what to retag.
    name = None
    for line in (loaded.stdout + loaded.stderr).splitlines():
        if ":" in line and "Loaded image" in line:
            name = line.split(":", 1)[1].strip()
            if name.startswith(" "):
                name = name.strip()
            name = line.split("image", 1)[1].lstrip(" (s):").strip()
    if not name:
        name = f"{POD_PREFIX}:latest"
    run([pm, "tag", name, ref])
    return ref


def cleanup_pods(reason: str = "") -> int:
    """Remove every pod/container this harness created (the Ctrl-C leak trap and
    `e2e-clean`). Targets ONLY our label - never the fixture tree, which the
    generator owns."""
    pm = podman()
    removed = 0
    listing = run(
        [pm, "pod", "ps", "--filter", f"label={PROJECT_LABEL}", "-q"], check=False
    ).stdout.split()
    for pod_id in listing:
        run([pm, "pod", "rm", "-f", pod_id], check=False)
        removed += 1
    # Any stray labelled containers not in a pod (the S7 separate-netns topology
    # runs its daemons as standalone --network containers, not pod members).
    stray = run(
        [pm, "ps", "-a", "--filter", f"label={PROJECT_LABEL}", "-q"], check=False
    ).stdout.split()
    for cid in stray:
        run([pm, "rm", "-f", cid], check=False)
    # Labelled networks (the S7 separate-netns topology creates two bridge
    # networks per arm). Removed AFTER the containers that attach to them, so the
    # rm cannot fail on an in-use network. Label-scoped like everything else here.
    nets = run(
        [pm, "network", "ls", "--filter", f"label={PROJECT_LABEL}", "-q"], check=False
    ).stdout.split()
    for net in nets:
        run([pm, "network", "rm", "-f", net], check=False)
    if reason:
        print(f"e2e-clean: removed {removed} pod(s) {reason}")
    return removed


def prune_images_and_volumes() -> None:
    """Prune dangling podman images + unused volumes (TASK-54 AC#1).

    Called ONLY from the `--clean` CLI path, never from `cleanup_pods` (which runs
    BETWEEN scenarios, where pruning would delete the very image the next scenario
    needs). `image prune` (no `-a`) removes only DANGLING images - untagged layers
    orphaned by a rebuilt e2e image - so a still-referenced image is never touched;
    a fresh `just e2e` reloads its image regardless. Rootless podman scopes both to
    THIS user's objects. Podman prints the bytes it reclaimed."""
    pm = podman()
    print("e2e-clean: pruning dangling images")
    run([pm, "image", "prune", "-f"], check=False)
    print("e2e-clean: pruning unused volumes")
    run([pm, "volume", "prune", "-f"], check=False)


def run_scenarios(ctx: Ctx, selected) -> int:
    if not selected:
        # Fail-closed honesty: a harness with nothing to run is a stub.
        print(STUB_MARKER)
        return 1
    print(f"e2e: {len(selected)} scenarios registered")
    results: list[tuple[str, bool, list[Check], float]] = []
    for name, fn in selected:
        print(f"\n=== scenario: {name} ===")
        checks: list[Check] = []
        started = time.monotonic()
        try:
            fn(ctx, make_expect(checks))
        except SystemExit:
            raise
        except Exception as error:  # noqa: BLE001 - a scenario crash is a failure
            checks.append(Check(False, "scenario raised", repr(error)))
        finally:
            cleanup_pods()  # never leak a pod between scenarios
        # Measured INSIDE the cleanup, so a scenario is charged for the pods it
        # leaves behind. `just e2e` selects a subset of these by name, and that
        # selection has to be defensible from timings rather than from a guess
        # about which scenario "feels" slow.
        elapsed = time.monotonic() - started
        passed = bool(checks) and all(c.ok for c in checks)
        results.append((name, passed, checks, elapsed))
        for check in checks:
            mark = "ok  " if check.ok else "FAIL"
            extra = f"  [{check.detail}]" if check.detail and not check.ok else ""
            print(f"  {mark} {check.name}{extra}")
        print(f"  => {name}: {'PASS' if passed else 'FAIL'}")

    print("\n=== summary ===")
    all_pass = True
    for name, passed, checks, elapsed in results:
        n_ok = sum(1 for c in checks if c.ok)
        print(
            f"  {'PASS' if passed else 'FAIL'} {name} "
            f"({n_ok}/{len(checks)} checks, {elapsed:.1f}s)"
        )
        all_pass = all_pass and passed
    total = sum(elapsed for _, _, _, elapsed in results)
    print(f"  ---- {len(results)} scenarios, {total:.1f}s total")
    print(f"\ne2e: {'ALL SCENARIOS PASSED' if all_pass else 'FAILURES PRESENT'}")
    return 0 if all_pass else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clean", action="store_true", help="tear down pods and exit")
    parser.add_argument("--list", action="store_true", help="list scenarios and exit")
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run the pure no-injection oracle BITE self-test (no containers) and exit",
    )
    parser.add_argument(
        "--only",
        action="append",
        default=[],
        help="run only this scenario (repeatable)",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=fx.repo_root() / "fixtures" / "out",
        help="fixture publication root",
    )
    args = parser.parse_args()

    if args.self_test:
        # Bounded, container-free: the tmp-byte probe bite AND the no-injection bite.
        _self_test_tmp_size_snippet()
        print("e2e: tmp-byte probe self-test passed", file=sys.stderr)
        return no_injection_self_test()

    _self_test_tmp_size_snippet()
    print("e2e: tmp-byte probe self-test passed", file=sys.stderr)

    if args.list:
        for name, _ in SCENARIOS:
            print(name)
        return 0
    if args.clean:
        cleanup_pods("(--clean)")
        prune_images_and_volumes()
        return 0

    preflight_gate()
    fixtures = resolve_fixtures(args.out.resolve())
    image = load_image()
    cleanup_pods()  # clear any stale pods from a crashed prior run

    scratch = Path(os.environ.get("TMPDIR", "/tmp")) / f"nix-p2p-e2e-{os.getpid()}"
    scratch.mkdir(parents=True, exist_ok=True)
    ctx = Ctx(podman=podman(), image=image, fixtures=fixtures, scratch=scratch)

    selected = SCENARIOS
    if args.only:
        wanted = set(args.only)
        selected = [(n, f) for n, f in SCENARIOS if n in wanted]
        missing = wanted - {n for n, _ in SCENARIOS}
        if missing:
            die(f"unknown scenario(s): {sorted(missing)}", code=2)

    try:
        return run_scenarios(ctx, selected)
    finally:
        cleanup_pods()  # Ctrl-C / exit leak trap
        with contextlib.suppress(OSError):
            shutil.rmtree(scratch)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        cleanup_pods("(interrupted)")
        sys.exit(130)
