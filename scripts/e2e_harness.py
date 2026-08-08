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
  * task-11 (chain N daemons): task-11 WILL add a `daemon_chain=N` param to Pod
    (not present yet) to run d1->d2->...->testproxy; today Pod starts one daemon.

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
import os
import shutil
import socket
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

# The DoD honesty marker (Justfile `stub_marker`). A real harness with zero
# scenarios registered is a stub pretending to pass; we print this and fail
# closed if that ever happens, and `just e2e` succeeding proves it absent.
STUB_MARKER = "0 scenarios registered - NOT a pass"

# The four fixture payloads (task-3 workload v1); the closure `app -> lib`
# exercises signed References.
ALL_ATTRS = ("lib", "app", "zstd", "big")

READY_TIMEOUT_S = 45.0


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
    ):
        self.ctx = ctx
        self.pod = f"{POD_PREFIX}-{name}"
        self.served_cache = served_cache
        self.with_daemon = with_daemon
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
        run(
            [
                self._pm,
                "pod",
                "create",
                "--name",
                self.pod,
                "--label",
                PROJECT_LABEL,
                "-p",
                f"127.0.0.1:{HOST_ORIGIN}:{ORIGIN_PORT}",
                "-p",
                f"127.0.0.1:{HOST_PROXY}:{PROXY_PORT}",
                "-p",
                f"127.0.0.1:{HOST_DAEMON}:{DAEMON_PORT}",
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
        if self.with_daemon:
            run(
                [
                    self._pm,
                    "run",
                    "-d",
                    "--pod",
                    self.pod,
                    "--name",
                    self._c("daemon"),
                    "--label",
                    PROJECT_LABEL,
                    self.ctx.image,
                    "/bin/daemon",
                    "--listen",
                    f"0.0.0.0:{DAEMON_PORT}",
                    "--upstream",
                    f"http://127.0.0.1:{PROXY_PORT}",
                ]
            )
        self._await_ready()

    def _await_ready(self) -> None:
        targets = [
            (f"http://127.0.0.1:{HOST_ORIGIN}/nix-cache-info", "origin"),
            (f"http://127.0.0.1:{HOST_PROXY}/nix-cache-info", "testproxy"),
        ]
        if self.with_daemon:
            targets.append((f"http://127.0.0.1:{HOST_DAEMON}/nix-cache-info", "daemon"))
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
        for role in ("origin", "proxy", "daemon"):
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

    def proxy_faults(self, params: str) -> None:
        status, body = http_post(
            f"http://127.0.0.1:{HOST_PROXY}/__testproxy/faults?{params}"
        )
        if status != 200:
            die(f"proxy faults?{params} returned {status}: {body!r}")

    # -- client invocations (inside the pod netns) --

    def client_run(
        self, targets: list[str], substituters: str, keys: str
    ) -> ClientResult:
        """Substitute `targets` with a FRESH client (empty store + wiped
        narinfo cache, per the oracle-pairing rule) in single-user root nix.

        A fresh `podman run` container gives a clean /nix/store (image paths
        only, no fixtures) and an empty XDG cache, so counting is not made
        vacuous by a warm client. max-substitution-jobs=1 pins the counts.
        """
        script = _CLIENT_SCRIPT.format(
            subs=substituters, keys=keys, targets=" ".join(targets)
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

    def exec(self, role: str, argv: list[str], check: bool = False):
        return run([self._pm, "exec", self._c(role), *argv], check=check)

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
  --option max-substitution-jobs 1
  --option http-connections 1
  --option narinfo-cache-positive-ttl 0
  --option narinfo-cache-negative-ttl 0
  --option substitute true
)
nix-store --realise "${{common[@]}}" {targets} >/tmp/realised 2>/tmp/err
RC=$?
echo "REALISE_RC=$RC"
cat /tmp/err >&2
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

# Sum the sizes of every in-progress NAR cache tmp file at the proxy. `stat`
# ships in the image's coreutils; `find` does NOT, so the glob loop is bash.
_TMP_SIZE_SNIPPET = (
    "s=0; for f in /tmp/proxy-cache/.tmp/*; do "
    '[ -f "$f" ] && s=$((s+$(stat -c %s "$f"))); done; echo "$s"'
)

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
    pod: Pod, threshold: int, action: str, deadline_s: float = 180.0
) -> int:
    """Poll the proxy's in-flight NAR byte gauge and fire `action` ("kill" or
    "pause") on the daemon the instant the transfer crosses `threshold` bytes.
    Returns the observed byte count at the moment of action (or the last reading
    if the deadline passed without crossing - the caller asserts the crossing,
    so a miss fails loudly, and `nar_tmp_bytes` dies on a broken probe)."""
    fire = {"kill": pod.kill, "pause": pod.pause}[action]
    deadline = time.time() + deadline_s
    observed = 0
    while time.time() < deadline:
        observed = pod.nar_tmp_bytes()
        if observed >= threshold:
            fire("daemon")
            return observed
        time.sleep(0.02)
    return observed


def _kill_daemon_at_bytes(pod: Pod, threshold: int, deadline_s: float = 180.0) -> int:
    """SIGKILL the daemon once the NAR transfer crosses `threshold` bytes."""
    return _daemon_action_at_bytes(pod, threshold, "kill", deadline_s)


def _stall_daemon_at_bytes(pod: Pod, threshold: int, deadline_s: float = 180.0) -> int:
    """FREEZE (pause) the daemon once the NAR crosses `threshold` - the SIGSTOP
    stall (no RST/FIN)."""
    return _daemon_action_at_bytes(pod, threshold, "pause", deadline_s)


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
    """AC#2: SIGSTOP-style stall (cgroup freeze: no RST/FIN). The daemon is
    FROZEN mid-NAR, so the client's connection to it goes silent. Nothing in the
    daemon bounds a stalled body (see upstream.rs / task-25), so recovery relies
    entirely on nix's client-side `stalled-download-timeout` - which we pin low
    for a bounded test and MEASURE. The build must still complete via fallback;
    if the stall exceeded an acceptable bound that is a FINDING (task-25), not a
    pass."""
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
            f"(FINDING for task-25 if exceeded: daemon has no body-idle timeout)",
            f"measured {elapsed:.1f}s (pinned stalled-download-timeout={pinned_timeout_s}s)",
        )
        print(
            f"  sigstop MEASURED: fallback completed {elapsed:.1f}s after the freeze; "
            f"nix stalled-download-timeout pinned to {pinned_timeout_s}s "
            "(default is 300s - the unbounded hang a daemon body-idle timeout would cap; task-25)"
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


SCENARIOS = [
    ("topology", scenario_topology),
    ("s1-byte-and-counts", scenario_s1_byte_and_counts),
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
]


# ---- preflight, image, runner ----------------------------------------------


def preflight_gate() -> None:
    """Run the fail-closed fixture gate BEFORE serving anything (round-2 deep-
    gate finding: never serve an unverified tree). --skip-determinism because
    the blob/sig/bite verification is what "unverified tree" means here;
    regeneration determinism is separately gated by `just fixtures-large`, which
    `just e2e` depends on."""
    script = Path(__file__).resolve().parent / "check-fixtures.py"
    result = subprocess.run(
        [sys.executable, str(script), "--require-tier", "full", "--skip-determinism"],
        check=False,
    )
    if result.returncode != 0:
        die(
            "check-fixtures gate failed - refusing to serve an unverified fixture "
            f"tree (exit {result.returncode}). Run `just fixtures-large`."
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
    # Any stray labelled containers not in a pod.
    stray = run(
        [pm, "ps", "-a", "--filter", f"label={PROJECT_LABEL}", "-q"], check=False
    ).stdout.split()
    for cid in stray:
        run([pm, "rm", "-f", cid], check=False)
    if reason:
        print(f"e2e-clean: removed {removed} pod(s) {reason}")
    return removed


def run_scenarios(ctx: Ctx, selected) -> int:
    if not selected:
        # Fail-closed honesty: a harness with nothing to run is a stub.
        print(STUB_MARKER)
        return 1
    print(f"e2e: {len(selected)} scenarios registered")
    results: list[tuple[str, bool, list[Check]]] = []
    for name, fn in selected:
        print(f"\n=== scenario: {name} ===")
        checks: list[Check] = []
        try:
            fn(ctx, make_expect(checks))
        except SystemExit:
            raise
        except Exception as error:  # noqa: BLE001 - a scenario crash is a failure
            checks.append(Check(False, "scenario raised", repr(error)))
        finally:
            cleanup_pods()  # never leak a pod between scenarios
        passed = bool(checks) and all(c.ok for c in checks)
        results.append((name, passed, checks))
        for check in checks:
            mark = "ok  " if check.ok else "FAIL"
            extra = f"  [{check.detail}]" if check.detail and not check.ok else ""
            print(f"  {mark} {check.name}{extra}")
        print(f"  => {name}: {'PASS' if passed else 'FAIL'}")

    print("\n=== summary ===")
    all_pass = True
    for name, passed, checks in results:
        n_ok = sum(1 for c in checks if c.ok)
        print(f"  {'PASS' if passed else 'FAIL'} {name} ({n_ok}/{len(checks)} checks)")
        all_pass = all_pass and passed
    print(f"\ne2e: {'ALL SCENARIOS PASSED' if all_pass else 'FAILURES PRESENT'}")
    return 0 if all_pass else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clean", action="store_true", help="tear down pods and exit")
    parser.add_argument("--list", action="store_true", help="list scenarios and exit")
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

    if args.list:
        for name, _ in SCENARIOS:
            print(name)
        return 0
    if args.clean:
        cleanup_pods("(--clean)")
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
