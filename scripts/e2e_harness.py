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
import subprocess
import sys
import time
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
    exit_code = 0
    for line in stdout.splitlines():
        if line.startswith("REALISE_RC="):
            exit_code = int(line.split("=", 1)[1])
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
        try:
            http_get(f"http://127.0.0.1:{HOST_DAEMON}/nix-cache-info", timeout=1.0)
            daemon_up = True
        except OSError:
            daemon_up = False
        expect(not daemon_up, "S2 precondition: daemon is not running", "")

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
