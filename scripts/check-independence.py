#!/usr/bin/env python3
"""Assert the product daemon and the test cache-proxy share no crate.

PRD round 4 splits the workspace into two components that must never share
code: the product `daemon` and the `testproxy` fixture, which is an
independent witness of wire behaviour. PRD round 5/6 narrows the exception to
low-level pure-data crates, and only once a second consumer actually exists -
so ALLOWLIST below starts EMPTY and widening it must be a reviewable diff.

This inspects DECLARED dependencies (`cargo metadata --no-deps`), not the
resolved graph of `cargo tree`. That distinction is the point: `cargo tree`
reports only what the default features on the host target happen to pull in,
so a shared crate declared `optional = true` behind a feature, or under
`[target.'cfg(...)'.dependencies]`, is invisible to it. A declaration is a
declaration regardless of feature flag, target triple, or dependency kind.

Because `--no-deps` describes only the members of one workspace, every path
dependency is followed in turn, including ones resolving outside the
workspace - otherwise `daemon -> ../vendor/middle -> shared` alongside
`testproxy -> shared` would look independent.

What this does NOT and cannot see, stated plainly so the gate is not read as
broader than it is:
  * source-file tricks - `[lib] path = "../other/src/lib.rs"`, `#[path]`
    module includes, a build script copying a common file. No manifest-level
    check reaches those.
  * both components independently depending on the SAME third-party crate
    (e.g. two copies of one HTTP stack). That is a real PRD concern and it is
    deliberately not mechanised here: a denylist of crate names nobody has
    chosen yet would be a gate that looks like a check and is not one. It is
    carried forward as a hard requirement onto the tasks that pick the stacks.

The guard self-tests against synthetic workspaces before it is trusted to
pass (TESTING.md "Prove-the-check-bites"): a gate that cannot be shown to
fail is not a gate. Run from the workspace root.

Exit codes are distinct so a machine can tell the two apart:
  0  independent
  1  coupled - a real violation
  2  the check could not be performed; nothing was proven either way
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import tomllib
from collections import deque
from pathlib import Path

# The two components PRD round 4 declares strictly separated.
SEPARATED = ("daemon", "testproxy")

# Workspace-local crates both components may legally share. Empty on purpose.
ALLOWLIST: frozenset[str] = frozenset()

# HTTP-stack denylist (PRD round 5: "no shared proxy or HTTP logic"; the fixture
# must stay an independent witness of wire behaviour). The manifest check above
# only forbids a shared WORKSPACE crate; it cannot see the other real hazard,
# which round 5 names explicitly - daemon and testproxy independently reaching
# for the SAME third-party HTTP stack. This set is the mechanical guard against
# that convergence: no crate here may be reachable by BOTH components at once.
#
# Scope is deliberate. Only client/server HTTP *logic* crates are listed -
# pure-data crates (`http`, `bytes`, `url`) are the low-level sharing round 5
# permits and are NOT here. testproxy (task-2) is std-only, so it shares nothing
# today; task-4's daemon will pick one of these, which stays legal until the day
# a testproxy change reaches for the same crate - at which point this gate bites.
# Add a crate here when either component adopts it.
HTTP_STACK_CRATES: frozenset[str] = frozenset(
    {
        # server / framework
        "tiny_http",
        "tiny-http",
        "axum",
        "axum-core",
        "actix-web",
        "warp",
        "rocket",
        "hyper",
        "hyper-util",
        "h2",
        # client
        "ureq",
        "reqwest",
        "isahc",
        "curl",
        "attohttpc",
        # tower middleware stack
        "tower",
        "tower-http",
        "tower-service",
        # TLS transport stacks (TASK-24 daemon=rustls, TASK-22 testproxy=native-tls).
        # Forward-carried from TASK-24/TASK-192: the denylist above forbids shared
        # HTTP-LOGIC crates but said nothing about TLS, so nothing mechanically
        # stopped the daemon's rustls from leaking into testproxy. Deny BOTH TLS
        # stacks so the two independent wire witnesses cannot converge on one TLS
        # implementation. The daemon reaches {rustls, tokio-rustls}; testproxy
        # reaches {native-tls, openssl}; the two sets are disjoint, so no crate
        # here is reachable by both - if a future change makes one so, this bites.
        "rustls",
        "tokio-rustls",
        "native-tls",
        "openssl",
    }
)

EXIT_OK = 0
EXIT_VIOLATION = 1
EXIT_CANNOT_CHECK = 2


class CheckError(RuntimeError):
    """The check could not be performed - distinct from finding a violation."""


def cargo_metadata(directory: Path) -> dict:
    """Declared manifest data for the workspace containing `directory`.

    `--no-deps` keeps this at declaration level and, as a side effect, needs
    neither the network nor a resolved lockfile, so it runs unchanged inside
    the nix sandbox.
    """
    try:
        result = subprocess.run(
            ["cargo", "metadata", "--no-deps", "--format-version", "1"],
            cwd=directory,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as error:
        raise CheckError(f"could not run cargo in {directory}: {error}") from error
    if result.returncode != 0:
        raise CheckError(
            f"cargo metadata failed in {directory}: {result.stderr.strip()}"
        )
    return json.loads(result.stdout)


def path_linked_graph(workspace: Path) -> dict[str, set[str]]:
    """Map every reachable crate to the path-linked crates it declares.

    Every declaration counts: normal, dev and build kinds, optional
    (feature-gated) dependencies, target-specific ones, and renamed ones -
    cargo reports the real package name, so an alias cannot launder an edge.
    """
    graph: dict[str, set[str]] = {}
    pending = deque([workspace])
    visited: set[Path] = set()
    while pending:
        directory = pending.popleft().resolve()
        if directory in visited:
            continue
        visited.add(directory)
        metadata = cargo_metadata(directory)
        members = {package["name"] for package in metadata["packages"]}
        for package in metadata["packages"]:
            edges = graph.setdefault(package["name"], set())
            for dependency in package["dependencies"]:
                path = dependency.get("path")
                if path is None and dependency["name"] not in members:
                    continue
                edges.add(dependency["name"])
                if path is not None:
                    # Follow it: its own manifest may lead back to a crate the
                    # other component also uses.
                    pending.append(Path(path))
    return graph


def reachable(graph: dict[str, set[str]], start: str) -> set[str]:
    """Crates reachable from `start`, transitively."""
    seen: set[str] = set()
    queue = deque([start])
    while queue:
        for dependency in graph.get(queue.popleft(), ()):
            if dependency not in seen:
                seen.add(dependency)
                queue.append(dependency)
    return seen


def find_violations(
    workspace: Path, allowlist: frozenset[str] = ALLOWLIST
) -> list[str]:
    """Every way the two components are coupled, as readable lines."""
    graph = path_linked_graph(workspace)
    absent = [name for name in SEPARATED if name not in graph]
    if absent:
        raise CheckError(f"workspace members not found: {', '.join(absent)}")

    left, right = SEPARATED
    reach = {name: reachable(graph, name) for name in SEPARATED}

    violations = []
    if right in reach[left]:
        violations.append(f"{left} depends on {right}")
    if left in reach[right]:
        violations.append(f"{right} depends on {left}")
    # The realistic violation is not a direct edge - nobody writes
    # `daemon = { path = ... }` into testproxy. They factor out "just the HTTP
    # bit" into a crate both sides pull in, possibly several hops away.
    shared = (reach[left] & reach[right]) - allowlist - set(SEPARATED)
    violations += [
        f"{left} and {right} share crate {crate}" for crate in sorted(shared)
    ]
    return violations


def graph_from_lock(cargo_lock: Path) -> dict[str, set[str]]:
    """Build a name -> {dependency names} graph from a Cargo.lock.

    The RESOLVED graph is what the HTTP-stack check needs: it must see
    third-party crates (which the `--no-deps` manifest graph deliberately does
    not), and transitively - `axum` pulling `hyper` pulling `h2` must all be
    reachable from `daemon`. Cargo.lock lists every resolved package with its
    dependency names, needs no network, and is part of the flake source, so this
    stays offline and sandbox-safe. Dependency strings are `"name"` or
    `"name version"`; only the name matters here.
    """
    data = tomllib.loads(cargo_lock.read_text())
    graph: dict[str, set[str]] = {}
    for package in data.get("package", []):
        name = package["name"]
        edges = graph.setdefault(name, set())
        for dependency in package.get("dependencies", []):
            edges.add(dependency.split(" ", 1)[0])
    return graph


def http_convergence(
    graph: dict[str, set[str]], http_crates: frozenset[str] = HTTP_STACK_CRATES
) -> list[str]:
    """Every HTTP-stack crate reachable by BOTH separated components.

    Works on any resolved graph (a real Cargo.lock graph, or a synthetic one in
    the self-test), so the rule can be proven to bite without a cargo build.
    """
    absent = [name for name in SEPARATED if name not in graph]
    if absent:
        raise CheckError(
            f"Cargo.lock is missing workspace members: {', '.join(absent)}"
        )
    left, right = SEPARATED
    reach = {name: reachable(graph, name) for name in SEPARATED}
    shared_http = (reach[left] & reach[right]) & http_crates
    return [
        f"{left} and {right} both use HTTP stack crate {crate} "
        "(PRD round 5: no shared HTTP logic)"
        for crate in sorted(shared_http)
    ]


# (label, resolved graph, must_fail). Synthetic graphs so the check is proven to
# bite without building anything - the same discipline as SELF_TEST_CASES.
HTTP_SELF_TEST_CASES: list[tuple[str, dict[str, set[str]], bool]] = [
    (
        "std-only testproxy, hyper daemon - no convergence",
        {"daemon": {"hyper", "h2"}, "testproxy": set(), "hyper": set(), "h2": set()},
        False,
    ),
    (
        "different stacks - axum daemon, ureq testproxy",
        {
            "daemon": {"axum"},
            "testproxy": {"ureq"},
            "axum": {"hyper"},
            "hyper": set(),
            "ureq": set(),
        },
        False,
    ),
    (
        "same stack reached directly by both",
        {"daemon": {"hyper"}, "testproxy": {"hyper"}, "hyper": set()},
        True,
    ),
    (
        "same stack reached transitively by both",
        {
            "daemon": {"axum"},
            "axum": {"hyper"},
            "testproxy": {"myhelper"},
            "myhelper": {"hyper"},
            "hyper": set(),
        },
        True,
    ),
]


def http_self_test() -> list[str]:
    """Run the HTTP-convergence check against synthetic graphs."""
    failures = []
    for label, graph, must_fail in HTTP_SELF_TEST_CASES:
        violations = http_convergence(graph)
        if must_fail and not violations:
            failures.append(f"'{label}' should have been caught, was reported clean")
        elif not must_fail and violations:
            failures.append(f"'{label}' should be clean, reported {violations}")
    return failures


SHARED = '[dependencies]\nshared = { path = "../shared" }\n'

# (label, workspace members, crates outside the workspace, allowlist, must_fail).
# Synthetic rather than copies of the real crates, so the self-test keeps
# testing the checker instead of drifting with whatever the manifests grow.
SELF_TEST_CASES: list[
    tuple[str, dict[str, str], dict[str, str], frozenset[str], bool]
] = [
    ("independent members", {"daemon": "", "testproxy": ""}, {}, frozenset(), False),
    (
        "direct edge testproxy -> daemon",
        {
            "daemon": "",
            "testproxy": '[dependencies]\ndaemon = { path = "../daemon" }\n',
        },
        {},
        frozenset(),
        True,
    ),
    (
        "direct edge daemon -> testproxy",
        {
            "daemon": '[dependencies]\ntestproxy = { path = "../testproxy" }\n',
            "testproxy": "",
        },
        {},
        frozenset(),
        True,
    ),
    (
        "shared crate as a plain dependency",
        {"daemon": SHARED, "testproxy": SHARED, "shared": ""},
        {},
        frozenset(),
        True,
    ),
    (
        "shared crate behind an optional feature",
        {
            "daemon": '[dependencies]\nshared = { path = "../shared", optional = true }\n',
            "testproxy": '[dependencies]\nshared = { path = "../shared", optional = true }\n',
            "shared": "",
        },
        {},
        frozenset(),
        True,
    ),
    (
        "shared crate under target-specific dependencies",
        {
            "daemon": '[target."cfg(unix)".dependencies]\nshared = { path = "../shared" }\n',
            "testproxy": '[target."cfg(windows)".dependencies]\nshared = { path = "../shared" }\n',
            "shared": "",
        },
        {},
        frozenset(),
        True,
    ),
    (
        "shared crate reachable only as a dev-dependency",
        {
            "daemon": '[dev-dependencies]\nshared = { path = "../shared" }\n',
            "testproxy": SHARED,
            "shared": "",
        },
        {},
        frozenset(),
        True,
    ),
    (
        "shared crate reachable only as a build-dependency",
        {
            "daemon": '[build-dependencies]\nshared = { path = "../shared" }\n',
            "testproxy": SHARED,
            "shared": "",
        },
        {},
        frozenset(),
        True,
    ),
    (
        "shared crate laundered through a dependency rename",
        {
            "daemon": '[dependencies]\nwireutil = { package = "shared", path = "../shared" }\n',
            "testproxy": SHARED,
            "shared": "",
        },
        {},
        frozenset(),
        True,
    ),
    (
        "shared crate two hops away inside the workspace",
        {
            "daemon": '[dependencies]\nmiddle = { path = "../middle" }\n',
            "testproxy": SHARED,
            "middle": SHARED,
            "shared": "",
        },
        {},
        frozenset(),
        True,
    ),
    (
        "shared crate hopped through a crate OUTSIDE the workspace",
        {
            "daemon": '[dependencies]\nmiddle = { path = "../../outside/middle" }\n',
            "testproxy": '[dependencies]\nshared = { path = "../../outside/shared" }\n',
        },
        {"middle": SHARED, "shared": ""},
        frozenset(),
        True,
    ),
    (
        "allowlisted shared crate is permitted",
        {"daemon": SHARED, "testproxy": SHARED, "shared": ""},
        {},
        frozenset({"shared"}),
        False,
    ),
]


def write_crate(directory: Path, name: str, body: str, standalone: bool) -> None:
    """Materialise one crate; `standalone` makes it its own workspace root."""
    (directory / "src").mkdir(parents=True)
    (directory / "src" / "lib.rs").write_text("")
    own_workspace_table = "[workspace]\n" if standalone else ""
    (directory / "Cargo.toml").write_text(
        f'[package]\nname = "{name}"\nversion = "0.0.0"\nedition = "2024"\n'
        f"{body}{own_workspace_table}"
    )


def write_workspace(
    case: Path, members: dict[str, str], outside: dict[str, str]
) -> Path:
    """Materialise a cargo workspace plus crates deliberately outside it.

    The `outside` crates are siblings of the workspace root, not children:
    cargo auto-promotes in-tree path dependencies to members, and refuses a
    nested `[workspace]` table under a workspace root, so a crate inside the
    tree cannot be made a non-member. Returns the workspace root.
    """
    workspace = case / "workspace"
    names = ", ".join(f'"{name}"' for name in members)
    workspace.mkdir(parents=True)
    (workspace / "Cargo.toml").write_text(
        f'[workspace]\nresolver = "3"\nmembers = [{names}]\n'
    )
    for name, body in members.items():
        write_crate(workspace / name, name, body, standalone=False)
    for name, body in outside.items():
        write_crate(case / "outside" / name, name, body, standalone=True)
    return workspace


def self_test() -> list[str]:
    """Run the guard against synthetic workspaces; returns failure lines."""
    failures = []
    with tempfile.TemporaryDirectory(prefix="independence-self-test-") as scratch:
        for index, (label, members, outside, allowlist, must_fail) in enumerate(
            SELF_TEST_CASES
        ):
            root = write_workspace(Path(scratch) / f"case{index}", members, outside)
            violations = find_violations(root, allowlist)
            if must_fail and not violations:
                failures.append(
                    f"'{label}' should have been caught, was reported clean"
                )
            elif not must_fail and violations:
                failures.append(f"'{label}' should be clean, reported {violations}")
    return failures


def main() -> int:
    try:
        failures = self_test() + http_self_test()
        if failures:
            for failure in failures:
                print(
                    f"independence guard self-test FAILED: {failure}", file=sys.stderr
                )
            print(
                "the guard is not trustworthy; the real check was not run",
                file=sys.stderr,
            )
            return EXIT_CANNOT_CHECK
        violations = find_violations(Path.cwd())

        # HTTP-stack convergence: read the RESOLVED graph from Cargo.lock. Its
        # absence is not a silent pass - the rule cannot be proven, so say so.
        cargo_lock = Path.cwd() / "Cargo.lock"
        if not cargo_lock.is_file():
            raise CheckError(
                f"Cargo.lock not found at {cargo_lock}; cannot prove HTTP-stack "
                "separation (run from the workspace root)"
            )
        violations += http_convergence(graph_from_lock(cargo_lock))
    except CheckError as error:
        print(f"independence check could not run: {error}", file=sys.stderr)
        return EXIT_CANNOT_CHECK

    if violations:
        for violation in violations:
            print(f"crate independence violated: {violation}", file=sys.stderr)
        return EXIT_VIOLATION

    caught = sum(1 for case in SELF_TEST_CASES if case[4])
    http_caught = sum(1 for case in HTTP_SELF_TEST_CASES if case[2])
    print(
        f"crate independence: self-test green ({caught} bypasses caught, "
        f"{len(SELF_TEST_CASES) - caught} legitimate cases passed); "
        f"no {SEPARATED[0]}<->{SEPARATED[1]} edge and no shared crate outside the "
        f"allowlist ({len(ALLOWLIST)} entries), across declared normal/dev/build "
        "dependencies of every feature and target, following path deps out of "
        "the workspace. "
        f"HTTP-stack denylist green ({http_caught} convergences caught in self-test, "
        f"{len(HTTP_STACK_CRATES)} crates denied): no HTTP-logic crate reachable "
        "by both components in the resolved Cargo.lock graph"
    )
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
