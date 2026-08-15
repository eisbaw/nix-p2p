# Canonical gates for nix-p2p (TESTING.md "Negative feedback").
# Run these inside `nix develop`; `_toolchain` below enforces it.
# `nix flake check` runs build/lint/fmt/test/independence again inside the
# sandbox - use it for CI and to catch anything that only passes against a
# warm ./target.

# Show the available gates.
default:
    @just --list

# Refuse to run gates against anything but the pinned toolchain derivation.
_toolchain:
    #!/usr/bin/env bash
    set -euo pipefail
    : "${NIX_P2P_TOOLCHAIN:?not set - run gates inside: nix develop -c just ...}"
    # Checking every tool, not just cargo: a stray rustfmt or clippy from
    # another derivation is exactly the phantom-failure source the pinning
    # exists to prevent.
    for tool in cargo rustc cargo-clippy rustfmt; do
        resolved=$(command -v "${tool}" || true)
        case "${resolved}" in
            "${NIX_P2P_TOOLCHAIN}"/*) ;;
            *)
                echo "${tool} resolves to '${resolved:-<not found>}', not the pinned toolchain ${NIX_P2P_TOOLCHAIN}" >&2
                exit 1
                ;;
        esac
    done
    # The env var above says where the toolchain is; rust-toolchain.toml says
    # which one it must be. Checking against the file keeps the single source
    # of truth authoritative - otherwise exporting NIX_P2P_TOOLCHAIN=/nix/store
    # reinstates the weak "any cargo in the store" check this replaced.
    channel=$(sed -n 's/^channel *= *"\([^"]*\)".*/\1/p' rust-toolchain.toml)
    case "${channel}" in
        [0-9]*)
            reported=$(rustc --version)
            case "${reported}" in
                "rustc ${channel} "*) ;;
                *)
                    echo "rustc reports '${reported}' but rust-toolchain.toml pins ${channel}" >&2
                    exit 1
                    ;;
            esac
            ;;
    esac

# Refuse to start a disk-heavy recipe below NIX_P2P_MIN_FREE_GIB free (default 15
# GiB), pointing at `just reclaim`, INSTEAD of a mid-run 100%-full crash that also
# kills the shell's output capture and manufactures false gate results (TASK-54).
# The heavy recipes list this FIRST so it fires before nix/python/cargo spin up.
# Override the threshold with NIX_P2P_MIN_FREE_GIB=<gib> for tests/demos. Integer
# math only (owner no-float rule).
_headroom:
    #!/usr/bin/env bash
    set -euo pipefail
    min_gib="${NIX_P2P_MIN_FREE_GIB:-15}"
    avail=$(df -B1 --output=avail . | tail -n1 | tr -d ' ')
    avail="${avail:-0}"
    min_bytes=$(( min_gib * 1024 * 1024 * 1024 ))
    if (( avail < min_bytes )); then
        echo "DISK HEADROOM TOO LOW: $(( avail / 1024 / 1024 / 1024 )) GiB free, need ${min_gib} GiB." >&2
        echo "Run 'just reclaim' to free rebuildable artifacts + podman, then retry." >&2
        echo "(Override with NIX_P2P_MIN_FREE_GIB=<gib> only if you know the run fits.)" >&2
        exit 1
    fi

# Only THIS user's podman objects and THIS project's rebuildable artifacts - never
# another session's files. Prunes podman images/volumes/build-cache, drops
# unreferenced fixture generations, prunes stale git worktrees, and clears the cargo
# target dir(s). Reports bytes freed. The next build after this is COLD by design.
# See scripts/reclaim.sh.
# Reclaim this project's rebuildable disk footprint + podman safely (reports bytes freed).
reclaim:
    scripts/reclaim.sh

# Refuse to run the fixture gates against anything but the pinned Python.
# Without this, `${NIX_P2P_PYTHON}/bin/python3` expands to `/bin/python3`
# outside `nix develop` - which EXISTS on Debian and Ubuntu, so the run would
# reach a system Python and die with an opaque missing-cryptography traceback
# instead of saying what is actually wrong.
_python:
    #!/usr/bin/env bash
    set -euo pipefail
    : "${NIX_P2P_PYTHON:?not set - run gates inside: nix develop -c just ...}"
    : "${NIX_P2P_NIX:?not set - run gates inside: nix develop -c just ...}"
    for tool in "${NIX_P2P_PYTHON}/bin/python3" "${NIX_P2P_NIX}/bin/nix"; do
        test -x "${tool}" || { echo "${tool} is not executable" >&2; exit 1; }
    done

# Compile the whole workspace, tests and benches included.
build: _toolchain
    cargo build --locked --workspace --all-targets
    # TASK-138 keeps its adversarial authority out of production builds, so
    # compile the evidence-only feature explicitly on every normal build gate.
    cargo build --locked --package daemon --all-targets --features evidence-fixture

# scripts/ is linted too: the gate scripts are safety-critical and would
# otherwise be the only unchecked files in a repo gated at -D warnings. The
# fixture source guard runs here rather than only in `test` because it is a
# source-policy check like `independence`, and it needs no generated fixture.
# Clippy (warnings are errors), rustfmt drift, and the source-policy guards.
lint: _toolchain _python independence
    cargo clippy --locked --workspace --all-targets -- -D warnings
    cargo clippy --locked --package daemon --all-targets --features evidence-fixture -- -D warnings
    cargo fmt --all --check
    ruff check scripts
    ruff format --check scripts
    "${NIX_P2P_PYTHON}/bin/python3" scripts/check-source-guard.py
    "${NIX_P2P_PYTHON}/bin/python3" scripts/check-lock-sources.py
    # TASK-103 AC#9: the shipped libp2p discovery path must be kad-exclusive (no LAN/tracker
    # substitute). --self-test first proves the guard bites, then the real scan must pass.
    "${NIX_P2P_PYTHON}/bin/python3" scripts/check-discovery-no-shortcut.py --self-test
    "${NIX_P2P_PYTHON}/bin/python3" scripts/check-discovery-no-shortcut.py
    # TASK-154 AC#3: the shipped kad path stays off the PUBLIC IPFS DHT and bakes in no
    # default bootstrap. --self-test proves the guard bites, then the real scan must pass.
    "${NIX_P2P_PYTHON}/bin/python3" scripts/check-public-dht-isolation.py --self-test
    "${NIX_P2P_PYTHON}/bin/python3" scripts/check-public-dht-isolation.py

# Source-policy guards: daemon/testproxy stay strictly separated (PRD round 5/6),
# link-shaping stays out of the shipped binary, and no float creeps into a gate/
# decision or serialized-integrity field (owner no-floats rule).
independence: _toolchain
    python3 scripts/check-independence.py
    python3 scripts/check_shaping_out_of_daemon.py
    python3 scripts/check-no-floats.py

# Depends on the fast fixture tier because the signing and tamper assertions
# live in scripts/, not in cargo (rationale: scripts/check-fixtures.py).
# Unit and integration tests plus the fixture gate (in-process, no containers).
# measure.py --self-test unit-tests the egress validator (classify_run) and the
# provenance fail-closed path with synthetic inputs - no containers, so it runs
# in the fast tier alongside the fixture gate.
# Run the fast unit, integration, fixture, and evidence self-test suite.
test: _headroom build _python fixtures
    cargo test --locked --workspace
    # The evidence fixture is feature-gated out of the workspace-default suite.
    cargo test --locked --package daemon --bin iroh-node-lookup-fixture --features evidence-fixture
    "${NIX_P2P_PYTHON}/bin/python3" scripts/check-fixtures.py
    "${NIX_P2P_PYTHON}/bin/python3" scripts/check-golden-vectors.py
    # TASK-126: the INDEPENDENT second-implementation half of the ProviderRecord /
    # ContentKey freeze - recompute the discovery key with stock blake3 derive_key and
    # re-verify the record signature with stock ed25519, against the same golden JSON
    # the Rust byte-pin test reads. A wrong recipe or a moved preimage fails here.
    "${NIX_P2P_PYTHON}/bin/python3" scripts/check-content-key-derivation.py
    "${NIX_P2P_PYTHON}/bin/python3" scripts/measure.py --self-test
    # task-18: the S5 fitter and the sweep's honesty logic are container-free by
    # design, so the machinery that decides "is this growth superlinear" and
    # "is this number labelled as a model output" is covered on EVERY cycle -
    # not only when someone runs the slow sweep. Both prove their oracles by
    # mutation (a report stripped of its labels must be REJECTED).
    "${NIX_P2P_PYTHON}/bin/python3" scripts/scalefit.py --self-test
    "${NIX_P2P_PYTHON}/bin/python3" scripts/scale_sweep.py --self-test
    # task-137: exercise routed-publication command safety and artifact mutation bites.
    "${NIX_P2P_PYTHON}/bin/python3" scripts/iroh_node_publication_evidence.py --self-test
    "${NIX_P2P_PYTHON}/bin/python3" scripts/finalize_iroh_node_publication.py --self-test
    # task-138: query-only routed lookup command safety and artifact mutation bites.
    "${NIX_P2P_PYTHON}/bin/python3" scripts/iroh_node_lookup_evidence.py --self-test
    "${NIX_P2P_PYTHON}/bin/python3" scripts/finalize_iroh_node_lookup.py --self-test
    # task-142: routed relay-capability command safety and artifact mutation bites.
    "${NIX_P2P_PYTHON}/bin/python3" scripts/iroh_relay_capability_evidence.py --self-test
    "${NIX_P2P_PYTHON}/bin/python3" scripts/finalize_iroh_relay_capability.py --self-test
    # TASK-155: the decentralized-content-discovery-v1 finalizer's full mutation set -
    # harness/ac9 bites, WIRE-level pcap bites (mdns / multicast / external unicast /
    # truncated pcap / kernel drop / no peer transfer), and TASK-126 frozen-tree bites
    # (anchor absent / golden ContentKey drift). Container-free; every bite must fire.
    "${NIX_P2P_PYTHON}/bin/python3" scripts/decentralized_discovery_evidence.py --self-test
    # task-42: the profiler's unit gate (NarSize vs FileSize can never share an
    # unlabelled `_bytes` key), its S9 class-recovery bite (a known-O(n^2) law is
    # NEVER fitted linear), the disk walk and the arm scoring are all
    # container-free, so the honesty machinery is covered on EVERY cycle. Every
    # rule is proven by mutation.
    "${NIX_P2P_PYTHON}/bin/python3" scripts/profile_p2p.py --self-test
    # task-49: real nix accepts the daemon's rewritten narinfo + raw nar
    # (none/xz/zstd) and rejects a signed-field mutation. Needs the `daemon`
    # binary (hence the `build` dep) and the fast-tier fixtures.
    "${NIX_P2P_PYTHON}/bin/python3" scripts/check-rewrite-realnix.py

# Regenerate the signed fixture cache - fast tier (none/xz/zstd, <1 MiB).
fixtures: _python
    "${NIX_P2P_PYTHON}/bin/python3" scripts/gen-fixtures.py

# The slow-tier counterpart of `just test`: deliberately not a `just test`
# dependency and not a flake check, because the payload must stay out of the
# fast loop and out of the devshell closure - but the 110 MiB path still has
# to be verified by something, so this recipe gates it rather than only
# building it.
# Regenerate and verify the fixture cache including the 110 MiB payload.
fixtures-large: _python
    "${NIX_P2P_PYTHON}/bin/python3" scripts/gen-fixtures.py --large
    "${NIX_P2P_PYTHON}/bin/python3" scripts/check-fixtures.py --require-tier full

# Rebuilds every payload derivation and compares against the realised output.
# Slow by construction, so it is not in `just test` - but it is REQUIRED before
# the J2 baseline is recorded: `just test` only proves export is repeatable,
# which a nondeterministic payload would pass forever once realised.
# Prove the fixture payloads BUILD deterministically, not just export so.
fixtures-verify-rebuild: _python
    "${NIX_P2P_PYTHON}/bin/python3" scripts/check-rebuild.py

# A Nix binary cache is static files, so any file server does; the containers
# in task-5 serve the same tree their own way. Served through `current`, the
# published-generation symlink every consumer resolves - never a generation
# directly, which would go stale the moment the fixture is regenerated.
# Serve the fixture cache as a mock upstream on 127.0.0.1.
fixtures-serve port="8080": _python
    "${NIX_P2P_PYTHON}/bin/python3" -m http.server --bind 127.0.0.1 --directory fixtures/out/current/cache {{ port }}

# Apply rustfmt in place; `just lint` is what enforces it.
fmt: _toolchain
    cargo fmt --all

# Build the flake packages that container images and the NixOS module consume.
package:
    nix build --no-link --print-out-paths .#daemon .#testproxy

# The e2e gate (task-5): rootless-podman-pod scenario runner driving
# client(real nix) -> daemon -> testproxy -> mock-origin, asserting the
# TESTING.md oracles. Depends on the full-tier fixtures (the 110 MiB payload is
# part of S1's byte/egress oracles) and on the fail-closed check-fixtures gate,
# which the harness itself invokes before serving anything. SLOW tier: container
# runs are minutes, deliberately out of the fast `build lint test` loop.
#
# ONE BREADTH-FIRST SCENARIO PER DISTINCT PATH, not a random sample. Each entry
# below is here because NOTHING ELSE in the fast set covers its path, so dropping
# any one of them makes a whole capability unguarded in the common loop:
#   s1-byte-and-counts    the core S1 acceptance signal - byte identity + the
#                         upstream-hit counts every other oracle is paired against
#   s2-fallback           daemon down -> nix still resolves (the additive invariant)
#   tamper-narhash        THE SAFETY BITE. Deliberately kept in the fast set: it
#                         proves nix REJECTS mutated content, and a fast gate that
#                         cannot catch a verification regression is the one gap
#                         worth paying seconds for.
#   chain-s1-and-counts   depth-3 composition - proves the daemon composes with
#                         itself, which single-hop scenarios cannot show
#   s6-p2p                the wave-2 peer-served-NAR acceptance signal
#
# NOT covered here, and the reason `e2e-full` still exists as the real gate: the
# crash suite (6 scenarios), the 7-fault x depth matrix, the timeout boundary,
# and the remaining tamper/s6 variants. Those are where regressions HIDE, so
# `e2e-full` is what must pass before a commit that touches the serving path.
#
# MEASURED 2026-08-10 (the harness prints per-scenario seconds, so this is data
# and not an impression): full 26 scenarios = 439.2s; this subset = 83.3s, about
# a 5x cut, 1m41s wall including fixtures and preflight.
# Two things that measurement CORRECTED, recorded so the next person tuning this
# list does not repeat them:
#   * fault-depth-matrix is NOT the long pole. It runs 29 checks in 11.8s because
#     it reuses one pod. The expensive scenarios are the ones that wait on real
#     process death: chain-kill-middle-daemon 37.3s, crash-kill-mid-nar 32.6s,
#     crash-sigstop-stall 28.9s, chain-timeout-boundary 26.0s.
#   * There is a ~11s floor per scenario (pod setup), so the COUNT of scenarios
#     dominates the cost far more than which ones are chosen. Adding a sixth
#     "cheap" scenario here costs ~11s, not ~1s.
E2E_FAST := "--only s1-byte-and-counts --only s2-fallback --only tamper-narhash --only chain-s1-and-counts --only s6-p2p"

# Run the fast breadth-first e2e subset (5 scenarios) - the common pre-commit loop.
e2e: _headroom _python fixtures-large
    "${NIX_P2P_PYTHON}/bin/python3" scripts/e2e_harness.py {{E2E_FAST}}

# Required before shipping a serving-path change: it is the only run whose green
# means what `just e2e` used to mean, since the fast subset omits the crash
# suite, the fault x depth matrix and the timeout boundary.
# Run EVERY e2e scenario (the real gate; slower than `just e2e`).
e2e-full: _headroom _python fixtures-large
    "${NIX_P2P_PYTHON}/bin/python3" scripts/e2e_harness.py

# Scoped to the harness's own label - never the fixture tree. Also the manual
# counterpart of the Ctrl-C leak trap. Beyond pods/containers/networks it also
# prunes dangling podman images and unused volumes (TASK-54 AC#1) - the leftovers
# a bare `pod rm` leaves behind. For a deeper reclaim (cargo target, fixtures,
# build cache) use `just reclaim`.
# Tear down every pod/container/network the e2e harness created + prune dangling images/volumes.
e2e-clean:
    "${NIX_P2P_PYTHON}/bin/python3" scripts/e2e_harness.py --clean

# The NixOS VM truth layer (task-10): real nix-daemon + systemd + the NixOS
# module. Builds ONE dedicated flake package (packages.x86_64-linux.vm-test),
# NOT a flake check - a VM test under `checks` would make `nix flake check` and
# the devshell boot QEMU (task-1 codex finding 4), so it is invoked directly
# here and only here. Proves S1 byte-identity through the daemon, S2 fallback
# with the daemon stopped, and the module's daemon-off additive invariant.
# SLOW tier: boots three QEMU VMs, needs /dev/kvm; minutes, not seconds.
# Run the NixOS VM test (real nix-daemon + systemd).
e2e-vm:
    nix build -L --no-link .#vm-test

# The NAT-traversal VM truth layer (TASK-207): two NixOS VMs EACH behind its OWN
# NAT + a public circuit-v2 relay, driving the shipped services.nix-p2p module +
# daemon-libp2p. GATED proofs: the real-NAT boundary (direct dial blocked), the
# relay RESERVATION over real NAT, and that the relay is load-bearing (remove it ->
# no reservation). Discovery over NAT + the end-to-end byte fetch are NON-GATING
# evidence (documented residual TASK-218: the circuit dial-address does not resolve
# via kad peer-routing). Like e2e-vm it is a PACKAGE, not a check; needs /dev/kvm.
# HEAVY (boots 5 QEMU VMs).
# Run the NAT-traversal NixOS VM test (relay circuit-v2 over real NAT).
e2e-nat-vm: _headroom
    nix build -L --no-link .#nat-vm-test

# The S3/S4 measurement instrument (task-9): runs an identical scripted workload
# with-daemon vs without-daemon over the task-5 Pod seam and emits a
# machine-readable egress + p95 + gap-histogram report, with each oracle proven
# to bite by mutation. The counting rule it freezes lives next to the code in
# scripts/MEASUREMENT_COUNTING_RULE.md. Full-tier fixtures + the fail-closed
# check-fixtures gate (via the harness). SLOW tier: container runs are minutes.
# WAVE-1 SCOPE: this measures the INSTRUMENT (offload is ~0 with no p2p yet).
# Run the egress/latency/gap measurement and emit the report (S3/S4).
measure *ARGS: _headroom _python fixtures-large
    "${NIX_P2P_PYTHON}/bin/python3" scripts/measure.py {{ ARGS }}

# The S5 scale-sweep instrument (task-18): runs the real system at N over the
# axes that exist - concurrent clients, proxy-chain depth, and the client
# concurrency knobs {1,16,128} - samples per-node peak RSS (VmHWM), fds and
# latency, fits O(1)/O(log n)/O(n)/O(n log n)/O(n^2) via scripts/scalefit.py and
# extrapolates to 10/100/1000 with confidence intervals. Every extrapolated
# number is structurally labelled a model output and a superlinear fit is a RED
# FLAG printed first; the honesty rules are asserted, and a violating report
# fails the run. Each point is run 3x (--repeats) and the replicates are fitted
# as separate observations: single-draw sweeps picked a DIFFERENT growth class
# for the same metric on consecutive runs. SLOW tier: ~12 minutes of container
# runs at the default grid (the fast-tier half is the --self-test wired into
# `just test`). Cleans up label-scoped, like `e2e-clean`, on exit and SIGTERM.
# Run the S5 scale sweep and emit the fitted/extrapolated report.
scale-sweep *ARGS: _headroom _python fixtures-large
    "${NIX_P2P_PYTHON}/bin/python3" scripts/scale_sweep.py {{ ARGS }}

# The owner-goal profiling instrument (task-42): RAM / disk / latency /
# throughput / speedup over the p2p testbed. Two arms. (1) A real SWARM of n
# holder peers (n+1 daemon processes in one pod, each an iroh provider) swept
# over 1,2,4,8,16 - the peer axis with REAL points, since two nodes cannot
# discriminate O(n) from O(n log n) - fitted by scripts/scalefit.py and
# extrapolated to 10/100/1000 as labelled MODEL OUTPUT. (2) A peers-ON vs
# peers-OFF speedup arm scored by the FROZEN counting rule (net-upstream-egress-v2,
# via measure.classify_run), over the 110 MiB payload so throughput is a real
# number. Every `*_bytes` key carries its unit - NarSize and FileSize are
# different units and the report refuses to name either one plain `_bytes`.
# (3) The task-65 SIZE and CONCURRENCY axes (scripts/sizeaxis.py): peak RSS
# against the SIZE of what a node holds and serves, over >= 5 distinct NAR sizes,
# fitted to a SLOPE WITH A CONFIDENCE INTERVAL for the holder and the fetcher
# separately - the axis TASK-61/TASK-62 gate their RSS criteria on, since a slope
# tested at one size is unfalsifiable. Plus k overlapping serves whose overlap is
# MEASURED at the holder (a point whose measured overlap is not k is INVALID), and
# a residency oracle that is NOT peak RSS: what the holder's blob store says it
# HOLDS. Its payloads are synthesised into a scratch cache and deleted with it.
# Full-tier fixtures + the fail-closed check-fixtures gate. SLOW tier: ~45
# minutes of container runs at the default grid (the fast-tier half is the
# --self-test wired into `just test`, which now covers sizeaxis too). Use
# `--skip-size` / `--skip-speedup` for a dev loop. Label-scoped cleanup on exit
# and SIGTERM.
# Do NOT run this concurrently with `e2e`/`measure`/`scale-sweep`: they share one
# podman label and would tear down each other's pods mid-run (TASK-58).
# Run the p2p profile (RAM/disk/latency/throughput/speedup) and emit the report.
profile *ARGS: _headroom _python fixtures-large
    "${NIX_P2P_PYTHON}/bin/python3" scripts/profile_p2p.py {{ ARGS }}

# The task-91 closure-discovery arm of the profiler, ALONE. It is the profiler's
# only container-free arm - production still wires InMemoryDiscovery from config,
# so there is no peer-probing container path to run it over - which is why it does
# NOT depend on `fixtures-large` the way `profile` does. ~1 minute: it measures
# what finding the holders of a 200-path closure costs, one-at-a-time vs batched,
# at 0 ms and at the profiler's WAN RTT. Non-zero exit if the arm is INVALID.
# Measure closure-discovery cost, batched vs one-at-a-time (task-91).
discovery: _toolchain _python
    "${NIX_P2P_PYTHON}/bin/python3" scripts/profile_p2p.py --discovery-only

# The TASK-206 shaped-libp2p connectivity proof: runs the REAL libp2p
# discover->fetch->serve between two swarm nodes whose kad/stream traffic
# traverses a `tc netem`-shaped veth pair (real RTT + bandwidth cap), and proves
# the fetched NAR is BYTE-IDENTICAL + BLAKE3-verified over that shaped link - not
# secretly loopback. Reuses the TASK-70 netns/veth/tc substrate and the proven
# `shaped_link.assert_shaping` oracle (injected RTT recovered, fetch throughput
# near the cap, UNSHAPED negative control measurably faster). All shaping stays on
# the measurement surface (check_shaping_out_of_daemon green). Needs userns caps
# (`unshare -Urn`). `--self-test` runs the hermetic parse/verdict biting checks.
# Run the shaped-libp2p connectivity proof (TASK-206).
shaped-libp2p *ARGS: _toolchain _python
    cargo build --locked -p fabric-libp2p --example shaped_probe
    "${NIX_P2P_PYTHON}/bin/python3" scripts/shaped_libp2p.py {{ ARGS }}

# The TASK-209 shaped-kad-DISCOVERY proof + RTT sweep: extends shaped-libp2p from 2
# nodes to a 3-node kad topology (bootstrap B + provider P in ns A; consumer C in
# ns B) so the DISCOVER half - kad `get_providers` + peer-routing `get_closest_peers`
# - ALSO crosses the shaped veth, not just the fetch. C knows ONLY the bootstrap and
# resolves the provider purely through the DHT (AC#9), then fetches BYTE-IDENTICAL.
# Reuses the same netns/veth/tc substrate and the proven `shaped_link.assert_shaping`
# oracle. `--sweep` sweeps the injected one-way delay to find the RTT at which kad
# discovery misses its 10s query_timeout; `--self-test` runs the hermetic mutation
# checks. Needs userns caps (`unshare -Urn`).
# Run the shaped-kad-discovery proof / RTT sweep (TASK-209).
shaped-kad *ARGS: _toolchain _python
    cargo build --locked -p fabric-libp2p --example shaped_kad_probe
    "${NIX_P2P_PYTHON}/bin/python3" scripts/shaped_kad.py {{ ARGS }}

# The task-64 transport decomposition: a layered loopback throughput bench
# (memcpy / TCP / raw UDP / raw QUIC / iroh-blobs / the product's own fetch)
# that attributes the peer-path per-byte cost to a LAYER, so "iroh is slow" is
# replaced by a number per layer. RELEASE on purpose: a debug build measures
# rustc, not iroh. No containers and no fixtures - it synthesises its payload -
# so it runs in ~3 minutes anywhere. NOT a gate: it prints numbers and asserts
# only that each arm really moved the bytes. A throughput THRESHOLD on a shared
# host would be a flake, not an oracle.
# Decompose the iroh peer-path throughput by layer (task-64).
iroh-bench: _toolchain
    cargo run --locked --release --example iroh_throughput

# Reuses the e2e Pod seam (scripts/e2e_harness.py) as its driver and asserts the
# two operator oracles - the daemon's per-substitution log story (AC#1) and the
# fallback-served-by-request-counts proof (AC#2) - then emits its FRICTION
# manifest. Full-tier fixtures + the e2e image, so it shares e2e's SLOW tier and
# fail-closed preflight gate.
# J1 operator journey (task-6): substitute through the daemon, then lose it.
journey: _headroom _python fixtures-large
    "${NIX_P2P_PYTHON}/bin/python3" scripts/journey.py

# Capture isolated routed Iroh node-publication evidence with an immutable image.
iroh-publication-evidence image output="artifacts/iroh-publication" *ARGS: _python
    "${NIX_P2P_PYTHON}/bin/python3" scripts/iroh_node_publication_evidence.py --image {{ quote(image) }} --output {{ quote(output) }} {{ ARGS }}

# Finalize one passing raw publication run against its reviewed implementation commit.
iroh-publication-artifact raw_run implementation_commit output="artifacts/iroh-node-publication-v1.json" *ARGS: _python
    "${NIX_P2P_PYTHON}/bin/python3" scripts/finalize_iroh_node_publication.py --raw-run {{ quote(raw_run) }} --implementation-commit {{ quote(implementation_commit) }} --output {{ quote(output) }} {{ ARGS }}

# Capture isolated routed Iroh NodeId-lookup evidence with an immutable image.
iroh-lookup-evidence image output="artifacts/iroh-lookup" *ARGS: _python
    "${NIX_P2P_PYTHON}/bin/python3" scripts/iroh_node_lookup_evidence.py --image {{ quote(image) }} --output {{ quote(output) }} {{ ARGS }}

# Finalize one passing raw lookup run against its reviewed implementation commit.
iroh-lookup-artifact raw_run implementation_commit output="artifacts/iroh-node-lookup-v1.json" *ARGS: _python
    "${NIX_P2P_PYTHON}/bin/python3" scripts/finalize_iroh_node_lookup.py --raw-run {{ quote(raw_run) }} --implementation-commit {{ quote(implementation_commit) }} --output {{ quote(output) }} {{ ARGS }}

# Capture isolated routed Iroh relay-capability evidence with an immutable image.
iroh-relay-evidence image output="artifacts/iroh-relay" *ARGS: _python
    "${NIX_P2P_PYTHON}/bin/python3" scripts/iroh_relay_capability_evidence.py --image {{ quote(image) }} --output {{ quote(output) }} {{ ARGS }}

# Finalize one passing raw relay-capability run against its reviewed implementation commit.
iroh-relay-artifact raw_run implementation_commit output="artifacts/iroh-relay-capability-v1.json" *ARGS: _python
    "${NIX_P2P_PYTHON}/bin/python3" scripts/finalize_iroh_relay_capability.py --raw-run {{ quote(raw_run) }} --implementation-commit {{ quote(implementation_commit) }} --output {{ quote(output) }} {{ ARGS }}

# TASK-155: capture the decentralized-content-discovery-v1 evidence (runs the s7-libp2p
# arms + AC#9 guard + TASK-126 anchor, and captures the s7 pod netns to a pcap). Needs
# rootless podman + host tcpdump/nsenter; writes raw captures ONLY (no verdict).
discovery-evidence-capture out="artifacts/decentralized-content-discovery": _python
    "${NIX_P2P_PYTHON}/bin/python3" scripts/decentralized_discovery_evidence.py --capture --out {{ quote(out) }}

# Finalize the captured discovery evidence: re-derive the verdict from the raw captures
# (recount checks, reparse the pcap, re-check the frozen golden) and write the tracked
# artifacts/decentralized-content-discovery-v1.json. Fails closed.
discovery-evidence-finalize out="artifacts/decentralized-content-discovery": _python
    "${NIX_P2P_PYTHON}/bin/python3" scripts/decentralized_discovery_evidence.py --finalize --out {{ quote(out) }}

# Re-verify the tracked discovery artifact against its on-disk raw captures (hash match).
discovery-evidence-verify out="artifacts/decentralized-content-discovery": _python
    "${NIX_P2P_PYTHON}/bin/python3" scripts/decentralized_discovery_evidence.py --verify --out {{ quote(out) }}
