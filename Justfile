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

# Only THIS user's podman objects and THIS project's rebuildable artifacts. Retains
# current+previous fixture generations, prunes stale worktrees, and clears cargo
# targets: cargo-sweep prunes STALE artifacts but KEEPS the current dep cache, so the
# next build is incremental (NOT cold). Set NIX_P2P_RECLAIM_MAXSIZE for an aggressive cap.
# See scripts/reclaim.sh.
# Reclaim this project's rebuildable footprint and rootless Podman objects safely.
reclaim: _python
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
#
# NON-MASKABLE (TASK-288): this recipe is a single bash block that runs EVERY
# stage even when an earlier one fails, then exits 0 iff all passed / 1 otherwise.
# `just` normally halts at the first non-zero line, so a clippy RED used to short-
# circuit the recipe and HIDE a tree-wide `ruff format --check` RED -- which rode
# past multiple "lint green" Done claims. Accumulating (not aborting) makes a green
# `just lint` provably mean every stage passed, and surfaces ALL reds in one run.
# CI's `just lint` step (.github/workflows/ci.yml) captures this exit code, so the
# gate is the recipe's real exit, not a self-report. `set +e` is deliberate: we
# capture each stage's rc and decide at the end. Do NOT add `-`/`|| true` swallowers
# and do NOT weaken any stage -- that would reintroduce the masking this fixes.
# `independence` runs first (as before, when it was a prereq) as one accumulated
# stage via `just independence`; the self-test guards still run immediately before
# their real scan so the "guard bites, then real scan passes" ordering is preserved.
# Clippy (warnings are errors), rustfmt drift, and the source-policy guards.
lint: _toolchain _python
    #!/usr/bin/env bash
    set -uo pipefail
    set +e
    fail_count=0
    summary=()
    # run "<label>" <cmd...>: execute one stage, record PASS/FAIL, never abort.
    run() {
        local label="$1"; shift
        "$@"
        local rc=$?
        if [ "${rc}" -eq 0 ]; then
            summary+=("PASS  ${label}")
        else
            summary+=("FAIL  ${label} (exit ${rc})")
            fail_count=$(( fail_count + 1 ))
        fi
    }
    run "independence (source-policy guards)" just independence
    run "clippy: workspace all-targets -D warnings" \
        cargo clippy --locked --workspace --all-targets -- -D warnings
    run "clippy: daemon evidence-fixture -D warnings" \
        cargo clippy --locked --package daemon --all-targets --features evidence-fixture -- -D warnings
    # The production Iroh patch is intentionally excluded from workspace-wide
    # upstream integration targets; lint its patched library explicitly.
    run "clippy: vendored iroh lib -D warnings" \
        cargo clippy --locked --manifest-path vendor/iroh/Cargo.toml --lib -- -D warnings
    run "rustfmt: workspace --check" cargo fmt --all --check
    run "rustfmt: vendored iroh --check" cargo fmt --manifest-path vendor/iroh/Cargo.toml -- --check
    run "ruff check: scripts" ruff check scripts
    run "ruff format --check: scripts" ruff format --check scripts
    run "check-source-guard.py" "${NIX_P2P_PYTHON}/bin/python3" scripts/check-source-guard.py
    run "check-lock-sources.py" "${NIX_P2P_PYTHON}/bin/python3" scripts/check-lock-sources.py
    # TASK-103 AC#9: the shipped libp2p discovery path must be kad-exclusive (no LAN/tracker
    # substitute). --self-test first proves the guard bites, then the real scan must pass.
    run "check-discovery-no-shortcut.py --self-test" \
        "${NIX_P2P_PYTHON}/bin/python3" scripts/check-discovery-no-shortcut.py --self-test
    run "check-discovery-no-shortcut.py (real scan)" \
        "${NIX_P2P_PYTHON}/bin/python3" scripts/check-discovery-no-shortcut.py
    # TASK-154 AC#3: the shipped kad path stays off the PUBLIC IPFS DHT and bakes in no
    # default bootstrap. --self-test proves the guard bites, then the real scan must pass.
    run "check-public-dht-isolation.py --self-test" \
        "${NIX_P2P_PYTHON}/bin/python3" scripts/check-public-dht-isolation.py --self-test
    run "check-public-dht-isolation.py (real scan)" \
        "${NIX_P2P_PYTHON}/bin/python3" scripts/check-public-dht-isolation.py
    # TASK-284 AC#5: the SHIPPED Mainline rendezvous bootstrap builds only a client — never
    # server_mode/DhtRole::Server (which would serve the public BitTorrent DHT). --self-test
    # proves the guard bites, then the real scan must pass.
    run "check-mainline-client-only.py --self-test" \
        "${NIX_P2P_PYTHON}/bin/python3" scripts/check-mainline-client-only.py --self-test
    run "check-mainline-client-only.py (real scan)" \
        "${NIX_P2P_PYTHON}/bin/python3" scripts/check-mainline-client-only.py
    # TASK-284 AC#5 SEMANTIC oracle: the vendored `mainline` client-only patch. Runs BOTH the
    # negative test (a no_adaptive node stays a client when not firewalled) AND its positive
    # control (a stock node under the identical condition DOES promote). The `adaptive` substring
    # selects exactly those two (a plain `no_adaptive` filter would miss the `stock_adaptive_...`
    # control). Reverting the `if self.no_adaptive { return; }` guard turns this stage RED.
    run "vendored mainline client-only oracle (neg + positive control)" \
        cargo test --locked --manifest-path vendor/mainline/Cargo.toml adaptive
    echo
    echo "== just lint stage summary =="
    printf '%s\n' "${summary[@]}"
    if [ "${fail_count}" -ne 0 ]; then
        echo "just lint: ${fail_count} stage(s) FAILED -- see FAIL lines above" >&2
        exit 1
    fi
    echo "just lint: all ${#summary[@]} stages passed"

# Source-policy guards: daemon/testproxy stay strictly separated (PRD round 5/6),
# link-shaping stays out of the shipped binary, and no float creeps into a gate/
# decision or serialized-integrity field (owner no-floats rule). NON-MASKABLE
# (TASK-288, same rationale as `lint`): all three guards run even if one fails, so
# one RED never hides another; exits 0 iff all passed. Also called as a `just lint`
# stage, so this is the single source of truth for the source-policy guard set.
independence: _toolchain
    #!/usr/bin/env bash
    set -uo pipefail
    set +e
    fail_count=0
    summary=()
    run() {
        local label="$1"; shift
        "$@"
        local rc=$?
        if [ "${rc}" -eq 0 ]; then
            summary+=("PASS  ${label}")
        else
            summary+=("FAIL  ${label} (exit ${rc})")
            fail_count=$(( fail_count + 1 ))
        fi
    }
    run "check-independence.py" python3 scripts/check-independence.py
    run "check_shaping_out_of_daemon.py" python3 scripts/check_shaping_out_of_daemon.py
    run "check-no-floats.py" python3 scripts/check-no-floats.py
    if [ "${fail_count}" -ne 0 ]; then
        echo "== independence stage summary =="
        printf '%s\n' "${summary[@]}"
        echo "independence: ${fail_count} guard(s) FAILED" >&2
        exit 1
    fi

# Standalone (no _toolchain prereq) because cargo-deny reads Cargo.lock directly
# and does not use the pinned rustc, and because TASK-230's CI must call this
# recipe verbatim. NOTE: `check advisories` fetches the RustSec advisory-db from
# GitHub, so this recipe needs network (fine locally and on Determinate-Nix CI).
# A non-zero exit means a real advisory/license/source violation - see the
# printed RUSTSEC IDs; do not suppress without a filed follow-up task.
# Supply-chain gate: RustSec advisories + licenses + bans + sources (deny.toml).
audit:
    cargo deny check

# CI-side mirror of the local .git/hooks/commit-msg guard (TASK-230): so a hook
# bypassed with `git commit --no-verify` is still caught on the remote. The regex
# is kept byte-identical to the hook. RANGE defaults to the tip commit; CI passes
# the push/PR range (e.g. origin/master..HEAD). Defensive by construction: if the
# base of RANGE is not a resolvable commit (shallow clone / brand-new branch /
# first CI run) it falls back to scanning HEAD alone, so it never manufactures a
# failure from a missing ref - it only fails on an actual forbidden trailer.
# Reject AI/co-author credit in every commit message in RANGE (mirrors the hook).
check-commit-msg range="HEAD~1..HEAD":
    #!/usr/bin/env bash
    set -euo pipefail
    range="{{ range }}"
    base="${range%%..*}"
    if [ -z "${range}" ] || [ "${base}" = "${range}" ] \
       || ! git rev-parse --verify --quiet "${base}^{commit}" >/dev/null 2>&1; then
        echo "check-commit-msg: base of '${range}' unresolvable; scanning HEAD only" >&2
        range=""
    fi
    if [ -n "${range}" ]; then
        shas="$(git rev-list "${range}" 2>/dev/null || true)"
    else
        shas=""
    fi
    [ -n "${shas}" ] || shas="$(git rev-parse HEAD)"
    bad=0
    while IFS= read -r sha; do
        [ -n "${sha}" ] || continue
        if git log -1 --format=%B "${sha}" \
           | grep -qiE 'co-authored-by:.*(claude|anthropic|noreply@anthropic)|generated with.*(claude|claude code)|🤖 generated'; then
            echo "commit-msg policy VIOLATION in ${sha}: AI/co-author credit is not allowed (disclose in README.md)." >&2
            bad=1
        fi
    done <<< "${shas}"
    exit "${bad}"

# Depends on the fast fixture tier because the signing and tamper assertions
# live in scripts/, not in cargo (rationale: scripts/check-fixtures.py).
# Unit and integration tests plus the fixture gate (in-process, no containers).
# measure.py --self-test unit-tests the egress validator (classify_run) and the
# provenance fail-closed path with synthetic inputs - no containers, so it runs
# in the fast tier alongside the fixture gate.
# Run the fast unit, integration, fixture, and evidence self-test suite.
test: _headroom build _python fixtures
    cargo test --locked --workspace
    # Exercise only the deterministic release-barrier regressions in vendored
    # Iroh; its upstream integration targets contact staging infrastructure.
    cargo test --locked --manifest-path vendor/iroh/Cargo.toml --lib fixed_port_
    # The evidence fixture is feature-gated out of the workspace-default suite.
    cargo test --locked --package daemon --bin iroh-node-lookup-fixture --features evidence-fixture
    "${NIX_P2P_PYTHON}/bin/python3" scripts/check-fixtures.py
    # task-53: NO --allow-missing-fixtures here. `fixtures` is a dependency of
    # this recipe, so the tree IS present; absence is a real failure and must
    # fail-CLOSED (exit 1), never soft-skip the addressed-unit byte-check.
    "${NIX_P2P_PYTHON}/bin/python3" scripts/check-golden-vectors.py --self-test
    "${NIX_P2P_PYTHON}/bin/python3" scripts/check-golden-vectors.py
    # TASK-126: the INDEPENDENT second-implementation half of the ProviderRecord /
    # ContentKey freeze - recompute the discovery key with stock blake3 derive_key and
    # re-verify the record signature with stock ed25519, against the same golden JSON
    # the Rust byte-pin test reads. A wrong recipe or a moved preimage fails here.
    "${NIX_P2P_PYTHON}/bin/python3" scripts/check-content-key-derivation.py
    # TASK-156: independently decode the additive schema-v1 libp2p tag-2 layout,
    # validate its bounded strict relay identities and signatures, and prove a
    # historical tag-0/tag-1 reader fails closed with UnknownOffer.
    "${NIX_P2P_PYTHON}/bin/python3" scripts/check-provider-record-libp2p-tag2.py
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
    # TASK-112: the Python PROPERTY tests (hypothesis) with a FIXED seed + bounded
    # examples - deterministic, so they belong in the flake-gated fast suite. The
    # Rust `prop_*` properties ran above inside `cargo test` (fixed seed by default
    # via prop_support::runner). `just prop` runs the SAME properties with a FREE
    # seed for exploration.
    "${NIX_P2P_PYTHON}/bin/python3" scripts/prop_tests.py --check

# Property tests with a FREE/random seed + many cases (EXPLORATION mode). Run
# deliberately, NOT on every cycle: `just test` runs the SAME properties with a
# FIXED seed so the fast gate stays deterministic (TASK-109/112). Rust proptest is
# seeded via daemon-core's prop_support::runner (PROPTEST_FREE_SEED); Python via
# hypothesis. Override the count with PROPTEST_CASES (Rust) / the explore profile
# (Python).
prop: _toolchain _python
    PROPTEST_FREE_SEED=1 PROPTEST_CASES="${PROPTEST_CASES:-1024}" cargo test --locked -p daemon-core prop_
    "${NIX_P2P_PYTHON}/bin/python3" scripts/prop_tests.py --explore

# BROAD/SLOW fuzz tier (TASK-282 AC#4; folds TASK-113): structured proptest fuzzers
# over the untrusted wire/parse surfaces - the multiaddr LAN-provenance classifier,
# the /nar/4 bao leaf+proof decoder, the signed provider-record decode+verify, and
# the narinfo parser. DELIBERATELY NOT a `just test`/`just lint` dependency: fuzzing
# stays out of the fast loop (TESTING.md fast/slow split). Targets are `#[ignore]`d
# so `cargo test` never runs them; here they run BOUNDED (PROPTEST_CASES cases, a
# FREE seed for exploration) under a per-target wall-clock cap, and ANY crash fails
# the recipe. cargo-fuzz is NOT used: it needs a nightly toolchain + `-Zsanitizer`,
# and the reproducibility pin (rust-toolchain.toml, TASK-113 AC#9) forbids nightly;
# proptest gives generation + SHRINKING (crash minimisation) on the pinned stable
# toolchain. On a crash, follow fuzz/README.md's triage runbook (commit the shrunk
# proptest-regressions repro + a non-ignored regression test). Raise PROPTEST_CASES
# for a deeper run - and raise FUZZ_TIMEOUT with it so a longer run is not mis-read
# as a hang. Runs each target; non-masking (reports every failure, exits 1 if any).
# Run the wire/parse fuzz targets bounded (BROAD tier, never the fast loop).
fuzz-smoke: _toolchain
    #!/usr/bin/env bash
    set -uo pipefail
    cases="${PROPTEST_CASES:-20000}"
    timeout_s="${FUZZ_TIMEOUT:-90}"
    # Build all fuzz test binaries FIRST so a cold compile is never charged to a
    # per-target timeout (which would masquerade as a fuzz hang).
    cargo test --locked --lib -p fabric-libp2p -p peer-fabric -p daemon-core --no-run || exit 1
    rc=0
    run() {
        local crate="$1" test="$2" c="$3"
        echo "== fuzz ${test} (crate ${crate}, ${c} cases, ${timeout_s}s cap) =="
        if ! PROPTEST_FREE_SEED=1 PROPTEST_CASES="${c}" timeout "${timeout_s}" \
            cargo test --locked --lib -p "${crate}" "${test}" -- --ignored --exact --nocapture; then
            echo "FUZZ FAIL: ${crate} ${test} (crash, or timeout - see above)" >&2
            rc=1
        fi
    }
    # The bao decoder does real hashing + zstd per case, so it gets a smaller budget.
    run fabric-libp2p fuzz::fuzz_multiaddr_lan_provenance "${cases}"
    run fabric-libp2p fuzz::fuzz_nar_v4_decode_verified "$(( cases / 10 ))"
    run peer-fabric   fuzz::fuzz_decode_provider_assertion "${cases}"
    run daemon-core   fuzz::fuzz_narinfo_to_raw "${cases}"
    if [ "${rc}" -eq 0 ]; then echo "fuzz-smoke: all targets OK (bounded run)"; else echo "fuzz-smoke: FAILURES above" >&2; fi
    exit "${rc}"

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

# Build and gate the opt-in 128-member wide fixture under fixtures/out-wide.
fixtures-wide: _headroom _python
    "${NIX_P2P_PYTHON}/bin/python3" scripts/gen-fixtures.py --wide
    "${NIX_P2P_PYTHON}/bin/python3" scripts/check-fixtures.py --require-tier wide

# Rebuilds every payload derivation and compares against the realised output.
# Slow by construction, so it is not in `just test` - but it is REQUIRED before
# the J2 baseline is recorded: `just test` only proves export is repeatable,
# which a nondeterministic payload would pass forever once realised.
# Prove the fixture payloads BUILD deterministically, not just export so.
fixtures-verify-rebuild: _python
    "${NIX_P2P_PYTHON}/bin/python3" scripts/check-rebuild.py

# Prove each wide member and its root rebuild identically on this host.
fixtures-wide-verify-rebuild: _headroom _python
    "${NIX_P2P_PYTHON}/bin/python3" scripts/check-rebuild.py --wide

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
#   narinfo-default-cache-offload  TASK-29: the default-on daemon narinfo cache
#                         offloads the REPEAT narinfo (0 upstream PAIRED with N
#                         served-locally), with an --no-narinfo-cache negative
#                         control that reddens the oracle - the only scenario
#                         guarding the narinfo-offload path
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
E2E_FAST := "--only s1-byte-and-counts --only narinfo-default-cache-offload --only s2-fallback --only tamper-narhash --only chain-s1-and-counts --only s6-p2p --only s9-libp2p-grow --only s10-libp2p-seed-and-grow --only libp2p-leech --only libp2p-bootstrap-outage --only libp2p-mdns-bootstrap --only libp2p-mdns-scope-isolation --only libp2p-lan-share-zeroconfig --only libp2p-lan-share-cross-host-serve --only libp2p-lan-share-isolation-bridge"

# Run the fast breadth-first e2e subset (15 scenarios) - the common pre-commit loop.
# NB: libp2p-lan-share-isolation-bridge (TASK-280 AC#4) needs rootless two-network podman
# (LAN 10.211.34.0/24 + PUBLIC 203.0.113.0/24 TEST-NET-3); validated GREEN with the scope-split
# KEY+END-TO-END system oracles proven RED-at-HEAD on revert (TASK-282 hardened its attribution).
e2e: _headroom _python fixtures-large
    "${NIX_P2P_PYTHON}/bin/python3" scripts/e2e_harness.py {{E2E_FAST}}

# Required before shipping a serving-path change: it is the only run whose green
# means what `just e2e` used to mean, since the fast subset omits the crash
# suite, the fault x depth matrix and the timeout boundary.
# Run EVERY e2e scenario (the real gate; slower than `just e2e`).
e2e-full: _headroom _python fixtures-large
    "${NIX_P2P_PYTHON}/bin/python3" scripts/e2e_harness.py

# TASK-272: mDNS + kad get_providers discovery-latency measurement (instrument, not a gate).
# Reuses the zero-bootstrap mDNS topology with RUST_LOG=info and writes integer-ms latencies +
# raw daemon logs to evidence/task-272/. See the discovery-latency section of docs/profiling.md.
# Measure discovery latency (mDNS + kad get_providers) to evidence/task-272/.
discovery-latency: _headroom _python fixtures-large
    "${NIX_P2P_PYTHON}/bin/python3" scripts/e2e_harness.py --only measure-discovery-latency

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
# daemon-libp2p. GATED proofs: the real-NAT boundary, relay reservation, kad record
# discovery, byte-identical NAR carriage through the relay, and the warm single-
# variable relay-UP succeeds / relay-DOWN circuit-unreachable load-bearing bite.
# After that bite, the same consumer also proves production upstream fallback for
# an already-raw Compression:none fixed-point URL by retrying against a runtime-
# activated NAR at the unchanged HTTP URL. Compressed-to-raw fallback remains a
# separate product gap. A PACKAGE; needs /dev/kvm.
# HEAVY (boots 6 QEMU VMs: gwa, gwb, nodea, nodeb, relay, zboot).
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

# ---- TASK-253 profiling & benchmark toolchain (INSTRUMENTATION, not the value thesis) ----
# All three recipes target the claim/hold-query WIRE CODEC (daemon-core/src/claim.rs) - the
# frozen format the PRIMARY libp2p discovery+serve path speaks (consumed by daemon-libp2p;
# NOT the deprioritized iroh path). They produce NO policy evidence, NO PRD success claim,
# and gate nothing (owner: this is TASK-253, explicitly not TASK-237). Every derived number
# they emit is an INTEGER (counts/byte totals); raw tool JSON is kept verbatim. Run cost is
# BOUNDED and documented per recipe - the box is SHARED, so none of these is a soak or a
# parallel farm. Tool choices + the perf privilege note live in docs/profiling.md.

# Benchmark the libp2p claim-wire codec two ways: (1) a criterion in-process microbench
# (per-op time estimate) and (2) a hyperfine whole-process wall-clock A/B (small vs large
# claim payload). BOUNDED: criterion sample_size=20 / 2s measure / 0.5s warmup (in the
# harness's bounded() config); hyperfine --warmup 2 --runs 10, each invocation --iters 20000.
# JSON is exported under artifacts/profiling/ for a later report layer.
# Benchmark the libp2p claim-wire codec: criterion microbench + hyperfine A/B (bounded).
bench: _toolchain
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p artifacts/profiling
    # (1) criterion microbench - in-process, statistical per-op estimate (bounded config).
    cargo bench --locked -p daemon-core --bench claim_wire
    # (2) hyperfine A/B - whole-process wall-clock, small vs large claim payload.
    cargo build --locked --release -p daemon-core --example claim_wire_load
    bin="${CARGO_TARGET_DIR:-$PWD/target}/release/examples/claim_wire_load"
    hyperfine --warmup 2 --runs 10 \
        --export-json artifacts/profiling/hyperfine-claim-wire.json \
        -n small "${bin} --iters 20000 --payload small" \
        -n large "${bin} --iters 20000 --payload large"

# CPU-attribute the libp2p claim-wire codec. PRIMARY: cargo-flamegraph (perf) - a real
# flamegraph of the release example, written to artifacts/profiling/flamegraph.svg. perf
# needs kernel.perf_event_paranoid <= 2 for the unprivileged USER-SPACE sampling this uses
# (our attribution is user-space; kernel frames need <= 1). If perf is unavailable or too
# restricted, FALL BACK to valgrind/callgrind (privilege-independent) and say so - a precise
# "perf needs X, used callgrind" is the honest outcome, never a faked flamegraph. BOUNDED:
# perf run --iters 400000 (~1-2s of samples); callgrind --iters 4000 (callgrind is ~50x slower).
# CPU-flamegraph the libp2p claim-wire codec (perf; valgrind/callgrind fallback).
profile-cpu: _toolchain
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p artifacts/profiling
    cargo build --locked --release -p daemon-core --example claim_wire_load
    bin="${CARGO_TARGET_DIR:-$PWD/target}/release/examples/claim_wire_load"
    paranoid="$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo 99)"
    use_callgrind=0
    if command -v flamegraph >/dev/null 2>&1 && [ "${paranoid}" -le 2 ]; then
        echo "profile-cpu: perf_event_paranoid=${paranoid} (<=2) -> cargo-flamegraph (user-space perf)"
        if flamegraph -o artifacts/profiling/flamegraph.svg -- "${bin}" --iters 400000 --payload large; then
            echo "profile-cpu: flamegraph -> artifacts/profiling/flamegraph.svg"
        else
            echo "profile-cpu: perf/flamegraph failed at runtime; falling back to callgrind" >&2
            use_callgrind=1
        fi
        # perf writes a multi-hundred-MB perf.data next to the CWD; drop it (the SHARED box is
        # disk-tight) - the flamegraph.svg is the kept artifact.
        rm -f perf.data perf.data.old
    else
        echo "profile-cpu: perf unavailable or perf_event_paranoid=${paranoid} (>2) -> valgrind/callgrind fallback" >&2
        use_callgrind=1
    fi
    if [ "${use_callgrind}" -eq 1 ]; then
        valgrind --tool=callgrind \
            --callgrind-out-file=artifacts/profiling/callgrind.out \
            "${bin}" --iters 4000 --payload large
        echo "profile-cpu: CPU attribution in artifacts/profiling/callgrind.out"
        echo "profile-cpu: view with 'callgrind_annotate artifacts/profiling/callgrind.out' (no flamegraph: perf sampling unavailable)"
    fi

# ALLOCATION-profile the libp2p claim-wire codec via dhat - the RAM oracle that is BETTER
# than peak RSS (it counts what the codec actually allocates, total and at-peak, not the
# process high-water mark; the existing serve-budget residency oracle is untouched). Builds
# the example with --features dhat-heap (dhat's global allocator), runs a BOUNDED --iters
# 2000 (dhat instruments every allocation, ~10-50x slower; the per-op allocation profile is
# iteration-count-independent, so a small run suffices). Prints an integer alloc summary and
# writes dhat-heap.json under artifacts/profiling/ (view at https://nnethercote.github.io/dh_view/dh_view.html).
# Allocation-profile the libp2p claim-wire codec via dhat (an oracle better than peak RSS).
profile-ram: _toolchain
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p artifacts/profiling
    cargo build --locked -p daemon-core --example claim_wire_load --features dhat-heap
    bin="${CARGO_TARGET_DIR:-$PWD/target}/debug/examples/claim_wire_load"
    # dhat writes dhat-heap.json to CWD; run inside artifacts/profiling so it lands there.
    ( cd artifacts/profiling && "${bin}" --iters 2000 --payload large )
    echo "profile-ram: allocation profile in artifacts/profiling/dhat-heap.json"
