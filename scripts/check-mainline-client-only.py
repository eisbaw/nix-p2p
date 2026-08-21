#!/usr/bin/env python3
"""TASK-284 AC#5 (client-only): the SHIPPED Mainline rendezvous bootstrap path never
builds a SERVING Mainline node.

The security fix has two halves. The SEMANTIC, mutation-provable half lives in the
vendored crate: `mainline`'s `no_adaptive` flag disables stock v8's adaptive
promotion, pinned by `no_adaptive_client_never_promotes_when_not_firewalled` in
`vendor/mainline/src/rpc.rs` (revert the guard -> RED). THIS script is the cheap
SECONDARY source lint that keeps the SHIPPED wiring honest: the one file that spawns
the Mainline node on the product path — `daemon-libp2p/src/mainline_bootstrap.rs` —
must only ever build a `DhtRole::Client`, never request `server_mode()` and never
name `DhtRole::Server`. If a future edit re-enabled serving on the shipped path
(directly `server_mode()`, or by switching the role to `DhtRole::Server`), the node
would start answering — and adaptively serving — the PUBLIC BitTorrent DHT, exactly
the AC#5 / TASK-258 privacy violation the vendored patch exists to prevent.

It is a SIBLING to `check-public-dht-isolation.py` (which governs the kad DHT path)
and `check-discovery-no-shortcut.py` (which forbids non-kad content-discovery
substitutes). Disjoint invariants, disjoint guards.

Two kinds of check, over the governed file:

  FORBIDDEN (a mutation ADDING any of these in CODE bites): `server_mode` and
  `DhtRole::Server`. Matched over COMMENT-STRIPPED source, because the honest module
  doc deliberately DISCUSSES `server_mode`/`DhtRole::Server` to explain why the
  client path avoids them — a raw-text scan would false-positive on that prose. The
  comment stripper (shared shape with the isolation guard) preserves string literals,
  so a `server_mode` smuggled into a string still bites.

  POSITIVE (removing it bites): the governed file MUST still build a
  `DhtRole::Client` in real code. This proves the scan is exercising the real wiring
  and not an empty/renamed file — a guard that scans nothing proves nothing
  ("oracle must bite by mutation").

Limits, stated plainly: like its siblings this is a dependency-free substring scan
over comment-stripped Rust, not a lexer or an adversarial proof. It catches the
accidental / straightforward re-enablement (`.server_mode()`, `DhtRole::Server`) at
lint time; a determined obfuscation (an aliased constant, a runtime-selected role,
or simply deleting this guard) is out of scope — that is what the vendored semantic
oracle is for. It governs ONLY the shipped bootstrap file; `mainline-rendezvous`
itself legitimately retains a `DhtRole::Server` path for the hermetic e2e bootstrap
node, which is NOT part of any shipped daemon.

Usage: check-mainline-client-only.py [--self-test] [FILE ...]
Exit codes: 0 clean, 1 a serving-mode enabler is present OR the client wiring is
missing, 2 nothing was scanned so nothing was proven.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

# The ONE shipped-product file that spawns the Mainline rendezvous node. The
# `mainline-rendezvous` crate's own `build_node` keeps a `DhtRole::Server` arm for the
# hermetic e2e bootstrap node, so it is deliberately NOT governed here — only the
# daemon-side wiring that runs on a real user's node is.
DEFAULT_TARGETS = ("daemon-libp2p/src/mainline_bootstrap.rs",)

# Tokens that mean "this file can make the shipped node SERVE the public DHT". Matched
# over comment-stripped CODE. `server_mode` covers `.server_mode()` and the config
# field; `DhtRole::Server` covers selecting the serving role.
FORBIDDEN = {
    "server_mode": (
        "the shipped Mainline rendezvous node must never request server mode — a serving "
        "node answers (and adaptively serves) the PUBLIC BitTorrent DHT (AC#5 / TASK-258)"
    ),
    "DhtRole::Server": (
        "the shipped path must build a client, never DhtRole::Server (that role exists only "
        "for the hermetic e2e bootstrap node, never a real nix-p2p node)"
    ),
}

# The positive invariant: the governed file must still wire a client. Removing it means
# the file no longer builds the client-only node this guard is asserting about.
REQUIRED_CODE_MARKER = "DhtRole::Client"

# MED-6: the LOAD-BEARING wiring call. `mainline_rendezvous::build_node`'s `DhtRole::Client`
# arm must call `.no_adaptive()` — that call, and only that call, activates the vendored
# client-only patch on the shipped path. Deleting it survives the FORBIDDEN scan above (a
# different file) and the vendored semantic oracle (which sets `Config::no_adaptive` directly,
# bypassing `build_node`), silently restoring the original security HIGH. So the wrapper is
# governed SEPARATELY: it must contain both the client role and the `no_adaptive(` call in real
# code. It is NOT subject to the FORBIDDEN scan, because its `DhtRole::Server` arm legitimately
# calls `server_mode()` for the hermetic e2e bootstrap node.
WIRING_TARGETS = ("mainline-rendezvous/src/lib.rs",)
# Both must be present in comment-stripped code: the client role AND the activating call.
WIRING_REQUIRED_MARKERS = ("DhtRole::Client", "no_adaptive(")


def strip_comments(text: str) -> str:
    """Rust line (`//`, `///`, `//!`) and block (`/* */`, nested) comments -> a single
    space, PRESERVING string/char literals (so a token hidden in a string still bites).
    A small hand state machine, not a Rust lexer (the guard's stated limit); shared
    shape with check-public-dht-isolation.py.
    """
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        # Raw string: r"..." / r#"..."# (verbatim; may contain // and ")
        if c == "r" and (nxt == '"' or nxt == "#"):
            j = i + 1
            hashes = 0
            while j < n and text[j] == "#":
                hashes += 1
                j += 1
            if j < n and text[j] == '"':
                j += 1
                closer = '"' + "#" * hashes
                end = text.find(closer, j)
                end = n if end == -1 else end + len(closer)
                out.append(text[i:end])
                i = end
                continue
            out.append(c)
            i += 1
            continue
        # Ordinary string literal
        if c == '"':
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == '"':
                    j += 1
                    break
                j += 1
            out.append(text[i:j])
            i = j
            continue
        # Char literal (kept short so a lifetime tick `'a` is left alone)
        if c == "'":
            if nxt == "\\" and i + 3 < n and text[i + 3] == "'":
                out.append(text[i : i + 4])
                i += 4
                continue
            if nxt != "\\" and i + 2 < n and text[i + 2] == "'":
                out.append(text[i : i + 3])
                i += 3
                continue
            out.append(c)
            i += 1
            continue
        # Line comment
        if c == "/" and nxt == "/":
            j = text.find("\n", i)
            j = n if j == -1 else j
            out.append(" ")
            i = j
            continue
        # Block comment (nested-aware)
        if c == "/" and nxt == "*":
            depth = 1
            j = i + 2
            while j < n and depth > 0:
                if text[j] == "/" and j + 1 < n and text[j + 1] == "*":
                    depth += 1
                    j += 2
                elif text[j] == "*" and j + 1 < n and text[j + 1] == "/":
                    depth -= 1
                    j += 2
                else:
                    j += 1
            out.append(" ")
            i = j
            continue
        out.append(c)
        i += 1
    return "".join(out)


def scan_file(path: Path) -> tuple[list[str], bool]:
    """Return (violations, has_required_marker) for one file over comment-stripped code."""
    violations: list[str] = []
    try:
        raw = path.read_text()
    except (UnicodeDecodeError, OSError) as exc:
        return ([f"{path}: cannot be scanned ({exc})"], False)
    code = strip_comments(raw)
    for needle, reason in FORBIDDEN.items():
        if needle in code:
            violations.append(f"{path}: contains {needle!r} in code — {reason}")
    return (violations, REQUIRED_CODE_MARKER in code)


def scan(targets: list[Path]) -> tuple[list[str], int, bool]:
    """Return (violations, files_scanned, any_required_marker)."""
    violations: list[str] = []
    scanned = 0
    any_marker = False
    for path in targets:
        if not path.exists():
            violations.append(
                f"{path}: governed file is missing — the shipped Mainline "
                f"rendezvous wiring must exist for this guard to prove anything"
            )
            continue
        scanned += 1
        file_violations, has_marker = scan_file(path)
        violations.extend(file_violations)
        any_marker = any_marker or has_marker
    return (violations, scanned, any_marker)


def scan_wiring(targets: list[Path]) -> tuple[list[str], int]:
    """Return (violations, files_scanned) for the wrapper wiring: each target must
    contain every `WIRING_REQUIRED_MARKERS` token in comment-stripped CODE (the client
    role and the load-bearing `.no_adaptive()` call). NO forbidden scan here — the wrapper
    legitimately calls `server_mode()` in its `DhtRole::Server` arm."""
    violations: list[str] = []
    scanned = 0
    for path in targets:
        if not path.exists():
            violations.append(
                f"{path}: wiring file is missing — the load-bearing `.no_adaptive()` call "
                f"cannot be verified"
            )
            continue
        scanned += 1
        try:
            code = strip_comments(path.read_text())
        except (UnicodeDecodeError, OSError) as exc:
            violations.append(f"{path}: cannot be scanned ({exc})")
            continue
        for marker in WIRING_REQUIRED_MARKERS:
            if marker not in code:
                violations.append(
                    f"{path}: missing {marker!r} in code — build_node's DhtRole::Client arm "
                    f"must call `.no_adaptive()` (the vendored client-only patch's activation "
                    f"on the shipped path); deleting it silently restores the security HIGH"
                )
    return (violations, scanned)


def run(targets: list[Path], wiring_targets: list[Path] | None = None) -> int:
    wiring_targets = [] if wiring_targets is None else wiring_targets
    violations, scanned, any_marker = scan(targets)
    if scanned and not any_marker:
        violations.append(
            "positive invariant missing: no governed file builds a "
            f"{REQUIRED_CODE_MARKER!r} in code — the shipped client-only wiring is gone "
            "(a guard that scans nothing proves nothing)"
        )
    wiring_violations, wiring_scanned = scan_wiring(wiring_targets)
    violations.extend(wiring_violations)
    total_scanned = scanned + wiring_scanned
    if total_scanned == 0:
        print(
            "check-mainline-client-only: FAIL — nothing scanned, nothing proven",
            file=sys.stderr,
        )
        return 2
    if violations:
        print("check-mainline-client-only: FAIL", file=sys.stderr)
        for v in violations:
            print(f"  - {v}", file=sys.stderr)
        return 1
    print(
        f"check-mainline-client-only: OK ({total_scanned} file(s): shipped bootstrap is "
        f"client-only and the wrapper wires .no_adaptive())"
    )
    return 0


CLEAN = """\
//! The shipped node builds a DhtRole::Client — never server_mode()/DhtRole::Server.
//! (This very comment names server_mode and DhtRole::Server to EXPLAIN the invariant;
//! comment-stripping means that prose must not trip the guard.)
fn spawn() {
    let dht = build_node(DhtRole::Client, &bootstrap, Ipv4Addr::UNSPECIFIED, 0);
    let _ = dht;
}
"""

MUT_SERVER_MODE = """\
fn spawn() {
    let mut builder = Dht::builder();
    builder.server_mode();
    let dht = build_node(DhtRole::Client, &bootstrap, Ipv4Addr::UNSPECIFIED, 0);
    let _ = dht;
}
"""

MUT_SERVER_ROLE = """\
fn spawn() {
    let dht = build_node(DhtRole::Server, &bootstrap, Ipv4Addr::UNSPECIFIED, 0);
    let _ = dht;
}
"""

MUT_NO_CLIENT = """\
//! The client wiring was deleted; only the comment mentioning DhtRole::Client remains.
fn spawn() {
    do_something_else();
}
"""

SERVER_MODE_ONLY_IN_COMMENT = """\
//! We never call server_mode() and never use DhtRole::Server on the shipped path.
/* server_mode DhtRole::Server — both only ever discussed, never invoked. */
fn spawn() {
    let dht = build_node(DhtRole::Client, &bootstrap, Ipv4Addr::UNSPECIFIED, 0);
    let _ = dht;
}
"""


# --- MED-6 wrapper-wiring synthetic cases (build_node shape) ---
WIRING_CLEAN = """\
fn build_node(role: DhtRole) {
    match role {
        // The Server arm legitimately calls server_mode() — the wrapper is NOT forbidden-scanned.
        DhtRole::Server => { builder.server_mode(); }
        DhtRole::Client => { builder.no_adaptive(); }
    }
}
"""

WIRING_NO_ADAPTIVE_DELETED = """\
fn build_node(role: DhtRole) {
    // The load-bearing call was deleted; only this comment still mentions no_adaptive().
    match role {
        DhtRole::Server => { builder.server_mode(); }
        DhtRole::Client => { /* nothing — regressed */ }
    }
}
"""


def self_test() -> int:
    """Prove the guard bites. Bootstrap arm: a clean shipped-shape file PASSES; each
    serving-mode mutation and the removed-client mutation FAIL; server_mode named only in a
    comment PASSES (comment-stripping is load-bearing). Wiring arm (MED-6): a build_node that
    calls `.no_adaptive()` PASSES; deleting that call FAILS.
    """
    # (label, content, want_exit, kind): kind selects which governed rule the case exercises.
    cases: list[tuple[str, str, int, str]] = [
        ("clean client-only wiring", CLEAN, 0, "bootstrap"),
        (
            "mutation: builder.server_mode() added in code",
            MUT_SERVER_MODE,
            1,
            "bootstrap",
        ),
        ("mutation: DhtRole::Server selected in code", MUT_SERVER_ROLE, 1, "bootstrap"),
        (
            "mutation: client wiring removed (positive invariant)",
            MUT_NO_CLIENT,
            1,
            "bootstrap",
        ),
        (
            "server_mode/DhtRole::Server only in comments (must NOT trip)",
            SERVER_MODE_ONLY_IN_COMMENT,
            0,
            "bootstrap",
        ),
        (
            "wiring: build_node Client arm calls .no_adaptive()",
            WIRING_CLEAN,
            0,
            "wiring",
        ),
        (
            "wiring mutation: .no_adaptive() call deleted (MED-6)",
            WIRING_NO_ADAPTIVE_DELETED,
            1,
            "wiring",
        ),
    ]
    ok = True
    with tempfile.TemporaryDirectory() as td:
        for i, (label, content, want, kind) in enumerate(cases):
            f = Path(td) / f"case_{i}.rs"
            f.write_text(content)
            got = run([f], []) if kind == "bootstrap" else run([], [f])
            status = "PASS" if got == want else "FAIL"
            if got != want:
                ok = False
            print(f"  self-test [{status}] {label}: got exit {got}, want {want}")
    if ok:
        print(
            "check-mainline-client-only --self-test: OK (guard bites on every mutation)"
        )
        return 0
    print("check-mainline-client-only --self-test: FAILED", file=sys.stderr)
    return 1


def main(argv: list[str]) -> int:
    args = argv[1:]
    # `--self-test` is exclusive (mirrors check-public-dht-isolation.py and the Justfile,
    # which invoke the self-test and the real scan as two separate stages).
    if "--self-test" in args:
        return self_test()
    repo = Path(__file__).resolve().parent.parent
    explicit = [Path(a) for a in args]
    if explicit:
        # Explicit args are treated as bootstrap targets (the ad-hoc single-file case).
        return run(explicit, [])
    targets = [repo / t for t in DEFAULT_TARGETS]
    wiring = [repo / t for t in WIRING_TARGETS]
    return run(targets, wiring)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
