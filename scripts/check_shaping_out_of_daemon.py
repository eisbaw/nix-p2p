#!/usr/bin/env python3
"""AC#2 guard (task-70): link-shaping must never enter the shipped binary.

The shaped-link measurement primitive (`scripts/shaped_link*.py`,
`scripts/shaped_link_inner.sh`) emulates a real peer link with `unshare`, `veth`
and `tc netem`. That is ENVIRONMENT/measurement machinery, and task-70 AC#2
requires it to stay out of the product daemon -- the PRD forbids adversarial or
environment logic living in the shipped code path. This guard makes that a gate,
not a promise: it fails if any distinctive shaping token appears in the compiled
`src/` of a shipped crate.

It scans only `src/` (what links into the binary), not `tests/`, `examples/`, or
`scripts/`. A NAR of prose that merely mentions "netem" in a doc comment would
trip it -- deliberately: the cheap fix is to move the mention, and a false
citation about where shaping lives is exactly what this exists to prevent. If a
legitimate exception ever arises, add it to ALLOW with a reason, keeping the
exception visible (the `check-independence.py` discipline)."""

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Crates whose src/ compiles into the shipped daemon / testproxy binaries.
SHIPPED_CRATE_SRC = [
    "daemon/src",
    "daemon-core/src",
    "daemon-libp2p/src",
    "fabric-libp2p/src",
    "fabric-iroh/src",
    "peer-fabric/src",
    "testproxy/src",
]

# Distinctive shaping tokens -- specific enough not to collide with ordinary
# words like "rate". Each is something only link-emulation code would contain.
SHAPING_TOKENS = [
    "netem",
    "tc qdisc",
    "ip netns",
    "veth",
    "unshare -",
    "NET_ADMIN",
    "shaped_link",
]

# Deliberate, reasoned exceptions (file-substring, token). Empty for now.
ALLOW: list[tuple[str, str]] = []


def main() -> int:
    violations = []
    for crate_src in SHIPPED_CRATE_SRC:
        base = ROOT / crate_src
        if not base.exists():
            continue
        for path in base.rglob("*.rs"):
            rel = path.relative_to(ROOT).as_posix()
            for lineno, line in enumerate(path.read_text().splitlines(), 1):
                for token in SHAPING_TOKENS:
                    if token in line:
                        if any(a in rel and t == token for a, t in ALLOW):
                            continue
                        violations.append(
                            f"{rel}:{lineno} contains '{token}': {line.strip()}"
                        )

    if violations:
        print(
            "SHAPING-IN-DAEMON: link-shaping leaked into shipped src/ (task-70 AC#2):",
            file=sys.stderr,
        )
        for v in violations:
            print(f"  {v}", file=sys.stderr)
        return 1

    scanned = sum(
        1
        for c in SHIPPED_CRATE_SRC
        if (ROOT / c).exists()
        for _ in (ROOT / c).rglob("*.rs")
    )
    print(
        f"check-shaping-out-of-daemon: OK ({scanned} shipped src files clean of "
        f"{len(SHAPING_TOKENS)} shaping tokens)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
