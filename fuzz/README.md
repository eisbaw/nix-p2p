# Fuzzing the wire/parse surfaces (TASK-282 AC#4)

This directory holds the **seed corpora** and this runbook for nix-p2p's fuzz
targets. The targets themselves live **next to the code they exercise** (as
`#[cfg(test)]` `src/fuzz.rs` modules), so they can reach `pub(crate)` parse
functions without widening any production API.

This work **folds and supersedes TASK-113** (coverage-guided fuzzing): see
"Relationship to TASK-113" below for what carries over and what changed.

## Engine decision: proptest on stable, not cargo-fuzz

`cargo-fuzz` / libFuzzer is **not usable** in this repo. It needs a **nightly**
toolchain plus `-Zsanitizer`, and `rust-toolchain.toml` pins `channel = "1.97.1"`
(stable, `profile = minimal`) precisely so `nix develop` and the crane build cannot
drift. TASK-113 AC#9 makes that a hard rule: *"No nightly enters the default
devshell or crane build."* We verified the constraint rather than assuming it:
`cargo-fuzz` 0.13.1 is on `PATH` in the devshell, but `rustc -Zsanitizer=address`
fails with *"the option `Z` is only accepted on the nightly compiler."*

So the targets use **`proptest`** (already vendored — it was a daemon-core dev-dep
for TASK-112 property tests). proptest gives us the three things a fuzzer needs:

1. **Structured generation** — grammar-aware strategies, not just random bytes.
2. **Shrinking** = automatic **crash minimisation** (the triage requirement).
3. A **`proptest-regressions/<module>.txt`** persistence file that, on a discovered
   failure, records the minimal seed — a **committed crash corpus** replayed on the
   next run.

**Honest limit:** this is **bounded random structured fuzzing, not
coverage-guided**. There is no coverage feedback steering generation toward new
branches. A full `cargo-fuzz` setup would add libFuzzer coverage feedback and
AddressSanitizer; it is deferred because it requires a **separately pinned nightly
toolchain** (permitted by TASK-113 AC#9 only for `just fuzz`, never the devshell)
plus sanitizer builds in a **separate heavy target dir** — a real cost on this
disk-constrained shared box, deferred deliberately this cycle, not overlooked.

## Cadence: BROAD only — never the fast loop

Every target is a `#[test]` marked **`#[ignore]`**, so `just test` / `cargo test`
(the fast loop) **never** runs it. They run **only** via:

```
just fuzz-smoke
```

which is a **BROAD/SLOW tier** recipe (TESTING.md fast/slow split). It runs each
target under a **bounded** `PROPTEST_CASES` with a `PROPTEST_FREE_SEED` (fresh
entropy for exploration) and a wall-clock `timeout` guard, and **fails on any
crash**. It is deliberately **not** wired into `just lint` or `just test`.

## Targets and invariants (beyond "doesn't panic")

| Target | Surface | Crate / module | Load-bearing invariant |
|---|---|---|---|
| `fuzz_multiaddr_lan_provenance` | `multiaddr_lan_provenance` | fabric-libp2p `src/fuzz.rs` | an **ACCEPTED** multiaddr carries **no** routable/CGNAT/wildcard IP, **no** `/dns*`, **no** `/p2p-circuit`, and **exactly one** IP hop — re-derived by an **independent** oracle, so the compound-address bypass bites |
| `fuzz_nar_v4_decode_verified` | `nar_v4::decode_verified` (`/nar/4`) | fabric-libp2p `src/fuzz.rs` | a Bao-authenticated decode **never** returns `Ok` with content differing from the source; any tampered stream errors |
| `fuzz_decode_provider_assertion` | `decode_provider_assertion` | peer-fabric `src/fuzz.rs` | a decoder **never** returns `Ok` on bytes that fail signature/integrity: mutated bytes never verify to a *different* record; arbitrary bytes never forge one |
| `fuzz_narinfo_to_raw` | `rewrite::to_raw` | daemon-core `src/fuzz.rs` | no panic/overflow on adversarial narinfo; parse is **deterministic**; `NarSize` is an **integer** (no-floats rule); the signed `NarHash` survives the rewrite verbatim |

The `/nar` **request/response framing** parse (surface 5) is partially covered here:
`nar_v4::decode_verified` is the body verifier the response path hands the stream
to. The full async framing loop (`nar::read_response_streamed_since`,
`serve_stream`) is driven over a tokio runtime with idle timeouts; a dedicated
async framing fuzz target is a tractable follow-up, noted honestly as not done this
cycle.

## Corpus

`corpus/<target>/` holds committed seeds — **valid** inputs (so the target proves
non-vacuity: a real input is accepted) and **adversarial** inputs (the compound
bypass, overflowing `NarSize`, truncated records, garbage bao streams). The harness
replays every corpus file through the same invariant **before** the proptest loop.
Multiaddr seeds are text (one address per line, `#` comments); the record and bao
seeds are raw bytes.

## Crash-triage runbook

When a target fails:

1. **Reproduce.** proptest prints the shrunk (minimal) counterexample and writes it
   to `<crate>/proptest-regressions/fuzz.txt`. That file is the reproducer — commit
   it.
2. **Minimise + save.** The shrunk input goes into `corpus/<target>/` as a named
   file so it is replayed deterministically going forward.
3. **Decide bug vs. expected.** An invariant violation on a parse surface is almost
   always a **real bug** (a security invariant — e.g. an accepted non-LAN address —
   is a real security bug; headline it).
4. **Fix the root cause**, not the symptom (per project standards).
5. **Pin a regression.** Add a **non-`#[ignore]`** `#[test]` (a named
   `regression_*` case) that replays the minimal input through the production path,
   so `just test` (the fast loop) guards it forever. This is what satisfies
   TASK-113 AC#4 ("every crash → a regression replayed by `just test`").

This cycle found **no crash**: these surfaces already carry unit coverage (TASK-280
/ TASK-282 AC#2), and the fuzzers agree so far. That is a bounded result — see the
honest limit above; absence of a found crash under bounded random generation is not
proof of absence.

## Relationship to TASK-113

TASK-113 (coverage-guided fuzzing) is **folded into this work**:

- **Kept:** a dedicated fuzz tier behind its own recipe, named SLOW/BROAD in
  TESTING.md and kept out of `just test` (AC#1); ≥2 targets with real seed corpora
  (AC#2 — here: 4 targets); the crash → committed-regression → `just test` replay
  path (AC#4); honest statement of what is *not* reached (AC#6); the toolchain
  decision recorded (AC#9 — stable proptest, nightly cargo-fuzz explicitly deferred
  with evidence).
- **Superseded/dropped:** the BitTorrent metainfo/infohash and Iroh
  framing/compression targets (AC#7/#8) are **dead** by the owner steer that
  deprioritised iroh/BitTorrent (the task's own note says to delete them when
  picked up); they are not implemented.
- **Preserved (AC#5):** the existing TASK-13/112 seeded loops (narinfo_cache
  `safe_key`, testproxy `cache.rs`, the narinfo-identity fuzz) are untouched and
  still run in `just test`; this adds targets, it does not replace them.
