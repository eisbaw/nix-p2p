---
id: TASK-260
title: >-
  Triage 3 fresh 2026 RustSec advisories blocking just audit (hickory-proto
  0.25.2 + iroh h2)
status: To Do
assignee: []
created_date: '2026-08-18 22:43'
updated_date: '2026-08-19 14:22'
labels:
  - security
  - supply-chain
  - cargo-deny
  - audit
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
just audit (cargo deny) is RED at HEAD as of the 2026 advisory-db, INDEPENDENT of any single feature. Cargo.lock is byte-identical to HEAD; all-features=true in deny.toml resolves the full superset. Three advisories fail:
- RUSTSEC-2026-0118 (hickory-proto 0.25.2, NSEC3 DNSSEC unbounded loop): reachable via libp2p-mdns 0.48 AND libp2p-dns 0.44 -> hickory-resolver 0.25.2. DOES NOT APPLY: no dnssec feature is enabled anywhere in the workspace (grep dnssec empty), so DnssecDnsHandle is never constructed. DoS-class, not integrity.
- RUSTSEC-2026-0119 (hickory-proto 0.25.2, O(n^2) name-compression CPU on encode): same carriers. Encoding is over records WE construct (bounded), not attacker-controlled. DoS-class.
- RUSTSEC-2026-0258 (h2 / hickory-net 0.26.1 via hickory-resolver 0.26.1 -> iroh v1.0.3 subtree): pre-existing iroh dependency; iroh is prune-pending TASK-202. DoS-class.

None breaches the integrity TCB (README/PRD guarantee: never a bad store path; a hostile peer costs at most a retry). All are unfixable without upstream bumps: hickory-proto ^0.25 is pinned by libp2p 0.56 (fix rides hickory 0.26 behind a newer libp2p); 0258 rides the iroh subtree.

PLAN (per mped ruling on TASK-257): add all three IDs to deny.toml [advisories] ignore with per-ID provenance + rationale, as ONE owner-visible, cross-model-gated change (NOT buried in a feature diff). File upstream-bump follow-ups (libp2p bump clears both hickory-0.25 advisories at once; iroh prune/bump clears 0258). Re-check upstream at each bump.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 deny.toml ignores RUSTSEC-2026-0118, -0119, -0258 with a per-ID comment stating provenance + why it does not apply / is DoS-class + the upstream-bump follow-up
- [ ] #2 just audit returns RC 0
- [ ] #3 no advisory is suppressed silently: each ignore line carries a rationale and a filed upstream-bump follow-up reference
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
WORDING CORRECTION (TASK-257 DEEP gate, mped Finding 4). This tasks rationale should NOT assert hickory-proto 0.25.2 was already reachable at RUNTIME via libp2p-dns: the `dns` feature is NOT in fabric-libp2ps libp2p feature list (kad/tcp/quic/identify/request-response/tokio/macros/noise/yamux/autonat/dcutr/relay + the new mdns), so at HEAD hickory-proto 0.25.2 was in the LOCKFILE but NOT compiled into the binary. Enabling --libp2p-mdns newly compiles libp2p-mdns -> hickory-proto INTO the running binary. The audit DEFERRAL stays SOUND -- Cargo.lock is byte-identical so cargo-deny (all-features=true) produces an identical verdict at HEAD, and the advisories are DoS-class (RUSTSEC-2026-0118 dnssec-gated with no dnssec feature enabled; 0119 encode-side over records we construct; mDNS is default-OFF + LAN-only). But state the provenance as unchanged at the LOCKFILE/AUDIT granularity, NOT as prior runtime reachability. Keep the deny.toml ignore + upstream-bump follow-ups as filed.

IMPLEMENTATION 2026-08-19 (recovered directly after the first implementer died on a transient API error; ignore-only change, Cargo.lock untouched). All 3 rationales VERIFIED via cargo tree -e features + cargo deny (NOT transcribed — the task description had TWO wrong rationales): (1) the "grep dnssec is empty" claim is FALSE (BASE32_DNSSEC exists in vendor/iroh, an unrelated base32 alphabet); the CORRECT check is the feature set: hickory-proto 0.25.2 enabled features = futures-io/std/mdns/socket2 ONLY, no dnssec-ring/dnssec-aws-lc-rs node in the tree, so 0118 DNSSEC validation never runs. (2) "0258 rides the iroh subtree" is INCOMPLETE: h2 0.4.15 is also reachable via hyper 1.11, BUT the shipped daemon enables ONLY hyper http1 (daemon-core/Cargo.toml:27, daemon/Cargo.toml:117; http1-only usage in observ.rs/server.rs/upstream.rs), so no h2/HTTP-2 server ever runs on the shipped path — h2 is present solely via the iroh subtree (prune=TASK-202). 0119 = encode-side O(n2) over our own bounded mDNS records. All 3 DoS-class, integrity TCB untouched. just audit (cargo deny check) now rc=0: advisories ok, bans ok, licenses ok, sources ok; exactly the 3 IDs ignored (before: exactly 3 RED, 1:1, no silent suppression). Follow-ups: TASK-265 (libp2p/hickory bump, blocked on MSRV-aware resolution dragging 14 collateral downgrades), TASK-202 (iroh prune clears 0258). Pending cross-model codex gate on rationale soundness before Done.

CODEX 260R1 GATE 2026-08-19 -> NOGO on the 0258 SUPPRESSION, GO on 0118/0119. Correction applied: 0258 (h2 empty DATA frames) is NOT ignored — it is FIXED by bumping h2 0.4.15 -> 0.4.16 (codex verified `cargo update -p h2 --precise 0.4.16` changes ONLY h2, no MSRV collateral; confirmed: Cargo.lock diff is h2-only, and `cargo build --workspace` rc=0 through the iroh subtree). My original 0258 rationale was unsound (the h2 advisory also affects HTTP/2 CLIENTS not just servers, and TASK-202 is Done + RETAINS iroh so it would never prune the h2 tree). 0118 + 0119 ignores RETAINED — codex confirmed both rationales SOUND: 0118 the dnssec-ring/dnssec-aws-lc-rs feature is not enabled (features=futures-io/std/mdns/socket2); 0119 libp2p-mdns hand-builds mDNS replies from fixed service names + local peer id/addrs/TTL (dns.rs:107), reflecting only a fixed-width transaction id from a hostile query — hickory BinEncoder is never invoked, so the attacker-shaped O(n2) encode is unreachable. Suppression scope verified: exactly 2 IDs ignored now (0258 fixed), no wildcard, all other/new advisories still block. FINAL: cargo deny check rc=0; workspace builds. Follow-up TASK-265 (bump for 0118/0119) unchanged.
<!-- SECTION:NOTES:END -->
