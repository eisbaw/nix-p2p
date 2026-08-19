---
id: TASK-257
title: >-
  libp2p mDNS LAN peer discovery behind --libp2p-mdns (zero-config bootstrap for
  the org pool)
status: Done
assignee:
  - '@claude'
created_date: '2026-08-18 20:53'
updated_date: '2026-08-19 08:52'
labels:
  - libp2p
  - mdns
  - discovery
  - bootstrap
  - lan
  - user-value
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
OWNER DIRECTION 2026-08-18, FIRST PRIORITY of the three bootstrap mechanisms.

THE PROBLEM: a DHT cannot bootstrap itself. Kademlia routes once you are IN; joining needs one live members address learned out of band. Verified at HEAD: there are NO default bootstrap nodes anywhere in the codebase, and consume-only REFUSES TO START without an explicit --libp2p-bootstrap PeerId@multiaddr (daemon-libp2p/src/main.rs:664). So today every user must be handed peers by someone they know.

WHY mDNS IS FIRST: it removes bootstrap ENTIRELY for the LAN/org case -- zero configuration, zero DNS, zero hardcoded peers, and no infrastructure anyone has to run or pay for. It is also the ONLY one of the three mechanisms compatible with lan-share: the Wave-2c privacy contract requires lan_share to emit ZERO packets/records to public tracker, DNS discovery, relay, DHT or Mainline infrastructure, which rules out both DNSADDR and Mainline there. mDNS is link-local multicast and emits nothing off-LAN. Combined with the existing scope mechanism (protocol names are /nix-p2p/<scope>/kad/1.0.0, so a distinct scope is ALREADY a disjoint network) this makes the private org pool work with no new architecture.

SCOPE:
  * Add the libp2p mdns feature (tokio variant) to fabric-libp2p and wire the behaviour into the existing swarm alongside kad/identify/autonat/dcutr/relay.
  * New CLI flag --libp2p-mdns, DEFAULT OFF, mirrored as a NixOS module option under services.nix-p2p.libp2p (match the existing naming: provider/leech/router/listen/bootstrap/scope).
  * Discovered peers feed the SAME NodeLocator/bootstrap path as an explicit --libp2p-bootstrap entry; mDNS supplies peer addresses, it does NOT become a second content-discovery mechanism.
  * Honour the scope: a peer discovered by mDNS but running a different /nix-p2p/<scope>/kad protocol name must not join. mDNS discovery and scope isolation are independent and must compose correctly.

OPERATOR-CONTRACT MAPPING (TASK-120 axes -- enabling one axis NEVER implies another):
  * This is axis 1, LOCAL DISCOVERY, only. It must not imply serving, announcing, publication, or public participation.
  * upstream_only MUST remain zero-P2P: with the profile set to upstream-only, --libp2p-mdns must be refused or inert, and the node must emit ZERO multicast packets.
  * Permitted under consume_only, lan_share and public_share as an explicit opt-in.
  * Exposure: mDNS discloses this hosts presence and NodeId to every device on the LAN. That is a real disclosure and must be recorded in the exposure ledger and surfaced by preflight/--status, not silently accepted because it is local.

TESTING IS REQUIRED (owner: "we need to test both"). The oracle must BITE by mutation, not by inspection:
  * Two daemons on one LAN segment with NO --libp2p-bootstrap discover each other and complete a real fetch. Disable mDNS on one and the same scenario must FAIL to discover -- that is the bite proving mDNS is load-bearing and no other path leaked the address in.
  * Packet-level proof that upstream-only emits zero multicast; mutate the guard and watch it go red.
  * Scope-mismatch negative control: same LAN, different --libp2p-scope, must NOT form a network.
  * Prefer the existing rootless-podman container topology over adding a new harness family.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The libp2p mdns behaviour is wired into the shipped swarm behind a default-OFF --libp2p-mdns flag, mirrored as a NixOS module option under services.nix-p2p.libp2p
- [ ] #2 Two daemons on one LAN segment with NO --libp2p-bootstrap discover each other and complete a real byte-identical NAR fetch
- [ ] #3 BITE: disabling mDNS on one node makes that same scenario fail to discover, proving mDNS was load-bearing and no address leaked in by another path
- [ ] #4 upstream-only emits ZERO multicast packets with --libp2p-mdns requested; proven at packet level and the guard bites under mutation
- [ ] #5 Negative control: two nodes on the same LAN with different --libp2p-scope do NOT form a network (mDNS discovery and scope isolation compose)
- [ ] #6 mDNS presence/NodeId disclosure to the LAN is recorded in the exposure ledger and surfaced by preflight and --status
- [ ] #7 mDNS supplies peer ADDRESSES into the existing bootstrap/NodeLocator path only; it does not become a second content-discovery mechanism and no holdings enumeration is possible
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Sequence (owner 2026-08-18): mDNS FIRST, then TASK-258 Mainline rendezvous, then TASK-259 DNSADDR. Owner will NOT run public server infra, so there are no public bootstrap nodes: TASK-258 is the only path to a global public pool, TASK-259 is enterprise/internal only, and this task (mDNS) is the zero-infrastructure answer for the LAN/org pool. All three are default-OFF CLI flags plus mirrored NixOS options; all three need tests whose oracles bite by mutation.

IMPLEMENTED + committed bd12c02 (explicit pathspec, no push). Full gate GREEN: cargo test --workspace (1178 passed), fmt --check clean, clippy -D warnings clean, check-no-floats green, check-golden-vectors BYTE-IDENTICAL, check-discovery-no-shortcut refined guard (self-test proves BOTH mdns directions + real-code mutation bites), just e2e exit 0 (all 11 fast scenarios incl libp2p-mdns-bootstrap 8/8 and libp2p-mdns-scope-isolation 7/7, no regression).

just audit is the ONE non-green gate, and it is a PRE-EXISTING HEAD condition, NOT a 257 regression: Cargo.lock is BYTE-IDENTICAL to HEAD (diff empty), so 257 introduces ZERO new advisories. Three fresh 2026 advisories fail at HEAD (RUSTSEC-2026-0118/0119 on hickory-proto 0.25.2 reachable via libp2p-mdns AND libp2p-dns; 0258 on h2/hickory-net in the iroh subtree). deny.toml all-features=true resolves the superset. mped ruling: 257 ships on its own merits; the honest audit unblock is the separate owner-visible TASK-260 (adds the 3 IDs to deny.toml ignore with per-ID rationale + upstream-bump follow-ups). Not marking Done (orchestrator owns Done + the cross-model gate).

DEEP GATE codex-257R NO-GO (afeb96d). F1 (composite report-matches-wire) CONFIRMED FIXED. FOUR substantive findings for the fix round: (1) ROUTING-FLOOD/ECLIPSE: mDNS accepts UNAUTHENTICATED + UNCAPPED LAN advertisements (attacker PeerId/addr/TTL), app loops all into kad.add_address with NO admission/rate cap (swarm.rs:2412; libp2p-mdns keeps every pair in an uncapped SmallVec + trusts advertised TTL) -> a malicious LAN host floods/skews the Kad routing table. Materially worse than a finite explicit bootstrap list. FIX: bounded admission/rate cap on mDNS-discovered peers. (2) CROSS-SCOPE ROUTING POLLUTION: scope blocks cross-scope CONTENT but a cross-scope mDNS peer still gets add_addressd -> occupies routing state + is propagated as a routing hint (kad add_address inserts as Disconnected before any handshake; kad server responses do not filter disconnected peers). FIX: remove cross-scope peers from routing after the failed scoped handshake (or filter). Scope e2e must assert the cross-scope peer is ABSENT from routing, not just content-unresolved. (3) EXPOSURELEDGER GAP (AC): the mDNS NodeId/address disclosure is a --status LABEL only; it is NOT appended to the real ExposureLedger (peer-fabric/src/exposure.rs) by the mDNS handler/startup. FIX: record OurNodeId/OurAddress (broadcast) + LanPeer (discovered) disclosures in the ledger when mDNS fires. (4) NONDETERMINISM/WORKAROUND: the e2e passes only via a harness provider-restart up-to-6x (e2e_harness.py:2532) compensating for the ONE-SHOT startup announce (daemon-libp2p/main.rs:956) losing the put-quorum race; production has no retry -> nondeterministic. FIX: fold TASK-261 (in-daemon bounded announce-retry) into 257 so the e2e passes WITHOUT the restart workaround (CLAUDE.md: no workarounds). Minor: daemon-libp2p --preflight --libp2p-mdns prints upstream-only + active mDNS (dry-run, no socket) - report inconsistency; exposure wording LAN-broadcast->link-local multicast, cannot-JOIN should acknowledge routing pollution. Audit-HEAD-condition (TASK-260) confirmed honest, NOT the rejection basis. Content integrity chain SOUND (sig/PeerId-binding/Bao/NarHash) - a hostile mDNS peer costs a retry, never a bad store path. ALL FIXES NEED cargo+e2e -> BLOCKED on disk (9.6G).

DEEP GATE PASSED (arbitrated), 2026-08-19. Commits bd12c02+afeb96d+3028ef1+a014590. mDNS zero-config LAN bootstrap WORKS OUT OF THE BOX: e2e libp2p-mdns-bootstrap 8/8 RESTART-FREE (lone first node discoverable, no --libp2p-bootstrap) + scope-isolation 9/9. F1 admission cap, F2 sweep-deleted->bounded-by-cap+TASK-262 (arbitrated within TCB via mped, codex eviction-demand exceeds TCB), F3 ExposureLedger, F4 restart-free (TASK-261 folded). mped arbitration GO + required doc-fix applied. Residuals: TASK-260 (audit HEAD-condition), 262 (deterministic eviction), 263 (readiness gate). Full gate green except audit(260).
<!-- SECTION:NOTES:END -->
