---
id: TASK-204
title: >-
  daemon-libp2p (thin binary): wire the TASK-103 public-NAR allowlist announce
  door for parity with the composite daemon
status: Done
assignee: []
created_date: '2026-08-14 15:43'
updated_date: '2026-08-14 17:44'
labels: []
dependencies:
  - TASK-103
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-103 wired the PUBLIC-announce allowlist door into the COMPOSITE daemon crate (daemon/src/main.rs), which is what the s7-libp2p container e2e runs (/bin/daemon). The per-backend thin binary daemon-libp2p/src/main.rs still uses lan_share_or_refuse only + PublicNarAllowlist::disabled(), so a bootstrapped daemon-libp2p provider REFUSES to announce (fail-CLOSED/SAFE, but no public participation). Mirror the composite wiring: the same flags (--libp2p-trusted-public-key / --libp2p-public-allowlist-path / --libp2p-prove-public-narinfo), build_public_allowlist, and route seed/store announces through announce_public_seeds / announce_public_provisions in PUBLIC mode. The shared lib door already exists in daemon-libp2p/src/lib.rs. Ideally de-duplicate the near-identical install_provider between the two binaries into the lib. No container e2e exercises daemon-libp2p today, so add a unit/integration check that a bootstrapped provider WITH an allowlist announces and WITHOUT one still refuses.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 daemon-libp2p bootstrapped provider announces its allowlisted content through the typed public door; with no allowlist it still refuses (fail-closed); the composite-daemon and thin-binary policies do not drift
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
TASK-204 landed: brought daemon-libp2p thin binary to PARITY with composite daemon's public-NAR allowlist door.

SSOT extraction (preferred path taken): the config->allowlist wiring is now ONE function, daemon_libp2p::open_public_allowlist(path, trusted_keys, identity_seed, prove_narinfo) in daemon-libp2p/src/lib.rs. The composite daemon's Config::build_public_allowlist now DELEGATES to it (body removed); the thin binary calls it directly. Both binaries also already shared the announce door (announce_public_seeds/announce_public_provisions) via the daemon-libp2p lib, so there is no copy of door logic.

Thin binary wiring (daemon-libp2p/src/main.rs): added --libp2p-trusted-public-key / --libp2p-public-allowlist-path / --libp2p-prove-public-narinfo (+ parse_prove_public_narinfo, mirrored fail-closed companion validation). main() builds the allowlist ONCE via open_public_allowlist and passes the SAME Arc into both the provider announce gate and RunConfig.public_allowlist (was disabled()). install_seed_provider/install_store_provider now route through announce_public_seeds/announce_public_provisions when --libp2p-public-allowlist-path is set, else keep the lan_share_or_refuse + announce_provider_seeds/announce_store_provisions isolated-LAN stopgap (LanShare witness intact).

Security: no property weakened. Allowlist is SSOT; operator naming a path != public (trusted narinfo-signature gate decides, in daemon-core, unchanged); typed door consumes claims; store trait sealed; MAC/correlation/strict-file unchanged. No-float NarSize unaffected.

Parity tests: daemon-libp2p/tests/public_announce_door.rs (real fabric: un-allowlisted seed REFUSED by announce_public_seeds while the same seed announces over the LAN path; shared builder proves the trusted-signed APP narinfo public -> door approves the proven seed, refuses a foreign one; file-backed no-trusted-key opens as error). Plus 4 parse_config parity unit tests in main.rs (the three fail-closed companion validations + a clean public-provider parse) — drives the binary's OWN Config, the anti-drift bite.

Gotchas: (1) thin binary Config has NO derive(Debug) on purpose, so .expect_err needs let-else instead. (2) removed now-unused imports (LearnOutcome/StoreHash/TrustedNarKeys/derive_allowlist_mac_key) from composite main after delegating. (3) open_public_allowlist added to daemon crate's daemon_libp2p re-export.

Bounded gate: daemon-core+daemon-libp2p cargo test green; daemon --lib + public_allowlist_learn/libp2p_provider_path/serve_budget_and_supply/doc_citations/no_enumeration green; new door tests 2/2 + parity units green; no_iroh_closure_guard still green; cargo fmt --all --check clean; clippy -D warnings clean on daemon-core/daemon-libp2p/daemon; just independence green.

Honest limit: no full container e2e exercises the thin daemon-libp2p provider (none existed); a container e2e for the thin-binary public announce is a follow-up. Full 'just test' was NOT run here (bounded gate only) — orchestrator re-verifies.

DONE 2026-08-14. daemon-libp2p thin binary brought to allowlist-door parity with the composite daemon via a SHARED SSOT free fn open_public_allowlist (daemon-libp2p/src/lib.rs:1150) that BOTH binaries call (composite delegates, thin calls directly) — no copied door logic; one Arc feeds both the announce gate and RunConfig. Was disabled()+lan_isolation-refuse; now a bootstrapped thin-binary provider legitimately announces allowlisted-public content through the typed door (approve_*_for_public -> announce_public_*), isolated-LAN path intact. Parity test bites (un-allowlisted seed refused by the door; same seed announces isolated-LAN -> refusal attributable to the gate). Security UNCHANGED (wiring only; allowlist SSOT, sealed store, MAC all in shared daemon-core). Orchestrator-verified: daemon-core 172/0, door+lan_isolation tests bite, independence+fmt green. Honest limit: no container e2e for the thin-binary public announce (none existed; covered by the real-fabric door test + parse_config parity units); filed as a follow-up.
<!-- SECTION:NOTES:END -->
