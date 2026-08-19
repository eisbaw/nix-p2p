---
id: TASK-255
title: >-
  Whole-store supply coverage: a node offers paths it already holds, not just
  ones named by flag or re-fetched
status: To Do
assignee: []
created_date: '2026-08-18 20:35'
updated_date: '2026-08-19 10:40'
labels:
  - supply
  - cornerstone
  - user-value
  - prd-risk-4
dependencies: []
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
UNFILED CORNERSTONE surfaced by COMPASS (F5) and VERIFIED against the call graph 2026-08-18 before filing.

THE GAP: there is no path by which a nodes EXISTING /nix/store becomes available to the swarm. Verified at HEAD: --libp2p-provide-store parses via parse_libp2p_seed_nar and PUSHES ONE narhash=storepath PAIR PER FLAG OCCURRENCE (daemon-libp2p/src/main.rs:431), with the operator supplying the pre-computed NarHash. The only other supply channel is --libp2p-announce-after-fetch, which is budget-capped and covers only paths fetched THROUGH the daemon. Grep across daemon-libp2p/src, daemon-core/src and fabric-libp2p/src finds NOTHING that enumerates the store: no nix path-info --all, no db.sqlite read, no store read_dir. Only comments mention path-info.

MECHANISM VS COVERAGE. TASK-191/194 delivered the regenerate-on-demand MECHANISM (dump from /nix/store, hold no second copy) and TASK-83s re-scope note is correct about that. This task owns the missing COVERAGE: which paths a node offers. Read quickly, TASK-83 makes a reader believe the whole property is closed. It is not.

WHY IT MATTERS FOR USERS: a freshly installed node contributes nothing, and a node already holding 40 GB of nixpkgs still contributes nothing until each path is named by hand or re-fetched through the daemon. That is PRD risk 4 (announce-on-demand means supply lags demand) in its most acute form, and it directly caps any offload number the value-thesis work can produce.

DESIGN CONSTRAINTS THAT MAKE THIS NON-TRIVIAL:
  * The no-enumeration invariant is frozen and must hold: building an internal index of local holdings is fine, but no call may LIST holdings to a peer. Yes/no per named NarHash only.
  * TASK-102s publication allowlist is the single enforcement point: a public record may name only content proven signed-public by an exact cache.nixos.org narinfo with a verified trusted signature. So a locally-built private derivation is unannounceable by design, and eligibility filtering is part of this task, not an afterthought.
  * The supply-integrity floor (TASK-56) must still gate every announce: sha256(nix-store --dump path) equals the signed NarHash before advertising.
  * Cost: computing NarHash for every store path means dumping the whole store once. On the owners measured corpus that is 12,396 servable paths and about 103 GiB of NAR. TASK-82 persists the immutable NarHashKey binding precisely so this is paid once, not per boot. Warming at boot is NOT acceptable (PRD supply-model cost #2).

SEQUENCING: this should be decided by evidence, not assumption. Run the offline closure-overlap probe first. If overlap says announce-after-fetch is already sufficient for the org/LAN case, this may not be worth building; if a cold node must be able to offer what it already holds, this is the next cornerstone.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
256 DOWNSCOPE 2026-08-19: TASK-256 (verified) shows same-pin peers warm to 95% paths / 99% NAR bytes via announce-on-fetch ALONE, and cross-rev supply overlap is structurally 0 (nothing to announce). Whole-store cold supply buys ~nothing for the org/LAN case. Priority->Low; revisit only if a same-pin org pilot shows announce-after-fetch leaving real hits on the table.
<!-- SECTION:NOTES:END -->
