---
id: TASK-231
title: >-
  Shipped fabric-libp2p announcer must consume the seam-level eligibility
  witness (TASK-100 AC#6 residual)
status: To Do
assignee: []
created_date: '2026-08-16 05:03'
updated_date: '2026-08-16 05:58'
labels:
  - publication
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The shipped fabric-libp2p AvailabilityAnnouncer must STRUCTURALLY consume the single TASK-102 publication-eligibility decision at the adapter (TASK-100 AC#6 residual). Today the shipped announcer takes a bare ProviderRecord and relies on the ApprovedPublicProvision gate one layer up in daemon-libp2p (which is structural + bite-tested, but a caller reaching announce() directly bypasses it). TASK-100 landed the SEAM CONTRACT (peer_fabric::PublicationEligibility authority + AnnounceError::Ineligible + fake announcer consuming it, bite-proven). Close the shipped gap: thread a mechanism-neutral eligibility WITNESS as the required announce input so the fabric-libp2p announcer cannot emit a record that did not pass the decision. ROOT CAUSE to design around: the frozen ProviderRecord no longer carries the sha256 NarHash the PublicNarAllowlist is keyed by (only the derived ContentKey + BLAKE3 content), so eligibility is inherently decided PRE-record; the witness should be minted from the existing ApprovedPublicProvision (which has the NarHash) rather than re-derived at announce. Scope note: this is a ~46-call-site announce signature change (mostly tests) - do it as one atomic change; do NOT touch the frozen wire.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The seam AvailabilityAnnouncer::announce requires a mechanism-neutral eligibility witness (not a bare ProviderRecord); a bare-record announce does not compile
- [ ] #2 The shipped fabric-libp2p announcer consumes the single TASK-102 decision (witness minted from ApprovedPublicProvision); a bypass makes a test fail
- [ ] #3 The LAN/consume paths mint a distinct explicit witness (not allowlist-gated); upstream_only announces nothing
- [ ] #4 Frozen wire untouched (golden vectors byte-identical); full gate incl just e2e green
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
RE-SCOPED per codex DEEP gate (TASK-100 BLOCKER, AC#6): this is a REAL PUBLICATION-ELIGIBILITY + MODE-CONFINEMENT SECURITY HOLE, not an architecture deferral. codex demonstrated: the shipped fabric-libp2p announcer publishes to the public kad DHT after only identity/TTL/encoding checks; the ApprovedPublicProvision/TASK-102 gate is BYPASSABLE library routing (announce_provider_seeds with a freely-mintable LanShare::operator_assembled reaches the DHT with an UNALLOWLISTED record - public_announce_door.rs:89/126), violating PRD 102/120/624 (a public record may name only signed-public-upstream content; LAN-share emits zero records to the public DHT).

PARTIALLY CLOSED in TASK-100 (commit pending): the shipped announcer now VERIFIES the ed25519 signature before start_providing/put_record (decode_provider_assertion/verify_strict), so the ZERO-SIGNATURE self-provider vector is closed fail-closed (bite: record_lifecycle::announce_rejects_a_zero_signature_record_before_reaching_the_dht). The UNALLOWLISTED-but-validly-signed vector remains open and is this task.

REQUIRED FIX (the remaining vector): make eligibility an ADAPTER INVARIANT, not bypassable routing. (1) The shipped Libp2pAvailabilityAnnouncer must CONSUME a peer_fabric::PublicationEligibility authority FAIL-CLOSED before start_providing/put_record (default RefusePublication; no announcer without an authority). (2) Wire it through NodeConfig + fabric.rs assemble; the shipped daemon-libp2p PUBLIC path injects an allowlist-backed authority, the genuinely-isolated-LAN path an explicit AdmitAllPublication. (3) The allowlist-backed authority checks a ProviderRecord by its ContentKey: add PublicNarAllowlist::contains_content_key deriving ContentKey=derive_from_signed_nar_hash(NarHash) per allowlisted entry (ContentKey is a deterministic derive of the NarHash the record carries, so admit(&record) can consult the single TASK-102 decision without the raw NarHash). (4) Update the ~17 announce test sites to pass an explicit authority; re-point public_announce_door.rs so a public-reachable node REFUSES an unallowlisted LAN-path announce. BITE: an unallowlisted (validly-signed) record announced through the shipped adapter is REFUSED and nothing reaches the DHT; removing the consult reddens it. Constraint: do NOT touch the frozen wire; keep the existing ApprovedPublicProvision gate consistent (single source = the allowlist). This spans daemon-libp2p TASK-102/103/204 DEEP-gated surface, hence its own security task.
<!-- SECTION:NOTES:END -->
