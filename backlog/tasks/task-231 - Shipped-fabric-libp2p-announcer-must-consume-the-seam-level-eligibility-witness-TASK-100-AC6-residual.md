---
id: TASK-231
title: >-
  Shipped fabric-libp2p announcer must consume the seam-level eligibility
  witness (TASK-100 AC#6 residual)
status: To Do
assignee: []
created_date: '2026-08-16 05:03'
labels:
  - wave-2b
dependencies: []
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
