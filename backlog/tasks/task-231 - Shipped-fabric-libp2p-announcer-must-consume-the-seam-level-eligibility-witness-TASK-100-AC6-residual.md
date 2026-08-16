---
id: TASK-231
title: >-
  Shipped fabric-libp2p announcer must consume the seam-level eligibility
  witness (TASK-100 AC#6 residual)
status: In Progress
assignee:
  - '@claude'
created_date: '2026-08-16 05:03'
updated_date: '2026-08-16 13:27'
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

TASK-231 design (mped-architect GO-WITH-CHANGES arbitrated against explicit ACs):
Two mechanisms, distinct roles.
- MECH A (AC#1, seam-contract, compile-time): NEW opaque peer_fabric::PublicationWitness wrapping a ProviderRecord, sealed pub(crate) ctor; PublicationEligibility gains a DEFAULT authorize(record)->Result<PublicationWitness,IneligibleReason> = { admit(&record)?; sealed(record) }. announce(&self, witness:&PublicationWitness, budget) - bare-record announce no longer compiles. In-process only, never on the wire.
- MECH B (AC#2, load-bearing runtime gate + the BITE): the announcer HOLDS Arc<dyn PublicationEligibility> (default RefusePublication; no announcer without one) and RE-CONSULTS admit(witness.record()) fail-closed before start_providing/put_record. Per-FABRIC authority = the node audience: public provider -> AllowlistEligibility(same allowlist the public door uses = SSOT); genuinely-isolated LAN -> AdmitAllPublication (explicit opt-in); else RefusePublication.
- daemon-core: PublicNarAllowlist::contains_content_key(&ContentKey) derives ContentKey=derive_from_signed_nar_hash(NarHash) per entry OUTSIDE the entries lock (snapshot keys, release, derive+compare); caller-NAMED bool, in-process admit only, never a remote/CLI/RPC surface; SSOT = entries (no stored index).
- Per-path witness mint (AC#3): LAN doors mint via AdmitAllPublication (NOT allowlist-gated); public doors mint via a borrowed allowlist authority (from ApprovedPublicProvision). upstream_only: no announcer, announces nothing.
- ADDED per mped E-finding: gate withdraw(key) on announced-map membership (self-serve invariant: only retract what THIS node announced) - closes the ungated-tombstone leak codex will probe.
- Re-point daemon-libp2p/tests/public_announce_door.rs: isolated fabric+AdmitAll for the LAN positive; bootstrapped/RefusePublication fabric REFUSES the same unallowlisted LAN announce (new AC#3 bite); keep public-door empty-allowlist refusal.
- AC#4: frozen wire (RawNarV1/ContentKey/ProviderRecord/claim/golden vectors) BYTE-IDENTICAL; witness is a new in-process type only.
NOTE: mped judged the witness redundant with MECH B; kept anyway because AC#1 explicitly and repeatedly mandates the compile-time bare-record-does-not-compile property + the ~46-site signature change. Flagging transparently.
fabric-iroh has its own put_record (iroh_publication.rs) but does NOT impl AvailabilityAnnouncer and is TASK-202-prune-pending; out of scope, noted.

TASK-231 IMPLEMENTED (commit c15a3f4; not pushed; Done/AC left for orchestrator).
Gate (all green): peer-fabric OK (golden vectors BYTE-IDENTICAL - AC#4); daemon-core lib OK (contains_content_key bite); fabric-libp2p 83+16+... all suites 0 failed (incl publication_eligibility_adapter 2/2, record_lifecycle withdraw gate, discovery); daemon-libp2p 22+13+... 0 failed (public_announce_door re-point 2/2); daemon libp2p integration 4/4. cargo fmt --check clean; cargo clippy --workspace --all-targets -D warnings clean; check-no-floats clean; check-golden-vectors byte-identical; check-content-key-derivation OK; check-discovery-no-shortcut --self-test OK. just e2e: 1st run hit a PRE-EXISTING iroh fixed-port flake (shutdown_cancels_..._fixed_iroh_port, port 35907 bind race - untouched subsystem; passes in isolation); 2nd run ALL SCENARIOS PASSED (s1/s2/tamper/chain/s6-p2p).
Mutation proof: removing self.eligibility.admit(record)? in fabric-libp2p announce REDDENS announce_refuses_an_unallowlisted_record_before_reaching_the_dht (verified + restored).
Reviewer note for the DEEP gate: mped-architect judged the witness (AC#1) redundant with the announcer-authority (AC#2) and would drop it; KEPT because AC#1 explicitly and repeatedly mandates the compile-time bare-record-does-not-compile property + the ~46-site signature change. Adopted mpeds concrete findings: withdraw gate (E-hole), RefusePublication default + explicit AdmitAll opt-in, derive-outside-lock, per-fabric binding, contains_content_key in-process-admit-only.

CODEX DEEP GATE NO-GO on c15a3f4 (2 real bypasses, orchestrator-confirmed in-code). AC#1/#4 PASS. FAIL: (1) SHADOW-ANNOUNCER - announcer constructors are pub + take eligibility as an arg, so a second announcer with AdmitAllPublication on a cloned SwarmHandle announces an unallowlisted record; authority is per-instance not sealed to the fabric. (2) CROSS-MODE WITHDRAW - announced floor re-seeded from disk without mode/authority provenance and withdraw() consults only floor membership, so LAN-AdmitAll-announce K -> restart same state-dir in public mode -> withdraw(K) emits an unallowlisted tombstone to the public DHT. Fix cycle: seal authority to the fabric (downgrade pub constructors; fabric assembly is sole binder from operator mode) + withdraw() consults CURRENT eligibility before put_record + add both bites mutation-proven.
<!-- SECTION:NOTES:END -->
