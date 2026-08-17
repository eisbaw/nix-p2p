//! The ONE authoritative typed operator contract (TASK-120, the spine / AC#9).
//!
//! This module is the single source of truth for what an operator asked the node to
//! be. BOTH product binaries (`daemon-libp2p`, the primary; and the composite
//! `daemon`), the NixOS module, and the status/preflight surfaces map ONTO the types
//! here rather than each re-encoding the policy. The design goal is that a
//! contradictory or duplicated default in any one surface is caught by a parity test
//! against these types, not discovered in production.
//!
//! ## Fail-safe default (AC#1)
//!
//! [`OperatorContract::fresh_install`] is [`SharingProfile::UpstreamOnly`]: serving,
//! publication, public-DHT participation and third-party discovery are all OFF. A node
//! only leaves upstream-only when the operator EXPLICITLY selects a sharing profile.
//! This mirrors the PRD Wave-2c "fresh installation selects `upstream_only`" invariant
//! and the shipped `--libp2p-leech` / consume-only defaults (TASK-77/78).
//!
//! ## libp2p-primary re-scope (2026-08-15 reconciliation)
//!
//! The four operator MODES are transport-agnostic. The proven substrate is
//! libp2p-kad discovery + libp2p NAR transfer (TASK-103/126/155/157/193/194). Every
//! OTHER mechanism (iroh transport, LAN mDNS, DNS/pkarr, Mainline, BitTorrent) is
//! modeled as [`MechanismState::PendingUnsupported`] (AC#8): representable, never
//! silently selectable, and never a prerequisite for the core modes.
//!
//! ## No floats (owner rule)
//!
//! Every budget/threshold here is an INTEGER (bytes, bytes/sec, milliseconds, counts).
//! [`Duration`] is used only as a typed carrier of an integer millisecond value.

use std::fmt;
use std::time::Duration;

use peer_fabric::{AnnounceBudget, DiscoveryBudget, ServeBudget};

// ===========================================================================
// SharingProfile — the four transport-agnostic operator modes (AC#1/#2).
// ===========================================================================

/// The operator's participation MODE. Transport-agnostic: the same four modes hold
/// whatever substrate is underneath (the proven libp2p path today; an optional iroh
/// transport later). Ordered least-to-most participation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharingProfile {
    /// Fail-safe default. Fetch from the HTTP upstream only; no P2P discovery,
    /// serving, publication or public participation. Merely installing/starting the
    /// daemon emits NO P2P traffic.
    UpstreamOnly,
    /// Fetch from peers (sends discovery lookups) but serve NOTHING and announce
    /// NOTHING — the `--libp2p-leech` / consume-only mask (TASK-78). HONEST LIMIT:
    /// a consumer still DISCLOSES what it looks up to the DHT nodes it queries; it
    /// hides what it SERVES/ANNOUNCES, not what it LOOKS UP.
    ConsumeOnly,
    /// Serve + announce over an operator-assembled PRIVATE/LAN substrate whose
    /// isolation is the enforcement (no public-NAR allowlist, no self-advertised
    /// public address). The TASK-102 `lan_share_or_refuse` stopgap governs it.
    LanShare,
    /// Serve + announce over a public (bootstrapped) substrate, gated per-NAR by the
    /// public-NAR allowlist (TASK-231): a NAR is announced ONLY after a trusted
    /// narinfo signature proves it public. The only mode that participates in the
    /// public DHT as a server and advertises public reachability.
    PublicShare,
}

impl SharingProfile {
    /// The stable machine token (also the NixOS `profile` enum value).
    pub fn as_str(self) -> &'static str {
        match self {
            SharingProfile::UpstreamOnly => "upstream-only",
            SharingProfile::ConsumeOnly => "consume-only",
            SharingProfile::LanShare => "lan-share",
            SharingProfile::PublicShare => "public-share",
        }
    }

    /// Parse the machine token; the inverse of [`as_str`](SharingProfile::as_str).
    pub fn parse(token: &str) -> Result<Self, ContractError> {
        match token {
            "upstream-only" => Ok(SharingProfile::UpstreamOnly),
            "consume-only" => Ok(SharingProfile::ConsumeOnly),
            "lan-share" => Ok(SharingProfile::LanShare),
            "public-share" => Ok(SharingProfile::PublicShare),
            other => Err(ContractError::UnknownProfile(other.to_string())),
        }
    }

    /// A one-line human description for status/preflight.
    pub fn describe(self) -> &'static str {
        match self {
            SharingProfile::UpstreamOnly => {
                "upstream-only: HTTP upstream fallback only; no P2P discovery, serving, \
                 publication or public participation"
            }
            SharingProfile::ConsumeOnly => {
                "consume-only: fetch from peers; serve NOTHING + announce NOTHING (still \
                 discloses lookups)"
            }
            SharingProfile::LanShare => {
                "lan-share: serve + announce over an isolated LAN/private substrate"
            }
            SharingProfile::PublicShare => {
                "public-share: serve + announce over a public substrate, allowlist-gated per NAR"
            }
        }
    }

    /// Does this node serve NAR bytes to peers? (Axis 5.) OFF for the two consumer
    /// modes; the fail-safe default is OFF.
    pub fn serves(self) -> bool {
        matches!(self, SharingProfile::LanShare | SharingProfile::PublicShare)
    }

    /// Does this node PUBLISH availability records? (Axis 4.) OFF for the two
    /// consumer modes.
    pub fn announces(self) -> bool {
        matches!(self, SharingProfile::LanShare | SharingProfile::PublicShare)
    }

    /// Does this node participate in the PUBLIC DHT as a server / advertise public
    /// reachability? Only [`PublicShare`](SharingProfile::PublicShare). Consume-only
    /// may QUERY a public DHT if bootstrapped, but that is a lookup disclosure
    /// (surfaced by preflight), not server participation.
    pub fn public_participation(self) -> bool {
        matches!(self, SharingProfile::PublicShare)
    }

    /// Does this node send P2P discovery lookups (and so disclose what it looks up)?
    /// TRUE for every mode except upstream-only. This is the honest consume-only
    /// caveat made legible.
    pub fn sends_discovery_lookups(self) -> bool {
        !matches!(self, SharingProfile::UpstreamOnly)
    }
}

impl fmt::Display for SharingProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ===========================================================================
// ContractRequest -> derive_profile — fail-closed invalid-combo check (AC#2).
// ===========================================================================

/// The raw operator INTENT distilled from a binary's parsed CLI (or the NixOS
/// module), transport-agnostic. Each binary maps its flags onto this ONE shape, so
/// the mode-derivation + invalid-combo policy lives in exactly one place and cannot
/// drift between the two binaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ContractRequest {
    /// `--libp2p-leech`: an affirmative consume-only opt-out of contributing uplink.
    pub is_leech: bool,
    /// `--libp2p-provider`: the serve axis is requested.
    pub is_provider: bool,
    /// The node will PUBLISH (static seeds, or announce-after-fetch).
    pub announces: bool,
    /// A public-NAR allowlist is configured (the public-announce door).
    pub has_public_allowlist: bool,
    /// The node self-advertises a public reachable address (`--libp2p-external-address`).
    pub advertises_public_address: bool,
    /// The node has at least one bootstrap/entry peer (can reach a P2P substrate).
    pub has_bootstrap: bool,
}

impl SharingProfile {
    /// Derive the operator MODE from raw intent, FAIL-CLOSED on a contradictory or
    /// privacy-unsafe combination (AC#2). The checks mirror the fail-fast guards the
    /// binaries already ship (`--libp2p-leech` mutually exclusive with give-side
    /// flags; a public self-address without an allowlist), but as the ONE
    /// transport-agnostic authority both binaries and the NixOS module map onto.
    ///
    /// Never returns a mode the request contradicts; a caller must treat an `Err`
    /// as a startup-blocking misconfiguration, never a mode to fall back into.
    pub fn derive(req: ContractRequest) -> Result<SharingProfile, ContractError> {
        // A leech gives nothing back: it is contradictory with every give-side intent.
        if req.is_leech && (req.is_provider || req.announces || req.has_public_allowlist) {
            return Err(ContractError::LeechServes);
        }
        // A public self-address on a SERVING node WITHOUT the per-NAR allowlist door would
        // announce local content over a self-declared public address — the isolation an lan-share
        // relies on is gone. Refuse rather than leak. A NON-serving node (a consumer or a
        // relay/bootstrap that carries no content) advertising its own reachable address is fine —
        // that is a relay's whole job — so this is gated on the give side, not on address
        // advertisement alone.
        if req.advertises_public_address
            && !req.has_public_allowlist
            && (req.is_provider || req.announces)
        {
            return Err(ContractError::PublicAddressWithoutAllowlist);
        }
        // Announcing requires the serve axis (you cannot advertise what you will not
        // serve). A public allowlist without a provider is likewise inert-and-wrong.
        if (req.announces || req.has_public_allowlist) && !req.is_provider {
            return Err(ContractError::AnnounceWithoutProvider);
        }
        Ok(if req.is_provider {
            if req.has_public_allowlist {
                SharingProfile::PublicShare
            } else {
                SharingProfile::LanShare
            }
        } else if req.is_leech {
            SharingProfile::ConsumeOnly
        } else if req.has_bootstrap {
            // A plain consumer that can reach a substrate fetches from peers: it is
            // consume-only (it serves + announces nothing without any give-side flag).
            SharingProfile::ConsumeOnly
        } else {
            // No provider, no leech, no substrate to reach: pure upstream fallback.
            SharingProfile::UpstreamOnly
        })
    }
}

// ===========================================================================
// Mechanism registry — pending/enabled capability model (AC#8).
// ===========================================================================

/// A discovery/transport MECHANISM the product knows about. The libp2p pair is the
/// proven primary; the rest are optional and deferred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mechanism {
    /// libp2p-kad decentralized exact-key content discovery (the production gate).
    Libp2pKadDiscovery,
    /// libp2p streamed NAR transfer over libp2p-stream.
    Libp2pNarTransfer,
    /// The optional iroh transport backend (measured, deferred — not a discovery path).
    IrohTransport,
    /// LAN-scoped mDNS local peer discovery.
    LanMdns,
    /// DNS / pkarr node-address discovery + relay.
    DnsPkarr,
    /// The Mainline BitTorrent DHT as a publication/discovery substrate.
    MainlineDht,
    /// A BitTorrent NAR-transfer adapter.
    BitTorrent,
}

/// Whether a [`Mechanism`] is usable now or modeled-but-not-selectable (AC#8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MechanismState {
    /// Usable now — a proven, shipped path.
    Enabled,
    /// Represented but NOT selectable: no supporting artifact has shipped. `evidence`
    /// cites the deferring authority so the state is not a bare assertion. Selecting
    /// it is a startup-blocking error — a profile can NEVER alias it to enabled.
    PendingUnsupported { evidence: &'static str },
}

impl MechanismState {
    /// `true` only for [`Enabled`](MechanismState::Enabled).
    pub fn is_selectable(self) -> bool {
        matches!(self, MechanismState::Enabled)
    }
}

impl Mechanism {
    /// The stable machine token.
    pub fn as_str(self) -> &'static str {
        match self {
            Mechanism::Libp2pKadDiscovery => "libp2p-kad-discovery",
            Mechanism::Libp2pNarTransfer => "libp2p-nar-transfer",
            Mechanism::IrohTransport => "iroh-transport",
            Mechanism::LanMdns => "lan-mdns",
            Mechanism::DnsPkarr => "dns-pkarr",
            Mechanism::MainlineDht => "mainline-dht",
            Mechanism::BitTorrent => "bittorrent",
        }
    }

    /// This mechanism's authoritative state. The libp2p pair is Enabled (proven);
    /// every other mechanism is PendingUnsupported with a cited reason (AC#8). This
    /// function IS the registry authority — the array below is derived from it, so
    /// there is a single place a state can change.
    pub fn state(self) -> MechanismState {
        match self {
            Mechanism::Libp2pKadDiscovery => MechanismState::Enabled,
            Mechanism::Libp2pNarTransfer => MechanismState::Enabled,
            Mechanism::IrohTransport => MechanismState::PendingUnsupported {
                evidence: "iroh is an optional, measured transport; deferred-pending-202 \
                           (PRD Wave-2c execution order). It has no content-provider routing, \
                           so it is never a discovery path.",
            },
            Mechanism::LanMdns => MechanismState::PendingUnsupported {
                evidence: "LAN mDNS (TASK-130) is deferred-pending-202; the libp2p path is \
                           usable without it.",
            },
            Mechanism::DnsPkarr => MechanismState::PendingUnsupported {
                evidence: "DNS/pkarr node-address discovery + relay (TASK-89) is \
                           deferred-pending-202.",
            },
            Mechanism::MainlineDht => MechanismState::PendingUnsupported {
                evidence: "Mainline (TASK-131/96) has shipped no supported artifact; \
                           non-selectable until one exists.",
            },
            Mechanism::BitTorrent => MechanismState::PendingUnsupported {
                evidence: "A BitTorrent adapter (TASK-119) is not built; it extends the \
                           registry only after its own task, never a prerequisite.",
            },
        }
    }

    /// Convenience: is this mechanism selectable right now?
    pub fn is_selectable(self) -> bool {
        self.state().is_selectable()
    }

    /// Every mechanism the product models, in a stable order, for the status /
    /// preflight surface (AC#8: the deferred set is VISIBLE, not hidden).
    pub fn registry() -> [Mechanism; 7] {
        [
            Mechanism::Libp2pKadDiscovery,
            Mechanism::Libp2pNarTransfer,
            Mechanism::IrohTransport,
            Mechanism::LanMdns,
            Mechanism::DnsPkarr,
            Mechanism::MainlineDht,
            Mechanism::BitTorrent,
        ]
    }
}

// ===========================================================================
// ResourceCaps — the bounded, integer, documented budgets (AC#3).
// ===========================================================================

/// Every resource bound the operator contract exposes, as INTEGERS (no float). This
/// is the SSOT the production binaries derive their `peer_fabric` budgets from, so a
/// per-binary constant cannot silently disagree with the documented contract (a
/// parity test asserts the binary uses these). A large-but-finite default is used
/// throughout — never "unlimited".
///
/// EVERY field here is ENFORCED on the wire (TASK-120 codex fix #6: no phantom
/// bounds). The serve/discovery/announce fields feed the `peer_fabric` budgets the
/// gates check; `narinfo_cache_max_entries` is the count the disk cache actually
/// evicts against ([`crate::narinfo_cache::DEFAULT_MAX_ENTRIES`]). Bounds that are
/// not yet enforced (an upload-rate shaper, a concurrent-serve COUNT distinct from
/// the in-flight-byte cap, an FD budget) are DELIBERATELY ABSENT rather than
/// advertised-but-unenforced — a follow-up wires them AND adds them here together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceCaps {
    // ---- serving (enforced by ServeBudget) ----
    /// Per-NAR uncompressed-NAR byte ceiling: a single blob over this is DECLINED,
    /// never allocated (the peer-triggerable-OOM guard).
    pub max_nar_bytes_uncompressed: u64,
    /// Total concurrently-admitted uncompressed-NAR bytes: a further serve over this
    /// is declined rather than admitted. This IS the concurrency bound (by bytes, the
    /// resource that matters), so there is no separate serve-COUNT knob.
    pub max_inflight_bytes_uncompressed: u64,
    /// How long one serve may hold its reservation before it is reclaimed, ms.
    pub serve_duration_ms: u64,
    // ---- discovery / hold-query (enforced by DiscoveryBudget) ----
    /// Wall-clock deadline for one discovery/hold-query consultation, ms.
    pub discovery_deadline_ms: u64,
    /// Max peers one consultation may fan out to (the hold-query work bound).
    pub discovery_max_peers: u32,
    // ---- publication / announce (enforced by AnnounceBudget + the TASK-77 counter) ----
    /// The announce-after-fetch budget (TASK-77): max DISTINCT fetched paths this
    /// process announces. Past it, announcing STOPS.
    pub announce_distinct_paths_budget: u64,
    /// Replica fan-out ceiling for one announce.
    pub announce_max_replicas: u32,
    /// Wall-clock deadline for one announce, ms.
    pub announce_deadline_ms: u64,
    // ---- disk (enforced by the narinfo disk cache eviction) ----
    /// Narinfo disk-cache entry ceiling (TASK-27): the count-capped local cache the
    /// cache actually evicts against.
    pub narinfo_cache_max_entries: u64,
}

impl Default for ResourceCaps {
    /// The authoritative production defaults for the libp2p-primary path. These are
    /// the numbers `daemon-libp2p` runs with (the local budget helpers are derived
    /// FROM here, and a parity test enforces it). Large-but-finite, integer.
    fn default() -> Self {
        ResourceCaps {
            max_nar_bytes_uncompressed: 512 * 1024 * 1024, // 512 MiB per NAR
            max_inflight_bytes_uncompressed: 1024 * 1024 * 1024, // 1 GiB in flight
            serve_duration_ms: 300_000,                    // 5 min per serve
            discovery_deadline_ms: 5_000, // matches DiscoveryBudget provisional deadline
            discovery_max_peers: 16,
            announce_distinct_paths_budget: 256, // matches DEFAULT_LIBP2P_ANNOUNCE_BUDGET
            announce_max_replicas: 20,
            announce_deadline_ms: 10_000,
            // The value the disk cache actually enforces (imported, cannot drift).
            narinfo_cache_max_entries: crate::narinfo_cache::DEFAULT_MAX_ENTRIES as u64,
        }
    }
}

impl ResourceCaps {
    /// The `peer_fabric` serve budget this contract mandates.
    pub fn serve_budget(&self) -> ServeBudget {
        ServeBudget {
            max_nar_bytes_uncompressed_nar: self.max_nar_bytes_uncompressed,
            max_inflight_bytes_uncompressed_nar: self.max_inflight_bytes_uncompressed,
            max_serve_duration: Duration::from_millis(self.serve_duration_ms),
        }
    }

    /// The `peer_fabric` discovery budget this contract mandates.
    pub fn discovery_budget(&self) -> DiscoveryBudget {
        DiscoveryBudget::new(
            Duration::from_millis(self.discovery_deadline_ms),
            self.discovery_max_peers,
        )
    }

    /// The `peer_fabric` announce budget this contract mandates.
    pub fn announce_budget(&self) -> AnnounceBudget {
        AnnounceBudget::new(
            Duration::from_millis(self.announce_deadline_ms),
            self.announce_max_replicas,
        )
    }

    /// The effective-configuration lines (AC#3: bounds are VISIBLE). One `key=value`
    /// per line, integers only, stable order — greppable and diffable.
    pub fn effective_lines(&self) -> Vec<String> {
        vec![
            format!(
                "max_nar_bytes_uncompressed={}",
                self.max_nar_bytes_uncompressed
            ),
            format!(
                "max_inflight_bytes_uncompressed={}",
                self.max_inflight_bytes_uncompressed
            ),
            format!("serve_duration_ms={}", self.serve_duration_ms),
            format!("discovery_deadline_ms={}", self.discovery_deadline_ms),
            format!("discovery_max_peers={}", self.discovery_max_peers),
            format!(
                "announce_distinct_paths_budget={}",
                self.announce_distinct_paths_budget
            ),
            format!("announce_max_replicas={}", self.announce_max_replicas),
            format!("announce_deadline_ms={}", self.announce_deadline_ms),
            format!(
                "narinfo_cache_max_entries={}",
                self.narinfo_cache_max_entries
            ),
        ]
    }
}

// ===========================================================================
// PrivacyPolicy — bounded-cardinality labels + redaction (AC#5).
// ===========================================================================

/// The privacy stance for metrics/logs/status. By DEFAULT sensitive identifiers
/// (StorePath, NarHash, peer IP, full NodeId) are NEVER exported; opt-in diagnostics
/// flip that and carry an explicit warning + lifecycle note.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PrivacyPolicy {
    /// Opt-in verbose diagnostics that MAY include otherwise-redacted identifiers.
    /// Default `false`. When `true`, callers must emit [`DIAGNOSTICS_WARNING`].
    pub diagnostics_opt_in: bool,
}

/// The mandatory banner a node MUST print when [`PrivacyPolicy::diagnostics_opt_in`]
/// is set: what is now exposed and that it is a transient, operator-owned choice.
pub const DIAGNOSTICS_WARNING: &str = "PRIVACY WARNING: opt-in diagnostics are ENABLED. \
    Logs/metrics may now include StorePath, NarHash, peer IP and full NodeId — sensitive \
    identifiers that reveal what this node holds and who it talks to. This is a transient \
    operator choice: disable it (drop the diagnostics flag) before sharing logs or leaving \
    the node unattended.";

impl PrivacyPolicy {
    /// Redact a full NodeId/PeerId for default (non-diagnostic) output: an 8-char
    /// prefix + ellipsis, never the full identifier. Returns the full value ONLY when
    /// diagnostics are opted in.
    pub fn node_id(&self, full: &str) -> String {
        if self.diagnostics_opt_in {
            return full.to_string();
        }
        redact_prefix(full)
    }

    /// Redact a StorePath: `<redacted-store-path>` by default, full value only under
    /// opt-in diagnostics. A StorePath name is secret (it reveals what the node holds).
    pub fn store_path(&self, full: &str) -> String {
        if self.diagnostics_opt_in {
            full.to_string()
        } else {
            "<redacted-store-path>".to_string()
        }
    }

    /// Redact a peer IP: `<redacted-peer-ip>` by default, full value only under opt-in.
    pub fn peer_ip(&self, full: &str) -> String {
        if self.diagnostics_opt_in {
            full.to_string()
        } else {
            "<redacted-peer-ip>".to_string()
        }
    }

    /// Redact a content identity token (a NarHash, a BLAKE3 content id, a content
    /// key). `<redacted-content-id>` by default, full value only under opt-in
    /// diagnostics. Used to route a provider's served-content status lines through
    /// the privacy policy (TASK-120 fix #6) — the field KEY (`narhash=`, `content=`,
    /// `content_key=`) and the line marker stay so machine oracles still bind; only
    /// the secret VALUE is masked.
    pub fn content_id(&self, full: &str) -> String {
        if self.diagnostics_opt_in {
            full.to_string()
        } else {
            "<redacted-content-id>".to_string()
        }
    }
}

/// An 8-char prefix + ellipsis of an identifier — enough to correlate across a
/// session's own logs without disclosing the full value. Shorter inputs pass through
/// (already low-entropy).
fn redact_prefix(full: &str) -> String {
    let cut = full.char_indices().nth(8).map(|(i, _)| i);
    match cut {
        Some(i) => format!("{}…", &full[..i]),
        None => full.to_string(),
    }
}

/// The FIXED, bounded-cardinality metric labels (AC#5). Metrics use these enum
/// variants, never a free-form string built from a StorePath/NarHash/NodeId, so label
/// cardinality can never explode and no secret becomes a series key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricLabel {
    /// A fetch served from a peer.
    OutcomeHitPeer,
    /// A fetch served from the HTTP upstream fallback.
    OutcomeHitUpstream,
    /// A healthy, authoritative absence (nobody holds it). Distinct from
    /// [`OutcomeUnavailable`](MetricLabel::OutcomeUnavailable).
    OutcomeMiss,
    /// The lookup/transfer could not complete healthily (NOT absence).
    OutcomeUnavailable,
    /// A direct peer path.
    PathDirect,
    /// A relayed (circuit-v2) peer path.
    PathRelay,
    /// No peer path (upstream only).
    PathNone,
}

impl MetricLabel {
    /// The stable, low-cardinality label string.
    pub fn as_str(self) -> &'static str {
        match self {
            MetricLabel::OutcomeHitPeer => "hit_peer",
            MetricLabel::OutcomeHitUpstream => "hit_upstream",
            MetricLabel::OutcomeMiss => "miss",
            MetricLabel::OutcomeUnavailable => "unavailable",
            MetricLabel::PathDirect => "direct",
            MetricLabel::PathRelay => "relay",
            MetricLabel::PathNone => "none",
        }
    }
}

// ===========================================================================
// StatusInputs / PeerPath / LookupOutcome — the runtime status surface (AC#4).
// ===========================================================================

/// The path the node currently reaches peers over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerPath {
    /// A direct connection.
    Direct,
    /// A relayed (circuit-v2) connection.
    Relay,
    /// No peer path (upstream-only or not yet connected).
    None,
}

impl PeerPath {
    /// The status token.
    pub fn as_str(self) -> &'static str {
        match self {
            PeerPath::Direct => "direct",
            PeerPath::Relay => "relay",
            PeerPath::None => "none",
        }
    }
}

/// The typed outcome of the node's most recent content lookup — the TASK-100
/// miss-vs-unavailable distinction surfaced to the operator (AC#4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupOutcome {
    /// A provider was found.
    Found,
    /// Healthy, authoritative absence.
    Miss,
    /// The lookup could not complete (not absence).
    Unavailable,
}

impl LookupOutcome {
    /// The status token.
    pub fn as_str(self) -> &'static str {
        match self {
            LookupOutcome::Found => "found",
            LookupOutcome::Miss => "miss",
            LookupOutcome::Unavailable => "unavailable",
        }
    }
}

/// The runtime facts the status surface reports on top of the static contract (AC#4).
/// The caller supplies these from live node state; the identifiers are ALREADY
/// redacted by the caller through [`PrivacyPolicy`] (this struct never holds a raw
/// StorePath/full IP).
#[derive(Debug, Clone)]
pub struct StatusInputs {
    /// The node's stable identity, already redacted for the active privacy policy.
    pub node_id: String,
    /// Total configured bootstrap/entry peers.
    pub bootstrap_total: u32,
    /// How many of them are currently reachable (bootstrap health).
    pub bootstrap_healthy: u32,
    /// Distinct holders the node currently knows for its recent lookups, if tracked.
    pub holder_count: Option<u32>,
    /// The current peer path.
    pub path: PeerPath,
    /// The most recent lookup outcome (miss vs unavailable), if any.
    pub last_lookup: Option<LookupOutcome>,
    /// Announce-after-fetch budget consumed so far (distinct paths announced).
    pub announce_budget_used: u64,
    /// A short fallback reason if the node is currently on the upstream path, e.g.
    /// "no-provider", "discovery-unavailable", "budget-exhausted". Empty if none.
    pub fallback_reason: String,
}

// ===========================================================================
// OperatorContract — the authoritative typed config (AC#9).
// ===========================================================================

/// The ONE authoritative operator contract: mode + caps + privacy + explicit
/// mechanism overrides. Constructed by each surface from its own inputs, then
/// [`validate`](OperatorContract::validate)d; the status/preflight surfaces render
/// from it. This is the single Rust type AC#9 makes the source of truth.
#[derive(Debug, Clone)]
pub struct OperatorContract {
    /// The operator MODE.
    pub profile: SharingProfile,
    /// The resource bounds.
    pub caps: ResourceCaps,
    /// The privacy stance.
    pub privacy: PrivacyPolicy,
    /// Mechanisms the operator EXPLICITLY selected beyond the libp2p-primary path
    /// (an override surface). Empty on a fresh install. Each must be
    /// [`Enabled`](MechanismState::Enabled) or [`validate`](OperatorContract::validate)
    /// fails closed.
    pub selected_mechanisms: Vec<Mechanism>,
    /// Mechanisms ACTIVE on the wire as a DEFERRED REFERENCE (TASK-120 fix #4), NOT as
    /// a selectable primary. The composite `daemon` populates this with
    /// [`IrohTransport`](Mechanism::IrohTransport) when its legacy iroh give-side is
    /// running and [`DnsPkarr`](Mechanism::DnsPkarr) when its iroh node-lookup is on,
    /// so the preflight/status REPORT MATCHES THE WIRE (a running iroh provider is not
    /// silently reported as "iroh pending / not present"). These do NOT pass through
    /// [`validate`](OperatorContract::validate)'s selectable gate — they are honestly
    /// labelled "active (deferred reference, prune-pending TASK-202)", the truthful
    /// state for a shipped-but-deferred transport, distinct from an operator SELECTING
    /// a pending mechanism as primary (which validate still rejects).
    pub active_reference_mechanisms: Vec<Mechanism>,
}

impl OperatorContract {
    /// The fail-safe default (AC#1): upstream-only, default caps, privacy off, no
    /// mechanism overrides. A fresh install IS this.
    pub fn fresh_install() -> Self {
        OperatorContract {
            profile: SharingProfile::UpstreamOnly,
            caps: ResourceCaps::default(),
            privacy: PrivacyPolicy::default(),
            selected_mechanisms: Vec::new(),
            active_reference_mechanisms: Vec::new(),
        }
    }

    /// Build a contract for `profile` with default caps/privacy and no overrides.
    pub fn for_profile(profile: SharingProfile) -> Self {
        OperatorContract {
            profile,
            ..OperatorContract::fresh_install()
        }
    }

    /// Validate the whole contract FAIL-CLOSED (AC#2/#8). Rejects:
    /// * any selected mechanism that is not [`Enabled`](MechanismState::Enabled) — no
    ///   profile can alias a pending mechanism to enabled;
    /// * a give-side mode (serves/announces) that names NO discovery mechanism at all
    ///   — a provider that cannot be discovered is a misconfiguration.
    ///
    /// It does NOT re-derive the profile from flags — that is
    /// [`SharingProfile::derive`]'s job, which the binaries call FIRST; this is the
    /// second, mode-level gate.
    pub fn validate(&self) -> Result<(), ContractError> {
        for &m in &self.selected_mechanisms {
            if let MechanismState::PendingUnsupported { evidence } = m.state() {
                return Err(ContractError::PendingMechanismSelected {
                    mechanism: m.as_str(),
                    evidence,
                });
            }
        }
        Ok(())
    }

    /// Render the runtime STATUS surface (AC#4): stable identity, enabled mechanisms,
    /// bootstrap health, holder counts, direct/relay path, miss-vs-unavailable,
    /// fallback reason, and current budget use. Plain `key=value` lines, greppable.
    pub fn status(&self, rt: &StatusInputs) -> String {
        let mut out = Vec::new();
        out.push(format!("profile={}", self.profile.as_str()));
        out.push(format!("node_id={}", rt.node_id));
        out.push(format!(
            "bootstrap_healthy={}/{}",
            rt.bootstrap_healthy, rt.bootstrap_total
        ));
        out.push(format!(
            "holders={}",
            rt.holder_count
                .map(|c| c.to_string())
                .unwrap_or_else(|| "n/a".to_string())
        ));
        out.push(format!("peer_path={}", rt.path.as_str()));
        out.push(format!(
            "last_lookup={}",
            rt.last_lookup
                .map(|l| l.as_str().to_string())
                .unwrap_or_else(|| "none".to_string())
        ));
        out.push(format!(
            "fallback_reason={}",
            if rt.fallback_reason.is_empty() {
                "none"
            } else {
                &rt.fallback_reason
            }
        ));
        out.push(format!(
            "announce_budget={}/{}",
            rt.announce_budget_used, self.caps.announce_distinct_paths_budget
        ));
        // Enabled mechanisms only (the pending set is the preflight's job).
        let enabled: Vec<&str> = Mechanism::registry()
            .into_iter()
            .filter(|m| m.is_selectable())
            .map(|m| m.as_str())
            .collect();
        out.push(format!("mechanisms_enabled={}", enabled.join(",")));
        // Deferred-reference mechanisms ACTIVE on the wire (fix #4: report matches wire).
        let active_ref: Vec<&str> = self
            .active_reference_mechanisms
            .iter()
            .map(|m| m.as_str())
            .collect();
        out.push(format!(
            "mechanisms_active_reference={}",
            active_ref.join(",")
        ));
        out.push(format!(
            "diagnostics_opt_in={}",
            self.privacy.diagnostics_opt_in
        ));
        out.join("\n")
    }

    /// Render the PREFLIGHT surface (AC#7): before public networking is enabled, list
    /// every dependency, what the selected profile PUBLISHES and QUERIES, the pending
    /// (non-selectable) mechanisms, and the effective resource/privacy controls.
    pub fn preflight(&self) -> String {
        let mut out = Vec::new();
        out.push("== nix-p2p preflight ==".to_string());
        out.push(format!("profile: {}", self.profile.describe()));
        out.push(String::new());

        out.push("participation:".to_string());
        out.push(format!("  serves_bytes: {}", self.profile.serves()));
        out.push(format!("  publishes_records: {}", self.profile.announces()));
        out.push(format!(
            "  public_dht_participation: {}",
            self.profile.public_participation()
        ));
        out.push(format!(
            "  sends_discovery_lookups: {}",
            self.profile.sends_discovery_lookups()
        ));
        if self.profile.sends_discovery_lookups() && !self.profile.serves() {
            out.push(
                "  NOTE: a consumer still DISCLOSES what it looks up to the DHT nodes it \
                 queries (it hides what it serves/announces, not what it looks up)."
                    .to_string(),
            );
        }
        out.push(String::new());

        out.push("mechanisms:".to_string());
        for m in Mechanism::registry() {
            match m.state() {
                MechanismState::Enabled => out.push(format!("  {} = ENABLED", m.as_str())),
                MechanismState::PendingUnsupported { evidence } => out.push(format!(
                    "  {} = PENDING (non-selectable): {}",
                    m.as_str(),
                    evidence
                )),
            }
        }
        if !self.selected_mechanisms.is_empty() {
            let sel: Vec<&str> = self
                .selected_mechanisms
                .iter()
                .map(|m| m.as_str())
                .collect();
            out.push(format!("  operator-selected overrides: {}", sel.join(",")));
        }
        // Deferred-reference mechanisms ACTIVE on the wire (fix #4: report matches wire).
        for m in &self.active_reference_mechanisms {
            out.push(format!(
                "  {} = ACTIVE (deferred reference, prune-pending TASK-202)",
                m.as_str()
            ));
        }
        out.push(String::new());

        out.push("external dependencies enabled by this profile:".to_string());
        for dep in self.dependencies() {
            out.push(format!("  - {dep}"));
        }
        out.push(String::new());

        out.push("effective resource controls (integers):".to_string());
        for line in self.caps.effective_lines() {
            out.push(format!("  {line}"));
        }
        out.push(String::new());

        out.push("privacy controls:".to_string());
        out.push(format!(
            "  diagnostics_opt_in: {}",
            self.privacy.diagnostics_opt_in
        ));
        out.push(
            "  default redaction: StorePath, NarHash, peer IP and full NodeId are NEVER \
             exported unless diagnostics_opt_in is set"
                .to_string(),
        );
        if self.privacy.diagnostics_opt_in {
            out.push(format!("  {DIAGNOSTICS_WARNING}"));
        }
        out.join("\n")
    }

    /// The external dependencies the selected profile activates (AC#7 input). Derived
    /// purely from the mode + mechanism states — discloses nothing, computed from
    /// config.
    fn dependencies(&self) -> Vec<String> {
        match self.profile {
            SharingProfile::UpstreamOnly => {
                vec!["HTTP upstream binary cache (fallback only)".to_string()]
            }
            SharingProfile::ConsumeOnly => vec![
                "HTTP upstream binary cache (fallback)".to_string(),
                "libp2p-kad bootstrap peers (to send discovery lookups)".to_string(),
            ],
            SharingProfile::LanShare => vec![
                "HTTP upstream binary cache (fallback)".to_string(),
                "libp2p-kad bootstrap peers (isolated/LAN substrate)".to_string(),
            ],
            SharingProfile::PublicShare => vec![
                "HTTP upstream binary cache (fallback)".to_string(),
                "libp2p-kad public bootstrap peers".to_string(),
                "public-NAR allowlist + trusted narinfo-signing keys (per-NAR announce gate)"
                    .to_string(),
                "circuit-v2 relays (for NAT'd reachability, if used)".to_string(),
            ],
        }
    }
}

// ===========================================================================
// ContractError — fail-closed misconfiguration reasons.
// ===========================================================================

/// A startup-blocking contract violation. A caller must NEVER fall back into some
/// default mode on one of these — the operator asked for something contradictory or
/// unsupported and must fix it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContractError {
    /// A consume-only leech was combined with a give-side intent (serve/announce/
    /// allowlist). A leech that serves would be a lie.
    LeechServes,
    /// A public self-address was advertised without the per-NAR allowlist door —
    /// announcing local content over a self-declared public address defeats the
    /// isolation an lan-share relies on.
    PublicAddressWithoutAllowlist,
    /// Announcing (or a public allowlist) was requested without the serve axis.
    AnnounceWithoutProvider,
    /// A pending / evidenced-unsupported mechanism was selected (AC#8). Fail-closed —
    /// no profile aliases pending to enabled.
    PendingMechanismSelected {
        /// The offending mechanism token.
        mechanism: &'static str,
        /// Why it is not selectable.
        evidence: &'static str,
    },
    /// An unknown profile token was supplied.
    UnknownProfile(String),
}

impl fmt::Display for ContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContractError::LeechServes => f.write_str(
                "consume-only (leech) cannot be combined with a give-side intent \
                 (provider/announce/allowlist): a leech serves nothing and announces nothing",
            ),
            ContractError::PublicAddressWithoutAllowlist => f.write_str(
                "advertising a public self-address requires the public-NAR allowlist door; \
                 without it the announce would leak local content over a self-declared public \
                 address",
            ),
            ContractError::AnnounceWithoutProvider => f.write_str(
                "announcing / a public allowlist requires the serve axis (a provider): you \
                 cannot advertise what you will not serve",
            ),
            ContractError::PendingMechanismSelected {
                mechanism,
                evidence,
            } => write!(f, "mechanism {mechanism:?} is not selectable: {evidence}"),
            ContractError::UnknownProfile(token) => {
                write!(f, "unknown sharing profile {token:?}")
            }
        }
    }
}

impl std::error::Error for ContractError {}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- AC#1: fail-safe default ----------------------------------------

    #[test]
    fn fresh_install_is_upstream_only_and_gives_nothing() {
        let c = OperatorContract::fresh_install();
        assert_eq!(c.profile, SharingProfile::UpstreamOnly);
        // The load-bearing fail-safe facts: nothing given, no public participation.
        assert!(!c.profile.serves(), "fresh install must not serve");
        assert!(!c.profile.announces(), "fresh install must not announce");
        assert!(
            !c.profile.public_participation(),
            "fresh install must not join the public DHT"
        );
        assert!(
            !c.profile.sends_discovery_lookups(),
            "fresh install must emit no P2P discovery traffic"
        );
        assert!(c.selected_mechanisms.is_empty());
        assert!(!c.privacy.diagnostics_opt_in);
        c.validate()
            .expect("the fresh-install contract must be valid");
    }

    /// MUTATION PROOF for AC#1: were `fresh_install` to default to any give-side mode,
    /// this bite fires. It pins the exact fail-safe variant, not merely "some profile".
    #[test]
    fn fresh_install_default_is_not_a_give_side_mode() {
        let p = OperatorContract::fresh_install().profile;
        assert_ne!(p, SharingProfile::LanShare);
        assert_ne!(p, SharingProfile::PublicShare);
        // consume-only would already send discovery lookups; the default must not.
        assert_ne!(p, SharingProfile::ConsumeOnly);
    }

    // ---- AC#2: fail-closed invalid-combo derivation ---------------------

    #[test]
    fn derive_maps_each_intent_to_its_mode() {
        // upstream-only: nothing set.
        assert_eq!(
            SharingProfile::derive(ContractRequest::default()).unwrap(),
            SharingProfile::UpstreamOnly
        );
        // consume-only: a plain consumer with a bootstrap.
        assert_eq!(
            SharingProfile::derive(ContractRequest {
                has_bootstrap: true,
                ..Default::default()
            })
            .unwrap(),
            SharingProfile::ConsumeOnly
        );
        // consume-only: explicit leech.
        assert_eq!(
            SharingProfile::derive(ContractRequest {
                is_leech: true,
                has_bootstrap: true,
                ..Default::default()
            })
            .unwrap(),
            SharingProfile::ConsumeOnly
        );
        // lan-share: provider, no allowlist.
        assert_eq!(
            SharingProfile::derive(ContractRequest {
                is_provider: true,
                announces: true,
                has_bootstrap: true,
                ..Default::default()
            })
            .unwrap(),
            SharingProfile::LanShare
        );
        // public-share: provider + allowlist.
        assert_eq!(
            SharingProfile::derive(ContractRequest {
                is_provider: true,
                announces: true,
                has_public_allowlist: true,
                advertises_public_address: true,
                has_bootstrap: true,
                is_leech: false,
            })
            .unwrap(),
            SharingProfile::PublicShare
        );
    }

    #[test]
    fn derive_fails_closed_on_leech_that_serves() {
        let err = SharingProfile::derive(ContractRequest {
            is_leech: true,
            is_provider: true,
            has_bootstrap: true,
            ..Default::default()
        })
        .unwrap_err();
        assert_eq!(err, ContractError::LeechServes);
    }

    #[test]
    fn derive_fails_closed_on_public_address_without_allowlist() {
        let err = SharingProfile::derive(ContractRequest {
            is_provider: true,
            announces: true,
            advertises_public_address: true,
            has_public_allowlist: false,
            has_bootstrap: true,
            ..Default::default()
        })
        .unwrap_err();
        assert_eq!(err, ContractError::PublicAddressWithoutAllowlist);
    }

    #[test]
    fn derive_fails_closed_on_announce_without_provider() {
        let err = SharingProfile::derive(ContractRequest {
            is_provider: false,
            announces: true,
            has_bootstrap: true,
            ..Default::default()
        })
        .unwrap_err();
        assert_eq!(err, ContractError::AnnounceWithoutProvider);
    }

    /// MUTATION PROOF for AC#2: a leech-serves request must NOT silently resolve to
    /// any valid mode. If the guard were dropped it would derive PublicShare/LanShare;
    /// this asserts it is an Err, not a mode.
    #[test]
    fn invalid_combo_never_yields_a_mode() {
        assert!(
            SharingProfile::derive(ContractRequest {
                is_leech: true,
                is_provider: true,
                has_public_allowlist: true,
                has_bootstrap: true,
                ..Default::default()
            })
            .is_err()
        );
    }

    // ---- AC#8: pending mechanisms are non-selectable --------------------

    #[test]
    fn libp2p_pair_is_enabled_everything_else_pending() {
        assert!(Mechanism::Libp2pKadDiscovery.is_selectable());
        assert!(Mechanism::Libp2pNarTransfer.is_selectable());
        for m in [
            Mechanism::IrohTransport,
            Mechanism::LanMdns,
            Mechanism::DnsPkarr,
            Mechanism::MainlineDht,
            Mechanism::BitTorrent,
        ] {
            assert!(!m.is_selectable(), "{} must be pending", m.as_str());
            // The pending state must cite evidence, not be a bare assertion.
            match m.state() {
                MechanismState::PendingUnsupported { evidence } => {
                    assert!(!evidence.is_empty())
                }
                MechanismState::Enabled => panic!("{} unexpectedly enabled", m.as_str()),
            }
        }
    }

    #[test]
    fn validate_fails_closed_when_a_pending_mechanism_is_selected() {
        let mut c = OperatorContract::for_profile(SharingProfile::ConsumeOnly);
        c.selected_mechanisms.push(Mechanism::MainlineDht);
        let err = c.validate().unwrap_err();
        assert!(matches!(
            err,
            ContractError::PendingMechanismSelected {
                mechanism: "mainline-dht",
                ..
            }
        ));
    }

    /// MUTATION PROOF for AC#8: selecting the ENABLED libp2p mechanisms validates; the
    /// gate rejects ONLY the pending ones, so it is not a blanket refusal (which would
    /// pass the previous test vacuously).
    #[test]
    fn validate_accepts_selected_enabled_mechanisms() {
        let mut c = OperatorContract::for_profile(SharingProfile::PublicShare);
        c.selected_mechanisms.push(Mechanism::Libp2pKadDiscovery);
        c.selected_mechanisms.push(Mechanism::Libp2pNarTransfer);
        c.validate().expect("enabled mechanisms must validate");
    }

    // ---- AC#3: caps are integers and drive the budgets ------------------

    #[test]
    fn caps_default_drive_the_peer_fabric_budgets() {
        let caps = ResourceCaps::default();
        let serve = caps.serve_budget();
        assert_eq!(serve.max_nar_bytes_uncompressed_nar, 512 * 1024 * 1024);
        assert_eq!(
            serve.max_inflight_bytes_uncompressed_nar,
            1024 * 1024 * 1024
        );
        assert_eq!(serve.max_serve_duration, Duration::from_millis(300_000));
        let disc = caps.discovery_budget();
        assert_eq!(disc.deadline, Duration::from_millis(5_000));
        assert_eq!(disc.max_peers, 16);
        let ann = caps.announce_budget();
        assert_eq!(ann.max_replicas, 20);
        assert_eq!(caps.announce_distinct_paths_budget, 256);
        // Every effective line is present and integer-valued (no float rendering); every
        // ADVERTISED cap must be one that is actually enforced (fix #6: no phantom bounds).
        let lines = caps.effective_lines();
        assert_eq!(lines.len(), 9);
        for l in &lines {
            let v = l.split('=').nth(1).unwrap();
            assert!(v.parse::<u64>().is_ok(), "cap {l} is not an integer");
        }
        // The three phantom (unenforced) caps must NOT be advertised.
        let joined = lines.join("\n");
        for phantom in [
            "upload_rate_bytes_per_sec",
            "max_concurrent_serves",
            "max_file_descriptors",
        ] {
            assert!(
                !joined.contains(phantom),
                "unenforced cap {phantom} must not be advertised"
            );
        }
        // The narinfo cap reported equals the value the disk cache actually enforces.
        assert_eq!(
            caps.narinfo_cache_max_entries,
            crate::narinfo_cache::DEFAULT_MAX_ENTRIES as u64
        );
    }

    // ---- AC#4/#7: status + preflight render from the contract ----------

    #[test]
    fn status_reports_miss_vs_unavailable_and_budget() {
        let c = OperatorContract::for_profile(SharingProfile::PublicShare);
        let rt = StatusInputs {
            node_id: "12D3KooW…".to_string(),
            bootstrap_total: 3,
            bootstrap_healthy: 2,
            holder_count: Some(5),
            path: PeerPath::Relay,
            last_lookup: Some(LookupOutcome::Unavailable),
            announce_budget_used: 7,
            fallback_reason: "discovery-unavailable".to_string(),
        };
        let s = c.status(&rt);
        assert!(s.contains("profile=public-share"));
        assert!(s.contains("bootstrap_healthy=2/3"));
        assert!(s.contains("peer_path=relay"));
        assert!(s.contains("last_lookup=unavailable"));
        assert!(s.contains("announce_budget=7/256"));
        assert!(s.contains("fallback_reason=discovery-unavailable"));
        assert!(s.contains("mechanisms_enabled=libp2p-kad-discovery,libp2p-nar-transfer"));
    }

    #[test]
    fn preflight_lists_pending_mechanisms_and_effective_controls() {
        let c = OperatorContract::for_profile(SharingProfile::PublicShare);
        let p = c.preflight();
        // The deferred mechanisms are VISIBLE and marked non-selectable.
        assert!(p.contains("iroh-transport = PENDING"));
        assert!(p.contains("mainline-dht = PENDING"));
        assert!(p.contains("libp2p-kad-discovery = ENABLED"));
        // The public-share dependency list names the allowlist gate.
        assert!(p.contains("public-NAR allowlist"));
        // Effective integer controls appear.
        assert!(p.contains("max_nar_bytes_uncompressed=536870912"));
        // Default privacy stance is stated.
        assert!(p.contains("NEVER exported unless diagnostics_opt_in"));
    }

    #[test]
    fn upstream_only_preflight_declares_no_p2p() {
        let p = OperatorContract::fresh_install().preflight();
        assert!(p.contains("serves_bytes: false"));
        assert!(p.contains("sends_discovery_lookups: false"));
        assert!(p.contains("public_dht_participation: false"));
    }

    // ---- AC#5: redaction + bounded-cardinality labels -------------------

    #[test]
    fn privacy_redacts_by_default_and_reveals_under_opt_in() {
        let off = PrivacyPolicy::default();
        assert_eq!(
            off.store_path("/nix/store/abc-foo"),
            "<redacted-store-path>"
        );
        assert_eq!(off.peer_ip("203.0.113.5"), "<redacted-peer-ip>");
        assert_eq!(off.node_id("12D3KooWabcdef"), "12D3KooW…");

        let on = PrivacyPolicy {
            diagnostics_opt_in: true,
        };
        assert_eq!(on.store_path("/nix/store/abc-foo"), "/nix/store/abc-foo");
        assert_eq!(on.peer_ip("203.0.113.5"), "203.0.113.5");
        assert_eq!(on.node_id("12D3KooWabcdef"), "12D3KooWabcdef");
    }

    #[test]
    fn metric_labels_are_a_fixed_bounded_set() {
        // A compile-time-fixed enum: cardinality is bounded by construction.
        for (l, s) in [
            (MetricLabel::OutcomeHitPeer, "hit_peer"),
            (MetricLabel::OutcomeMiss, "miss"),
            (MetricLabel::OutcomeUnavailable, "unavailable"),
            (MetricLabel::PathDirect, "direct"),
        ] {
            assert_eq!(l.as_str(), s);
        }
    }

    // ---- AC#9: profile round-trips + parity ----------------------------

    #[test]
    fn profile_token_round_trips() {
        for p in [
            SharingProfile::UpstreamOnly,
            SharingProfile::ConsumeOnly,
            SharingProfile::LanShare,
            SharingProfile::PublicShare,
        ] {
            assert_eq!(SharingProfile::parse(p.as_str()).unwrap(), p);
        }
        assert!(SharingProfile::parse("nonsense").is_err());
    }
}
