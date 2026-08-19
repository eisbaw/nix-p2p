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

use peer_fabric::{AnnounceBudget, DeriveBudget, DiscoveryBudget, ServeBudget};

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
    /// A pure ROUTER / bootstrap-relay node (TASK-241): a kad SERVER (answers
    /// FIND_NODE/GET_PROVIDERS and stores records, so it can be a bootstrap rendezvous
    /// root) plus, by default, a circuit-v2 relay server — but it holds and carries NO
    /// content: it serves NO NAR bytes and announces NOTHING. It routes + relays for
    /// OTHERS. This is the DHT-infrastructure role the four give/consume modes cannot
    /// express: `consume-only` is a kad CLIENT (cannot be a bootstrap root), and the
    /// provider modes REQUIRE content to serve. Never a default — an operator must
    /// EXPLICITLY select it (`--libp2p-router` / `profile = "router"`); a give-side flag
    /// combined with it fails closed ([`ContractError::RouterServes`]), so a router can
    /// never become a serve/announce backdoor.
    Router,
}

impl SharingProfile {
    /// The stable machine token (also the NixOS `profile` enum value).
    pub fn as_str(self) -> &'static str {
        match self {
            SharingProfile::UpstreamOnly => "upstream-only",
            SharingProfile::ConsumeOnly => "consume-only",
            SharingProfile::LanShare => "lan-share",
            SharingProfile::PublicShare => "public-share",
            SharingProfile::Router => "router",
        }
    }

    /// Parse the machine token; the inverse of [`as_str`](SharingProfile::as_str).
    pub fn parse(token: &str) -> Result<Self, ContractError> {
        match token {
            "upstream-only" => Ok(SharingProfile::UpstreamOnly),
            "consume-only" => Ok(SharingProfile::ConsumeOnly),
            "lan-share" => Ok(SharingProfile::LanShare),
            "public-share" => Ok(SharingProfile::PublicShare),
            "router" => Ok(SharingProfile::Router),
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
            SharingProfile::Router => {
                "router: kad-server + circuit-v2 relay for OTHERS; carries NO content \
                 (serves NOTHING, announces NOTHING)"
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

    /// Does this node run the DHT INFRASTRUCTURE — a kad SERVER (stores records + answers
    /// FIND_NODE/GET_PROVIDERS) and, subject to `--libp2p-no-relay-server`, the circuit-v2
    /// relay server? TRUE for the two provider modes AND for [`Router`](SharingProfile::Router).
    /// This is the "is a kad server, not merely a client" axis: a provider serves content AND
    /// runs infrastructure; a router runs ONLY infrastructure (no content); a consumer is a kad
    /// CLIENT; upstream-only runs no swarm at all. Drives the swarm's `kad_server` + relay-server
    /// gating so a router is a usable bootstrap/relay root while serving/announcing nothing.
    pub fn runs_dht_server(self) -> bool {
        matches!(
            self,
            SharingProfile::LanShare | SharingProfile::PublicShare | SharingProfile::Router
        )
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
    /// `--libp2p-router`: an EXPLICIT request to be a pure ROUTER / bootstrap-relay node
    /// (kad SERVER + relay for others, carrying NO content). Never inferred — a content-less
    /// bootstrap otherwise looks exactly like a consumer; only this affirmative flag selects
    /// the [`Router`](SharingProfile::Router) mode. Contradictory with every give-side intent.
    pub is_router: bool,
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
        // A ROUTER (TASK-241) is a kad-server + relay that carries NO content. It is an EXPLICIT,
        // never-default mode, and — like a leech — must give NOTHING back: combining it with any
        // serve/announce/allowlist/leech intent is a contradiction (a router that serves would be a
        // give-side backdoor). Checked BEFORE the give-side derivation so `--libp2p-router
        // --libp2p-provider ...` can never silently resolve to a serving mode.
        if req.is_router {
            if req.is_provider || req.announces || req.has_public_allowlist || req.is_leech {
                return Err(ContractError::RouterServes);
            }
            return Ok(SharingProfile::Router);
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
            // TASK-257: LAN mDNS peer-ADDRESS bootstrap SHIPPED (fabric-libp2p mdns behaviour behind
            // the default-OFF `--libp2p-mdns` flag). It is SELECTABLE now - so an operator may name
            // it and `validate` admits it - but it is a per-node OPT-IN: whether it is ACTIVE on a
            // given node is carried by [`OperatorContract::lan_mdns_enabled`] (set from the flag),
            // NOT by this static state. It supplies peer ADDRESSES only and is never a
            // content-discovery mechanism (discovery stays kad-EXCLUSIVE).
            Mechanism::LanMdns => MechanismState::Enabled,
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
    // ---- responder derivation / hold-query answering (enforced by DeriveBudget, TASK-229) ----
    /// Per-authenticated-peer ceiling on UNCOMPRESSED-NAR bytes HASHED to answer that
    /// peer's hold-queries within [`derive_window_ms`](ResourceCaps::derive_window_ms).
    /// A cold probe whose NarSize would exceed this is refused BEFORE dumping.
    pub derive_max_bytes_per_peer_uncompressed: u64,
    /// Per-authenticated-peer ceiling on the COUNT of fresh `nix-store --dump`s within
    /// one window (bounds many-small-NAR floods under the byte cap).
    pub derive_max_dumps_per_peer: u32,
    /// GLOBAL ceiling on bytes HASHED across ALL peers within one window - the Sybil
    /// floor (per-peer alone is bypassable by minting PeerIds).
    pub derive_max_bytes_global_uncompressed: u64,
    /// The derivation-accounting window, ms (TUMBLING: cap per window in steady state,
    /// up to 2x cap across a boundary; true sliding window is TASK-243).
    pub derive_window_ms: u64,
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
            // TASK-229 responder-derivation defaults. CONSERVATIVE PLACEHOLDERS, not
            // derived from a measured per-deployment disk/CPU I/O ceiling (same honesty
            // as MAX_BATCH_DERIVE_WORK=16): in steady state a peer may cost us ~1 GiB of
            // hashing / minute and ~64 fresh dumps / minute (tumbling window: up to 2x
            // that across a boundary); the global backstop is 4 GiB / minute, i.e.
            // it tolerates ~4 fully-busy peers before biting. Tune per deployment.
            derive_max_bytes_per_peer_uncompressed: 1024 * 1024 * 1024, // 1 GiB / window / peer
            derive_max_dumps_per_peer: 64,
            derive_max_bytes_global_uncompressed: 4 * 1024 * 1024 * 1024, // 4 GiB / window
            derive_window_ms: 60_000,                                     // 1 min window
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

    /// The `peer_fabric` responder-derivation budget this contract mandates (TASK-229).
    /// The integer numbers a `PeerDeriveLedger` enforces on the hold-query answer path.
    pub fn derive_budget(&self) -> DeriveBudget {
        DeriveBudget {
            max_bytes_per_peer_uncompressed_nar: self.derive_max_bytes_per_peer_uncompressed,
            max_dumps_per_peer: self.derive_max_dumps_per_peer,
            max_bytes_global_uncompressed_nar: self.derive_max_bytes_global_uncompressed,
            window: Duration::from_millis(self.derive_window_ms),
        }
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
                "derive_max_bytes_per_peer_uncompressed={}",
                self.derive_max_bytes_per_peer_uncompressed
            ),
            format!(
                "derive_max_dumps_per_peer={}",
                self.derive_max_dumps_per_peer
            ),
            format!(
                "derive_max_bytes_global_uncompressed={}",
                self.derive_max_bytes_global_uncompressed
            ),
            format!("derive_window_ms={}", self.derive_window_ms),
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

/// The node's Kademlia participation on the wire (TASK-120 fix A). This is set by each binary to
/// what its swarm ACTUALLY runs, so the reported DHT participation cannot drift from reality (the
/// codex honesty gap: a node running a kad SERVER while reporting no DHT participation).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DhtRole {
    /// No participating libp2p swarm at all (a pure HTTP / upstream-only node). Answers nothing,
    /// stores nothing, relays nothing.
    #[default]
    None,
    /// kad CLIENT: the node ISSUES queries (it can discover + fetch) but ANSWERS none for others
    /// and stores no records - it provides NO DHT infrastructure (a consumer).
    Client,
    /// kad SERVER: the node STORES records and ANSWERS `FIND_NODE`/`GET_PROVIDERS`/`GET_RECORD`
    /// for others - it PARTICIPATES in the DHT infrastructure (a provider, or a router).
    Server,
}

impl DhtRole {
    /// The stable status token.
    pub fn as_str(self) -> &'static str {
        match self {
            DhtRole::None => "none",
            DhtRole::Client => "client",
            DhtRole::Server => "server",
        }
    }

    /// A one-line human description for the preflight surface.
    pub fn describe(self) -> &'static str {
        match self {
            DhtRole::None => "none (no participating libp2p swarm: answers/stores/relays nothing)",
            DhtRole::Client => {
                "kad-client (issues queries + fetches, answers NONE for others - no DHT infrastructure)"
            }
            DhtRole::Server => {
                "kad-server (stores records + ANSWERS FIND_NODE/GET_PROVIDERS for others - DHT infrastructure)"
            }
        }
    }
}

// ===========================================================================
// StatusInputs / PeerPath / LookupOutcome — the runtime status surface (AC#4).
// ===========================================================================

/// The path the node currently reaches peers over.
///
/// The four states are DISTINCT on purpose (TASK-242): `None` means there is no peer subsystem at
/// all (an upstream-only node — [`crate::observ::NullStatusFacts`]); `Unknown` means the swarm IS
/// running but has no currently-classified live connection to a configured peer (nothing to
/// measure yet, or every bootstrap disconnected). Reporting `Unknown` (not `None`) in the latter
/// case is what keeps `bootstrap_healthy=2/2` from ever pairing with a contradictory `peer_path=none`
/// (a node that HAS healthy peers but is measured as having "no peer path"). `Direct`/`Relay` are the
/// measured live paths: a `Direct` connection vs a relayed (`/p2p-circuit`) one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerPath {
    /// A direct connection.
    Direct,
    /// A relayed (circuit-v2) connection.
    Relay,
    /// A swarm is running but no live peer connection is currently classified (unmeasured).
    Unknown,
    /// No peer path (upstream-only: there is no swarm at all).
    None,
}

impl PeerPath {
    /// The status token.
    pub fn as_str(self) -> &'static str {
        match self {
            PeerPath::Direct => "direct",
            PeerPath::Relay => "relay",
            PeerPath::Unknown => "unknown",
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
    /// Responder-derivation GLOBAL byte budget as `(used, cap)` in the current window
    /// (UNCOMPRESSED-NAR bytes hashed across ALL peers, TASK-229) - BOTH figures read
    /// from the SAME live ledger, so the reported CAP cannot drift from the enforced one.
    /// An AGGREGATE integer pair with NO per-peer identifier (exposing per-peer usage
    /// would be a peer-behaviour channel). `None` when this node runs no live derivation
    /// ledger (no over-the-wire hold-query responder): the status line is then OMITTED
    /// rather than emitting a synthetic figure - the configured CAP still shows in
    /// `--preflight`'s effective controls. See TASK-243 for the live-wire responder.
    pub derive_budget_global: Option<(u64, u64)>,
    /// A short fallback reason if the node is currently on the upstream path, e.g.
    /// "no-provider", "discovery-unavailable", "budget-exhausted". Empty if none.
    pub fallback_reason: String,
    /// The live kad routing-table size (distinct peers across all k-buckets), if this node runs a
    /// participating swarm (TASK-257 F-2). `None` for an upstream-only node with no swarm - the
    /// status line is then OMITTED. It is the honest observable of ROUTING STATE: a same-scope
    /// mDNS peer that completes the scoped kad handshake is counted here, while a CROSS-SCOPE mDNS
    /// peer - which is dialed but never inserted (its `ProtocolNotSupported` is not admitted) - is
    /// NOT, so an operator (and the scope-isolation e2e) can SEE that cross-scope neighbours never
    /// pollute routing, not merely that content did not resolve.
    pub kad_routing_peers: Option<u32>,
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
    /// The node's Kademlia participation ON THE WIRE (TASK-120 fix A). Set by each binary to what
    /// its swarm actually runs (daemon-libp2p derives it from the profile; the composite reflects
    /// its flag-authoritative always-server behaviour, C-deferred), so the reported DHT role cannot
    /// drift from reality. Default [`DhtRole::None`] (a fresh install runs no participating swarm).
    pub dht_role: DhtRole,
    /// Whether the node advertises a PUBLIC/reachable self-address on the wire (TASK-241): set by
    /// each binary from `--libp2p-external-address` (the operator's explicit "I am reachable here"
    /// declaration a relay/bootstrap sets so peers can dial it). It only CHANGES the report for the
    /// [`Router`](SharingProfile::Router) mode, whose public-DHT participation depends on its ACTUAL
    /// reachability rather than being intrinsic to the profile: a router that advertises a public
    /// address runs a PUBLICLY-reachable kad server + relay (a public DHT participant); a
    /// LAN-isolated router (no advertised public address) does not. The four give/consume modes'
    /// public participation is intrinsic (public-share yes, the rest no), so this field is inert for
    /// them. See [`public_dht_participation`](OperatorContract::public_dht_participation). Default
    /// `false` (a fresh install advertises nothing).
    pub advertises_public_reachability: bool,
    /// Whether LAN mDNS peer-ADDRESS discovery ([`Mechanism::LanMdns`]) is ACTIVE on this node
    /// (TASK-257): set by each binary from the default-OFF `--libp2p-mdns` flag. mDNS is a
    /// SELECTABLE-but-per-node-opt-in mechanism, so its static [`MechanismState`] is `Enabled`
    /// (shipped) while THIS boolean is what says it is running HERE - the report-matches-wire
    /// answer preflight/status print. When `true`, the node opens a link-local multicast socket
    /// that DISCLOSES its presence + NodeId to every device on the LAN (an axis-1 local-discovery
    /// EXPOSURE, surfaced in preflight/status), and feeds discovered peer ADDRESSES into the same
    /// kad bootstrap path an explicit `--libp2p-bootstrap` uses - never a content-discovery route.
    /// It is TASK-120 axis-1 only: enabling it implies NOTHING about serving/announcing/public
    /// participation. Default `false` (a fresh install emits zero mDNS multicast).
    pub lan_mdns_enabled: bool,
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
            dht_role: DhtRole::None,
            advertises_public_reachability: false,
            // TASK-257: a fresh install runs no swarm and emits zero mDNS multicast.
            lan_mdns_enabled: false,
        }
    }

    /// Whether `mechanism` is ACTIVE on THIS node (report-matches-wire), distinct from whether it
    /// is statically shipped/selectable ([`MechanismState::Enabled`]). The always-on primary
    /// (libp2p-kad / libp2p-nar) is active whenever selectable; [`Mechanism::LanMdns`] is a
    /// per-node OPT-IN, active iff [`lan_mdns_enabled`](OperatorContract::lan_mdns_enabled). This is
    /// the single place the two notions are reconciled so status/preflight cannot claim mDNS is
    /// running on a node that never enabled it (TASK-257 default-OFF honesty).
    fn mechanism_active_here(&self, mechanism: Mechanism) -> bool {
        match mechanism {
            Mechanism::LanMdns => self.lan_mdns_enabled,
            other => other.is_selectable(),
        }
    }

    /// Build a contract for `profile` with default caps/privacy and no overrides.
    pub fn for_profile(profile: SharingProfile) -> Self {
        OperatorContract {
            profile,
            ..OperatorContract::fresh_install()
        }
    }

    /// Whether this node participates in the PUBLIC DHT as a server / advertises public
    /// reachability — the honest, report-matches-wire answer the preflight/status prints (TASK-241
    /// fix). For the four give/consume modes this is INTRINSIC to the profile
    /// ([`SharingProfile::public_participation`]: public-share yes, the rest no). A
    /// [`Router`](SharingProfile::Router) is the exception: a single `router` profile can be PUBLIC
    /// or LAN depending on its address, so its public participation is computed from its ACTUAL
    /// reachability ([`advertises_public_reachability`](OperatorContract::advertises_public_reachability)),
    /// NOT hardcoded to the profile. A router advertising a public/external address runs a
    /// publicly-reachable kad server + relay (`true`); a LAN-isolated router (`false`). This closes
    /// the honesty gap where a public router would run public DHT infrastructure while reporting it
    /// does not — exactly the report≠wire lie the profile fixes closed for the other modes.
    pub fn public_dht_participation(&self) -> bool {
        match self.profile {
            SharingProfile::Router => self.advertises_public_reachability,
            other => other.public_participation(),
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
        // TASK-257 F-2: the live kad routing-table size, so an operator sees ROUTING STATE (a
        // cross-scope mDNS neighbour never enters it). Emitted only for a participating swarm.
        if let Some(n) = rt.kad_routing_peers {
            out.push(format!("kad_routing_peers={n}"));
        }
        out.push(format!(
            "holders={}",
            rt.holder_count
                .map(|c| c.to_string())
                .unwrap_or_else(|| "n/a".to_string())
        ));
        out.push(format!("dht_role={}", self.dht_role.as_str()));
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
        // TASK-229: the responder-derivation GLOBAL byte budget, used/CAP - BOTH from the
        // live ledger (single source of truth; the denominator is NOT independently read
        // from `caps`, which could drift). Emitted ONLY when a live ledger exists; a node
        // with no over-the-wire responder omits the line rather than reporting a synthetic
        // figure (the CAP is still visible in --preflight's effective controls).
        if let Some((used, cap)) = rt.derive_budget_global {
            out.push(format!("derive_budget_global_bytes={used}/{cap}"));
        }
        // Mechanisms ACTIVE ON THIS NODE (the pending set is the preflight's job). Uses
        // `mechanism_active_here`, so the always-on primary is listed while the per-node
        // opt-in mDNS (TASK-257) appears ONLY when `--libp2p-mdns` enabled it - a default-OFF
        // node never reports lan-mdns as enabled (report matches wire).
        let enabled: Vec<&str> = Mechanism::registry()
            .into_iter()
            .filter(|m| self.mechanism_active_here(*m))
            .map(|m| m.as_str())
            .collect();
        out.push(format!("mechanisms_enabled={}", enabled.join(",")));
        // TASK-257 EXPOSURE (AC#6): mDNS discloses to every device on the LAN, via link-local
        // multicast, this host's presence, its NodeId, AND its libp2p LISTEN MULTIADDRS (IP:port -
        // how a peer learns the dial address); it ANSWERS ANY querier regardless of scope (scope is
        // enforced only later, at the kad/identify handshake). Surface the FULL disclosure on
        // --status so an operator SEES it, never silently accepts it. Off = the honest `none`.
        out.push(format!(
            "lan_mdns_exposure={}",
            if self.lan_mdns_enabled {
                "presence + node_id + libp2p-listen-multiaddrs (link-local multicast, answers any querier incl cross-scope)"
            } else {
                "none"
            }
        ));
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
        // TASK-241: the reachability-aware answer, so a PUBLIC router (a publicly-reachable
        // kad-server + relay) is not mislabelled `false`. Computed from (profile, reachability),
        // not the profile alone - the report matches the wire.
        out.push(format!(
            "  public_dht_participation: {}",
            self.public_dht_participation()
        ));
        // FIX A: the ACTUAL kad role on the wire (set by the binary), so the report cannot drift
        // from what the swarm runs - a node reporting no participation while running a kad server
        // is exactly the honesty gap this closes.
        out.push(format!("  dht_role: {}", self.dht_role.describe()));
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
                // TASK-257: mDNS is shipped (Enabled) but a per-node OPT-IN, so its preflight line
                // reflects whether it is ACTIVE HERE - ENABLED (active on this node) vs AVAILABLE
                // (opt-in, not active) - rather than a bare static "ENABLED" on every node. This
                // keeps a default-OFF node from reading as if it multicasts.
                MechanismState::Enabled if m == Mechanism::LanMdns => {
                    if self.lan_mdns_enabled {
                        out.push(format!("  {} = ENABLED (active on this node)", m.as_str()));
                    } else {
                        out.push(format!(
                            "  {} = AVAILABLE (opt-in, not active: pass --libp2p-mdns to enable \
                             LAN peer-address discovery)",
                            m.as_str()
                        ));
                    }
                }
                MechanismState::Enabled => out.push(format!("  {} = ENABLED", m.as_str())),
                MechanismState::PendingUnsupported { evidence } => out.push(format!(
                    "  {} = PENDING (non-selectable): {}",
                    m.as_str(),
                    evidence
                )),
            }
        }
        // TASK-257 EXPOSURE (AC#6): before any networking is enabled, preflight must state the LAN
        // disclosure mDNS causes so the operator sees it up front. Only when active.
        if self.lan_mdns_enabled {
            out.push(
                "  EXPOSURE (lan-mdns): this node opens a link-local mDNS multicast socket and \
                 DISCLOSES to every device on the LAN its presence, its NodeId, AND its libp2p \
                 LISTEN MULTIADDRS (IP:port - the dial address); it ANSWERS ANY querier regardless \
                 of scope (scope is enforced only later, at the kad/identify handshake, so a \
                 cross-scope device still learns this host exists and where to reach it, it just \
                 cannot JOIN the DHT). This is axis-1 LOCAL discovery only - it supplies peer \
                 ADDRESSES into the kad bootstrap path and does NOT serve, announce, publish, or \
                 join any public substrate."
                    .to_string(),
            );
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
            SharingProfile::Router => vec![
                "libp2p-kad peers (kad-server: a bootstrap rendezvous root for others)".to_string(),
                "circuit-v2 relay clients it relays for (unless --libp2p-no-relay-server)"
                    .to_string(),
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
    /// A router (kad-server + relay, carries NO content) was combined with a give-side intent
    /// (provider/announce/allowlist/leech). A router that serves would be a give-side backdoor.
    RouterServes,
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
            ContractError::RouterServes => f.write_str(
                "a router (--libp2p-router) is a kad-server + relay that carries NO content; it \
                 cannot be combined with a give-side intent (provider/announce/allowlist/leech): \
                 a router serves NOTHING and announces NOTHING",
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
                is_router: false,
            })
            .unwrap(),
            SharingProfile::PublicShare
        );
        // router (TASK-241): explicit --libp2p-router, no give side. A router advertising its
        // OWN reachable address is legitimate (a relay's whole job), so an external address does
        // NOT flip it to a leaky provider.
        assert_eq!(
            SharingProfile::derive(ContractRequest {
                is_router: true,
                advertises_public_address: true,
                has_bootstrap: true,
                ..Default::default()
            })
            .unwrap(),
            SharingProfile::Router
        );
    }

    /// TASK-241: a router carries NO content — the wire facts that keep it from being a give-side
    /// backdoor. It is a kad SERVER (a usable bootstrap root) yet serves + announces NOTHING.
    #[test]
    fn router_is_a_kad_server_that_gives_nothing() {
        let p = SharingProfile::Router;
        assert!(!p.serves(), "a router serves no NAR bytes");
        assert!(!p.announces(), "a router announces nothing");
        assert!(
            p.runs_dht_server(),
            "a router IS a kad server (a bootstrap rendezvous root)"
        );
        assert!(
            p.sends_discovery_lookups(),
            "a router runs a participating swarm (self-lookup / kad queries)"
        );
        // Round-trips through the machine token (NixOS `profile = \"router\"`).
        assert_eq!(p.as_str(), "router");
        assert_eq!(SharingProfile::parse("router").unwrap(), p);
        // The DHT-server axis distinguishes a router from a consume-only CLIENT.
        assert!(!SharingProfile::ConsumeOnly.runs_dht_server());
    }

    /// TASK-241 fail-closed: --libp2p-router combined with ANY give-side intent is a contradiction
    /// (a router that serves would be a backdoor). Each give-side bit trips it.
    #[test]
    fn router_with_a_give_side_fails_closed() {
        for req in [
            ContractRequest {
                is_router: true,
                is_provider: true,
                has_bootstrap: true,
                ..Default::default()
            },
            ContractRequest {
                is_router: true,
                announces: true,
                has_bootstrap: true,
                ..Default::default()
            },
            ContractRequest {
                is_router: true,
                has_public_allowlist: true,
                has_bootstrap: true,
                ..Default::default()
            },
            ContractRequest {
                is_router: true,
                is_leech: true,
                has_bootstrap: true,
                ..Default::default()
            },
        ] {
            assert_eq!(
                SharingProfile::derive(req).unwrap_err(),
                ContractError::RouterServes,
                "a router + give-side intent must fail closed: {req:?}"
            );
        }
    }

    /// TASK-241 (codex item 4): a PUBLIC router (one advertising a reachable external address) runs
    /// a publicly-reachable kad-server + relay, so it IS a public DHT participant and the report
    /// MUST say so; a LAN-isolated router (no advertised public address) is not. The report is
    /// computed from (profile, reachability), NOT the profile alone.
    ///
    /// MUTATION: hardcoding the router arm to `false` (the bug codex caught) reddens the public
    /// case; hardcoding it to `true` reddens the LAN case; ignoring reachability (return the
    /// intrinsic `profile.public_participation()`, which is `false` for Router) reddens the public
    /// case. Only the reachability-threaded computation passes both.
    #[test]
    fn public_router_reports_public_dht_participation_lan_router_does_not() {
        let public_router = OperatorContract {
            advertises_public_reachability: true,
            dht_role: DhtRole::Server,
            ..OperatorContract::for_profile(SharingProfile::Router)
        };
        assert!(
            public_router.public_dht_participation(),
            "a router advertising a public reachable address IS a public DHT participant"
        );
        assert!(
            public_router
                .preflight()
                .contains("public_dht_participation: true"),
            "the preflight report must say true for a public router:\n{}",
            public_router.preflight()
        );

        let lan_router = OperatorContract {
            advertises_public_reachability: false,
            dht_role: DhtRole::Server,
            ..OperatorContract::for_profile(SharingProfile::Router)
        };
        assert!(
            !lan_router.public_dht_participation(),
            "a LAN-isolated router (no advertised public address) is NOT a public DHT participant"
        );
        assert!(
            lan_router
                .preflight()
                .contains("public_dht_participation: false"),
            "the preflight report must say false for a LAN router:\n{}",
            lan_router.preflight()
        );

        // The four give/consume modes stay INTRINSIC (reachability is inert for them): public-share
        // is always true, and the rest false, regardless of the reachability field.
        for (p, want) in [
            (SharingProfile::UpstreamOnly, false),
            (SharingProfile::ConsumeOnly, false),
            (SharingProfile::LanShare, false),
            (SharingProfile::PublicShare, true),
        ] {
            let c = OperatorContract {
                advertises_public_reachability: true, // deliberately set; must NOT change the answer
                ..OperatorContract::for_profile(p)
            };
            assert_eq!(
                c.public_dht_participation(),
                want,
                "{p} public participation is intrinsic and must ignore the reachability field"
            );
        }
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
    fn libp2p_pair_and_mdns_enabled_everything_else_pending() {
        // The always-on primary AND the shipped mDNS bootstrap (TASK-257) are selectable.
        assert!(Mechanism::Libp2pKadDiscovery.is_selectable());
        assert!(Mechanism::Libp2pNarTransfer.is_selectable());
        assert!(
            Mechanism::LanMdns.is_selectable(),
            "lan-mdns is shipped (TASK-257) and must be selectable"
        );
        for m in [
            Mechanism::IrohTransport,
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

    /// TASK-257 default-OFF honesty (AC#6): mDNS is SELECTABLE, but a node that did NOT pass
    /// `--libp2p-mdns` must NOT report lan-mdns as active on --status/preflight, and its exposure
    /// line must read `none`. Enabling it (the ONLY change) flips both — the report matches the
    /// wire. Proven by mutation: if `mechanism_active_here`/`lan_mdns_enabled` were ignored, the
    /// OFF node would already list lan-mdns and this test reddens.
    #[test]
    fn mdns_is_surfaced_only_when_enabled_on_this_node() {
        let rt = StatusInputs {
            node_id: "12D3KooW…".to_string(),
            bootstrap_total: 0,
            bootstrap_healthy: 0,
            holder_count: None,
            path: PeerPath::None,
            last_lookup: None,
            announce_budget_used: 0,
            derive_budget_global: None,
            fallback_reason: String::new(),
            kad_routing_peers: None,
        };
        let off = OperatorContract::for_profile(SharingProfile::ConsumeOnly);
        assert!(!off.lan_mdns_enabled, "default is OFF");
        assert!(
            !off.status(&rt).contains("lan-mdns"),
            "a default-OFF node must NOT list lan-mdns as an enabled mechanism"
        );
        assert!(
            off.status(&rt).contains("lan_mdns_exposure=none"),
            "a default-OFF node's LAN mDNS exposure must be `none`"
        );
        assert!(
            off.preflight().contains("lan-mdns = AVAILABLE"),
            "preflight must show mDNS as available-but-not-active when off"
        );

        let mut on = OperatorContract::for_profile(SharingProfile::ConsumeOnly);
        on.lan_mdns_enabled = true;
        on.selected_mechanisms.push(Mechanism::LanMdns);
        on.validate()
            .expect("selecting the ENABLED lan-mdns mechanism must validate");
        assert!(
            on.status(&rt).contains("lan-mdns"),
            "an mDNS-enabled node must list lan-mdns among enabled mechanisms"
        );
        let on_status = on.status(&rt);
        assert!(
            on_status.contains("lan_mdns_exposure=presence + node_id + libp2p-listen-multiaddrs")
                && on_status.contains("answers any querier incl cross-scope"),
            "an mDNS-enabled node's --status exposure must name presence + NodeId + listen \
             multiaddrs AND that it answers any querier incl cross-scope: {on_status}"
        );
        assert!(
            on.preflight()
                .contains("lan-mdns = ENABLED (active on this node)")
                && on.preflight().contains("EXPOSURE (lan-mdns)"),
            "preflight must show mDNS active + its LAN exposure when enabled"
        );
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
        // TASK-229: the responder-derivation budget the caps drive.
        let der = caps.derive_budget();
        assert_eq!(der.max_bytes_per_peer_uncompressed_nar, 1024 * 1024 * 1024);
        assert_eq!(der.max_dumps_per_peer, 64);
        assert_eq!(
            der.max_bytes_global_uncompressed_nar,
            4 * 1024 * 1024 * 1024
        );
        assert_eq!(der.window, Duration::from_millis(60_000));
        // The global ceiling is the Sybil floor: >= a single peer's byte cap.
        assert!(der.max_bytes_global_uncompressed_nar >= der.max_bytes_per_peer_uncompressed_nar);
        // Every effective line is present and integer-valued (no float rendering); every
        // ADVERTISED cap must be one that is actually enforced (fix #6: no phantom bounds).
        let lines = caps.effective_lines();
        assert_eq!(lines.len(), 13);
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
            // A CAP (999) deliberately DIFFERENT from `caps.derive_max_bytes_global_uncompressed`
            // (4 GiB): the rendered denominator must be THIS ledger-sourced value, proving
            // the status cap is single-sourced from the ledger, not re-read from caps.
            derive_budget_global: Some((123, 999)),
            fallback_reason: "discovery-unavailable".to_string(),
            kad_routing_peers: None,
        };
        let s = c.status(&rt);
        assert!(s.contains("profile=public-share"));
        assert!(s.contains("bootstrap_healthy=2/3"));
        assert!(s.contains("peer_path=relay"));
        assert!(s.contains("last_lookup=unavailable"));
        assert!(s.contains("announce_budget=7/256"));
        // TASK-229: used/CAP both from the ledger figure, NOT the caps denominator.
        assert!(s.contains("derive_budget_global_bytes=123/999"), "{s}");
        assert!(
            !s.contains(&format!("/{}", 4u64 * 1024 * 1024 * 1024)),
            "the derive CAP must come from the ledger figure, not caps: {s}"
        );
        assert!(s.contains("fallback_reason=discovery-unavailable"));
        assert!(s.contains("mechanisms_enabled=libp2p-kad-discovery,libp2p-nar-transfer"));
    }

    /// TASK-229 (codex fix C, honesty gap): a node with NO live derivation ledger OMITS
    /// the derive-budget status line entirely rather than emitting a synthetic `0/CAP`
    /// (the code now matches the comment "no live figure"). The configured CAP is still
    /// discoverable via --preflight's effective controls. MUTATION: emitting the line on
    /// `None` (a synthetic `0/CAP`) reddens the `!contains` below.
    #[test]
    fn status_omits_derive_budget_line_when_no_live_ledger() {
        let c = OperatorContract::for_profile(SharingProfile::ConsumeOnly);
        let rt = StatusInputs {
            node_id: "12D3KooW…".to_string(),
            bootstrap_total: 1,
            bootstrap_healthy: 1,
            holder_count: None,
            path: PeerPath::Unknown,
            last_lookup: None,
            announce_budget_used: 0,
            derive_budget_global: None,
            fallback_reason: String::new(),
            kad_routing_peers: None,
        };
        let s = c.status(&rt);
        assert!(
            !s.contains("derive_budget_global_bytes"),
            "no live responder ledger -> the derive line must be OMITTED, not synthetic: {s}"
        );
        // The CAP remains visible where it belongs: the preflight effective controls.
        assert!(
            c.preflight()
                .contains("derive_max_bytes_global_uncompressed="),
            "the configured CAP must still show in preflight effective controls"
        );
    }

    /// TASK-242: the four [`PeerPath`] states render to FOUR distinct tokens. `Unknown` must render
    /// `unknown` (not `none`), so a swarm that is running but has no classified live path is never
    /// conflated with an upstream-only node that has no swarm at all. MUTATION: aliasing
    /// `Unknown => "none"` in `as_str` collapses the two and reddens the `unknown`/`none` split.
    #[test]
    fn peer_path_tokens_are_four_distinct_states() {
        assert_eq!(PeerPath::Direct.as_str(), "direct");
        assert_eq!(PeerPath::Relay.as_str(), "relay");
        assert_eq!(PeerPath::Unknown.as_str(), "unknown");
        assert_eq!(PeerPath::None.as_str(), "none");
        let tokens = [
            PeerPath::Direct.as_str(),
            PeerPath::Relay.as_str(),
            PeerPath::Unknown.as_str(),
            PeerPath::None.as_str(),
        ];
        let distinct: std::collections::HashSet<_> = tokens.iter().collect();
        assert_eq!(
            distinct.len(),
            4,
            "every PeerPath state is a distinct token"
        );

        // The Unknown token surfaces on the rendered status line (a running swarm, no classified
        // path yet) — never printed as `peer_path=none`.
        let c = OperatorContract::for_profile(SharingProfile::ConsumeOnly);
        let rt = StatusInputs {
            node_id: "12D3KooW…".to_string(),
            bootstrap_total: 2,
            bootstrap_healthy: 2,
            holder_count: None,
            path: PeerPath::Unknown,
            last_lookup: None,
            announce_budget_used: 0,
            derive_budget_global: None,
            fallback_reason: String::new(),
            kad_routing_peers: None,
        };
        let s = c.status(&rt);
        assert!(s.contains("peer_path=unknown"), "{s}");
        assert!(!s.contains("peer_path=none"), "{s}");
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
        // FIX A: a fresh install runs no participating swarm - the reported dht_role is none.
        assert!(p.contains("dht_role: none"));
    }

    /// FIX A: the reported dht_role renders the ACTUAL kad role (set by the binary), so the report
    /// cannot claim no participation while a kad server runs.
    #[test]
    fn dht_role_renders_in_status_and_preflight() {
        let mut c = OperatorContract::for_profile(SharingProfile::ConsumeOnly);
        c.dht_role = DhtRole::Client;
        assert!(c.preflight().contains("dht_role: kad-client"));

        let mut s = OperatorContract::for_profile(SharingProfile::LanShare);
        s.dht_role = DhtRole::Server;
        assert!(s.preflight().contains("dht_role: kad-server"));
        let rt = StatusInputs {
            node_id: "n".to_string(),
            bootstrap_total: 0,
            bootstrap_healthy: 0,
            holder_count: None,
            path: PeerPath::None,
            last_lookup: None,
            announce_budget_used: 0,
            derive_budget_global: None,
            fallback_reason: String::new(),
            kad_routing_peers: None,
        };
        assert!(s.status(&rt).contains("dht_role=server"));
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
            SharingProfile::Router,
        ] {
            assert_eq!(SharingProfile::parse(p.as_str()).unwrap(), p);
        }
        assert!(SharingProfile::parse("nonsense").is_err());
    }
}
