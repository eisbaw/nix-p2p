//! The ANNOUNCE-AFTER-FETCH seam (TASK-77).
//!
//! This is how the swarm GROWS. Today a node announces only what an operator handed
//! it (`--libp2p-provide-store` / `--libp2p-seed-nar`); nothing publishes new
//! availability after a successful fetch, so popular paths depend on a few fixed
//! seeders. Announce-after-fetch closes that: a node that just fetched a NAR (from a
//! peer OR from upstream) becomes a DISCOVERABLE HOLDER for it, so a second node can
//! fetch it from the first and holders accrue naturally.
//!
//! ## Why a seam here (fabric-neutral)
//!
//! The serving frontend ([`crate::server`] / [`crate::run`]) is stack-neutral: it
//! knows nothing about libp2p, signing, or the DHT. Announcing a record needs all
//! three, which live in the backend binary. So this crate names only the INTENTION -
//! "a NAR was fetched; become a holder for it" - and the backend supplies the
//! concrete authority (the `daemon-libp2p` announce-after-fetch impl), exactly as
//! `public_allowlist` and `extra_raw_serve` are already binary-supplied injection
//! points. There is no announce mechanism in this crate.
//!
//! ## What "become a holder" means (TASK-61 arm-a)
//!
//! No blob is retained at rest. After the LOCAL nix realises the fetched path into
//! `/nix/store`, the STORE is the copy: the impl registers the store path into its
//! availability index and regenerates the raw NAR on demand (`nix-store --dump`) to
//! serve a peer. So the hook is handed the signed `NarHash` and the narinfo's signed
//! `StorePath`; the store path is what makes the fetched NAR reserve-mappable and
//! servable later.
//!
//! ## Contract (fail-safe, non-blocking, gated)
//!
//! [`PostFetchAnnounce::on_fetched`] MUST NOT block the serve path - an impl spawns
//! its own task and returns immediately. It is BEST-EFFORT: a failure to announce
//! never fails the fetch. It MUST honour three properties the backend enforces:
//!   * NEVER announce content it cannot serve (TASK-72 index-coverage ==
//!     provider-coverage): the impl verifies `sha256(nix-store --dump path) ==
//!     signed NarHash` before announcing, and simply does not announce a path the
//!     local store has not (yet) materialised;
//!   * route the announce through the node's fail-closed publication-eligibility
//!     authority (TASK-231), so a node that is not allowed to publish this content
//!     announces nothing;
//!   * respect an explicit, integer announce BUDGET (TASK-77 AC#2): past the budget,
//!     announcing STOPS.
//!
//! ## AC#3 serveability is EVENTUALLY consistent (honest residual)
//!
//! "Never announce what you cannot serve" (index-coverage == provider-coverage) holds
//! at announce time (the `sha256(--dump)==NarHash` floor gates it) and is kept EVENTUALLY
//! consistent afterwards, not instantaneously. The store's GC can unlink an announced
//! path after the fact; the backend then self-heals by WITHDRAWING that record - but the
//! trigger is OPPORTUNISTIC (it reconciles on the next fetch) plus the record's own kad
//! TTL, so a window exists where an idle node still advertises a GC'd path. That window is
//! WITHIN the project TCB: the serve side re-dumps and BLAKE3-re-verifies before emitting a
//! byte, so a GC'd path yields a CLEAN decline (zero bytes) - a querier just retries the
//! next provider, never a bad byte. STRICT always-coverage (pin a GC root for the announce
//! lifetime, or a periodic reconcile timer) is deliberately OUT of TASK-77's scope (it is a
//! supply-model / retention decision, TASK-61/120) and is a filed follow-up.
//!
//! ## The privacy cost (TASK-77 AC#4), and the consume-only escape hatch
//!
//! Announcing is not free of disclosure: a positive availability record on the DHT
//! REVEALS THAT THIS NODE FETCHED THAT CONTENT. Over time the set of paths a node
//! announces is a partial fingerprint of what it builds/uses. That is the inherent
//! cost of being a holder - the swarm grows precisely because holders are
//! discoverable. Two things bound and gate that cost:
//!   * the integer BUDGET caps how many distinct fetched paths a node ever reveals
//!     (past it, growth - and disclosure - stops); and
//!   * an operator who does not want to disclose ANY fetch simply runs CONSUME-ONLY
//!     (leech): leave this hook unset (`None`), and the node fetches without ever
//!     announcing what it fetched. This is the privacy-preserving default.
//!
//! This is exactly the leech-mode axis TASK-78 will formalise as a first-class flag.
//! Until then, the presence/absence of this hook IS the consume-only toggle: the
//! `daemon`/`daemon-libp2p` binaries only build it under `--libp2p-announce-after-fetch`,
//! so the shipped default (flag absent) is consume-only. When TASK-78 lands its
//! dedicated leech flag, it must gate THIS hook (and the peer/upstream fetch it wraps)
//! - a leech node keeps `post_fetch_announce == None`.

use crate::source::NarHash;

/// A backend-supplied authority that turns a successful fetch into a holder announce.
///
/// Implemented in the p2p backend (`daemon-libp2p`), injected into [`crate::server::App`]
/// via [`crate::run::RunConfig`]. `None` on the `App`/`RunConfig` is the CONSUME-ONLY
/// (leech) posture (TASK-77 AC#4, TASK-78): the node fetches without ever announcing what
/// it fetched, so an operator who does not want to reveal its fetch history simply leaves
/// the hook unset.
pub trait PostFetchAnnounce: Send + Sync {
    /// A NAR identified by `nar_hash`, whose narinfo declared local store path
    /// `store_path`, was successfully fetched and served. Become a discoverable holder
    /// for it (register + verify + announce), subject to the budget and the
    /// publication-eligibility authority.
    ///
    /// MUST return promptly: the serve path calls this inline, so an impl offloads the
    /// materialisation wait + dump + announce onto its own task. `nar_hash` is the loose
    /// narinfo form (the impl canonicalises it to the wire key); `store_path` is the
    /// `/nix/store/<hash>-<name>` the local nix realises this NAR to.
    fn on_fetched(&self, nar_hash: &NarHash, store_path: &str);
}
