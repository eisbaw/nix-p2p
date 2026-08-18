//! `daemon-libp2p` (lib) - the libp2p CONSTRUCTION over the stack-neutral `daemon-core`.
//!
//! The generic discover-then-fetch [`NarSource`] and dynamic raw-serve decision live in
//! `daemon-core` (`PeerFabricNarSource`/`PeerFabricRawServe`, generic over
//! `Arc<dyn PeerFabric>`); this lib holds only what needs `fabric_libp2p`: the
//! [`Libp2pSourceConfig`] the CLI parses into, and the builders that START a
//! [`Libp2pFabric`], JOIN the DHT (listen + bootstrap-dial + the composition-root
//! `require_axes` gate), and WRAP the running fabric in the daemon-core source. It re-exports
//! the daemon-core source types under their historical `Libp2p*` names.
//!
//! It is the single source of truth for the libp2p construction: BOTH the `daemon-libp2p`
//! BINARY (the clean primary, `daemon_core::run(Libp2pFabric::…)`) and the interim `daemon`
//! composite (which re-exports these) build the libp2p path through here, so they cannot
//! drift. The binary's dependency closure contains NO iroh (a build guard proves it); the
//! `daemon` composite additionally links `fabric-iroh` for its retained iroh path.
//!
//! ## The flow (matching the FROZEN recipe)
//!
//! ```text
//!   NarSource::resolve(NarKey::SignedNarHash{ hash })
//!     -> ContentKey::derive_from_signed_nar_hash    (FROZEN peer-fabric content.rs recipe)
//!     -> fabric.provider_directory().find_providers(ContentKey)   (libp2p-kad, NOT injected)
//!     -> for each offer: fabric.transfer(tag).fetch(content, offer, size, envelope)
//!         (dial address resolved via kad peer-routing INSIDE the fabric - TASK-169; gate-1
//!         BLAKE3 verify INSIDE the transfer, so a lying holder fails closed, next offer tried)
//!     -> hand the raw NAR up; Nix re-verifies sig + sha256==NarHash (gate 2, the TCB)
//! ```
//!
//! A discovery miss / exhausted offer set folds to a fast fallback to HTTP upstream (S2); a
//! deliberate size abort propagates (every offer addresses the same oversized content).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;

use fabric_libp2p::{
    ANNOUNCE_SEQ_FILENAME, ConnPath, Libp2pNarSupplier, Multiaddr, NodeConfig,
    PROVIDER_FLOOR_FILENAME, PeerId, SwarmHandle,
};
// `Libp2pFabric` is used in several places under its bare name; keep it a separate line so the
// status-facts wiring above can re-order without churn.
use fabric_libp2p::Libp2pFabric;

use ed25519_dalek::SigningKey;
use peer_fabric::{
    AdmitAllPublication, AnnounceBudget, AnnounceError, Axis, Blake3Digest, ContentKey,
    DiscoveryBudget, IneligibleReason, NodeId, PeerFabric, ProviderRecord, PublicationEligibility,
    RefusePublication, SafetyEnvelope, TransportOffer, TransportTag, require_axes,
    sign_provider_record,
};

use daemon_core::claim::NarHashKey;
use daemon_core::rewrite::RawServeDecision;
use daemon_core::source::{NarHash, NarSource};
use daemon_core::{
    AvailabilityIndex, HoldAnswer, LearnOutcome, PostFetchAnnounce, PublicNarAllowlist,
    PublicNarClaim, PublicationRejected, StoreHash, StorePath, TrustedNarKeys,
    derive_allowlist_mac_key,
};

mod store_probe;
pub use store_probe::Libp2pCatalogProbe;

// The generic PeerFabric-backed NarSource + raw-serve decision moved into `daemon-core`
// (TASK-146): they were ALREADY generic over `Arc<dyn PeerFabric>` - only their
// CONSTRUCTION named `fabric_libp2p`. Re-export them under the daemon's historical libp2p
// names so `daemon::Libp2pNarSource` / `daemon::Libp2pRawServe` and the flat re-exports keep
// resolving; this module now holds ONLY the libp2p-specific construction (start + join +
// wrap), which the daemon-libp2p binary shares via the same daemon-core source.
pub use daemon_core::peer_source::{
    PeerFabricNarSource as Libp2pNarSource, PeerFabricRawServe as Libp2pRawServe,
};

/// The composition-root numbers for the PRODUCTION libp2p `NarSource` (TASK-162).
///
/// The daemon binary parses its CLI flags (`--libp2p-bootstrap`, `--libp2p-listen`,
/// `--libp2p-scope`, `--libp2p-provider-addr`, `--libp2p-identity-seed`) into this
/// shape and hands it to [`build_libp2p_nar_source`]; the in-process production-path
/// integration test drives the SAME builder from an equivalent config, so the two
/// exercise one construction path (the CLI parse is unit-tested separately in the
/// binary). This is the interim both-backends wiring ahead of the clean daemon-core
/// split (TASK-145/146); the numbers are owned here (the composition root), not baked
/// into the seam types.
#[derive(Debug, Clone)]
pub struct Libp2pSourceConfig {
    /// 32-byte ed25519 identity seed for this node.
    pub identity_seed: [u8; 32],
    /// The kad/identify protocol network scope (`/nix-p2p/<scope>/kad/1.0.0`).
    pub network_scope: String,
    /// The multiaddr to listen on, if any (a pure dial-out consumer may omit it).
    pub listen: Option<Multiaddr>,
    /// kad bootstrap/entry peers (`PeerId` + dial `Multiaddr`). MUST be non-empty for
    /// discovery to work - an empty set is a consumer that can never find anyone.
    pub bootstrap: Vec<(PeerId, Multiaddr)>,
    /// OPTIONAL address-book seed for the swarm's kad routing table (TASK-169). The
    /// production path does NOT need this: the libp2p transfer resolves a discovered
    /// provider's dial address THROUGH kad peer-routing INSIDE the fabric
    /// (`Libp2pFabric::node_locator()`, TASK-159) and dials off that resolution, so BOTH
    /// legs are decentralized (discover WHO via kad get_providers, resolve WHERE via kad
    /// peer-routing) with zero injection. Keep it EMPTY - that is the normal production
    /// shape and it proves no-injection.
    ///
    /// HONEST LIMIT (do not overclaim): since TASK-169 the transport DIALS only off a
    /// successful peer-routing resolution, so entries here do NOT independently enable a
    /// dial to a provider the DHT cannot resolve - `add_address` only seeds the local kad
    /// routing table (a bootstrap/entry hint), and kad `get_closest_peers` will not report
    /// a target's address unless a SHARED peer learned it via identify. A real static
    /// per-peer address book that the transfer honours for a dial (the `ExplicitPeersOnly`
    /// policy) is the locator's job and is TASK-168; until then these entries only help kad
    /// converge, they are not a per-provider dial override.
    pub provider_addrs: Vec<(PeerId, Multiaddr)>,
    /// The bound on each `find_providers` consultation.
    pub discovery_budget: DiscoveryBudget,
    /// The fetch time envelope handed to each transfer.
    pub envelope: SafetyEnvelope,
    /// PER-NODE durable state directory (TASK-185, AC#1). When `Some`, the fabric is started
    /// through [`Libp2pFabric::start_durable`] / `start_with_supplier_durable`, so the
    /// consumer's anti-rollback FLOOR and the provider's per-key announce SEQUENCE are
    /// persisted here and re-seeded on restart - the shipped daemon then genuinely runs in the
    /// restart-durable mode the README describes. When `None` the fabric is session-scoped
    /// (the historical non-durable behaviour), for a throwaway/ephemeral node.
    ///
    /// EACH NODE NEEDS ITS OWN DIRECTORY: the files are keyed by directory, not by identity,
    /// so two nodes sharing one `state_dir` corrupt each other's floor/sequence. A fail-loud
    /// advisory lock is the TASK-185 hardening follow-up.
    pub state_dir: Option<PathBuf>,
    /// Whether this node runs the circuit-v2 relay SERVER (TASK-207/208). Default `true`
    /// (the permissionless-swarm intent: any public node helps NAT'd peers). Set `false`
    /// for a node that must be kad-only - e.g. a dedicated bootstrap that offers NO
    /// reservation service, so it can never be an ALTERNATIVE relay path. Threads straight to
    /// [`NodeConfig::with_relay_server`]: the relay-client / autonat / dcutr behaviours stay
    /// intact, only the server (which accepts reservations + forwards circuits) is dropped.
    pub relay_server_enabled: bool,
    /// Whether this node runs Kademlia in SERVER mode (TASK-120 fix A). Threads straight to
    /// [`NodeConfig::with_kad_server`]. The operator contract sets it from the participation
    /// profile: a PROVIDER (lan-share/public-share) is a kad SERVER (stores + answers DHT
    /// queries for others - real DHT participation); a CONSUMER (consume-only) is a kad CLIENT
    /// (issues queries, answers none). An upstream-only node runs no participating swarm at all
    /// and never builds this config. Default `true` (server); a consumer sets `false`.
    pub kad_server: bool,
}

/// Build the PRODUCTION libp2p [`NarSource`] from `cfg`: start a [`Libp2pFabric`],
/// bind the listener, join the DHT through the configured bootstrap peers (kad
/// self-lookup), seed any OPTIONAL `provider_addrs` into the kad routing table (normally
/// none - the fetch path resolves dial addresses via kad peer-routing INSIDE the transfer,
/// TASK-169; these seeds only help kad converge, they are not a per-provider dial
/// override - see the field doc), and wrap the running fabric in a [`Libp2pNarSource`].
///
/// Returns the `Arc<Libp2pFabric>`, the `NarSource`, AND its paired
/// [`Libp2pRawServe`] decision. Building all three from the ONE running fabric and the
/// ONE `discovery_budget` here is deliberate: it makes the narinfo-rewrite decision and
/// the NAR fetch impossible to drift apart (they share the exact discovery mechanism),
/// the libp2p analogue of the iroh path seeding discovery + allowlist from one claim
/// set (TASK-164). In production the binary keeps the source and the raw-serve; the
/// returned fabric handle lets a test poll discovery readiness before serving.
/// Connectivity setup is fail-fast: a listen or bootstrap-dial error is a loud startup
/// error, never a silent degrade to upstream-only.
pub async fn build_libp2p_nar_source(
    cfg: Libp2pSourceConfig,
) -> Result<
    (
        Arc<Libp2pFabric>,
        Arc<dyn NarSource>,
        Arc<dyn RawServeDecision>,
    ),
    String,
> {
    // A pure consumer never announces, so its announcer authority is the fail-closed default.
    let fabric = start_and_join_libp2p(&cfg, None, Arc::new(RefusePublication)).await?;
    Ok(wrap_consumer_source(fabric, &cfg))
}

/// The SERVING sibling of [`build_libp2p_nar_source`] (TASK-178): start the fabric WITH
/// a `supplier`, so the fabric exposes the serve axis (`server()` is `Some`) and can
/// answer inbound NAR requests. It runs the SAME connectivity join as the consumer
/// builder ([`start_and_join_libp2p`]), so a serving node is reachable in the DHT, and
/// returns the running fabric PLUS its own consumer source/raw-serve (a provider is also
/// a consumer - it can discover+fetch what it does not hold). The composition root then
/// installs the serve gate (`fabric.server().serve(budget)`) and announces the signed
/// provider records; that stays in the caller because the records are minted from the
/// caller's seed catalog (raw NAR + its NarHash), which the fabric does not know.
///
/// ONE fabric serves AND consumes on ONE identity/listen, so there is no second
/// same-identity swarm to collide with (the footgun a separate provider node would
/// create). The returned `Arc<Libp2pFabric>` is what the caller drives to serve/announce
/// and MUST keep alive for the process (the source holds its own clone too).
pub async fn build_libp2p_provider_source(
    cfg: Libp2pSourceConfig,
    supplier: Arc<dyn Libp2pNarSupplier>,
    publication_eligibility: Arc<dyn PublicationEligibility>,
) -> Result<
    (
        Arc<Libp2pFabric>,
        Arc<dyn NarSource>,
        Arc<dyn RawServeDecision>,
    ),
    String,
> {
    let fabric = start_and_join_libp2p(&cfg, Some(supplier), publication_eligibility).await?;

    // Unlike a CONSUMER (whose find_providers RETRIES until the routing table fills), a
    // provider's announce is a ONE-SHOT at startup and needs a non-empty kad routing table
    // to reach the k-closest nodes - an announce against an empty table fails
    // `Unavailable(InsufficientRouting)`. So WAIT (bounded) for the bootstrap join to
    // populate at least one routing peer before the caller announces. Fail-fast with a
    // clear message on timeout rather than letting the caller's announce fail obscurely.
    // Only relevant when a bootstrap set was configured (the join target).
    if !cfg.bootstrap.is_empty() {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if fabric.handle().routing_peers().await >= 1 {
                break;
            }
            if Instant::now() >= deadline {
                return Err(
                    "libp2p provider: kad routing table stayed empty after joining the \
                     bootstrap peer(s); cannot announce into an unreachable DHT"
                        .to_string(),
                );
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    Ok(wrap_consumer_source(fabric, &cfg))
}

/// Build + SIGN a [`ProviderRecord`] for one seeded NAR (TASK-178), signed by the node's
/// ed25519 identity `seed`. SELF-SERVE v1: the record's `provider` is `NodeId(verifying
/// key of seed)`, which equals the fabric's own `node_id` (both derive from the same
/// seed) - the announcer REJECTS a record it did not sign, so this identity match is
/// load-bearing. The discovery [`ContentKey`] is derived from the Nix `NarHash`, so a
/// consumer that derived the SAME key from a narinfo discovers this provider; the
/// `content` [`Blake3Digest`] is the raw NAR's hash, the axis the transfer/serve keys on
/// and gate-1 BLAKE3-verifies. The lone offer carries the native libp2p tag with an
/// empty bounded relay-hint set; TASK-219 will populate it from live reservations.
///
/// This is the SINGLE SOURCE OF TRUTH for a provider record's construction: the daemon
/// binary's `--libp2p-provider` path and the integration test both mint records here, so
/// the two cannot drift on the key-derivation / signing recipe.
///
/// `sequence` is DURABLY ALLOCATED by the caller from the fabric's announcer
/// ([`Libp2pFabric::next_announce_sequence`]) - NOT a hardcoded `1` (TASK-185, AC#2). Because
/// the record is signed above the seam (the sequence is inside the signed bytes, and the
/// frozen wire/codec forbids the backend clamping it), the sequence must be chosen BEFORE
/// signing; the durable announcer is the monotonic source, so a restarted provider mints
/// `last + 1` and its record is strictly newer than every record it previously published.
/// The frozen record recipe is otherwise untouched: same `provider`/`content`/`offers`/expiry
/// derivation, only the sequence field now comes from durable state instead of the constant.
pub fn sign_libp2p_provider_record(
    seed: [u8; 32],
    nar_hash: &NarHashKey,
    nar_bytes: &[u8],
    ttl_secs: u64,
    now: u64,
    sequence: u64,
) -> ProviderRecord {
    // The `--libp2p-seed-nar` (Memory) path holds the raw NAR bytes, so it derives the content
    // digest FROM those bytes. The store-supply path (TASK-191) has no bytes at announce time;
    // it takes the VERIFIED digest straight from the availability index (see
    // [`sign_libp2p_store_record`]). Both funnel through the ONE record recipe below.
    sign_libp2p_record_for_content(
        seed,
        nar_hash,
        Blake3Digest::from_raw_nar(nar_bytes),
        ttl_secs,
        now,
        sequence,
    )
}

/// Build + SIGN a [`ProviderRecord`] for a store path this node serves on demand (TASK-191),
/// taking the raw-NAR `content` [`Blake3Digest`] DIRECTLY rather than re-hashing bytes it does
/// not hold. The `content` MUST be the availability index's VERIFIED
/// (`sha256(--dump) == nar_hash`, TASK-56) `Blake3Digest` for `nar_hash` - see
/// [`verify_store_provisions`], the store analogue of [`verify_provider_seeds`], which is the
/// only sanctioned source of a `(nar_hash, content)` provision. This is the store-supply
/// sign-site: it never mints a record from the operator's word, only from a verified binding.
pub fn sign_libp2p_store_record(
    seed: [u8; 32],
    nar_hash: &NarHashKey,
    content: Blake3Digest,
    ttl_secs: u64,
    now: u64,
    sequence: u64,
) -> ProviderRecord {
    sign_libp2p_record_for_content(seed, nar_hash, content, ttl_secs, now, sequence)
}

/// The SINGLE record recipe both the seed (Memory) and store (dump-on-demand) announce paths
/// share: derive the discovery [`ContentKey`] from the Nix `nar_hash`, carry the raw-NAR
/// `content` digest the transfer/serve keys on and gate-1 BLAKE3-verifies, and self-serve under
/// this node's own identity. Keeping it in one place means the two paths cannot drift on the
/// key-derivation / signing / offer recipe.
fn sign_libp2p_record_for_content(
    seed: [u8; 32],
    nar_hash: &NarHashKey,
    content: Blake3Digest,
    ttl_secs: u64,
    now: u64,
    sequence: u64,
) -> ProviderRecord {
    let signing_key = SigningKey::from_bytes(&seed);
    let provider = NodeId::from_bytes(signing_key.verifying_key().to_bytes());
    let key = ContentKey::derive_from_signed_nar_hash(nar_hash.as_bytes());
    let record = ProviderRecord {
        key,
        content,
        provider,
        offers: vec![TransportOffer::libp2p(provider)],
        sequence,
        issued_at: now,
        expiry: now + ttl_secs,
        signature: [0u8; 64],
    };
    sign_provider_record(&signing_key, &record)
}

/// Derive the discovery [`ContentKey`] for `nar_hash` exactly as
/// [`sign_libp2p_provider_record`] does, so the provider path can look up the durable
/// announce sequence for the record it is about to mint (TASK-185, AC#2). Kept here, next to
/// the record construction, so the two cannot drift on the derivation recipe.
/// Wall-clock UNIX seconds, the `now` an announced record's `issued_at`/`expiry` are stamped
/// from. Saturates to 0 before the epoch (an unreachable clock skew), never a float.
fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn provider_content_key(nar_hash: &NarHashKey) -> ContentKey {
    ContentKey::derive_from_signed_nar_hash(nar_hash.as_bytes())
}

/// A provider seed whose DECLARED Nix NarHash does not match its bytes: the operator
/// gave `--libp2p-seed-nar <declared>=/path/to/bytes.nar` where
/// `sha256(bytes) != declared`. Signing/announcing a [`ProviderRecord`] for `declared`
/// over those bytes would mint a FALSE CLAIM - a consumer discovers this provider by
/// `declared`, fetches, then rejects it at its OWN NarHash gate: a wasted dial that
/// pollutes honest offload accounting (the very thing TASK-56 forbids, here on the
/// path that actually ships). Refused at the announce SSOT BEFORE any record is signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedNarHashMismatch {
    /// The NarHash the operator DECLARED for this seed (the discovery key a consumer
    /// would look this provider up by).
    pub declared: NarHashKey,
    /// The NarHash the seed BYTES actually hash to (`sha256` of the raw NAR).
    pub actual: NarHashKey,
}

impl std::fmt::Display for SeedNarHashMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "provider seed NarHash mismatch: declared {} but the seed bytes hash to {}; \
             refusing to sign or announce a false provider record",
            self.declared, self.actual
        )
    }
}

impl std::error::Error for SeedNarHashMismatch {}

/// Verify that every provider seed's bytes hash to its DECLARED NarHash BEFORE any
/// record is signed (TASK-56): `NarHashKey::from_raw_nar(bytes) == declared`, reusing
/// the EXACT `daemon-core` helper the availability index uses to close the same gap on
/// the index-backed path. This is the site where a provider CLAIM is minted, so it is
/// the architecturally correct place to assert the bytes match the identity the claim
/// will advertise - regardless of whether the supply source is `--libp2p-seed-nar` or a
/// future index-backed dump (TASK-158). The WHOLE batch is refused on the first
/// mismatch (fail-fast), so a mis-specified seed fails the provider loudly at startup
/// rather than announcing a false claim.
pub fn verify_provider_seeds(seeds: &[(NarHashKey, Vec<u8>)]) -> Result<(), SeedNarHashMismatch> {
    for (declared, bytes) in seeds {
        let actual = NarHashKey::from_raw_nar(bytes);
        if actual != *declared {
            return Err(SeedNarHashMismatch {
                declared: *declared,
                actual,
            });
        }
    }
    Ok(())
}

/// The file under a `state_dir` that durably anchors this node's libp2p IDENTITY seed
/// (TASK-185 GB1), the companion to the `announce-seq-v1.txt` / `provider-floor-v1.txt` the
/// fabric writes there. A STABLE identity is what makes the durable sequence floor matter at
/// all: the anti-rollback floor and the record's `provider` are keyed by `NodeId(seed)`, so a
/// fresh random seed on every restart would announce in a DIFFERENT namespace and permanently
/// orphan every pre-restart record (it could neither supersede nor withdraw them). Persisting
/// the seed next to the sequence floor makes a plain identical-argv restart with only
/// `--libp2p-state-dir` come back as the SAME node.
pub const IDENTITY_SEED_FILENAME: &str = "identity-seed-v1";

/// Generate a fresh 32-byte libp2p identity seed from `/dev/urandom`.
fn random_identity_seed() -> Result<[u8; 32], String> {
    use std::io::Read;
    let mut seed = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut seed))
        .map_err(|e| format!("generating libp2p identity seed from /dev/urandom: {e}"))?;
    Ok(seed)
}

/// Parse 64 lowercase-hex chars into a 32-byte seed (the `--libp2p-identity-seed` wire form).
fn parse_seed_hex(hex: &str) -> Result<[u8; 32], String> {
    if hex.len() != 64 {
        return Err(format!(
            "expected 64 hex chars (32 bytes), got {}",
            hex.len()
        ));
    }
    let mut seed = [0u8; 32];
    for (i, byte) in seed.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16)
            .map_err(|e| format!("bad hex at byte {i}: {e}"))?;
    }
    Ok(seed)
}

/// Load the seed persisted at `path`, or `None` if the file does not exist. A file that
/// exists but is MALFORMED is a hard error, NOT a silent regenerate: regenerating a different
/// random identity here would orphan this state dir's anti-rollback floor (the exact GB1
/// hazard), so we refuse and make the operator fix or remove the file.
fn load_identity_seed(path: &Path) -> Result<Option<[u8; 32]>, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => parse_seed_hex(text.trim()).map(Some).map_err(|e| {
            format!(
                "the persisted libp2p identity seed {} is malformed ({e}); refusing to start \
                 with a DIFFERENT random identity that would orphan this state dir's \
                 anti-rollback floor - fix or remove the file",
                path.display()
            )
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!(
            "reading persisted libp2p identity seed {}: {e}",
            path.display()
        )),
    }
}

/// Persist `seed` to `path` as 64 lowercase-hex chars, mode 0600, with the SAME atomic +
/// fsync discipline the sequence floor uses (write a sibling temp, fsync it, rename, fsync the
/// parent directory) so a crash right after first announce cannot leave a torn or lost
/// identity file.
fn save_identity_seed(path: &Path, seed: &[u8; 32]) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let parent = path.parent();
    if let Some(parent) = parent {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("creating libp2p state dir {}: {e}", parent.display()))?;
    }
    let hex: String = seed.iter().map(|b| format!("{b:02x}")).collect();
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| format!("creating identity-seed temp {}: {e}", tmp.display()))?;
        f.write_all(hex.as_bytes())
            .and_then(|()| f.write_all(b"\n"))
            .and_then(|()| f.sync_all())
            .map_err(|e| format!("writing identity-seed temp {}: {e}", tmp.display()))?;
    }
    std::fs::rename(&tmp, path)
        .map_err(|e| format!("renaming identity-seed into place {}: {e}", path.display()))?;
    if let Some(parent) = parent {
        std::fs::File::open(parent)
            .and_then(|d| d.sync_all())
            .map_err(|e| format!("fsync libp2p state dir {}: {e}", parent.display()))?;
    }
    Ok(())
}

/// The durable floor/sequence sidecars a fabric writes under a state dir - the pieces that,
/// if present while the identity file is ABSENT, mean the state dir is inconsistent (see
/// [`resolve_durable_identity_seed`]). Returns which of them exist under `dir`.
fn orphaned_floor_sidecars(dir: &Path) -> Vec<&'static str> {
    [ANNOUNCE_SEQ_FILENAME, PROVIDER_FLOOR_FILENAME]
        .into_iter()
        .filter(|name| dir.join(name).exists())
        .collect()
}

/// Resolve this node's 32-byte libp2p identity seed, anchoring it to `state_dir` when given
/// (TASK-185 GB1) so a plain identical-argv restart with only `--libp2p-state-dir` yields a
/// STABLE identity - and therefore a usable durable sequence floor (both are keyed to the
/// same directory). Precedence, fail-safe:
///   * No `state_dir`: `explicit` if given, else a fresh `/dev/urandom` seed - the historical
///     session-scoped behaviour (the caller warns that a provider here is non-durable).
///   * `state_dir`, no `explicit`: load the persisted seed if present, else generate one and
///     PERSIST it so the next restart reloads the SAME identity.
///   * `state_dir` AND `explicit`: the explicit seed WINS but must be CONSISTENT with any
///     persisted seed - a mismatch is a hard ERROR (fail-safe), because an explicit seed that
///     disagrees with the dir's identity would silently orphan that dir's floor. When nothing
///     is persisted yet, the explicit seed is persisted so later state-dir-only restarts match.
///
/// STATE-DIR CONSISTENCY (TASK-185 re-gate): the identity file is created EAGERLY (before any
/// floor/sequence file), so a floor/sequence sidecar present while the identity is ABSENT can
/// ONLY mean the identity was lost under partial corruption. Generating a fresh identity there
/// would silently REKEY this node and orphan the records the surviving floor is bound to - the
/// GB1 failure class, re-opened via partial loss. That direction is fail-closed here.
///
/// HONEST LIMIT (the symmetric direction is NOT cleanly detectable, and is deliberately NOT
/// special-cased here - TASK-189): the floor/sequence files are created LAZILY (a pure consumer
/// never writes an announce-seq file; a provider writes it only on its first announce), so
/// "identity present, floor absent" is INDISTINGUISHABLE from a legitimate first boot / pure
/// consumer / pre-first-announce provider. Fail-closing on it would break normal operation.
/// Fully closing that direction (and the whole partial-corruption space) needs a single atomic
/// durable-state file with an init marker, tracked as TASK-189.
pub fn resolve_durable_identity_seed(
    state_dir: Option<&Path>,
    explicit: Option<[u8; 32]>,
) -> Result<[u8; 32], String> {
    let Some(dir) = state_dir else {
        return match explicit {
            Some(seed) => Ok(seed),
            None => random_identity_seed(),
        };
    };
    let path = dir.join(IDENTITY_SEED_FILENAME);
    let persisted = load_identity_seed(&path)?;
    if persisted.is_none() {
        // Identity absent: refuse to (re)generate one while a durable floor it would NOT own
        // survives on disk. A false positive is impossible - the identity is written before any
        // floor, so a floor without an identity is always loss, never a legitimate first boot.
        let orphaned = orphaned_floor_sidecars(dir);
        if !orphaned.is_empty() {
            return Err(format!(
                "libp2p state dir {} is INCONSISTENT: durable floor/sequence file(s) {orphaned:?} \
                 exist but the identity file {IDENTITY_SEED_FILENAME} is missing. Regenerating an \
                 identity would silently rekey this node and orphan its existing records. Refusing \
                 to start: restore {IDENTITY_SEED_FILENAME}, or wipe the state dir to start fresh.",
                dir.display()
            ));
        }
    }
    match (explicit, persisted) {
        (Some(seed), Some(disk)) if seed != disk => Err(format!(
            "--libp2p-identity-seed disagrees with the identity already persisted in {}; \
             refusing to start (an explicit seed that differs from the state dir's identity \
             would orphan its anti-rollback floor). Remove the flag to use the persisted \
             identity, or point --libp2p-state-dir at a fresh directory.",
            path.display()
        )),
        (Some(seed), Some(_consistent)) => Ok(seed),
        (Some(seed), None) => {
            save_identity_seed(&path, &seed)?;
            Ok(seed)
        }
        (None, Some(disk)) => Ok(disk),
        (None, None) => {
            let seed = random_identity_seed()?;
            save_identity_seed(&path, &seed)?;
            Ok(seed)
        }
    }
}

/// Announce a signed provider record for each `(nar_hash, nar_bytes)` seed through `fabric`,
/// DURABLY allocating each record's sequence (TASK-185 AC#2) from the fabric's announcer floor,
/// signing with `identity_seed` (self-serve: must be the fabric's own identity), and
/// publishing under `budget`. Returns the announced records (index-aligned with `seeds`) so a
/// caller can log their keys/sequences.
///
/// This is THE shipped provider announce path (SSOT): BOTH thin binaries' `--libp2p-provider`
/// install AND the TASK-185 restart-durability integration test call this exact function, so a
/// mutation here (e.g. a hardcoded `sequence`) is caught by the test rather than hiding in a
/// binary `fn main` no test exercises.
///
/// It is a PRIVATE / LAN announce (requires a [`LanShare`] witness): the operator-named seed bytes
/// are content-verified (TASK-56) but NOT publication-authorized. Announcing them to a gated PUBLIC
/// DHT must go through the allowlist door (TASK-102/103); the shipped modes assert `LanShare` only
/// after the bootstrap guard refuses a bootstrapped announce without a configured allowlist.
pub async fn announce_provider_seeds(
    fabric: &Libp2pFabric,
    identity_seed: [u8; 32],
    seeds: &[(NarHashKey, Vec<u8>)],
    _lan: LanShare,
    ttl_secs: u64,
    now: u64,
    budget: &AnnounceBudget,
) -> Result<Vec<ProviderRecord>, String> {
    // LAN door (AC#3): the witness is minted via an EXPLICIT AdmitAllPublication - NOT
    // allowlist-gated. On a PUBLIC-reachable node the fabric's OWN authority (allowlist or
    // RefusePublication) still refuses at the adapter, so this permissive witness does not open a
    // bypass; on a genuinely-isolated node the fabric's AdmitAll authority admits.
    announce_seed_records(
        fabric,
        identity_seed,
        seeds,
        &AdmitAllPublication,
        ttl_secs,
        now,
        budget,
    )
    .await
}

/// The shared raw-seed announce loop: TASK-56-verify every seed, then per key
/// durably-allocate the sequence, sign, and announce. PRIVATE to this module - BOTH the
/// substrate-neutral LAN door ([`announce_provider_seeds`]) and the allowlist-gated PUBLIC
/// door ([`announce_public_seeds`]) funnel through it, so the verify-then-sign SSOT (the
/// site where a provider CLAIM is minted) is single-sourced and a public seed announce
/// signs the exact same record a LAN one would.
async fn announce_seed_records(
    fabric: &Libp2pFabric,
    identity_seed: [u8; 32],
    seeds: &[(NarHashKey, Vec<u8>)],
    witness_authority: &dyn PublicationEligibility,
    ttl_secs: u64,
    now: u64,
    budget: &AnnounceBudget,
) -> Result<Vec<ProviderRecord>, String> {
    // TASK-56: verify every seed's bytes hash to its declared NarHash BEFORE signing or
    // announcing ANY record. This is the shipped SSOT where the provider CLAIM is minted
    // (both thin binaries and the composite daemon call this exact loop), so a
    // mis-specified `--libp2p-seed-nar <X>=/path/to/Y.nar` is refused here instead of
    // advertising a false claim. Refusing the whole batch up front means no partial
    // announce leaves a false record behind a later mismatch.
    verify_provider_seeds(seeds).map_err(|e| e.to_string())?;
    let announcer = fabric
        .announcer()
        .ok_or_else(|| "internal: libp2p provider fabric exposes no announcer".to_string())?;
    let mut records = Vec::with_capacity(seeds.len());
    for (nar_hash, bytes) in seeds {
        // Allocate the durable sequence, then sign, then announce - in that order, per key
        // (the allocation is a non-reserving read finalised by announce's save-before-publish).
        let sequence = fabric.next_announce_sequence(&provider_content_key(nar_hash));
        let record =
            sign_libp2p_provider_record(identity_seed, nar_hash, bytes, ttl_secs, now, sequence);
        // TASK-231 (AC#1): mint the eligibility witness for THIS path's authority (AdmitAll for
        // the LAN door, the allowlist for the public door), then hand it to `announce`. The
        // announcer ALSO re-checks with its own per-fabric authority, so a public node still
        // refuses an unallowlisted record even if this witness is permissive.
        let witness = witness_authority.authorize(record.clone()).map_err(|e| {
            format!("publication eligibility refused libp2p seed record for {nar_hash}: {e}")
        })?;
        announcer
            .announce(&witness, budget)
            .await
            .map_err(|e| format!("announcing libp2p provider record for {nar_hash}: {e}"))?;
        records.push(record);
    }
    Ok(records)
}

/// One VERIFIED store-supply provision: a `nar_hash` this node will announce, the availability
/// index's VERIFIED raw-NAR [`Blake3Digest`] for it, and its declared (uncompressed) `NarSize`.
///
/// It is a CAPABILITY, not a plain record: its fields are private and it has NO public
/// constructor, so the ONLY way to obtain one is [`verify_store_provisions`], which mints it
/// only after the availability index's TASK-56 `sha256(--dump) == nar_hash` check passed.
/// [`announce_store_provisions`] consumes `&[StoreProvision]`, so - by the type system - the
/// SHIPPED store-announce path can never announce a record for a store path that was not
/// verification-gated. This is the store analogue of the
/// `verify_provider_seeds`-before-`announce_provider_seeds` discipline, made gated-by-construction
/// on the shipped path rather than merely conventional. NOTE (not absolute): the lower-level
/// [`sign_libp2p_store_record`] takes a raw caller-supplied digest and is NOT itself
/// `StoreProvision`-gated - a direct library caller could sign an unverified record (a footgun no
/// shipped call site uses). Generic record-signing makes library-wide prevention impossible; the
/// guarantee is that the `--libp2p-provide-store` announce path is type-gated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreProvision {
    nar_hash: NarHashKey,
    content: Blake3Digest,
    declared_size: u64,
}

impl StoreProvision {
    /// The Nix NarHash the store path was registered under (the discovery key a consumer looks
    /// this provider up by).
    pub fn nar_hash(&self) -> &NarHashKey {
        &self.nar_hash
    }

    /// The raw-NAR `BLAKE3(RawNarV1)` the index VERIFIED this path dumps to (TASK-56) - the
    /// `content` the announced record advertises and the serve path gate-1 BLAKE3-verifies.
    pub fn content(&self) -> Blake3Digest {
        self.content
    }

    /// The declared UNCOMPRESSED NAR size (the index's persisted `NarSize`, NOT a compressed
    /// FileSize), learned WITHOUT re-dumping - the admission size a serve budget checks. A
    /// caller refuses to announce a provision over its per-NAR serve bound with this, so it does
    /// not publish a claim it would then decline (the store analogue of the seed-size guard).
    pub fn declared_size(&self) -> u64 {
        self.declared_size
    }
}

/// The STORE analogue of [`verify_provider_seeds`] (AC#2, TASK-191): gate the store-supply
/// announce on the TASK-56 verification, deriving each provision's advertised content FROM the
/// availability index's verified binding rather than the operator's word.
///
/// For each `nar_hash`, [`AvailabilityIndex::hold`] runs the TASK-56 index-side check - dump the
/// store path, assert `sha256(--dump) == nar_hash`, QUARANTINE a mismatch - and, on success,
/// publishes the reverse-map record into the supply catalog (so the [`Libp2pCatalogProbe`]-backed
/// [`fabric_libp2p::CatalogNarSupplier`] can then serve it) and returns the VERIFIED
/// `Blake3Digest`. The whole batch is refused (fail-fast, BEFORE any record is signed or
/// announced) if ANY key:
///   * QUARANTINED - the store path dumps to a different NarHash (a mis-registration); or
///   * `Absent` - the store path is not materialised (never registered here, or GC'd); or
///   * errors in the dump/persist.
///
/// So a store path the index quarantined or never verified is NEVER announced, and there is no
/// parallel unverified announce path: the ONLY way to obtain a [`StoreProvision`] is through this
/// gate. The returned provisions carry the verified digest, which [`sign_libp2p_store_record`]
/// advertises as the record `content`.
///
/// BLOCKING NOTE: `hold` shells out to `nix-store --dump` under a per-entry lock (a blocking
/// dump). This runs at provider STARTUP, once per provided path, before the serve loop begins,
/// so the brief block is acceptable; a large provided set on an async runtime should drive this
/// via `spawn_blocking` (a follow-up, not a correctness gap).
pub fn verify_store_provisions(
    index: &AvailabilityIndex,
    nar_hashes: &[NarHashKey],
) -> Result<Vec<StoreProvision>, String> {
    let catalog = index.supply_catalog();
    let mut provisions = Vec::with_capacity(nar_hashes.len());
    for nar_hash in nar_hashes {
        match index.hold(nar_hash).map_err(|e| {
            format!(
                "verifying store provision {nar_hash} against the availability index: {e}; \
                 refusing to announce a store path the index has not verified"
            )
        })? {
            HoldAnswer::Have { blake3, .. } => {
                // `hold` just PUBLISHED the reverse-map record (verified digest -> store path)
                // into the supply catalog, so its declared NarSize is now readable here without
                // a re-dump. Its absence would mean the record was retired between hold and now
                // (a concurrent unregister) - fail loud rather than announce a size we cannot
                // confirm.
                let declared_size = catalog
                    .probe_record(&blake3)
                    .map(|r| r.declared_size)
                    .ok_or_else(|| {
                        format!(
                            "store provision {nar_hash} verified to {blake3} but its supply record \
                         vanished before its size could be read; refusing to announce"
                        )
                    })?;
                provisions.push(StoreProvision {
                    nar_hash: *nar_hash,
                    content: blake3,
                    declared_size,
                });
            }
            HoldAnswer::Absent => {
                return Err(format!(
                    "store provision {nar_hash} is not held by the availability index (the store \
                     path is unregistered or no longer materialised); refusing to announce a \
                     claim this node cannot serve"
                ));
            }
        }
    }
    Ok(provisions)
}

/// A WITNESS that an announce targets a PRIVATE / LAN / operator-assembled substrate, NOT a
/// gated PUBLIC DHT. [`announce_provider_seeds`] and [`announce_store_provisions`] require one, so
/// a call site must EXPLICITLY declare "this is a private announce" - it can never be confused
/// with the PUBLIC door, which instead consumes an allowlist-minted [`ApprovedPublicProvision`].
///
/// Publicness is a property of the SUBSTRATE (does this DHT reach strangers?), which the LIBRARY
/// cannot know; the composition root asserts it. The two guarantees are ORTHOGONAL: the private
/// loop still content-verifies every provision (TASK-56), so no bad store path is ever published;
/// what it does NOT assert is publication AUTHORIZATION (the allowlist). The shipped provider modes
/// construct this only AFTER refusing any bootstrapped (potentially public) announce without a
/// configured allowlist (the TASK-102 bootstrap guard; see `daemon-libp2p::main`/`daemon::main`).
#[derive(Debug, Clone, Copy)]
pub struct LanShare(());

impl LanShare {
    /// Assert this announce targets a private / LAN / operator-assembled substrate. The caller
    /// (the composition root) owns the assertion; the type only makes it EXPLICIT and greppable so
    /// a bare provision can never be handed to a PUBLIC announce API by accident.
    pub fn operator_assembled() -> Self {
        LanShare(())
    }
}

/// The FULL node-reachability configuration the LAN-isolation witness inspects (TASK-102 fix
/// cycle #2). Borrowed from the composition root's parsed CLI so the guard sees EVERY public-reach
/// signal the shipped config can express - not just the bootstrap vector, which was the residual
/// hole: a provider started with `--libp2p-provider-addr` (a dial-addr override) but EMPTY
/// `--libp2p-bootstrap` STILL joins the public kad DHT (the provider-addr enters the routing table),
/// yet a bootstrap-only guard minted a `LanShare` and announced UNGATED. `bootstrap-empty` is NOT
/// `isolated-LAN`; the witness must require POSITIVE proof the node is loopback/link-local-only.
pub struct LanReachability<'a> {
    /// `--libp2p-bootstrap` peers. ANY entry means the node is joining a kad DHT it did not
    /// assemble; whatever that bootstrap peer bridges to (potentially the public DHT) receives the
    /// announced records. Presence alone is a public-reach signal, regardless of the peer's address.
    pub bootstrap: &'a [(PeerId, Multiaddr)],
    /// `--libp2p-provider-addr` seeds. ANY entry is `add_address`-ed into the kad routing table (a
    /// dial-addr override / entry hint), giving an otherwise-empty-bootstrap provider a peer to
    /// `start_providing`/`put_record` against - the EXACT residual that let an ungated announce
    /// reach a public substrate. Presence alone is a public-reach signal, like a bootstrap peer.
    pub provider_addrs: &'a [(PeerId, Multiaddr)],
    /// `--libp2p-listen` bind address, if any. A listen address that is NOT provably
    /// loopback/link-local (a public IP, a wildcard `0.0.0.0`/`::`, or a DNS name) makes the node
    /// reachable by strangers, so it is a public-reach signal. A loopback/link-local listen is not.
    pub listen: Option<&'a Multiaddr>,
}

/// Whether a multiaddr is PROVABLY LAN-only: it carries at least one inspectable IP literal and
/// every such literal is loopback or link-local. A multiaddr without an inspectable IP (a DNS name
/// that resolves to who-knows-what, a relay `/p2p-circuit`, or a wildcard `0.0.0.0`/`::` which
/// binds every interface including public ones) is NOT provably local, so this returns `false` -
/// fail-closed: absence of proof is treated as public-reach, never assumed safe.
fn multiaddr_is_lan_only(addr: &Multiaddr) -> bool {
    use fabric_libp2p::Protocol;
    let mut saw_ip = false;
    for proto in addr.iter() {
        match proto {
            Protocol::Ip4(ip) => {
                saw_ip = true;
                if !(ip.is_loopback() || ip.is_link_local()) {
                    return false;
                }
            }
            Protocol::Ip6(ip) => {
                saw_ip = true;
                // `Ipv6Addr::is_unicast_link_local` is unstable, so test the `fe80::/10` prefix
                // directly. Loopback `::1` is covered by `is_loopback`.
                let link_local = (ip.segments()[0] & 0xffc0) == 0xfe80;
                if !(ip.is_loopback() || link_local) {
                    return false;
                }
            }
            // A hostname resolves to an address we cannot inspect here; treat as non-local.
            Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_) | Protocol::Dnsaddr(_) => {
                return false;
            }
            _ => {}
        }
    }
    saw_ip
}

/// The TASK-102 LAN-isolation witness (fix cycle #2): mint a [`LanShare`] ONLY when the node is
/// provably isolated from any public substrate, else REFUSE (fail-closed, naming TASK-103). This is
/// the ONE place the shipped provider modes turn a reachability config into the private-announce
/// witness, so both thin binaries share exactly one policy (no per-binary drift).
///
/// It refuses on ANY public-reach signal in `reach`:
///   1. a non-empty `--libp2p-bootstrap` (joining a DHT we did not assemble);
///   2. a non-empty `--libp2p-provider-addr` (an external entry seeded into the kad routing table -
///      the residual that let an empty-bootstrap provider still announce to the public DHT); or
///   3. a `--libp2p-listen` address that is not provably loopback/link-local.
///
/// A relay is NOT a shipped-config signal (the thin binaries expose no relay flag), so there is
/// nothing to check for it here; were a relay flag added, it would be a fourth refusal.
///
/// Only a node with NO bootstrap, NO provider-addr, and (if listening at all) a loopback/link-local
/// listen is `LanShare`-eligible - the genuinely-isolated single-host / link-local MVP. The real
/// allowlist-gated PUBLIC announce door that lifts this restriction is TASK-103's hard blocker.
pub fn lan_isolation_or_refuse(reach: LanReachability<'_>) -> Result<LanShare, String> {
    if !reach.bootstrap.is_empty() {
        return Err(
            "refusing to announce provider records: --libp2p-bootstrap joins a (potentially \
             PUBLIC) kad DHT and there is no configured public-NAR allowlist, so this would publish \
             operator-named local content to strangers. The allowlist-gated public announce door is \
             wired by TASK-103; run with NO --libp2p-bootstrap, NO --libp2p-provider-addr, and a \
             loopback/link-local --libp2p-listen for an isolated LAN announce."
                .to_string(),
        );
    }
    if !reach.provider_addrs.is_empty() {
        return Err(
            "refusing to announce provider records: --libp2p-provider-addr seeds an external peer \
             into the kad routing table, so even with an empty --libp2p-bootstrap the node can reach \
             a (potentially PUBLIC) DHT to store its records - and there is no configured public-NAR \
             allowlist, so this would publish operator-named local content to strangers. The \
             allowlist-gated public announce door is wired by TASK-103; run with NO \
             --libp2p-provider-addr for an isolated LAN announce."
                .to_string(),
        );
    }
    if let Some(listen) = reach.listen
        && !multiaddr_is_lan_only(listen)
    {
        return Err(format!(
            "refusing to announce provider records: --libp2p-listen {listen} is not provably \
             loopback/link-local, so the node is reachable by strangers and its announce could \
             reach a public substrate - and there is no configured public-NAR allowlist. The \
             allowlist-gated public announce door is wired by TASK-103; listen on a \
             loopback/link-local address for an isolated LAN announce."
        ));
    }
    Ok(LanShare::operator_assembled())
}

/// A verified store [`StoreProvision`] PAIRED with the allowlist [`PublicNarClaim`] that
/// authorises announcing it PUBLICLY. Private fields, minted ONLY by
/// [`approve_provisions_for_public`], so a public announce CANNOT be represented without an
/// allowlist-minted claim - the claim is LOAD-BEARING (held through the announce), not cosmetic.
#[derive(Debug, Clone)]
pub struct ApprovedPublicProvision {
    provision: StoreProvision,
    /// The unforgeable proof the allowlist approved this NAR for public announce. Held (never
    /// discarded) so this capability cannot exist without it.
    claim: PublicNarClaim,
}

impl ApprovedPublicProvision {
    /// The verified provision to announce (its `content` is the TASK-56-verified digest).
    pub fn provision(&self) -> &StoreProvision {
        &self.provision
    }

    /// The allowlist claim authorising the PUBLIC announce of this provision's NAR.
    pub fn claim(&self) -> &PublicNarClaim {
        &self.claim
    }
}

/// The single TASK-102 publication-eligibility decision as a PER-FABRIC authority the shipped
/// announcer HOLDS (TASK-231, AC#2): it ADMITS exactly the derived [`ContentKey`]s of the NARs the
/// [`PublicNarAllowlist`] proved public. The public provider path injects this so the announcer
/// refuses - fail-closed, AT THE ADAPTER, before any `start_providing`/`put_record` - any record the
/// allowlist did not approve. This is what structurally closes the bypass where a freely-minted LAN
/// witness reached `announce` carrying an unallowlisted-but-signed record.
pub struct AllowlistEligibility {
    allowlist: Arc<PublicNarAllowlist>,
}

impl AllowlistEligibility {
    /// An authority backed by `allowlist` - the SAME instance the public door consults, so the
    /// announcer's re-check and the door's approve gate are ONE decision (single source of truth).
    pub fn new(allowlist: Arc<PublicNarAllowlist>) -> Self {
        AllowlistEligibility { allowlist }
    }
}

impl PublicationEligibility for AllowlistEligibility {
    fn admit(&self, record: &ProviderRecord) -> Result<(), IneligibleReason> {
        allowlist_admits(&self.allowlist, record)
    }
}

/// A BORROWED allowlist authority used only to MINT a public-announce witness at the door
/// (transient): the public path's witness is thus genuinely allowlist-gated (AC#3), distinct from
/// the LAN path's [`AdmitAllPublication`] witness. Never stored; `authorize` returns an owned witness
/// and the borrow ends with the call.
struct AllowlistWitnessAuthority<'a> {
    allowlist: &'a PublicNarAllowlist,
}

impl PublicationEligibility for AllowlistWitnessAuthority<'_> {
    fn admit(&self, record: &ProviderRecord) -> Result<(), IneligibleReason> {
        allowlist_admits(self.allowlist, record)
    }
}

/// The ONE admit rule both allowlist authorities share: a record is admitted iff its derived
/// [`ContentKey`] matches an allowlisted NAR. The frozen `ProviderRecord` carries no `NarHash`
/// preimage, so the allowlist reverse-derives each entry's key (see
/// [`PublicNarAllowlist::contains_content_key`]). Fail-closed: no match -> refuse.
fn allowlist_admits(
    allowlist: &PublicNarAllowlist,
    record: &ProviderRecord,
) -> Result<(), IneligibleReason> {
    if allowlist.contains_content_key(&record.key) {
        Ok(())
    } else {
        Err(IneligibleReason::NotAllowlisted)
    }
}

/// The shared record-signing announce loop. PRIVATE to this module: neither the public nor the
/// private door is a bare-provision entry point reachable from outside. For each provision it
/// durably allocates the announce sequence, signs a record whose `content` is the verified digest
/// (via [`sign_libp2p_store_record`]), and publishes it under `budget`.
async fn announce_store_records(
    fabric: &Libp2pFabric,
    identity_seed: [u8; 32],
    provisions: &[StoreProvision],
    witness_authority: &dyn PublicationEligibility,
    ttl_secs: u64,
    now: u64,
    budget: &AnnounceBudget,
) -> Result<Vec<ProviderRecord>, String> {
    let announcer = fabric
        .announcer()
        .ok_or_else(|| "internal: libp2p provider fabric exposes no announcer".to_string())?;
    let mut records = Vec::with_capacity(provisions.len());
    for provision in provisions {
        let sequence = fabric.next_announce_sequence(&provider_content_key(&provision.nar_hash));
        let record = sign_libp2p_store_record(
            identity_seed,
            &provision.nar_hash,
            provision.content,
            ttl_secs,
            now,
            sequence,
        );
        // TASK-231 (AC#1): mint this path's eligibility witness (see `announce_seed_records`).
        let witness = witness_authority.authorize(record.clone()).map_err(|e| {
            format!(
                "publication eligibility refused libp2p store record for {}: {e}",
                provision.nar_hash
            )
        })?;
        announcer.announce(&witness, budget).await.map_err(|e| {
            format!(
                "announcing libp2p store provider record for {}: {e}",
                provision.nar_hash
            )
        })?;
        records.push(record);
    }
    Ok(records)
}

/// Announce a signed [`ProviderRecord`] for each VERIFIED store [`StoreProvision`] this node serves
/// on demand over a PRIVATE / LAN substrate (AC#1/#2, TASK-191), the store analogue of
/// [`announce_provider_seeds`]. It requires a [`LanShare`] witness, so the call site EXPLICITLY
/// declares the substrate is not a gated public DHT (the PUBLIC analogue is
/// [`announce_public_provisions`], which instead demands allowlist claims).
///
/// It consumes only [`StoreProvision`]s, which - being an un-forgeable capability minted solely by
/// [`verify_store_provisions`] - GUARANTEES every announced `content` came from the index's
/// TASK-56-verified binding, never the operator's word. The `fabric-libp2p` serve path re-runs the
/// len + BLAKE3 recheck (TASK-158/193) as the last-line integrity anchor.
pub async fn announce_store_provisions(
    fabric: &Libp2pFabric,
    identity_seed: [u8; 32],
    provisions: &[StoreProvision],
    _lan: LanShare,
    ttl_secs: u64,
    now: u64,
    budget: &AnnounceBudget,
) -> Result<Vec<ProviderRecord>, String> {
    // LAN door (AC#3): AdmitAll witness, as `announce_provider_seeds`.
    announce_store_records(
        fabric,
        identity_seed,
        provisions,
        &AdmitAllPublication,
        ttl_secs,
        now,
        budget,
    )
    .await
}

// -------------------------------------------------------------------------
// The TYPED PUBLIC-ANNOUNCE door (TASK-102): the ONLY announce path gated on the
// public-NAR allowlist. Closed-by-construction, so a PUBLIC announce cannot bypass it.
// -------------------------------------------------------------------------

/// CONSULT the public-NAR allowlist for a batch of verified store provisions a node
/// intends to announce PUBLICLY, minting one [`PublicNarClaim`] per provision. FAIL-CLOSED
/// and ALL-OR-NOTHING: if ANY provision is not allowlisted (never proven public via a
/// trusted cache.nixos.org signature), the WHOLE batch is refused and NO claim is minted,
/// so no partial announce can leak an un-approved NAR.
///
/// This is the single consult point (AC#1) the PUBLIC announce door goes through. It is a
/// PURE function of `(provisions, allowlist)`, so the closed-by-construction gate is
/// unit-testable without a live DHT: an operator-seeded LOCAL fixture (absent from the
/// allowlist) yields a NAMED [`PublicationRejected`] and mints nothing. The size the
/// allowlist proved must equal the provision's declared NarSize, or the claim is refused
/// (a NAR can be announced only at exactly the size a trusted signature covered).
///
/// It is deliberately SEPARATE from [`announce_provider_seeds`] / [`announce_store_provisions`],
/// which are SUBSTRATE-NEUTRAL (they legitimately serve LAN / private / test announces where
/// operator-named local content is fine). Publicness is a property of the SUBSTRATE, so the
/// allowlist gate belongs only at the PUBLIC boundary - this door - not inside the neutral loops.
pub fn approve_provisions_for_public(
    provisions: &[StoreProvision],
    allowlist: &PublicNarAllowlist,
) -> Result<Vec<ApprovedPublicProvision>, PublicationRejected> {
    let mut approved = Vec::with_capacity(provisions.len());
    for provision in provisions {
        // `approve` mints an UNFORGEABLE PublicNarClaim iff the NarHash is allowlisted AND its
        // approved size matches what this node would advertise. Absence -> fail-closed. The claim
        // is PAIRED with the provision into the capability and HELD through the announce, so a
        // public announce cannot be represented without it.
        let claim = allowlist.approve(provision.nar_hash(), Some(provision.declared_size()))?;
        approved.push(ApprovedPublicProvision {
            provision: provision.clone(),
            claim,
        });
    }
    Ok(approved)
}

/// Announce a signed [`ProviderRecord`] for each verified store [`StoreProvision`], but
/// ONLY after the public-NAR allowlist has PROVEN every one publishable (TASK-102). This is
/// the PUBLIC analogue of [`announce_store_provisions`]: it FIRST runs
/// [`approve_provisions_for_public`] (fail-closed, all-or-nothing) and announces nothing if
/// any provision is un-allowlisted, then reuses the same verified-content announce loop.
///
/// STATUS: this typed door exists so that - by construction - the only way to PUBLICLY announce
/// store content is through the allowlist gate. It takes `provisions + allowlist` and CONSUMES the
/// minted [`ApprovedPublicProvision`]s (claim held through the announce), so a public announce with
/// no allowlist-minted claim is UNREPRESENTABLE - there is no bare-provision public entry point.
/// It is not yet wired to a shipped binary: TASK-103 (the DHT discovery-announce driver) is the
/// integration that routes public participation through this door and populates the allowlist for
/// operator-provided paths by proving each public via the same narinfo-signature gate.
pub async fn announce_public_provisions(
    fabric: &Libp2pFabric,
    identity_seed: [u8; 32],
    provisions: &[StoreProvision],
    allowlist: &PublicNarAllowlist,
    ttl_secs: u64,
    now: u64,
    budget: &AnnounceBudget,
) -> Result<Vec<ProviderRecord>, String> {
    // THE GATE (fail-closed, before any record is signed or announced): every provision must be
    // allowlisted, minting a claim-bearing capability, or the whole public announce is refused.
    let approved = approve_provisions_for_public(provisions, allowlist)
        .map_err(|rejected| format!("public announce refused by the allowlist gate: {rejected}"))?;
    announce_approved_public(
        fabric,
        identity_seed,
        &approved,
        allowlist,
        ttl_secs,
        now,
        budget,
    )
    .await
}

/// Announce a record per [`ApprovedPublicProvision`], the PUBLIC counterpart of
/// [`announce_store_records`]. Consuming the capability (claim held) is what makes a public
/// announce impossible without an allowlist-minted claim. The witness is minted from the SAME
/// `allowlist` (AC#2/#3): allowlist-gated, distinct from the LAN path's AdmitAll witness.
async fn announce_approved_public(
    fabric: &Libp2pFabric,
    identity_seed: [u8; 32],
    approved: &[ApprovedPublicProvision],
    allowlist: &PublicNarAllowlist,
    ttl_secs: u64,
    now: u64,
    budget: &AnnounceBudget,
) -> Result<Vec<ProviderRecord>, String> {
    let provisions: Vec<StoreProvision> = approved
        .iter()
        .map(|a| {
            // The claim is load-bearing: its NarHash must match the provision it authorises.
            debug_assert_eq!(a.claim().nar_hash(), a.provision().nar_hash());
            a.provision().clone()
        })
        .collect();
    announce_store_records(
        fabric,
        identity_seed,
        &provisions,
        &AllowlistWitnessAuthority { allowlist },
        ttl_secs,
        now,
        budget,
    )
    .await
}

// -------------------------------------------------------------------------
// ANNOUNCE-AFTER-FETCH (TASK-77): the swarm-GROWTH hook. A node that just fetched a
// NAR becomes a discoverable holder for it, so popular paths acquire holders naturally.
// It REUSES the verified announce doors above (verify_store_provisions ->
// announce_store_provisions / announce_public_provisions) - there is deliberately NO
// second announce path that could bypass the TASK-231 eligibility authority.
// -------------------------------------------------------------------------

/// The publication door an announce-after-fetch node uses, mirroring the two shipped
/// provider doors (the substrate's publicness is a composition-root fact - see [`LanShare`] /
/// the allowlist - so the binary picks the door, never the library).
#[derive(Clone)]
pub enum AnnounceAfterFetchDoor {
    /// A PUBLIC (bootstrapped) substrate: announce ONLY allowlisted content. The allowlist is
    /// the SAME instance the fabric's `AllowlistEligibility` authority holds and that
    /// `respond_narinfo` keeps learning from the trusted-signed narinfos this node fetches, so a
    /// fetched path is announced iff a trusted narinfo proved it public - and the announcer
    /// re-checks that authority fail-closed (TASK-231). An unallowlisted fetched path is REFUSED
    /// here (nothing reaches the DHT).
    Public(Arc<PublicNarAllowlist>),
    /// A genuinely-isolated LAN substrate (the operator asserted no public reach): a fetched
    /// path may be announced without the public-allowlist gate (the fabric's `AdmitAll`
    /// authority admits), still TASK-56 verification-gated. The witness is the composition
    /// root's [`LanShare`].
    Lan(LanShare),
}

/// The integer announce BUDGET + the dedup state (TASK-77 AC#2). One `Mutex` guards all three so
/// the reserve/dedup/refund decisions are atomic under concurrent fetches.
///
/// The budget is spent on RESERVE and REFUNDED if the grow does not actually announce (TASK-77
/// FIX 2): a fetch that fails eligibility, never materialises, or fails to publish must NOT
/// permanently consume a node's growth budget - only a real announce does. So a stream of invalid
/// fetches cannot exhaust the budget.
struct AnnounceLedger {
    /// Remaining announce-after-fetch announces this process may still make. An INTEGER (no
    /// float). At zero, announcing STOPS (not degrades) - the guardrail against unbounded
    /// self-DoS + the privacy surface (every announce reveals a path you fetched).
    remaining: u64,
    /// Keys whose grow is IN FLIGHT (reserved, not yet committed). Prevents a concurrent duplicate
    /// grow for the same key, and is where a refund returns the unit from on failure.
    inflight: HashSet<NarHashKey>,
    /// Keys SUCCESSFULLY announced (budget spent for good). Dedup: a re-fetch of an already-
    /// announced path is a no-op (this node is already a holder).
    announced: HashSet<NarHashKey>,
    /// The still-advertised holdings, `nar_hash -> (announced ContentKey, store path)` (TASK-77
    /// FIX 3b/D). [`reconcile`] walks this to WITHDRAW any holding whose store path was GC'd, so the
    /// node self-heals a record it can no longer serve. This is EVENTUALLY consistent, not
    /// instantaneous: between a GC (or an ambiguous announce) and the next successful reconcile, the
    /// node CAN transiently keep advertising a record it cannot serve - bounded by reconcile-on-
    /// dispatch and the record's kad TTL (a stale record costs a querier one clean-declined retry,
    /// within the TCB; see the module doc's eventually-consistent residual). A withdrawn holding is
    /// dropped from here ONLY on a SUCCESSFUL withdraw (a failed one is KEPT for retry); it stays in
    /// `announced` for dedup, so its one budget unit is not re-spent.
    held: HashMap<NarHashKey, (ContentKey, String)>,
}

/// The outcome of [`begin`]: whether `on_fetched` should proceed to spawn a grow.
#[derive(Debug, PartialEq, Eq)]
enum Begin {
    /// A budget unit was reserved and the key marked in-flight; spawn the grow.
    Proceed,
    /// The key is already announced or a grow for it is in flight; do nothing (not a failure).
    AlreadyHandled,
    /// The budget is spent; announcing STOPS. This is the AC#2 enforcement point that `on_fetched`
    /// consults - the mutation that removes the guard (or the `begin` CALL in `on_fetched`) makes
    /// the announce count grow unbounded.
    Exhausted,
}

/// The pure AC#2 reserve: atomically dedup + reserve one budget unit for `key`, marking it
/// in-flight. Past the budget this returns [`Begin::Exhausted`] and `on_fetched` spawns NOTHING.
/// Pure over the ledger, so the production bite (drive `on_fetched`, count spawns) needs no
/// runtime/fabric. Removing the `remaining == 0` guard here - or the `begin` call in `on_fetched`
/// - lets the announce count grow unbounded (both mutations reddened by the budget bite).
fn begin(ledger: &Mutex<AnnounceLedger>, key: &NarHashKey) -> Begin {
    let mut led = ledger.lock().expect("announce ledger poisoned");
    if led.announced.contains(key) || led.inflight.contains(key) {
        return Begin::AlreadyHandled;
    }
    if led.remaining == 0 {
        return Begin::Exhausted;
    }
    led.remaining -= 1;
    led.inflight.insert(*key);
    Begin::Proceed
}

/// Commit a grow that DID announce: the reservation becomes permanent (budget stays spent), the
/// key moves to `announced` (dedup), and the holding is tracked in `held` (`content_key` +
/// `store_path`) so [`reconcile`] can withdraw it if the path is later GC'd (FIX 3b).
fn commit_success(
    ledger: &Mutex<AnnounceLedger>,
    key: &NarHashKey,
    content_key: ContentKey,
    store_path: String,
) {
    let mut led = ledger.lock().expect("announce ledger poisoned");
    led.inflight.remove(key);
    led.announced.insert(*key);
    led.held.insert(*key, (content_key, store_path));
}

/// Commit a grow that did NOT announce (ineligible / never-materialised / publish failed): REFUND
/// the reserved unit (TASK-77 FIX 2) so an invalid fetch does not consume growth budget, and drop
/// the in-flight mark so a later fetch of the same path may retry. Removing the `remaining += 1`
/// refund is the mutation the exhaustion bite catches (invalid fetches would then drain the budget).
fn commit_failure(ledger: &Mutex<AnnounceLedger>, key: &NarHashKey) {
    let mut led = ledger.lock().expect("announce ledger poisoned");
    if led.inflight.remove(key) {
        led.remaining += 1;
    }
}

/// Retract a provider record this node published (TASK-77 FIX 3b). Returns `true` iff the
/// withdrawal was published, so [`reconcile`] KEEPS a holding whose withdraw FAILED and retries it
/// on a later dispatch (FIX B). Decoupled from the fabric so the GC-withdraw bite needs no live
/// swarm: the production impl drives `fabric.announcer().withdraw` (the existing TASK-231 self-serve
/// tombstone path), the test double scripts success/failure.
#[async_trait]
trait Withdrawer: Send + Sync {
    async fn withdraw(&self, key: &ContentKey) -> bool;
}

/// The production [`Withdrawer`]: withdraw through the fabric's own announcer (the SAME announcer
/// that published the record, so the self-serve tombstone is signed by this node - TASK-231/152).
struct FabricWithdrawer {
    fabric: Arc<Libp2pFabric>,
}

#[async_trait]
impl Withdrawer for FabricWithdrawer {
    async fn withdraw(&self, key: &ContentKey) -> bool {
        let Some(announcer) = self.fabric.announcer() else {
            eprintln!("LIBP2P-ANNOUNCE-AFTER-FETCH withdraw skipped: fabric exposes no announcer");
            return false;
        };
        match announcer.withdraw(key).await {
            Ok(_) => {
                println!("LIBP2P-ANNOUNCE-AFTER-FETCH withdrew content_key={key} (GC'd path)");
                true
            }
            Err(e) => {
                eprintln!(
                    "LIBP2P-ANNOUNCE-AFTER-FETCH withdraw of {key} failed: {e} (retained; retried \
                     on the next fetch, and it expires by TTL regardless)"
                );
                false
            }
        }
    }
}

/// GC-serveability reconcile (TASK-77 FIX 3b, AC#3 / TASK-72): WITHDRAW every held record whose
/// store path is no longer materialised (GC'd since the announce), self-healing toward
/// index==provider coverage. This is EVENTUALLY consistent, not instantaneous: it runs
/// OPPORTUNISTICALLY (on the next dispatch), so between a GC and the next successful reconcile the
/// node CAN transiently keep advertising a record it cannot serve - bounded by that reconcile and
/// the record's kad TTL. Self-correcting, no disk growth, reuses the existing TASK-231 withdraw.
/// `path.exists()` is the GC signal (the store GC unlinks the path); the serve side ALSO fails
/// cleanly on a vanished path (fabric-libp2p re-dumps + BLAKE3-re-verifies before emitting a byte,
/// so a stale holding costs a peer a clean Declined retry, never a wrong byte - the transient
/// window is within the TCB), so this is the ACTIVE self-heal on top of that passive safety. A
/// holding is dropped from `held` ONLY on a SUCCESSFUL withdraw (FIX B): a failed withdraw is KEPT
/// so the next dispatch retries it. Removing the `withdraw` call - the mutation the production GC
/// bite catches - leaves a lasting false holding on the DHT.
async fn reconcile(ledger: &Mutex<AnnounceLedger>, withdrawer: &dyn Withdrawer) {
    // Snapshot the GC'd holdings under the lock (do not hold it across the async withdraw).
    let gone: Vec<(NarHashKey, ContentKey)> = {
        let led = ledger.lock().expect("announce ledger poisoned");
        led.held
            .iter()
            .filter(|(_, (_, store_path))| !Path::new(store_path).exists())
            .map(|(key, (content_key, _))| (*key, *content_key))
            .collect()
    };
    for (key, content_key) in gone {
        if withdrawer.withdraw(&content_key).await {
            // Drop it from `held` (stop tracking) ONLY on success; it stays in `announced` so its
            // budget unit is not re-spent by a later re-fetch of the same path. A FAILED withdraw is
            // KEPT in `held` so the next dispatch retries it (FIX B).
            ledger
                .lock()
                .expect("announce ledger poisoned")
                .held
                .remove(&key);
        }
    }
}

/// The nix-base32 alphabet (`0-9a-z` minus `e o u t`), the encoding of a store path's `<hash>`
/// component. Used by [`validate_store_path`] to reject a non-store-shaped path shape.
const NIXBASE32_ALPHABET: &[u8] = b"0123456789abcdfghijklmnpqrsvwxyz";

/// Structural validation (TASK-77 FIX 3a, tightened per FIX C) that `store_path` is a well-formed
/// Nix store path DIRECTLY under this node's REAL store directory - `<store_dir>/<32-char
/// nix-base32 hash>-<name>` - BEFORE the node registers/dumps it. It requires the path's PARENT to
/// be exactly `store_dir` (the daemon's `--store-dir`, `/nix/store` in production), so a merely
/// store-SHAPED path elsewhere (e.g. `/tmp/store/<validhash>-x`) is refused rather than dumped.
/// The narinfo `StorePath` is signature-covered for allowlisted content and the TASK-56
/// `sha256(nix-store --dump) == NarHash` check is the ULTIMATE integrity gate; this is cheap
/// defense-in-depth so a hostile/odd path can never make the node shell `nix-store --dump` at an
/// arbitrary filesystem path (e.g. `/etc/shadow`). It checks the SHAPE + LOCATION, not the hash
/// (that is nix's job at dump time).
fn validate_store_path(store_path: &str, store_dir: &str) -> Result<(), String> {
    let path = Path::new(store_path);
    if !path.is_absolute() {
        return Err(format!("store path {store_path:?} is not absolute"));
    }
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| format!("store path {store_path:?} has no valid final component"))?;
    let (hash, rest) = name
        .split_once('-')
        .ok_or_else(|| format!("store path basename {name:?} is not <hash>-<name>"))?;
    if hash.len() != 32 || !hash.bytes().all(|b| NIXBASE32_ALPHABET.contains(&b)) {
        return Err(format!(
            "store path basename {name:?} has a non-nix-base32 32-char <hash> component"
        ));
    }
    if rest.is_empty() {
        return Err(format!(
            "store path basename {name:?} has an empty <name> component"
        ));
    }
    // The immediate parent must be EXACTLY the node's real store dir, so a store-shaped path
    // outside `/nix/store` (a decoy `/tmp/store/<hash>-x`) is refused rather than dumped (FIX C).
    match path.parent() {
        Some(parent) if parent == Path::new(store_dir) => Ok(()),
        _ => Err(format!(
            "store path {store_path:?} is not directly under the store dir {store_dir:?}"
        )),
    }
}

/// The pure AC#3 core: STRUCTURALLY validate `store_path` (FIX 3a), register `key -> store_path`
/// in `index` and VERIFY it is servable (TASK-56 `sha256(--dump)==NarHash`, quarantine on
/// mismatch), enforce the per-NAR serve-size guard, and - for a PUBLIC door - approve it against
/// the allowlist (refuse an unallowlisted fetched path BEFORE any DHT touch). Returns the verified
/// provisions ready to announce, or a typed refusal. This is where "never announce what you cannot
/// serve" is enforced independently of the announcer's own TASK-231 re-check; removing the allowlist
/// approval (the mutation the eligibility bite catches) lets an unallowlisted fetched path become a
/// provision that would reach the DHT. Free + fabric-free so the bite needs no live swarm; the
/// blocking dump runs on the caller thread.
fn eligible_provisions(
    index: &AvailabilityIndex,
    serve_budget: &peer_fabric::ServeBudget,
    door: &AnnounceAfterFetchDoor,
    store_dir: &str,
    key: &NarHashKey,
    store_path: &str,
) -> Result<Vec<StoreProvision>, String> {
    validate_store_path(store_path, store_dir)?;
    index
        .register(*key, StorePath::new(store_path))
        .map_err(|e| format!("registering fetched store path {store_path:?} under {key}: {e}"))?;
    // verify_store_provisions runs the index's TASK-56 dump+sha256==NarHash gate and refuses (Err)
    // an Absent/quarantined/undumpable path - so index-coverage == provider-coverage.
    let provisions = verify_store_provisions(index, std::slice::from_ref(key))?;
    // Size guard: never announce a NAR the serve gate would then decline (TooLarge).
    for provision in &provisions {
        if provision.declared_size() > serve_budget.max_nar_bytes_uncompressed_nar {
            return Err(format!(
                "fetched NAR {} dumps to {} B but the per-NAR serve bound is {}: not announcing a \
                 claim this node would decline to serve",
                provision.nar_hash(),
                provision.declared_size(),
                serve_budget.max_nar_bytes_uncompressed_nar
            ));
        }
    }
    // PUBLIC door (AC#3): announce a fetched path iff a trusted narinfo proved it public (it is in
    // the allowlist). Refuses BEFORE any DHT touch; the announcer's TASK-231 authority is the
    // second, independent gate. A LAN door skips this (publicness asserted by the composition
    // root's LanShare), still TASK-56-gated.
    if let AnnounceAfterFetchDoor::Public(allowlist) = door {
        approve_provisions_for_public(&provisions, allowlist).map_err(|rejected| {
            format!("announce-after-fetch refused by the allowlist gate: {rejected}")
        })?;
    }
    Ok(provisions)
}

/// A bounded wait for the LOCAL nix to MATERIALISE a fetched path into `/nix/store` (TASK-77).
///
/// The daemon RELAYS the NAR bytes; the local nix imports+registers the store path a moment
/// AFTER the serve completes (nix builds into a temp dir then renames the finished tree into
/// place atomically). So announce-after-fetch waits (bounded, cheap `exists()` polls) for the
/// path to appear before it dumps + announces - you announce only once you can actually serve
/// (TASK-72). If it never materialises (a truncated body the client rejected, a pure relay with
/// no local store), the wait times out and NOTHING is announced: fail-safe, never a claim this
/// node cannot back. The bound is an integer count of polls at an integer interval (no float).
#[derive(Debug, Clone, Copy)]
struct MaterialiseWait {
    poll_interval: Duration,
    max_polls: u32,
}

impl Default for MaterialiseWait {
    fn default() -> Self {
        // 250 ms x 240 = up to 60 s: generous headroom for a large-closure import, while a
        // never-materialising path gives up promptly enough not to pile up tasks. Tunable
        // integers, not wire constants.
        MaterialiseWait {
            poll_interval: Duration::from_millis(250),
            max_polls: 240,
        }
    }
}

/// The clonable WORKER that does the actual grow (verify + announce) for one fetched path. It
/// holds only cheap-to-clone handles (Arcs + Copy budgets), so [`PostFetchAnnounce::on_fetched`]
/// can clone it into a detached task without needing `Arc<Self>`. The stateful ledger stays on
/// [`Libp2pAnnounceAfterFetch`]; the worker is stateless over the ledger.
#[derive(Clone)]
struct GrowWorker {
    fabric: Arc<Libp2pFabric>,
    identity_seed: [u8; 32],
    /// The SHARED availability index: the provider serve path (`CatalogNarSupplier`) reads its
    /// reverse-map, so a path THIS worker registers+verifies is immediately servable to a peer.
    index: Arc<AvailabilityIndex>,
    door: AnnounceAfterFetchDoor,
    /// The per-NAR serve bound: a fetched NAR larger than this is NOT announced (announcing it
    /// would publish a claim the serve gate would then decline - the same guard the provider
    /// applies at startup).
    serve_budget: peer_fabric::ServeBudget,
    /// The DHT publish bound (deadline + replica fan-out) each announce runs under.
    announce_budget: AnnounceBudget,
    /// The record TTL (seconds) an announced record carries, matching the provider's.
    ttl_secs: u64,
    /// This node's REAL store dir (`--store-dir`, `/nix/store` in production): a fetched path must
    /// be DIRECTLY under it or it is refused before any dump (FIX C).
    store_dir: String,
    materialise: MaterialiseWait,
}

impl GrowWorker {
    /// Register + VERIFY + (public) approve one fetched path (delegates to the pure, fabric-free
    /// [`eligible_provisions`]). See there for the "never announce what you cannot serve" argument.
    fn eligible_provisions(
        &self,
        key: &NarHashKey,
        store_path: &str,
    ) -> Result<Vec<StoreProvision>, String> {
        eligible_provisions(
            &self.index,
            &self.serve_budget,
            &self.door,
            &self.store_dir,
            key,
            store_path,
        )
    }

    /// Announce ONE verified provision through the fabric's announcer, returning the outcome
    /// CLASSIFIED (FIX D) by whether a DHT side-effect could have occurred. This drives
    /// `announcer.announce` DIRECTLY (rather than the String-collapsing door) so the typed
    /// [`AnnounceError`] survives for classification. It does NOT bypass the eligibility gate: the
    /// witness is minted by THIS door's authority (Public: allowlist-gated; Lan: AdmitAll) AND the
    /// announcer re-checks with the FABRIC'S OWN per-fabric authority fail-closed (TASK-231), the
    /// same allowlist `eligible_provisions` already approved - three independent gates, no bypass.
    async fn announce_one(&self, provision: &StoreProvision) -> AnnounceAttempt {
        let Some(announcer) = self.fabric.announcer() else {
            // No announcer -> nothing published -> clean pre-publication failure.
            return AnnounceAttempt::CleanFailure("fabric exposes no announcer".to_string());
        };
        let now = now_unix_secs();
        let sequence = self
            .fabric
            .next_announce_sequence(&provider_content_key(provision.nar_hash()));
        let record = sign_libp2p_store_record(
            self.identity_seed,
            provision.nar_hash(),
            provision.content(),
            self.ttl_secs,
            now,
            sequence,
        );
        let content_key = record.key;
        // Mint the witness via THIS door's authority (a witness-authorize refusal is a CLEAN
        // pre-publication failure - nothing reached the announcer).
        let witness = match &self.door {
            AnnounceAfterFetchDoor::Public(allowlist) => AllowlistWitnessAuthority {
                allowlist: allowlist.as_ref(),
            }
            .authorize(record.clone()),
            AnnounceAfterFetchDoor::Lan(_) => AdmitAllPublication.authorize(record.clone()),
        };
        let witness = match witness {
            Ok(w) => w,
            Err(reason) => {
                return AnnounceAttempt::CleanFailure(format!(
                    "witness refused (not published): {reason}"
                ));
            }
        };
        let attempt = classify_announce(
            announcer
                .announce(&witness, &self.announce_budget)
                .await
                .map(|_| ()),
            content_key,
        );
        match &attempt {
            AnnounceAttempt::Published(_) => println!(
                "LIBP2P-ANNOUNCE-AFTER-FETCH narhash={} content={} content_key={content_key} nar_size={}",
                provision.nar_hash(),
                provision.content().to_hex(),
                provision.declared_size(),
            ),
            AnnounceAttempt::Ambiguous(_) => eprintln!(
                "LIBP2P-ANNOUNCE-AFTER-FETCH narhash={} reason=announce-ambiguous \
                 (record may be live; tracked for withdraw, budget spent)",
                provision.nar_hash()
            ),
            AnnounceAttempt::CleanFailure(why) => eprintln!(
                "LIBP2P-ANNOUNCE-AFTER-FETCH narhash={} reason=announce-clean-fail: {why} \
                 (guaranteed not published; budget refunded)",
                provision.nar_hash()
            ),
        }
        attempt
    }
}

/// The outcome of announcing one provision, classified for FIX D accounting.
#[derive(Debug)]
enum AnnounceAttempt {
    /// The announcer returned `Ok`: the record was published. Track + keep budget spent.
    Published(ContentKey),
    /// The announce could have taken effect (an [`AnnounceError`] raised DURING/AROUND the publish
    /// future). The record MAY be live, so track it for `reconcile` + keep the budget SPENT.
    Ambiguous(ContentKey),
    /// A CLEAN pre-publication failure (no announcer / witness refused / an [`AnnounceError`]
    /// raised BEFORE the publish future - GUARANTEED not published). Refund the budget, track nothing.
    CleanFailure(String),
}

impl AnnounceAttempt {
    /// The FIX D ledger decision: `Some(content_key)` for Published OR Ambiguous (the caller
    /// `commit_success`es - SPENDS the budget + TRACKS the holding for `reconcile`), `None` for a
    /// CleanFailure (the caller `commit_failure`s - REFUNDS the budget + tracks nothing). Pure, so
    /// the discriminating FIX D bite chains `classify_announce` -> here -> the ledger without a swarm.
    fn into_grow_result(self) -> Option<ContentKey> {
        match self {
            AnnounceAttempt::Published(ck) | AnnounceAttempt::Ambiguous(ck) => Some(ck),
            AnnounceAttempt::CleanFailure(_) => None,
        }
    }
}

/// Classify one announce result into the FIX D accounting outcome (PURE, so the discriminating bite
/// needs no live swarm). `Ok` -> published (spend + track); an AMBIGUOUS error -> the record may be
/// live (spend + track for `reconcile`); a CLEAN error -> guaranteed not published (refund).
fn classify_announce(
    result: Result<(), AnnounceError>,
    content_key: ContentKey,
) -> AnnounceAttempt {
    match result {
        Ok(()) => AnnounceAttempt::Published(content_key),
        Err(e) if announce_error_is_ambiguous(&e) => AnnounceAttempt::Ambiguous(content_key),
        Err(e) => AnnounceAttempt::CleanFailure(e.to_string()),
    }
}

/// Classify an [`AnnounceError`] (FIX D): is it AMBIGUOUS (a DHT side-effect could have occurred) or
/// a CLEAN pre-publication failure (guaranteed not published)? Per `fabric-libp2p/src/announcer.rs`:
/// `Persist` is raised in save-before-publish BEFORE the `publish` future (announcer.rs:459), and
/// `Rejected` (record encode/decode/expiry/TTL) and `Ineligible` before it too - all GUARANTEED not
/// on the wire. Only `Unreachable` (raised inside `publish`'s `start_providing`/`put_record`) and
/// `DeadlineExceeded` (the `publish` future timed out, possibly after `start_providing`) can have a
/// side-effect. Exhaustive (no wildcard), so a NEW `AnnounceError` variant forces a conscious
/// clean-vs-ambiguous classification here rather than defaulting silently.
fn announce_error_is_ambiguous(err: &AnnounceError) -> bool {
    match err {
        AnnounceError::Unreachable(_) | AnnounceError::DeadlineExceeded => true,
        AnnounceError::Rejected(_) | AnnounceError::Persist(_) | AnnounceError::Ineligible(_) => {
            false
        }
    }
}

/// The announce side-effect for one fetched path, DECOUPLED from the ledger/spawn wiring so the
/// production-wired GC/retry bites can drive the real dispatch body ([`WorkerSpawner::run`]) with a
/// fake. The production impl is [`GrowWorker`].
#[async_trait]
trait Grower: Send + Sync {
    /// Bounded materialisation wait -> validate/verify -> announce for one reserved key. Returns
    /// `Some(content_key)` iff the record was PUBLISHED, OR the publish was AMBIGUOUSLY attempted
    /// (the announce call may have taken effect before erroring/timing out) - in both cases the
    /// caller TRACKS the holding (so `reconcile` can withdraw it) and keeps the budget SPENT.
    /// Returns `None` only on a CLEAN pre-publication failure (never materialised / ineligible /
    /// verify failed - no DHT side-effect), where the caller REFUNDS the budget (FIX 2/D).
    async fn grow(&self, key: &NarHashKey, store_path: &str) -> Option<ContentKey>;
}

#[async_trait]
impl Grower for GrowWorker {
    async fn grow(&self, key: &NarHashKey, store_path: &str) -> Option<ContentKey> {
        // Bounded wait for the local store to materialise the path (the daemon relayed the bytes;
        // nix imports them a moment later). A never-materialising path times out -> CLEAN failure.
        let mut materialised = false;
        for _ in 0..self.materialise.max_polls {
            if Path::new(store_path).exists() {
                materialised = true;
                break;
            }
            tokio::time::sleep(self.materialise.poll_interval).await;
        }
        if !materialised {
            eprintln!(
                "LIBP2P-ANNOUNCE-AFTER-FETCH skipped narhash={key} reason=not-materialised \
                 (store path {store_path:?} did not appear within the wait bound; not announced)"
            );
            return None; // clean pre-publication failure -> refund
        }

        // The validate+dump+verify is blocking; run it off the async worker. All failures here are
        // CLEAN (no DHT side-effect yet) -> refund.
        let worker = self.clone();
        let k = *key;
        let sp = store_path.to_string();
        let verified =
            tokio::task::spawn_blocking(move || worker.eligible_provisions(&k, &sp)).await;
        let provisions = match verified {
            Ok(Ok(p)) => p,
            Ok(Err(why)) => {
                eprintln!(
                    "LIBP2P-ANNOUNCE-AFTER-FETCH skipped narhash={key} reason=ineligible: {why}"
                );
                return None;
            }
            Err(join) => {
                eprintln!(
                    "LIBP2P-ANNOUNCE-AFTER-FETCH skipped narhash={key} reason=verify-panicked: {join}"
                );
                return None;
            }
        };

        // Announce each verified provision (one per fetched key). FIX D: `announce_one` classifies
        // the announce outcome by whether a DHT side-effect could have occurred, so a CLEAN
        // pre-publication failure (e.g. `AnnounceError::Persist`, raised BEFORE `start_providing`)
        // REFUNDS (returns `None`) while a Published/Ambiguous outcome SPENDS + tracks (returns
        // `Some`). A CleanFailure short-circuits: no `Some` was set, so the caller refunds.
        let mut content_key = None;
        for provision in &provisions {
            match self.announce_one(provision).await.into_grow_result() {
                Some(ck) => content_key = Some(ck),
                None => return None, // clean pre-publication failure -> refund
            }
        }
        content_key
    }
}

/// The seam that turns a reserved fetch into a spawned dispatch (TASK-77 FIX 1). It DECOUPLES the
/// announce side-effect from `on_fetched`'s budget gate, so the production budget bite - drive
/// `on_fetched` and count grows - needs no live swarm. The production impl also RECONCILES GC'd
/// holdings on every fetch (FIX 3b).
trait GrowSpawner: Send + Sync {
    /// On EVERY fetch: reconcile GC'd holdings (FIX 3b), and - iff `grow` is `Some` (the fetch was
    /// admitted by the budget gate) - run the grow for that reserved key, committing the outcome
    /// back to `ledger`. Running reconcile on every fetch (not only on a grow) means a
    /// budget-exhausted node still self-heals its stale holdings.
    fn dispatch(&self, ledger: Arc<Mutex<AnnounceLedger>>, grow: Option<(NarHashKey, String)>);
}

/// The production [`GrowSpawner`]. Its [`run`](WorkerSpawner::run) body - self-heal GC'd holdings,
/// then (if admitted) grow + commit - is async over its `Arc<dyn>` deps, so the production-wired
/// GC/retry bites drive `run` DIRECTLY with fakes (removing the `reconcile` call in `run` reddens
/// the GC bite). `dispatch` is the thin `tokio::spawn(run(..))` fire-and-forget wrapper.
struct WorkerSpawner {
    grower: Arc<dyn Grower>,
    withdrawer: Arc<dyn Withdrawer>,
}

impl WorkerSpawner {
    /// The production dispatch BODY (what `dispatch` spawns): reconcile GC'd holdings, then (if
    /// admitted) grow + commit its outcome. `commit_success` on a published/ambiguous grow (track +
    /// keep budget spent); `commit_failure` (REFUND) on a clean pre-publication failure.
    async fn run(
        ledger: Arc<Mutex<AnnounceLedger>>,
        grower: Arc<dyn Grower>,
        withdrawer: Arc<dyn Withdrawer>,
        grow: Option<(NarHashKey, String)>,
    ) {
        // FIX 3b: WITHDRAW any holding whose store path was GC'd since we announced it. Runs on
        // EVERY fetch, so an exhausted-budget node still reconciles. Timer-free; an IDLE node
        // relies on the clean serve-fail + record TTL (the documented eventually-consistent
        // residual - see the module doc).
        reconcile(&ledger, &*withdrawer).await;
        if let Some((key, store_path)) = grow {
            match grower.grow(&key, &store_path).await {
                Some(content_key) => commit_success(&ledger, &key, content_key, store_path),
                None => commit_failure(&ledger, &key),
            }
        }
    }
}

impl GrowSpawner for WorkerSpawner {
    fn dispatch(&self, ledger: Arc<Mutex<AnnounceLedger>>, grow: Option<(NarHashKey, String)>) {
        let grower = Arc::clone(&self.grower);
        let withdrawer = Arc::clone(&self.withdrawer);
        // Fire-and-forget: never blocks the serve path. Honest limit: a detached task is not tied to
        // a shutdown supervisor, so an in-flight announce is dropped on process exit - acceptable
        // for a best-effort growth announce (kad republish / TTL cover it).
        tokio::spawn(WorkerSpawner::run(ledger, grower, withdrawer, grow));
    }
}

/// The libp2p ANNOUNCE-AFTER-FETCH authority (TASK-77): the backend impl of the fabric-neutral
/// [`PostFetchAnnounce`] seam. It shares the provider's [`AvailabilityIndex`] (so a path it
/// registers becomes servable through the same `CatalogNarSupplier` reverse-map) and the
/// fabric's announcer (so every announce goes through the TASK-231 eligibility authority - no
/// bypass). On a successful fetch it: reserves a budget unit (AC#2), waits for the local store to
/// materialise the path, VALIDATES + verifies `sha256(--dump)==NarHash` (AC#3 / TASK-72:
/// index-coverage == provider-coverage), announces via the SAME verified door the shipped provider
/// uses, and reconciles/withdraws GC'd holdings (FIX 3b). An ineligible/failed fetch REFUNDS its
/// budget unit (FIX 2).
pub struct Libp2pAnnounceAfterFetch {
    ledger: Arc<Mutex<AnnounceLedger>>,
    spawner: Arc<dyn GrowSpawner>,
    /// The configured announce budget CAP (TASK-77 AC#2), retained so the live status surface can
    /// report `used = cap - remaining` (TASK-240 AC#4) from the SAME ledger the gate enforces.
    budget_cap: u64,
}

impl Libp2pAnnounceAfterFetch {
    /// Build the hook. `announce_budget_count` is the INTEGER number of distinct fetched paths this
    /// process may announce (AC#2); `index`/`fabric`/`identity_seed` MUST be the SAME ones the
    /// provider serve path + announcer use, so a registered path is servable and every announce (and
    /// withdrawal) is signed by this node and re-checked by its eligibility authority.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        fabric: Arc<Libp2pFabric>,
        identity_seed: [u8; 32],
        index: Arc<AvailabilityIndex>,
        door: AnnounceAfterFetchDoor,
        serve_budget: peer_fabric::ServeBudget,
        announce_budget: AnnounceBudget,
        ttl_secs: u64,
        store_dir: String,
        announce_budget_count: u64,
    ) -> Self {
        let worker = GrowWorker {
            fabric: Arc::clone(&fabric),
            identity_seed,
            index,
            door,
            serve_budget,
            announce_budget,
            ttl_secs,
            store_dir,
            materialise: MaterialiseWait::default(),
        };
        let grower: Arc<dyn Grower> = Arc::new(worker);
        let withdrawer: Arc<dyn Withdrawer> = Arc::new(FabricWithdrawer { fabric });
        Libp2pAnnounceAfterFetch {
            ledger: Arc::new(Mutex::new(AnnounceLedger {
                remaining: announce_budget_count,
                inflight: HashSet::new(),
                announced: HashSet::new(),
                held: HashMap::new(),
            })),
            spawner: Arc::new(WorkerSpawner { grower, withdrawer }),
            budget_cap: announce_budget_count,
        }
    }

    /// The remaining budget (test/observability).
    pub fn remaining_budget(&self) -> u64 {
        self.ledger
            .lock()
            .expect("announce ledger poisoned")
            .remaining
    }
}

impl PostFetchAnnounce for Libp2pAnnounceAfterFetch {
    fn on_fetched(&self, nar_hash: &NarHash, store_path: &str) {
        let key = match NarHashKey::from_str(nar_hash.as_str()) {
            Ok(k) => k,
            // A NarHash that is not a canonical p2p key can never be a discovery key; nothing to
            // announce (the UpstreamPath cold-start path never reaches here anyway).
            Err(_) => return,
        };
        // AC#2 (FIX 1): the budget gate the PRODUCTION path consults. Only a `Proceed` carries a
        // grow; removing this `begin` CALL - or the `remaining == 0` guard inside it - makes the
        // grow/announce count grow unbounded, which the production budget bite (drive on_fetched,
        // count grows) catches. `dispatch` ALSO reconciles GC'd holdings on every fetch (FIX 3b),
        // so it is called regardless of the budget outcome.
        let grow = match begin(&self.ledger, &key) {
            Begin::Proceed => Some((key, store_path.to_string())),
            Begin::AlreadyHandled => None,
            Begin::Exhausted => {
                eprintln!(
                    "LIBP2P-ANNOUNCE-AFTER-FETCH budget-exhausted narhash={key} \
                     (announce budget spent; not announcing - swarm growth is capped here)"
                );
                None
            }
        };
        self.spawner.dispatch(Arc::clone(&self.ledger), grow);
    }

    /// TASK-240 AC#4: the announce budget CONSUMED so far, read from the SAME ledger the gate
    /// enforces — `cap - remaining`, saturating (a reseeded-from-disk remaining can never exceed
    /// the cap in practice, but saturate rather than underflow).
    fn budget_used(&self) -> Option<u64> {
        Some(self.budget_cap.saturating_sub(self.remaining_budget()))
    }
}

// -------------------------------------------------------------------------
// The PUBLIC-ANNOUNCE door for raw SEEDS (`--libp2p-seed-nar`): the seed
// counterpart of the StoreProvision public door above. The shipped seed-supply
// provider (`daemon`/`daemon-libp2p`) uses it to announce over a PUBLIC (bootstrapped)
// substrate, gated on the same public-NAR allowlist. Seeds and store provisions are
// DISTINCT capabilities (a seed carries raw bytes; a provision carries an index-verified
// digest), so publicness is gated by a parallel typed door rather than by fabricating a
// `StoreProvision` from a byte string.
// -------------------------------------------------------------------------

/// A TASK-56-verified raw seed PAIRED with the allowlist [`PublicNarClaim`] that authorises
/// announcing it PUBLICLY. Private fields, minted ONLY by [`approve_seeds_for_public`], so a
/// public seed announce CANNOT be represented without an allowlist-minted claim - the claim is
/// LOAD-BEARING (held through the announce), the seed analogue of [`ApprovedPublicProvision`].
#[derive(Debug, Clone)]
pub struct ApprovedPublicSeed {
    nar_hash: NarHashKey,
    bytes: Vec<u8>,
    /// The unforgeable proof the allowlist approved this NAR for public announce. Held (never
    /// discarded) so this capability cannot exist without it.
    claim: PublicNarClaim,
}

impl ApprovedPublicSeed {
    /// The NAR identity this seed will announce.
    pub fn nar_hash(&self) -> &NarHashKey {
        &self.nar_hash
    }

    /// The allowlist claim authorising the PUBLIC announce of this seed's NAR.
    pub fn claim(&self) -> &PublicNarClaim {
        &self.claim
    }
}

/// CONSULT the public-NAR allowlist for a batch of raw seeds a node intends to announce
/// PUBLICLY, minting one [`PublicNarClaim`] per seed. FAIL-CLOSED and ALL-OR-NOTHING: if ANY
/// seed is not allowlisted (never proven public via a trusted narinfo signature), the WHOLE
/// batch is refused and NO claim is minted, so no partial announce can leak an un-approved NAR.
///
/// The size the allowlist gates on is `bytes.len()` - the raw UNCOMPRESSED NAR length, which is
/// exactly the signed NarSize a trusted narinfo proved. A wrong-length seed is refused as a
/// [`PublicationRejected::SizeMismatch`] here; a right-length-but-wrong-CONTENT seed is refused
/// by the TASK-56 `verify_provider_seeds` check inside the shared announce loop. The seed analogue
/// of [`approve_provisions_for_public`]; a PURE function of `(seeds, allowlist)`, so the
/// closed-by-construction gate is unit-testable without a DHT.
pub fn approve_seeds_for_public(
    seeds: &[(NarHashKey, Vec<u8>)],
    allowlist: &PublicNarAllowlist,
) -> Result<Vec<ApprovedPublicSeed>, PublicationRejected> {
    let mut approved = Vec::with_capacity(seeds.len());
    for (nar_hash, bytes) in seeds {
        // `approve` mints an UNFORGEABLE PublicNarClaim iff the NarHash is allowlisted AND its
        // approved size equals this seed's byte length. Absence -> fail-closed. The claim is
        // PAIRED with the seed and HELD through the announce.
        let claim = allowlist.approve(nar_hash, Some(bytes.len() as u64))?;
        approved.push(ApprovedPublicSeed {
            nar_hash: *nar_hash,
            bytes: bytes.clone(),
            claim,
        });
    }
    Ok(approved)
}

/// Announce a signed [`ProviderRecord`] for each raw seed, but ONLY after the public-NAR
/// allowlist has PROVEN every one publishable (TASK-102). The PUBLIC analogue of
/// [`announce_provider_seeds`] and the seed counterpart of [`announce_public_provisions`]: it
/// FIRST runs [`approve_seeds_for_public`] (fail-closed, all-or-nothing) and announces nothing
/// if any seed is un-allowlisted, then reuses the SAME verified-content announce loop
/// ([`announce_seed_records`]) a LAN announce uses. CONSUMING the minted [`ApprovedPublicSeed`]s
/// (claim held to the announce) is what makes a public seed announce with no allowlist-minted
/// claim UNREPRESENTABLE - there is no bare-seed public entry point.
pub async fn announce_public_seeds(
    fabric: &Libp2pFabric,
    identity_seed: [u8; 32],
    seeds: &[(NarHashKey, Vec<u8>)],
    allowlist: &PublicNarAllowlist,
    ttl_secs: u64,
    now: u64,
    budget: &AnnounceBudget,
) -> Result<Vec<ProviderRecord>, String> {
    // THE GATE (fail-closed, before any record is signed or announced): every seed must be
    // allowlisted, minting a claim-bearing capability, or the whole public announce is refused.
    let approved = approve_seeds_for_public(seeds, allowlist)
        .map_err(|rejected| format!("public announce refused by the allowlist gate: {rejected}"))?;
    // The claim is held to HERE, so a public seed announce is unrepresentable without an
    // allowlist-minted claim. Reconstruct the (already-verified) seeds for the shared loop.
    let approved_seeds: Vec<(NarHashKey, Vec<u8>)> = approved
        .iter()
        .map(|a| {
            debug_assert_eq!(a.claim().nar_hash(), &a.nar_hash);
            (a.nar_hash, a.bytes.clone())
        })
        .collect();
    // Public door (AC#2/#3): mint the witness from the SAME allowlist (allowlist-gated), distinct
    // from the LAN door's AdmitAll witness.
    announce_seed_records(
        fabric,
        identity_seed,
        &approved_seeds,
        &AllowlistWitnessAuthority { allowlist },
        ttl_secs,
        now,
        budget,
    )
    .await
}

/// Build the node's ONE public-NAR allowlist (TASK-103), the single authority the PUBLIC announce
/// door ([`announce_public_seeds`] / [`announce_public_provisions`]) consults AND the serving
/// daemon learns into (`App::public_allowlist`). This is the SINGLE SOURCE OF TRUTH for the
/// config->allowlist wiring: BOTH the composite `daemon` binary and the thin `daemon-libp2p`
/// binary call it from their parsed CLI, so their publication policy cannot drift (TASK-204).
///
/// Without `allowlist_path` this returns a DISABLED allowlist (no trusted keys, in-memory,
/// `contains` always false) - the pre-TASK-103 behaviour, so a non-public node is unchanged. WITH
/// a path it opens the MAC-integrity-protected file (key derived from the durable identity seed via
/// [`derive_allowlist_mac_key`]) and POPULATES it by PROVING each `prove_public_narinfo` public
/// through the trusted-key signature gate: the operator NAMING a seed/store path never makes it
/// public - only a trusted narinfo signature does. A narinfo that does not prove public,
/// mis-correlates to its requested store hash, or fails to persist is a LOUD startup error
/// (fail-closed), never a silently-empty allowlist.
///
/// `prove_public_narinfo` is a slice of `(requested-store-hash, path-to-narinfo)`: the store hash
/// the narinfo must correlate to (its signed `StorePath`'s `<hash>`) and the narinfo file to prove.
pub fn open_public_allowlist(
    allowlist_path: Option<&Path>,
    trusted_public_keys: &[String],
    identity_seed: &[u8; 32],
    prove_public_narinfo: &[(String, String)],
) -> Result<Arc<PublicNarAllowlist>, String> {
    let Some(path) = allowlist_path else {
        return Ok(Arc::new(PublicNarAllowlist::disabled()));
    };
    let trusted = TrustedNarKeys::from_lines(trusted_public_keys)
        .map_err(|e| format!("--libp2p-trusted-public-key: {e}"))?;
    // Guard here too (the CLI layer also rejects this) so the function is safe to call in
    // isolation: a disabled-by-emptiness allowlist proves nothing, a silent no-op public provider.
    if trusted.is_empty() {
        return Err(
            "internal: public allowlist path set with no trusted keys (the CLI should have rejected this)".into(),
        );
    }
    let mac_key = derive_allowlist_mac_key(identity_seed);
    let allowlist = PublicNarAllowlist::open_file(trusted, path.to_path_buf(), mac_key)
        .map_err(|e| format!("opening the public-NAR allowlist at {path:?}: {e}"))?;
    for (store_hash, narinfo_path) in prove_public_narinfo {
        let bytes = std::fs::read(narinfo_path)
            .map_err(|e| format!("reading --libp2p-prove-public-narinfo {narinfo_path:?}: {e}"))?;
        match allowlist.learn(&StoreHash::new(store_hash.clone()), &bytes) {
            LearnOutcome::Appended { nar_hash, nar_size } => {
                // Machine-readable proof line: which NAR identity was proven public + its size.
                println!(
                    "LIBP2P-PUBLIC-LEARN store_hash={store_hash} nar_hash={nar_hash} nar_size={nar_size}"
                );
            }
            LearnOutcome::AlreadyPresent { nar_hash } => {
                println!(
                    "LIBP2P-PUBLIC-LEARN store_hash={store_hash} nar_hash={nar_hash} already_present"
                );
            }
            LearnOutcome::Rejected(reject) => {
                return Err(format!(
                    "--libp2p-prove-public-narinfo {store_hash}: narinfo did not prove public: {reject}"
                ));
            }
            LearnOutcome::RequestMismatch { requested, signed } => {
                return Err(format!(
                    "--libp2p-prove-public-narinfo {store_hash}: the signed narinfo is for store hash {signed}, not the requested {requested} (mis-correlated response)"
                ));
            }
            LearnOutcome::PersistFailed(e) => {
                return Err(format!(
                    "--libp2p-prove-public-narinfo {store_hash}: persisting the allowlist failed: {e}"
                ));
            }
        }
    }
    Ok(Arc::new(allowlist))
}

/// Wrap a running `fabric` in the consumer [`Libp2pNarSource`] + its paired
/// [`Libp2pRawServe`], both holding the SAME fabric and discovery budget so the
/// rewrite-to-raw decision and the fetch can never drift (TASK-164). Shared by the
/// consumer and provider builders (single source of truth for the wrapping).
fn wrap_consumer_source(
    fabric: Arc<Libp2pFabric>,
    cfg: &Libp2pSourceConfig,
) -> (
    Arc<Libp2pFabric>,
    Arc<dyn NarSource>,
    Arc<dyn RawServeDecision>,
) {
    let raw_serve: Arc<dyn RawServeDecision> = Arc::new(Libp2pRawServe::new(
        fabric.clone() as Arc<dyn PeerFabric>,
        cfg.discovery_budget,
    ));
    let source: Arc<dyn NarSource> = Arc::new(Libp2pNarSource::new(
        fabric.clone() as Arc<dyn PeerFabric>,
        cfg.discovery_budget,
        cfg.envelope,
    ));
    (fabric, source, raw_serve)
}

/// Start a [`Libp2pFabric`] for `cfg` and JOIN the DHT: bind the listener, dial the
/// bootstrap peers (fatal only if EVERY dial fails), run the kad self-lookup, and seed
/// any optional `provider_addrs` into the routing table. With `supplier` `Some` the
/// fabric ALSO serves (`start_with_supplier`); `None` is a pure consumer. This is the
/// ONE connectivity sequence both [`build_libp2p_nar_source`] and
/// [`build_libp2p_provider_source`] run - extracted so the join discipline (fail-fast on
/// a total bootstrap outage, tolerant of a partial one) has a single source of truth.
async fn start_and_join_libp2p(
    cfg: &Libp2pSourceConfig,
    supplier: Option<Arc<dyn Libp2pNarSupplier>>,
    publication_eligibility: Arc<dyn PublicationEligibility>,
) -> Result<Arc<Libp2pFabric>, String> {
    let mut node_config = NodeConfig::new(cfg.identity_seed)
        .with_network_scope(cfg.network_scope.clone())
        .with_relay_server(cfg.relay_server_enabled)
        // TASK-120 fix A: kad server/client mode from the participation profile.
        .with_kad_server(cfg.kad_server)
        // TASK-231 (AC#2): the announcer's per-fabric publication-eligibility authority. A pure
        // CONSUMER passes RefusePublication (it never announces); a PROVIDER injects the
        // allowlist-backed (public) or AdmitAll (isolated-LAN) decision from the composition root.
        .with_publication_eligibility(publication_eligibility);
    // TASK-218: teach the node-locator the relays this node knows from bootstrap config,
    // so a discovery-only consumer can CONSTRUCT a NAT'd provider's /p2p-circuit
    // dial-address (<relayAddr>/p2p/<relayPeer>/p2p-circuit/p2p/<providerPeer>) from the
    // provider PeerId it discovered via kad plus a bootstrap-known relay. A bootstrap peer
    // IS the relay a NAT'd provider reserves on in the shipped topology; this is permitted
    // config, NOT out-of-band provider-address injection (the provider identity still comes
    // ONLY from kad get_providers). See NodeConfig::known_relays for the generality limit.
    for (peer, addr) in &cfg.bootstrap {
        node_config = node_config.with_known_relay(*peer, addr.clone());
    }
    let serving = supplier.is_some();
    // TASK-185, AC#1: a configured `state_dir` routes to the DURABLE constructors, so the
    // shipped daemon reloads its anti-rollback floor + per-key announce sequence on restart.
    // Without a `state_dir` the historical session-scoped (non-durable) path is used.
    let fabric = match (supplier, &cfg.state_dir) {
        (Some(supplier), Some(dir)) => {
            Libp2pFabric::start_with_supplier_durable(node_config, supplier, dir.clone())
        }
        (Some(supplier), None) => Libp2pFabric::start_with_supplier(node_config, supplier),
        (None, Some(dir)) => Libp2pFabric::start_durable(node_config, dir.clone()),
        (None, None) => Libp2pFabric::start(node_config),
    }
    .map_err(|e| format!("libp2p fabric start failed: {e}"))?;
    let fabric = Arc::new(fabric);

    // Composition-root REQUIRED-axis assertion (TASK-144 AC#4, the "Unsupported-axis
    // dilemma" resolution): fail fast HERE, at construction, if the selected profile needs
    // an axis this fabric does not offer - never a silent runtime degrade (a fetch that
    // always falls back, a provider that announces then cannot serve). A libp2p CONSUMER
    // needs content discovery, node-address resolution and the native libp2p fetch
    // transport; a PROVIDER additionally needs the
    // serve + announce axes. The single check lives in `peer_fabric::require_axes`, shared
    // with the iroh composition root so the two cannot drift on what "required" means.
    let mut required = vec![
        Axis::ProviderDirectory,
        Axis::NodeLocator,
        Axis::Transfer(TransportTag::Libp2p),
    ];
    if serving {
        required.push(Axis::Server);
        required.push(Axis::Announcer);
    }
    require_axes(fabric.as_ref(), &required).map_err(|missing| {
        format!("libp2p fabric does not satisfy the required axes for this profile: {missing}")
    })?;

    if let Some(listen) = &cfg.listen {
        fabric
            .handle()
            .listen(listen.clone())
            .await
            .map_err(|e| format!("libp2p listen on {listen} failed: {e}"))?;
    }

    // Join the DHT through the bootstrap peers: add_address seeds kad's routing table
    // (so the subsequent bootstrap self-lookup has a peer to query) and dial opens the
    // connection. A bootstrap SET is plural for RESILIENCE - the invariant is "at least
    // one dial succeeds", not "all succeed": a single mistyped/down entry among several
    // must not brick startup. So dial errors are collected and only fatal when EVERY
    // bootstrap dial failed (then it is a loud startup error, not a silent no-discovery).
    if !cfg.bootstrap.is_empty() {
        let mut dial_errors = Vec::new();
        for (peer, addr) in &cfg.bootstrap {
            fabric.handle().add_address(*peer, addr.clone()).await;
            if let Err(e) = fabric.handle().dial(addr.clone()).await {
                dial_errors.push(format!("{peer} @ {addr}: {e}"));
            }
        }
        if dial_errors.len() == cfg.bootstrap.len() {
            return Err(format!(
                "libp2p: every bootstrap dial failed ({} peer(s)); cannot join the DHT: {}",
                cfg.bootstrap.len(),
                dial_errors.join("; ")
            ));
        }
        if !dial_errors.is_empty() {
            eprintln!(
                "daemon: libp2p {}/{} bootstrap dial(s) failed (continuing on the rest): {}",
                dial_errors.len(),
                cfg.bootstrap.len(),
                dial_errors.join("; ")
            );
        }
        // The kad self-lookup that populates the routing table. Not fatal on error:
        // add_address already seeded routing; a transient self-lookup error must not
        // brick startup. NOTE: this returns before discovery has CONVERGED - the daemon
        // starts serving immediately and early requests simply miss libp2p and fall back
        // to HTTP until the routing table fills (a benign cold-start window). A gate-able
        // readiness signal on the source seam is a follow-up (TASK-163).
        if let Err(e) = fabric.handle().bootstrap().await {
            eprintln!("daemon: libp2p kad bootstrap self-lookup returned: {e}");
        }
    }

    // OPTIONAL kad routing-table seed (TASK-169): normally EMPTY. The production fetch
    // path resolves a discovered provider's dial address through kad peer-routing INSIDE
    // the transfer and dials off that resolution, so no address needs injecting here.
    // HONEST LIMIT (see the `provider_addrs` field doc): these `add_address` seeds only
    // populate the local kad routing table (a bootstrap/entry hint); since the transport
    // dials only off a successful resolution, they do NOT independently enable a dial to a
    // provider the DHT cannot resolve. A transfer-honoured static per-peer dial override
    // (`ExplicitPeersOnly`) is the locator's job, TASK-168.
    for (peer, addr) in &cfg.provider_addrs {
        fabric.handle().add_address(*peer, addr.clone()).await;
    }

    Ok(fabric)
}

/// The LIVE swarm-facts provider for the operator status surface (TASK-240/242). It answers the
/// two connectivity facts the stack-neutral frontend cannot compute itself (they live in the
/// backend's swarm):
///
/// * **bootstrap health** — how many of the configured bootstrap/entry peers the running swarm
///   holds an established connection to right now, via [`SwarmHandle::is_connected`]. A genuinely
///   live signal: it degrades the instant a bootstrap dies (the dependency-outage drill keys on it).
/// * **peer path** — direct vs relayed, via [`SwarmHandle::connection_path`], which reads the same
///   connection ledger `is_connected` does. `Direct` if ANY bootstrap connection is direct, else
///   `Relay` if a bootstrap is reachable only over a `/p2p-circuit`, else `Unknown` (a running swarm
///   with no classified live bootstrap connection — NEVER `None`, which is reserved for an
///   upstream-only node with no swarm at all; see [`daemon_core::PeerPath`]).
///
/// HONEST SCOPE (TASK-242): `peer_path` classifies the path to the CONFIGURED BOOTSTRAP peers (the
/// same peer set `bootstrap_healthy` counts), not a NAT-reachability verdict. A NAT'd node's
/// OUTBOUND dial to a bootstrap is typically direct even when the node itself is only reachable
/// INBOUND via a relay; the "am I publicly reachable" verdict is autonat's, surfaced separately.
/// What this reports is truthful and load-bearing: it is `relay` exactly when the only live path to
/// a bootstrap is a circuit, and `direct` when a direct connection exists.
pub struct SwarmStatusFacts {
    handle: SwarmHandle,
    bootstrap: Vec<PeerId>,
}

impl SwarmStatusFacts {
    /// Wire the live-facts provider over a running swarm's [`SwarmHandle`] and the configured
    /// bootstrap peer set (the same set `--libp2p-bootstrap` parsed).
    pub fn new(handle: SwarmHandle, bootstrap: Vec<PeerId>) -> Self {
        SwarmStatusFacts { handle, bootstrap }
    }
}

#[async_trait]
impl daemon_core::StatusFacts for SwarmStatusFacts {
    async fn snapshot(&self) -> daemon_core::StatusFactSnapshot {
        let mut healthy = 0u32;
        let mut any_direct = false;
        let mut any_relay = false;
        for peer in &self.bootstrap {
            // Bootstrap health is read from the ACTUAL connection state (is_connected), so a dead
            // bootstrap drops the count — the drill's load-bearing signal.
            if self.handle.is_connected(*peer).await {
                healthy += 1;
            }
            // Path classification reads the SAME connection ledger, so it can never disagree with
            // is_connected about whether the peer is connected.
            match self.handle.connection_path(*peer).await {
                ConnPath::Direct => any_direct = true,
                ConnPath::Relay => any_relay = true,
                ConnPath::None => {}
            }
        }
        // Direct dominates (a hole-punched peer reports direct even while a stale circuit lingers);
        // a swarm with no classified live bootstrap connection reports Unknown, never None.
        let path = if any_direct {
            daemon_core::PeerPath::Direct
        } else if any_relay {
            daemon_core::PeerPath::Relay
        } else {
            daemon_core::PeerPath::Unknown
        };
        daemon_core::StatusFactSnapshot {
            bootstrap_total: self.bootstrap.len() as u32,
            bootstrap_healthy: healthy,
            path,
        }
    }
}

#[cfg(test)]
mod identity_seed_tests {
    //! TASK-185 GB1: `resolve_durable_identity_seed` is the anchor that makes durability real -
    //! a state-dir-only restart must come back as the SAME node. These are fast, network-free
    //! unit tests of that contract (the end-to-end restart bite is
    //! `tests/restart_durable_sequence_through_run.rs`).
    use super::{IDENTITY_SEED_FILENAME, resolve_durable_identity_seed};

    /// A unique, empty temp dir for one test (process + thread + counter keyed).
    fn fresh_dir(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "nix-p2p-identtest-{tag}-{}-{:?}-{}",
            std::process::id(),
            std::thread::current().id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn state_dir_only_is_stable_across_boots() {
        // The GB1 property: two boots with only a state dir resolve the SAME identity, and it
        // is persisted. If persistence were a no-op these would differ.
        let dir = fresh_dir("stable");
        let first = resolve_durable_identity_seed(Some(&dir), None).expect("first boot");
        assert!(
            dir.join(IDENTITY_SEED_FILENAME).exists(),
            "the identity seed must be persisted under the state dir"
        );
        let second = resolve_durable_identity_seed(Some(&dir), None).expect("second boot");
        assert_eq!(
            first, second,
            "a state-dir-only restart is the SAME identity"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn no_state_dir_honours_explicit_and_is_session_scoped_otherwise() {
        // Without a state dir: explicit wins verbatim; None is random (session-scoped) - two
        // calls need not agree (and almost never will).
        let seed = [9u8; 32];
        assert_eq!(
            resolve_durable_identity_seed(None, Some(seed)).unwrap(),
            seed
        );
        let a = resolve_durable_identity_seed(None, None).unwrap();
        let b = resolve_durable_identity_seed(None, None).unwrap();
        assert_ne!(
            a, b,
            "session-scoped random seeds are (overwhelmingly) distinct"
        );
    }

    #[test]
    fn explicit_seed_is_persisted_then_reused_by_a_state_dir_only_restart() {
        let dir = fresh_dir("explicit-persist");
        let seed = [7u8; 32];
        assert_eq!(
            resolve_durable_identity_seed(Some(&dir), Some(seed)).unwrap(),
            seed
        );
        // A later state-dir-only boot reuses the persisted explicit seed.
        assert_eq!(
            resolve_durable_identity_seed(Some(&dir), None).unwrap(),
            seed,
            "the explicit seed was persisted and is reused on a state-dir-only restart"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn explicit_seed_conflicting_with_persisted_is_fail_closed() {
        // Fail-safe: an explicit seed that disagrees with the state dir's persisted identity is
        // a hard error (else it would orphan the dir's anti-rollback floor).
        let dir = fresh_dir("conflict");
        resolve_durable_identity_seed(Some(&dir), None).expect("persist a random identity");
        let err = resolve_durable_identity_seed(Some(&dir), Some([0xAB; 32]))
            .expect_err("a conflicting explicit seed must be rejected");
        assert!(
            err.contains("disagrees"),
            "error must name the conflict: {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_malformed_persisted_seed_is_fail_closed_not_silently_regenerated() {
        // A corrupt identity file must NOT be silently replaced with a fresh random identity
        // (that would orphan the floor) - it is a hard error the operator must resolve.
        let dir = fresh_dir("malformed");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(IDENTITY_SEED_FILENAME), b"not-hex\n").unwrap();
        assert!(
            resolve_durable_identity_seed(Some(&dir), None).is_err(),
            "a malformed persisted identity must fail closed, not regenerate a new one"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_floor_without_its_identity_is_fail_closed_corruption() {
        // TASK-185 re-gate, case 1 (GB1 re-opened via PARTIAL loss): a floor/sequence file
        // present while the identity file is GONE must FAIL-CLOSED, not silently regenerate a
        // fresh identity (which would rekey the node and orphan the records the floor is bound
        // to). BITE: remove the consistency check in resolve and this returns a fresh seed -> the
        // expect_err goes red. Covered for BOTH floor sidecars.
        use fabric_libp2p::{ANNOUNCE_SEQ_FILENAME, PROVIDER_FLOOR_FILENAME};
        for orphan in [ANNOUNCE_SEQ_FILENAME, PROVIDER_FLOOR_FILENAME] {
            let dir = fresh_dir("orphan-floor");
            std::fs::create_dir_all(&dir).unwrap();
            // A floor file exists but NO identity file (partial corruption).
            std::fs::write(dir.join(orphan), b"# surviving floor state\n").unwrap();
            let err = resolve_durable_identity_seed(Some(&dir), None).expect_err(
                "a durable floor without its identity must fail closed, not silently rekey",
            );
            assert!(
                err.contains("INCONSISTENT"),
                "error must name the inconsistency (orphan {orphan}): {err}"
            );
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn identity_present_without_a_floor_is_a_normal_boot_not_corruption() {
        // The AMBIGUOUS direction is deliberately NOT fail-closed (TASK-189): a pure consumer or
        // a pre-first-announce provider legitimately has an identity but no floor file yet, so a
        // restart there is a normal SAME-identity boot, not corruption.
        let dir = fresh_dir("ident-no-floor");
        let first = resolve_durable_identity_seed(Some(&dir), None).expect("first boot");
        let second =
            resolve_durable_identity_seed(Some(&dir), None).expect("restart with no floor yet");
        assert_eq!(
            first, second,
            "identity-present + floor-absent is a normal boot, not corruption"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod public_announce_gate_tests {
    //! TASK-102: the PUBLIC announce door is closed-by-construction on the allowlist.
    //! These are network-free unit tests of [`approve_provisions_for_public`] - the single
    //! consult point every public announce goes through. StoreProvision has private fields,
    //! but this test lives in the SAME crate, so it can mint one directly (the shipped path
    //! mints it only via `verify_store_provisions`; here we only need the gate's decision).
    use super::{StoreProvision, approve_provisions_for_public, approve_seeds_for_public};
    use daemon_core::content_id::Blake3Digest;
    use daemon_core::{
        NarHashKey, PublicNarAllowlist, PublicationRejected, StoreHash, TrustedNarKeys,
    };

    const FIXTURE_PUBKEY: &str = "nix-p2p-test-1:empdFBu9wVZG12rPKToHMOTsU1qzWzeCcLdq/KQH0JQ=";
    // The real `app` narinfo (NarHash sha256:0pgsb9..., NarSize 408), trusted-signed.
    const APP_NARINFO: &[u8] = b"StorePath: /nix/store/l30jg5xg904s62jvw5znmr682xpr993c-nix-p2p-fixture-app\n\
URL: nar/15m2z8ar1r1jm5x7fqblq4s7438ghdmam396l5kwvc25jq8rzxb7.nar.xz\n\
Compression: xz\n\
FileHash: sha256:15m2z8ar1r1jm5x7fqblq4s7438ghdmam396l5kwvc25jq8rzxb7\n\
FileSize: 260\n\
NarHash: sha256:0pgsb9mjmfj57w1ddmqn9z9667nwbqbnn699j1s1s99jhy6cppsm\n\
NarSize: 408\n\
References: 0a0lslqb6gbqnj6xqjlaljjqg6kgb3wz-nix-p2p-fixture-lib\n\
Deriver: 3135ldqj1kl5wxkrrdnf4dfxiqakjz0z-nix-p2p-fixture-app.drv\n\
Sig: nix-p2p-test-1:Xqf1bjNJ1ReFahm86zY+hv80+7QeJer5V/HjlEAvP39yJEK8w8jHG9WH5lM7mN9WCIbdH/DDx81dmsjVObMqAQ==\n";

    fn allowlist_with_app() -> PublicNarAllowlist {
        let trusted = TrustedNarKeys::from_lines([FIXTURE_PUBKEY]).unwrap();
        let list = PublicNarAllowlist::in_memory(trusted);
        list.learn(
            &StoreHash::new("l30jg5xg904s62jvw5znmr682xpr993c"),
            APP_NARINFO,
        );
        list
    }

    fn provision(nar_hash: &str, declared_size: u64) -> StoreProvision {
        StoreProvision {
            nar_hash: nar_hash.parse::<NarHashKey>().unwrap(),
            content: Blake3Digest::from_bytes([0u8; 32]),
            declared_size,
        }
    }

    #[test]
    fn allowlisted_provision_is_approved() {
        let list = allowlist_with_app();
        let provisions = vec![provision(
            "sha256:0pgsb9mjmfj57w1ddmqn9z9667nwbqbnn699j1s1s99jhy6cppsm",
            408,
        )];
        let approved = approve_provisions_for_public(&provisions, &list).expect("approved");
        assert_eq!(approved.len(), 1);
        assert_eq!(approved[0].claim().nar_size(), 408);
        // The claim is load-bearing: it authorises exactly the provision's NarHash.
        assert_eq!(
            approved[0].claim().nar_hash(),
            approved[0].provision().nar_hash()
        );
    }

    #[test]
    fn an_operator_seeded_local_fixture_is_refused_from_public_announce() {
        // THE BITE (mped-architect must-have #2): a purely-local NAR the operator named is
        // NOT allowlisted, so the public door refuses the whole batch and mints NO claim.
        // Neuter the `approve` consult inside `approve_provisions_for_public` and this goes
        // green (claims minted) -> the guard bites. This is the closed-by-construction gate:
        // without a PublicNarClaim, `announce_public_provisions` cannot announce it.
        let list = allowlist_with_app();
        let local_only = provision(
            "sha256:1nn8563y6j55y003xjk1bvb1854abmigsas2jgzy4shy0f4vnzpa",
            524808,
        );
        match approve_provisions_for_public(&[local_only], &list) {
            Err(PublicationRejected::NotAllowlisted(_)) => {}
            other => panic!("expected NotAllowlisted, got {other:?}"),
        }
    }

    #[test]
    fn all_or_nothing_one_unapproved_refuses_the_whole_batch() {
        // Fail-closed batch semantics: an approved provision alongside an un-allowlisted one
        // refuses BOTH, so no partial public announce can leak the un-approved NAR.
        let list = allowlist_with_app();
        let provisions = vec![
            provision(
                "sha256:0pgsb9mjmfj57w1ddmqn9z9667nwbqbnn699j1s1s99jhy6cppsm",
                408,
            ),
            provision(
                "sha256:1nn8563y6j55y003xjk1bvb1854abmigsas2jgzy4shy0f4vnzpa",
                524808,
            ),
        ];
        assert!(approve_provisions_for_public(&provisions, &list).is_err());
    }

    #[test]
    fn a_size_that_disagrees_with_the_proof_is_refused() {
        // A NarHash allowlisted at 408 announced at a different size is refused: a NAR may be
        // announced only at exactly the size a trusted signature covered (defensive guard).
        let list = allowlist_with_app();
        let wrong_size = provision(
            "sha256:0pgsb9mjmfj57w1ddmqn9z9667nwbqbnn699j1s1s99jhy6cppsm",
            999,
        );
        match approve_provisions_for_public(&[wrong_size], &list) {
            Err(PublicationRejected::SizeMismatch { .. }) => {}
            other => panic!("expected SizeMismatch, got {other:?}"),
        }
    }

    // ---- the SEED public door (announce_public_seeds), the path the s7-libp2p e2e drives ----

    const APP_NAR_HASH: &str = "sha256:0pgsb9mjmfj57w1ddmqn9z9667nwbqbnn699j1s1s99jhy6cppsm";

    fn seed(nar_hash: &str, len: usize) -> (NarHashKey, Vec<u8>) {
        // The GATE (approve_seeds_for_public) checks only the allowlist membership + byte length;
        // the raw-content->NarHash TASK-56 check lives in the shared announce loop, so these
        // fixture bytes need only the right length to exercise the gate.
        (nar_hash.parse::<NarHashKey>().unwrap(), vec![0u8; len])
    }

    #[test]
    fn allowlisted_seed_is_approved() {
        let list = allowlist_with_app();
        let approved =
            approve_seeds_for_public(&[seed(APP_NAR_HASH, 408)], &list).expect("approved");
        assert_eq!(approved.len(), 1);
        assert_eq!(approved[0].claim().nar_size(), 408);
        assert_eq!(approved[0].claim().nar_hash(), approved[0].nar_hash());
    }

    #[test]
    fn an_operator_named_local_seed_is_refused_from_public_announce() {
        // THE SEED BITE: a purely-local NAR the operator named via --libp2p-seed-nar is NOT
        // allowlisted (never proven public via a trusted narinfo signature), so the public seed
        // door refuses the whole batch and mints NO claim. Neuter the `approve` consult and this
        // goes green -> the guard bites. Without a claim, announce_public_seeds cannot announce it.
        let list = allowlist_with_app();
        let local = seed(
            "sha256:1nn8563y6j55y003xjk1bvb1854abmigsas2jgzy4shy0f4vnzpa",
            1234,
        );
        match approve_seeds_for_public(&[local], &list) {
            Err(PublicationRejected::NotAllowlisted(_)) => {}
            other => panic!("expected NotAllowlisted, got {other:?}"),
        }
    }

    #[test]
    fn seed_all_or_nothing_one_unapproved_refuses_the_whole_batch() {
        let list = allowlist_with_app();
        let seeds = vec![
            seed(APP_NAR_HASH, 408),
            seed(
                "sha256:1nn8563y6j55y003xjk1bvb1854abmigsas2jgzy4shy0f4vnzpa",
                1234,
            ),
        ];
        assert!(approve_seeds_for_public(&seeds, &list).is_err());
    }

    #[test]
    fn a_seed_length_that_disagrees_with_the_proof_is_refused() {
        // A NarHash allowlisted at 408 B announced from a seed of a DIFFERENT length is refused:
        // the raw NAR length must equal the NarSize the trusted signature covered.
        let list = allowlist_with_app();
        match approve_seeds_for_public(&[seed(APP_NAR_HASH, 999)], &list) {
            Err(PublicationRejected::SizeMismatch { .. }) => {}
            other => panic!("expected SizeMismatch, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod lan_isolation_tests {
    //! TASK-102 fix cycle #2: the LAN-isolation witness must require POSITIVE loopback/link-local
    //! isolation, not merely absence-of-bootstrap. Each public-reach signal must make
    //! [`lan_isolation_or_refuse`] REFUSE; only a provably-isolated node mints a [`LanShare`].
    use super::{LanReachability, lan_isolation_or_refuse, multiaddr_is_lan_only};
    use fabric_libp2p::{Multiaddr, PeerId};

    fn peer() -> PeerId {
        "12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN"
            .parse()
            .unwrap()
    }

    fn addr(s: &str) -> Multiaddr {
        s.parse().unwrap()
    }

    fn none() -> LanReachability<'static> {
        LanReachability {
            bootstrap: &[],
            provider_addrs: &[],
            listen: None,
        }
    }

    #[test]
    fn isolated_node_with_no_reach_signals_is_permitted() {
        // No bootstrap, no provider-addr, no listen: a genuinely-isolated node -> LanShare.
        assert!(lan_isolation_or_refuse(none()).is_ok());
    }

    #[test]
    fn a_loopback_listen_only_node_is_permitted() {
        let listen = addr("/ip4/127.0.0.1/tcp/0");
        let reach = LanReachability {
            listen: Some(&listen),
            ..none()
        };
        assert!(
            lan_isolation_or_refuse(reach).is_ok(),
            "a loopback-listen isolated node is a valid LAN announce"
        );
    }

    #[test]
    fn a_link_local_listen_only_node_is_permitted() {
        for a in ["/ip4/169.254.10.10/tcp/0", "/ip6/fe80::1/tcp/0"] {
            let listen = addr(a);
            let reach = LanReachability {
                listen: Some(&listen),
                ..none()
            };
            assert!(
                lan_isolation_or_refuse(reach).is_ok(),
                "a link-local listen ({a}) is LAN-only"
            );
        }
    }

    #[test]
    fn a_bootstrapped_announce_is_refused() {
        // Presence of ANY bootstrap peer refuses, regardless of its address (even loopback).
        let bootstrap = [(peer(), addr("/ip4/127.0.0.1/tcp/4001"))];
        let reach = LanReachability {
            bootstrap: &bootstrap,
            ..none()
        };
        let err = lan_isolation_or_refuse(reach).expect_err("bootstrap must refuse");
        assert!(err.contains("TASK-103"), "must name TASK-103: {err}");
        assert!(
            err.contains("--libp2p-bootstrap"),
            "must name the signal: {err}"
        );
    }

    #[test]
    fn a_provider_addr_with_empty_bootstrap_is_refused() {
        // THE residual bite (fix cycle #2): a --libp2p-provider-addr with EMPTY bootstrap still
        // seeds the kad routing table and reaches the public DHT, so it must REFUSE. Before the fix
        // (bootstrap-only guard) this MINTED a LanShare and announced ungated. Loopback addr proves
        // the refusal is on PRESENCE, not the address literal.
        let provider_addrs = [(peer(), addr("/ip4/127.0.0.1/tcp/4001"))];
        let reach = LanReachability {
            provider_addrs: &provider_addrs,
            ..none()
        };
        let err = lan_isolation_or_refuse(reach)
            .expect_err("a provider-addr with empty bootstrap must be refused");
        assert!(err.contains("TASK-103"), "must name TASK-103: {err}");
        assert!(
            err.contains("--libp2p-provider-addr"),
            "must name the provider-addr signal: {err}"
        );
    }

    #[test]
    fn a_public_listen_refuses_and_a_private_lan_listen_also_refuses() {
        // A public IP and a wildcard bind must refuse. A PRIVATE-LAN address (192.168/10/172.16) is
        // deliberately ALSO refused: it is routable/NAT-able, so it is not PROVABLY isolated - only
        // loopback/link-local is. This is the conservative fail-closed posture (positive proof).
        for a in [
            "/ip4/203.0.113.7/tcp/4001",
            "/ip4/0.0.0.0/tcp/4001",
            "/ip6/::/tcp/4001",
            "/dns4/example.com/tcp/4001",
            "/ip4/192.168.1.5/tcp/4001",
            "/ip4/10.0.0.5/tcp/4001",
        ] {
            let listen = addr(a);
            let reach = LanReachability {
                listen: Some(&listen),
                ..none()
            };
            assert!(
                lan_isolation_or_refuse(reach).is_err(),
                "listen {a} is not provably loopback/link-local; must refuse"
            );
        }
    }

    #[test]
    fn multiaddr_is_lan_only_classifies_correctly() {
        assert!(multiaddr_is_lan_only(&addr("/ip4/127.0.0.1/tcp/0")));
        assert!(multiaddr_is_lan_only(&addr("/ip6/::1/tcp/0")));
        assert!(multiaddr_is_lan_only(&addr("/ip4/169.254.1.1/tcp/0")));
        assert!(multiaddr_is_lan_only(&addr("/ip6/fe80::abcd/tcp/0")));
        assert!(!multiaddr_is_lan_only(&addr("/ip4/0.0.0.0/tcp/0")));
        assert!(!multiaddr_is_lan_only(&addr("/ip4/8.8.8.8/tcp/0")));
        assert!(!multiaddr_is_lan_only(&addr("/ip4/192.168.0.1/tcp/0")));
        assert!(!multiaddr_is_lan_only(&addr("/dns4/example.com/tcp/0")));
        // A multiaddr with no IP literal at all is not provably local.
        assert!(!multiaddr_is_lan_only(&addr(
            "/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN"
        )));
    }
}

#[cfg(test)]
mod announce_after_fetch_tests {
    //! Mutation-proven bites for the TASK-77 announce-after-fetch invariants. Each targets a pure
    //! core / seam (no live swarm); end-to-end swarm growth is proven in the e2e `s9-libp2p-grow`.
    //!
    //! - AC#2 FIX 1: budget enforced through the PRODUCTION `on_fetched` path (fake `GrowSpawner`
    //!   counts grows; neutering the `begin` call in `on_fetched` reddens it).
    //! - AC#2 FIX 2 / FIX D: the PRODUCTION dispatch body `WorkerSpawner::run` REFUNDS a clean
    //!   pre-publication failure and SPENDS + TRACKS an announced/ambiguous grow.
    //! - AC#3 / TASK-72 FIX 3b: `WorkerSpawner::run` reconciles + WITHDRAWS a GC'd holding (the
    //!   production wiring; removing the `reconcile` call in `run` reddens it).
    //! - AC#3 FIX B: a FAILED withdraw is retained + retried, dropped only on success.
    //! - AC#3 FIX C: `validate_store_path` rejects a store-shaped path outside the real store dir.

    use super::{
        AnnounceAfterFetchDoor, AnnounceLedger, Begin, GrowSpawner, Grower,
        Libp2pAnnounceAfterFetch, Withdrawer, WorkerSpawner, begin, classify_announce,
        eligible_provisions, validate_store_path,
    };
    use async_trait::async_trait;
    use std::collections::{HashMap, HashSet};
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    use daemon_core::{
        AvailabilityIndex, NarDumper, NarHash, NarHashKey, NodeId, NullAnnounce, NullStore,
        PublicNarAllowlist, RegularFileNarDumper,
    };
    use peer_fabric::{AnnounceError, ContentKey, IneligibleReason, ServeBudget};

    const HASH32: &str = "0123456789abcdfghijklmnpqrsvwxyz";
    const STORE_DIR: &str = "/nix/store";

    fn unique_temp(stem: &str) -> PathBuf {
        let suffix = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        std::env::temp_dir().join(format!("nix-p2p-task77-{stem}-{suffix}"))
    }
    fn nar_hash(seed: u8) -> NarHash {
        NarHash::new(NarHashKey::from_sha256_bytes([seed; 32]).to_string())
    }
    fn key(seed: u8) -> NarHashKey {
        NarHashKey::from_sha256_bytes([seed; 32])
    }
    fn content_key(seed: u8) -> ContentKey {
        ContentKey::from_bytes([seed; 32])
    }
    fn store_path_str(seed: u8) -> String {
        format!("/nix/store/{HASH32}-pkg-{seed}")
    }
    fn empty_ledger(budget: u64) -> Arc<Mutex<AnnounceLedger>> {
        Arc::new(Mutex::new(AnnounceLedger {
            remaining: budget,
            inflight: HashSet::new(),
            announced: HashSet::new(),
            held: HashMap::new(),
        }))
    }

    // ---- FIX 1: budget enforced through on_fetched (fake GrowSpawner counts dispatched grows) ----

    struct FakeSpawner {
        grows: Arc<Mutex<Vec<NarHashKey>>>,
    }
    impl GrowSpawner for FakeSpawner {
        fn dispatch(
            &self,
            _ledger: Arc<Mutex<AnnounceLedger>>,
            grow: Option<(NarHashKey, String)>,
        ) {
            if let Some((k, _)) = grow {
                self.grows.lock().unwrap().push(k);
            }
        }
    }
    fn hook_with_fake(budget: u64, grows: Arc<Mutex<Vec<NarHashKey>>>) -> Libp2pAnnounceAfterFetch {
        Libp2pAnnounceAfterFetch {
            ledger: empty_ledger(budget),
            spawner: Arc::new(FakeSpawner { grows }),
            budget_cap: budget,
        }
    }

    #[test]
    fn budget_is_enforced_through_the_production_on_fetched_path() {
        use daemon_core::PostFetchAnnounce;
        let grows = Arc::new(Mutex::new(Vec::new()));
        let hook = hook_with_fake(2, Arc::clone(&grows));
        for seed in [1u8, 2, 3] {
            hook.on_fetched(&nar_hash(seed), &store_path_str(seed));
        }
        assert_eq!(
            grows.lock().unwrap().len(),
            2,
            "on_fetched must STOP dispatching grows past the integer budget"
        );
        assert_eq!(hook.remaining_budget(), 0);
        // A re-fetch of an already-handled path is a no-op (dedup), not a new grow.
        hook.on_fetched(&nar_hash(1), &store_path_str(1));
        assert_eq!(
            grows.lock().unwrap().len(),
            2,
            "a re-fetch does not re-dispatch"
        );
    }

    /// TASK-240 AC#4: the LIVE announce-budget figure the status surface reports is read from the
    /// SAME ledger the gate enforces — `cap - remaining` — so it cannot drift from what is spent.
    /// MUTATION: reporting a constant (e.g. `Some(0)`) reddens the `== 2` after the budget is spent;
    /// reading a second, non-enforcing counter would not track the exhaustion here.
    #[test]
    fn budget_used_tracks_the_enforced_ledger() {
        use daemon_core::PostFetchAnnounce;
        let grows = Arc::new(Mutex::new(Vec::new()));
        let hook = hook_with_fake(2, Arc::clone(&grows));
        assert_eq!(hook.budget_used(), Some(0), "fresh: nothing spent yet");
        for seed in [1u8, 2, 3] {
            hook.on_fetched(&nar_hash(seed), &store_path_str(seed));
        }
        // Two distinct paths announced under a cap of 2 -> the surface reports 2/2 (exhausted).
        assert_eq!(hook.remaining_budget(), 0);
        assert_eq!(
            hook.budget_used(),
            Some(2),
            "budget_used = cap - remaining, read from the enforced ledger"
        );
    }

    // ---- the production dispatch body (WorkerSpawner::run) with fakes ----

    struct FakeGrower {
        outcome: Arc<Mutex<Option<ContentKey>>>,
    }
    #[async_trait]
    impl Grower for FakeGrower {
        async fn grow(&self, _key: &NarHashKey, _store_path: &str) -> Option<ContentKey> {
            *self.outcome.lock().unwrap()
        }
    }
    /// A grower that is never called (used when driving `run` with `grow == None`).
    struct NoopGrower;
    #[async_trait]
    impl Grower for NoopGrower {
        async fn grow(&self, _key: &NarHashKey, _store_path: &str) -> Option<ContentKey> {
            None
        }
    }
    struct FakeWithdrawer {
        result: Arc<Mutex<bool>>,
        withdrawn: Arc<Mutex<Vec<ContentKey>>>,
    }
    #[async_trait]
    impl Withdrawer for FakeWithdrawer {
        async fn withdraw(&self, k: &ContentKey) -> bool {
            self.withdrawn.lock().unwrap().push(*k);
            *self.result.lock().unwrap()
        }
    }
    fn noop_withdrawer() -> Arc<dyn Withdrawer> {
        Arc::new(FakeWithdrawer {
            result: Arc::new(Mutex::new(true)),
            withdrawn: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// AC#2 FIX 2 + FIX D BITE: a CLEAN pre-publication failure (grow -> None) REFUNDS the budget
    /// and tracks nothing; an announced/AMBIGUOUS grow (grow -> Some) SPENDS the budget and TRACKS
    /// the holding for reconcile. MUTATION: flip either arm in `WorkerSpawner::run` (None ->
    /// commit_success, or Some -> commit_failure) and one of these assertions reddens.
    #[tokio::test]
    async fn run_refunds_clean_failures_and_spends_plus_tracks_announced() {
        // Clean failure: reserve, then grow returns None -> refund, not tracked.
        let ledger = empty_ledger(1);
        assert_eq!(begin(&ledger, &key(1)), Begin::Proceed);
        assert_eq!(ledger.lock().unwrap().remaining, 0, "reserved");
        WorkerSpawner::run(
            Arc::clone(&ledger),
            Arc::new(FakeGrower {
                outcome: Arc::new(Mutex::new(None)),
            }),
            noop_withdrawer(),
            Some((key(1), store_path_str(1))),
        )
        .await;
        {
            let led = ledger.lock().unwrap();
            assert_eq!(led.remaining, 1, "a clean failure REFUNDS the budget");
            assert!(led.held.is_empty(), "a clean failure tracks nothing");
            assert!(led.announced.is_empty());
        }

        // Announced/ambiguous: reserve, grow returns Some -> spend + track.
        assert_eq!(begin(&ledger, &key(2)), Begin::Proceed);
        WorkerSpawner::run(
            Arc::clone(&ledger),
            Arc::new(FakeGrower {
                outcome: Arc::new(Mutex::new(Some(content_key(2)))),
            }),
            noop_withdrawer(),
            Some((key(2), store_path_str(2))),
        )
        .await;
        let led = ledger.lock().unwrap();
        assert_eq!(
            led.remaining, 0,
            "an announced/ambiguous grow SPENDS the budget"
        );
        assert!(led.announced.contains(&key(2)));
        assert!(
            led.held.contains_key(&key(2)),
            "the holding is TRACKED for reconcile"
        );
    }

    /// AC#3 FIX D BITE (discriminating): the announce-error classification drives the ledger. A
    /// CLEAN pre-publication error (`Persist`/`Rejected`/`Ineligible` - GUARANTEED not published)
    /// maps to `None` -> `commit_failure` REFUNDS + tracks nothing; an AMBIGUOUS error
    /// (`Unreachable`/`DeadlineExceeded` - may be live) or `Ok` maps to `Some` -> `commit_success`
    /// SPENDS + TRACKS for `reconcile`. (The `None`->refund / `Some`->spend+track half is proven by
    /// `run_refunds_clean_failures_and_spends_plus_tracks_announced`.) MUTATION: making `Persist`
    /// ambiguous (or an ambiguous variant clean) in `announce_error_is_ambiguous` flips the mapped
    /// result - this reddens, discriminating the exact error the announcer raises BEFORE vs
    /// during/after `start_providing`/`put_record`.
    #[test]
    fn announce_error_classification_discriminates_clean_pre_publication_from_ambiguous() {
        let ck = content_key(9);
        // CLEAN pre-publication (announcer.rs: raised BEFORE the publish future) -> None -> refund.
        for clean in [
            AnnounceError::Persist("save-before-publish failed".into()),
            AnnounceError::Rejected("bad record".into()),
            AnnounceError::Ineligible(IneligibleReason::NotAllowlisted),
        ] {
            assert_eq!(
                classify_announce(Err(clean), ck).into_grow_result(),
                None,
                "a clean pre-publication announce error must REFUND (guaranteed not published)"
            );
        }
        // AMBIGUOUS (raised inside/around the publish future - may be live) -> Some -> spend + track.
        for ambiguous in [
            AnnounceError::Unreachable("partition".into()),
            AnnounceError::DeadlineExceeded,
        ] {
            assert_eq!(
                classify_announce(Err(ambiguous), ck).into_grow_result(),
                Some(ck),
                "an ambiguous announce error must SPEND + TRACK (reconcile may need to withdraw)"
            );
        }
        // Ok -> published -> Some (spend + track).
        assert_eq!(classify_announce(Ok(()), ck).into_grow_result(), Some(ck));
    }

    /// AC#3 / TASK-72 FIX 3b BITE (production-wired): `WorkerSpawner::run` reconciles + WITHDRAWS a
    /// GC'd holding and leaves a present one. MUTATION: delete the `reconcile(&ledger, ...)` call in
    /// `run` and the GC'd holding is never withdrawn - this reddens (this is the exact production
    /// dispatch body, not a directly-called `reconcile`).
    #[tokio::test]
    async fn run_reconciles_and_withdraws_a_gc_d_holding_through_the_production_path() {
        let present = unique_temp("present").join("store");
        std::fs::create_dir_all(&present).unwrap();
        let present_path = present
            .join(format!("{HASH32}-present"))
            .to_string_lossy()
            .into_owned();
        std::fs::write(&present_path, b"here").unwrap();
        let gone_path = format!("/nix/store/{HASH32}-gc-d");

        let mut held = HashMap::new();
        held.insert(key(1), (content_key(1), present_path));
        held.insert(key(2), (content_key(2), gone_path));
        let ledger = Arc::new(Mutex::new(AnnounceLedger {
            remaining: 0,
            inflight: HashSet::new(),
            announced: [key(1), key(2)].into_iter().collect(),
            held,
        }));
        let withdrawn = Arc::new(Mutex::new(Vec::new()));
        let wd: Arc<dyn Withdrawer> = Arc::new(FakeWithdrawer {
            result: Arc::new(Mutex::new(true)),
            withdrawn: Arc::clone(&withdrawn),
        });
        // Drive the production dispatch body with grow == None (a budget-exhausted fetch): reconcile
        // still runs.
        WorkerSpawner::run(Arc::clone(&ledger), Arc::new(NoopGrower), wd, None).await;

        assert_eq!(
            *withdrawn.lock().unwrap(),
            vec![content_key(2)],
            "only the GC'd record withdrawn"
        );
        let led = ledger.lock().unwrap();
        assert!(led.held.contains_key(&key(1)), "present holding kept");
        assert!(
            !led.held.contains_key(&key(2)),
            "GC'd holding dropped on success"
        );
    }

    /// AC#3 FIX B BITE: a FAILED withdraw is RETAINED in `held` and RETRIED on the next dispatch;
    /// only a SUCCESSFUL withdraw drops it. MUTATION: drop-on-failure in `reconcile` and the
    /// "retained after a failed withdraw" assertion reddens.
    #[tokio::test]
    async fn a_failed_withdraw_is_retained_and_retried() {
        let gone_path = format!("/nix/store/{HASH32}-gc-d");
        let mut held = HashMap::new();
        held.insert(key(5), (content_key(5), gone_path));
        let ledger = Arc::new(Mutex::new(AnnounceLedger {
            remaining: 0,
            inflight: HashSet::new(),
            announced: [key(5)].into_iter().collect(),
            held,
        }));
        let result = Arc::new(Mutex::new(false)); // fail the first withdraw
        let withdrawn = Arc::new(Mutex::new(Vec::new()));
        let wd: Arc<dyn Withdrawer> = Arc::new(FakeWithdrawer {
            result: Arc::clone(&result),
            withdrawn: Arc::clone(&withdrawn),
        });
        WorkerSpawner::run(
            Arc::clone(&ledger),
            Arc::new(NoopGrower),
            Arc::clone(&wd),
            None,
        )
        .await;
        assert_eq!(withdrawn.lock().unwrap().len(), 1, "one withdraw attempted");
        assert!(
            ledger.lock().unwrap().held.contains_key(&key(5)),
            "a FAILED withdraw KEEPS the holding for retry"
        );

        *result.lock().unwrap() = true; // succeed on retry
        WorkerSpawner::run(Arc::clone(&ledger), Arc::new(NoopGrower), wd, None).await;
        assert_eq!(
            withdrawn.lock().unwrap().len(),
            2,
            "retried on the next dispatch"
        );
        assert!(
            !ledger.lock().unwrap().held.contains_key(&key(5)),
            "a SUCCESSFUL withdraw drops the holding"
        );
    }

    // ---- AC#3 / TASK-72 eligibility + FIX C store-path location (fabric-free) ----

    fn verified_index() -> (Arc<AvailabilityIndex>, NarHashKey, String, String) {
        let body = b"a raw NAR regenerated on demand from a fetched store path (TASK-77)".to_vec();
        let true_key = NarHashKey::from_raw_nar(&body);
        // A well-formed path DIRECTLY under a temp store dir; eligible_provisions is told that same
        // store dir, so validate_store_path (FIX C) accepts it.
        let store_dir = unique_temp("root").join("store");
        std::fs::create_dir_all(&store_dir).unwrap();
        let nar_path = store_dir.join(format!("{HASH32}-fetched"));
        std::fs::write(&nar_path, &body).unwrap();
        let index = AvailabilityIndex::open(
            NodeId::from_bytes([0u8; 32]),
            Arc::new(RegularFileNarDumper) as Arc<dyn NarDumper>,
            Arc::new(NullStore),
            Arc::new(NullAnnounce),
        )
        .expect("index opens");
        (
            Arc::new(index),
            true_key,
            store_dir.to_string_lossy().into_owned(),
            nar_path.to_string_lossy().into_owned(),
        )
    }
    fn big_serve_budget() -> ServeBudget {
        ServeBudget {
            max_nar_bytes_uncompressed_nar: 1 << 30,
            max_inflight_bytes_uncompressed_nar: 1 << 30,
            max_serve_duration: std::time::Duration::from_secs(30),
        }
    }

    #[test]
    fn public_door_refuses_an_unallowlisted_fetched_path_lan_admits_it() {
        let (index, true_key, store_dir, store_path) = verified_index();
        let public = eligible_provisions(
            &index,
            &big_serve_budget(),
            &AnnounceAfterFetchDoor::Public(Arc::new(PublicNarAllowlist::disabled())),
            &store_dir,
            &true_key,
            &store_path,
        );
        assert!(
            public.is_err() && public.as_ref().unwrap_err().contains("allowlist"),
            "a PUBLIC node must not announce a fetched path it is not allowlisted to publish; got {public:?}"
        );

        let (index2, true_key2, store_dir2, store_path2) = verified_index();
        let lan = eligible_provisions(
            &index2,
            &big_serve_budget(),
            &AnnounceAfterFetchDoor::Lan(super::LanShare::operator_assembled()),
            &store_dir2,
            &true_key2,
            &store_path2,
        )
        .expect("a LAN door admits a verified-servable fetched path");
        assert_eq!(*lan[0].nar_hash(), true_key2);
    }

    #[test]
    fn a_mis_registered_fetched_path_is_never_announced() {
        let (index, _true_key, store_dir, store_path) = verified_index();
        let refused = eligible_provisions(
            &index,
            &big_serve_budget(),
            &AnnounceAfterFetchDoor::Lan(super::LanShare::operator_assembled()),
            &store_dir,
            &NarHashKey::from_sha256_bytes([0xAB; 32]),
            &store_path,
        );
        assert!(
            refused.is_err(),
            "a fetched path whose bytes do not hash to the registered NarHash must never be \
             announced; got {refused:?}"
        );
    }

    /// AC#3 FIX C BITE: `validate_store_path` requires the path DIRECTLY under the real store dir -
    /// a store-SHAPED decoy elsewhere (`/tmp/store/<validhash>-x`) is rejected before any dump.
    #[test]
    fn validate_store_path_requires_the_real_store_dir() {
        assert!(validate_store_path(&format!("/nix/store/{HASH32}-ok"), STORE_DIR).is_ok());
        assert!(
            validate_store_path("relative/path", STORE_DIR).is_err(),
            "not absolute"
        );
        assert!(
            validate_store_path("/etc/shadow", STORE_DIR).is_err(),
            "not a store path"
        );
        assert!(
            validate_store_path(&format!("/nix/store/{HASH32}-x/nested"), STORE_DIR).is_err(),
            "not directly under the store dir"
        );
        assert!(
            validate_store_path("/nix/store/tooshorthash-x", STORE_DIR).is_err(),
            "hash not 32 nix-base32 chars"
        );
        assert!(
            validate_store_path("/nix/store/0123456789abcdefghijklmnpqrsvwxy-x", STORE_DIR)
                .is_err(),
            "'e' is not in the nix-base32 alphabet"
        );
        // FIX C: a store-shaped path under a DIFFERENT parent (a decoy) is rejected.
        assert!(
            validate_store_path(&format!("/tmp/store/{HASH32}-x"), STORE_DIR).is_err(),
            "a /tmp/store decoy is not the real /nix/store"
        );
    }
}
