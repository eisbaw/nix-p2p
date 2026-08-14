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

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use fabric_libp2p::{
    ANNOUNCE_SEQ_FILENAME, Libp2pFabric, Libp2pNarSupplier, Multiaddr, NodeConfig,
    PROVIDER_FLOOR_FILENAME, PeerId,
};

use ed25519_dalek::SigningKey;
use peer_fabric::{
    AnnounceBudget, Axis, Blake3Digest, ContentKey, DiscoveryBudget, NodeId, PeerFabric,
    ProviderRecord, SafetyEnvelope, TransportOffer, TransportTag, require_axes,
    sign_provider_record,
};

use daemon_core::claim::NarHashKey;
use daemon_core::rewrite::RawServeDecision;
use daemon_core::source::NarSource;
use daemon_core::{
    AvailabilityIndex, HoldAnswer, PublicNarAllowlist, PublicNarClaim, PublicationRejected,
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
    let fabric = start_and_join_libp2p(&cfg, None).await?;
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
) -> Result<
    (
        Arc<Libp2pFabric>,
        Arc<dyn NarSource>,
        Arc<dyn RawServeDecision>,
    ),
    String,
> {
    let fabric = start_and_join_libp2p(&cfg, Some(supplier)).await?;

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
/// and gate-1 BLAKE3-verifies. The lone offer carries the libp2p NAR transport (registered
/// under [`TransportOffer::Iroh`], per fabric-libp2p's ADR).
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
        offers: vec![TransportOffer::Iroh { node: provider }],
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
    announce_seed_records(fabric, identity_seed, seeds, ttl_secs, now, budget).await
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
        announcer
            .announce(&record, budget)
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

/// The shared record-signing announce loop. PRIVATE to this module: neither the public nor the
/// private door is a bare-provision entry point reachable from outside. For each provision it
/// durably allocates the announce sequence, signs a record whose `content` is the verified digest
/// (via [`sign_libp2p_store_record`]), and publishes it under `budget`.
async fn announce_store_records(
    fabric: &Libp2pFabric,
    identity_seed: [u8; 32],
    provisions: &[StoreProvision],
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
        announcer.announce(&record, budget).await.map_err(|e| {
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
    announce_store_records(fabric, identity_seed, provisions, ttl_secs, now, budget).await
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
    announce_approved_public(fabric, identity_seed, &approved, ttl_secs, now, budget).await
}

/// Announce a record per [`ApprovedPublicProvision`], the PUBLIC counterpart of
/// [`announce_store_records`]. Consuming the capability (claim held) is what makes a public
/// announce impossible without an allowlist-minted claim.
async fn announce_approved_public(
    fabric: &Libp2pFabric,
    identity_seed: [u8; 32],
    approved: &[ApprovedPublicProvision],
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
    announce_store_records(fabric, identity_seed, &provisions, ttl_secs, now, budget).await
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
    announce_seed_records(
        fabric,
        identity_seed,
        &approved_seeds,
        ttl_secs,
        now,
        budget,
    )
    .await
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
) -> Result<Arc<Libp2pFabric>, String> {
    let node_config = NodeConfig {
        identity_seed: cfg.identity_seed,
        network_scope: cfg.network_scope.clone(),
    };
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
    // needs content discovery, node-address resolution and the fetch transport (registered
    // under the Iroh tag per the fabric-libp2p ADR); a PROVIDER additionally needs the
    // serve + announce axes. The single check lives in `peer_fabric::require_axes`, shared
    // with the iroh composition root so the two cannot drift on what "required" means.
    let mut required = vec![
        Axis::ProviderDirectory,
        Axis::NodeLocator,
        Axis::Transfer(TransportTag::Iroh),
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
