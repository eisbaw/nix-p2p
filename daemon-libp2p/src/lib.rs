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
    let signing_key = SigningKey::from_bytes(&seed);
    let provider = NodeId::from_bytes(signing_key.verifying_key().to_bytes());
    let key = ContentKey::derive_from_signed_nar_hash(nar_hash.as_bytes());
    let content = Blake3Digest::from_raw_nar(nar_bytes);
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
pub async fn announce_provider_seeds(
    fabric: &Libp2pFabric,
    identity_seed: [u8; 32],
    seeds: &[(NarHashKey, Vec<u8>)],
    ttl_secs: u64,
    now: u64,
    budget: &AnnounceBudget,
) -> Result<Vec<ProviderRecord>, String> {
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
