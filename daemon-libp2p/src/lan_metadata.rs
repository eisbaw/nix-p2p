//! Explicitly trusted LAN metadata, backed by the local Nix store and existing
//! verified supply/announcement path. Pool keys never enter PublicNarAllowlist.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64::Engine;
use daemon_core::source::{NarinfoSource, SourceError, StoreHash, UpstreamResponse};
use daemon_core::{AvailabilityIndex, NarHashKey, PeerDeriveLedger, StorePath, TrustedNarKeys};
use ed25519_dalek::{Signer, SigningKey};
use fabric_libp2p::metadata::{
    LAN_METADATA_TIMEOUT, LanMetadataSource, MAX_LAN_NARINFO, valid_store_hash,
};
use fabric_libp2p::{Libp2pFabric, PeerId, SwarmHandle};
use http_body_util::{BodyExt, Full};
use peer_fabric::{AnnounceBudget, Blake3Digest, NodeId, PeerFabric, ServeBudget};
use tokio::io::AsyncReadExt;

use crate::{
    InitialAnnounceConfig, LanShare, ProviderRelayReadiness, announce_store_provisions,
    verify_store_provisions_cancellable,
};

pub struct LanSigningKey {
    name: String,
    key: SigningKey,
}

impl LanSigningKey {
    pub fn load(path: &str) -> Result<Self, String> {
        let text =
            std::fs::read_to_string(path).map_err(|e| format!("reading LAN signing key: {e}"))?;
        Self::parse(text.trim())
    }

    fn parse(text: &str) -> Result<Self, String> {
        let (name, value) = text
            .split_once(':')
            .ok_or("LAN key must use Nix name:base64 format")?;
        if name.is_empty() || name.bytes().any(|b| b.is_ascii_whitespace() || b == b';') {
            return Err("invalid LAN key name".into());
        }
        let raw = base64::engine::general_purpose::STANDARD
            .decode(value)
            .map_err(|_| "invalid LAN secret key encoding")?;
        let pair: [u8; 64] = raw
            .try_into()
            .map_err(|_| "LAN secret key must contain 64 bytes")?;
        let key = SigningKey::from_keypair_bytes(&pair)
            .map_err(|_| "inconsistent LAN signing keypair")?;
        Ok(Self {
            name: name.into(),
            key,
        })
    }

    pub fn public_key(&self) -> String {
        format!(
            "{}:{}",
            self.name,
            base64::engine::general_purpose::STANDARD.encode(self.key.verifying_key().to_bytes())
        )
    }

    fn sign(&self, path: &str, hash: NarHashKey, size: u64, refs: &[String]) -> Vec<u8> {
        let fingerprint = format!("1;{path};{hash};{size};{}", refs.join(","));
        let signature = self.key.sign(fingerprint.as_bytes());
        let references = refs
            .iter()
            .map(|p| p.rsplit('/').next().unwrap_or(p))
            .collect::<Vec<_>>()
            .join(" ");
        let hash_text = hash.to_string();
        let digest = hash_text.strip_prefix("sha256:").expect("canonical sha256");
        format!("StorePath: {path}\nURL: nar/{digest}.nar\nCompression: none\nFileHash: {hash}\nFileSize: {size}\nNarHash: {hash}\nNarSize: {size}\nReferences: {references}\nSig: {}:{}\n",
            self.name, base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())).into_bytes()
    }
}

const MAX_LAN_STATE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone)]
struct VerifiedAlias {
    key: NarHashKey,
    path: StorePath,
    derived: daemon_core::DerivedNar,
}

/// Admitted output paths are the durable source of truth. AvailabilityIndex
/// keeps one chosen backing per NarHash; this registry retains equal-NAR aliases
/// so losing that backing does not lose another admitted, still-live output.
struct LanAliases {
    file: PathBuf,
    limit: usize,
    paths: Mutex<HashMap<String, VerifiedAlias>>,
}

impl LanAliases {
    fn path_hash(path: &StorePath) -> Result<String, String> {
        let hash = path
            .as_path()
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.split_once('-'))
            .map(|(hash, _)| hash)
            .filter(|hash| valid_store_hash(hash))
            .ok_or("invalid LAN alias store path")?;
        Ok(hash.to_owned())
    }

    fn open(
        file: PathBuf,
        limit: usize,
        legacy: &[daemon_core::availability::PersistedRegistration],
        excluded: &HashSet<NarHashKey>,
    ) -> Result<Self, String> {
        let (mut paths, migrated) = match std::fs::File::open(&file) {
            Ok(input) => {
                let mut bytes = Vec::new();
                Read::take(input, (MAX_LAN_STATE_BYTES + 1) as u64)
                    .read_to_end(&mut bytes)
                    .map_err(|e| format!("reading LAN aliases: {e}"))?;
                if bytes.len() > MAX_LAN_STATE_BYTES {
                    return Err("LAN aliases exceed 4 MiB".into());
                }
                // Full store path -> (NarHash, verified BLAKE3, uncompressed NarSize).
                let raw: BTreeMap<String, (String, String, u64)> =
                    serde_json::from_slice(&bytes)
                        .map_err(|e| format!("invalid LAN alias state: {e}"))?;
                if raw.len() > limit {
                    return Err("LAN aliases exceed path budget".into());
                }
                let mut paths = HashMap::new();
                for (path, (key, digest, size)) in raw {
                    let path = StorePath::new(path);
                    let key: NarHashKey = key.parse().map_err(|_| "invalid LAN alias NarHash")?;
                    let blake3 = digest.parse().map_err(|_| "invalid LAN alias digest")?;
                    if size == 0 {
                        return Err("zero LAN alias NarSize".into());
                    }
                    if paths
                        .insert(
                            Self::path_hash(&path)?,
                            VerifiedAlias {
                                key,
                                path,
                                derived: daemon_core::DerivedNar {
                                    blake3,
                                    nar_size_uncompressed_nar: size,
                                },
                            },
                        )
                        .is_some()
                    {
                        return Err("ambiguous LAN alias store hash".into());
                    }
                }
                (paths, false)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let paths = legacy
                    .iter()
                    .filter_map(|reg| reg.derived.map(|derived| (reg, derived)))
                    .map(|(reg, derived)| {
                        Ok((
                            Self::path_hash(&reg.store_path)?,
                            VerifiedAlias {
                                key: reg.key,
                                path: reg.store_path.clone(),
                                derived,
                            },
                        ))
                    })
                    .collect::<Result<HashMap<_, _>, String>>()?;
                (paths, true)
            }
            Err(error) => return Err(format!("opening LAN aliases: {error}")),
        };
        paths.retain(|_, alias| !excluded.contains(&alias.key));
        let registry = Self {
            file,
            limit,
            paths: Mutex::new(paths),
        };
        // Migration records only already-verified bindings. Later boots load the
        // alias set, not merely the index's most recently selected backing.
        if migrated {
            registry.save(&registry.paths.lock().expect("LAN aliases poisoned"))?;
        }
        Ok(registry)
    }

    fn save(&self, paths: &HashMap<String, VerifiedAlias>) -> Result<(), String> {
        if paths.len() > self.limit {
            return Err("LAN alias path budget exhausted".into());
        }
        let raw: BTreeMap<_, _> = paths
            .values()
            .map(|alias| {
                let path = alias
                    .path
                    .as_path()
                    .to_str()
                    .ok_or("non-UTF8 LAN alias path")?;
                Ok((
                    path.to_owned(),
                    (
                        alias.key.to_string(),
                        alias.derived.blake3.to_string(),
                        alias.derived.nar_size_uncompressed_nar,
                    ),
                ))
            })
            .collect::<Result<_, String>>()?;
        let bytes =
            serde_json::to_vec(&raw).map_err(|e| format!("serializing LAN aliases: {e}"))?;
        if bytes.len() > MAX_LAN_STATE_BYTES {
            return Err("LAN aliases exceed 4 MiB".into());
        }
        let parent = self
            .file
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."));
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("creating LAN alias directory: {e}"))?;
        let temp = self
            .file
            .with_extension(format!("tmp-{}", std::process::id()));
        let result = (|| -> std::io::Result<()> {
            let mut out = std::fs::File::create(&temp)?;
            out.write_all(&bytes)?;
            out.sync_all()?;
            std::fs::rename(&temp, &self.file)?;
            std::fs::File::open(parent)?.sync_all()
        })();
        if let Err(error) = result {
            let _ = std::fs::remove_file(temp);
            return Err(format!("persisting LAN aliases: {error}"));
        }
        Ok(())
    }

    fn len(&self) -> usize {
        self.paths.lock().expect("LAN aliases poisoned").len()
    }

    fn can_admit(&self, hash: &str) -> bool {
        let paths = self.paths.lock().expect("LAN aliases poisoned");
        paths.contains_key(hash) || paths.len() < self.limit
    }

    fn keys(&self) -> HashSet<NarHashKey> {
        self.paths
            .lock()
            .expect("LAN aliases poisoned")
            .values()
            .map(|alias| alias.key)
            .collect()
    }

    fn admit(
        &self,
        index: &AvailabilityIndex,
        key: NarHashKey,
        path: StorePath,
        size: u64,
        cancellation: &dyn daemon_core::availability::CancellationCheck,
    ) -> Result<Vec<crate::StoreProvision>, String> {
        let hash = Self::path_hash(&path)?;
        if !self.can_admit(&hash) {
            return Err("LAN alias path budget exhausted".into());
        }
        // Verify before replacement. A corrupt candidate or rejected persistence
        // cannot retire a healthy sibling's current backing.
        let derived = index
            .verify_and_register(key, path.clone(), size, cancellation)
            .map_err(|e| e.to_string())?;
        {
            // Commit ownership before any further cancellation check. If the
            // requester leaves now, refresh still owns this verified binding.
            let mut paths = self.paths.lock().expect("LAN aliases poisoned");
            let mut next = paths.clone();
            next.insert(hash, VerifiedAlias { key, path, derived });
            self.save(&next)?;
            *paths = next;
        }
        verify_store_provisions_cancellable(index, &[key], cancellation)
    }

    fn reconcile(
        &self,
        index: &AvailabilityIndex,
        key: NarHashKey,
        ledger: &PeerDeriveLedger,
        peer: &NodeId,
        cancellation: &dyn daemon_core::availability::CancellationCheck,
    ) -> Result<Option<Vec<crate::StoreProvision>>, String> {
        let mut live: Vec<_> = self
            .paths
            .lock()
            .expect("LAN aliases poisoned")
            .values()
            .filter(|alias| alias.key == key && alias.path.exists())
            .cloned()
            .collect();
        live.sort_by(|a, b| a.path.as_path().cmp(b.path.as_path()));
        let Some(first) = live.first() else {
            index.unregister(&key).map_err(|e| e.to_string())?;
            // Retain the aliases until the caller successfully withdraws, allowing retry.
            return Ok(None);
        };
        let current = index.supply_catalog().probe_record(&first.derived.blake3);
        let warm = current.as_ref().and_then(|record| {
            live.iter().find(|alias| {
                alias.path.as_path() == record.store_path
                    && alias.derived.nar_size_uncompressed_nar == record.declared_size
            })
        });
        let chosen = warm.unwrap_or(first);
        if warm.is_none() {
            if !ledger
                .try_admit_work(peer, chosen.derived.nar_size_uncompressed_nar, 1)
                .is_admitted()
            {
                return Err("LAN replacement verification work budget exhausted".into());
            }
            index
                .verify_and_register(
                    key,
                    chosen.path.clone(),
                    chosen.derived.nar_size_uncompressed_nar,
                    cancellation,
                )
                .map_err(|e| e.to_string())?;
        }
        let provisions = verify_store_provisions_cancellable(index, &[key], cancellation)?;
        let mut paths = self.paths.lock().expect("LAN aliases poisoned");
        let mut next = paths.clone();
        next.retain(|_, alias| alias.key != key || alias.path.exists());
        if next.len() != paths.len() {
            self.save(&next)?;
            *paths = next;
        }
        Ok(Some(provisions))
    }

    fn remove_key(&self, key: NarHashKey) -> Result<(), String> {
        let mut paths = self.paths.lock().expect("LAN aliases poisoned");
        let mut next = paths.clone();
        next.retain(|_, alias| alias.key != key);
        self.save(&next)?;
        *paths = next;
        Ok(())
    }
}

/// All authority is supplied at construction by the LAN-only composition root.
pub struct LocalLanMetadata {
    pub signer: LanSigningKey,
    pub fabric: Arc<Libp2pFabric>,
    pub readiness: ProviderRelayReadiness,
    pub index: Arc<AvailabilityIndex>,
    pub lan: LanShare,
    pub identity_seed: [u8; 32],
    pub ledger: Arc<PeerDeriveLedger>,
    pub serve_budget: ServeBudget,
    pub announce_budget: AnnounceBudget,
    pub path_limit: usize,
    pub store_dir: PathBuf,
    aliases: Arc<LanAliases>,
    publication: tokio::sync::Mutex<()>,
    ttl_secs: u64,
    excluded: HashSet<NarHashKey>,
    work: Arc<tokio::sync::Semaphore>,
    fetched_slots: Arc<tokio::sync::Semaphore>,
}

pub struct LocalLanMetadataConfig {
    pub signer: LanSigningKey,
    pub fabric: Arc<Libp2pFabric>,
    pub readiness: ProviderRelayReadiness,
    pub index: Arc<AvailabilityIndex>,
    pub lan: LanShare,
    pub identity_seed: [u8; 32],
    pub ledger: Arc<PeerDeriveLedger>,
    pub serve_budget: ServeBudget,
    pub announce_budget: AnnounceBudget,
    pub path_limit: usize,
    pub store_dir: PathBuf,
    pub state_file: PathBuf,
    pub ttl_secs: u64,
    pub excluded: HashSet<NarHashKey>,
}

impl LocalLanMetadata {
    pub fn new(config: LocalLanMetadataConfig) -> Result<Self, String> {
        let LocalLanMetadataConfig {
            signer,
            fabric,
            readiness,
            index,
            lan,
            identity_seed,
            ledger,
            serve_budget,
            announce_budget,
            path_limit,
            store_dir,
            state_file,
            ttl_secs,
            excluded,
        } = config;
        use daemon_core::IndexStore;
        let path_limit = path_limit.min(4096);
        let registrations = BoundedLanStore::new(state_file.clone(), path_limit)
            .load()
            .map_err(|e| e.to_string())?;
        let aliases = Arc::new(LanAliases::open(
            state_file.with_extension("aliases.json"),
            path_limit,
            &registrations,
            &excluded,
        )?);
        let owned = aliases.keys();
        // An interrupted initial admission can leave a chosen backing without a
        // committed alias. Only the durable alias registry owns dynamic supply.
        for reg in &registrations {
            if !owned.contains(&reg.key) && !excluded.contains(&reg.key) {
                index.unregister(&reg.key).map_err(|e| e.to_string())?;
            }
        }
        Ok(Self {
            signer,
            fabric,
            readiness,
            index,
            lan,
            identity_seed,
            ledger,
            serve_budget,
            announce_budget,
            path_limit,
            store_dir,
            aliases,
            publication: tokio::sync::Mutex::new(()),
            ttl_secs,
            excluded,
            work: Arc::new(tokio::sync::Semaphore::new(2)),
            fetched_slots: Arc::new(tokio::sync::Semaphore::new(4)),
        })
    }

    async fn produce(&self, peer: PeerId, hash: &str) -> Option<Vec<u8>> {
        if !valid_store_hash(hash) {
            return None;
        }
        let deadline = std::time::Instant::now() + LAN_METADATA_TIMEOUT;
        let _publication = self.publication.lock().await;
        let permit = self.work.clone().try_acquire_owned().ok()?;
        let ledger_key =
            NodeId::from_bytes(*Blake3Digest::from_raw_nar(&peer.to_bytes()).as_bytes());
        if !self.ledger.try_admit_work(&ledger_key, 0, 1).is_admitted() {
            return None;
        }
        let prefix = format!("{hash}-");
        let mut entries = tokio::fs::read_dir(&self.store_dir).await.ok()?;
        let mut found = None;
        let mut complete = false;
        // Local-only name lookup; never sends a listing to a peer. Explicit cap
        // and async iteration make even negative lookups bounded/cancellable.
        for _ in 0..200_000 {
            let Some(entry) = entries.next_entry().await.ok()? else {
                complete = true;
                break;
            };
            if entry.file_name().to_string_lossy().starts_with(&prefix) {
                if found.is_some() {
                    return None;
                }
                found = Some(entry.path());
            }
        }
        if !complete {
            return None;
        }
        let path = found?;
        let path_text = path.to_str()?.to_owned();
        let info = path_info(&path_text).await?;
        let size = info.get("narSize")?.as_u64()?;
        if size == 0 || size > self.serve_budget.max_nar_bytes_uncompressed_nar {
            return None;
        }
        let raw_hash = info.get("narHash")?.as_str()?;
        let nar_hash = if let Some(b64) = raw_hash.strip_prefix("sha256-") {
            NarHashKey::from_sha256_bytes(
                base64::engine::general_purpose::STANDARD
                    .decode(b64)
                    .ok()?
                    .try_into()
                    .ok()?,
            )
        } else {
            raw_hash.parse().ok()?
        };
        let mut refs: Vec<String> = info
            .get("references")?
            .as_array()?
            .iter()
            .map(|v| v.as_str().map(str::to_owned))
            .collect::<Option<_>>()?;
        refs.sort();
        if refs
            .iter()
            .any(|p| !p.starts_with("/nix/store/") || p.contains(['\n', ';', ',']))
        {
            return None;
        }
        let bytes = self.signer.sign(&path_text, nar_hash, size, &refs);
        if bytes.len() > MAX_LAN_NARINFO {
            return None;
        }
        // Existing static supply has its own publication owner. Never refresh
        // or withdraw its claim from the local-output manager.
        if self.excluded.contains(&nar_hash) {
            return Some(bytes);
        }
        if !self.aliases.can_admit(hash) {
            return None;
        }
        if !self
            .ledger
            .try_admit_work(&ledger_key, size, 1)
            .is_admitted()
        {
            return None;
        }
        let index = self.index.clone();
        let aliases = self.aliases.clone();
        let store_path = StorePath::new(path);
        // Admission commits its verified alias inside the owned worker. A dropped
        // network waiter cannot strand a successful registration without an owner.
        let provisions = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            aliases
                .admit(
                    &index,
                    nar_hash,
                    store_path,
                    size,
                    &VerificationDeadline(deadline),
                )
                .map_err(|_| tracing::warn!("LAN store admission failed"))
                .ok()
        })
        .await
        .ok()??;
        self.announce(&provisions).await?;
        tracing::info!("LAN custom metadata published with verified store supply");
        Some(bytes)
    }

    async fn announce(&self, provisions: &[crate::StoreProvision]) -> Option<()> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
        announce_store_provisions(
            &self.fabric,
            &self.readiness,
            InitialAnnounceConfig {
                identity_seed: self.identity_seed,
                ttl_secs: self.ttl_secs,
                now,
                budget: &self.announce_budget,
            },
            provisions,
            self.lan,
        )
        .await
        .map_err(|_| tracing::warn!("LAN publication failed"))
        .ok()?;
        Some(())
    }

    // Renewal is maintenance of admitted registrations, not a new metadata query.
    // The index reuses verified bindings; no fake dump work is charged to peers.
    async fn refresh(&self) {
        for key in self.aliases.keys() {
            // One publication lifecycle per content identity, even when several
            // admitted output paths have identical NAR bytes.
            let _publication = self.publication.lock().await;
            let index = self.index.clone();
            let aliases = self.aliases.clone();
            let ledger = self.ledger.clone();
            let ledger_key = NodeId::from_bytes(
                *Blake3Digest::from_raw_nar(&self.fabric.peer_id().to_bytes()).as_bytes(),
            );
            let permit = match self.work.clone().acquire_owned().await {
                Ok(permit) => permit,
                Err(_) => return,
            };
            let deadline = std::time::Instant::now() + LAN_METADATA_TIMEOUT;
            let refreshed = tokio::task::spawn_blocking(move || {
                let _permit = permit;
                aliases.reconcile(
                    &index,
                    key,
                    &ledger,
                    &ledger_key,
                    &VerificationDeadline(deadline),
                )
            })
            .await;
            match refreshed {
                Ok(Ok(Some(provisions))) => {
                    let _ = tokio::time::timeout(LAN_METADATA_TIMEOUT, self.announce(&provisions))
                        .await;
                }
                Ok(Ok(None)) => {
                    let Some(announcer) = self.fabric.announcer() else {
                        continue;
                    };
                    if matches!(
                        tokio::time::timeout(
                            LAN_METADATA_TIMEOUT,
                            announcer.withdraw(&crate::provider_content_key(&key))
                        )
                        .await,
                        Ok(Ok(_))
                    ) {
                        if self.aliases.remove_key(key).is_err() {
                            tracing::warn!("LAN alias retirement persistence failed");
                        }
                    } else {
                        tracing::warn!("LAN supply withdrawal failed; will retry");
                    }
                }
                _ => tracing::warn!("LAN supply renewal verification failed"),
            }
        }
    }

    pub fn start_refresh(self: &Arc<Self>) -> fabric_libp2p::metadata::LanMetadataServer {
        let source = self.clone();
        fabric_libp2p::metadata::LanMetadataServer::new(tokio::spawn(async move {
            let period = Duration::from_secs((source.ttl_secs / 3).clamp(1, 300));
            let mut interval = tokio::time::interval(period);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                source.refresh().await;
            }
        }))
    }
}

#[async_trait]
impl LanMetadataSource for LocalLanMetadata {
    async fn lookup(&self, peer: PeerId, hash: &str) -> Option<Vec<u8>> {
        tokio::time::timeout(LAN_METADATA_TIMEOUT, self.produce(peer, hash))
            .await
            .ok()
            .flatten()
    }
}

async fn path_info(path: &str) -> Option<serde_json::Value> {
    let mut child = tokio::process::Command::new("nix")
        .args([
            "--extra-experimental-features",
            "nix-command",
            "path-info",
            "--json",
            "--option",
            "substituters",
            "",
            path,
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| tracing::warn!(%error, "starting local Nix metadata query failed"))
        .ok()?;
    let mut bytes = Vec::new();
    child
        .stdout
        .take()?
        .take((MAX_LAN_NARINFO + 1) as u64)
        .read_to_end(&mut bytes)
        .await
        .ok()?;
    if bytes.len() > MAX_LAN_NARINFO {
        return None;
    }
    let status = child
        .wait()
        .await
        .map_err(|error| tracing::warn!(%error, "waiting for local Nix metadata query failed"))
        .ok()?;
    if !status.success() {
        tracing::debug!(%status, "local Nix metadata query declined path");
        return None;
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|error| tracing::warn!(%error, "invalid local Nix metadata JSON"))
        .ok()?;
    value
        .get(path)
        .cloned()
        .or_else(|| value.as_array()?.first().cloned())
}

pub struct LanNarinfoSource {
    pub upstream: Arc<dyn NarinfoSource>,
    pub handle: SwarmHandle,
    pub local: Option<Arc<LocalLanMetadata>>,
    pub keys: TrustedNarKeys,
}

impl LanNarinfoSource {
    fn validate(&self, bytes: &[u8], hash: &StoreHash) -> Option<Vec<u8>> {
        validate_lan_metadata(bytes, hash, &self.keys)
    }

    async fn lookup(&self, hash: &StoreHash) -> Option<Vec<u8>> {
        if let Some(local) = &self.local
            && let Some(bytes) = local.lookup(local.fabric.peer_id(), hash.as_str()).await
            && let Some(bytes) = self.validate(&bytes, hash)
        {
            return Some(bytes);
        }
        let mut requests = tokio::task::JoinSet::new();
        for peer in self.handle.lan_metadata_candidates().await {
            let handle = self.handle.clone();
            let hash = hash.as_str().to_owned();
            requests.spawn(async move { handle.fetch_lan_metadata(peer, &hash).await });
        }
        while let Some(result) = requests.join_next().await {
            if let Ok(Some(bytes)) = result
                && let Some(bytes) = self.validate(&bytes, hash)
            {
                return Some(bytes);
            }
        }
        None
    }
}

#[async_trait]
impl NarinfoSource for LanNarinfoSource {
    async fn fetch(&self, hash: &StoreHash) -> Result<UpstreamResponse, SourceError> {
        self.fetch_within(hash, None).await
    }

    async fn fetch_within(
        &self,
        hash: &StoreHash,
        budget: Option<Duration>,
    ) -> Result<UpstreamResponse, SourceError> {
        let start = std::time::Instant::now();
        let limit = budget
            .unwrap_or(LAN_METADATA_TIMEOUT)
            .min(LAN_METADATA_TIMEOUT);
        if let Ok(Some(bytes)) = tokio::time::timeout(limit, self.lookup(hash)).await {
            return Ok(UpstreamResponse {
                status: 200,
                headers: http::HeaderMap::new(),
                body: Full::new(bytes::Bytes::from(bytes))
                    .map_err(|never| match never {})
                    .boxed(),
            });
        }
        let remaining = budget.map(|b| b.saturating_sub(start.elapsed()));
        self.upstream.fetch_within(hash, remaining).await
    }
}

fn validate_lan_metadata(bytes: &[u8], hash: &StoreHash, keys: &TrustedNarKeys) -> Option<Vec<u8>> {
    let proof = daemon_core::public_allowlist::prove_public(bytes, keys)
        .map_err(|_| tracing::warn!("LAN metadata rejected"))
        .ok()?;
    if proof.store_hash != hash.as_str() {
        return None;
    }
    Some(daemon_core::rewrite::to_raw(bytes).ok()?.body)
}

struct VerificationDeadline(std::time::Instant);
impl daemon_core::availability::CancellationCheck for VerificationDeadline {
    fn is_cancelled(&self) -> bool {
        std::time::Instant::now() >= self.0
    }
}

/// The same durable index used by store-backed payload serving, with an explicit
/// local-output retention bound. It stores metadata/digests, never NAR bodies.
pub struct BoundedLanStore {
    path: PathBuf,
    limit: usize,
}
impl BoundedLanStore {
    pub fn new(path: PathBuf, limit: usize) -> Self {
        Self {
            path,
            limit: limit.min(4096),
        }
    }
}
impl daemon_core::IndexStore for BoundedLanStore {
    fn load(
        &self,
    ) -> Result<
        Vec<daemon_core::availability::PersistedRegistration>,
        daemon_core::availability::PersistError,
    > {
        use daemon_core::availability::PersistError;
        if std::fs::metadata(&self.path).is_ok_and(|m| m.len() > 4 * 1024 * 1024) {
            return Err(PersistError("LAN supply state exceeds 4 MiB".into()));
        }
        let entries = daemon_core::JsonFileStore::new(&self.path).load()?;
        if entries.len() > self.limit {
            return Err(PersistError(
                "LAN supply state exceeds configured path budget".into(),
            ));
        }
        Ok(entries)
    }
    fn save(
        &self,
        entries: &[daemon_core::availability::PersistedRegistration],
    ) -> Result<(), daemon_core::availability::PersistError> {
        if entries.len() > self.limit {
            return Err(daemon_core::availability::PersistError(
                "LAN supply path budget exhausted".into(),
            ));
        }
        daemon_core::JsonFileStore::new(&self.path).save(entries)
    }
}

/// When custom sharing is enabled it owns the whole dynamic store leg, so
/// fetched and locally built paths cannot race separate announcement owners.
pub struct LanAfterFetch(pub Arc<LocalLanMetadata>);
impl daemon_core::PostFetchAnnounce for LanAfterFetch {
    fn on_fetched(&self, _: &daemon_core::source::NarHash, path: &str) {
        let Some(hash) = std::path::Path::new(path)
            .file_name()
            .and_then(|v| v.to_str())
            .and_then(|v| v.split_once('-'))
            .map(|(h, _)| h.to_owned())
        else {
            return;
        };
        let Ok(permit) = self.0.fetched_slots.clone().try_acquire_owned() else {
            return;
        };
        let source = self.0.clone();
        tokio::spawn(async move {
            let _permit = permit;
            // Nix imports after HTTP completion; allow that commit to become visible.
            for _ in 0..20 {
                tokio::time::sleep(Duration::from_millis(100)).await;
                if source
                    .lookup(source.fabric.peer_id(), &hash)
                    .await
                    .is_some()
                {
                    break;
                }
            }
        });
    }
    fn budget_used(&self) -> Option<u64> {
        Some(self.0.aliases.len() as u64)
    }
}

/// Consuming a LAN-signed output is not permission to share it. With local
/// custom sharing disabled, only upstream-proven paths reach the dynamic index.
pub struct UpstreamOnlyAfterFetch {
    pub inner: Arc<dyn daemon_core::PostFetchAnnounce>,
    pub allowed: Arc<daemon_core::PublicNarAllowlist>,
}
impl daemon_core::PostFetchAnnounce for UpstreamOnlyAfterFetch {
    fn on_fetched(&self, hash: &daemon_core::source::NarHash, path: &str) {
        if hash
            .as_str()
            .parse::<NarHashKey>()
            .is_ok_and(|key| self.allowed.contains(&key))
        {
            self.inner.on_fetched(hash, path);
        }
    }
    fn budget_used(&self) -> Option<u64> {
        self.inner.budget_used()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NeverCancelled;
    impl daemon_core::availability::CancellationCheck for NeverCancelled {
        fn is_cancelled(&self) -> bool {
            false
        }
    }

    struct AliasFixture {
        dir: PathBuf,
        first: StorePath,
        second: StorePath,
        bytes: Vec<u8>,
    }
    impl AliasFixture {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "nixp2p-lan-alias-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let first = StorePath::new(dir.join("00000000000000000000000000000000-first"));
            let second = StorePath::new(dir.join("11111111111111111111111111111111-second"));
            let bytes = b"same raw NAR under distinct store path names".to_vec();
            std::fs::write(first.as_path(), &bytes).unwrap();
            std::fs::write(second.as_path(), &bytes).unwrap();
            Self {
                dir,
                first,
                second,
                bytes,
            }
        }
        fn open(&self, limit: usize) -> (AvailabilityIndex, LanAliases) {
            use daemon_core::IndexStore;
            let store = Arc::new(BoundedLanStore::new(self.dir.join("index.json"), limit));
            let legacy = store.load().unwrap();
            let index = AvailabilityIndex::open(
                NodeId::from_bytes([3; 32]),
                Arc::new(daemon_core::RegularFileNarDumper),
                store,
                Arc::new(daemon_core::NullAnnounce),
            )
            .unwrap();
            let aliases = LanAliases::open(
                self.dir.join("index.aliases.json"),
                limit,
                &legacy,
                &HashSet::new(),
            )
            .unwrap();
            (index, aliases)
        }
    }
    impl Drop for AliasFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn equal_nar_alias_survives_restart_and_gc_of_either_path() {
        // Test both GC orders. Losing the currently selected backing requires a
        // metered replacement dump; losing its sibling requires no dump.
        for remove_current in [true, false] {
            let fixture = AliasFixture::new();
            let key = NarHashKey::from_raw_nar(&fixture.bytes);
            let digest = Blake3Digest::from_raw_nar(&fixture.bytes);
            let size = fixture.bytes.len() as u64;
            let (index, aliases) = fixture.open(2);
            aliases
                .admit(&index, key, fixture.first.clone(), size, &NeverCancelled)
                .unwrap();
            aliases
                .admit(&index, key, fixture.second.clone(), size, &NeverCancelled)
                .unwrap();
            assert_eq!(aliases.len(), 2);
            assert_eq!(aliases.keys().len(), 1);
            assert_eq!(
                index
                    .supply_catalog()
                    .probe_record(&digest)
                    .unwrap()
                    .store_path,
                fixture.second.as_path()
            );
            drop(aliases);
            drop(index);
            // Restore from real on-disk state, without asking for metadata again.
            let (index, aliases) = fixture.open(2);
            assert_eq!(aliases.len(), 2);
            let (removed, surviving) = if remove_current {
                (&fixture.second, &fixture.first)
            } else {
                (&fixture.first, &fixture.second)
            };
            std::fs::remove_file(removed.as_path()).unwrap();
            let ledger = PeerDeriveLedger::new(peer_fabric::DeriveBudget::default());
            let peer = NodeId::from_bytes([4; 32]);
            assert!(
                aliases
                    .reconcile(&index, key, &ledger, &peer, &NeverCancelled)
                    .unwrap()
                    .is_some()
            );
            assert_eq!(aliases.len(), 1);
            assert_eq!(
                index
                    .supply_catalog()
                    .probe_record(&digest)
                    .unwrap()
                    .store_path,
                surviving.as_path()
            );
            assert_eq!(
                index
                    .supply_raw_nar_cancellable(&digest, &NeverCancelled)
                    .unwrap(),
                fixture.bytes
            );
            let expected_work = if remove_current { size } else { 0 };
            assert_eq!(ledger.global_bytes_used(), expected_work);
            // TTL refresh uses the warm binding, with no fictitious work charge.
            assert!(
                aliases
                    .reconcile(&index, key, &ledger, &peer, &NeverCancelled)
                    .unwrap()
                    .is_some()
            );
            assert_eq!(ledger.global_bytes_used(), expected_work);
            drop(aliases);
            drop(index);
            let (index, aliases) = fixture.open(2);
            assert_eq!(aliases.len(), 1);
            assert_eq!(
                index
                    .supply_raw_nar_cancellable(&digest, &NeverCancelled)
                    .unwrap(),
                fixture.bytes
            );
            std::fs::remove_file(surviving.as_path()).unwrap();
            assert!(
                aliases
                    .reconcile(&index, key, &ledger, &peer, &NeverCancelled)
                    .unwrap()
                    .is_none()
            );
            // Keep withdrawal retry state until the announcement owner succeeds.
            assert!(aliases.keys().contains(&key));
            assert!(index.supply_catalog().probe_record(&digest).is_none());
            aliases.remove_key(key).unwrap();
            drop(aliases);
            drop(index);
            assert!(fixture.open(2).1.keys().is_empty());
        }
    }

    #[test]
    fn alias_budget_rejects_new_path_without_replacing_healthy_backing() {
        let fixture = AliasFixture::new();
        let key = NarHashKey::from_raw_nar(&fixture.bytes);
        let digest = Blake3Digest::from_raw_nar(&fixture.bytes);
        let size = fixture.bytes.len() as u64;
        let (index, aliases) = fixture.open(1);
        aliases
            .admit(&index, key, fixture.first.clone(), size, &NeverCancelled)
            .unwrap();
        assert!(
            aliases
                .admit(&index, key, fixture.second.clone(), size, &NeverCancelled)
                .is_err()
        );
        assert_eq!(aliases.len(), 1);
        assert_eq!(
            index
                .supply_catalog()
                .probe_record(&digest)
                .unwrap()
                .store_path,
            fixture.first.as_path()
        );
        drop(aliases);
        drop(index);
        assert_eq!(fixture.open(1).1.len(), 1);
    }

    #[test]
    fn consuming_a_custom_output_does_not_enable_resharing() {
        use daemon_core::PostFetchAnnounce;
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Counter(AtomicUsize);
        impl PostFetchAnnounce for Counter {
            fn on_fetched(&self, _: &daemon_core::source::NarHash, _: &str) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
        let upstream = LanSigningKey {
            name: "upstream".into(),
            key: SigningKey::from_bytes(&[17; 32]),
        };
        let custom = LanSigningKey {
            name: "custom".into(),
            key: SigningKey::from_bytes(&[18; 32]),
        };
        let allowed = Arc::new(daemon_core::PublicNarAllowlist::in_memory(
            TrustedNarKeys::from_lines([upstream.public_key()]).unwrap(),
        ));
        let counter = Arc::new(Counter(AtomicUsize::new(0)));
        let hook = UpstreamOnlyAfterFetch {
            inner: counter.clone(),
            allowed: allowed.clone(),
        };
        let path = "/nix/store/00000000000000000000000000000000-example";
        let requested = StoreHash::new("00000000000000000000000000000000");
        let hash = NarHashKey::from_raw_nar(b"payload");
        let nar_hash = daemon_core::source::NarHash::new(hash.to_string());
        allowed.learn(&requested, &custom.sign(path, hash, 7, &[]));
        hook.on_fetched(&nar_hash, path);
        assert_eq!(counter.0.load(Ordering::Relaxed), 0);
        allowed.learn(&requested, &upstream.sign(path, hash, 7, &[]));
        hook.on_fetched(&nar_hash, path);
        assert_eq!(counter.0.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn lan_signature_gate_rejects_tampering_wrong_authority_and_wrong_request() {
        let signer = LanSigningKey {
            name: "test-lan".into(),
            key: SigningKey::from_bytes(&[7; 32]),
        };
        let hash = StoreHash::new("00000000000000000000000000000000");
        let keys = TrustedNarKeys::from_lines([signer.public_key()]).unwrap();
        let metadata = signer.sign(
            "/nix/store/00000000000000000000000000000000-output",
            NarHashKey::from_raw_nar(b"test"),
            120,
            &[],
        );
        assert!(validate_lan_metadata(&metadata, &hash, &keys).is_some());
        assert!(validate_lan_metadata(&metadata, &hash, &TrustedNarKeys::empty()).is_none());
        let foreign = LanSigningKey {
            name: "test-lan".into(),
            key: SigningKey::from_bytes(&[8; 32]),
        };
        let foreign_keys = TrustedNarKeys::from_lines([foreign.public_key()]).unwrap();
        assert!(validate_lan_metadata(&metadata, &hash, &foreign_keys).is_none());
        let tampered = String::from_utf8(metadata.clone())
            .unwrap()
            .replace("NarSize: 120", "NarSize: 121");
        assert!(validate_lan_metadata(tampered.as_bytes(), &hash, &keys).is_none());
        assert!(
            validate_lan_metadata(
                &metadata,
                &StoreHash::new("11111111111111111111111111111111"),
                &keys
            )
            .is_none()
        );
    }

    #[test]
    fn untrusted_transport_url_cannot_redirect_a_verified_lan_request() {
        let signer = LanSigningKey {
            name: "test-lan".into(),
            key: SigningKey::from_bytes(&[7; 32]),
        };
        let keys = TrustedNarKeys::from_lines([signer.public_key()]).unwrap();
        let metadata = signer.sign(
            "/nix/store/00000000000000000000000000000000-output",
            NarHashKey::from_raw_nar(b"test"),
            120,
            &[],
        );
        let text = String::from_utf8(metadata).unwrap();
        let hostile = text
            .lines()
            .map(|line| {
                if line.starts_with("URL:") {
                    "URL: http://attacker.invalid/evil"
                } else {
                    line
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        let result = validate_lan_metadata(
            hostile.as_bytes(),
            &StoreHash::new("00000000000000000000000000000000"),
            &keys,
        )
        .unwrap();
        let result = String::from_utf8(result).unwrap();
        assert!(!result.contains("attacker.invalid"));
        assert!(result.contains("URL: nar/"));
    }
}
