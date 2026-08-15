//! MINIMAL 2-node discovery end-to-end (task-40), driven through the PUBLIC
//! `daemon` API - the seam->swarm wiring that proves S6 is reachable.
//!
//! Two nodes in THIS process, NO cache.nixos.org:
//!   * node B holds a NAR: a real iroh-blobs PROVIDER seeds it (addressed by
//!     `BLAKE3(RawNarV1)`), and a task-50 `AvailabilityIndex` registers the same
//!     NarHash -> a materialised store path, so B can ANSWER "do you hold X?".
//!   * node A resolves the signed NarHash to B's COMPLETE offer via the real
//!     `HoldQuery`/`HoldResponse` envelope (answered from B's index), then fetches
//!     the bytes over a REAL iroh QUIC connection and passes the NarHash gate.
//!
//! The query TOPOLOGY is minimal (an in-process rendezvous keyed by `NodeId`) but
//! the query WIRE and the FETCH are real: the envelope genuinely round-trips the
//! frozen codec, and the bytes cross a real iroh connection. The DHT that would
//! REPLACE the configured peer set is task-47.
//!
//! Nothing here names the generated fixture tree (the source guard forbids it):
//! the NAR is synthesised in memory and the store path is a temp file.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use daemon::{
    AvailabilityIndex, Blake3Digest, DirectDiscovery, FallbackNarSource, InProcessPeerQuery,
    IrohClientNode, IrohProvider, IrohProviderNode, MemoryNarDumper, NarHash, NarHashKey, NarKey,
    NarPathToken, NarSource, NullAnnounce, NullStore, SourceError, StorePath, TransportNarSource,
    TransportRegistry, UpstreamResponse, verify_blake3,
};
use http::HeaderMap;
use http_body_util::{BodyExt, Full};
use sha2::{Digest, Sha256};

// ---- a real (uncompressed) nix-archive-1 NAR, synthesised in memory ----------

fn nar_str(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(bytes);
    let pad = (8 - (bytes.len() % 8)) % 8;
    out.extend(std::iter::repeat_n(0u8, pad));
}

/// A valid raw NAR for a single regular file whose contents are `contents`.
fn synth_raw_nar(contents: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    nar_str(&mut out, b"nix-archive-1");
    nar_str(&mut out, b"(");
    nar_str(&mut out, b"type");
    nar_str(&mut out, b"regular");
    nar_str(&mut out, b"contents");
    nar_str(&mut out, contents);
    nar_str(&mut out, b")");
    out
}

/// The signed NarHash the narinfo would carry: sha256 over the raw NAR bytes,
/// wrapped as the canonical `NarHashKey`. This is the p2p lookup key - a DIFFERENT
/// identity from the `BLAKE3` the transport addresses (the two-gate split).
fn nar_hash_key(nar: &[u8]) -> NarHashKey {
    let digest: [u8; 32] = Sha256::digest(nar).into();
    NarHashKey::from_sha256_bytes(digest)
}

// ---- a fixed dumper + a self-cleaning temp store path ------------------------

struct TempDir {
    path: PathBuf,
}
impl TempDir {
    fn new(label: &str) -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "nixp2p-disco-e2e-{label}-{}-{n}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        TempDir { path }
    }
    fn store_file(&self, name: &str) -> StorePath {
        let p = self.path.join(name);
        std::fs::write(&p, b"materialised store path").expect("write store file");
        StorePath::new(p)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Build node B: a live iroh provider serving `nar`, plus an availability index
/// (using B's real node id) that registers `key -> a materialised store path` and
/// dumps `nar`. Returns (provider, index, temp-dir-guard).
async fn spawn_holder(
    nar: &[u8],
    key: NarHashKey,
) -> (IrohProviderNode, Arc<AvailabilityIndex>, TempDir) {
    let provider = IrohProviderNode::spawn().await.expect("provider binds");
    let content = provider.seed(nar).await.expect("seed the raw NAR");
    assert_eq!(
        content,
        Blake3Digest::from_raw_nar(nar),
        "the iroh-blobs blob hash IS our frozen Blake3Digest"
    );

    let dir = TempDir::new("holder");
    let store_path = dir.store_file("nar");
    let index = AvailabilityIndex::open(
        provider.node_id().unwrap(),
        Arc::new(MemoryNarDumper::new(nar.to_vec())),
        Arc::new(NullStore),
        Arc::new(NullAnnounce),
    )
    .expect("open index");
    index
        .register(key, store_path)
        .expect("register the holding");
    (provider, Arc::new(index), dir)
}

/// Build node A's p2p source: an iroh client wired to `provider`'s address (the
/// NodeId->addr resolution a real rendezvous would do; wave-2a uses the task-39
/// address book, task-47 makes it dynamic) registered as the fetch transport, plus
/// a `DirectDiscovery` over the in-process query rendezvous that reaches B's index.
async fn spawn_seeker(
    provider: &IrohProvider,
    index: Arc<AvailabilityIndex>,
) -> (TransportNarSource, IrohClientNode) {
    // The fetch transport: an iroh client that knows how to dial B directly.
    let client = IrohClientNode::spawn().await.expect("client binds");
    client.add_peer(&provider.addr().await.expect("provider addr"));
    let mut registry = TransportRegistry::new();
    registry.register(Box::new(client.transport_handle()));

    // The query rendezvous: A asks B (by NodeId) and B answers from its real index.
    let mut rendezvous = InProcessPeerQuery::new();
    rendezvous.add_index(provider.node_id().unwrap(), index);
    let discovery = DirectDiscovery::new(vec![provider.node_id().unwrap()], Arc::new(rendezvous));

    (
        TransportNarSource::new(registry, Arc::new(discovery)),
        client,
    )
}

async fn collect(resp: UpstreamResponse) -> Vec<u8> {
    resp.body.collect().await.expect("body").to_bytes().to_vec()
}

// ---- AC#1: A resolves a fixture NarHash to B and fetches over real iroh -------

#[tokio::test]
async fn node_a_resolves_and_fetches_from_node_b_over_real_iroh() {
    let nar = synth_raw_nar(b"AC#1: the NAR node B holds and A resolves+fetches");
    let key = nar_hash_key(&nar);

    let (provider, index, _dir) = spawn_holder(&nar, key).await;
    let (source, client) = spawn_seeker(&provider, index).await;

    // The seam key the serving layer would build from the narinfo: the SIGNED
    // NarHash (what discovery resolves on) plus the URL token a p2p source ignores.
    let seam_key = NarKey::SignedNarHash {
        hash: NarHash::new(key.to_string()),
        upstream_hint: NarPathToken::new("nar/1irrelevant.nar.xz"),
        transport: Default::default(),
    };

    // resolve: discovery (real HoldQuery envelope, answered by B's index) -> claim
    // -> fetch_via_offers -> a REAL iroh QUIC fetch. NO upstream involved.
    let resp = source
        .resolve(&seam_key, Some(nar.len() as u64))
        .await
        .expect("A resolves the signed NarHash to B and fetches it over iroh");
    assert_eq!(resp.status, 200);
    let got = collect(resp).await;

    // Byte-identical to what B holds, and gate 1 (BLAKE3) holds on the output.
    assert_eq!(got, nar, "the resolved NAR is byte-identical to B's NAR");
    assert!(
        verify_blake3(&Blake3Digest::from_raw_nar(&nar), &got).is_ok(),
        "gate 1 (transport BLAKE3) holds on the fetched bytes"
    );
    // Gate 2 (Nix's trust anchor): sha256(bytes) == the signed NarHash we resolved.
    assert_eq!(
        nar_hash_key(&got),
        key,
        "gate 2 (sha256 == NarHash) holds - what we fetched is what we asked for"
    );

    client.shutdown().await.unwrap();
    provider.shutdown().await.unwrap();
}

// ---- AC#2: a NarHash NO peer holds misses FAST over the real stack, then the
// FallbackNarSource serves it from upstream (S2 preserved) --------------------

/// The upstream secondary (stands in for cache.nixos.org): always serves `body`.
struct StubUpstream {
    body: Vec<u8>,
}
#[async_trait::async_trait]
impl NarSource for StubUpstream {
    async fn resolve(
        &self,
        _key: &NarKey,
        _expected_size: Option<u64>,
    ) -> Result<UpstreamResponse, SourceError> {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::CONTENT_LENGTH, self.body.len().into());
        Ok(UpstreamResponse {
            status: 200,
            headers,
            body: Full::new(bytes::Bytes::from(self.body.clone()))
                .map_err(|never| match never {})
                .boxed(),
        })
    }
}

#[tokio::test]
async fn an_unheld_nar_hash_misses_fast_then_falls_back_to_upstream() {
    // B holds `held`, but A asks for a DIFFERENT NAR nobody holds.
    let held = synth_raw_nar(b"AC#2: the NAR B actually holds");
    let held_key = nar_hash_key(&held);
    let wanted = synth_raw_nar(b"AC#2: a NAR NO peer holds");
    let wanted_key = nar_hash_key(&wanted);
    assert_ne!(held_key, wanted_key);

    let (provider, index, _dir) = spawn_holder(&held, held_key).await;
    let (p2p_source, client) = spawn_seeker(&provider, index).await;

    let seam_key = NarKey::SignedNarHash {
        hash: NarHash::new(wanted_key.to_string()),
        upstream_hint: NarPathToken::new("nar/1wanted.nar.xz"),
        transport: Default::default(),
    };

    // The p2p source alone: a MISS, and it comes back FAST (the real HoldQuery is
    // answered Absent immediately; the point is it does not hang the build path).
    let started = Instant::now();
    let miss = p2p_source.resolve(&seam_key, None).await;
    let elapsed = started.elapsed();
    assert!(
        matches!(miss, Err(SourceError::Unreachable(_))),
        "an unheld NarHash must be a clean p2p miss (Unreachable)"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "the miss must be bounded, took {elapsed:?}"
    );

    // Composed with upstream: the same miss now serves from the CDN secondary.
    let upstream_bytes = b"served by upstream after the p2p miss (S2)".to_vec();
    let fallback = FallbackNarSource::new(
        Arc::new(p2p_source),
        Arc::new(StubUpstream {
            body: upstream_bytes.clone(),
        }),
    );
    let resp = fallback
        .resolve(&seam_key, None)
        .await
        .expect("the bounded miss falls back and the upstream serves");
    assert_eq!(
        collect(resp).await,
        upstream_bytes,
        "S2 fallback served the NAR"
    );

    client.shutdown().await.unwrap();
    provider.shutdown().await.unwrap();
}
