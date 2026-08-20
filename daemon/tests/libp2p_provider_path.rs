//! TASK-178 PASS BAR: the daemon's libp2p SERVING/PROVIDER path serves + announces a NAR
//! that a CONSUMER discovers via kad (NOT injected) and fetches byte-identical.
//!
//! The daemon could CONSUME via libp2p (TASK-160/162, `build_libp2p_nar_source`) but could
//! not SERVE. This proves the serving half wired in TASK-178:
//!
//!   * PROVIDER `P` is stood up through the daemon LIB's [`build_libp2p_provider_source`]
//!     (the exact builder the binary's `--libp2p-provider` path calls), then its serve gate
//!     is installed (`server().serve`) and a signed [`ProviderRecord`] is announced for the
//!     seeded NAR - built by [`sign_libp2p_provider_record`], the SAME single-source-of-truth
//!     helper the binary uses (so the test cannot drift from production on the key-derivation
//!     / signing recipe).
//!   * CONSUMER `C` is built by [`build_libp2p_nar_source`] and is CONFIGURED with only the
//!     bootstrap `B` as an injected address (`provider_addrs` EMPTY) - it is NEVER told `P`'s
//!     dial address.
//!
//! Oracle: `C` (a) DISCOVERS `P`'s exact signed record via kad get_providers, (b) resolves
//! `P`'s REAL listen address via kad peer-routing (the no-injection proof: `C` was never told
//! it), and (c) its `NarSource::resolve` returns bytes BYTE-IDENTICAL to what `P` seeded.
//!
//! What this does NOT cover (honestly deferred): the binary's CLI parse (--libp2p-provider /
//! --libp2p-seed-nar / --libp2p-print-peer-address) is unit-tested in `main.rs`; the
//! multi-daemon podman e2e (two real daemon processes, one --libp2p-provider) is TASK-161.
//! This is the in-process integration proof of the serving plumbing.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use http_body_util::BodyExt;

use daemon::{
    Libp2pSourceConfig, NarHash, NarHashKey, NarKey, NarPathToken, build_libp2p_nar_source,
    build_libp2p_provider_source, sign_libp2p_provider_record,
};
use fabric_libp2p::{Libp2pFabric, MemoryNarSupplier, Multiaddr, NodeConfig};
use peer_fabric::{
    AnnounceBudget, Blake3Digest, ContentKey, DiscoveryBudget, Lookup, PeerFabric, ProviderRecord,
    ResolutionPolicy, SafetyEnvelope, ServeBudget, TransportOffer,
};

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
}

/// Bring up a bootstrap fabric on an ephemeral loopback TCP port; return it + its address.
async fn start_bootstrap(seed: u8, scope: &str) -> (Arc<Libp2pFabric>, Multiaddr) {
    let fabric = Libp2pFabric::start(NodeConfig::new([seed; 32]).with_network_scope(scope))
        .expect("bootstrap starts");
    fabric
        .handle()
        .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .await
        .expect("listen bound");
    let deadline = Instant::now() + Duration::from_secs(5);
    let addr = loop {
        if let Some(addr) = fabric.handle().listen_addrs().await.into_iter().next() {
            break addr;
        }
        assert!(
            Instant::now() < deadline,
            "bootstrap bound no address in time"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    (Arc::new(fabric), addr)
}

/// Collect a resolved `UpstreamResponse` body into bytes.
async fn body_bytes(resp: daemon::UpstreamResponse) -> Vec<u8> {
    resp.body
        .collect()
        .await
        .expect("body collects")
        .to_bytes()
        .to_vec()
}

/// TASK-231: wrap a record in a PublicationWitness for the witness-taking `announce`. The provider
/// fabric is built with the explicit AdmitAll test authority.
fn eligible(record: &peer_fabric::ProviderRecord) -> peer_fabric::PublicationWitness {
    use peer_fabric::PublicationEligibility;
    peer_fabric::AdmitAllPublication
        .authorize(record.clone())
        .expect("admit-all authorizes a test record")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn provider_serves_and_announces_a_nar_a_consumer_discovers_and_fetches_without_injection() {
    let scope = "task178-provider-path";

    let nar = b"nix-archive-1 raw NAR SERVED over the libp2p PROVIDER path (TASK-178)".to_vec();
    let content = Blake3Digest::from_raw_nar(&nar);

    let nar_hash_bytes = [0x5au8; 32];
    let nar_hash_key = NarHashKey::from_sha256_bytes(nar_hash_bytes);
    let content_key = ContentKey::derive_from_signed_nar_hash(&nar_hash_bytes);

    // ---- B: the ONLY address P and C are configured with ----
    let (bootstrap, boot_addr) = start_bootstrap(1, scope).await;
    let boot_peer = bootstrap.peer_id();

    // ---- P: the SERVING PROVIDER, stood up through the daemon lib's provider builder ----
    // Exactly what the binary's --libp2p-provider path runs: start_with_supplier + join.
    let provider_seed = [3u8; 32];
    let provider_cfg = Libp2pSourceConfig {
        identity_seed: provider_seed,
        network_scope: scope.to_string(),
        listen: Some("/ip4/127.0.0.1/tcp/0".parse().unwrap()),
        additional_listens: Vec::new(),
        external_addresses: Vec::new(),
        bootstrap: vec![(boot_peer, boot_addr.clone())],
        provider_addrs: vec![],
        discovery_budget: DiscoveryBudget::new(Duration::from_secs(10), 32),
        envelope: SafetyEnvelope::default(),
        state_dir: None,
        relay_server_enabled: true,
        kad_server: true,
        mdns_enabled: false,
        // TASK-280: not a lan-share isolation test; unconfined.
        lan_confinement: false,
    };
    let supplier = Arc::new(MemoryNarSupplier::new([nar.clone()]));
    let (provider_fabric, _p_source, _p_raw_serve, _readiness) = build_libp2p_provider_source(
        provider_cfg,
        supplier,
        Arc::new(peer_fabric::AdmitAllPublication),
    )
    .await
    .expect("provider builder starts a serving fabric joined to the DHT");

    // The provider's REAL listen address - the no-injection oracle target below. C is NEVER
    // told this; it can only learn it through the DHT.
    let provider_listen_addr = provider_fabric
        .handle()
        .listen_addrs()
        .await
        .into_iter()
        .next()
        .expect("provider bound a listen address");

    // Install the serve gate + announce the signed record (the binary's install sequence).
    let _serve = provider_fabric
        .server()
        .expect("provider fabric exposes a serve axis (start_with_supplier)")
        .serve(ServeBudget::default())
        .await
        .expect("serve gate installs");
    let sequence = provider_fabric.next_announce_sequence(&content_key);
    let relay_hints = provider_fabric
        .live_relay_hints()
        .await
        .expect("read live relay listeners before signing");
    let record: ProviderRecord = sign_libp2p_provider_record(
        provider_seed,
        &nar_hash_key,
        &nar,
        relay_hints,
        3600,
        unix_now(),
        sequence,
    );
    assert_eq!(
        record.provider,
        provider_fabric.node_id(),
        "self-serve: the record is signed by the provider's own identity"
    );
    assert_eq!(
        record.key, content_key,
        "the announced key is derived from the NarHash the consumer will derive from"
    );
    assert_eq!(
        record.content, content,
        "the record carries the raw NAR's BLAKE3"
    );
    assert!(
        matches!(
            record.offers.as_slice(),
            [TransportOffer::Libp2p { node, relay_hints }]
                if *node == record.provider && relay_hints.is_empty()
        ),
        "the production writer must publish one native Libp2p offer with empty TASK-156 hints"
    );
    provider_fabric
        .announcer()
        .expect("provider announces")
        .announce(
            &eligible(&record),
            &AnnounceBudget::new(Duration::from_secs(10), 20),
        )
        .await
        .expect("announce admitted (provider is DHT-joined)");

    // ---- C: the CONSUMER, built by the production consumer builder, told ONLY B ----
    let consumer_cfg = Libp2pSourceConfig {
        identity_seed: [4u8; 32],
        network_scope: scope.to_string(),
        listen: Some("/ip4/127.0.0.1/tcp/0".parse().unwrap()),
        additional_listens: Vec::new(),
        external_addresses: Vec::new(),
        bootstrap: vec![(boot_peer, boot_addr.clone())],
        provider_addrs: vec![], // NEVER told P's address.
        discovery_budget: DiscoveryBudget::new(Duration::from_secs(10), 32),
        envelope: SafetyEnvelope::default(),
        state_dir: None,
        relay_server_enabled: true,
        kad_server: true,
        mdns_enabled: false,
        // TASK-280: not a lan-share isolation test; unconfined.
        lan_confinement: false,
    };
    let (consumer_fabric, libp2p_source, _c_raw_serve) = build_libp2p_nar_source(consumer_cfg)
        .await
        .expect("consumer builder constructs a running libp2p NarSource");

    // ---- Readiness: C discovers P's exact signed record through kad (absorb propagation) ----
    let discovery_budget = DiscoveryBudget::new(Duration::from_secs(10), 32);
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match consumer_fabric
            .provider_directory()
            .expect("consumer directory")
            .find_providers(&content_key, &discovery_budget)
            .await
        {
            Lookup::Found(records)
                if records
                    .iter()
                    .any(|r| r.provider == provider_fabric.node_id()) =>
            {
                assert!(
                    records.contains(&record),
                    "the discovered record is P's exact signed record (kad-produced, not injected)"
                );
                break;
            }
            other => {
                assert!(
                    Instant::now() < deadline,
                    "consumer never discovered the provider through kad (last: {other:?})"
                );
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        }
    }

    // ---- No-injection oracle: C resolves P's REAL listen address via kad peer-routing ----
    let locator = consumer_fabric.node_locator().expect("consumer locator");
    let provider_listen = provider_listen_addr.to_string();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match locator
            .locate(
                &provider_fabric.node_id(),
                &ResolutionPolicy::PublicInfrastructure,
            )
            .await
        {
            Lookup::Found(dial_info)
                if dial_info
                    .locations
                    .iter()
                    .any(|loc| loc.starts_with(&provider_listen)) =>
            {
                break;
            }
            other => {
                assert!(
                    Instant::now() < deadline,
                    "consumer never resolved P's dial address via kad peer-routing \
                     (no injected address); last: {other:?}"
                );
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        }
    }

    // ---- The pass bar: C's NarSource resolves the seeded NAR byte-identically ----
    // libp2p's source keys on the signed NarHash; the upstream_hint is ignored by it.
    let nar_key = NarKey::SignedNarHash {
        hash: NarHash::new(nar_hash_key.to_string()),
        upstream_hint: NarPathToken::new("ignored-by-the-libp2p-source"),
        transport: Default::default(),
    };
    let resolved = libp2p_source
        .resolve(&nar_key, Some(nar.len() as u64))
        .await
        .expect("consumer resolves the NAR through the discovered+served provider");
    assert_eq!(resolved.status, 200, "resolved 200");
    let served = body_bytes(resolved).await;
    assert_eq!(
        served, nar,
        "the consumer served the EXACT NAR the provider seeded (gate-1 BLAKE3-verified \
         over libp2p, provider address never injected)"
    );
    assert_eq!(
        Blake3Digest::from_raw_nar(&served),
        content,
        "served bytes hash to the announced content id"
    );
}
