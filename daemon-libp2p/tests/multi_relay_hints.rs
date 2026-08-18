//! TASK-219: production-signed relay hints close the general multi-relay NAT path.
//!
//! Topology: C knows only R1; P has no direct listener and reserves only on R2; R1 and R2 are
//! ordinary kad peers. P's shipped announce loop derives the R2 identity from its accepted live
//! circuit listener, signs it in tag 2, and C resolves R2's address through raw kad before dialing
//! P transiently through R2. No P or R2 address is ever added to either consumer.

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use daemon_core::NarHashKey;
use daemon_libp2p::{
    InitialAnnounceConfig, LanShare, Libp2pSourceConfig, announce_provider_seeds,
    build_libp2p_nar_source, build_libp2p_provider_source,
};
use fabric_libp2p::{
    CatalogNarSupplier, CatalogProbe, ConnPath, Libp2pFabric, Multiaddr, NodeConfig, PeerId,
    ProbedSource, ProbedSupply, Protocol, relay_hints_from_circuit_addresses,
};
use peer_fabric::{
    AdmitAllPublication, AnnounceBudget, Blake3Digest, Disclosed, DiscoveryBudget, Lookup,
    NarTransfer, PeerFabric, ProviderRecord, Recipient, RelayHints, SafetyEnvelope, ServeBudget,
    TransferError, TransportOffer, TransportTag,
};

struct BlockingProbe {
    content: Blake3Digest,
    bytes: Arc<Vec<u8>>,
    block: Arc<AtomicBool>,
    marker_dir: PathBuf,
    release_file: PathBuf,
}

impl CatalogProbe for BlockingProbe {
    fn probe(&self, content: &Blake3Digest) -> Option<ProbedSupply> {
        if content != &self.content {
            return None;
        }
        let source = if self.block.load(Ordering::Acquire) {
            ProbedSource::Process {
                program: PathBuf::from("sh"),
                args: vec![
                    OsString::from("-c"),
                    OsString::from(
                        "touch \"$1/started.$$\"; while [ ! -e \"$2\" ]; do sleep 0.05; done; \
                         printf '%s' \"$3\"",
                    ),
                    OsString::from("task219-blocking-supplier"),
                    self.marker_dir.as_os_str().to_owned(),
                    self.release_file.as_os_str().to_owned(),
                    OsString::from(
                        std::str::from_utf8(self.bytes.as_slice())
                            .expect("TASK-219 fixture NAR is ASCII"),
                    ),
                ],
            }
        } else {
            ProbedSource::Memory(Arc::clone(&self.bytes))
        };
        Some(ProbedSupply {
            declared_size: self.bytes.len() as u64,
            source,
        })
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
}

fn direct_tcp(address: &Multiaddr) -> bool {
    !address
        .iter()
        .any(|protocol| matches!(protocol, Protocol::P2pCircuit))
        && address
            .iter()
            .any(|protocol| matches!(protocol, Protocol::Tcp(_)))
}

async fn wait_for<T, Fut, F>(label: &str, timeout: Duration, mut probe: F) -> T
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<T>>,
{
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(value) = probe().await {
            return value;
        }
        assert!(
            Instant::now() < deadline,
            "{label} did not become true within {timeout:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn bind_router(fabric: &Libp2pFabric) -> Multiaddr {
    fabric
        .handle()
        .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .await
        .expect("router direct listen starts");
    let address = wait_for(
        "router direct listener",
        Duration::from_secs(10),
        || async {
            fabric
                .handle()
                .listen_addrs()
                .await
                .into_iter()
                .find(direct_tcp)
        },
    )
    .await;
    fabric.handle().add_external_address(address.clone()).await;
    address
}

async fn join(node: &Libp2pFabric, entry_peer: PeerId, entry_address: Multiaddr) {
    node.handle()
        .add_address(entry_peer, entry_address.clone())
        .await;
    node.handle()
        .dial(entry_address)
        .await
        .expect("entry dial starts");
    let _ = node.handle().bootstrap().await;
    wait_for(
        "joined node has a kad peer",
        Duration::from_secs(15),
        || async { (node.handle().routing_peers().await >= 1).then_some(()) },
    )
    .await;
}

fn source_config(
    seed: u8,
    scope: &str,
    listen: Option<Multiaddr>,
    bootstrap: (PeerId, Multiaddr),
) -> Libp2pSourceConfig {
    Libp2pSourceConfig {
        identity_seed: [seed; 32],
        network_scope: scope.to_string(),
        listen,
        additional_listens: Vec::new(),
        external_addresses: Vec::new(),
        bootstrap: vec![bootstrap],
        // Load-bearing no-injection boundary: neither provider nor non-bootstrap relay address.
        provider_addrs: Vec::new(),
        discovery_budget: DiscoveryBudget::new(Duration::from_secs(10), 32),
        envelope: SafetyEnvelope {
            dial_timeout: Duration::from_secs(8),
            body_idle_timeout: Duration::from_secs(8),
            total_timeout: Duration::from_secs(20),
        },
        state_dir: None,
        relay_server_enabled: true,
        kad_server: true,
    }
}

async fn discover_exact(
    consumer: &Libp2pFabric,
    expected: &ProviderRecord,
    budget: &DiscoveryBudget,
) -> ProviderRecord {
    wait_for(
        "exact signed record is discoverable",
        Duration::from_secs(25),
        || async {
            match consumer
                .provider_directory()
                .expect("consumer directory")
                .find_providers(&expected.key, budget)
                .await
            {
                Lookup::Found(records) => records.into_iter().find(|record| record == expected),
                Lookup::Miss | Lookup::Unavailable(_) => None,
            }
        },
    )
    .await
}

fn compose_circuit_from_dht_relay(
    relay_address: &Multiaddr,
    relay: PeerId,
    provider: PeerId,
) -> Multiaddr {
    let mut circuit: Multiaddr = relay_address
        .iter()
        .filter(|protocol| !matches!(protocol, Protocol::P2p(_) | Protocol::P2pCircuit))
        .collect();
    circuit.push(Protocol::P2p(relay));
    circuit.push(Protocol::P2pCircuit);
    circuit.push(Protocol::P2p(provider));
    circuit
}

/// Deterministic negative-control setup: learn R2's transport address through raw kad, compose
/// P's circuit in this test only, and open it without adding anything to kad/address config.
/// Production still has to consume the signature-bound offer below. We cannot synchronize on raw
/// P query OUTPUT: libp2p-kad's multi-source overwrite may return `[]` after that query already
/// opened P's circuit, which is the exact ambient-route ambiguity this test must reject.
async fn establish_dht_derived_ambient_relay(
    consumer: &Libp2pFabric,
    provider: PeerId,
    relay: PeerId,
) {
    let relay_address = wait_for(
        "raw kad resolves R2's direct transport address",
        Duration::from_secs(15),
        || async {
            let (addresses, _) = consumer.handle().locate_peer(relay).await.ok()?;
            addresses.into_iter().find(direct_tcp)
        },
    )
    .await;
    let circuit = compose_circuit_from_dht_relay(&relay_address, relay, provider);
    consumer
        .handle()
        .dial(circuit)
        .await
        .expect("DHT-derived ambient R2 circuit dial starts");
    wait_for(
        "actual negative-control consumer has a live ambient R2 route",
        Duration::from_secs(10),
        || async {
            consumer
                .handle()
                .connection_relay_peers(provider)
                .await
                .contains(&relay)
                .then_some(())
        },
    )
    .await;
}

fn dht_identity_queries(fabric: &Libp2pFabric) -> usize {
    fabric
        .exposure_ledger()
        .entries()
        .iter()
        .filter(|entry| entry.to == Recipient::DhtNode && entry.disclosed == Disclosed::OurNodeId)
        .count()
}

fn short_failure_envelope() -> SafetyEnvelope {
    SafetyEnvelope {
        dial_timeout: Duration::from_secs(2),
        body_idle_timeout: Duration::from_secs(2),
        total_timeout: Duration::from_secs(5),
    }
}

async fn assert_not_opened(
    transfer: &dyn NarTransfer,
    content: &Blake3Digest,
    offer: &TransportOffer,
    size: usize,
) {
    let error = transfer
        .fetch(content, offer, Some(size as u64), &short_failure_envelope())
        .await
        .expect_err("wrong/missing/dead relay route must not fetch P");
    match error {
        TransferError::Unavailable(reason) => assert!(
            reason.contains("NotOpened")
                || reason.contains("could not open a NAR stream")
                || reason.contains("dialing/opening a NAR stream"),
            "failure must be attributed before the NAR substream opened, got: {reason}"
        ),
        other => panic!("relay reachability failure must be Unavailable/NotOpened, got {other}"),
    }
}

async fn start_consumer(
    seed: u8,
    scope: &str,
    r1_peer: PeerId,
    r1_address: Multiaddr,
) -> Arc<Libp2pFabric> {
    let (consumer, _source, _raw) = build_libp2p_nar_source(source_config(
        seed,
        scope,
        Some("/ip4/127.0.0.1/tcp/0".parse().unwrap()),
        (r1_peer, r1_address),
    ))
    .await
    .expect("production consumer builder joins through R1 only");
    consumer
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn production_signed_hint_resolves_unknown_r2_and_is_load_bearing() {
    let _ = tracing_subscriber::fmt::try_init();
    let scope = "task219-general-multi-relay";

    // R1 is C's ONLY configured entry. R2 is independently addressable and joins R1 through kad.
    let r1 = Libp2pFabric::start(
        NodeConfig::new([61u8; 32])
            .with_network_scope(scope)
            .with_admit_all_publication(),
    )
    .expect("R1 starts");
    let r1_address = bind_router(&r1).await;
    let r1_peer = r1.peer_id();

    let r2 = Libp2pFabric::start(
        NodeConfig::new([62u8; 32])
            .with_network_scope(scope)
            .with_admit_all_publication(),
    )
    .expect("R2 starts");
    let r2_address = bind_router(&r2).await;
    let r2_peer = r2.peer_id();
    let r2_node = r2.node_id();
    join(&r2, r1_peer, r1_address.clone()).await;
    wait_for(
        "R1 sees another kad peer",
        Duration::from_secs(15),
        || async { (r1.handle().routing_peers().await >= 1).then_some(()) },
    )
    .await;

    // P is circuit-only: no direct listener exists for a loopback consumer to accidentally use.
    // Its one listener requests a reservation on R2. Its ordinary DHT entry is R1 so the shared
    // builder does not race a bare R2 bootstrap dial against the relay-client reservation dial.
    // This keeps the axes honest: P reserves ONLY on R2 while publishing through the DHT normally.
    let nar = b"nix-archive-1 TASK-219 exact NAR through a relay unknown to C".to_vec();
    let nar_hash = NarHashKey::from_raw_nar(&nar);
    let content = Blake3Digest::from_raw_nar(&nar);
    let block_supply = Arc::new(AtomicBool::new(false));
    let fixture_dir = std::env::temp_dir().join(format!(
        "nix-p2p-task219-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos()
    ));
    let marker_dir = fixture_dir.join("started");
    let release_file = fixture_dir.join("release");
    std::fs::create_dir_all(&marker_dir).expect("create blocking-supplier marker directory");
    let supplier = CatalogNarSupplier::new(
        BlockingProbe {
            content,
            bytes: Arc::new(nar.clone()),
            block: Arc::clone(&block_supply),
            marker_dir: marker_dir.clone(),
            release_file: release_file.clone(),
        },
        "unused-regular-file-helper",
    );
    let p_seed = 63u8;
    let circuit_listen = r2_address
        .clone()
        .with(Protocol::P2p(r2_peer))
        .with(Protocol::P2pCircuit);
    let p_cfg = source_config(
        p_seed,
        scope,
        Some(circuit_listen.clone()),
        (r1_peer, r1_address.clone()),
    );
    let (provider, _p_source, _p_raw, readiness) =
        build_libp2p_provider_source(p_cfg, Arc::new(supplier), Arc::new(AdmitAllPublication))
            .await
            .expect("production provider builder starts circuit-only P");
    let requested = relay_hints_from_circuit_addresses(provider.node_id(), &[circuit_listen])
        .expect("configured R2 circuit is representable");
    let live = provider
        .wait_for_live_relay_hints(requested, Duration::from_secs(20))
        .await
        .expect("R2 reservation becomes an accepted live listener before announce");
    assert_eq!(live.as_slice(), &[r2_node]);
    assert!(
        provider
            .handle()
            .listen_addrs()
            .await
            .iter()
            .all(|address| !direct_tcp(address)),
        "P must expose no direct TCP listener; otherwise loopback can bypass relay carriage"
    );
    let _serve = provider
        .server()
        .expect("P server axis")
        .serve(ServeBudget::default())
        .await
        .expect("P serve gate starts");

    // The shipped initial-batch door crosses its private readiness token and captures one live
    // listener snapshot immediately before signing.
    let announce_budget = AnnounceBudget::new(Duration::from_secs(10), 20);
    let record = announce_provider_seeds(
        &provider,
        &readiness,
        InitialAnnounceConfig::new([p_seed; 32], 3600, unix_now(), &announce_budget),
        &[(nar_hash, nar.clone())],
        LanShare::operator_assembled(),
    )
    .await
    .expect("production announce signs and publishes the live R2 hint")
    .into_iter()
    .next()
    .expect("one record");
    let production_offer = match &record.offers[..] {
        [TransportOffer::Libp2p { node, relay_hints }] => {
            assert_eq!(*node, provider.node_id());
            assert_eq!(relay_hints.as_slice(), &[r2_node]);
            record.offers[0]
        }
        offers => panic!("expected exactly one native libp2p offer, got {offers:?}"),
    };

    let budget = DiscoveryBudget::new(Duration::from_secs(10), 32);

    // Independent C2 arm: two signed hints, R1 dead for P and R2 live. Both raw-kad lookups occur,
    // yet the bounded transient dial reaches P through R2 and returns exact bytes.
    let two_hint_consumer = start_consumer(64, scope, r1_peer, r1_address.clone()).await;
    let discovered = discover_exact(&two_hint_consumer, &record, &budget).await;
    assert_eq!(
        discovered, record,
        "exact signed record survives DHT storage"
    );
    let mut two_nodes = [r1.node_id(), r2_node];
    two_nodes.sort();
    let two_hint_offer = TransportOffer::Libp2p {
        node: provider.node_id(),
        relay_hints: RelayHints::try_from(two_nodes).expect("two canonical strict hints"),
    };
    let before = dht_identity_queries(&two_hint_consumer);
    let two_hint_bytes = two_hint_consumer
        .transfer(TransportTag::Libp2p)
        .expect("native transport")
        .fetch(
            &content,
            &two_hint_offer,
            Some(nar.len() as u64),
            &SafetyEnvelope::default(),
        )
        .await
        .expect("one dead + one live signed hint reaches P through R2");
    assert_eq!(two_hint_bytes, nar);
    assert_eq!(
        dht_identity_queries(&two_hint_consumer) - before,
        3,
        "one provider query plus exactly two bounded relay-hint queries"
    );
    assert_eq!(
        two_hint_consumer
            .handle()
            .connection_path(provider.peer_id())
            .await,
        ConnPath::Relay,
        "circuit-only P must actually be reached over relay carriage"
    );
    drop(two_hint_consumer);

    // Main C knows only R1. Discovery remains healthy while deleting R2 or replacing it with R1
    // makes reachability fail before a substream opens. Then the untouched production offer works.
    let consumer = start_consumer(65, scope, r1_peer, r1_address.clone()).await;
    discover_exact(&consumer, &record, &budget).await;
    let transport = consumer
        .transfer(TransportTag::Libp2p)
        .expect("native libp2p transport");

    discover_exact(&consumer, &record, &budget).await;
    establish_dht_derived_ambient_relay(&consumer, provider.peer_id(), r2_peer).await;
    let no_hint = TransportOffer::Libp2p {
        node: provider.node_id(),
        relay_hints: RelayHints::empty(),
    };
    assert_not_opened(transport, &content, &no_hint, nar.len()).await;
    assert!(
        consumer
            .handle()
            .connection_relay_peers(provider.peer_id())
            .await
            .contains(&r2_peer),
        "empty offer must refuse to USE ambient R2 without closing a concurrent route"
    );

    discover_exact(&consumer, &record, &budget).await;
    establish_dht_derived_ambient_relay(&consumer, provider.peer_id(), r2_peer).await;
    let wrong_r1 = TransportOffer::Libp2p {
        node: provider.node_id(),
        relay_hints: RelayHints::try_from([r1.node_id()]).expect("R1 identity is strict"),
    };
    assert_not_opened(transport, &content, &wrong_r1, nar.len()).await;
    assert!(
        consumer
            .handle()
            .connection_relay_peers(provider.peer_id())
            .await
            .contains(&r2_peer),
        "wrong-R1 offer must leave ambient R2 live while refusing to use it"
    );

    discover_exact(&consumer, &record, &budget).await;
    let before = dht_identity_queries(&consumer);
    let fetched = transport
        .fetch(
            &content,
            &production_offer,
            Some(nar.len() as u64),
            &SafetyEnvelope::default(),
        )
        .await
        .expect("C resolves signed R2 identity through raw kad and fetches through R2");
    assert_eq!(fetched, nar, "relay fetch returns the exact NAR");
    assert_eq!(Blake3Digest::from_raw_nar(&fetched), content);
    assert_eq!(
        dht_identity_queries(&consumer) - before,
        2,
        "one provider query plus exactly one R2 raw-kad query"
    );
    assert_eq!(
        consumer.handle().connection_path(provider.peer_id()).await,
        ConnPath::Relay,
        "P has no direct listener, so success must be relay carriage through R2"
    );

    // Same-route multiplexing bite: two substitutions overlap on the same authorized R2
    // connection and both complete. This catches accidental peer-wide teardown/serialization
    // independently of the conflicting-route authority bite below.
    block_supply.store(true, Ordering::Release);
    {
        let a_consumer = Arc::clone(&consumer);
        let a_offer = production_offer;
        let a_content = content;
        let nar_len = nar.len();
        let fetch_a = tokio::spawn(async move {
            a_consumer
                .transfer(TransportTag::Libp2p)
                .expect("same-R2 A native transport")
                .fetch(
                    &a_content,
                    &a_offer,
                    Some(nar_len as u64),
                    &SafetyEnvelope::default(),
                )
                .await
        });
        wait_for(
            "same-R2 fetch A reaches blocking supplier",
            Duration::from_secs(10),
            || async {
                (std::fs::read_dir(&marker_dir)
                    .ok()
                    .map(|entries| entries.count())
                    .unwrap_or(0)
                    >= 1)
                    .then_some(())
            },
        )
        .await;

        let b_consumer = Arc::clone(&consumer);
        let b_offer = production_offer;
        let b_content = content;
        let fetch_b = tokio::spawn(async move {
            b_consumer
                .transfer(TransportTag::Libp2p)
                .expect("same-R2 B native transport")
                .fetch(
                    &b_content,
                    &b_offer,
                    Some(nar_len as u64),
                    &SafetyEnvelope::default(),
                )
                .await
        });
        wait_for(
            "same-R2 fetch B overlaps at blocking supplier",
            Duration::from_secs(10),
            || async {
                (std::fs::read_dir(&marker_dir)
                    .ok()
                    .map(|entries| entries.count())
                    .unwrap_or(0)
                    >= 2)
                    .then_some(())
            },
        )
        .await;
        std::fs::write(&release_file, b"release").expect("release same-R2 productions");
        let (a_result, b_result) = tokio::join!(fetch_a, fetch_b);
        assert_eq!(
            a_result
                .expect("same-R2 A task does not panic")
                .expect("same-R2 A survives overlap"),
            nar
        );
        assert_eq!(
            b_result
                .expect("same-R2 B task does not panic")
                .expect("same-R2 B survives overlap"),
            nar
        );
    }
    block_supply.store(false, Ordering::Release);
    for entry in std::fs::read_dir(&marker_dir).expect("read same-R2 markers") {
        std::fs::remove_file(entry.expect("marker entry").path()).expect("remove same-R2 marker");
    }
    std::fs::remove_file(&release_file).expect("reset blocking supplier release");

    // Add an accepted R1 reservation only AFTER the production R2-only record was signed. This
    // gives one provider conflicting live relay routes without changing the record under test.
    // A is authorized only for R2; while it is open, B is authorized only for R1. The exact
    // ConnectionId stream API must keep those authorities separate.
    let r1_node = r1.node_id();
    let r1_circuit_listen = r1_address
        .clone()
        .with(Protocol::P2p(r1_peer))
        .with(Protocol::P2pCircuit);
    provider
        .handle()
        .listen(r1_circuit_listen)
        .await
        .expect("provider accepts a second reservation through R1");
    wait_for(
        "provider exposes both accepted relay listeners",
        Duration::from_secs(10),
        || async {
            let hints = provider.live_relay_hints().await.ok()?;
            (hints.as_slice().contains(&r1_node) && hints.as_slice().contains(&r2_node))
                .then_some(())
        },
    )
    .await;
    let r1_only_offer = TransportOffer::Libp2p {
        node: provider.node_id(),
        relay_hints: RelayHints::try_from([r1_node]).expect("R1 identity is strict"),
    };

    block_supply.store(true, Ordering::Release);
    let a_consumer = Arc::clone(&consumer);
    let a_offer = production_offer;
    let a_content = content;
    let nar_len = nar.len();
    let fetch_a = tokio::spawn(async move {
        a_consumer
            .transfer(TransportTag::Libp2p)
            .expect("A native transport")
            .fetch(
                &a_content,
                &a_offer,
                Some(nar_len as u64),
                &SafetyEnvelope::default(),
            )
            .await
    });
    wait_for(
        "fetch A reaches blocking supplier",
        Duration::from_secs(10),
        || async {
            (std::fs::read_dir(&marker_dir)
                .ok()
                .map(|entries| entries.count())
                .unwrap_or(0)
                >= 1)
                .then_some(())
        },
    )
    .await;

    let b_consumer = Arc::clone(&consumer);
    let b_offer = r1_only_offer;
    let b_content = content;
    let fetch_b = tokio::spawn(async move {
        b_consumer
            .transfer(TransportTag::Libp2p)
            .expect("B native transport")
            .fetch(
                &b_content,
                &b_offer,
                Some(nar_len as u64),
                &SafetyEnvelope::default(),
            )
            .await
    });
    wait_for(
        "R1-authorized fetch B overlaps R2-authorized fetch A at blocking supplier",
        Duration::from_secs(10),
        || async {
            (std::fs::read_dir(&marker_dir)
                .ok()
                .map(|entries| entries.count())
                .unwrap_or(0)
                >= 2)
                .then_some(())
        },
    )
    .await;
    let overlapping_routes = consumer
        .handle()
        .connection_relay_peers(provider.peer_id())
        .await;
    assert!(
        overlapping_routes.contains(&r1_peer) && overlapping_routes.contains(&r2_peer),
        "overlapping exact requests must keep conflicting R1 and R2 routes live: {overlapping_routes:?}"
    );

    // Sever only R2 while both bodies are blocked. A must lose its exact R2 stream; B must remain
    // usable on exact R1. A peer-wide/random stream selection makes this outcome unstable.
    drop(r2);
    wait_for(
        "consumer retires R2 but keeps R1",
        Duration::from_secs(15),
        || async {
            let routes = consumer
                .handle()
                .connection_relay_peers(provider.peer_id())
                .await;
            (!routes.contains(&r2_peer) && routes.contains(&r1_peer)).then_some(())
        },
    )
    .await;
    std::fs::write(&release_file, b"release").expect("release both blocked NAR productions");
    let (a_result, b_result) = tokio::join!(fetch_a, fetch_b);
    assert!(
        a_result.expect("A fetch task does not panic").is_err(),
        "R2-authorized A must fail when its exact relay route is severed"
    );
    assert_eq!(
        b_result
            .expect("B fetch task does not panic")
            .expect("R1-authorized B survives R2 loss"),
        nar,
        "B returns the exact NAR over its distinct authorized R1 connection"
    );
    block_supply.store(false, Ordering::Release);

    // The warm consumer still has R1, but the exact production offer authorizes only dead R2.
    // Record discovery remains healthy; route resolution may fail before dialing (the signed R2
    // identity is now absent) or at exact stream-open, but both are explicitly attributed as
    // NotOpened and neither may fall back to live R1.
    discover_exact(&consumer, &record, &budget).await;
    assert_not_opened(transport, &content, &production_offer, nar.len()).await;
    assert!(
        consumer
            .handle()
            .connection_relay_peers(provider.peer_id())
            .await
            .contains(&r1_peer),
        "the unauthorized R1 route remains live; failure comes from exact authority, not teardown"
    );
    std::fs::remove_dir_all(&fixture_dir).expect("remove blocking-supplier fixture directory");
}
