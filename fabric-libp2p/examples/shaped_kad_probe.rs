//! Shaped-link kad-DHT DISCOVERY probe (TASK-209, test/measurement surface only).
//!
//! TASK-206 proved a real libp2p NAR fetch is BYTE-IDENTICAL over a `tc netem`-shaped
//! `veth` pair, but drove the fetch via a DIRECT-multiaddr dial - so the DISCOVER half (kad
//! `get_providers` + peer-routing `get_closest_peers`) never crossed the shaped link; that
//! half is shown only unshaped (TASK-179 routed netns at ~0 RTT). This probe closes it: a
//! 3-node kad topology where a CONSUMER that knows ONLY the bootstrap discovers a provider
//! purely through the DHT and then fetches - with every consumer kad round-trip traversing
//! the shaped link. It is deliberately an EXAMPLE, not a `src/` module: shaping/measurement
//! machinery must stay out of the shipped daemon (`check_shaping_out_of_daemon.py` scans `src/`).
//!
//! Three modes, one process each, launched by `scripts/shaped_kad_inner.sh` into two netns
//! (bootstrap B + provider P in ns A; consumer C in ns B across the shaped veth):
//!
//!   bootstrap <listen-ip> <port> <id-seed> <peerid-file>
//!       A pure node (no supplier). Listen, publish PeerId to <peerid-file>, print READY,
//!       serve until killed. This is the ONLY address the consumer is ever told.
//!
//!   provide-dht <listen-ip> <port> <id-seed> <nar-bytes> <nar-seed> \
//!               <boot-ip> <boot-port> <boot-peerid> <ready-file>
//!       Serve one deterministic INCOMPRESSIBLE NAR, JOIN the network through B only,
//!       ANNOUNCE a signed ProviderRecord for the NAR's discovery key, write <ready-file>,
//!       serve until killed. P and B share ns A, so P's announce is unshaped; only the
//!       consumer's queries cross the shaped link.
//!
//!   fetch-dht <consumer-ip> <id-seed> <nar-bytes> <nar-seed> \
//!             <boot-ip> <boot-port> <boot-peerid> <disc-budget-secs> <outer-secs>
//!       Knowing ONLY B, JOIN through B, then DISCOVER the provider purely through the DHT:
//!       (1) kad `get_providers` for the key derived from (nar-bytes, nar-seed), then
//!       (2) kad peer-routing `get_closest_peers` (NodeLocator) to resolve the discovered
//!       provider's dial address - WITHOUT ever `add_address`-injecting P. Print a
//!       machine-parseable DISCOVERY_DONE line (outcomes + elapsed), and, if discovery
//!       succeeded, fetch the NAR over `/nar/4` and print FETCH_DONE (byte-identity +
//!       BLAKE3). AC#9: C is given NO provider addr/PeerId - the answer is Kademlia's.
//!
//! Both P and C regenerate the SAME NAR and the SAME discovery key from the SAME
//! (nar-bytes, nar-seed) - public parameters - so C knows WHAT to look for and can assert
//! byte-identity with no side channel, yet learns WHO/WHERE only from the DHT. Integer-only
//! reporting (bytes, ns) per the project no-float rule; the Python side derives rates as
//! exact rationals.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use fabric_libp2p::{
    Libp2pFabric, Libp2pNarSupplier, MemoryNarSupplier, Multiaddr, NodeConfig, PeerId,
};
use peer_fabric::{
    AnnounceBudget, Blake3Digest, ContentKey, DiscoveryBudget, Lookup, NodeId, PeerFabric,
    ProviderRecord, ResolutionPolicy, SafetyEnvelope, ServeBudget, TransportOffer, TransportTag,
    Unavailable, sign_provider_record,
};

const SCOPE: &str = "shaped209";

/// Deterministic pseudo-random bytes (splitmix64). INCOMPRESSIBLE, so the default zstd link
/// codec cannot shrink the wire volume below the NAR size and the bandwidth cap is observable
/// in the fetch throughput. Same (len, seed) -> same bytes on both ends.
fn incompressible_nar(len: usize, seed: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut x = seed ^ 0x9E37_79B9_7F4A_7C15;
    while out.len() < len {
        x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = x;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        out.extend_from_slice(&z.to_le_bytes());
    }
    out.truncate(len);
    out
}

/// Deterministic 32-byte "signed NarHash" derived from the NAR seed alone, so PROVIDER and
/// CONSUMER derive the SAME `ContentKey` without either being told it out of band. This is a
/// stand-in for the real signed NarHash; the discovery key derivation is the FROZEN recipe.
fn nar_hash_from_seed(seed: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut x = seed ^ 0xD1B5_4A32_D192_ED03;
    for chunk in out.chunks_mut(8) {
        x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = x;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        chunk.copy_from_slice(&z.to_le_bytes()[..chunk.len()]);
    }
    out
}

fn seed32(byte: u8) -> [u8; 32] {
    [byte; 32]
}

/// One-word label for a non-Found lookup arm, for the machine-parseable contract line.
fn lookup_label<T>(l: &Lookup<T>) -> &'static str {
    match l {
        Lookup::Found(_) => "Found",
        Lookup::Miss => "Miss",
        Lookup::Unavailable(Unavailable::InsufficientRouting) => "InsufficientRouting",
        Lookup::Unavailable(Unavailable::DeadlineExceeded) => "DeadlineExceeded",
        Lookup::Unavailable(Unavailable::BootstrapOutage) => "BootstrapOutage",
        Lookup::Unavailable(Unavailable::Partition) => "Partition",
        Lookup::Unavailable(Unavailable::Backend(_)) => "Backend",
    }
}

/// TASK-231: wrap a record in a PublicationWitness for the witness-taking `announce`. A test
/// fabric is a genuinely-isolated in-process network built with the explicit
/// `with_admit_all_publication()` authority, so the announcer admits and the record reaches the
/// DHT exactly as before.
fn eligible(record: &peer_fabric::ProviderRecord) -> peer_fabric::PublicationWitness {
    use peer_fabric::PublicationEligibility;
    peer_fabric::AdmitAllPublication
        .authorize(record.clone())
        .expect("admit-all authorizes a test record")
}

async fn wait_listen_addr(fabric: &Libp2pFabric) -> Multiaddr {
    for _ in 0..500 {
        if let Some(addr) = fabric.handle().listen_addrs().await.into_iter().next() {
            return addr;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("node never reported a listen address");
}

/// Join `fabric` to the network THROUGH the bootstrap peer only, then wait until its routing
/// table has at least `min_peers` entries. Adding the BOOTSTRAP address is legitimate (it is
/// the entry peer); the provider's address is what must NOT be injected. Every one of these
/// round-trips crosses the shaped link when the caller is the consumer.
///
/// Returns `true` if the routing table reached `min_peers` within `window`. On a HIGH-RTT
/// shaped link the bootstrap self-lookup can itself fail to converge in the window - that is
/// a legitimate measured outcome for the sweep, so we return `false` rather than panic and
/// let the caller decide (fatal for the provider setup, a data point for the consumer).
async fn join(
    fabric: &Libp2pFabric,
    boot_peer: PeerId,
    boot_addr: Multiaddr,
    min_peers: usize,
    window: Duration,
) -> bool {
    fabric
        .handle()
        .add_address(boot_peer, boot_addr.clone())
        .await;
    if fabric.handle().dial(boot_addr).await.is_err() {
        return false;
    }
    let _ = fabric.handle().bootstrap().await;

    let deadline = Instant::now() + window;
    loop {
        if fabric.handle().routing_peers().await >= min_peers {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn bootstrap_mode(args: &[String]) {
    let listen_ip = &args[0];
    let port: u16 = args[1].parse().expect("port");
    let id_seed: u8 = args[2].parse().expect("id-seed");
    let peerid_file = PathBuf::from(&args[3]);

    let fabric = Libp2pFabric::start(
        NodeConfig::new(seed32(id_seed))
            .with_network_scope(SCOPE)
            .with_admit_all_publication(),
    )
    .expect("bootstrap fabric starts");
    fabric
        .handle()
        .listen(
            format!("/ip4/{listen_ip}/tcp/{port}")
                .parse()
                .expect("listen multiaddr"),
        )
        .await
        .expect("listen binds");
    let addr = wait_listen_addr(&fabric).await;

    std::fs::write(&peerid_file, format!("{}\n", fabric.peer_id())).expect("write peerid file");
    println!("BOOTSTRAP_READY peerid={} addr={addr}", fabric.peer_id());
    println!("READY");
    flush();

    loop {
        tokio::time::sleep(Duration::from_secs(3600)).await;
    }
}

async fn provide_dht_mode(args: &[String]) {
    let listen_ip = &args[0];
    let port: u16 = args[1].parse().expect("port");
    let id_seed: u8 = args[2].parse().expect("id-seed");
    let nar_bytes: usize = args[3].parse().expect("nar-bytes");
    let nar_seed: u64 = args[4].parse().expect("nar-seed");
    let boot_ip = &args[5];
    let boot_port: u16 = args[6].parse().expect("boot-port");
    let boot_peer: PeerId = args[7].parse().expect("boot-peerid");
    let ready_file = PathBuf::from(&args[8]);

    let nar = incompressible_nar(nar_bytes, nar_seed);
    let content = Blake3Digest::from_raw_nar(&nar);
    let nar_hash = nar_hash_from_seed(nar_seed);
    let key = ContentKey::derive_from_signed_nar_hash(&nar_hash);

    let supplier: Arc<dyn Libp2pNarSupplier> = Arc::new(MemoryNarSupplier::new([nar]));
    let fabric = Libp2pFabric::start_with_supplier(
        NodeConfig::new(seed32(id_seed))
            .with_network_scope(SCOPE)
            .with_admit_all_publication(),
        supplier,
    )
    .expect("provider fabric starts");

    fabric
        .handle()
        .listen(
            format!("/ip4/{listen_ip}/tcp/{port}")
                .parse()
                .expect("listen multiaddr"),
        )
        .await
        .expect("listen binds");
    let listen_addr = wait_listen_addr(&fabric).await;

    // Install the serve gate so the consumer's later /nar/4 fetch is admitted.
    let _serve = fabric
        .server()
        .expect("provider fabric serves")
        .serve(ServeBudget::default())
        .await
        .expect("serve starts");

    // Join through B (unshaped: P and B share ns A) and populate the routing table.
    let boot_addr: Multiaddr = format!("/ip4/{boot_ip}/tcp/{boot_port}")
        .parse()
        .expect("boot multiaddr");
    // Provider and bootstrap share ns A (unshaped): a join failure here is a real setup fault.
    assert!(
        join(&fabric, boot_peer, boot_addr, 1, Duration::from_secs(30)).await,
        "provider failed to join the bootstrap (unshaped, ns A) - setup fault"
    );

    // Announce our OWN signed ProviderRecord for the key. The provider NodeId is the ed25519
    // verifying key of our identity seed (self-serve identity), so record.provider == node_id.
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed32(id_seed));
    let provider = NodeId::from_bytes(signing_key.verifying_key().to_bytes());
    assert_eq!(
        provider,
        fabric.node_id(),
        "libp2p identity must equal the ed25519 verifying key of the same seed"
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let record = ProviderRecord {
        key,
        content,
        provider,
        offers: vec![TransportOffer::libp2p(provider)],
        sequence: 1,
        issued_at: now,
        expiry: now + 3600,
        signature: [0u8; 64],
    };
    let signed = sign_provider_record(&signing_key, &record);
    fabric
        .announcer()
        .expect("announcer present")
        .announce(
            &eligible(&signed),
            &AnnounceBudget::new(Duration::from_secs(20), 20),
        )
        .await
        .expect("provider announce admitted");

    std::fs::write(&ready_file, "ready\n").expect("write ready file");
    println!(
        "PROVIDE_READY peerid={} node={provider:?} addr={listen_addr} content={content:?}",
        fabric.peer_id()
    );
    println!("READY");
    flush();

    loop {
        tokio::time::sleep(Duration::from_secs(3600)).await;
    }
}

async fn fetch_dht_mode(args: &[String]) {
    let consumer_ip = &args[0];
    let id_seed: u8 = args[1].parse().expect("id-seed");
    let nar_bytes: usize = args[2].parse().expect("nar-bytes");
    let nar_seed: u64 = args[3].parse().expect("nar-seed");
    let boot_ip = &args[4];
    let boot_port: u16 = args[5].parse().expect("boot-port");
    let boot_peer: PeerId = args[6].parse().expect("boot-peerid");
    let disc_budget_secs: u64 = args[7].parse().expect("disc-budget-secs");
    let outer_secs: u64 = args[8].parse().expect("outer-secs");

    // C knows only the PUBLIC parameters (nar-bytes, nar-seed) and B. It regenerates the NAR
    // to learn the content id + discovery key; it is told NOTHING about the provider.
    let expected = incompressible_nar(nar_bytes, nar_seed);
    let content = Blake3Digest::from_raw_nar(&expected);
    let nar_hash = nar_hash_from_seed(nar_seed);
    let key = ContentKey::derive_from_signed_nar_hash(&nar_hash);

    // Drive the SAME budget into the kad iterative-query timeout (TASK-210) as into the
    // application DiscoveryBudget below, so the sweep measures the REAL single-query budget
    // a shipped consumer configures — not the old hardcoded 10s that truncated TASK-209.
    let fabric = Libp2pFabric::start(
        NodeConfig::new(seed32(id_seed))
            .with_network_scope(SCOPE)
            .with_admit_all_publication()
            .with_kad_query_timeout(Duration::from_secs(disc_budget_secs)),
    )
    .expect("consumer fabric starts");
    fabric
        .handle()
        .listen(
            format!("/ip4/{consumer_ip}/tcp/0")
                .parse()
                .expect("listen multiaddr"),
        )
        .await
        .expect("listen binds");
    let _ = wait_listen_addr(&fabric).await;

    let boot_addr: Multiaddr = format!("/ip4/{boot_ip}/tcp/{boot_port}")
        .parse()
        .expect("boot multiaddr");
    // Every round-trip in this join crosses the shaped link (C is in ns B). The join itself
    // is part of what we measure: at high RTT the bootstrap self-lookup can fail to converge.
    let t_join = Instant::now();
    let joined = join(
        &fabric,
        boot_peer,
        boot_addr,
        1,
        Duration::from_secs(outer_secs),
    )
    .await;
    if !joined {
        let elapsed_ns = t_join.elapsed().as_nanos();
        println!(
            "DISCOVERY_DONE find_outcome=JoinFailed locate_outcome=NotAttempted \
             provider_matched=0 located= discovery_elapsed_ns={elapsed_ns} \
             find_attempts=0 locate_attempts=0"
        );
        flush();
        return;
    }

    // ---- Timed DHT discovery over the shaped link. Each attempt is a REAL, injection-free
    // kad query carrying the production budget; we retry within a bounded outer window to
    // absorb record propagation. The BREAKING POINT is where every attempt DeadlineExceeds. ----
    let budget = DiscoveryBudget::new(Duration::from_secs(disc_budget_secs), 32);
    let t0 = Instant::now();
    let outer_deadline = t0 + Duration::from_secs(outer_secs);

    let mut find_attempts = 0u32;
    let mut find_label;
    let mut provider_node: Option<NodeId> = None;
    loop {
        find_attempts += 1;
        let lookup = fabric
            .provider_directory()
            .expect("directory present")
            .find_providers(&key, &budget)
            .await;
        if let Lookup::Found(records) = &lookup {
            // SSOT + AC#9: every resolved record answers the queried key, and the provider
            // identity came from Kademlia, not from any input to this process.
            assert!(
                records.iter().all(|r| r.key == key),
                "every discovered record must answer the queried key"
            );
            provider_node = Some(records[0].provider);
            find_label = "Found";
            break;
        }
        find_label = lookup_label(&lookup);
        if Instant::now() >= outer_deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    let Some(provider_node) = provider_node else {
        // Discovery MISSED its budget at this RTT: report and stop (no fetch to attempt).
        let elapsed_ns = t0.elapsed().as_nanos();
        println!(
            "DISCOVERY_DONE find_outcome={find_label} locate_outcome=NotAttempted \
             provider_matched=0 located= discovery_elapsed_ns={elapsed_ns} \
             find_attempts={find_attempts} locate_attempts=0"
        );
        flush();
        return;
    };

    // ---- Resolve the discovered provider's dial address THROUGH kad peer-routing. C was
    // NEVER told P's address; the only source is the DHT/identify via B. ----
    let locator = fabric.node_locator().expect("locator present");
    let mut locate_attempts = 0u32;
    let mut locate_label;
    let mut located: Vec<String> = Vec::new();
    loop {
        locate_attempts += 1;
        let lookup = locator
            .locate(&provider_node, &ResolutionPolicy::PublicInfrastructure)
            .await;
        if let Lookup::Found(info) = &lookup {
            located = info.locations.clone();
            locate_label = "Found";
            break;
        }
        locate_label = lookup_label(&lookup);
        if Instant::now() >= outer_deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    let discovery_elapsed_ns = t0.elapsed().as_nanos();

    println!(
        "DISCOVERY_DONE find_outcome={find_label} locate_outcome={locate_label} \
         provider_matched=1 located={} discovery_elapsed_ns={discovery_elapsed_ns} \
         find_attempts={find_attempts} locate_attempts={locate_attempts}",
        located.join(",")
    );
    // AC#9 witness: the provider node the DHT produced (C never received it as an argument).
    println!("DISCOVERED_PROVIDER node={provider_node:?} via=kad_get_providers+get_closest_peers");
    flush();

    if locate_label != "Found" {
        return;
    }

    // ---- Fetch the NAR over the DHT-resolved dial address (no injected address anywhere).
    // The transport resolves P's address through the SAME shared node-locator before dialing. ----
    let envelope = SafetyEnvelope {
        dial_timeout: Duration::from_secs(30),
        body_idle_timeout: Duration::from_secs(30),
        total_timeout: Duration::from_secs(120),
    };
    let offer = TransportOffer::libp2p(provider_node);
    let transport = fabric
        .transfer(TransportTag::Libp2p)
        .expect("transport present");
    let t1 = Instant::now();
    let bytes = transport
        .fetch(&content, &offer, Some(nar_bytes as u64), &envelope)
        .await
        .expect("fetch over shaped link succeeds using DHT-resolved address");
    let fetch_elapsed_ns = t1.elapsed().as_nanos();

    let byte_identical = bytes == expected;
    let blake3_ok = Blake3Digest::from_raw_nar(&bytes) == content;
    println!(
        "FETCH_DONE bytes={} expect={} elapsed_ns={} byte_identical={} blake3_ok={}",
        bytes.len(),
        nar_bytes,
        fetch_elapsed_ns,
        if byte_identical { 1 } else { 0 },
        if blake3_ok { 1 } else { 0 },
    );
    flush();
    if !byte_identical || !blake3_ok || bytes.len() != nar_bytes {
        eprintln!("FETCH_FAIL byte-identity/blake3/size mismatch");
        std::process::exit(1);
    }
}

fn flush() {
    use std::io::Write;
    std::io::stdout().flush().ok();
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let argv: Vec<String> = std::env::args().collect();
    if argv.len() < 2 {
        eprintln!("usage: shaped_kad_probe <bootstrap|provide-dht|fetch-dht> ...");
        std::process::exit(2);
    }
    let mode = argv[1].as_str();
    let rest = &argv[2..];
    match mode {
        "bootstrap" => bootstrap_mode(rest).await,
        "provide-dht" => provide_dht_mode(rest).await,
        "fetch-dht" => fetch_dht_mode(rest).await,
        other => {
            eprintln!("unknown mode {other:?}");
            std::process::exit(2);
        }
    }
}
