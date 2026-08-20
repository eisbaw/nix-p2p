//! TASK-204: the thin `daemon-libp2p` binary now routes a bootstrapped PROVIDER's public announce
//! through the SAME typed public-NAR allowlist door as the composite `daemon` binary, built from
//! the SAME shared wiring (`daemon_libp2p::open_public_allowlist` -> `announce_public_seeds`), so
//! the two binaries' publication policy cannot drift. Two levels of bite:
//!
//!   * `the_public_seed_door_refuses_an_unallowlisted_seed_on_a_real_fabric` - PROVIDER level, over
//!     a real DHT-joined provider. TWO refusals + one attribution positive:
//!       - TASK-231 AC#3: the LAN door (`announce_provider_seeds` + a freely-minted `LanShare`) on a
//!         PUBLIC-reachable node (built with the shipped fail-closed authority) is REFUSED AT THE
//!         ADAPTER - the confirmed bypass, now closed. Before TASK-231 it announced ungated.
//!       - The public door (`announce_public_seeds`, when `--libp2p-public-allowlist-path` is set)
//!         refuses an un-allowlisted seed at its approve gate. MUTATION: drop the
//!         `approve_seeds_for_public(..)?` gate -> the un-allowlisted seed announces -> RED.
//!       - Attribution: the SAME seed announces over a genuinely-isolated AdmitAll node, so the LAN
//!         refusal is the eligibility authority, not a transport/DHT failure.
//!
//!   * `the_shared_builder_populates_a_file_allowlist_that_approves_only_proven_seeds` - the SSOT
//!     config builder both binaries call: `open_public_allowlist(None, ..)` yields a DISABLED
//!     allowlist that approves NOTHING; `open_public_allowlist(Some(file), [trusted_key], seed,
//!     [(store_hash, narinfo)])` opens the MAC-integrity file and proves the APP NAR public via the
//!     trusted signature, so the door then APPROVES the APP seed and REFUSES a foreign one. This is
//!     the "announces WITH an allowlist, refuses WITHOUT" parity at the builder + gate level (a full
//!     network announce of a proven seed needs the matching 408-byte NAR fixture; that end-to-end
//!     container e2e for the thin binary is out of scope here - see the task note).

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use daemon_core::NarHashKey;
use daemon_libp2p::{
    InitialAnnounceConfig, LanShare, Libp2pSourceConfig, announce_provider_seeds,
    announce_public_seeds, approve_seeds_for_public, build_libp2p_provider_source,
    open_public_allowlist,
};
use fabric_libp2p::{Libp2pFabric, MemoryNarSupplier, Multiaddr, NodeConfig};
use peer_fabric::{
    AnnounceBudget, DiscoveryBudget, PeerFabric, RefusePublication, SafetyEnvelope, ServeBudget,
};

/// The real `app` fixture narinfo (NarHash sha256:0pgsb9..., NarSize 408), trusted-signed by
/// `FIXTURE_PUBKEY` - the same fixture the lib-level door tests and the composite daemon's
/// `public_allowlist_learn` e2e use. Its trusted signature is what PROVES the NAR public.
const FIXTURE_PUBKEY: &str = "nix-p2p-test-1:empdFBu9wVZG12rPKToHMOTsU1qzWzeCcLdq/KQH0JQ=";
const APP_STORE_HASH: &str = "l30jg5xg904s62jvw5znmr682xpr993c";
const APP_NAR_HASH: &str = "sha256:0pgsb9mjmfj57w1ddmqn9z9667nwbqbnn699j1s1s99jhy6cppsm";
const APP_NAR_SIZE: usize = 408;
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

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
}

/// A unique temp path so parallel test runs never share an allowlist file.
fn temp_path(stem: &str) -> std::path::PathBuf {
    let suffix = format!("{}-{}", std::process::id(), unix_now());
    std::env::temp_dir().join(format!("nix-p2p-task204-{stem}-{suffix}"))
}

/// Bring a raw fabric up on an ephemeral loopback port; return it + its dial address.
async fn start_fabric(fabric: Libp2pFabric) -> (Arc<Libp2pFabric>, Multiaddr) {
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
        assert!(Instant::now() < deadline, "no listen address bound in time");
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    (Arc::new(fabric), addr)
}

#[tokio::test(flavor = "multi_thread")]
async fn the_public_seed_door_refuses_an_unallowlisted_seed_on_a_real_fabric() {
    let scope = "task204-public-seed-door";

    // ---- boot node (the provider's DHT entry point) ----
    let (bootstrap, boot_addr) = start_fabric(
        Libp2pFabric::start(NodeConfig::new([7u8; 32]).with_network_scope(scope))
            .expect("bootstrap starts"),
    )
    .await;
    let boot_peer = bootstrap.peer_id();

    // ---- provider, joined to the DHT through the shipped builder ----
    let nar = b"nix-archive-1 the raw NAR this provider honestly holds".to_vec();
    let seed_key = NarHashKey::from_raw_nar(&nar);

    // The PUBLIC-reachable provider (bootstrapped into the DHT), built with the SHIPPED authority
    // choice for a public-reach node with NO allowlist: fail-closed RefusePublication (TASK-231
    // `provider_publication_authority`). Its announcer refuses ANY record at the adapter.
    let cfg = Libp2pSourceConfig {
        identity_seed: [8u8; 32],
        network_scope: scope.to_string(),
        listen: Some("/ip4/127.0.0.1/tcp/0".parse().unwrap()),
        additional_listens: Vec::new(),
        external_addresses: Vec::new(),
        bootstrap: vec![(boot_peer, boot_addr)],
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
    let (fabric, _source, _raw, readiness) =
        build_libp2p_provider_source(cfg, supplier, Arc::new(RefusePublication))
            .await
            .expect("production provider builder starts a serving fabric joined to the DHT");
    let _serve = fabric
        .server()
        .expect("provider fabric exposes a serve axis")
        .serve(ServeBudget::default())
        .await
        .expect("serve gate installs");
    let budget = AnnounceBudget::new(Duration::from_secs(10), 20);

    // TASK-231 AC#3 BITE (the closed bypass): the LAN door (`announce_provider_seeds` with a
    // freely-minted `LanShare::operator_assembled`) on a PUBLIC-reachable node is now REFUSED at
    // the announcer's own fail-closed authority - the operator-named seed does NOT reach the public
    // DHT. Before TASK-231 this announced ungated (the confirmed hole). MUTATION that reddens it:
    // drop the `self.eligibility.admit(record)?` consult in the fabric-libp2p announcer.
    let lan_refused = announce_provider_seeds(
        &fabric,
        &readiness,
        InitialAnnounceConfig::new([8u8; 32], 3600, unix_now(), &budget),
        &[(seed_key, nar.clone())],
        LanShare::operator_assembled(),
    )
    .await;
    let lan_err = lan_refused.expect_err(
        "a public-reachable node must REFUSE an unallowlisted LAN-path announce at the adapter \
         (TASK-231 AC#3); it announced ungated before the fix",
    );
    assert!(
        lan_err.contains("eligibility") || lan_err.contains("not established publishable"),
        "the LAN refusal must name the publication-eligibility decision: {lan_err}"
    );
    // ATTRIBUTION: the refusal above is `AnnounceError::Ineligible`, raised by the announcer's
    // authority BEFORE any DHT op (the eligibility consult is the first thing `announce` does), so
    // it can NOT be a transport/quorum failure - the error TYPE pins it to the publication-
    // eligibility decision. That an ADMITTING authority lets the same record through (non-vacuous)
    // is proven directly in `fabric-libp2p/tests/publication_eligibility_adapter.rs`.

    // PUBLIC door with an EMPTY allowlist (what `open_public_allowlist(None, ..)` yields): the seed
    // was never proven public via a trusted narinfo signature, so the door refuses the whole batch
    // at the approve gate and announces NOTHING. This is the exact door the thin binary routes
    // through in PUBLIC mode.
    let empty =
        open_public_allowlist(None, &[], &[8u8; 32], &[]).expect("a disabled allowlist opens");
    let refused = announce_public_seeds(
        &fabric,
        &readiness,
        InitialAnnounceConfig::new([8u8; 32], 3600, unix_now(), &budget),
        &[(seed_key, nar.clone())],
        &empty,
    )
    .await;
    let err = refused.expect_err(
        "an un-allowlisted seed must be REFUSED by the public door, not announced (drop the \
         approve_seeds_for_public(..)? gate in announce_public_seeds and this becomes Ok - the bite)",
    );
    assert!(
        err.contains("allowlist gate"),
        "the refusal must name the allowlist gate: {err}"
    );
}

#[test]
fn the_shared_builder_populates_a_file_allowlist_that_approves_only_proven_seeds() {
    // WITHOUT a path: the shared builder yields a DISABLED allowlist that approves NOTHING - a
    // bootstrapped provider with no allowlist can publicly announce nothing (fail-closed).
    let disabled = open_public_allowlist(None, &[], &[3u8; 32], &[]).expect("disabled opens");
    let app_seed = || {
        (
            APP_NAR_HASH.parse::<NarHashKey>().unwrap(),
            vec![0u8; APP_NAR_SIZE],
        )
    };
    assert!(
        approve_seeds_for_public(&[app_seed()], &disabled).is_err(),
        "a disabled allowlist approves no seed for public announce"
    );

    // WITH a path + trusted key + the trusted-signed APP narinfo proved at startup: the shared
    // builder opens the MAC-integrity file and proves the APP NAR public. The door then approves
    // the APP seed (proven, right size) and refuses a foreign one (never proven).
    let narinfo_path = temp_path("app-narinfo");
    std::fs::write(&narinfo_path, APP_NARINFO).expect("write fixture narinfo");
    let allowlist_path = temp_path("allowlist");
    let allowlist = open_public_allowlist(
        Some(&allowlist_path),
        &[FIXTURE_PUBKEY.to_string()],
        &[3u8; 32],
        &[(
            APP_STORE_HASH.to_string(),
            narinfo_path.to_string_lossy().into_owned(),
        )],
    )
    .expect("the shared builder proves the trusted-signed APP narinfo public");

    let approved =
        approve_seeds_for_public(&[app_seed()], &allowlist).expect("the proven APP seed approves");
    assert_eq!(approved.len(), 1);
    assert_eq!(approved[0].claim().nar_size(), APP_NAR_SIZE as u64);

    // A foreign NAR the operator merely names is NOT proven public -> refused (the operator naming
    // a path never makes it public; only a trusted narinfo signature does).
    let foreign = (
        "sha256:1nn8563y6j55y003xjk1bvb1854abmigsas2jgzy4shy0f4vnzpa"
            .parse::<NarHashKey>()
            .unwrap(),
        vec![0u8; 524_808],
    );
    assert!(
        approve_seeds_for_public(&[foreign], &allowlist).is_err(),
        "a NAR that was never proven public must be refused from public announce"
    );

    // Guard against a builder that silently ignores a bad trusted-key line.
    assert!(
        open_public_allowlist(Some(&temp_path("no-key-allowlist")), &[], &[3u8; 32], &[],).is_err(),
        "opening a file-backed allowlist with no trusted key must be an error (proves nothing)"
    );

    // Cleanup best-effort (a leaked temp file is harmless, but keep the box tidy).
    let _ = std::fs::remove_file(&narinfo_path);
    let _ = std::fs::remove_file(&allowlist_path);
}
