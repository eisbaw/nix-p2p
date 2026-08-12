use super::*;
use crate::iroh_node_record::{NodeLocation, encode_node_record};
use crate::iroh_publication::{
    NodePublicationConfig, NodePublicationRuntime, PUBLICATION_STATE_FILENAME,
    PublicationAuthorityAuthorization, seed_pending_state_for_test,
};
use crate::iroh_runtime::{
    AddressLookupCapability, DAEMON_TEST_ENDPOINT_PROFILE, IdentitySource, RelayCapability,
    bind_endpoint, spawn_publication_address_watch,
};
use iroh::address_lookup::pkarr::PkarrRelayClient;

struct TempDir(PathBuf);

static NEXT_TEMP_DIR: AtomicU64 = AtomicU64::new(0);

impl TempDir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "nix-p2p-{label}-{}-{}-{}",
            std::process::id(),
            unix_micros().unwrap(),
            NEXT_TEMP_DIR.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn authority() -> (PublicationAuthority, TempDir) {
    let state = TempDir::new("authority");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = listener.local_addr().unwrap();
    let config = PublicationAuthorityConfig {
        listen,
        state_dir: state.0.clone(),
        namespace: "run-1".into(),
        signed_recipient: "authority.test:v1".into(),
        expected_host: "authority.test".into(),
        owner: "test operator".into(),
        signer_admission: AuthoritySignerAdmission::TestOnlyUnrestricted,
    };
    config.validate().unwrap();
    let (store, authority_state) = AuthorityStateStore::open(&config).unwrap();
    let authority =
        PublicationAuthority::from_listener(config, store, authority_state, listener).unwrap();
    (authority, state)
}

#[tokio::test]
async fn stock_iroh_pkarr_client_publishes_and_resolves_exact_packet() {
    let state = TempDir::new("authority-stock-iroh");
    let key = iroh::SecretKey::generate();
    let signer = key.public().to_z32();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = listener.local_addr().unwrap();
    let config = PublicationAuthorityConfig {
        listen,
        state_dir: state.0.clone(),
        namespace: "run-stock-iroh".into(),
        signed_recipient: "authority.test:v1".into(),
        expected_host: listen.to_string(),
        owner: "test operator".into(),
        signer_admission: AuthoritySignerAdmission::explicit([signer]).unwrap(),
    };
    config.validate().unwrap();
    let (store, authority_state) = AuthorityStateStore::open(&config).unwrap();
    let authority =
        PublicationAuthority::from_listener(config, store, authority_state, listener).unwrap();

    let endpoint = bind_endpoint(
        DAEMON_TEST_ENDPOINT_PROFILE,
        IdentitySource::Ephemeral,
        RelayCapability::Disabled,
        AddressLookupCapability::Disabled,
    )
    .await
    .unwrap();
    let relay_url = format!("http://{listen}/pkarr").parse().unwrap();
    let client = PkarrRelayClient::new(
        relay_url,
        endpoint.tls_config().clone(),
        endpoint.dns_resolver().unwrap().clone(),
    );
    let now = unix_micros().unwrap();
    let packet = encode_node_record(
        &key,
        "run-stock-iroh",
        "authority.test:v1",
        30,
        now,
        now + 30_000_000,
        PublicationState::Live,
        &[NodeLocation::direct("127.0.0.1:4433".parse().unwrap()).unwrap()],
    )
    .unwrap();

    client.publish(&packet).await.unwrap();
    let resolved = client.resolve(key.public()).await.unwrap();
    assert_eq!(resolved.as_bytes(), packet.as_bytes());

    endpoint.close().await;
    authority.shutdown().await.unwrap();
}

#[tokio::test]
async fn durable_state_failure_terminates_the_serving_task_and_reports_unhealthy() {
    let state = TempDir::new("authority-fatal-health");
    let key = iroh::SecretKey::generate();
    let signer = key.public().to_z32();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = listener.local_addr().unwrap();
    let config = PublicationAuthorityConfig {
        listen,
        state_dir: state.0.clone(),
        namespace: "run-fatal-health".into(),
        signed_recipient: "authority.test:v1".into(),
        expected_host: listen.to_string(),
        owner: "test operator".into(),
        signer_admission: AuthoritySignerAdmission::explicit([signer]).unwrap(),
    };
    let (store, authority_state) = AuthorityStateStore::open(&config).unwrap();
    let authority =
        PublicationAuthority::from_listener(config, store, authority_state, listener).unwrap();
    authority
        .inner
        .state
        .lock()
        .unwrap()
        .0
        .fail_next_write
        .store(true, Ordering::Release);

    let endpoint = bind_endpoint(
        DAEMON_TEST_ENDPOINT_PROFILE,
        IdentitySource::Ephemeral,
        RelayCapability::Disabled,
        AddressLookupCapability::Disabled,
    )
    .await
    .unwrap();
    let relay_url = format!("http://{listen}/pkarr").parse().unwrap();
    let client = PkarrRelayClient::new(
        relay_url,
        endpoint.tls_config().clone(),
        endpoint.dns_resolver().unwrap().clone(),
    );
    let sequence = unix_micros().unwrap();
    let packet = encode_node_record(
        &key,
        "run-fatal-health",
        "authority.test:v1",
        30,
        sequence,
        sequence + 30_000_000,
        PublicationState::Live,
        &[NodeLocation::direct("127.0.0.1:4433".parse().unwrap()).unwrap()],
    )
    .unwrap();

    assert!(client.publish(&packet).await.is_err());
    let fatal = tokio::time::timeout(Duration::from_secs(2), authority.wait_for_failure())
        .await
        .expect("authority serving task did not report its fatal state");
    assert!(
        fatal.to_string().contains("authority state write failure"),
        "unexpected fatal health: {fatal}"
    );
    endpoint.close().await;
    assert!(authority.shutdown().await.is_err());
}

#[test]
fn authority_config_requires_explicit_canonical_signer_admission_and_concrete_bind() {
    assert!(AuthoritySignerAdmission::explicit(Vec::<String>::new()).is_err());
    assert!(AuthoritySignerAdmission::explicit(["not-a-key".to_string()]).is_err());
    let signer = iroh::SecretKey::generate().public().to_z32();
    let config_for = |listen: &str| PublicationAuthorityConfig {
        listen: listen.parse().unwrap(),
        state_dir: PathBuf::from("unused"),
        namespace: "run-1".into(),
        signed_recipient: "authority.test:v1".into(),
        expected_host: "authority.test".into(),
        owner: "operator".into(),
        signer_admission: AuthoritySignerAdmission::explicit([signer.clone()]).unwrap(),
    };
    for forbidden in [
        "[::ffff:0.0.0.0]:8080",
        "8.8.8.8:8080",
        "[2001:4860:4860::8888]:8080",
        "[fe80::1]:8080",
    ] {
        let error = config_for(forbidden).validate().unwrap_err();
        assert!(
            error
                .to_string()
                .contains("public plain-HTTP binds are forbidden"),
            "unexpected error for {forbidden}: {error}"
        );
    }
    for admitted in ["127.0.0.1:8080", "10.20.30.40:8080", "[fd00::2]:8080"] {
        config_for(admitted).validate().unwrap();
    }
}

fn publisher_config(
    authority: &PublicationAuthority,
    location: NodeLocation,
    ttl: Duration,
    refresh: Duration,
) -> NodePublicationConfig {
    NodePublicationConfig::new(
        "run-1",
        "authority.test:v1",
        authority.local_addr(),
        "authority.test",
        PublicationAuthorityAuthorization::LocalProductionShaped {
            owner: "test operator".into(),
        },
        ttl,
        refresh,
        Duration::from_millis(200),
        [location],
    )
    .unwrap()
}

#[tokio::test]
async fn publisher_config_rejects_over_limit_locations_without_truncation() {
    let (authority, _authority_state) = authority().await;
    let locations = (1..=crate::iroh_node_record::MAX_NODE_LOCATIONS + 1)
        .map(|index| {
            NodeLocation::direct(SocketAddr::from(([10, 0, 0, index as u8], 4433))).unwrap()
        })
        .collect::<Vec<_>>();
    let error = NodePublicationConfig::new(
        "run-1",
        "authority.test:v1",
        authority.local_addr(),
        "authority.test",
        PublicationAuthorityAuthorization::LocalProductionShaped {
            owner: "test operator".into(),
        },
        Duration::from_secs(30),
        Duration::from_secs(10),
        Duration::from_secs(2),
        locations,
    )
    .unwrap_err();
    assert!(error.to_string().contains("maximum is 16"));
    assert!(error.to_string().contains("refusing to truncate"));
    authority.shutdown().await.unwrap();
}

#[tokio::test]
async fn publisher_is_visible_idempotent_and_withdraws() {
    let (authority, _authority_state) = authority().await;
    let client_state = TempDir::new("publisher");
    let key = iroh::SecretKey::generate();
    let location = NodeLocation::direct("127.0.0.1:4433".parse().unwrap()).unwrap();
    let config = publisher_config(
        &authority,
        location.clone(),
        Duration::from_secs(30),
        Duration::from_secs(10),
    );
    let (runtime, first) = NodePublicationRuntime::start(
        &client_state.0,
        key,
        config,
        tokio::time::Instant::now() + Duration::from_secs(10),
    )
    .await
    .unwrap();
    assert_eq!(first.record.state, PublicationState::Live);
    let requests_after_first = authority.request_count();
    let second = runtime.handle().update_locations([location]).await.unwrap();
    assert!(second.reused_committed_packet);
    assert!(second.put_elapsed.is_some());
    assert_eq!(
        authority.request_count(),
        requests_after_first + 2,
        "fresh committed reuse is one exact idempotent PUT plus one visibility GET"
    );
    let withdrawn = runtime
        .shutdown(tokio::time::Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(withdrawn.record.state, PublicationState::Withdrawn);
    authority.shutdown().await.unwrap();
}

#[tokio::test]
async fn restart_after_graceful_withdrawal_records_a_new_live_intent() {
    let (authority, _authority_state) = authority().await;
    let client_state = TempDir::new("publisher-graceful-restart");
    let key = iroh::SecretKey::generate();
    let signer = key.public().to_z32();
    let location = NodeLocation::direct("127.0.0.1:4433".parse().unwrap()).unwrap();
    let config = publisher_config(
        &authority,
        location.clone(),
        Duration::from_secs(30),
        Duration::from_secs(10),
    );
    let (runtime, first) = NodePublicationRuntime::start(
        &client_state.0,
        key.clone(),
        config.clone(),
        tokio::time::Instant::now() + Duration::from_secs(10),
    )
    .await
    .unwrap();
    let withdrawn = runtime
        .shutdown(tokio::time::Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(withdrawn.record.state, PublicationState::Withdrawn);
    assert!(withdrawn.record.sequence > first.record.sequence);

    let (restarted, live) = NodePublicationRuntime::start(
        &client_state.0,
        key,
        config,
        tokio::time::Instant::now() + Duration::from_secs(10),
    )
    .await
    .unwrap();
    assert_eq!(live.record.state, PublicationState::Live);
    assert_eq!(live.record.locations, vec![location]);
    assert!(live.record.sequence > withdrawn.record.sequence);
    let visible = decode_node_record(&authority.packet_for_test(&signer).unwrap()).unwrap();
    assert_eq!(visible, live.record);

    restarted
        .shutdown(tokio::time::Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    authority.shutdown().await.unwrap();
}

#[tokio::test]
async fn restart_repairs_empty_authority_with_exact_committed_packet() {
    let (first_authority, _first_authority_state) = authority().await;
    let client_state = TempDir::new("publisher-authority-loss");
    let key = iroh::SecretKey::generate();
    let signer = key.public().to_z32();
    let location = NodeLocation::direct("127.0.0.1:4433".parse().unwrap()).unwrap();
    let first_config = publisher_config(
        &first_authority,
        location.clone(),
        Duration::from_secs(30),
        Duration::from_secs(10),
    );
    let (first_runtime, first_receipt) = NodePublicationRuntime::start(
        &client_state.0,
        key.clone(),
        first_config,
        tokio::time::Instant::now() + Duration::from_secs(10),
    )
    .await
    .unwrap();
    let committed = first_runtime
        .handle()
        .committed_packet_for_test()
        .await
        .unwrap();
    first_runtime.crash_for_test().await;
    first_authority.shutdown().await.unwrap();

    let (empty_authority, _empty_authority_state) = authority().await;
    assert!(empty_authority.packet_for_test(&signer).is_none());
    let restart_config = publisher_config(
        &empty_authority,
        location,
        Duration::from_secs(30),
        Duration::from_secs(10),
    );
    let started = std::time::Instant::now();
    let (restarted, recovered) = tokio::time::timeout(
        crate::iroh_publication::PUBLICATION_TRANSITION_DEADLINE + Duration::from_secs(1),
        NodePublicationRuntime::start(
            &client_state.0,
            key,
            restart_config,
            tokio::time::Instant::now() + Duration::from_secs(10),
        ),
    )
    .await
    .expect("empty-authority recovery exceeded transition bound")
    .unwrap();
    assert!(started.elapsed() <= Duration::from_secs(6));
    assert!(recovered.reused_committed_packet);
    assert_eq!(recovered.record, first_receipt.record);
    assert_eq!(empty_authority.request_count(), 2);
    assert_eq!(
        empty_authority.packet_for_test(&signer).as_deref(),
        Some(committed.as_slice())
    );

    restarted
        .shutdown(tokio::time::Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    empty_authority.shutdown().await.unwrap();
}

#[tokio::test]
async fn committed_recovery_rejects_conflicting_equal_sequence() {
    let (first_authority, _first_authority_state) = authority().await;
    let client_state = TempDir::new("publisher-authority-conflict");
    let key = iroh::SecretKey::generate();
    let signer = key.public().to_z32();
    let location = NodeLocation::direct("127.0.0.1:4433".parse().unwrap()).unwrap();
    let first_config = publisher_config(
        &first_authority,
        location.clone(),
        Duration::from_secs(30),
        Duration::from_secs(10),
    );
    let (first_runtime, first_receipt) = NodePublicationRuntime::start(
        &client_state.0,
        key.clone(),
        first_config,
        tokio::time::Instant::now() + Duration::from_secs(10),
    )
    .await
    .unwrap();
    first_runtime.crash_for_test().await;
    first_authority.shutdown().await.unwrap();

    let (conflicting_authority, _conflicting_authority_state) = authority().await;
    let conflicting = encode_node_record(
        &key,
        "run-1",
        "authority.test:v1",
        first_receipt.record.ttl_seconds,
        first_receipt.record.sequence,
        first_receipt.record.expires_unix_micros,
        PublicationState::Live,
        &[NodeLocation::direct("127.0.0.1:4434".parse().unwrap()).unwrap()],
    )
    .unwrap();
    assert_eq!(
        apply_request(
            &conflicting_authority.inner,
            AuthorityRequest {
                method: "PUT".into(),
                signer,
                body: conflicting.to_relay_payload(),
            },
        )
        .unwrap()
        .status,
        201
    );
    let restart_config = publisher_config(
        &conflicting_authority,
        location,
        Duration::from_secs(30),
        Duration::from_secs(10),
    );
    let error = NodePublicationRuntime::start(
        &client_state.0,
        key,
        restart_config,
        tokio::time::Instant::now() + Duration::from_secs(10),
    )
    .await
    .unwrap_err();
    assert_eq!(
        error.kind,
        crate::iroh_publication::PublicationErrorKind::Authority
    );
    assert!(error.to_string().contains("status 409"));
    assert_eq!(
        conflicting_authority.request_count(),
        3,
        "conflict PUT is followed only by bounded higher tombstone PUT+GET cleanup"
    );
    conflicting_authority.shutdown().await.unwrap();
}

async fn crash_restart_case(failpoint: crate::iroh_publication::PublicationFailpoint) {
    let (authority, _authority_state) = authority().await;
    let client_state = TempDir::new("publisher-crash");
    let key = iroh::SecretKey::generate();
    let signer = key.public().to_z32();
    let first_location = NodeLocation::direct("127.0.0.1:4433".parse().unwrap()).unwrap();
    let next_location = NodeLocation::direct("127.0.0.1:4434".parse().unwrap()).unwrap();
    let first_config = publisher_config(
        &authority,
        first_location,
        Duration::from_secs(30),
        Duration::from_secs(10),
    );
    let (runtime, first) = NodePublicationRuntime::start(
        &client_state.0,
        key.clone(),
        first_config,
        tokio::time::Instant::now() + Duration::from_secs(10),
    )
    .await
    .unwrap();
    let handle = runtime.handle();
    let failed = handle
        .update_locations_with_failpoint([next_location.clone()], failpoint)
        .await
        .unwrap_err();
    assert_eq!(
        failed.kind,
        crate::iroh_publication::PublicationErrorKind::InjectedCrash
    );
    let pending_packet = handle
        .pending_packet_for_test()
        .await
        .expect("crash point must leave the exact packet pending");
    let pending_record = decode_node_record(&pending_packet).unwrap();
    assert!(pending_record.sequence > first.record.sequence);
    assert_eq!(pending_record.locations, vec![next_location.clone()]);
    let idempotent_before_restart = authority.idempotent_put_count();
    match failpoint {
        crate::iroh_publication::PublicationFailpoint::AfterPendingPersist => {
            assert_ne!(
                authority.packet_for_test(&signer).as_deref(),
                Some(pending_packet.as_slice()),
                "pending-before-PUT must not already be authoritative"
            );
        }
        crate::iroh_publication::PublicationFailpoint::AfterPutBeforeCommit => {
            assert_eq!(
                authority.packet_for_test(&signer).as_deref(),
                Some(pending_packet.as_slice()),
                "PUT-before-commit must have stored the pending bytes exactly"
            );
        }
        crate::iroh_publication::PublicationFailpoint::None => unreachable!(),
    }
    drop(handle);
    runtime.crash_for_test().await;

    let restart_config = publisher_config(
        &authority,
        next_location.clone(),
        Duration::from_secs(30),
        Duration::from_secs(10),
    );
    let (restarted, recovered) = NodePublicationRuntime::start(
        &client_state.0,
        key,
        restart_config,
        tokio::time::Instant::now() + Duration::from_secs(10),
    )
    .await
    .unwrap();
    assert_eq!(recovered.record, pending_record);
    assert_eq!(recovered.record.locations, vec![next_location]);
    assert_eq!(
        restarted
            .handle()
            .committed_packet_for_test()
            .await
            .as_deref(),
        Some(pending_packet.as_slice()),
        "restart must commit the byte-identical pending packet"
    );
    assert_eq!(
        authority.packet_for_test(&signer).as_deref(),
        Some(pending_packet.as_slice())
    );
    if failpoint == crate::iroh_publication::PublicationFailpoint::AfterPutBeforeCommit {
        assert_eq!(
            authority.idempotent_put_count(),
            idempotent_before_restart + 1,
            "restart must exercise the authority's exact-replay idempotent PUT path"
        );
    }
    restarted
        .shutdown(tokio::time::Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    authority.shutdown().await.unwrap();
}

#[tokio::test]
async fn restart_retries_exact_pending_before_put() {
    crash_restart_case(crate::iroh_publication::PublicationFailpoint::AfterPendingPersist).await;
}

#[tokio::test]
async fn restart_recovers_put_before_local_commit_idempotently() {
    crash_restart_case(crate::iroh_publication::PublicationFailpoint::AfterPutBeforeCommit).await;
}

#[tokio::test]
async fn restart_with_lower_ttl_advances_instead_of_reusing_old_committed_packet() {
    let (authority, _authority_state) = authority().await;
    let client_state = TempDir::new("publisher-lower-ttl-committed");
    let key = iroh::SecretKey::generate();
    let location = NodeLocation::direct("127.0.0.1:4433".parse().unwrap()).unwrap();
    let old_config = publisher_config(
        &authority,
        location.clone(),
        Duration::from_secs(30),
        Duration::from_secs(10),
    );
    let (runtime, old) = NodePublicationRuntime::start(
        &client_state.0,
        key.clone(),
        old_config,
        tokio::time::Instant::now() + Duration::from_secs(10),
    )
    .await
    .unwrap();
    runtime.crash_for_test().await;

    let new_config = publisher_config(
        &authority,
        location.clone(),
        Duration::from_secs(6),
        Duration::from_secs(2),
    );
    let (restarted, current) = NodePublicationRuntime::start(
        &client_state.0,
        key,
        new_config,
        tokio::time::Instant::now() + Duration::from_secs(10),
    )
    .await
    .unwrap();
    assert!(!current.reused_committed_packet);
    assert_eq!(current.record.ttl_seconds, 6);
    assert!(current.record.sequence > old.record.sequence);
    assert_eq!(current.record.locations, vec![location]);

    restarted
        .shutdown(tokio::time::Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    authority.shutdown().await.unwrap();
}

#[tokio::test]
async fn restart_may_recover_old_ttl_pending_then_must_advance_to_current_ttl() {
    let (authority, _authority_state) = authority().await;
    let client_state = TempDir::new("publisher-lower-ttl-pending");
    let key = iroh::SecretKey::generate();
    let first_location = NodeLocation::direct("127.0.0.1:4433".parse().unwrap()).unwrap();
    let next_location = NodeLocation::direct("127.0.0.1:4434".parse().unwrap()).unwrap();
    let old_config = publisher_config(
        &authority,
        first_location,
        Duration::from_secs(30),
        Duration::from_secs(10),
    );
    let (runtime, _) = NodePublicationRuntime::start(
        &client_state.0,
        key.clone(),
        old_config,
        tokio::time::Instant::now() + Duration::from_secs(10),
    )
    .await
    .unwrap();
    let interrupted = runtime
        .handle()
        .update_locations_with_failpoint(
            [next_location.clone()],
            crate::iroh_publication::PublicationFailpoint::AfterPutBeforeCommit,
        )
        .await
        .unwrap_err();
    assert_eq!(
        interrupted.kind,
        crate::iroh_publication::PublicationErrorKind::InjectedCrash
    );
    let pending =
        decode_node_record(&runtime.handle().pending_packet_for_test().await.unwrap()).unwrap();
    assert_eq!(pending.ttl_seconds, 30);
    runtime.crash_for_test().await;

    let new_config = publisher_config(
        &authority,
        next_location.clone(),
        Duration::from_secs(6),
        Duration::from_secs(2),
    );
    let (restarted, current) = NodePublicationRuntime::start(
        &client_state.0,
        key,
        new_config,
        tokio::time::Instant::now() + Duration::from_secs(10),
    )
    .await
    .unwrap();
    assert_eq!(current.record.ttl_seconds, 6);
    assert!(current.record.sequence > pending.sequence);
    assert_eq!(current.record.locations, vec![next_location]);

    restarted
        .shutdown(tokio::time::Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    authority.shutdown().await.unwrap();
}

#[tokio::test]
async fn interrupted_updates_retry_the_latest_durable_intent_including_withdrawal() {
    let (authority, _authority_state) = authority().await;
    let client_state = TempDir::new("publisher-latest-intent");
    let key = iroh::SecretKey::generate();
    let signer = key.public().to_z32();
    let first_location = NodeLocation::direct("127.0.0.1:4433".parse().unwrap()).unwrap();
    let next_location = NodeLocation::direct("127.0.0.1:4434".parse().unwrap()).unwrap();
    let config = publisher_config(
        &authority,
        first_location,
        Duration::from_secs(30),
        Duration::from_secs(10),
    );
    let (runtime, _) = NodePublicationRuntime::start(
        &client_state.0,
        key,
        config,
        tokio::time::Instant::now() + Duration::from_secs(10),
    )
    .await
    .unwrap();
    let handle = runtime.handle();

    let error = handle
        .update_locations_with_failpoint(
            [next_location.clone()],
            crate::iroh_publication::PublicationFailpoint::AfterPendingPersist,
        )
        .await
        .unwrap_err();
    assert_eq!(
        error.kind,
        crate::iroh_publication::PublicationErrorKind::InjectedCrash
    );
    let recovered = handle.refresh_current_for_test().await.unwrap();
    assert_eq!(recovered.record.state, PublicationState::Live);
    assert_eq!(recovered.record.locations, vec![next_location.clone()]);

    let error = handle
        .update_locations_with_failpoint(
            Vec::<NodeLocation>::new(),
            crate::iroh_publication::PublicationFailpoint::AfterPutBeforeCommit,
        )
        .await
        .unwrap_err();
    assert_eq!(
        error.kind,
        crate::iroh_publication::PublicationErrorKind::InjectedCrash
    );
    let recovered = handle.refresh_current_for_test().await.unwrap();
    assert_eq!(recovered.record.state, PublicationState::Withdrawn);
    assert!(recovered.record.locations.is_empty());

    let refreshed = handle.refresh_current_for_test().await.unwrap();
    assert_eq!(refreshed.record.state, PublicationState::Withdrawn);
    assert!(refreshed.record.locations.is_empty());
    let visible = decode_node_record(&authority.packet_for_test(&signer).unwrap()).unwrap();
    assert_eq!(visible.state, PublicationState::Withdrawn);
    assert!(visible.locations.is_empty());

    drop(handle);
    runtime.crash_for_test().await;
    authority.shutdown().await.unwrap();
}

#[tokio::test]
async fn newer_withdrawal_retires_older_pending_live_packet_without_replaying_it() {
    let (authority, _authority_state) = authority().await;
    let client_state = TempDir::new("publisher-stale-pending-withdrawal");
    let key = iroh::SecretKey::generate();
    let signer = key.public().to_z32();
    let first_location = NodeLocation::direct("127.0.0.1:4433".parse().unwrap()).unwrap();
    let stale_location = NodeLocation::direct("127.0.0.1:4434".parse().unwrap()).unwrap();
    let config = publisher_config(
        &authority,
        first_location,
        Duration::from_secs(30),
        Duration::from_secs(10),
    );
    let (runtime, _) = NodePublicationRuntime::start(
        &client_state.0,
        key,
        config,
        tokio::time::Instant::now() + Duration::from_secs(10),
    )
    .await
    .unwrap();
    let handle = runtime.handle();
    handle
        .update_locations_with_failpoint(
            [stale_location],
            crate::iroh_publication::PublicationFailpoint::AfterPendingPersist,
        )
        .await
        .unwrap_err();
    let requests_before_withdrawal = authority.request_count();
    let withdrawn = handle
        .update_locations(Vec::<NodeLocation>::new())
        .await
        .unwrap();
    assert_eq!(withdrawn.record.state, PublicationState::Withdrawn);
    assert_eq!(
        authority.request_count(),
        requests_before_withdrawal + 2,
        "stale pending live bytes must be retired locally, leaving only withdrawal PUT+GET"
    );
    let visible = decode_node_record(&authority.packet_for_test(&signer).unwrap()).unwrap();
    assert_eq!(visible.state, PublicationState::Withdrawn);
    assert!(visible.locations.is_empty());

    drop(handle);
    runtime.crash_for_test().await;
    authority.shutdown().await.unwrap();
}

#[tokio::test]
async fn transient_visibility_failure_retries_the_latest_desired_location() {
    let (authority, _authority_state) = authority().await;
    let client_state = TempDir::new("publisher-visibility-retry");
    let key = iroh::SecretKey::generate();
    let signer = key.public().to_z32();
    let first_location = NodeLocation::direct("127.0.0.1:4433".parse().unwrap()).unwrap();
    let next_location = NodeLocation::direct("127.0.0.1:4434".parse().unwrap()).unwrap();
    let config = publisher_config(
        &authority,
        first_location,
        Duration::from_secs(30),
        Duration::from_secs(10),
    );
    let (runtime, _) = NodePublicationRuntime::start(
        &client_state.0,
        key,
        config,
        tokio::time::Instant::now() + Duration::from_secs(10),
    )
    .await
    .unwrap();
    authority.fail_next_visibility_get();
    let receipt = runtime
        .handle()
        .update_locations([next_location.clone()])
        .await
        .unwrap();
    assert_eq!(receipt.record.locations, vec![next_location.clone()]);
    let visible = decode_node_record(&authority.packet_for_test(&signer).unwrap()).unwrap();
    assert_eq!(visible.locations, vec![next_location]);

    runtime
        .shutdown(tokio::time::Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    authority.shutdown().await.unwrap();
}

#[tokio::test]
async fn concurrent_churn_converges_on_the_newest_intent_and_never_resurrects_old() {
    let (authority, _authority_state) = authority().await;
    let client_state = TempDir::new("publisher-concurrent-latest");
    let key = iroh::SecretKey::generate();
    let signer = key.public().to_z32();
    let first_location = NodeLocation::direct("127.0.0.1:4433".parse().unwrap()).unwrap();
    let middle_location = NodeLocation::direct("127.0.0.1:4434".parse().unwrap()).unwrap();
    let newest_location = NodeLocation::direct("127.0.0.1:4435".parse().unwrap()).unwrap();
    let config = publisher_config(
        &authority,
        first_location,
        Duration::from_secs(30),
        Duration::from_secs(10),
    );
    let (runtime, _) = NodePublicationRuntime::start(
        &client_state.0,
        key,
        config,
        tokio::time::Instant::now() + Duration::from_secs(10),
    )
    .await
    .unwrap();
    authority.block_next_put();
    let middle_handle = runtime.handle();
    let middle =
        tokio::spawn(async move { middle_handle.update_locations([middle_location]).await });
    authority.wait_until_put_blocked().await;
    let newest_handle = runtime.handle();
    let newest_for_task = newest_location.clone();
    let newest =
        tokio::spawn(async move { newest_handle.update_locations([newest_for_task]).await });
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if runtime.handle().desired_locations_for_test().unwrap()
                == vec![newest_location.clone()]
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("newest intent was not recorded before releasing the older PUT");
    authority.release_blocked_put();
    middle.await.unwrap().unwrap();
    let newest_receipt = newest.await.unwrap().unwrap();
    assert_eq!(
        newest_receipt.record.locations,
        vec![newest_location.clone()]
    );

    let refreshed = runtime.handle().refresh_current_for_test().await.unwrap();
    assert_eq!(refreshed.record.locations, vec![newest_location.clone()]);
    let visible = decode_node_record(&authority.packet_for_test(&signer).unwrap()).unwrap();
    assert_eq!(visible.locations, vec![newest_location]);

    runtime
        .shutdown(tokio::time::Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    authority.shutdown().await.unwrap();
}

#[tokio::test]
async fn concurrent_publisher_state_owner_is_rejected() {
    let (authority, _authority_state) = authority().await;
    let client_state = TempDir::new("publisher-lock");
    let key = iroh::SecretKey::generate();
    let location = NodeLocation::direct("127.0.0.1:4433".parse().unwrap()).unwrap();
    let config = publisher_config(
        &authority,
        location,
        Duration::from_secs(30),
        Duration::from_secs(10),
    );
    let (runtime, _) = NodePublicationRuntime::start(
        &client_state.0,
        key.clone(),
        config.clone(),
        tokio::time::Instant::now() + Duration::from_secs(10),
    )
    .await
    .unwrap();
    let second = NodePublicationRuntime::start(
        &client_state.0,
        key,
        config,
        tokio::time::Instant::now() + Duration::from_secs(10),
    )
    .await;
    assert!(second.is_err());
    runtime
        .shutdown(tokio::time::Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    authority.shutdown().await.unwrap();
}

#[tokio::test]
async fn refresh_uses_latest_churned_location_not_startup_location() {
    let (authority, _authority_state) = authority().await;
    let client_state = TempDir::new("publisher-refresh");
    let key = iroh::SecretKey::generate();
    let first_location = NodeLocation::direct("127.0.0.1:4433".parse().unwrap()).unwrap();
    let next_location = NodeLocation::direct("127.0.0.1:4434".parse().unwrap()).unwrap();
    let config = publisher_config(
        &authority,
        first_location,
        Duration::from_secs(3),
        Duration::from_millis(200),
    );
    let (runtime, _) = NodePublicationRuntime::start(
        &client_state.0,
        key,
        config,
        tokio::time::Instant::now() + Duration::from_secs(10),
    )
    .await
    .unwrap();
    let handle = runtime.handle();
    let churned = handle
        .update_locations([next_location.clone()])
        .await
        .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let current = loop {
        let current = handle.current_record().await.unwrap().unwrap();
        if current.sequence > churned.record.sequence
            && current.expires_unix_micros > unix_micros().unwrap()
        {
            break current;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "refresh never advanced the churned record before the bound"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert_eq!(current.state, PublicationState::Live);
    assert_eq!(current.locations, vec![next_location]);
    drop(handle);
    runtime
        .shutdown(tokio::time::Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    authority.shutdown().await.unwrap();
}

#[tokio::test]
async fn delayed_startup_refreshes_from_signed_expiry_without_visibility_gap() {
    let (authority, _authority_state) = authority().await;
    let client_state = TempDir::new("publisher-delayed-startup-refresh");
    let state_path = client_state.0.clone();
    let key = iroh::SecretKey::generate();
    let signer = key.public().to_z32();
    let location = NodeLocation::direct("127.0.0.1:4433".parse().unwrap()).unwrap();
    let config = publisher_config(
        &authority,
        location,
        Duration::from_secs(3),
        Duration::from_secs(1),
    );
    authority.block_next_put();
    let startup = tokio::spawn(async move {
        NodePublicationRuntime::start(
            &state_path,
            key,
            config,
            tokio::time::Instant::now() + Duration::from_secs(10),
        )
        .await
    });
    authority.wait_until_put_blocked().await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    authority.release_blocked_put();
    let (runtime, first) = startup.await.unwrap().unwrap();

    let observe_until = first.record.expires_unix_micros + 300_000;
    while unix_micros().unwrap() <= observe_until {
        let response = apply_request(
            &authority.inner,
            AuthorityRequest {
                method: "GET".into(),
                signer: signer.clone(),
                body: Vec::new(),
            },
        )
        .unwrap();
        assert_eq!(
            response.status, 200,
            "authority visibility gapped around the first signed expiry"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let refreshed = runtime.handle().current_record().await.unwrap().unwrap();
    assert!(refreshed.sequence > first.record.sequence);
    assert!(refreshed.expires_unix_micros > first.record.expires_unix_micros);

    runtime
        .shutdown(tokio::time::Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    authority.shutdown().await.unwrap();
}

#[tokio::test]
async fn near_expiry_pending_is_retired_before_recovery_and_replaced_fresh() {
    let (authority, _authority_state) = authority().await;
    let client_state = TempDir::new("publisher-near-expiry-recovery");
    let key = iroh::SecretKey::generate();
    let first_location = NodeLocation::direct("127.0.0.1:4433".parse().unwrap()).unwrap();
    let next_location = NodeLocation::direct("127.0.0.1:4434".parse().unwrap()).unwrap();
    let config = publisher_config(
        &authority,
        first_location,
        Duration::from_secs(3),
        Duration::from_secs(1),
    );
    let (runtime, _) = NodePublicationRuntime::start(
        &client_state.0,
        key.clone(),
        config,
        tokio::time::Instant::now() + Duration::from_secs(10),
    )
    .await
    .unwrap();
    runtime
        .handle()
        .update_locations_with_failpoint(
            [next_location.clone()],
            crate::iroh_publication::PublicationFailpoint::AfterPendingPersist,
        )
        .await
        .unwrap_err();
    let pending =
        decode_node_record(&runtime.handle().pending_packet_for_test().await.unwrap()).unwrap();
    runtime.crash_for_test().await;
    tokio::time::sleep(Duration::from_millis(1_850)).await;
    let remaining = pending
        .expires_unix_micros
        .saturating_sub(unix_micros().unwrap());
    assert!(remaining > 0, "fixture must remain unexpired");
    assert!(
        remaining <= 1_200_000,
        "fixture must be inside the completion-safe recovery margin"
    );

    let restart_config = publisher_config(
        &authority,
        next_location.clone(),
        Duration::from_secs(3),
        Duration::from_secs(1),
    );
    let requests_before = authority.request_count();
    let (restarted, fresh) = NodePublicationRuntime::start(
        &client_state.0,
        key,
        restart_config,
        tokio::time::Instant::now() + Duration::from_secs(10),
    )
    .await
    .unwrap();
    assert!(!fresh.reused_committed_packet);
    assert!(fresh.record.sequence > pending.sequence);
    assert_eq!(fresh.record.locations, vec![next_location]);
    assert_eq!(
        authority.request_count(),
        requests_before + 2,
        "near-expiry pending bytes must be retired locally, leaving only fresh PUT+GET"
    );

    restarted
        .shutdown(tokio::time::Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    authority.shutdown().await.unwrap();
}

#[tokio::test]
async fn persistent_refresh_failure_latches_fatal_health_instead_of_logging_only() {
    let (authority, _authority_state) = authority().await;
    let client_state = TempDir::new("publisher-fatal-refresh");
    let key = iroh::SecretKey::generate();
    let config = publisher_config(
        &authority,
        NodeLocation::direct("127.0.0.1:4433".parse().unwrap()).unwrap(),
        Duration::from_secs(3),
        Duration::from_millis(100),
    );
    let (runtime, _) = NodePublicationRuntime::start(
        &client_state.0,
        key,
        config,
        tokio::time::Instant::now() + Duration::from_secs(10),
    )
    .await
    .unwrap();
    let handle = runtime.handle();
    authority.shutdown().await.unwrap();

    let fatal = tokio::time::timeout(Duration::from_secs(3), handle.wait_for_fatal())
        .await
        .expect("refresh failure remained log-only instead of reaching health");
    assert_eq!(
        fatal.kind,
        crate::iroh_publication::PublicationErrorKind::Transport
    );
    assert!(fatal.to_string().contains("failed twice"));
    assert!(runtime.fatal_error().is_some());
    assert!(
        handle.current_record().await.is_err(),
        "public status must not return stale committed data after fatal refresh health"
    );
    assert!(
        runtime
            .shutdown(tokio::time::Instant::now() + Duration::from_secs(2))
            .await
            .is_err(),
        "shutdown must not report success after the authority is persistently unavailable"
    );
}

#[tokio::test]
async fn endpoint_close_while_watcher_is_live_latches_fatal_publication_health() {
    let (authority, _authority_state) = authority().await;
    let client_state = TempDir::new("publisher-endpoint-close-health");
    let endpoint = bind_endpoint(
        DAEMON_TEST_ENDPOINT_PROFILE,
        IdentitySource::Ephemeral,
        RelayCapability::Disabled,
        AddressLookupCapability::Disabled,
    )
    .await
    .unwrap();
    let observed = endpoint
        .addr()
        .ip_addrs()
        .next()
        .copied()
        .expect("test endpoint must expose one direct address");
    let location = NodeLocation::direct(observed).unwrap();
    let config = publisher_config(
        &authority,
        location.clone(),
        Duration::from_secs(30),
        Duration::from_secs(10),
    );
    let (runtime, _) = NodePublicationRuntime::start(
        &client_state.0,
        iroh::SecretKey::generate(),
        config,
        tokio::time::Instant::now() + Duration::from_secs(10),
    )
    .await
    .unwrap();
    let handle = runtime.handle();
    let watcher = spawn_publication_address_watch(
        &endpoint,
        handle.clone(),
        vec![location.clone()],
        vec![location],
    );
    endpoint.close().await;
    let fatal = tokio::time::timeout(Duration::from_secs(1), handle.wait_for_fatal())
        .await
        .expect("endpoint close remained invisible to publication health");
    assert_eq!(
        fatal.kind,
        crate::iroh_publication::PublicationErrorKind::Closed
    );
    assert!(fatal.to_string().contains("endpoint closed"));
    watcher.await.unwrap();

    drop(handle);
    runtime.crash_for_test().await;
    authority.shutdown().await.unwrap();
}

#[tokio::test]
async fn expired_pending_is_not_resurrected_and_high_water_survives_clock_rollback() {
    let (authority, _authority_state) = authority().await;
    let client_state = TempDir::new("publisher-expired-pending");
    let key = iroh::SecretKey::generate();
    let location = NodeLocation::direct("127.0.0.1:4433".parse().unwrap()).unwrap();
    let config = publisher_config(
        &authority,
        location.clone(),
        Duration::from_secs(30),
        Duration::from_secs(10),
    );
    let now = unix_micros().unwrap();
    let future_high_water = now + 500_000;
    let expired_sequence = now - 30_000_001;
    let expired = encode_node_record(
        &key,
        "run-1",
        "authority.test:v1",
        30,
        expired_sequence,
        expired_sequence + 30_000_000,
        PublicationState::Live,
        &[NodeLocation::direct("127.0.0.1:4999".parse().unwrap()).unwrap()],
    )
    .unwrap();
    seed_pending_state_for_test(
        &client_state.0,
        &key,
        &config,
        expired.as_bytes(),
        future_high_water,
    )
    .unwrap();

    let requests_before = authority.request_count();
    let (runtime, recovered) = NodePublicationRuntime::start(
        &client_state.0,
        key,
        config,
        tokio::time::Instant::now() + Duration::from_secs(10),
    )
    .await
    .unwrap();
    assert_eq!(recovered.record.sequence, future_high_water + 1);
    assert_eq!(
        recovered.record.expires_unix_micros,
        recovered.record.sequence + 30_000_000,
        "clock rollback/high-water recovery must derive expiry from the signed sequence"
    );
    assert_eq!(recovered.record.locations, vec![location]);
    assert!(recovered.record.expires_unix_micros > unix_micros().unwrap());
    assert_eq!(
        authority.request_count(),
        requests_before + 2,
        "expired pending must be cleared locally, then only the replacement PUT+GET is sent"
    );
    runtime
        .shutdown(tokio::time::Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    authority.shutdown().await.unwrap();
}

#[tokio::test]
async fn publisher_state_write_failure_is_transactional_and_sends_nothing() {
    let (authority, _authority_state) = authority().await;
    let client_state = TempDir::new("publisher-write-failure");
    let key = iroh::SecretKey::generate();
    let first_location = NodeLocation::direct("127.0.0.1:4433".parse().unwrap()).unwrap();
    let next_location = NodeLocation::direct("127.0.0.1:4434".parse().unwrap()).unwrap();
    let config = publisher_config(
        &authority,
        first_location,
        Duration::from_secs(30),
        Duration::from_secs(10),
    );
    let (runtime, _) = NodePublicationRuntime::start(
        &client_state.0,
        key,
        config,
        tokio::time::Instant::now() + Duration::from_secs(10),
    )
    .await
    .unwrap();
    let handle = runtime.handle();
    let committed_before = handle.committed_packet_for_test().await.unwrap();
    let requests_before = authority.request_count();
    // Both the initial durable-intent write and the one bounded retry must
    // fail. A single transient write failure is expected to recover now.
    handle.fail_next_state_writes_for_test(2);
    let error = handle.update_locations([next_location]).await.unwrap_err();
    assert_eq!(
        error.kind,
        crate::iroh_publication::PublicationErrorKind::State
    );
    assert_eq!(authority.request_count(), requests_before);
    assert_eq!(
        handle.committed_packet_for_test().await.as_deref(),
        Some(committed_before.as_slice())
    );
    assert!(handle.pending_packet_for_test().await.is_none());
    runtime
        .shutdown(tokio::time::Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    authority.shutdown().await.unwrap();
}

#[tokio::test]
async fn unauthorized_location_update_is_an_error_not_old_record_success() {
    let (authority, _authority_state) = authority().await;
    let client_state = TempDir::new("publisher-invalid-update");
    let key = iroh::SecretKey::generate();
    let first_location = NodeLocation::direct("127.0.0.1:4433".parse().unwrap()).unwrap();
    let config = publisher_config(
        &authority,
        first_location.clone(),
        Duration::from_secs(30),
        Duration::from_secs(10),
    );
    let (runtime, _) = NodePublicationRuntime::start(
        &client_state.0,
        key,
        config,
        tokio::time::Instant::now() + Duration::from_secs(10),
    )
    .await
    .unwrap();
    let handle = runtime.handle();
    let requests_before = authority.request_count();
    let error = handle
        .update_locations([NodeLocation::relay("https://relay.example.test").unwrap()])
        .await
        .unwrap_err();
    assert_eq!(
        error.kind,
        crate::iroh_publication::PublicationErrorKind::Configuration
    );
    assert!(error.to_string().contains("explicitly enabled"));
    assert_eq!(authority.request_count(), requests_before);
    let noncanonical = handle
        .update_locations([NodeLocation::Relay(
            "https://RELAY.example.test/".to_string(),
        )])
        .await
        .unwrap_err();
    assert_eq!(
        noncanonical.kind,
        crate::iroh_publication::PublicationErrorKind::Configuration
    );
    assert!(noncanonical.to_string().contains("not canonical"));
    assert_eq!(
        authority.request_count(),
        requests_before,
        "invalid public-variant location reached the authority"
    );
    assert_eq!(
        handle.current_record().await.unwrap().unwrap().locations,
        vec![first_location.clone()]
    );
    assert_eq!(
        handle.desired_locations_for_test().unwrap(),
        vec![first_location]
    );

    runtime
        .shutdown(tokio::time::Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    authority.shutdown().await.unwrap();
}

#[tokio::test]
async fn publisher_post_rename_failure_poison_prevents_stale_memory_use() {
    let (authority, _authority_state) = authority().await;
    let client_state = TempDir::new("publisher-post-rename-poison");
    let key = iroh::SecretKey::generate();
    let config = publisher_config(
        &authority,
        NodeLocation::direct("127.0.0.1:4433".parse().unwrap()).unwrap(),
        Duration::from_secs(30),
        Duration::from_secs(10),
    );
    let (runtime, _) = NodePublicationRuntime::start(
        &client_state.0,
        key,
        config,
        tokio::time::Instant::now() + Duration::from_secs(10),
    )
    .await
    .unwrap();
    let handle = runtime.handle();
    let requests_before = authority.request_count();
    handle.fail_next_post_rename_for_test();
    let first_error = handle
        .update_locations([NodeLocation::direct("127.0.0.1:4434".parse().unwrap()).unwrap()])
        .await
        .unwrap_err();
    assert!(first_error.to_string().contains("poisoned"));
    assert_eq!(authority.request_count(), requests_before);
    assert!(
        handle
            .current_record()
            .await
            .unwrap_err()
            .to_string()
            .contains("poisoned")
    );
    assert!(
        handle
            .update_locations([NodeLocation::direct("127.0.0.1:4435".parse().unwrap()).unwrap()])
            .await
            .unwrap_err()
            .to_string()
            .contains("poisoned")
    );
    assert_eq!(authority.request_count(), requests_before);
    drop(handle);
    runtime.crash_for_test().await;
    authority.shutdown().await.unwrap();
}

#[tokio::test]
async fn corrupt_publisher_state_fails_before_any_authority_request() {
    let (authority, _authority_state) = authority().await;
    let client_state = TempDir::new("publisher-corrupt");
    let key = iroh::SecretKey::generate();
    let config = publisher_config(
        &authority,
        NodeLocation::direct("127.0.0.1:4433".parse().unwrap()).unwrap(),
        Duration::from_secs(30),
        Duration::from_secs(10),
    );
    let (runtime, _) = NodePublicationRuntime::start(
        &client_state.0,
        key.clone(),
        config.clone(),
        tokio::time::Instant::now() + Duration::from_secs(10),
    )
    .await
    .unwrap();
    runtime.crash_for_test().await;
    let state_path = client_state.0.join(PUBLICATION_STATE_FILENAME);
    let mut bytes = std::fs::read(&state_path).unwrap();
    let corrupt_at = bytes.len() / 2;
    bytes[corrupt_at] ^= 1;
    std::fs::write(&state_path, bytes).unwrap();
    let requests_before = authority.request_count();
    let result = NodePublicationRuntime::start(
        &client_state.0,
        key,
        config,
        tokio::time::Instant::now() + Duration::from_secs(10),
    )
    .await;
    assert!(result.is_err());
    assert_eq!(authority.request_count(), requests_before);
    authority.shutdown().await.unwrap();
}

#[tokio::test]
async fn one_file_publisher_state_rollback_is_rejected_by_independent_anchor() {
    let (authority, _authority_state) = authority().await;
    let client_state = TempDir::new("publisher-snapshot-rollback");
    let key = iroh::SecretKey::generate();
    let first_location = NodeLocation::direct("127.0.0.1:4433".parse().unwrap()).unwrap();
    let next_location = NodeLocation::direct("127.0.0.1:4434".parse().unwrap()).unwrap();
    let config = publisher_config(
        &authority,
        first_location,
        Duration::from_secs(30),
        Duration::from_secs(10),
    );
    let (runtime, _) = NodePublicationRuntime::start(
        &client_state.0,
        key.clone(),
        config.clone(),
        tokio::time::Instant::now() + Duration::from_secs(10),
    )
    .await
    .unwrap();
    let state_path = client_state.0.join(PUBLICATION_STATE_FILENAME);
    let old_snapshot = std::fs::read(&state_path).unwrap();
    runtime
        .handle()
        .update_locations([next_location])
        .await
        .unwrap();
    runtime.crash_for_test().await;
    std::fs::write(&state_path, old_snapshot).unwrap();

    let requests_before = authority.request_count();
    let error = NodePublicationRuntime::start(
        &client_state.0,
        key,
        config,
        tokio::time::Instant::now() + Duration::from_secs(10),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("rollback anchor"));
    assert_eq!(authority.request_count(), requests_before);
    authority.shutdown().await.unwrap();
}

#[tokio::test]
async fn empty_effective_startup_is_rejected_before_any_authority_request() {
    let (authority, _authority_state) = authority().await;
    let client_state = TempDir::new("publisher-empty-readiness");
    let key = iroh::SecretKey::generate();
    let config = publisher_config(
        &authority,
        NodeLocation::direct("127.0.0.1:4433".parse().unwrap()).unwrap(),
        Duration::from_secs(30),
        Duration::from_secs(10),
    );
    let requests_before = authority.request_count();
    let error = NodePublicationRuntime::start_with_effective_locations(
        &client_state.0,
        key,
        config,
        Vec::new(),
        tokio::time::Instant::now() + Duration::from_secs(1),
    )
    .await
    .unwrap_err();
    assert_eq!(
        error.kind,
        crate::iroh_publication::PublicationErrorKind::Configuration
    );
    assert!(error.to_string().contains("withdrawal is not readiness"));
    assert_eq!(authority.request_count(), requests_before);
    authority.shutdown().await.unwrap();
}

#[tokio::test]
async fn startup_visibility_failure_publishes_a_higher_tombstone_before_returning() {
    let (authority, _authority_state) = authority().await;
    let client_state = TempDir::new("publisher-startup-cleanup");
    let key = iroh::SecretKey::generate();
    let signer = key.public().to_z32();
    let config = publisher_config(
        &authority,
        NodeLocation::direct("127.0.0.1:4433".parse().unwrap()).unwrap(),
        Duration::from_secs(30),
        Duration::from_secs(10),
    );
    authority.fail_next_visibility_get();
    let error = NodePublicationRuntime::start(
        &client_state.0,
        key.clone(),
        config.clone(),
        tokio::time::Instant::now() + Duration::from_secs(10),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("higher-sequence withdrawal"));
    let packet = authority.packet_for_test(&signer).unwrap();
    let record = decode_node_record(&packet).unwrap();
    assert_eq!(record.state, PublicationState::Withdrawn);
    assert!(record.locations.is_empty());
    assert_eq!(
        authority.request_count(),
        4,
        "live PUT, failed visibility GET, tombstone PUT, visibility GET"
    );

    let tombstone = record;
    let (restarted, live) = NodePublicationRuntime::start(
        &client_state.0,
        key,
        config,
        tokio::time::Instant::now() + Duration::from_secs(10),
    )
    .await
    .unwrap();
    assert_eq!(live.record.state, PublicationState::Live);
    assert!(!live.record.locations.is_empty());
    assert!(live.record.sequence > tombstone.sequence);
    restarted
        .shutdown(tokio::time::Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    authority.shutdown().await.unwrap();
}

#[tokio::test]
async fn in_flight_live_update_cannot_outlive_shutdown_tombstone() {
    let (authority, _authority_state) = authority().await;
    let client_state = TempDir::new("publisher-shutdown-race");
    let key = iroh::SecretKey::generate();
    let signer = key.public().to_z32();
    let first_location = NodeLocation::direct("127.0.0.1:4433".parse().unwrap()).unwrap();
    let next_location = NodeLocation::direct("127.0.0.1:4434".parse().unwrap()).unwrap();
    let config = publisher_config(
        &authority,
        first_location,
        Duration::from_secs(30),
        Duration::from_secs(10),
    );
    let (runtime, _) = NodePublicationRuntime::start(
        &client_state.0,
        key,
        config,
        tokio::time::Instant::now() + Duration::from_secs(10),
    )
    .await
    .unwrap();
    authority.block_next_put();
    let handle = runtime.handle();
    let update = tokio::spawn(async move { handle.update_locations([next_location]).await });
    authority.wait_until_put_blocked().await;
    let withdrawn = runtime
        .shutdown(tokio::time::Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(withdrawn.record.state, PublicationState::Withdrawn);
    assert!(update.await.unwrap().is_err());
    authority.release_blocked_put();
    tokio::time::sleep(Duration::from_millis(50)).await;
    {
        let guarded = authority.inner.state.lock().unwrap();
        let packet = decode_hex(&guarded.1.records[&signer].packet_hex).unwrap();
        let visible = decode_node_record(&packet).unwrap();
        assert_eq!(visible.state, PublicationState::Withdrawn);
    }
    authority.shutdown().await.unwrap();
}

#[test]
fn stale_equal_conflict_and_expired_high_water_are_rejected() {
    let state_dir = TempDir::new("authority-pure");
    let config = PublicationAuthorityConfig {
        listen: "127.0.0.1:39092".parse().unwrap(),
        state_dir: state_dir.0.clone(),
        namespace: "run-1".into(),
        signed_recipient: "authority.test:v1".into(),
        expected_host: "authority.test".into(),
        owner: "test operator".into(),
        signer_admission: AuthoritySignerAdmission::TestOnlyUnrestricted,
    };
    let (store, state) = AuthorityStateStore::open(&config).unwrap();
    let inner = AuthorityInner {
        config,
        monotonic_expiry: Mutex::new(monotonic_expiry_deadlines(&state, unix_micros().unwrap())),
        state: Mutex::new((store, state)),
        request_count: AtomicU64::new(0),
        block_next_put: AtomicU64::new(0),
        put_started: Notify::new(),
        release_put: Notify::new(),
        idempotent_puts: AtomicU64::new(0),
        fail_next_get: AtomicU64::new(0),
    };
    let key = iroh::SecretKey::generate();
    let signer = key.public().to_z32();
    let now = unix_micros().unwrap();
    let location = NodeLocation::direct("127.0.0.1:4433".parse().unwrap()).unwrap();
    let packet = encode_node_record(
        &key,
        "run-1",
        "authority.test:v1",
        30,
        now,
        now + 30_000_000,
        PublicationState::Live,
        std::slice::from_ref(&location),
    )
    .unwrap();
    let first = apply_request(
        &inner,
        AuthorityRequest {
            method: "PUT".into(),
            signer: signer.clone(),
            body: packet.to_relay_payload(),
        },
    )
    .unwrap();
    assert_eq!(first.status, 201);
    let writes_after_first = inner
        .state
        .lock()
        .unwrap()
        .0
        .successful_writes
        .load(Ordering::Acquire);
    let exact = apply_request(
        &inner,
        AuthorityRequest {
            method: "PUT".into(),
            signer: signer.clone(),
            body: packet.to_relay_payload(),
        },
    )
    .unwrap();
    assert_eq!(exact.status, 200);
    assert_eq!(
        apply_request(
            &inner,
            AuthorityRequest {
                method: "GET".into(),
                signer: signer.clone(),
                body: Vec::new(),
            },
        )
        .unwrap()
        .status,
        200
    );
    assert_eq!(
        inner
            .state
            .lock()
            .unwrap()
            .0
            .successful_writes
            .load(Ordering::Acquire),
        writes_after_first,
        "idempotent PUT and sub-granularity live GET must not add fsync transactions"
    );
    let stale = encode_node_record(
        &key,
        "run-1",
        "authority.test:v1",
        30,
        now - 1,
        now - 1 + 30_000_000,
        PublicationState::Live,
        &[location],
    )
    .unwrap();
    let rejected = apply_request(
        &inner,
        AuthorityRequest {
            method: "PUT".into(),
            signer,
            body: stale.to_relay_payload(),
        },
    )
    .unwrap();
    assert_eq!(rejected.status, 409);
}

#[test]
fn expired_record_stays_invisible_and_high_water_survives_restart() {
    let state_dir = TempDir::new("authority-expired-restart");
    let config = PublicationAuthorityConfig {
        listen: "127.0.0.1:39094".parse().unwrap(),
        state_dir: state_dir.0.clone(),
        namespace: "run-1".into(),
        signed_recipient: "authority.test:v1".into(),
        expected_host: "authority.test".into(),
        owner: "test operator".into(),
        signer_admission: AuthoritySignerAdmission::TestOnlyUnrestricted,
    };
    let key = iroh::SecretKey::generate();
    let signer = key.public().to_z32();
    let sequence = unix_micros().unwrap() - 2_000_000;
    let expiring = encode_node_record(
        &key,
        "run-1",
        "authority.test:v1",
        1,
        sequence,
        sequence + 1_000_000,
        PublicationState::Live,
        &[NodeLocation::direct("127.0.0.1:4433".parse().unwrap()).unwrap()],
    )
    .unwrap();
    {
        let (store, state) = AuthorityStateStore::open(&config).unwrap();
        let inner = AuthorityInner {
            config: config.clone(),
            monotonic_expiry: Mutex::new(monotonic_expiry_deadlines(&state, sequence)),
            state: Mutex::new((store, state)),
            request_count: AtomicU64::new(0),
            block_next_put: AtomicU64::new(0),
            put_started: Notify::new(),
            release_put: Notify::new(),
            idempotent_puts: AtomicU64::new(0),
            fail_next_get: AtomicU64::new(0),
        };
        assert_eq!(
            apply_request_at(
                &inner,
                AuthorityRequest {
                    method: "PUT".into(),
                    signer: signer.clone(),
                    body: expiring.to_relay_payload(),
                },
                sequence,
            )
            .unwrap()
            .status,
            201
        );
    }

    let (store, state) = AuthorityStateStore::open(&config).unwrap();
    assert_eq!(state.records[&signer].high_water_sequence, sequence);
    let inner = AuthorityInner {
        config: config.clone(),
        monotonic_expiry: Mutex::new(monotonic_expiry_deadlines(&state, sequence)),
        state: Mutex::new((store, state)),
        request_count: AtomicU64::new(0),
        block_next_put: AtomicU64::new(0),
        put_started: Notify::new(),
        release_put: Notify::new(),
        idempotent_puts: AtomicU64::new(0),
        fail_next_get: AtomicU64::new(0),
    };
    assert_eq!(
        apply_request_at(
            &inner,
            AuthorityRequest {
                method: "GET".into(),
                signer: signer.clone(),
                body: Vec::new(),
            },
            sequence + 1_000_000,
        )
        .unwrap()
        .status,
        404
    );
    assert!(inner.state.lock().unwrap().1.records[&signer].expired);
    drop(inner);

    let (store, state) = AuthorityStateStore::open(&config).unwrap();
    assert!(state.records[&signer].expired);
    let inner = AuthorityInner {
        config,
        monotonic_expiry: Mutex::new(monotonic_expiry_deadlines(&state, sequence)),
        state: Mutex::new((store, state)),
        request_count: AtomicU64::new(0),
        block_next_put: AtomicU64::new(0),
        put_started: Notify::new(),
        release_put: Notify::new(),
        idempotent_puts: AtomicU64::new(0),
        fail_next_get: AtomicU64::new(0),
    };
    assert_eq!(
        apply_request_at(
            &inner,
            AuthorityRequest {
                method: "GET".into(),
                signer: signer.clone(),
                body: Vec::new(),
            },
            sequence,
        )
        .unwrap()
        .status,
        404,
        "durable expiry latch must survive restart and wall-clock rollback"
    );
    assert_eq!(
        apply_request_at(
            &inner,
            AuthorityRequest {
                method: "PUT".into(),
                signer: signer.clone(),
                body: expiring.to_relay_payload(),
            },
            sequence,
        )
        .unwrap()
        .status,
        409,
        "an expired exact replay must never become visible again"
    );

    let now = sequence;
    for (label, rejected) in [
        (
            "lower-sequence",
            encode_node_record(
                &key,
                "run-1",
                "authority.test:v1",
                1,
                sequence - 1,
                sequence - 1 + 1_000_000,
                PublicationState::Live,
                &[NodeLocation::direct("127.0.0.1:4434".parse().unwrap()).unwrap()],
            )
            .unwrap(),
        ),
        (
            "equal-sequence-different-bytes",
            encode_node_record(
                &key,
                "run-1",
                "authority.test:v1",
                1,
                sequence,
                sequence + 1_000_000,
                PublicationState::Live,
                &[NodeLocation::direct("127.0.0.1:4435".parse().unwrap()).unwrap()],
            )
            .unwrap(),
        ),
    ] {
        assert_eq!(
            apply_request_at(
                &inner,
                AuthorityRequest {
                    method: "PUT".into(),
                    signer: signer.clone(),
                    body: rejected.to_relay_payload(),
                },
                now,
            )
            .unwrap()
            .status,
            409,
            "{label} bypassed durable authority high-water"
        );
    }
    assert_eq!(
        apply_request_at(
            &inner,
            AuthorityRequest {
                method: "GET".into(),
                signer,
                body: Vec::new(),
            },
            now,
        )
        .unwrap()
        .status,
        404
    );
}

#[test]
fn failed_authority_persistence_does_not_mutate_live_state() {
    let state_dir = TempDir::new("authority-transaction");
    let config = PublicationAuthorityConfig {
        listen: "127.0.0.1:39093".parse().unwrap(),
        state_dir: state_dir.0.clone(),
        namespace: "run-1".into(),
        signed_recipient: "authority.test:v1".into(),
        expected_host: "authority.test".into(),
        owner: "test operator".into(),
        signer_admission: AuthoritySignerAdmission::TestOnlyUnrestricted,
    };
    let (store, mut state) = AuthorityStateStore::open(&config).unwrap();
    let key = iroh::SecretKey::generate();
    let signer = key.public().to_z32();
    let now = unix_micros().unwrap();
    let packet = encode_node_record(
        &key,
        "run-1",
        "authority.test:v1",
        30,
        now,
        now + 30_000_000,
        PublicationState::Live,
        &[NodeLocation::direct("127.0.0.1:4433".parse().unwrap()).unwrap()],
    )
    .unwrap();
    state.records.insert(
        signer.clone(),
        AuthorityEntry {
            high_water_sequence: now,
            expires_unix_micros: now + 30_000_000,
            state: AuthorityRecordState::Live,
            expired: false,
            packet_hex: encode_hex(packet.as_bytes()),
        },
    );
    store.write(&state).unwrap();
    let inner = AuthorityInner {
        config,
        monotonic_expiry: Mutex::new(monotonic_expiry_deadlines(&state, unix_micros().unwrap())),
        state: Mutex::new((store, state)),
        request_count: AtomicU64::new(0),
        block_next_put: AtomicU64::new(0),
        put_started: Notify::new(),
        release_put: Notify::new(),
        idempotent_puts: AtomicU64::new(0),
        fail_next_get: AtomicU64::new(0),
    };
    let newer = encode_node_record(
        &key,
        "run-1",
        "authority.test:v1",
        30,
        now + 1,
        now + 1 + 30_000_000,
        PublicationState::Live,
        &[NodeLocation::direct("127.0.0.1:4434".parse().unwrap()).unwrap()],
    )
    .unwrap();
    inner
        .state
        .lock()
        .unwrap()
        .0
        .fail_next_write
        .store(true, Ordering::Release);
    assert!(
        apply_request(
            &inner,
            AuthorityRequest {
                method: "PUT".into(),
                signer: signer.clone(),
                body: newer.to_relay_payload(),
            },
        )
        .is_err()
    );
    assert_eq!(
        inner.state.lock().unwrap().1.records[&signer].high_water_sequence,
        now
    );
}

#[test]
fn authority_post_rename_failure_poison_prevents_stale_get_or_write() {
    let state_dir = TempDir::new("authority-post-rename-poison");
    let config = PublicationAuthorityConfig {
        listen: "127.0.0.1:39095".parse().unwrap(),
        state_dir: state_dir.0.clone(),
        namespace: "run-1".into(),
        signed_recipient: "authority.test:v1".into(),
        expected_host: "authority.test".into(),
        owner: "test operator".into(),
        signer_admission: AuthoritySignerAdmission::TestOnlyUnrestricted,
    };
    let key = iroh::SecretKey::generate();
    let signer = key.public().to_z32();
    let now = unix_micros().unwrap();
    let first = encode_node_record(
        &key,
        "run-1",
        "authority.test:v1",
        30,
        now,
        now + 30_000_000,
        PublicationState::Live,
        &[NodeLocation::direct("127.0.0.1:4433".parse().unwrap()).unwrap()],
    )
    .unwrap();
    let newer = encode_node_record(
        &key,
        "run-1",
        "authority.test:v1",
        30,
        now + 1,
        now + 1 + 30_000_000,
        PublicationState::Live,
        &[NodeLocation::direct("127.0.0.1:4434".parse().unwrap()).unwrap()],
    )
    .unwrap();
    {
        let (store, state) = AuthorityStateStore::open(&config).unwrap();
        let inner = AuthorityInner {
            config: config.clone(),
            monotonic_expiry: Mutex::new(monotonic_expiry_deadlines(
                &state,
                unix_micros().unwrap(),
            )),
            state: Mutex::new((store, state)),
            request_count: AtomicU64::new(0),
            block_next_put: AtomicU64::new(0),
            put_started: Notify::new(),
            release_put: Notify::new(),
            idempotent_puts: AtomicU64::new(0),
            fail_next_get: AtomicU64::new(0),
        };
        assert_eq!(
            apply_request(
                &inner,
                AuthorityRequest {
                    method: "PUT".into(),
                    signer: signer.clone(),
                    body: first.to_relay_payload(),
                },
            )
            .unwrap()
            .status,
            201
        );
        inner
            .state
            .lock()
            .unwrap()
            .0
            .fail_next_post_rename
            .store(true, Ordering::Release);
        assert!(
            apply_request(
                &inner,
                AuthorityRequest {
                    method: "PUT".into(),
                    signer: signer.clone(),
                    body: newer.to_relay_payload(),
                },
            )
            .unwrap_err()
            .to_string()
            .contains("poisoned")
        );
        assert!(
            apply_request(
                &inner,
                AuthorityRequest {
                    method: "GET".into(),
                    signer: signer.clone(),
                    body: Vec::new(),
                },
            )
            .is_err()
        );
        assert!(
            apply_request(
                &inner,
                AuthorityRequest {
                    method: "PUT".into(),
                    signer: signer.clone(),
                    body: first.to_relay_payload(),
                },
            )
            .is_err()
        );
    }
    let (_store, state) = AuthorityStateStore::open(&config).unwrap();
    assert_eq!(state.records[&signer].high_water_sequence, now + 1);
    assert_eq!(
        decode_hex(&state.records[&signer].packet_hex).unwrap(),
        newer.as_bytes()
    );
}

#[test]
fn one_file_valid_snapshot_rollback_is_rejected_by_consistency_anchor() {
    let state_dir = TempDir::new("authority-snapshot-rollback");
    let config = PublicationAuthorityConfig {
        listen: "127.0.0.1:39096".parse().unwrap(),
        state_dir: state_dir.0.clone(),
        namespace: "run-1".into(),
        signed_recipient: "authority.test:v1".into(),
        expected_host: "authority.test".into(),
        owner: "test operator".into(),
        signer_admission: AuthoritySignerAdmission::TestOnlyUnrestricted,
    };
    let key = iroh::SecretKey::generate();
    let signer = key.public().to_z32();
    let now = unix_micros().unwrap();
    let packet = |sequence, port| {
        encode_node_record(
            &key,
            "run-1",
            "authority.test:v1",
            30,
            sequence,
            sequence + 30_000_000,
            PublicationState::Live,
            &[NodeLocation::direct(SocketAddr::from(([127, 0, 0, 1], port))).unwrap()],
        )
        .unwrap()
    };
    let first = packet(now, 4433);
    let second = packet(now + 1, 4434);
    {
        let (store, state) = AuthorityStateStore::open(&config).unwrap();
        let inner = AuthorityInner {
            config: config.clone(),
            monotonic_expiry: Mutex::new(BTreeMap::new()),
            state: Mutex::new((store, state)),
            request_count: AtomicU64::new(0),
            block_next_put: AtomicU64::new(0),
            put_started: Notify::new(),
            release_put: Notify::new(),
            idempotent_puts: AtomicU64::new(0),
            fail_next_get: AtomicU64::new(0),
        };
        assert_eq!(
            apply_request_at(
                &inner,
                AuthorityRequest {
                    method: "PUT".into(),
                    signer: signer.clone(),
                    body: first.to_relay_payload(),
                },
                now,
            )
            .unwrap()
            .status,
            201
        );
        let old_snapshot = std::fs::read(state_dir.0.join(AUTHORITY_STATE_FILENAME)).unwrap();
        assert_eq!(
            apply_request_at(
                &inner,
                AuthorityRequest {
                    method: "PUT".into(),
                    signer: signer.clone(),
                    body: second.to_relay_payload(),
                },
                now,
            )
            .unwrap()
            .status,
            201
        );
        drop(inner);
        std::fs::write(state_dir.0.join(AUTHORITY_STATE_FILENAME), old_snapshot).unwrap();
    }
    let error = match AuthorityStateStore::open(&config) {
        Err(error) => error,
        Ok(_) => panic!("one-file state rollback unexpectedly passed its anchor"),
    };
    assert!(error.to_string().contains("rollback anchor"));
}
