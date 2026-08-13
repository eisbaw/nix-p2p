use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use daemon::{
    AddressLookupCapability, EndpointProfile, EndpointScope, IdentitySource, IrohRuntimeBuilder,
    NodeId, NodeLocation, NodeLookupAuthorityAuthorization, NodeLookupConfig,
    NodeLookupUnavailableKind, PublicationState, RelayCapability, ShutdownOutcome,
    encode_node_record,
};
use iroh::SecretKey;
use iroh_dns::pkarr::{SignedPacket, Timestamp};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

#[derive(Clone)]
struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

impl HttpResponse {
    fn ok(body: Vec<u8>) -> Self {
        Self { status: 200, body }
    }

    fn not_found() -> Self {
        Self {
            status: 404,
            body: Vec::new(),
        }
    }
}

async fn scripted_authority(
    responses: Vec<HttpResponse>,
) -> (SocketAddr, tokio::task::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut requests = Vec::new();
        for response in responses {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_request(&mut stream).await;
            requests.push(String::from_utf8(request).unwrap());
            let reason = match response.status {
                200 => "OK",
                404 => "Not Found",
                _ => "Error",
            };
            let headers = format!(
                "HTTP/1.1 {} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response.status,
                response.body.len()
            );
            stream.write_all(headers.as_bytes()).await.unwrap();
            stream.write_all(&response.body).await.unwrap();
            stream.shutdown().await.unwrap();
        }
        requests
    });
    (address, task)
}

async fn synchronized_routed_authority(
    responses: Vec<(NodeId, HttpResponse)>,
    expected_requests: usize,
) -> (SocketAddr, tokio::task::JoinHandle<Vec<String>>) {
    assert!(expected_requests > 1);
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let routes = Arc::new(
        responses
            .into_iter()
            .map(|(node_id, response)| (signer_path(node_id), response))
            .collect::<HashMap<_, _>>(),
    );
    let barrier = Arc::new(tokio::sync::Barrier::new(expected_requests));
    let task = tokio::spawn(async move {
        let mut handlers = tokio::task::JoinSet::new();
        for _ in 0..expected_requests {
            let (mut stream, _) = listener.accept().await.unwrap();
            let routes = routes.clone();
            let barrier = barrier.clone();
            handlers.spawn(async move {
                let request = String::from_utf8(read_request(&mut stream).await).unwrap();
                let path = request
                    .lines()
                    .next()
                    .and_then(|line| line.strip_prefix("GET "))
                    .and_then(|line| line.strip_suffix(" HTTP/1.1"))
                    .expect("lookup request line must be canonical");
                let response = routes
                    .get(path)
                    .unwrap_or_else(|| panic!("no response routed for {path}"));
                barrier.wait().await;
                let reason = match response.status {
                    200 => "OK",
                    404 => "Not Found",
                    _ => "Error",
                };
                let headers = format!(
                    "HTTP/1.1 {} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    response.status,
                    response.body.len()
                );
                stream.write_all(headers.as_bytes()).await.unwrap();
                stream.write_all(&response.body).await.unwrap();
                stream.shutdown().await.unwrap();
                request
            });
        }
        let mut requests = Vec::with_capacity(expected_requests);
        while let Some(result) = handlers.join_next().await {
            requests.push(result.unwrap());
        }
        requests
    });
    (address, task)
}

async fn read_request(stream: &mut TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        let mut chunk = [0u8; 1024];
        let read = stream.read(&mut chunk).await.unwrap();
        assert_ne!(read, 0, "request ended before headers");
        request.extend_from_slice(&chunk[..read]);
        assert!(request.len() < 8192, "request headers exceeded test bound");
    }
    request
}

fn now_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64
}

fn signed_payload(
    key: &SecretKey,
    namespace: &str,
    recipient: &str,
    sequence: u64,
    ttl_seconds: u32,
    state: PublicationState,
    locations: &[NodeLocation],
) -> Vec<u8> {
    encode_node_record(
        key,
        namespace,
        recipient,
        ttl_seconds,
        sequence,
        sequence + u64::from(ttl_seconds) * 1_000_000,
        state,
        locations,
    )
    .unwrap()
    .to_relay_payload()
}

fn schema_invalid_but_validly_signed_payload(
    key: &SecretKey,
    sequence: u64,
    locations: &[NodeLocation],
) -> Vec<u8> {
    let packet = encode_node_record(
        key,
        "lookup-test",
        "authority.test:v1",
        30,
        sequence,
        sequence + 30_000_000,
        PublicationState::Live,
        locations,
    )
    .unwrap();
    let mut dns = packet.encoded_packet().to_vec();
    let old = b"iroh-node-publication-v1";
    let new = b"iroh-node-publication-v2";
    let offset = dns
        .windows(old.len())
        .position(|window| window == old)
        .expect("schema TXT is present");
    dns[offset..offset + old.len()].copy_from_slice(new);
    let mut signable = format!("3:seqi{sequence}e1:v{}:", dns.len()).into_bytes();
    signable.extend_from_slice(&dns);
    let signature = key.sign(&signable);
    let mut bytes = Vec::with_capacity(104 + dns.len());
    bytes.extend_from_slice(key.public().as_bytes());
    bytes.extend_from_slice(&signature.to_bytes());
    bytes.extend_from_slice(&Timestamp::from_micros(sequence).to_be_bytes());
    bytes.extend_from_slice(&dns);
    SignedPacket::from_bytes(&bytes).unwrap().to_relay_payload()
}

fn config(authority: SocketAddr) -> NodeLookupConfig {
    NodeLookupConfig::new(
        "lookup-test",
        "authority.test:v1",
        authority,
        "authority.test",
        NodeLookupAuthorityAuthorization::LocalProductionShaped {
            owner: "test-operator".into(),
        },
    )
    .unwrap()
}

async fn runtime(authority: SocketAddr) -> daemon::IrohNodeRuntime {
    IrohRuntimeBuilder::new(
        EndpointProfile {
            scope: EndpointScope::Global { port: 0 },
        },
        IdentitySource::Ephemeral,
        RelayCapability::Disabled,
        AddressLookupCapability::PinnedPkarr(config(authority)),
    )
    .unwrap()
    .spawn()
    .await
    .unwrap()
}

fn direct(address: &str) -> NodeLocation {
    NodeLocation::direct(address.parse().unwrap()).unwrap()
}

fn signer_path(node_id: NodeId) -> String {
    let signer = iroh::PublicKey::from_bytes(node_id.as_bytes())
        .unwrap()
        .to_z32();
    format!("/pkarr/{signer}")
}

fn canonical_get(node_id: NodeId) -> String {
    format!(
        "GET {} HTTP/1.1\r\nHost: authority.test\r\nContent-Type: application/x-pkarr-signed-packet\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        signer_path(node_id)
    )
}

fn assert_get_only(requests: &[String], node_id: NodeId) {
    let expected = canonical_get(node_id);
    assert!(!requests.is_empty());
    for request in requests {
        assert_eq!(
            request, &expected,
            "lookup must emit one canonical zero-body GET and nothing else"
        );
    }
}

#[tokio::test]
async fn one_typed_node_resolves_and_the_installed_iroh_registry_returns_an_item() {
    let key = SecretKey::generate();
    let node_id = NodeId::from_bytes(*key.public().as_bytes());
    let sequence = now_micros().saturating_sub(100_000);
    let locations = vec![
        direct("192.0.2.9:4433"),
        NodeLocation::relay("https://relay.example".to_string()).unwrap(),
    ];
    let payload = signed_payload(
        &key,
        "lookup-test",
        "authority.test:v1",
        sequence,
        30,
        PublicationState::Live,
        &locations,
    );
    let (authority, server) = scripted_authority(vec![
        HttpResponse::ok(payload.clone()),
        HttpResponse::ok(payload),
    ])
    .await;
    let runtime = runtime(authority).await;
    let capabilities = runtime.capability_state().unwrap();
    assert_eq!(capabilities.address_lookup_services, 1);
    assert!(capabilities.node_lookup_enabled);
    let result = runtime
        .node_lookup_handle()
        .unwrap()
        .resolve(node_id)
        .await
        .unwrap();
    assert_eq!(result.node_id(), node_id);
    assert_eq!(result.namespace(), "lookup-test");
    assert_eq!(result.recipient(), "authority.test:v1");
    assert_eq!(result.sequence(), sequence);
    assert_eq!(result.candidates(), locations);
    assert_eq!(
        result.provenance(),
        daemon::NodeLookupProvenance::NetworkValidated
    );

    let item = runtime
        .resolve_registered_node_lookup(node_id)
        .await
        .unwrap();
    assert_eq!(item.endpoint_id(), key.public());
    assert_eq!(item.provenance(), daemon::NODE_LOOKUP_PROVENANCE);
    assert_eq!(item.last_updated(), Some(sequence));
    assert_eq!(item.to_endpoint_addr().ip_addrs().count(), 1);
    assert_eq!(item.to_endpoint_addr().relay_urls().count(), 1);
    assert_eq!(runtime.shutdown().await.unwrap(), ShutdownOutcome::Graceful);
    let requests = server.await.unwrap();
    assert_eq!(requests.len(), 2);
    assert_get_only(&requests, node_id);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_wire_lookups_serialize_replay_state_without_false_capacity() {
    let first_key = SecretKey::generate();
    let second_key = SecretKey::generate();
    let first_node = NodeId::from_bytes(*first_key.public().as_bytes());
    let second_node = NodeId::from_bytes(*second_key.public().as_bytes());
    let sequence = now_micros().saturating_sub(100_000);
    let first_payload = signed_payload(
        &first_key,
        "lookup-test",
        "authority.test:v1",
        sequence,
        30,
        PublicationState::Live,
        &[direct("192.0.2.31:4433")],
    );
    let second_payload = signed_payload(
        &second_key,
        "lookup-test",
        "authority.test:v1",
        sequence,
        30,
        PublicationState::Live,
        &[direct("192.0.2.32:4433")],
    );
    let (authority, server) = synchronized_routed_authority(
        vec![
            (first_node, HttpResponse::ok(first_payload)),
            (second_node, HttpResponse::ok(second_payload)),
        ],
        2,
    )
    .await;
    let distinct_runtime = runtime(authority).await;
    let handle = distinct_runtime.node_lookup_handle().unwrap();
    let (first, second) = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(handle.resolve(first_node), handle.resolve(second_node))
    })
    .await
    .expect("both distinct-NodeId lookups must complete");
    assert_eq!(first.unwrap().node_id(), first_node);
    assert_eq!(second.unwrap().node_id(), second_node);
    distinct_runtime.shutdown().await.unwrap();
    let requests = server.await.unwrap();
    assert_eq!(requests.len(), 2);
    let first_get = canonical_get(first_node);
    let second_get = canonical_get(second_node);
    assert_eq!(
        requests
            .iter()
            .filter(|request| *request == &first_get)
            .count(),
        1,
        "the first NodeId must emit exactly one GET"
    );
    assert_eq!(
        requests
            .iter()
            .filter(|request| *request == &second_get)
            .count(),
        1,
        "the second NodeId must emit exactly one GET"
    );

    let same_key = SecretKey::generate();
    let same_node = NodeId::from_bytes(*same_key.public().as_bytes());
    let same_sequence = now_micros().saturating_sub(100_000);
    let same_payload = signed_payload(
        &same_key,
        "lookup-test",
        "authority.test:v1",
        same_sequence,
        30,
        PublicationState::Live,
        &[direct("192.0.2.33:4433")],
    );
    let (authority, server) =
        synchronized_routed_authority(vec![(same_node, HttpResponse::ok(same_payload))], 2).await;
    let same_runtime = runtime(authority).await;
    let handle = same_runtime.node_lookup_handle().unwrap();
    let (first, second) = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(handle.resolve(same_node), handle.resolve(same_node))
    })
    .await
    .expect("both same-NodeId lookups must complete");
    assert_eq!(first.unwrap().sequence(), same_sequence);
    assert_eq!(second.unwrap().sequence(), same_sequence);
    same_runtime.shutdown().await.unwrap();
    let requests = server.await.unwrap();
    assert_eq!(requests.len(), 2);
    assert_get_only(&requests, same_node);
}

#[tokio::test]
async fn missing_bad_signature_namespace_and_recipient_are_distinct_unavailable_reasons() {
    let key = SecretKey::generate();
    let node_id = NodeId::from_bytes(*key.public().as_bytes());
    let sequence = now_micros().saturating_sub(100_000);
    let location = [direct("192.0.2.10:4433")];
    let mut bad_signature = signed_payload(
        &key,
        "lookup-test",
        "authority.test:v1",
        sequence,
        30,
        PublicationState::Live,
        &location,
    );
    bad_signature[0] ^= 0x80;
    let namespace = signed_payload(
        &key,
        "other-namespace",
        "authority.test:v1",
        sequence + 1,
        30,
        PublicationState::Live,
        &location,
    );
    let recipient = signed_payload(
        &key,
        "lookup-test",
        "other-authority:v1",
        sequence + 2,
        30,
        PublicationState::Live,
        &location,
    );
    let (authority, server) = scripted_authority(vec![
        HttpResponse::not_found(),
        HttpResponse::ok(bad_signature),
        HttpResponse::ok(namespace),
        HttpResponse::ok(recipient),
    ])
    .await;
    let runtime = runtime(authority).await;
    let handle = runtime.node_lookup_handle().unwrap();
    for expected in [
        NodeLookupUnavailableKind::EmptyNamespace,
        NodeLookupUnavailableKind::BadSignature,
        NodeLookupUnavailableKind::NamespaceMismatch,
        NodeLookupUnavailableKind::RecipientMismatch,
    ] {
        let error = handle.resolve(node_id).await.unwrap_err();
        assert_eq!(error.kind(), expected, "unexpected error: {error}");
    }
    runtime.shutdown().await.unwrap();
    let requests = server.await.unwrap();
    assert_get_only(&requests, node_id);
}

#[tokio::test]
async fn runtime_high_water_rejects_lower_and_equal_sequence_conflicts() {
    let key = SecretKey::generate();
    let node_id = NodeId::from_bytes(*key.public().as_bytes());
    let base = now_micros().saturating_sub(1_000_000);
    let high = signed_payload(
        &key,
        "lookup-test",
        "authority.test:v1",
        base + 10,
        30,
        PublicationState::Live,
        &[direct("192.0.2.11:4433")],
    );
    let low = signed_payload(
        &key,
        "lookup-test",
        "authority.test:v1",
        base,
        30,
        PublicationState::Live,
        &[direct("192.0.2.11:4433")],
    );
    let conflict = signed_payload(
        &key,
        "lookup-test",
        "authority.test:v1",
        base + 10,
        30,
        PublicationState::Live,
        &[direct("192.0.2.12:4433")],
    );
    let (authority, server) = scripted_authority(vec![
        HttpResponse::ok(high),
        HttpResponse::ok(low),
        HttpResponse::ok(conflict),
    ])
    .await;
    let runtime = runtime(authority).await;
    let handle = runtime.node_lookup_handle().unwrap();
    handle.resolve(node_id).await.unwrap();
    assert_eq!(
        handle.resolve(node_id).await.unwrap_err().kind(),
        NodeLookupUnavailableKind::StaleSequence
    );
    assert_eq!(
        handle.resolve(node_id).await.unwrap_err().kind(),
        NodeLookupUnavailableKind::ConflictingReplay
    );
    runtime.shutdown().await.unwrap();
    let requests = server.await.unwrap();
    assert_get_only(&requests, node_id);
}

#[tokio::test]
async fn higher_expired_and_withdrawn_records_advance_high_water() {
    for (state, expected) in [
        (PublicationState::Live, NodeLookupUnavailableKind::Expired),
        (
            PublicationState::Withdrawn,
            NodeLookupUnavailableKind::Withdrawn,
        ),
    ] {
        let key = SecretKey::generate();
        let node_id = NodeId::from_bytes(*key.public().as_bytes());
        let now = now_micros();
        let high_sequence = if state == PublicationState::Live {
            now.saturating_sub(2_000_000)
        } else {
            now.saturating_sub(100_000)
        };
        let high_locations = if state == PublicationState::Live {
            vec![direct("192.0.2.13:4433")]
        } else {
            Vec::new()
        };
        let high = signed_payload(
            &key,
            "lookup-test",
            "authority.test:v1",
            high_sequence,
            1,
            state,
            &high_locations,
        );
        let low = signed_payload(
            &key,
            "lookup-test",
            "authority.test:v1",
            high_sequence.saturating_sub(1),
            30,
            PublicationState::Live,
            &[direct("192.0.2.14:4433")],
        );
        let (authority, server) =
            scripted_authority(vec![HttpResponse::ok(high), HttpResponse::ok(low)]).await;
        let runtime = runtime(authority).await;
        let handle = runtime.node_lookup_handle().unwrap();
        assert_eq!(handle.resolve(node_id).await.unwrap_err().kind(), expected);
        assert_eq!(
            handle.resolve(node_id).await.unwrap_err().kind(),
            NodeLookupUnavailableKind::StaleSequence
        );
        runtime.shutdown().await.unwrap();
        let requests = server.await.unwrap();
        assert_get_only(&requests, node_id);
    }
}

#[tokio::test]
async fn offline_and_disabled_modes_reject_before_any_authority_request() {
    let (authority, server) = scripted_authority(Vec::new()).await;
    let offline = IrohRuntimeBuilder::new(
        EndpointProfile {
            scope: EndpointScope::OfflineTest { port: 0 },
        },
        IdentitySource::Ephemeral,
        RelayCapability::Disabled,
        AddressLookupCapability::PinnedPkarr(config(authority)),
    );
    assert!(offline.is_err());
    let disabled = IrohRuntimeBuilder::new(
        EndpointProfile {
            scope: EndpointScope::Global { port: 0 },
        },
        IdentitySource::Ephemeral,
        RelayCapability::Disabled,
        AddressLookupCapability::Disabled,
    )
    .unwrap()
    .spawn()
    .await
    .unwrap();
    assert!(disabled.node_lookup_handle().is_none());
    disabled.shutdown().await.unwrap();
    assert!(server.await.unwrap().is_empty());
}

#[tokio::test]
async fn enabling_lookup_alone_is_network_inert_until_one_typed_query() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let authority = listener.local_addr().unwrap();
    let runtime = runtime(authority).await;
    assert!(runtime.node_lookup_handle().is_some());
    assert!(
        tokio::time::timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err(),
        "enabling node lookup emitted a request without an asker"
    );
    runtime.shutdown().await.unwrap();
}

#[tokio::test]
async fn refused_authority_is_typed_and_never_becomes_content_miss() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let authority = listener.local_addr().unwrap();
    drop(listener);
    let runtime = runtime(authority).await;
    let key = SecretKey::generate();
    let error = runtime
        .node_lookup_handle()
        .unwrap()
        .resolve(NodeId::from_bytes(*key.public().as_bytes()))
        .await
        .unwrap_err();
    assert_eq!(
        error.kind(),
        NodeLookupUnavailableKind::AuthorityConnectionRefused
    );
    assert!(!error.to_string().contains("MISS"));
    runtime.shutdown().await.unwrap();
}

#[tokio::test]
async fn prior_success_is_never_returned_after_authority_outage() {
    let key = SecretKey::generate();
    let node_id = NodeId::from_bytes(*key.public().as_bytes());
    let sequence = now_micros().saturating_sub(100_000);
    let payload = signed_payload(
        &key,
        "lookup-test",
        "authority.test:v1",
        sequence,
        30,
        PublicationState::Live,
        &[direct("192.0.2.15:4433")],
    );
    let (authority, server) = scripted_authority(vec![HttpResponse::ok(payload)]).await;
    let runtime = runtime(authority).await;
    let handle = runtime.node_lookup_handle().unwrap();
    handle.resolve(node_id).await.unwrap();
    let requests = server.await.unwrap();
    assert_get_only(&requests, node_id);
    let outage = handle.resolve(node_id).await.unwrap_err();
    assert_eq!(
        outage.kind(),
        NodeLookupUnavailableKind::AuthorityConnectionRefused
    );
    assert!(!outage.to_string().contains("MISS"));
    runtime.shutdown().await.unwrap();
}

#[tokio::test]
async fn global_and_scoped_ipv6_candidates_survive_strict_lookup() {
    let key = SecretKey::generate();
    let node_id = NodeId::from_bytes(*key.public().as_bytes());
    let sequence = now_micros().saturating_sub(100_000);
    let locations = vec![direct("[2001:db8::1]:4433"), direct("[fe80::1%3]:4433")];
    assert!(NodeLocation::direct("[fe80::1]:4433".parse().unwrap()).is_err());
    let payload = signed_payload(
        &key,
        "lookup-test",
        "authority.test:v1",
        sequence,
        30,
        PublicationState::Live,
        &locations,
    );
    let (authority, server) = scripted_authority(vec![HttpResponse::ok(payload)]).await;
    let runtime = runtime(authority).await;
    let result = runtime
        .node_lookup_handle()
        .unwrap()
        .resolve(node_id)
        .await
        .unwrap();
    assert_eq!(result.candidates(), locations);
    assert_eq!(result.endpoint_addr().unwrap().ip_addrs().count(), 2);
    runtime.shutdown().await.unwrap();
    assert_get_only(&server.await.unwrap(), node_id);
}

#[tokio::test]
async fn valid_signature_with_unsupported_schema_reaches_strict_decoder_and_fails() {
    let key = SecretKey::generate();
    let node_id = NodeId::from_bytes(*key.public().as_bytes());
    let sequence = now_micros().saturating_sub(100_000);
    let payload =
        schema_invalid_but_validly_signed_payload(&key, sequence, &[direct("192.0.2.16:4433")]);
    let (authority, server) = scripted_authority(vec![HttpResponse::ok(payload)]).await;
    let runtime = runtime(authority).await;
    let error = runtime
        .node_lookup_handle()
        .unwrap()
        .resolve(node_id)
        .await
        .unwrap_err();
    assert_eq!(
        error.kind(),
        NodeLookupUnavailableKind::MalformedOrUntrustedRecord
    );
    assert!(error.message().contains("unsupported node-record schema"));
    runtime.shutdown().await.unwrap();
    assert_get_only(&server.await.unwrap(), node_id);
}

// The absolute deadline is exercised against a REAL iroh endpoint in REAL time
// with a SHORT injected deadline (via `resolve_before`) rather than the 10 s
// production default. Paused tokio time (`start_paused`) is INCOMPATIBLE with a
// real endpoint: iroh's maintenance timers and the real socket readiness need
// wall-clock progress that a frozen clock never delivers, so the lookup — and
// the whole `cargo test --workspace` gate — hung indefinitely (TASK-190). The
// short real-time deadline keeps the endpoint healthy while still firing the
// deadline deterministically.
#[tokio::test]
async fn hanging_authority_is_cancelled_at_the_single_absolute_ten_second_deadline() {
    // Short enough for a fast gate, long enough for a localhost GET to land
    // before it fires even under shared-box load.
    const SHORT_DEADLINE: Duration = Duration::from_millis(500);

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let authority = listener.local_addr().unwrap();
    let (accepted_tx, accepted_rx) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_request(&mut stream).await;
        accepted_tx.send(request).unwrap();
        std::future::pending::<()>().await;
    });
    let runtime = runtime(authority).await;
    let key = SecretKey::generate();
    let node_id = NodeId::from_bytes(*key.public().as_bytes());
    let handle = runtime.node_lookup_handle().unwrap();
    let started = tokio::time::Instant::now();
    let deadline = started + SHORT_DEADLINE;

    // OUTER oracle on a real (non-paused) clock: if the deadline mechanism is
    // broken and never cancels, this bound FAILS the test rather than letting it
    // hang forever. Neutering the cancellation must trip this timeout.
    let error = tokio::time::timeout(SHORT_DEADLINE + Duration::from_secs(2), async {
        let lookup = tokio::spawn(async move { handle.resolve_before(node_id, deadline).await });
        let request = accepted_rx.await.unwrap();
        let request = String::from_utf8(request).unwrap();
        assert!(request.starts_with("GET /pkarr/"));
        lookup.await.unwrap()
    })
    .await
    .expect("the absolute deadline must cancel the hanging lookup, not hang")
    .unwrap_err();

    assert_eq!(error.kind(), NodeLookupUnavailableKind::Deadline);
    assert!(started.elapsed() >= SHORT_DEADLINE);
    server.abort();
    let _ = server.await;
    runtime.shutdown().await.unwrap();
}

#[tokio::test]
async fn dropping_the_asker_cancels_the_owned_tcp_get() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let authority = listener.local_addr().unwrap();
    let (accepted_tx, accepted_rx) = oneshot::channel();
    let (closed_tx, closed_rx) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_request(&mut stream).await;
        accepted_tx.send(request).unwrap();
        let mut proof = [0u8; 1];
        let read = stream.read(&mut proof).await.unwrap();
        closed_tx.send(read).unwrap();
    });
    let runtime = runtime(authority).await;
    let key = SecretKey::generate();
    let node_id = NodeId::from_bytes(*key.public().as_bytes());
    let handle = runtime.node_lookup_handle().unwrap();
    let asker = tokio::spawn(async move { handle.resolve(node_id).await });
    accepted_rx.await.unwrap();
    asker.abort();
    let _ = asker.await;
    let read = tokio::time::timeout(Duration::from_secs(1), closed_rx)
        .await
        .expect("cancelled lookup must close its TCP request")
        .unwrap();
    assert_eq!(read, 0);
    server.await.unwrap();
    runtime.shutdown().await.unwrap();
}

#[tokio::test]
async fn shutdown_cancels_an_active_lookup_and_releases_its_fixed_iroh_port() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let authority = listener.local_addr().unwrap();
    let port_probe = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let iroh_port = port_probe.local_addr().unwrap().port();
    drop(port_probe);
    let (accepted_tx, accepted_rx) = oneshot::channel();
    let (closed_tx, closed_rx) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_request(&mut stream).await;
        accepted_tx.send(request).unwrap();
        let mut proof = [0u8; 1];
        closed_tx.send(stream.read(&mut proof).await).unwrap();
    });
    let runtime = IrohRuntimeBuilder::new(
        EndpointProfile {
            scope: EndpointScope::Global { port: iroh_port },
        },
        IdentitySource::Ephemeral,
        RelayCapability::Disabled,
        AddressLookupCapability::PinnedPkarr(config(authority)),
    )
    .unwrap()
    .spawn()
    .await
    .unwrap();
    let key = SecretKey::generate();
    let node_id = NodeId::from_bytes(*key.public().as_bytes());
    let handle = runtime.node_lookup_handle().unwrap();
    let lookup = tokio::spawn(async move { handle.resolve(node_id).await });
    accepted_rx.await.unwrap();

    assert_eq!(runtime.shutdown().await.unwrap(), ShutdownOutcome::Graceful);
    assert_eq!(
        lookup.await.unwrap().unwrap_err().kind(),
        NodeLookupUnavailableKind::Closed
    );
    match tokio::time::timeout(Duration::from_secs(1), closed_rx)
        .await
        .expect("shutdown must close the active lookup request")
        .unwrap()
    {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
            ) => {}
        observed => panic!("lookup TCP request remained active after shutdown: {observed:?}"),
    }
    server.await.unwrap();

    let restarted = IrohRuntimeBuilder::new(
        EndpointProfile {
            scope: EndpointScope::Global { port: iroh_port },
        },
        IdentitySource::Ephemeral,
        RelayCapability::Disabled,
        AddressLookupCapability::Disabled,
    )
    .unwrap()
    .spawn()
    .await
    .expect("lookup shutdown must release the fixed Iroh port");
    restarted.shutdown().await.unwrap();
}

#[tokio::test]
async fn invalid_ed25519_node_id_is_rejected_before_a_get() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let authority = listener.local_addr().unwrap();
    let runtime = runtime(authority).await;
    let invalid = (0u8..=u8::MAX)
        .map(|byte| [byte; 32])
        .find(|bytes| iroh::PublicKey::from_bytes(bytes).is_err())
        .expect("at least one repeated byte string is not a canonical Ed25519 key");
    let error = runtime
        .node_lookup_handle()
        .unwrap()
        .resolve(NodeId::from_bytes(invalid))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), NodeLookupUnavailableKind::InvalidNodeId);
    assert!(
        tokio::time::timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err(),
        "invalid typed identity emitted an authority request"
    );
    runtime.shutdown().await.unwrap();
}
