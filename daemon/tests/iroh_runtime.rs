//! TASK-115 runtime contract: identity state fails closed, offline is genuinely
//! loopback-only, one node shares endpoint ownership, and shutdown releases a
//! fixed port immediately (including the forced-deadline path).

use std::future::{self, Future};
use std::net::{Ipv4Addr, UdpSocket};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use daemon::iroh_runtime::{
    DAEMON_TEST_ENDPOINT_PROFILE, IdentityInitializationHooks, load_or_create_identity,
    load_or_create_identity_with_hooks,
};
use daemon::transport_iroh::endpoint_support;
use daemon::{
    AddressLookupCapability, App, Blake3Digest, CacheInfo, EndpointProfile, EndpointScope,
    IROH_BLOBS_ALPN, IROH_IDENTITY_FILENAME, IdentitySource, IrohClientNode, IrohNodeBuilder,
    IrohPeerAddr, IrohProviderConfig, KnownTransport, MemoryNarSupplier, NarCatalog, NarKey,
    NarSource, NarinfoSource, NoRawServe, NullCorrelation, RawUpstream, RelayCapability,
    SafetyEnvelope, ServeBudget, ShutdownOutcome, SourceError, StoreHash, StoreRetention,
    TaskSupervisor, Transport, UpstreamResponse, serve,
};
use iroh::endpoint::{Connection, RelayMode, VarInt};
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Notify;

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "nix-p2p-task115-{label}-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("unique test parent directory");
        Self(path)
    }

    fn state(&self) -> PathBuf {
        self.0.join("state")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn identity_path(state: &Path) -> PathBuf {
    state.join(IROH_IDENTITY_FILENAME)
}

fn initialize(label: &str) -> (TempDir, PathBuf, Vec<u8>) {
    let temp = TempDir::new(label);
    let state = temp.state();
    load_or_create_identity(&state).expect("identity initializes");
    let bytes = std::fs::read(identity_path(&state)).expect("read initialized record");
    (temp, state, bytes)
}

#[test]
fn persistent_identity_is_reused_with_restrictive_permissions() {
    let (_temp, state, original) = initialize("persist");
    let first = load_or_create_identity(&state).expect("first reload");
    let second = load_or_create_identity(&state).expect("second reload");
    assert_eq!(first.public(), second.public(), "restart preserves NodeId");
    assert_eq!(
        std::fs::read(identity_path(&state)).expect("record still readable"),
        original,
        "a valid existing identity is never rewritten"
    );
    assert_eq!(
        std::fs::metadata(&state).expect("state metadata").mode() & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(identity_path(&state))
            .expect("identity metadata")
            .mode()
            & 0o777,
        0o600
    );
}

#[test]
fn first_initializer_reopens_and_validates_the_published_directory_entry() {
    let temp = TempDir::new("first-return-validation");
    let state = temp.state();
    let validations = Arc::new(AtomicU64::new(0));
    let validations_for_hook = Arc::clone(&validations);
    let hooks = IdentityInitializationHooks::default().before_first_return_validation(move || {
        validations_for_hook.fetch_add(1, Ordering::AcqRel);
    });

    let initialized = load_or_create_identity_with_hooks(&state, &hooks)
        .expect("first initialization validates its published entry");
    assert_eq!(validations.load(Ordering::Acquire), 1);
    assert_eq!(
        load_or_create_identity(&state).unwrap().public(),
        initialized.public()
    );
}

#[test]
fn concurrent_initializers_publish_exactly_one_identity_without_temp_leaks() {
    let temp = TempDir::new("race");
    let state = temp.state();
    let barrier = Arc::new(Barrier::new(2));
    let mut workers = Vec::new();
    for _ in 0..2 {
        let state = state.clone();
        let barrier = barrier.clone();
        workers.push(std::thread::spawn(move || {
            let hooks = IdentityInitializationHooks::default().after_absent(move || {
                barrier.wait();
            });
            load_or_create_identity_with_hooks(&state, &hooks)
                .expect("concurrent identity initialization")
                .public()
        }));
    }
    let identities: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().expect("initializer thread"))
        .collect();
    assert!(
        identities.windows(2).all(|pair| pair[0] == pair[1]),
        "all concurrent starters must converge on the no-clobber winner"
    );
    let names: Vec<_> = std::fs::read_dir(&state)
        .expect("state listing")
        .map(|entry| entry.expect("state entry").file_name())
        .collect();
    assert_eq!(
        names,
        [IROH_IDENTITY_FILENAME],
        "no losing temp files remain"
    );
}

#[test]
fn a_crash_after_publication_is_recovered_by_a_durable_observer() {
    let temp = TempDir::new("publish-crash");
    let state = temp.state();
    let hooks = IdentityInitializationHooks::default().after_publish_before_sync(|| {
        panic!("deterministic crash after linkat and before directory fsync")
    });
    let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = load_or_create_identity_with_hooks(&state, &hooks);
    }));
    assert!(crashed.is_err(), "the publication failpoint must bite");

    let recovered = load_or_create_identity(&state)
        .expect("the next successful observer validates and fsyncs the published identity");
    assert_eq!(
        load_or_create_identity(&state).unwrap().public(),
        recovered.public(),
        "crash recovery must never clobber the published key"
    );
    let names = std::fs::read_dir(&state)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    assert_eq!(names, [IROH_IDENTITY_FILENAME]);
}

fn assert_identity_load_is_bounded_and_rejected(state: PathBuf, kind: &str) {
    let (sent, received) = std::sync::mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        let _ = sent.send(load_or_create_identity(&state).map(|key| key.public()));
    });
    let result = received
        .recv_timeout(Duration::from_millis(500))
        .unwrap_or_else(|_| panic!("opening a {kind} identity slot blocked"));
    assert!(result.is_err(), "a {kind} identity slot must fail closed");
    worker.join().expect("identity loader thread");
}

#[test]
fn fifo_socket_and_device_identity_slots_are_rejected_without_blocking() {
    let fifo_temp = TempDir::new("fifo-slot");
    let fifo_state = fifo_temp.state();
    std::fs::create_dir(&fifo_state).unwrap();
    std::fs::set_permissions(&fifo_state, std::fs::Permissions::from_mode(0o700)).unwrap();
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        identity_path(&fifo_state),
        rustix::fs::Mode::from_raw_mode(0o600),
    )
    .expect("create FIFO identity slot");
    assert_identity_load_is_bounded_and_rejected(fifo_state, "FIFO");

    let socket_temp = TempDir::new("socket-slot");
    let socket_state = socket_temp.state();
    std::fs::create_dir(&socket_state).unwrap();
    std::fs::set_permissions(&socket_state, std::fs::Permissions::from_mode(0o700)).unwrap();
    let _listener = UnixListener::bind(identity_path(&socket_state)).expect("Unix socket slot");
    assert_identity_load_is_bounded_and_rejected(socket_state, "Unix socket");

    // Creating a device node requires privilege. When available, exercise the
    // same bounded descriptor-first rejection against /dev/null's device id.
    let device_temp = TempDir::new("device-slot");
    let device_state = device_temp.state();
    std::fs::create_dir(&device_state).unwrap();
    std::fs::set_permissions(&device_state, std::fs::Permissions::from_mode(0o700)).unwrap();
    if rustix::fs::mknodat(
        rustix::fs::CWD,
        identity_path(&device_state),
        rustix::fs::FileType::CharacterDevice,
        rustix::fs::Mode::from_raw_mode(0o600),
        rustix::fs::makedev(1, 3),
    )
    .is_ok()
    {
        assert_identity_load_is_bounded_and_rejected(device_state, "device");
    }
}

#[test]
fn hardlinks_and_identity_path_swaps_fail_closed() {
    let (_hardlink_temp, hardlink_state, _bytes) = initialize("hardlink");
    let alias = hardlink_state.join("identity-hardlink");
    std::fs::hard_link(identity_path(&hardlink_state), &alias).unwrap();
    let error = load_or_create_identity(&hardlink_state)
        .expect_err("multiply-linked secret must be rejected")
        .to_string();
    assert!(error.contains("hard links"), "got {error}");

    let (replacement_temp, replacement_state, _) = initialize("swap-replacement");
    let replacement = replacement_temp.0.join("replacement.json");
    std::fs::copy(identity_path(&replacement_state), &replacement).unwrap();
    std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o600)).unwrap();
    let (swap_temp, swap_state, original) = initialize("swap-target");
    let target = identity_path(&swap_state);
    let target_for_hook = target.clone();
    let hooks = IdentityInitializationHooks::default().after_open_before_read(move || {
        std::fs::rename(&replacement, &target_for_hook).expect("swap directory entry")
    });
    let error = load_or_create_identity_with_hooks(&swap_state, &hooks)
        .expect_err("path replacement during read must fail")
        .to_string();
    assert!(
        error.contains("changed while") || error.contains("hard links"),
        "got {error}"
    );
    assert_ne!(std::fs::read(target).unwrap(), original);
    drop(swap_temp);
}

#[test]
fn identity_owned_by_another_uid_is_rejected_when_the_test_can_create_one() {
    if !rustix::process::geteuid().is_root() {
        return;
    }
    let (_temp, state, _) = initialize("foreign-uid");
    let path = identity_path(&state);
    rustix::fs::chownat(
        rustix::fs::CWD,
        &path,
        Some(rustix::process::Uid::from_raw(1)),
        None,
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    )
    .unwrap();
    let error = load_or_create_identity(&state)
        .expect_err("foreign-owned identity must fail")
        .to_string();
    assert!(error.contains("not owned"), "got {error}");
    rustix::fs::chownat(
        rustix::fs::CWD,
        &path,
        Some(rustix::process::Uid::ROOT),
        None,
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    )
    .unwrap();
}

#[test]
fn directory_and_identity_owner_policy_reject_foreign_uids_on_every_run() {
    let expected = rustix::process::geteuid().as_raw();
    let foreign = expected.wrapping_add(1);
    for label in ["state directory", "identity file"] {
        daemon::iroh_runtime::validate_expected_owner(label, expected, expected)
            .expect("matching owner is accepted");
        let error = daemon::iroh_runtime::validate_expected_owner(label, foreign, expected)
            .expect_err("foreign owner must fail independently of chown privilege")
            .to_string();
        assert!(error.contains(label), "got {error}");
        assert!(error.contains("not owned"), "got {error}");
    }
}

fn assert_rejected_without_rewrite(state: &Path, expected_bytes: &[u8], needle: &str) {
    let error = load_or_create_identity(state).expect_err("unsafe identity must fail closed");
    assert!(
        error.to_string().contains(needle),
        "error must name {needle:?}, got {error}"
    );
    assert_eq!(
        std::fs::read(identity_path(state)).expect("rejected record remains readable"),
        expected_bytes,
        "rejection must not rewrite or regenerate identity state"
    );
}

#[test]
fn malformed_unknown_version_checksum_and_public_key_mismatch_fail_without_rewrite() {
    let (_temp, state, _) = initialize("record-errors");

    let malformed = b"not-json\n".to_vec();
    std::fs::write(identity_path(&state), &malformed).expect("write malformed record");
    assert_rejected_without_rewrite(&state, &malformed, "malformed");

    // Reinitialize in fresh directories for independent fail-closed stories.
    let (_version_temp, version_state, original) = initialize("version");
    let text = String::from_utf8(original).expect("record is UTF-8 JSON");
    let version = text.replace("\"schema_version\": 1", "\"schema_version\": 999");
    assert_ne!(version, text, "version mutation must bite");
    std::fs::write(identity_path(&version_state), version.as_bytes()).expect("write version");
    assert_rejected_without_rewrite(&version_state, version.as_bytes(), "unknown schema_version");

    let (_checksum_temp, checksum_state, original) = initialize("checksum");
    let mut checksum = original;
    let marker = b"\"checksum_blake3_hex\": \"";
    let offset = checksum
        .windows(marker.len())
        .position(|window| window == marker)
        .expect("checksum field")
        + marker.len();
    checksum[offset] = if checksum[offset] == b'0' { b'1' } else { b'0' };
    std::fs::write(identity_path(&checksum_state), &checksum).expect("write checksum mutation");
    assert_rejected_without_rewrite(&checksum_state, &checksum, "checksum");

    let (_node_temp, node_state, original) = initialize("node-mismatch");
    let mut node = original;
    let marker = b"\"node_id_hex\": \"";
    let offset = node
        .windows(marker.len())
        .position(|window| window == marker)
        .expect("node field")
        + marker.len();
    node[offset] = if node[offset] == b'0' { b'1' } else { b'0' };
    std::fs::write(identity_path(&node_state), &node).expect("write node mutation");
    assert_rejected_without_rewrite(&node_state, &node, "does not match the secret key");
}

#[test]
fn unsafe_mode_unreadable_symlink_and_nonregular_state_fail_closed() {
    let (_mode_temp, mode_state, original) = initialize("mode");
    std::fs::set_permissions(
        identity_path(&mode_state),
        std::fs::Permissions::from_mode(0o644),
    )
    .expect("widen identity permissions");
    assert_rejected_without_rewrite(&mode_state, &original, "mode is");

    let (_unreadable_temp, unreadable_state, original) = initialize("unreadable");
    std::fs::set_permissions(
        identity_path(&unreadable_state),
        std::fs::Permissions::from_mode(0o000),
    )
    .expect("remove read permission");
    let error = load_or_create_identity(&unreadable_state)
        .expect_err("unreadable identity must fail closed")
        .to_string();
    assert!(error.contains("opening existing identity") || error.contains("mode is"));
    std::fs::set_permissions(
        identity_path(&unreadable_state),
        std::fs::Permissions::from_mode(0o600),
    )
    .expect("restore cleanup/read permission");
    assert_eq!(
        std::fs::read(identity_path(&unreadable_state)).unwrap(),
        original
    );

    let symlink_temp = TempDir::new("symlink");
    let symlink_state = symlink_temp.state();
    std::fs::create_dir(&symlink_state).expect("state dir");
    std::fs::set_permissions(&symlink_state, std::fs::Permissions::from_mode(0o700)).unwrap();
    let target = symlink_temp.0.join("target");
    std::fs::write(&target, b"secret target remains untouched").unwrap();
    symlink(&target, identity_path(&symlink_state)).expect("identity symlink");
    let error = load_or_create_identity(&symlink_state)
        .expect_err("identity symlink must fail")
        .to_string();
    assert!(error.contains("without following symlinks"), "got {error}");
    assert_eq!(
        std::fs::read(&target).unwrap(),
        b"secret target remains untouched"
    );

    let nonregular_temp = TempDir::new("nonregular");
    let nonregular_state = nonregular_temp.state();
    std::fs::create_dir(&nonregular_state).unwrap();
    std::fs::set_permissions(&nonregular_state, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::create_dir(identity_path(&nonregular_state)).unwrap();
    let error = load_or_create_identity(&nonregular_state)
        .expect_err("directory in identity slot must fail")
        .to_string();
    assert!(error.contains("not a regular file"), "got {error}");
    assert!(identity_path(&nonregular_state).is_dir());
}

#[test]
fn state_directory_symlink_and_unsafe_directory_mode_are_rejected() {
    let temp = TempDir::new("state-symlink");
    let real = temp.0.join("real");
    std::fs::create_dir(&real).unwrap();
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
    let state = temp.state();
    symlink(&real, &state).unwrap();
    let error = load_or_create_identity(&state)
        .expect_err("state symlink must fail")
        .to_string();
    assert!(error.contains("without following symlinks"), "got {error}");

    let mode_temp = TempDir::new("state-mode");
    let mode_state = mode_temp.state();
    std::fs::create_dir(&mode_state).unwrap();
    std::fs::set_permissions(&mode_state, std::fs::Permissions::from_mode(0o755)).unwrap();
    let error = load_or_create_identity(&mode_state)
        .expect_err("unsafe state dir mode must fail")
        .to_string();
    assert!(error.contains("mode is"), "got {error}");
}

#[test]
fn lan_scope_rejects_wildcards_multicast_and_unscoped_link_local_ipv6() {
    for scope in [
        EndpointScope::Lan {
            ipv4: Ipv4Addr::UNSPECIFIED,
            ipv6: None,
            port: 0,
        },
        EndpointScope::Lan {
            ipv4: Ipv4Addr::new(224, 0, 0, 1),
            ipv6: None,
            port: 0,
        },
        EndpointScope::Lan {
            ipv4: Ipv4Addr::LOCALHOST,
            ipv6: Some("fe80::1".parse().unwrap()),
            port: 0,
        },
    ] {
        assert!(
            daemon::IrohRuntimeBuilder::new(
                EndpointProfile { scope },
                IdentitySource::Ephemeral,
                RelayCapability::Disabled,
                AddressLookupCapability::Disabled,
            )
            .is_err(),
            "unsafe LAN bind {scope:?} must fail closed"
        );
    }
}

#[tokio::test]
async fn global_wildcard_binds_are_observable_but_never_publishable() {
    let node = IrohNodeBuilder::new(
        EndpointProfile {
            scope: EndpointScope::Global { port: 0 },
        },
        IdentitySource::Ephemeral,
        RelayCapability::Disabled,
        AddressLookupCapability::Memory,
    )
    .unwrap()
    .spawn()
    .await
    .unwrap();
    let bound = node.bound_socket_addrs().unwrap();
    assert!(
        bound.iter().all(|socket| socket.ip().is_unspecified()),
        "global scope binds wildcard sockets: {bound:?}"
    );
    assert_eq!(
        node.transport().reachable_socket_addrs().unwrap(),
        Vec::<std::net::SocketAddr>::new()
    );
    assert_eq!(
        node.transport().address_lookup_count().unwrap(),
        1,
        "IrohNodeBuilder must forward the authorized lookup service"
    );
    assert_eq!(
        node.transport().endpoint_capabilities().unwrap(),
        daemon::EndpointCapabilityState {
            relay_enabled: false,
            address_lookup_services: 1,
            node_lookup_enabled: false,
            node_publication_enabled: false,
        }
    );
    node.shutdown().await.unwrap();
}

#[tokio::test]
async fn lan_and_global_scopes_do_not_imply_lookup_or_relay() {
    let scopes = [
        EndpointScope::Lan {
            ipv4: Ipv4Addr::LOCALHOST,
            ipv6: None,
            port: 0,
        },
        EndpointScope::Global { port: 0 },
    ];
    for scope in scopes {
        let node = IrohNodeBuilder::new(
            EndpointProfile { scope },
            IdentitySource::Ephemeral,
            RelayCapability::Disabled,
            AddressLookupCapability::Disabled,
        )
        .unwrap()
        .spawn()
        .await
        .unwrap();
        assert_eq!(node.transport().address_lookup_count().unwrap(), 0);
        assert_eq!(
            node.transport().endpoint_capabilities().unwrap(),
            daemon::EndpointCapabilityState {
                relay_enabled: false,
                address_lookup_services: 0,
                node_lookup_enabled: false,
                node_publication_enabled: false,
            }
        );
        node.shutdown().await.unwrap();
    }
}

#[test]
fn explicit_relay_capability_is_observable_before_any_network_bind() {
    let builder = daemon::IrohRuntimeBuilder::new(
        EndpointProfile {
            scope: EndpointScope::Global { port: 49123 },
        },
        IdentitySource::Ephemeral,
        RelayCapability::Enabled(RelayMode::Default),
        AddressLookupCapability::Disabled,
    )
    .unwrap();
    assert_eq!(
        builder.capability_state(),
        daemon::EndpointCapabilityState {
            relay_enabled: true,
            address_lookup_services: 0,
            node_lookup_enabled: false,
            node_publication_enabled: false,
        }
    );
}

#[test]
fn enabled_relay_rejects_disabled_and_empty_modes() {
    for mode in [
        RelayMode::Disabled,
        RelayMode::Custom(iroh::RelayMap::empty()),
    ] {
        let error = daemon::IrohRuntimeBuilder::new(
            EndpointProfile {
                scope: EndpointScope::Global { port: 0 },
            },
            IdentitySource::Ephemeral,
            RelayCapability::Enabled(mode),
            AddressLookupCapability::Disabled,
        )
        .expect_err("Enabled must describe a real relay capability")
        .to_string();
        assert!(error.contains("non-disabled, non-empty"), "got {error}");
    }
}

#[tokio::test]
async fn relay_map_is_revalidated_immediately_before_bind() {
    let relay_url: iroh::RelayUrl = "https://relay.invalid.example"
        .parse()
        .expect("syntactically valid relay URL");
    let map = iroh::RelayMap::from_iter([relay_url.clone()]);
    let builder = daemon::IrohRuntimeBuilder::new(
        EndpointProfile {
            scope: EndpointScope::Global { port: 0 },
        },
        IdentitySource::Ephemeral,
        RelayCapability::Enabled(RelayMode::Custom(map.clone())),
        AddressLookupCapability::Disabled,
    )
    .expect("non-empty relay capability is initially valid");
    map.remove(&relay_url);

    let error = builder
        .spawn()
        .await
        .expect_err("shared custom map emptied before bind must fail closed")
        .to_string();
    assert!(error.contains("non-disabled, non-empty"), "got {error}");
}

#[tokio::test]
async fn bound_endpoint_owns_a_relay_snapshot_independent_of_caller_aliases() {
    let relay_url: iroh::RelayUrl = "https://relay.invalid.example".parse().unwrap();
    let caller_map = iroh::RelayMap::from(relay_url.clone());
    let endpoint = daemon::iroh_runtime::bind_endpoint(
        EndpointProfile {
            scope: EndpointScope::Global { port: 0 },
        },
        IdentitySource::Ephemeral,
        RelayCapability::Enabled(RelayMode::Custom(caller_map.clone())),
        AddressLookupCapability::Disabled,
    )
    .await
    .expect("endpoint binds from a concrete relay snapshot");

    caller_map.remove(&relay_url);
    assert!(caller_map.is_empty());
    assert!(
        endpoint.remove_relay(&relay_url).await.is_some(),
        "mutating the caller map after bind must not mutate endpoint recipients"
    );
    endpoint.close().await;
}

#[test]
fn relay_capability_debug_never_prints_auth_tokens() {
    let relay_url: iroh::RelayUrl = "https://relay.invalid.example".parse().unwrap();
    let config = iroh::RelayConfig::from(relay_url).with_auth_token("relay-secret-token");
    let capability = RelayCapability::Enabled(RelayMode::Custom(iroh::RelayMap::from(config)));
    let debug = format!("{capability:?}");
    assert!(!debug.contains("relay-secret-token"), "{debug}");
    assert!(debug.contains("relay_count"), "{debug}");
}

fn unused_port() -> u16 {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve free UDP port");
    socket.local_addr().expect("local address").port()
}

fn persistent_builder(state: PathBuf, port: u16) -> daemon::IrohRuntimeBuilder {
    daemon::IrohRuntimeBuilder::new(
        EndpointProfile {
            scope: EndpointScope::OfflineTest { port },
        },
        IdentitySource::Persistent { state_dir: state },
        RelayCapability::Disabled,
        AddressLookupCapability::Disabled,
    )
    .expect("offline persistent builder")
}

#[tokio::test]
async fn offline_runtime_has_only_loopback_no_lookups_and_restarts_on_fixed_port() {
    let temp = TempDir::new("restart");
    let state = temp.state();
    let port = unused_port();
    let runtime = persistent_builder(state.clone(), port)
        .spawn()
        .await
        .expect("first runtime");
    let first_id = runtime.node_id().expect("first NodeId");
    let handle = runtime.endpoint_handle();
    let sockets = runtime.bound_socket_addrs().expect("bound sockets");
    assert_eq!(sockets.len(), 2, "explicit IPv4 and IPv6 loopback binds");
    assert!(sockets.iter().all(|socket| socket.ip().is_loopback()));
    assert_eq!(handle.address_lookup_count().expect("lookup count"), 0);
    assert_eq!(runtime.shutdown().await.unwrap(), ShutdownOutcome::Graceful);
    assert!(
        handle.node_id().is_err(),
        "weak handle becomes inert on shutdown"
    );

    let restarted = persistent_builder(state, port)
        .spawn()
        .await
        .expect("immediate fixed-port restart");
    assert_eq!(restarted.node_id().unwrap(), first_id, "NodeId persists");
    assert_eq!(
        restarted.shutdown().await.unwrap(),
        ShutdownOutcome::Graceful
    );
}

#[derive(Debug, Clone)]
struct HangingShutdown;

impl ProtocolHandler for HangingShutdown {
    async fn accept(&self, _connection: Connection) -> Result<(), AcceptError> {
        Ok(())
    }

    async fn shutdown(&self) {
        future::pending::<()>().await;
    }
}

#[derive(Debug, Clone)]
struct StallingOutbound {
    accepted: Arc<Notify>,
}

impl ProtocolHandler for StallingOutbound {
    async fn accept(&self, _connection: Connection) -> Result<(), AcceptError> {
        self.accepted.notify_one();
        future::pending::<()>().await;
        Ok(())
    }
}

#[tokio::test]
async fn shutdown_deadline_forces_abort_and_still_releases_fixed_port() {
    let temp = TempDir::new("forced-restart");
    let state = temp.state();
    let port = unused_port();
    let runtime = persistent_builder(state.clone(), port)
        .accept(b"/nix-p2p/hanging-shutdown/1", HangingShutdown)
        .expect("unique handler")
        .shutdown_deadline(Duration::from_millis(75))
        .expect("positive deadline")
        .spawn()
        .await
        .expect("runtime");
    let id = runtime.node_id().unwrap();
    let started = Instant::now();
    assert_eq!(runtime.shutdown().await.unwrap(), ShutdownOutcome::Forced);
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "deadline is bounded"
    );

    let restarted = persistent_builder(state, port)
        .spawn()
        .await
        .expect("forced path released tasks and socket");
    assert_eq!(restarted.node_id().unwrap(), id);
    restarted.shutdown().await.unwrap();
}

#[test]
fn provider_boundary_has_no_generic_blocking_or_endpoint_callback_escape() {
    let runtime = include_str!("../../fabric-iroh/src/iroh_runtime.rs");
    let transport = include_str!("../../fabric-iroh/src/transport_iroh.rs");
    assert!(!runtime.contains("execute_blocking"));
    assert!(!runtime.contains("BlockingCancellation"));
    assert!(!runtime.contains("endpoint_operation"));
    assert!(!runtime.contains("FnOnce(Endpoint)"));
    assert!(!runtime.contains("AddressLookupBuilder"));
    assert!(!runtime.contains("pub fn address_lookup("));
    assert!(!transport.contains("impl NarSupplier for Cooperative"));
    assert!(!transport.contains("supply_raw_nar_cancellable("));
    assert!(!transport.contains("endpoint: Endpoint,"));
    assert!(
        !transport.contains("AvailabilityIndex"),
        "provider must depend only on the inert supply catalog"
    );
}

#[test]
fn shutdown_signal_receivers_are_installed_before_readiness_can_be_printed() {
    let main = include_str!("../src/main.rs");
    let installed = main
        .find("let shutdown_signals = match install_shutdown_signals()")
        .expect("startup installs signal receivers");
    let iroh_setup = main
        .find(
            "let iroh_node = match setup_iroh_node_with_deadline(&config, publication_startup_deadline).await",
        )
        .expect("deadline-aware Iroh readiness setup site");
    let http_readiness = main
        .find("daemon: listening on {local}")
        .expect("HTTP readiness site");
    assert!(installed < iroh_setup && installed < http_readiness);
}

struct DropObserved(Arc<AtomicBool>);

impl Drop for DropObserved {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

#[tokio::test]
async fn dropping_runtime_without_shutdown_aborts_tasks_and_releases_fixed_port() {
    let temp = TempDir::new("runtime-drop");
    let state = temp.state();
    let port = unused_port();
    let runtime = persistent_builder(state.clone(), port)
        .spawn()
        .await
        .unwrap();
    let task_started = Arc::new(Notify::new());
    let task_started_wait = task_started.notified();
    let task_started_for_worker = task_started.clone();
    let task_dropped = Arc::new(AtomicBool::new(false));
    let guard_state = task_dropped.clone();
    runtime
        .task_supervisor_handle()
        .spawn("raii-drop-regression", async move {
            let _guard = DropObserved(guard_state);
            task_started_for_worker.notify_one();
            future::pending::<()>().await;
        })
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), task_started_wait)
        .await
        .expect("supervised task started");

    drop(runtime);
    tokio::time::timeout(Duration::from_secs(1), async {
        while !task_dropped.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("runtime Drop aborts and drops supervised task futures");
    let restarted = persistent_builder(state, port)
        .spawn()
        .await
        .expect("runtime Drop releases the fixed endpoint socket");
    restarted.shutdown().await.unwrap();
}

#[tokio::test]
async fn supervised_task_panics_are_returned_by_node_shutdown() {
    let node = IrohNodeBuilder::offline_ephemeral()
        .unwrap()
        .spawn()
        .await
        .unwrap();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    node.spawn_task("panic-regression", async move {
        let _ = started_tx.send(());
        panic!("deliberate supervised task panic");
    })
    .unwrap();
    started_rx.await.expect("panic task began");
    tokio::task::yield_now().await;

    let error = node
        .shutdown()
        .await
        .expect_err("owned task panic must make shutdown fail loudly");
    let message = error.to_string();
    assert!(message.contains("panic-regression"), "{message}");
    assert!(message.contains("panicked"), "{message}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn completed_supervised_tasks_are_continuously_reaped_to_zero() {
    let supervisor = daemon::TaskSupervisor::new();
    let handle = supervisor.handle();
    let accepted = tokio::time::timeout(Duration::from_secs(5), async {
        let mut accepted = 0usize;
        while accepted < 2_000 {
            match handle.spawn(format!("short-lived-{accepted}"), async {}) {
                Ok(()) => accepted += 1,
                Err(error) if error.is_capacity_exhausted() => tokio::task::yield_now().await,
                Err(error) => panic!("short-lived task registration failed: {error}"),
            }
        }
        accepted
    })
    .await
    .expect("the task manager keeps accepting work as completed tasks are reaped");
    assert_eq!(accepted, 2_000);
    tokio::time::timeout(Duration::from_secs(5), async {
        while supervisor.active_task_count() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("completed tasks are removed instead of accumulating until shutdown");
    assert_eq!(handle.active_task_count().unwrap(), 0);
    supervisor.cancel_now();
    assert!(handle.spawn("after-close", async {}).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provider_capacity_declines_one_request_then_recovers_without_restarting() {
    let nar = b"capacity-recovery-nar".to_vec();
    let content = Blake3Digest::from_raw_nar(&nar);
    let supplier = Arc::new(MemoryNarSupplier::new([nar.clone()]));
    let node = IrohNodeBuilder::offline_ephemeral()
        .unwrap()
        .provider(IrohProviderConfig::supplying(
            supplier,
            ServeBudget {
                max_nar_bytes_uncompressed_nar: 1024,
                max_inflight_bytes_uncompressed_nar: 1024,
                max_serve_duration: Duration::from_secs(5),
            },
            Duration::from_secs(1),
        ))
        .spawn()
        .await
        .unwrap();
    let provider_addr = node.provider().unwrap().addr().await.unwrap();
    let provider_id = node.provider().unwrap().node_id().unwrap();
    let client = IrohClientNode::spawn().await.unwrap();
    client.add_peer(&provider_addr);
    let transport = client.transport_handle();

    // The provider event driver itself is supervised. Fill every remaining
    // global slot with quiescent tasks, then prove that one remote request is
    // refused promptly rather than queued without a bound.
    let supervisor = node.task_supervisor_handle();
    let (release_tx, release_rx) = tokio::sync::watch::channel(false);
    let mut accepted = 0usize;
    loop {
        let mut release = release_rx.clone();
        let result = supervisor.spawn(format!("capacity-filler-{accepted}"), async move {
            if !*release.borrow() {
                let _ = release.wait_for(|released| *released).await;
            }
        });
        match result {
            Ok(()) => accepted += 1,
            Err(error) if error.is_capacity_exhausted() => break,
            Err(error) => panic!("unexpected capacity-filler registration error: {error}"),
        }
    }
    assert!(accepted > 0);
    assert_eq!(
        supervisor.active_task_count().unwrap(),
        daemon::iroh_runtime::MAX_OWNED_TASKS,
        "queued plus running work has one explicit hard ceiling"
    );

    let refused = tokio::time::timeout(
        Duration::from_secs(2),
        transport.fetch(&content, &KnownTransport::Iroh { node: provider_id }, None),
    )
    .await
    .expect("an overloaded provider closes the rejected response promptly");
    assert!(refused.is_err(), "an unregistered request cannot be served");
    assert_eq!(node.provider().unwrap().serve_counters().declined_busy, 1);

    release_tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while supervisor.active_task_count().unwrap() != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("filler tasks are continuously reaped after capacity is released");

    let recovered = tokio::time::timeout(
        Duration::from_secs(2),
        transport.fetch(&content, &KnownTransport::Iroh { node: provider_id }, None),
    )
    .await
    .expect("provider accepts a later request without restart")
    .expect("provider serves after capacity recovers");
    assert_eq!(recovered, nar);

    client.shutdown().await.unwrap();
    node.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_cancels_closed_supplier_with_no_surviving_work_or_progress() {
    let temp = TempDir::new("closed-supplier");
    let state = temp.state();
    let port = unused_port();
    let content = Blake3Digest::from_raw_nar(b"x");
    let never_release = Arc::new(AtomicBool::new(false));
    let mut supplier = MemoryNarSupplier::new([b"x".to_vec()]);
    supplier.block_until(content, never_release);
    let supplier = Arc::new(supplier);
    let node = IrohNodeBuilder::new(
        EndpointProfile {
            scope: EndpointScope::OfflineTest { port },
        },
        IdentitySource::Persistent {
            state_dir: state.clone(),
        },
        RelayCapability::Disabled,
        AddressLookupCapability::Disabled,
    )
    .unwrap()
    .provider(IrohProviderConfig::supplying(
        supplier.clone(),
        ServeBudget {
            max_nar_bytes_uncompressed_nar: 1024,
            max_inflight_bytes_uncompressed_nar: 1024,
            max_serve_duration: Duration::from_secs(30),
        },
        Duration::from_secs(1),
    ))
    .spawn()
    .await
    .unwrap();
    let provider = node.provider().unwrap();
    assert!(
        provider.event_driver_ready(),
        "IrohNodeBuilder::spawn must not return before the provider driver's first poll"
    );
    let client = IrohClientNode::spawn().await.unwrap();
    client.add_peer(&provider.addr().await.unwrap());
    let client_transport = client.transport_handle();
    let provider_id = provider.node_id().unwrap();
    let fetch = tokio::spawn(async move {
        client_transport
            .fetch(&content, &KnownTransport::Iroh { node: provider_id }, None)
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        while supplier.active_operations() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("supplier entered materialisation");

    node.shutdown().await.unwrap();
    assert_eq!(supplier.active_operations(), 0);
    assert_eq!(supplier.cancelled_operations(), 1);
    let ticks_after_shutdown = supplier.activity_ticks();
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(
        supplier.activity_ticks(),
        ticks_after_shutdown,
        "no supply work may make progress after shutdown returns"
    );
    let fetch_result = tokio::time::timeout(Duration::from_secs(1), fetch)
        .await
        .unwrap()
        .unwrap();
    assert!(fetch_result.is_err());
    let restarted = persistent_builder(state, port).spawn().await.unwrap();
    restarted.shutdown().await.unwrap();
    client.shutdown().await.unwrap();
}

#[tokio::test]
async fn retained_provider_and_transport_handles_are_fallible_after_shutdown() {
    let temp = TempDir::new("retained-handles");
    let state = temp.state();
    let port = unused_port();
    let node = IrohNodeBuilder::new(
        EndpointProfile {
            scope: EndpointScope::OfflineTest { port },
        },
        IdentitySource::Persistent {
            state_dir: state.clone(),
        },
        RelayCapability::Disabled,
        AddressLookupCapability::Disabled,
    )
    .unwrap()
    .provider(IrohProviderConfig::retaining(StoreRetention::RetainAll))
    .spawn()
    .await
    .unwrap();
    let provider = node.provider_handle().unwrap();
    let transport = node.transport_handle();
    let id = provider.node_id().unwrap();
    assert_eq!(node.shutdown().await.unwrap(), ShutdownOutcome::Graceful);

    assert!(provider.node_id().is_err());
    assert!(provider.bound_socket_addrs().is_err());
    assert!(provider.reachable_socket_addrs().is_err());
    assert!(provider.addr().await.is_err());
    assert!(transport.node_id().is_err());
    assert!(transport.bound_socket_addrs().is_err());

    let restarted = persistent_builder(state, port).spawn().await.unwrap();
    assert_eq!(restarted.node_id().unwrap(), id);
    restarted.shutdown().await.unwrap();
}

#[tokio::test]
async fn once_polled_outbound_future_cannot_retain_endpoint_owner_or_fixed_port() {
    let remote_endpoint = endpoint_support::bind_endpoint(DAEMON_TEST_ENDPOINT_PROFILE)
        .await
        .expect("remote endpoint");
    let remote_node = daemon::NodeId::from_bytes(*remote_endpoint.id().as_bytes());
    let remote_sockets = remote_endpoint.bound_sockets();
    let remote_router = Router::builder(remote_endpoint)
        .accept(
            IROH_BLOBS_ALPN,
            StallingOutbound {
                accepted: Arc::new(Notify::new()),
            },
        )
        .spawn();

    let temp = TempDir::new("retained-operation-future");
    let state = temp.state();
    let port = unused_port();
    let node = IrohNodeBuilder::new(
        EndpointProfile {
            scope: EndpointScope::OfflineTest { port },
        },
        IdentitySource::Persistent {
            state_dir: state.clone(),
        },
        RelayCapability::Disabled,
        AddressLookupCapability::Disabled,
    )
    .unwrap()
    .spawn()
    .await
    .unwrap();
    let id = node.node_id().unwrap();
    node.transport()
        .add_peer(&IrohPeerAddr::new(remote_node, remote_sockets));
    let transport = node.transport_handle();
    let content = Blake3Digest::from_raw_nar(b"retained unpolled operation");
    let offer = KnownTransport::Iroh { node: remote_node };
    let mut operation = Box::pin(transport.fetch(&content, &offer, None));
    std::future::poll_fn(|context| match operation.as_mut().poll(context) {
        std::task::Poll::Pending => std::task::Poll::Ready(()),
        std::task::Poll::Ready(result) => {
            panic!("stalling fetch unexpectedly completed on first poll: {result:?}")
        }
    })
    .await;

    node.shutdown().await.unwrap();
    assert!(transport.node_id().is_err(), "retained handle is weak");
    let restarted = persistent_builder(state, port)
        .spawn()
        .await
        .expect("retained once-polled future cannot retain the fixed socket");
    assert_eq!(restarted.node_id().unwrap(), id);
    drop(operation);
    restarted.shutdown().await.unwrap();
    remote_router.shutdown().await.unwrap();
}

struct PendingHttpSources {
    started: Arc<Notify>,
    dropped: Arc<AtomicBool>,
}

struct PendingHttpGuard(Arc<AtomicBool>);

impl Drop for PendingHttpGuard {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

#[async_trait]
impl NarSource for PendingHttpSources {
    async fn resolve(
        &self,
        _key: &NarKey,
        _expected_size: Option<u64>,
    ) -> Result<UpstreamResponse, SourceError> {
        let _guard = PendingHttpGuard(self.dropped.clone());
        self.started.notify_one();
        future::pending().await
    }
}

#[async_trait]
impl NarinfoSource for PendingHttpSources {
    async fn fetch(&self, _store_hash: &StoreHash) -> Result<UpstreamResponse, SourceError> {
        Err(SourceError::Upstream("unused pending test source".into()))
    }
}

#[async_trait]
impl RawUpstream for PendingHttpSources {
    async fn get(&self, _path: &str) -> Result<UpstreamResponse, SourceError> {
        Err(SourceError::Upstream("unused pending test source".into()))
    }
}

#[tokio::test]
async fn active_http_connection_shares_the_node_shutdown_supervisor() {
    let temp = TempDir::new("active-http");
    let state = temp.state();
    let port = unused_port();
    let node = IrohNodeBuilder::new(
        EndpointProfile {
            scope: EndpointScope::OfflineTest { port },
        },
        IdentitySource::Persistent {
            state_dir: state.clone(),
        },
        RelayCapability::Disabled,
        AddressLookupCapability::Disabled,
    )
    .unwrap()
    .spawn()
    .await
    .unwrap();
    let started = Arc::new(Notify::new());
    let started_wait = started.notified();
    let dropped = Arc::new(AtomicBool::new(false));
    let sources = Arc::new(PendingHttpSources {
        started: started.clone(),
        dropped: dropped.clone(),
    });
    let app = Arc::new(App {
        narinfo: sources.clone(),
        nar: sources.clone(),
        passthrough: sources,
        cache_info: CacheInfo::default(),
        catalog: Arc::new(NarCatalog::new()),
        upstream_label: "pending-http-test".into(),
        correlation: Arc::new(NullCorrelation),
        raw_serve: Arc::new(NoRawServe),
        public_allowlist: Arc::new(daemon::PublicNarAllowlist::disabled()),
    });
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let http_addr = listener.local_addr().unwrap();
    let supervisor = node.task_supervisor_handle();
    let server = tokio::spawn(async move { serve(listener, app, supervisor).await });
    let mut client = tokio::net::TcpStream::connect(http_addr).await.unwrap();
    client
        .write_all(b"GET /nar/pending HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), started_wait)
        .await
        .expect("HTTP request entered pending source");

    node.shutdown().await.unwrap();
    assert!(
        dropped.load(Ordering::Acquire),
        "node shutdown must drop the active HTTP response future before returning"
    );
    let restarted = persistent_builder(state, port).spawn().await.unwrap();
    restarted.shutdown().await.unwrap();
    server.abort();
    let _ = server.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_capacity_drops_one_connection_then_recovers_without_restart() {
    let supervisor = TaskSupervisor::new();
    let handle = supervisor.handle();
    let sources = Arc::new(PendingHttpSources {
        started: Arc::new(Notify::new()),
        dropped: Arc::new(AtomicBool::new(false)),
    });
    let app = Arc::new(App {
        narinfo: sources.clone(),
        nar: sources.clone(),
        passthrough: sources,
        cache_info: CacheInfo::default(),
        catalog: Arc::new(NarCatalog::new()),
        upstream_label: "http-capacity-test".into(),
        correlation: Arc::new(NullCorrelation),
        raw_serve: Arc::new(NoRawServe),
        public_allowlist: Arc::new(daemon::PublicNarAllowlist::disabled()),
    });
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let http_addr = listener.local_addr().unwrap();
    let server_handle = handle.clone();
    let server = tokio::spawn(async move { serve(listener, app, server_handle).await });

    // Fill the shared supervisor with bounded, quiescent work. The next HTTP
    // connection must be declined and dropped; the listener itself must remain
    // alive so capacity recovery needs no daemon restart.
    let (release_tx, release_rx) = tokio::sync::watch::channel(false);
    for index in 0..daemon::iroh_runtime::MAX_OWNED_TASKS {
        let mut release = release_rx.clone();
        handle
            .spawn(format!("http-capacity-filler-{index}"), async move {
                if !*release.borrow() {
                    let _ = release.wait_for(|released| *released).await;
                }
            })
            .expect("every slot up to the explicit capacity is admitted");
    }
    assert_eq!(
        handle.active_task_count().unwrap(),
        daemon::iroh_runtime::MAX_OWNED_TASKS
    );

    let mut declined = tokio::net::TcpStream::connect(http_addr).await.unwrap();
    declined
        .write_all(b"GET /nix-cache-info HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut byte = [0u8; 1];
    match tokio::time::timeout(Duration::from_secs(1), declined.read(&mut byte))
        .await
        .expect("saturated connection is dropped promptly")
    {
        Ok(0) | Err(_) => {}
        Ok(read) => panic!("saturated connection unexpectedly received {read} response byte(s)"),
    }
    assert!(
        !server.is_finished(),
        "capacity exhaustion must not terminate the HTTP accept loop"
    );

    release_tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while handle.active_task_count().unwrap() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("released filler tasks are continuously reaped");

    let mut recovered = tokio::net::TcpStream::connect(http_addr).await.unwrap();
    recovered
        .write_all(b"GET /nix-cache-info HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(1), recovered.read_to_end(&mut response))
        .await
        .expect("recovered HTTP connection completes promptly")
        .expect("recovered HTTP response is readable");
    let response = String::from_utf8(response).expect("cache-info response is UTF-8");
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.contains("StoreDir: /nix/store"), "{response}");
    assert!(
        !server.is_finished(),
        "accept loop remains healthy after a recovered connection"
    );

    supervisor.cancel_now();
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn forced_shutdown_cancels_an_active_outbound_fetch_before_fixed_port_restart() {
    let remote_endpoint = endpoint_support::bind_endpoint(DAEMON_TEST_ENDPOINT_PROFILE)
        .await
        .expect("remote stalling endpoint");
    let remote_node = daemon::NodeId::from_bytes(*remote_endpoint.id().as_bytes());
    let remote_sockets = remote_endpoint.bound_sockets();
    let accepted = Arc::new(Notify::new());
    let accepted_wait = accepted.notified();
    let remote_router = Router::builder(remote_endpoint)
        .accept(
            IROH_BLOBS_ALPN,
            StallingOutbound {
                accepted: accepted.clone(),
            },
        )
        .spawn();

    let temp = TempDir::new("forced-active-restart");
    let state = temp.state();
    let port = unused_port();
    let node = IrohNodeBuilder::new(
        EndpointProfile {
            scope: EndpointScope::OfflineTest { port },
        },
        IdentitySource::Persistent {
            state_dir: state.clone(),
        },
        RelayCapability::Disabled,
        AddressLookupCapability::Disabled,
    )
    .unwrap()
    .safety_envelope(SafetyEnvelope {
        dial_timeout: Duration::from_secs(5),
        body_idle_timeout: Duration::from_secs(30),
        total_timeout: Duration::from_secs(30),
    })
    .accept(b"/nix-p2p/hanging-shutdown/active/1", HangingShutdown)
    .unwrap()
    .shutdown_deadline(Duration::from_millis(75))
    .unwrap()
    .spawn()
    .await
    .expect("fixed-port client runtime");
    let id = node.node_id().unwrap();
    node.transport()
        .add_peer(&IrohPeerAddr::new(remote_node, remote_sockets));
    let surviving_handle = node.transport_handle();
    let fetch_handle = surviving_handle.clone();
    let fetch = tokio::spawn(async move {
        let content = Blake3Digest::from_raw_nar(b"remote deliberately never returns this NAR");
        fetch_handle
            .fetch(&content, &KnownTransport::Iroh { node: remote_node }, None)
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), accepted_wait)
        .await
        .expect("outbound connection became active before shutdown");

    assert_eq!(node.shutdown().await.unwrap(), ShutdownOutcome::Forced);
    assert!(
        surviving_handle.node_id().is_err(),
        "a surviving application handle is inert after runtime shutdown"
    );
    let fetch_result = tokio::time::timeout(Duration::from_secs(1), fetch)
        .await
        .expect("active outbound fetch is cancelled by endpoint close")
        .expect("fetch task does not panic");
    assert!(
        fetch_result.is_err(),
        "a closed endpoint cannot complete the fetch"
    );

    let restarted = persistent_builder(state, port)
        .spawn()
        .await
        .expect("active outbound fetch released the fixed port");
    assert_eq!(restarted.node_id().unwrap(), id);
    restarted.shutdown().await.unwrap();
    remote_router.shutdown().await.unwrap();
}

const ECHO_ALPN: &[u8] = b"/nix-p2p/task115-echo/1";

#[derive(Debug, Clone)]
struct Echo;

impl ProtocolHandler for Echo {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let (mut send, mut recv) = connection.accept_bi().await?;
        let bytes = recv
            .read_to_end(1024)
            .await
            .map_err(AcceptError::from_err)?;
        send.write_all(&bytes)
            .await
            .map_err(AcceptError::from_err)?;
        send.finish()?;
        connection.closed().await;
        Ok(())
    }
}

#[tokio::test]
async fn active_inbound_connection_is_cancelled_before_fixed_port_restart() {
    let temp = TempDir::new("active-inbound");
    let state = temp.state();
    let port = unused_port();
    let accepted = Arc::new(Notify::new());
    let accepted_wait = accepted.notified();
    let node = IrohNodeBuilder::new(
        EndpointProfile {
            scope: EndpointScope::OfflineTest { port },
        },
        IdentitySource::Persistent {
            state_dir: state.clone(),
        },
        RelayCapability::Disabled,
        AddressLookupCapability::Disabled,
    )
    .unwrap()
    .provider(IrohProviderConfig::retaining(StoreRetention::RetainAll))
    .accept(
        ECHO_ALPN,
        StallingOutbound {
            accepted: accepted.clone(),
        },
    )
    .unwrap()
    .spawn()
    .await
    .unwrap();
    let provider = node.provider().unwrap();
    let client = endpoint_support::bind_endpoint(DAEMON_TEST_ENDPOINT_PROFILE)
        .await
        .unwrap();
    let retained_connection = client
        .connect(
            endpoint_support::provider_addr(provider).unwrap(),
            ECHO_ALPN,
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), accepted_wait)
        .await
        .expect("inbound handler became active");

    node.shutdown().await.unwrap();
    let restarted = persistent_builder(state, port)
        .spawn()
        .await
        .expect("active inbound connection cannot retain the listen socket");
    restarted.shutdown().await.unwrap();
    drop(retained_connection);
    client.close().await;
}

#[tokio::test]
async fn application_handler_cannot_collide_with_implicit_blobs_alpn() {
    let result = IrohNodeBuilder::offline_ephemeral()
        .unwrap()
        .accept(IROH_BLOBS_ALPN, Echo)
        .unwrap()
        .provider(IrohProviderConfig::retaining(StoreRetention::RetainAll))
        .spawn()
        .await;
    let error = match result {
        Ok(node) => {
            node.shutdown().await.unwrap();
            panic!("implicit provider ALPN collision must fail before bind")
        }
        Err(error) => error,
    };
    assert!(error.to_string().contains("duplicate Iroh ALPN"), "{error}");
}

#[tokio::test]
async fn provider_fetch_and_application_handler_share_one_identity_and_socket_set() {
    let node = IrohNodeBuilder::offline_ephemeral()
        .expect("offline node")
        .provider(IrohProviderConfig::retaining(StoreRetention::RetainAll))
        .accept(ECHO_ALPN, Echo)
        .expect("unique application ALPN")
        .spawn()
        .await
        .expect("shared node");
    let provider = node.provider().expect("provider installed");
    assert_eq!(provider.node_id().unwrap(), node.node_id().unwrap());
    assert_eq!(node.transport().node_id().unwrap(), node.node_id().unwrap());
    assert_eq!(
        provider.bound_socket_addrs().unwrap(),
        node.bound_socket_addrs().unwrap()
    );
    assert_eq!(
        node.transport().bound_socket_addrs().unwrap(),
        provider.bound_socket_addrs().unwrap()
    );

    let client = endpoint_support::bind_endpoint(DAEMON_TEST_ENDPOINT_PROFILE)
        .await
        .expect("raw client uses shared constructor");
    let connection = client
        .connect(
            endpoint_support::provider_addr(provider).expect("provider endpoint address"),
            ECHO_ALPN,
        )
        .await
        .expect("custom handler is on provider runtime router");
    let (mut send, mut recv) = connection.open_bi().await.expect("echo stream");
    send.write_all(b"one-router")
        .await
        .expect("write echo request");
    send.finish().expect("finish request");
    let echoed = recv.read_to_end(1024).await.expect("read echo response");
    assert_eq!(echoed, b"one-router");
    connection.close(VarInt::from_u32(0), b"done");
    client.close().await;
    node.shutdown().await.unwrap();
}

#[test]
fn benchmark_endpoint_construction_cannot_bypass_the_shared_runtime_constructor() {
    fn executable_tokens(source: &str) -> String {
        #[derive(Clone, Copy)]
        enum State {
            Code,
            LineComment,
            BlockComment,
            String,
        }
        let bytes = source.as_bytes();
        let mut state = State::Code;
        let mut escaped = false;
        let mut output = String::new();
        let mut index = 0;
        while index < bytes.len() {
            let byte = bytes[index];
            let next = bytes.get(index + 1).copied();
            match state {
                State::Code if byte == b'/' && next == Some(b'/') => {
                    state = State::LineComment;
                    index += 1;
                }
                State::Code if byte == b'/' && next == Some(b'*') => {
                    state = State::BlockComment;
                    index += 1;
                }
                State::Code if byte == b'"' => state = State::String,
                State::Code => {
                    if !byte.is_ascii_whitespace() {
                        output.push(byte as char);
                    }
                }
                State::LineComment if byte == b'\n' => state = State::Code,
                State::BlockComment if byte == b'*' && next == Some(b'/') => {
                    state = State::Code;
                    index += 1;
                }
                State::String => {
                    let terminator = b'"';
                    if escaped {
                        escaped = false;
                    } else if byte == b'\\' {
                        escaped = true;
                    } else if byte == terminator {
                        state = State::Code;
                    }
                }
                _ => {}
            }
            index += 1;
        }
        output
    }

    let runtime = executable_tokens(include_str!("../../fabric-iroh/src/iroh_runtime.rs"));
    assert_eq!(
        runtime
            .matches("Endpoint::builder(presets::Minimal)")
            .count(),
        1,
        "one centralized Minimal constructor is the only endpoint construction site"
    );
    for required in [
        ".clear_ip_transports()",
        ".clear_relay_transports()",
        ".clear_address_lookup()",
        ".portmapper_config(PortmapperConfig::Disabled)",
        ".net_report_config(NetReportConfig::minimal())",
    ] {
        assert!(
            runtime.contains(required),
            "offline safety policy lost {required}"
        );
    }

    let consumers = [
        ("benchmark", include_str!("../examples/iroh_throughput.rs")),
        (
            "transport",
            include_str!("../../fabric-iroh/src/transport_iroh.rs"),
        ),
        ("daemon", include_str!("../src/main.rs")),
        ("safety test", include_str!("iroh_safety_envelope.rs")),
    ];
    for (name, source) in consumers {
        let tokens = executable_tokens(source);
        for forbidden in [
            "Endpoint::builder(",
            "Endpoint::bind(",
            "iroh::Endpoint::builder(",
            "endpoint::Builder::",
            "BuilderasEndpointBuilder",
        ] {
            assert!(
                !tokens.contains(forbidden),
                "{name} bypasses the shared constructor through {forbidden}"
            );
        }
    }

    let benchmark = executable_tokens(include_str!("../examples/iroh_throughput.rs"));
    assert!(
        benchmark.contains("bind_endpoint(BENCHMARK_ENDPOINT_PROFILE)"),
        "benchmark endpoint creation must use the daemon-owned constructor"
    );
}
