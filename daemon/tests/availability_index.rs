//! The local availability index + claim producer (task-50), driven through the
//! PUBLIC `daemon` API - which also proves the surface is usable from outside the
//! crate (task-40 discovery is a downstream consumer of exactly these calls).
//!
//! The bites here:
//!   * yes/no from the REAL store, no enumeration (there is simply no listing call);
//!   * SINGLE-FLIGHT: N concurrent probes of one uncomputed key dump+hash ONCE
//!     (proven by a counting dumper) and all observe the same digest;
//!   * the COMPLETE offer (NodeId + Blake3 + transport), not merely a holder;
//!   * PERSISTENCE across a simulated restart, and a corrupt index fails LOUD;
//!   * a removed (GC'd) store path DROPS from availability and is pruned;
//!   * the computed BLAKE3 reproduces the task-48 golden recipe vectors (the digest
//!     is COMPUTED via the frozen recipe, never hardcoded).
//!
//! Nothing here names the generated fixture tree (the source guard forbids it):
//! each test synthesises its own NAR bytes / store paths in a temp dir.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::time::Duration;

use daemon::{
    AnnounceSink, AvailabilityIndex, Blake3Digest, Claim, HoldAnswer, HoldQuery, JsonFileStore,
    KnownPayload, KnownTransport, MemoryNarDumper, NarDumper, NarHashKey, NodeId, NullAnnounce,
    NullStore, QUERY_SCHEMA_VERSION, StorePath,
};

// ------------------------------------------------------------------ helpers

/// A unique temp directory that removes itself on drop, so parallel test runs and
/// a re-run never collide or leak.
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
            "nixp2p-avail-{label}-{}-{n}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        TempDir { path }
    }

    fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    /// Create a real file that stands in for a materialised store path.
    fn store_file(&self, name: &str) -> StorePath {
        let p = self.join(name);
        std::fs::write(&p, b"stand-in store path contents").expect("write store file");
        StorePath::new(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// A dumper that returns FIXED bytes, counts how many times it is invoked, and can
/// sleep to widen the single-flight contention window. The count is the bite: if
/// single-flight holds, it is 1 no matter how many callers raced.
struct CountingDumper;

impl CountingDumper {
    fn pair(bytes: Vec<u8>) -> (Arc<MemoryNarDumper>, Arc<MemoryNarDumper>) {
        let dumper = Arc::new(MemoryNarDumper::new(bytes));
        (dumper.clone(), dumper)
    }

    fn with_delay(bytes: Vec<u8>, delay: Duration) -> (Arc<MemoryNarDumper>, Arc<MemoryNarDumper>) {
        let dumper = Arc::new(MemoryNarDumper::with_delay(bytes, delay));
        (dumper.clone(), dumper)
    }
}

struct AtomicCancellation(Arc<std::sync::atomic::AtomicBool>);

impl daemon::availability::CancellationCheck for AtomicCancellation {
    fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

#[test]
fn command_dumper_cancellation_kills_and_reaps_its_process_group() {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new("command-cancel");
    let program = temp.join("fake-nix-store");
    let pid_file = temp.join("pids");
    std::fs::write(
        &program,
        br#"#!/bin/sh
child_loop() {
  trap '' TERM
  while :; do sleep 1; done
}
child_loop &
child_pid=$!
echo "$$ $child_pid" > "$2"
trap '' TERM
wait
"#,
    )
    .unwrap();
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
    let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let cancellation = AtomicCancellation(cancelled.clone());
    let path = StorePath::new(pid_file.clone());
    let worker = std::thread::spawn(move || {
        daemon::CommandNarDumper::with_program(program).dump(&path, &cancellation)
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !pid_file.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    let pids = std::fs::read_to_string(&pid_file).expect("fake dumper recorded its process group");
    cancelled.store(true, Ordering::Release);
    let error = worker
        .join()
        .expect("dumper thread")
        .expect_err("cancellation must fail the dump loudly");
    assert!(error.to_string().contains("cancelled"), "{error}");

    for raw_pid in pids.split_whitespace() {
        let pid = rustix::process::Pid::from_raw(raw_pid.parse::<i32>().unwrap()).unwrap();
        let reaped_by = std::time::Instant::now() + Duration::from_secs(2);
        while rustix::process::test_kill_process(pid).is_ok()
            && std::time::Instant::now() < reaped_by
        {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            rustix::process::test_kill_process(pid).is_err(),
            "cancelled process {pid} survived its dumper"
        );
    }
}

/// An announce sink that records every claim it is handed.
#[derive(Default)]
struct RecordingAnnounce {
    claims: Mutex<Vec<Claim>>,
}

impl AnnounceSink for RecordingAnnounce {
    fn announce(&self, claim: Claim) {
        self.claims.lock().unwrap().push(claim);
    }
}

/// Serialise one `nix-archive-1` NAR token (u64-LE length, bytes, zero-pad to 8).
fn nar_str(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(bytes);
    let pad = (8 - (bytes.len() % 8)) % 8;
    out.extend(std::iter::repeat_n(0u8, pad));
}

/// A genuine raw NAR for a single regular file (what `nix-store --dump` emits).
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

fn node() -> NodeId {
    NodeId::from_bytes([0x11; 32])
}

fn key_from(byte: u8) -> NarHashKey {
    NarHashKey::from_sha256_bytes([byte; 32])
}

// ------------------------------------------------------------- yes / no / offer

#[test]
fn unregistered_key_is_absent_and_there_is_no_listing_call() {
    // The ONLY probe is per-key hold(); the API has no "list holdings" method, so a
    // node can only ever be asked yes/no about a concrete NarHash it already names.
    let (dumper, _calls) = CountingDumper::pair(synth_raw_nar(b"unused"));
    let index =
        AvailabilityIndex::open(node(), dumper, Arc::new(NullStore), Arc::new(NullAnnounce))
            .expect("open");

    assert_eq!(
        index.hold(&key_from(0x01)).expect("hold"),
        HoldAnswer::Absent,
        "a key this node never registered is Absent, not an error and not a leak"
    );
}

#[test]
fn a_held_key_yields_the_complete_offer_from_the_real_store() {
    let tmp = TempDir::new("offer");
    let nar = synth_raw_nar(b"the payload this node actually holds");
    let expected = Blake3Digest::from_raw_nar(&nar);

    let (dumper, calls) = CountingDumper::pair(nar);
    let index =
        AvailabilityIndex::open(node(), dumper, Arc::new(NullStore), Arc::new(NullAnnounce))
            .expect("open");

    let key = key_from(0x02);
    index
        .register(key, tmp.store_file("held.nar"))
        .expect("register");

    // yes/no probe -> Have with the COMPUTED blake3 and an Iroh offer.
    match index.hold(&key).expect("hold") {
        HoldAnswer::Have { blake3, offers } => {
            assert_eq!(blake3, expected, "the digest is computed, not hardcoded");
            assert_eq!(offers, vec![KnownTransport::Iroh { node: node() }]);
        }
        HoldAnswer::Absent => panic!("a registered, materialised path must be Have"),
    }

    // The COMPLETE claim: blake3 to address + this node as holder + an Iroh offer -
    // a downstream fetch has everything (the task-40 "return the whole offer" find).
    let claim = index
        .claim(&key)
        .expect("claim")
        .expect("held -> Some claim");
    assert_eq!(claim.key, key);
    assert_eq!(
        claim.content_id(),
        Some(&expected),
        "the claim carries the single content identity to fetch"
    );
    assert_eq!(claim.holders, vec![node()], "the holder NodeId to dial");
    assert_eq!(
        claim.transports,
        vec![KnownTransport::Iroh { node: node() }],
        "the transport locator to fetch over"
    );
    assert!(matches!(
        claim.payload,
        Some(KnownPayload::WholeNar { blake3 }) if blake3 == expected
    ));

    // The versioned wire envelope mirrors the same yes/no answer.
    let response = index
        .answer(&HoldQuery {
            schema_version: QUERY_SCHEMA_VERSION,
            key,
        })
        .expect("answer");
    assert_eq!(response.schema_version, QUERY_SCHEMA_VERSION);
    assert!(matches!(response.answer, HoldAnswer::Have { .. }));

    // All of the above shared ONE computed digest (single-flight cache), so the
    // dump ran once across hold + claim + answer, not three times.
    assert_eq!(calls.calls(), 1, "digest computed once, then cached");
}

// ---------------------------------------------------------------- single-flight

#[test]
fn concurrent_probes_hash_the_nar_exactly_once() {
    // The real correctness point: N peers probing the same uncomputed key at once
    // must trigger EXACTLY ONE dump+hash of a (here, stand-in for a 100 MiB) NAR.
    let tmp = TempDir::new("single-flight");
    let nar = synth_raw_nar(b"a big NAR that must be hashed exactly once");
    let expected = Blake3Digest::from_raw_nar(&nar);

    // A delay widens the window so a broken (check-then-compute) index would race
    // multiple dumps through it - making the count-once assertion a real bite.
    let (dumper, calls) = CountingDumper::with_delay(nar, Duration::from_millis(50));
    let index = Arc::new(
        AvailabilityIndex::open(node(), dumper, Arc::new(NullStore), Arc::new(NullAnnounce))
            .expect("open"),
    );

    let key = key_from(0x03);
    index
        .register(key, tmp.store_file("big.nar"))
        .expect("register");

    const N: usize = 16;
    let barrier = Arc::new(Barrier::new(N));
    let mut handles = Vec::with_capacity(N);
    for _ in 0..N {
        let index = index.clone();
        let barrier = barrier.clone();
        handles.push(std::thread::spawn(move || {
            barrier.wait(); // release all threads at once for maximum contention
            index.hold(&key).expect("hold")
        }));
    }
    let answers: Vec<HoldAnswer> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    assert_eq!(
        calls.calls(),
        1,
        "single-flight FAILED: {N} concurrent callers dumped/hashed the NAR more than once"
    );
    for answer in &answers {
        match answer {
            HoldAnswer::Have { blake3, .. } => assert_eq!(*blake3, expected),
            HoldAnswer::Absent => panic!("a materialised held key must be Have"),
        }
    }
}

// ------------------------------------------------------------------ persistence

#[test]
fn registrations_survive_a_restart() {
    let tmp = TempDir::new("persist");
    let index_file = tmp.join("availability-index.json");
    let store_path = tmp.store_file("kept.nar");
    let nar = synth_raw_nar(b"content served after a restart");
    let expected = Blake3Digest::from_raw_nar(&nar);
    let key = key_from(0x04);

    // Boot 1: register, then drop the whole index (simulated shutdown).
    {
        let (dumper, _calls) = CountingDumper::pair(nar.clone());
        let index = AvailabilityIndex::open(
            node(),
            dumper,
            Arc::new(JsonFileStore::new(&index_file)),
            Arc::new(NullAnnounce),
        )
        .expect("open boot 1");
        index.register(key, store_path.clone()).expect("register");
    }
    assert!(
        index_file.is_file(),
        "the registration was persisted to disk"
    );

    // Boot 2: a fresh index loads the file and still answers Have, recomputing the
    // derived digest (which is deliberately NOT persisted).
    let (dumper, calls) = CountingDumper::pair(nar);
    let index = AvailabilityIndex::open(
        node(),
        dumper,
        Arc::new(JsonFileStore::new(&index_file)),
        Arc::new(NullAnnounce),
    )
    .expect("open boot 2");
    match index.hold(&key).expect("hold after restart") {
        HoldAnswer::Have { blake3, .. } => assert_eq!(blake3, expected),
        HoldAnswer::Absent => panic!("a persisted registration must survive restart"),
    }
    assert_eq!(
        calls.calls(),
        1,
        "the derived digest is recomputed once after restart (not persisted)"
    );
}

#[test]
fn a_corrupt_index_file_fails_loud_not_silently_empty() {
    let tmp = TempDir::new("corrupt");
    let index_file = tmp.join("availability-index.json");

    // Not JSON at all.
    std::fs::write(&index_file, b"this is not json").unwrap();
    let (dumper, _calls) = CountingDumper::pair(vec![]);
    assert!(
        AvailabilityIndex::open(
            node(),
            dumper.clone(),
            Arc::new(JsonFileStore::new(&index_file)),
            Arc::new(NullAnnounce),
        )
        .is_err(),
        "a corrupt index must fail loud, not lose the holdings silently"
    );

    // Valid JSON, but a non-canonical NarHash key: still rejected (the key routes
    // discovery; a bad one would split the network).
    std::fs::write(&index_file, br#"{"not-a-nar-hash":"/nix/store/x"}"#).unwrap();
    assert!(
        AvailabilityIndex::open(
            node(),
            dumper,
            Arc::new(JsonFileStore::new(&index_file)),
            Arc::new(NullAnnounce),
        )
        .is_err(),
        "a non-canonical key in the index file must be rejected"
    );
}

// -------------------------------------------------------- materialisation / GC

#[test]
fn a_removed_store_path_drops_from_availability_and_is_pruned() {
    let tmp = TempDir::new("gc");
    let index_file = tmp.join("availability-index.json");
    let store_path = tmp.store_file("gc-me.nar");
    let key = key_from(0x05);

    let (dumper, _calls) = CountingDumper::pair(synth_raw_nar(b"soon to be GC'd"));
    let index = AvailabilityIndex::open(
        node(),
        dumper,
        Arc::new(JsonFileStore::new(&index_file)),
        Arc::new(NullAnnounce),
    )
    .expect("open");
    index.register(key, store_path.clone()).expect("register");

    // Present while materialised.
    assert!(matches!(
        index.hold(&key).expect("hold"),
        HoldAnswer::Have { .. }
    ));

    // Simulate a GC: the store path vanishes.
    std::fs::remove_file(store_path.as_path()).expect("remove store path");

    // Now Absent - availability is read from the filesystem, not stale bookkeeping.
    assert_eq!(
        index.hold(&key).expect("hold after gc"),
        HoldAnswer::Absent,
        "a GC'd path must drop from availability"
    );

    // And the stale registration was pruned + persisted: a fresh index does not
    // resurrect it.
    let (dumper2, _c) = CountingDumper::pair(vec![]);
    let reopened = AvailabilityIndex::open(
        node(),
        dumper2,
        Arc::new(JsonFileStore::new(&index_file)),
        Arc::new(NullAnnounce),
    )
    .expect("reopen");
    assert_eq!(
        reopened.hold(&key).expect("hold"),
        HoldAnswer::Absent,
        "the pruned registration was persisted, not just forgotten in memory"
    );
}

#[test]
fn retiring_one_same_digest_registration_preserves_its_sibling() {
    let tmp = TempDir::new("same-digest-siblings");
    let nar = synth_raw_nar(b"shared payload");
    let digest = Blake3Digest::from_raw_nar(&nar);
    let (dumper, _calls) = CountingDumper::pair(nar);
    let index =
        AvailabilityIndex::open(node(), dumper, Arc::new(NullStore), Arc::new(NullAnnounce))
            .unwrap();
    let first = key_from(0x51);
    let second = key_from(0x52);
    index.register(first, tmp.store_file("first")).unwrap();
    index.register(second, tmp.store_file("second")).unwrap();
    assert!(matches!(
        index.hold(&first).unwrap(),
        HoldAnswer::Have { .. }
    ));
    assert!(matches!(
        index.hold(&second).unwrap(),
        HoldAnswer::Have { .. }
    ));

    index.unregister(&second).unwrap();
    index.unregister(&second).unwrap(); // retirement is explicitly idempotent
    let cancellation = AtomicCancellation(Arc::new(std::sync::atomic::AtomicBool::new(false)));
    assert_eq!(
        index
            .supply_size_cancellable(&digest, &cancellation)
            .unwrap(),
        Some(synth_raw_nar(b"shared payload").len() as u64),
        "the first registration still owns an independent catalog record"
    );

    index.unregister(&first).unwrap();
    index.unregister(&first).unwrap();
    assert_eq!(
        index
            .supply_size_cancellable(&digest, &cancellation)
            .unwrap(),
        None,
        "the digest disappears only after its final owner retires"
    );
}

#[test]
fn stale_derivation_cannot_resurrect_a_replaced_registration() {
    let tmp = TempDir::new("stale-derive-replacement");
    let nar = synth_raw_nar(b"replacement race payload");
    let digest = Blake3Digest::from_raw_nar(&nar);
    let (dumper, calls) = CountingDumper::with_delay(nar, Duration::from_millis(100));
    let index = Arc::new(
        AvailabilityIndex::open(node(), dumper, Arc::new(NullStore), Arc::new(NullAnnounce))
            .unwrap(),
    );
    let key = key_from(0x53);
    index.register(key, tmp.store_file("old")).unwrap();
    let holding = {
        let index = Arc::clone(&index);
        std::thread::spawn(move || index.hold(&key))
    };
    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    while calls.calls() == 0 && std::time::Instant::now() < deadline {
        std::thread::yield_now();
    }
    assert_eq!(calls.calls(), 1, "old derivation entered its slow dump");
    index.register(key, tmp.store_file("new")).unwrap();
    assert!(matches!(
        holding.join().unwrap().unwrap(),
        HoldAnswer::Have { .. }
    ));
    assert_eq!(
        calls.calls(),
        2,
        "stale hold retries and derives the current registration"
    );

    index.unregister(&key).unwrap();
    let cancellation = AtomicCancellation(Arc::new(std::sync::atomic::AtomicBool::new(false)));
    assert_eq!(
        index
            .supply_size_cancellable(&digest, &cancellation)
            .unwrap(),
        None,
        "retiring the replacement must not reveal the stale old entry"
    );
}

// ---------------------------------------------------------- announce-on-demand

#[test]
fn publish_announces_the_complete_claim_only_when_held() {
    let tmp = TempDir::new("announce");
    let nar = synth_raw_nar(b"announced payload");
    let expected = Blake3Digest::from_raw_nar(&nar);
    let sink = Arc::new(RecordingAnnounce::default());

    let (dumper, _calls) = CountingDumper::pair(nar);
    let index =
        AvailabilityIndex::open(node(), dumper, Arc::new(NullStore), sink.clone()).expect("open");

    // Not held yet -> nothing announced.
    let unheld = key_from(0x06);
    assert!(index.publish(&unheld).expect("publish").is_none());
    assert!(sink.claims.lock().unwrap().is_empty());

    // Held -> the complete claim is announced.
    let key = key_from(0x07);
    index
        .register(key, tmp.store_file("ann.nar"))
        .expect("register");
    let published = index.publish(&key).expect("publish").expect("held -> Some");
    assert_eq!(published.content_id(), Some(&expected));

    let recorded = sink.claims.lock().unwrap();
    assert_eq!(recorded.len(), 1, "exactly the held claim was announced");
    assert_eq!(
        recorded[0], published,
        "the announced claim is the complete offer"
    );
    assert_eq!(recorded[0].holders, vec![node()]);
    assert_eq!(
        recorded[0].transports,
        vec![KnownTransport::Iroh { node: node() }]
    );
}

// ----------------------------------------------- computed blake3 == golden

#[test]
fn computed_digest_reproduces_the_task48_golden_recipe_vectors() {
    // The index computes the addressed unit with the FROZEN recipe
    // (Blake3Digest::from_raw_nar over the exact --dump bytes). Feed the committed
    // task-48 golden recipe-vector inputs through the index's dump->hash pipeline
    // and assert the produced digest equals the golden string. This BITES: a keyed
    // or domain-separated recipe (or a hardcoded digest) would not land here. The
    // fixture-specific golden (blake3:95f49df0... for the `lib` NAR) is re-derived
    // from the real `nix-store --dump` bytes by scripts/check-golden-vectors.py,
    // over this very same recipe - the two halves share one source of truth.
    const GOLDEN: &str = include_str!("golden/raw_nar_v1.json");
    let doc: serde_json::Value = serde_json::from_str(GOLDEN).expect("golden JSON");
    let vectors = doc["recipe_vectors"].as_array().expect("recipe_vectors");
    assert!(
        !vectors.is_empty(),
        "there must be recipe vectors to bite on"
    );

    let tmp = TempDir::new("golden");
    for (i, vector) in vectors.iter().enumerate() {
        let input = vector["input_utf8"]
            .as_str()
            .expect("input_utf8")
            .as_bytes()
            .to_vec();
        let expected_str = vector["blake3"].as_str().expect("blake3");

        // A fresh index whose dumper yields exactly these golden bytes.
        let (dumper, _calls) = CountingDumper::pair(input.clone());
        let index =
            AvailabilityIndex::open(node(), dumper, Arc::new(NullStore), Arc::new(NullAnnounce))
                .expect("open");
        let key = key_from(0x40 + i as u8);
        index
            .register(key, tmp.store_file(&format!("vec-{i}.nar")))
            .expect("register");

        match index.hold(&key).expect("hold") {
            HoldAnswer::Have { blake3, .. } => assert_eq!(
                blake3.to_string(),
                expected_str,
                "the index must reproduce the golden digest via the frozen recipe"
            ),
            HoldAnswer::Absent => panic!("registered + materialised must be Have"),
        }
    }
}
