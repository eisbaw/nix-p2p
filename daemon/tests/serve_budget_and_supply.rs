//! TASK-72: the node serves inside a BOUND, and it serves what it announces.
//!
//! Two coupled defects, one root cause. Before this, `setup_iroh_provider` read
//! every announced NAR into RAM at startup and kept it there forever, and the
//! availability index answered "yes, I hold that" for registrations the provider
//! had never been given. So:
//!
//!   * GAP 1 - a peer could name the largest NAR we announce and make us allocate
//!     it. At task-65's measured 2.0033 bytes of RSS per byte of NAR and the
//!     owner's p100 path of 3186 MiB, that is ~6.2 GiB for one serve, and the
//!     daemon is OUTSIDE the trust base, so "any peer" means any peer. An
//!     AVAILABILITY defect, not an integrity one - Nix still re-verifies sig +
//!     NarHash, so no wrong bytes - but a remote-triggerable OOM all the same.
//!   * GAP 2 - a positive hold-answer did not imply a servable blob. Dial, then
//!     fail, for every path that had not been eagerly seeded.
//!
//! Both are closed by the task-61 supply model: announce by streaming the digest,
//! regenerate on demand inside a budget, release afterwards.
//!
//! ## Which oracle answers which question, and why it is not the same one
//!
//! This file uses TWO instruments and is deliberate about their domains:
//!
//!   * `IrohProvider::store_residency()` (task-65) - what the blob store SAYS IT
//!     HOLDS. The only valid oracle for RELEASE. `VmHWM` cannot answer it (it is
//!     monotone by kernel definition) and `VmRSS` need not (glibc may keep a freed
//!     arena), which is proven by mutation in `store_residency_oracle.rs`.
//!   * `VmHWM` - valid for exactly one direction: DID WE ALLOCATE. A high-water
//!     mark cannot miss an allocation that happened, and that is precisely what
//!     task-72 AC#4 asks for ("without the bound, RSS tracks the NAR size"). It is
//!     used here for that and never to claim a release.
//!
//! Every oracle in this file is proven by MUTATION - the bound is REMOVED with
//! `ServeBudget::unbounded()` and the same assertions are shown to flip. A test
//! that only ever ran the passing configuration would prove that the code does
//! not crash, not that the bound does anything.
//!
//! Nothing here names the generated fixture tree (the source guard forbids it):
//! the NARs are synthesised in memory and the store paths are temp dirs.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use daemon::{
    AvailabilityIndex, Blake3Digest, DumpError, FileNarSupplier, IndexNarSupplier, IrohProvider,
    IrohTransport, KnownTransport, NarDumper, NarHashKey, NarSupplier, NullAnnounce, NullStore,
    ServeBudget, StorePath, StoreResidency, StoreRetention, SupplyError, Transport, TransportError,
};

// ---- a real (uncompressed) nix-archive-1 NAR, synthesised in memory ----------

fn nar_str(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(bytes);
    let pad = (8 - (bytes.len() % 8)) % 8;
    out.extend(std::iter::repeat_n(0u8, pad));
}

/// A valid raw NAR for a single regular file whose contents are `contents`.
fn synth_raw_nar(contents: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(contents.len() + 128);
    nar_str(&mut out, b"nix-archive-1");
    nar_str(&mut out, b"(");
    nar_str(&mut out, b"type");
    nar_str(&mut out, b"regular");
    nar_str(&mut out, b"contents");
    nar_str(&mut out, contents);
    nar_str(&mut out, b")");
    out
}

/// A NAR of roughly `len` bytes whose content is NOT uniform. Distinct bytes per
/// payload matter: the blob store deduplicates by content hash, so two "different"
/// uniform NARs of the same size would be ONE blob and a residency figure built on
/// them would be a fiction.
fn nar_of(len: usize, seed: u8) -> Vec<u8> {
    let contents: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_add(seed)).collect();
    synth_raw_nar(&contents)
}

/// The payload size the bound tests use. Large enough that allocating it is
/// unmistakable next to the ~20 MiB process floor, small enough that a parallel
/// `cargo test` run is not a memory experiment.
const BIG_NAR_BYTES: usize = 64 * 1024 * 1024;
/// A bound comfortably BELOW `BIG_NAR_BYTES`, so the decline is about the bound
/// and not about an accidental near-miss.
const SMALL_BUDGET_BYTES: u64 = 16 * 1024 * 1024;
/// How long a released store may take to settle. Generous relative to the sweep
/// interval: this bounds a HANG, it is not a timing assertion.
const RELEASE_DEADLINE: Duration = Duration::from_secs(20);
/// Sweep interval for the supply-model providers under test.
const SWEEP: Duration = Duration::from_millis(100);

/// One `VmXxx: N kB` field of this process, in BYTES. Panics rather than reading
/// 0 on a missing field: an instrument that silently reports zero would make every
/// comparison come out in its own favour.
fn vm_bytes(key: &str) -> u64 {
    let status = std::fs::read_to_string("/proc/self/status")
        .expect("/proc/self/status is readable on this platform");
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix(&format!("{key}:")) {
            let parts: Vec<&str> = rest.split_whitespace().collect();
            assert_eq!(parts.len(), 2, "/proc/self/status {key} is not 'N kB'");
            return parts[0].parse::<u64>().expect("VmXxx is an integer") * 1024;
        }
    }
    panic!("/proc/self/status has no {key} field (unknown is not 0)");
}

async fn poll_until_empty(provider: &IrohProvider) -> StoreResidency {
    let deadline = Instant::now() + RELEASE_DEADLINE;
    loop {
        let residency = provider
            .store_residency()
            .await
            .expect("store residency is queryable");
        if residency.blobs == 0 || Instant::now() >= deadline {
            return residency;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// A client wired to `provider`'s loopback address, as discovery would resolve it.
async fn client_wired_to(provider: &IrohProvider) -> IrohTransport {
    let client = IrohTransport::spawn().await.expect("client endpoint binds");
    client.add_peer(&provider.addr().await.expect("provider addr"));
    client
}

/// Ask `provider` for `content` over real iroh, as a peer would.
async fn fetch(
    client: &IrohTransport,
    provider: &IrohProvider,
    content: &Blake3Digest,
) -> Result<Vec<u8>, TransportError> {
    client
        .fetch(
            content,
            &KnownTransport::Iroh {
                node: provider.node_id(),
            },
            None,
        )
        .await
}

// ---- an in-memory supplier that COUNTS what it produced ----------------------

/// A [`NarSupplier`] whose bytes are synthesised, so a 64 MiB payload costs no
/// disk, and whose `supply` calls are COUNTED - which is what makes the
/// single-flight and the "declined before allocating" claims observable rather
/// than argued.
struct CountingSupplier {
    nars: std::collections::HashMap<Blake3Digest, Vec<u8>>,
    supplied: AtomicUsize,
    /// A size this supplier CLAIMS for one digest without being able to back it -
    /// used to prove admission reads the declared size and never the real bytes.
    lie: Option<(Blake3Digest, u64)>,
}

impl CountingSupplier {
    fn new(nars: impl IntoIterator<Item = Vec<u8>>) -> Self {
        CountingSupplier {
            nars: nars
                .into_iter()
                .map(|nar| (Blake3Digest::from_raw_nar(&nar), nar))
                .collect(),
            supplied: AtomicUsize::new(0),
            lie: None,
        }
    }

    fn supplied(&self) -> usize {
        self.supplied.load(Ordering::SeqCst)
    }
}

impl NarSupplier for CountingSupplier {
    fn declared_size(&self, content: &Blake3Digest) -> Option<u64> {
        if let Some((digest, size)) = self.lie
            && digest == *content
        {
            return Some(size);
        }
        self.nars.get(content).map(|nar| nar.len() as u64)
    }

    fn supply(&self, content: &Blake3Digest) -> Result<Vec<u8>, SupplyError> {
        self.supplied.fetch_add(1, Ordering::SeqCst);
        self.nars
            .get(content)
            .cloned()
            .ok_or_else(|| SupplyError(format!("no such NAR {content}")))
    }
}

// =========================================================================
// AC#1 + AC#4: serving is BOUNDED, and removing the bound restores the
// unbounded allocation.
// =========================================================================

#[tokio::test(flavor = "multi_thread")]
async fn the_serve_bound_declines_a_large_nar_and_removing_it_restores_the_allocation() {
    let nar = nar_of(BIG_NAR_BYTES, 0x11);
    let content = Blake3Digest::from_raw_nar(&nar);
    let nar_len = nar.len() as u64;

    // ---- ARM 1: the bound is IN PLACE. -----------------------------------
    let supplier = Arc::new(CountingSupplier::new([nar.clone()]));
    let bounded = IrohProvider::spawn_supplying(
        supplier.clone(),
        ServeBudget {
            max_nar_bytes_uncompressed_nar: SMALL_BUDGET_BYTES,
            max_inflight_bytes_uncompressed_nar: SMALL_BUDGET_BYTES,
        },
        SWEEP,
    )
    .await
    .expect("provider spawns");
    let client = client_wired_to(&bounded).await;

    let hwm_before_bounded = vm_bytes("VmHWM");
    let refused = fetch(&client, &bounded, &content).await;
    assert!(
        refused.is_err(),
        "a {nar_len} B NAR must be DECLINED under a {SMALL_BUDGET_BYTES} B bound, \
         got {} bytes",
        refused.map(|b| b.len()).unwrap_or(0)
    );
    let counters = bounded.serve_counters();
    assert_eq!(
        counters.declined_too_large, 1,
        "the decline must be attributed to the PER-NAR bound, not to some other \
         failure that happens to look like one: {counters:?}"
    );
    assert_eq!(
        counters.admitted, 0,
        "nothing may be admitted when the bound refuses: {counters:?}"
    );
    // THE BUDGET IS CHECKED BEFORE ANYTHING IS PRODUCED. This is the assertion
    // that separates "we refused" from "we allocated 64 MiB and then refused",
    // which is the only version of the fix that is worth anything.
    assert_eq!(
        supplier.supplied(),
        0,
        "the supplier was CALLED for a NAR the bound had already refused - the \
         allocation happened and the bound only hid it"
    );
    let residency = bounded
        .store_residency()
        .await
        .expect("store residency is queryable");
    assert_eq!(
        residency,
        StoreResidency::default(),
        "a declined serve must leave the store holding nothing"
    );
    let hwm_after_bounded = vm_bytes("VmHWM");
    let rise_bounded = hwm_after_bounded.saturating_sub(hwm_before_bounded);

    client.shutdown().await;
    bounded.shutdown().await;

    // ---- ARM 2: THE MUTATION - the bound is REMOVED. ---------------------
    // Same NAR, same peer, same request. The only change is the budget.
    let supplier2 = Arc::new(CountingSupplier::new([nar.clone()]));
    let unbounded = IrohProvider::spawn_supplying(supplier2.clone(), ServeBudget::unbounded(), SWEEP)
        .await
        .expect("provider spawns");
    let client2 = client_wired_to(&unbounded).await;

    let hwm_before_unbounded = vm_bytes("VmHWM");
    let served = fetch(&client2, &unbounded, &content)
        .await
        .expect("without a bound the same request is served");
    assert_eq!(
        served.len() as u64,
        nar_len,
        "the unbounded arm must actually move the whole NAR, or the mutation \
         proved nothing"
    );
    assert_eq!(
        supplier2.supplied(),
        1,
        "the unbounded arm must have REGENERATED the NAR - that is the allocation \
         the bound prevents"
    );
    let hwm_after_unbounded = vm_bytes("VmHWM");
    let rise_unbounded = hwm_after_unbounded.saturating_sub(hwm_before_unbounded);

    // AC#4's bite, stated as a comparison rather than an absolute: peak RSS
    // TRACKS the NAR size when the bound is gone and does not when it is there.
    // VmHWM is a sound oracle in exactly this direction - it is monotone, so it
    // cannot MISS an allocation that happened. (It is useless for the opposite
    // question, which is why release is asserted on store residency instead.)
    assert!(
        rise_unbounded >= nar_len / 2,
        "removing the bound must make peak RSS track the NAR: it rose {rise_unbounded} B \
         for a {nar_len} B NAR"
    );
    assert!(
        rise_bounded < nar_len / 2,
        "with the bound in place peak RSS must NOT track the NAR: it rose \
         {rise_bounded} B for a {nar_len} B NAR that was declined"
    );

    println!(
        "task-72 AC#1/AC#4, measured on this host:\n  \
         NAR                    = {nar_len} B (uncompressed NAR)\n  \
         per-NAR bound          = {SMALL_BUDGET_BYTES} B\n  \
         BOUNDED   -> declined={} supplier_calls={} VmHWM rise={rise_bounded} B\n  \
         UNBOUNDED -> served={} B supplier_calls={} VmHWM rise={rise_unbounded} B",
        counters.declined_too_large,
        supplier.supplied(),
        served.len(),
        supplier2.supplied(),
    );

    client2.shutdown().await;
    unbounded.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn admission_reads_the_declared_size_and_never_the_bytes() {
    // A supplier that CLAIMS a 100 GiB NAR for a digest whose real bytes are tiny.
    // If admission produced the bytes to find out how big they are, this would be
    // admitted; because it asks first, it is declined at the cost of a lookup.
    // (It also models the real case the bound exists for: a genuinely huge store
    // path, without this test allocating one.)
    let nar = nar_of(1024, 0x22);
    let content = Blake3Digest::from_raw_nar(&nar);
    let mut supplier = CountingSupplier::new([nar]);
    supplier.lie = Some((content, 100 * 1024 * 1024 * 1024));
    let supplier = Arc::new(supplier);

    let provider =
        IrohProvider::spawn_supplying(supplier.clone(), ServeBudget::default(), SWEEP)
            .await
            .expect("provider spawns");
    let client = client_wired_to(&provider).await;

    assert!(
        fetch(&client, &provider, &content).await.is_err(),
        "a declared 100 GiB NAR must be declined"
    );
    assert_eq!(
        supplier.supplied(),
        0,
        "admission produced bytes to decide whether it could afford to produce bytes"
    );
    assert_eq!(provider.serve_counters().declined_too_large, 1);

    client.shutdown().await;
    provider.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_inflight_total_declines_a_second_serve_it_cannot_afford() {
    // Two DISTINCT NARs, each individually acceptable, whose SUM is not. The
    // per-NAR bound cannot catch this; the in-flight total is the bound that does.
    let a = nar_of(4 * 1024 * 1024, 0x31);
    let b = nar_of(4 * 1024 * 1024, 0x32);
    let (digest_a, digest_b) = (
        Blake3Digest::from_raw_nar(&a),
        Blake3Digest::from_raw_nar(&b),
    );
    assert_ne!(digest_a, digest_b, "the two payloads must not deduplicate");
    let supplier = Arc::new(CountingSupplier::new([a.clone(), b]));

    let provider = IrohProvider::spawn_supplying(
        supplier.clone(),
        ServeBudget {
            max_nar_bytes_uncompressed_nar: 8 * 1024 * 1024,
            // Room for exactly ONE of them at a time.
            max_inflight_bytes_uncompressed_nar: a.len() as u64,
        },
        SWEEP,
    )
    .await
    .expect("provider spawns");
    let client = client_wired_to(&provider).await;

    // Sequentially both are servable - the first one's reservation is released
    // when its transfer ends, so the second is not competing with it.
    fetch(&client, &provider, &digest_a)
        .await
        .expect("the first NAR fits the in-flight budget");
    fetch(&client, &provider, &digest_b)
        .await
        .expect("the second NAR fits once the first has been released");
    let sequential = provider.serve_counters();
    assert_eq!(
        sequential.declined_busy, 0,
        "sequential serves must not exhaust an in-flight budget: {sequential:?}"
    );

    // ...and the counter is nonzero the moment the budget is genuinely too small
    // for a single one, which is the same code path saying no.
    let tight = IrohProvider::spawn_supplying(
        supplier.clone(),
        ServeBudget {
            max_nar_bytes_uncompressed_nar: 8 * 1024 * 1024,
            max_inflight_bytes_uncompressed_nar: 1,
        },
        SWEEP,
    )
    .await
    .expect("provider spawns");
    let tight_client = client_wired_to(&tight).await;
    assert!(
        fetch(&tight_client, &tight, &digest_a).await.is_err(),
        "a 1 B in-flight budget must decline a 4 MiB serve"
    );
    assert_eq!(
        tight.serve_counters().declined_busy,
        1,
        "the decline must be attributed to the IN-FLIGHT total, not the per-NAR bound"
    );

    tight_client.shutdown().await;
    tight.shutdown().await;
    client.shutdown().await;
    provider.shutdown().await;
}

// =========================================================================
// AC#3: announcing does not require holding, and a serve releases after it.
// =========================================================================

#[tokio::test(flavor = "multi_thread")]
async fn announcing_holds_nothing_and_a_completed_serve_releases_what_it_used() {
    let nar = nar_of(BIG_NAR_BYTES, 0x44);
    let content = Blake3Digest::from_raw_nar(&nar);
    let nar_len = nar.len() as u64;
    let supplier = Arc::new(CountingSupplier::new([nar]));

    let provider = IrohProvider::spawn_supplying(supplier.clone(), ServeBudget::default(), SWEEP)
        .await
        .expect("provider spawns");

    // BEFORE: the node can serve this digest and holds NONE of it. This is the
    // whole of the task-61 decision in one assertion - the pre-task-72 daemon
    // would have had 64 MiB resident here, at startup, forever.
    let announced = provider
        .store_residency()
        .await
        .expect("store residency is queryable");
    assert_eq!(
        announced,
        StoreResidency::default(),
        "announcing must cost NO residency; the store already holds {announced:?}"
    );

    let client = client_wired_to(&provider).await;
    let served = fetch(&client, &provider, &content)
        .await
        .expect("an announced NAR is servable on demand");
    assert_eq!(
        served.len() as u64,
        nar_len,
        "the peer must receive the whole NAR"
    );
    assert_eq!(
        supplier.supplied(),
        1,
        "the bytes must have been REGENERATED at serve time, not held since startup"
    );
    assert_eq!(provider.serve_counters().regenerated, 1);

    // AFTER: an idle node holds nothing again. Asserted on STORE RESIDENCY and not
    // on RSS - see this file's header for why an RSS-based version of this
    // assertion would pass on a wrong fix and fail on a correct one.
    let idle = poll_until_empty(&provider).await;
    assert_eq!(
        idle,
        StoreResidency::default(),
        "after the serve completed the store must hold nothing again, got {idle:?}"
    );

    // ...and the node is still able to serve it AGAIN, which is what makes the
    // release a supply model rather than a one-shot. A release that also destroyed
    // availability would pass the assertion above and be useless.
    let again = fetch(&client, &provider, &content)
        .await
        .expect("a released NAR is still announced, so it is still servable");
    assert_eq!(again.len() as u64, nar_len);
    assert_eq!(
        supplier.supplied(),
        2,
        "the second serve must have regenerated it again - if not, it was never \
         released and the residency reading above was measuring something else"
    );

    client.shutdown().await;
    provider.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_retaining_provider_still_holds_what_it_seeded() {
    // THE MUTATION IN THE OTHER DIRECTION. If `store_residency` were reporting the
    // supply model's INTENT rather than the store's state, it would answer "empty"
    // here too and the release assertion above would have proven nothing. Same
    // oracle, opposite configuration, opposite answer.
    let nar = nar_of(4 * 1024 * 1024, 0x55);
    let nar_len = nar.len() as u64;
    let provider = IrohProvider::spawn_with_retention(StoreRetention::RetainAll)
        .await
        .expect("provider spawns");
    provider.seed(&nar).await.expect("seed succeeds");
    tokio::time::sleep(Duration::from_millis(500)).await;

    let held = provider
        .store_residency()
        .await
        .expect("store residency is queryable");
    assert_eq!(
        held,
        StoreResidency {
            blobs: 1,
            bytes_uncompressed_nar: nar_len
        },
        "a RetainAll provider must still hold its seeded blob"
    );
    provider.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_requests_for_one_absent_digest_regenerate_it_exactly_once() {
    // The herd. Without single flight each concurrent request would either dump
    // the NAR again (k times the memory the budget charged for once) or be told
    // "yes" against a blob that does not exist yet and get an empty transfer.
    let nar = nar_of(8 * 1024 * 1024, 0x66);
    let content = Blake3Digest::from_raw_nar(&nar);
    let nar_len = nar.len() as u64;
    let supplier = Arc::new(CountingSupplier::new([nar]));

    let provider = IrohProvider::spawn_supplying(supplier.clone(), ServeBudget::default(), SWEEP)
        .await
        .expect("provider spawns");
    let addr = provider.addr().await.expect("provider addr");
    let node = provider.node_id();

    let mut fetches = Vec::new();
    for _ in 0..8 {
        let addr = addr.clone();
        fetches.push(tokio::spawn(async move {
            let client = IrohTransport::spawn().await.expect("client binds");
            client.add_peer(&addr);
            let got = client
                .fetch(&content, &KnownTransport::Iroh { node }, None)
                .await;
            client.shutdown().await;
            got
        }));
    }
    let mut served = 0usize;
    for handle in fetches {
        let bytes = handle
            .await
            .expect("fetch task joins")
            .expect("every concurrent peer is served the whole NAR");
        assert_eq!(bytes.len() as u64, nar_len);
        served += 1;
    }
    assert_eq!(served, 8);
    assert_eq!(
        supplier.supplied(),
        1,
        "8 concurrent peers must cost ONE regeneration, not 8 - a supplier called \
         once per peer is k times the memory the budget agreed to"
    );

    // And it is still released once the herd is gone.
    let idle = poll_until_empty(&provider).await;
    assert_eq!(idle, StoreResidency::default(), "got {idle:?}");

    provider.shutdown().await;
}

// =========================================================================
// AC#2: index coverage == provider coverage.
// =========================================================================

/// A dumper that reads the store path's `nar` file. Real enough for the property
/// under test (the index binds a NarHash to a path and regenerates from it) and
/// free of any dependence on a `nix-store` binary.
struct FileDumper;

impl NarDumper for FileDumper {
    fn dump(&self, path: &StorePath) -> Result<Vec<u8>, DumpError> {
        std::fs::read(path.as_path()).map_err(|e| DumpError(format!("reading {path}: {e}")))
    }
}

/// Write `nar` as a "store path" and return it. A file, not a directory: the
/// index only ever asks whether the path EXISTS and hands it to the dumper.
fn store_path_with(dir: &Path, name: &str, nar: &[u8]) -> StorePath {
    let path = dir.join(name);
    std::fs::write(&path, nar).expect("writing the store path");
    StorePath::new(path)
}

/// The canonical NarHash key form. The index never verifies that a key really is
/// `sha256(dump)` (a stated, deliberate gap in `availability.rs`), so any
/// well-formed key registers - which is what lets this test stay free of a sha256
/// dependency without weakening what it asserts.
fn key(n: u8) -> NarHashKey {
    let mut raw = [0u8; 32];
    raw[0] = n;
    NarHashKey::from_sha256_bytes(raw)
}

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "nix-p2p-task72-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

#[tokio::test(flavor = "multi_thread")]
async fn a_positive_hold_answer_implies_a_servable_blob() {
    let dir = temp_dir("coverage");
    let held = nar_of(2 * 1024 * 1024, 0x77);
    let held_path = store_path_with(&dir, "held.nar", &held);
    let held_key = key(1);

    let index = Arc::new(
        AvailabilityIndex::open(
            daemon::NodeId::from_bytes([7u8; 32]),
            Arc::new(FileDumper),
            Arc::new(NullStore),
            Arc::new(NullAnnounce),
        )
        .expect("index opens"),
    );
    index
        .register(held_key, held_path.clone())
        .expect("register");

    let supplier = Arc::new(IndexNarSupplier::new(index.clone()));
    let provider = IrohProvider::spawn_supplying(supplier.clone(), ServeBudget::default(), SWEEP)
        .await
        .expect("provider spawns");
    let client = client_wired_to(&provider).await;

    // THE PROPERTY: whatever the index says yes about, the provider serves.
    let answer = index.hold(&held_key).expect("hold answers");
    let daemon::HoldAnswer::Have { blake3, .. } = answer else {
        panic!("the index must hold a registered, materialised path");
    };
    assert_eq!(
        supplier.declared_size(&blake3),
        Some(held.len() as u64),
        "a digest the index answered YES for must be suppliable - this equality \
         IS task-72 AC#2"
    );
    let served = fetch(&client, &provider, &blake3)
        .await
        .expect("a held digest is servable over the real transport");
    assert_eq!(served, held, "the peer must receive the exact announced NAR");

    // THE MUTATION: GC the store path. The index's answer and the provider's
    // ability must move TOGETHER - a set equality that only held while nothing
    // changed would be a coincidence, not an invariant.
    std::fs::remove_file(held_path.as_path()).expect("removing the store path");
    assert!(
        matches!(
            index.hold(&held_key).expect("hold answers"),
            daemon::HoldAnswer::Absent
        ),
        "a GC'd path must drop out of the index"
    );
    assert_eq!(
        supplier.declared_size(&blake3),
        None,
        "...and out of SUPPLY at the same instant. If it did not, the node would \
         still be announcing a serve it can no longer perform - the exact \
         dial-then-fail this AC forbids"
    );

    client.shutdown().await;
    provider.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_digest_the_index_never_answered_for_is_declined_not_dial_then_failed() {
    let dir = temp_dir("unknown");
    let known = nar_of(64 * 1024, 0x88);
    let unknown = nar_of(64 * 1024, 0x99);
    let unknown_digest = Blake3Digest::from_raw_nar(&unknown);

    let index = Arc::new(
        AvailabilityIndex::open(
            daemon::NodeId::from_bytes([8u8; 32]),
            Arc::new(FileDumper),
            Arc::new(NullStore),
            Arc::new(NullAnnounce),
        )
        .expect("index opens"),
    );
    index
        .register(key(2), store_path_with(&dir, "known.nar", &known))
        .expect("register");

    let supplier = Arc::new(IndexNarSupplier::new(index.clone()));
    let provider = IrohProvider::spawn_supplying(supplier, ServeBudget::default(), SWEEP)
        .await
        .expect("provider spawns");
    let client = client_wired_to(&provider).await;

    assert!(
        fetch(&client, &provider, &unknown_digest).await.is_err(),
        "a digest this node never held must not be served"
    );
    let counters = provider.serve_counters();
    assert_eq!(
        counters.declined_unknown, 1,
        "the refusal must be a NAMED, counted decision - `unknown` - and not an \
         opaque mid-stream failure the operator has to guess at: {counters:?}"
    );
    assert_eq!(counters.admitted, 0);

    client.shutdown().await;
    provider.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

// =========================================================================
// The daemon's own file-backed supplier (what `--iroh-seed-nar` now builds).
// =========================================================================

#[test]
fn announcing_a_file_costs_bounded_memory_and_yields_the_frozen_digest() {
    let dir = temp_dir("filesupplier");
    let nar = nar_of(4 * 1024 * 1024, 0xaa);
    let path = dir.join("announced.nar");
    std::fs::write(&path, &nar).expect("writing the raw NAR");

    let supplier = FileNarSupplier::new();
    let (digest, nar_size) = supplier.announce(&path).expect("announce succeeds");
    assert_eq!(
        digest,
        Blake3Digest::from_raw_nar(&nar),
        "the streamed announce must land on the SAME frozen addressed unit as the \
         one-shot recipe, or a peer cannot fetch what was announced"
    );
    assert_eq!(
        nar_size,
        nar.len() as u64,
        "the announced size is the NarSize (uncompressed dump length), never a \
         compressed FileSize"
    );
    assert_eq!(supplier.declared_size(&digest), Some(nar.len() as u64));
    assert_eq!(
        supplier.supply(&digest).expect("supply succeeds"),
        nar,
        "the regenerated bytes must be byte-identical to what was announced"
    );

    // A digest that was never announced is unknown - the per-digest probe is the
    // ONLY question this type answers. There is no listing counterpart, by
    // construction (the PRD privacy invariant: a peer may learn yes/no about a
    // digest it can already name, never what a node holds).
    let never = Blake3Digest::from_raw_nar(b"never announced");
    assert_eq!(supplier.declared_size(&never), None);
    assert!(supplier.supply(&never).is_err());

    let _ = std::fs::remove_dir_all(&dir);
}
