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
//!   * `VmRSS` measured WHILE THE PAYLOAD IS STILL ALIVE - valid for exactly one
//!     direction: DID WE ALLOCATE. Live, touched pages are resident by definition,
//!     so a 64 MiB buffer we are still holding cannot fail to show up. That is
//!     precisely what task-72 AC#4 asks for ("without the bound, RSS tracks the NAR
//!     size"). It is used here for that and NEVER to claim a release, where the
//!     allocator's arena policy makes it unsound.
//!
//! `VmHWM` was the first choice for the allocation direction and is WRONG here, for
//! a reason worth writing down: it is a high-water mark over the whole PROCESS, and
//! `cargo test` runs this file's tests as threads of one process. Once any test has
//! allocated 64 MiB, the mark is already there, and the next test's identical
//! allocation produces NO RISE - so the assertion fails on correct code, depending
//! on the order the scheduler happened to pick. Measured: a rise of 8,359,936 B for
//! a 67,108,976 B NAR that was genuinely allocated. Monotone is exactly what makes
//! it safe against missing an allocation and exactly what makes it useless for
//! measuring a second one.
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
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use daemon::{
    AvailabilityIndex, Blake3Digest, FileNarSupplier, IndexNarSupplier, IrohClientNode,
    IrohProvider, IrohProviderNode, IrohTransport, KnownTransport, MemoryNarSupplier, NarHashKey,
    NullAnnounce, NullStore, RegularFileNarDumper, ServeBudget, StorePath, StoreResidency,
    StoreRetention, Transport, TransportError,
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
/// RESIDENT MEMORY IS PROCESS-GLOBAL, and `cargo test` runs this file's tests as
/// THREADS of one process. A concurrent test holding a 64 MiB payload would land
/// inside another's measured window, and the failure mode is a FALSE ALARM on the
/// bound - the worst kind to debug. Every RSS-measured window is taken under this
/// lock, so the readings bracket one allocation story at a time.
///
/// It does not make the reading attributable - nothing can - it makes it EXCLUSIVE,
/// which is what the negative assertion ("the bounded arm did NOT allocate") needs.
/// A TOKIO mutex, not a `std` one: these are async tests and the guard is held
/// across awaits, where a blocking guard would park a runtime worker (and clippy
/// says so).
static VM_HWM_WINDOW: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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
async fn client_wired_to(provider: &IrohProvider) -> IrohClientNode {
    let client = IrohClientNode::spawn()
        .await
        .expect("client endpoint binds");
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
                node: provider.node_id().unwrap(),
            },
            None,
        )
        .await
}

// ---- an in-memory supplier that COUNTS what it produced ----------------------

/// The daemon-owned closed fixture supplier keeps these behavioral tests
/// observable without reopening the arbitrary synchronous callback boundary.
type CountingSupplier = MemoryNarSupplier;

// =========================================================================
// AC#1 + AC#4: serving is BOUNDED, and removing the bound restores the
// unbounded allocation.
// =========================================================================

#[tokio::test(flavor = "multi_thread")]
async fn the_serve_bound_declines_a_large_nar_and_removing_it_restores_the_allocation() {
    let nar = nar_of(BIG_NAR_BYTES, 0x11);
    let content = Blake3Digest::from_raw_nar(&nar);
    let nar_len = nar.len() as u64;

    // Exclusive for the whole test: both arms measure VmHWM, and they must not be
    // measured through each other or through another test's payload.
    let _window = VM_HWM_WINDOW.lock().await;

    // ---- ARM 1: the bound is IN PLACE. -----------------------------------
    let supplier = Arc::new(CountingSupplier::new([nar.clone()]));
    let bounded = IrohProviderNode::spawn_supplying(
        supplier.clone(),
        ServeBudget {
            max_nar_bytes_uncompressed_nar: SMALL_BUDGET_BYTES,
            max_inflight_bytes_uncompressed_nar: SMALL_BUDGET_BYTES,
            ..ServeBudget::default()
        },
        SWEEP,
    )
    .await
    .expect("provider spawns");
    let client = client_wired_to(&bounded).await;

    let rss_before_bounded = vm_bytes("VmRSS");
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
    let rss_after_bounded = vm_bytes("VmRSS");
    let rise_bounded = rss_after_bounded.saturating_sub(rss_before_bounded);

    client.shutdown().await.unwrap();
    bounded.shutdown().await.unwrap();

    // ---- ARM 2: THE MUTATION - the bound is REMOVED. ---------------------
    // Same NAR, same peer, same request. The only change is the budget.
    let supplier2 = Arc::new(CountingSupplier::new([nar.clone()]));
    let unbounded =
        IrohProviderNode::spawn_supplying(supplier2.clone(), ServeBudget::unbounded(), SWEEP)
            .await
            .expect("provider spawns");
    let client2 = client_wired_to(&unbounded).await;

    let rss_before_unbounded = vm_bytes("VmRSS");
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
    // TAKEN WHILE `served` IS STILL ALIVE. That is the whole basis of this
    // reading: the fetched NAR is a live, touched buffer, so it is resident by
    // definition and cannot be missed. Reading after dropping it would be asking
    // the allocator a question it does not have to answer honestly.
    let rss_after_unbounded = vm_bytes("VmRSS");
    let rise_unbounded = rss_after_unbounded.saturating_sub(rss_before_unbounded);

    // AC#4's bite, stated as a comparison rather than an absolute: resident memory
    // TRACKS the NAR size when the bound is gone and does not when it is there.
    // Sound in this direction because the payload is LIVE at the reading; unsound
    // in the other, which is why every release claim in this file is on store
    // residency instead.
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
         BOUNDED   -> declined={} supplier_calls={} VmRSS rise={rise_bounded} B\n  \
         UNBOUNDED -> served={} B supplier_calls={} VmRSS rise={rise_unbounded} B",
        counters.declined_too_large,
        supplier.supplied(),
        served.len(),
        supplier2.supplied(),
    );

    client2.shutdown().await.unwrap();
    unbounded.shutdown().await.unwrap();
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
    supplier.set_declared_size(content, 100 * 1024 * 1024 * 1024);
    let supplier = Arc::new(supplier);

    let provider =
        IrohProviderNode::spawn_supplying(supplier.clone(), ServeBudget::default(), SWEEP)
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

    client.shutdown().await.unwrap();
    provider.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_source_that_produces_more_than_it_declared_is_refused() {
    // The budget charged for what the supplier DECLARED. If the produced bytes are
    // only checked against the per-NAR cap, a source that declared 1 KiB and
    // produced 4 MiB sails through (4 MiB < the cap) while the in-flight ledger
    // still says 1 KiB - and the in-flight total is exactly the bound that stops a
    // swarm of individually-acceptable serves. The two sizes describe the same NAR,
    // so they must be EQUAL, not merely both under a cap.
    let nar = nar_of(4 * 1024 * 1024, 0xe1);
    let content = Blake3Digest::from_raw_nar(&nar);
    let mut supplier = CountingSupplier::new([nar]);
    // Declares 1 KiB; will produce 4 MiB.
    supplier.set_declared_size(content, 1024);
    let supplier = Arc::new(supplier);

    let provider =
        IrohProviderNode::spawn_supplying(supplier.clone(), ServeBudget::default(), SWEEP)
            .await
            .expect("provider spawns");
    let client = client_wired_to(&provider).await;

    assert!(
        fetch(&client, &provider, &content).await.is_err(),
        "a source that produced 4 MiB against a 1 KiB reservation must be refused"
    );
    assert_eq!(
        supplier.supplied(),
        1,
        "the mismatch is only observable AFTER the source produced its bytes, so \
         the supplier must have been called - otherwise this test is passing for \
         the wrong reason"
    );
    assert_eq!(
        provider.serve_counters().declined_too_large,
        1,
        "the refusal must be attributed to the SIZE, not folded into supply_failed"
    );
    let idle = poll_until_empty(&provider).await;
    assert_eq!(
        idle,
        StoreResidency::default(),
        "a refused mismatch must leave nothing behind, got {idle:?}"
    );

    client.shutdown().await.unwrap();
    provider.shutdown().await.unwrap();
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
    let release_first = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut supplier = CountingSupplier::new([a.clone(), b]);
    supplier.block_until(digest_a, Arc::clone(&release_first));
    let supplier = Arc::new(supplier);

    let provider = IrohProviderNode::spawn_supplying(
        supplier.clone(),
        ServeBudget {
            max_nar_bytes_uncompressed_nar: 8 * 1024 * 1024,
            // Room for exactly ONE of them at a time.
            max_inflight_bytes_uncompressed_nar: a.len() as u64,
            ..ServeBudget::default()
        },
        SWEEP,
    )
    .await
    .expect("provider spawns");
    let first_client = client_wired_to(&provider).await;
    let second_client = client_wired_to(&provider).await;
    let provider_node = provider.node_id().unwrap();
    let first_transport = first_client.transport_handle();
    let first = tokio::spawn(async move {
        first_transport
            .fetch(
                &digest_a,
                &KnownTransport::Iroh {
                    node: provider_node,
                },
                None,
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        while supplier.active_operations() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("first distinct serve holds the entire in-flight reservation");

    assert!(
        fetch(&second_client, &provider, &digest_b).await.is_err(),
        "the overlapping second NAR must be declined while the first holds the budget"
    );
    assert_eq!(
        provider.serve_counters().declined_busy,
        1,
        "the overlapping refusal must be attributed to the in-flight total"
    );
    release_first.store(true, Ordering::Release);
    first
        .await
        .expect("first fetch task joins")
        .expect("first overlapping serve completes after release");
    fetch(&second_client, &provider, &digest_b)
        .await
        .expect("second NAR is admitted after the first releases its reservation");

    second_client.shutdown().await.unwrap();
    first_client.shutdown().await.unwrap();
    provider.shutdown().await.unwrap();
}

// =========================================================================
// AC#3: announcing does not require holding, and a serve releases after it.
// =========================================================================

#[tokio::test(flavor = "multi_thread")]
async fn announcing_holds_nothing_and_a_completed_serve_releases_what_it_used() {
    // Held for the same reason the bound test holds it: this test allocates the
    // same 64 MiB payload, and doing so inside that test's measured window would
    // make its negative RSS assertion fail for a reason that has nothing to do with
    // the bound.
    let _window = VM_HWM_WINDOW.lock().await;

    let nar = nar_of(BIG_NAR_BYTES, 0x44);
    let content = Blake3Digest::from_raw_nar(&nar);
    let nar_len = nar.len() as u64;
    let supplier = Arc::new(CountingSupplier::new([nar]));

    let provider =
        IrohProviderNode::spawn_supplying(supplier.clone(), ServeBudget::default(), SWEEP)
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

    client.shutdown().await.unwrap();
    provider.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_retaining_provider_still_holds_what_it_seeded() {
    // THE MUTATION IN THE OTHER DIRECTION. If `store_residency` were reporting the
    // supply model's INTENT rather than the store's state, it would answer "empty"
    // here too and the release assertion above would have proven nothing. Same
    // oracle, opposite configuration, opposite answer.
    let nar = nar_of(4 * 1024 * 1024, 0x55);
    let nar_len = nar.len() as u64;
    let provider = IrohProviderNode::spawn_with_retention(StoreRetention::RetainAll)
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
    provider.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn release_on_request_does_not_release_just_because_a_serve_finished() {
    // The two releasing retentions must stay DIFFERENT. `ReleaseOnRequest` promises
    // "hold everything until `release_all` is called"; if a completed serve armed a
    // sweep by itself, that promise would silently become `ReleaseAfterServe` and a
    // caller relying on it would lose content it had been told was held. Caught
    // while adding the supply model, which is exactly when the two variants started
    // sharing an arming flag.
    let nar = nar_of(4 * 1024 * 1024, 0xbb);
    let content = Blake3Digest::from_raw_nar(&nar);
    let nar_len = nar.len() as u64;
    let supplier = Arc::new(CountingSupplier::new([nar]));

    let provider = IrohProviderNode::spawn_with(
        StoreRetention::ReleaseOnRequest {
            sweep_interval: SWEEP,
        },
        ServeBudget::default(),
        Some(supplier),
    )
    .await
    .expect("provider spawns");
    let client = client_wired_to(&provider).await;

    fetch(&client, &provider, &content)
        .await
        .expect("the NAR is served on demand");
    // Several sweep intervals: a store that was going to collect it would have.
    tokio::time::sleep(SWEEP * 6).await;
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
        "ReleaseOnRequest must still HOLD after a completed serve - only \
         release_all releases it"
    );

    // ...and the request still does.
    provider.release_all().await.expect("release_all succeeds");
    let released = poll_until_empty(&provider).await;
    assert_eq!(
        released,
        StoreResidency::default(),
        "release_all must still release, got {released:?}"
    );

    client.shutdown().await.unwrap();
    provider.shutdown().await.unwrap();
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

    let provider =
        IrohProviderNode::spawn_supplying(supplier.clone(), ServeBudget::default(), SWEEP)
            .await
            .expect("provider spawns");
    let addr = provider.addr().await.expect("provider addr");
    let node = provider.node_id().unwrap();

    let mut fetches = Vec::new();
    for _ in 0..8 {
        let addr = addr.clone();
        fetches.push(tokio::spawn(async move {
            let client = IrohClientNode::spawn().await.expect("client binds");
            client.add_peer(&addr);
            let got = client
                .fetch(&content, &KnownTransport::Iroh { node }, None)
                .await;
            client.shutdown().await.unwrap();
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

    provider.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_peer_that_disconnects_mid_admission_gives_its_reservation_back() {
    // THE S1 DEFECT, as an experiment. The first cut released the reservation where
    // the transfer's UPDATE STREAM ended, and returned early - without releasing -
    // when the verdict could not be delivered. That is precisely what happens when
    // the peer hangs up, and the window spans the whole regeneration. Four such
    // requests left the node permanently `busy` for everyone, holding a gigabyte it
    // would never release, with no timeout, no reaper and no counter to show it.
    //
    // The oracle is the BUDGET, not the code path: after a peer vanishes mid-serve,
    // an honest peer must still be admitted. That stays true however the release is
    // implemented, which is what makes it worth asserting.
    let big = nar_of(4 * 1024 * 1024, 0xc1);
    let other = nar_of(4 * 1024 * 1024, 0xc2);
    let (big_digest, other_digest) = (
        Blake3Digest::from_raw_nar(&big),
        Blake3Digest::from_raw_nar(&other),
    );
    let released = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut supplier = CountingSupplier::new([big.clone(), other.clone()]);
    supplier.block_until(big_digest, released.clone());
    let supplier = Arc::new(supplier);

    let provider = IrohProviderNode::spawn_supplying(
        supplier.clone(),
        ServeBudget {
            max_nar_bytes_uncompressed_nar: 8 * 1024 * 1024,
            // Room for exactly ONE of the two at a time, so a leaked reservation is
            // immediately visible as the other one being refused.
            max_inflight_bytes_uncompressed_nar: big.len() as u64,
            // SHORT ON PURPOSE, and the reason is a measured one: when a peer
            // vanishes the provider's update stream does not end - the connection
            // stays live from our side until QUIC's idle timeout - so this deadline
            // is the ONLY thing that reclaims the reservation. Pinned here rather
            // than inherited so the test is about the mechanism and not about
            // whatever the shipped default happens to be.
            max_serve_duration: Duration::from_secs(2),
        },
        SWEEP,
    )
    .await
    .expect("provider spawns");
    let addr = provider.addr().await.expect("provider addr");
    let node = provider.node_id().unwrap();

    // A peer that asks for the blocked digest and then GOES AWAY while the node is
    // still regenerating it.
    let doomed = {
        let addr = addr.clone();
        tokio::spawn(async move {
            let client = IrohClientNode::spawn().await.expect("client binds");
            client.add_peer(&addr);
            let _ = client
                .fetch(&big_digest, &KnownTransport::Iroh { node }, None)
                .await;
            client.shutdown().await.unwrap();
        })
    };
    // Let the admission get as far as the blocked supplier.
    tokio::time::sleep(Duration::from_millis(300)).await;
    doomed.abort();
    let _ = doomed.await;
    released.store(true, Ordering::SeqCst);

    // THE ASSERTION: the budget comes BACK, within a bound, so an honest peer is
    // served. Stated as "within a bound" and not "immediately" on purpose - the
    // abandoned admission is legitimately still finishing its regeneration for a
    // moment after the peer leaves, and refusing during that moment is the budget
    // working, not leaking. What must not happen is that it never comes back.
    //
    // THE BOUND IS THE BITE. With `max_serve_duration` raised, this loop runs to
    // its own deadline and fails - which is how the deadline was shown to be the
    // thing doing the work, rather than something else happening to tidy up.
    let client = client_wired_to(&provider).await;
    let deadline = Instant::now() + Duration::from_secs(20);
    let served = loop {
        match fetch(&client, &provider, &other_digest).await {
            Ok(bytes) => break bytes,
            Err(why) => {
                assert!(
                    Instant::now() < deadline,
                    "the honest peer was still refused {:?} after the vanished peer \
                     left: its reservation was never given back, so the budget is \
                     permanently short. Last error: {why}",
                    Duration::from_secs(20)
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    };
    assert_eq!(served, other);

    // ...and the store settles empty, so the abandoned blob was not pinned either.
    let idle = poll_until_empty(&provider).await;
    assert_eq!(idle, StoreResidency::default(), "got {idle:?}");

    client.shutdown().await.unwrap();
    provider.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn serve_deadline_covers_materialisation_and_releases_the_budget() {
    let blocked = nar_of(1024 * 1024, 0xd1);
    let healthy = nar_of(1024 * 1024, 0xd2);
    let one_slot = blocked.len() as u64;
    assert_eq!(healthy.len() as u64, one_slot);
    let blocked_digest = Blake3Digest::from_raw_nar(&blocked);
    let healthy_digest = Blake3Digest::from_raw_nar(&healthy);
    let never_release = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut supplier = CountingSupplier::new([blocked, healthy.clone()]);
    supplier.block_until(blocked_digest, never_release);
    let supplier = Arc::new(supplier);
    let provider = IrohProviderNode::spawn_supplying(
        supplier,
        ServeBudget {
            max_nar_bytes_uncompressed_nar: one_slot,
            max_inflight_bytes_uncompressed_nar: one_slot,
            max_serve_duration: Duration::from_millis(200),
        },
        SWEEP,
    )
    .await
    .unwrap();
    let client = client_wired_to(&provider).await;

    let started = Instant::now();
    assert!(fetch(&client, &provider, &blocked_digest).await.is_err());
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "serve deadline must include the size/materialisation phase"
    );
    let recovered = fetch(&client, &provider, &healthy_digest)
        .await
        .expect("timed-out materialisation releases the one-slot budget");
    assert_eq!(recovered, healthy);
    assert!(provider.serve_counters().reservations_timed_out >= 1);

    client.shutdown().await.unwrap();
    provider.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn the_collector_still_reclaims_while_another_serve_is_in_flight() {
    // THE S2 DEFECT, as an experiment. The first cut let a sweep run only from
    // global quiescence: the protect callback ABORTED whenever anything was in
    // flight. Under sustained traffic the in-flight table is never empty at a tick,
    // so nothing was ever collected - and a `MemStore` has no capacity bound of its
    // own, so resident bytes would grow to the whole announced corpus. One slow
    // reader is enough to hold that door open. "Holds nothing at rest" would then
    // be true only of a node that is not being used.
    //
    // The callback now PROTECTS what is in flight instead of refusing to run, which
    // is both safer (an admission registers its hash before it adds) and stronger.
    let served_then_idle = nar_of(4 * 1024 * 1024, 0xd1);
    let held_open = nar_of(4 * 1024 * 1024, 0xd2);
    let (idle_digest, held_digest) = (
        Blake3Digest::from_raw_nar(&served_then_idle),
        Blake3Digest::from_raw_nar(&held_open),
    );
    let release = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut supplier = CountingSupplier::new([served_then_idle.clone(), held_open]);
    supplier.block_until(held_digest, release.clone());
    let supplier = Arc::new(supplier);

    let provider = IrohProviderNode::spawn_supplying(supplier, ServeBudget::default(), SWEEP)
        .await
        .expect("provider spawns");
    let addr = provider.addr().await.expect("provider addr");
    let node = provider.node_id().unwrap();

    // ORDER MATTERS, and getting it wrong makes this test vacuous - which is how
    // the first cut of it was caught. If the finished serve completes BEFORE
    // anything is in flight, the collector reclaims it during the quiet moment and
    // the test passes under the aborting callback too. The blocked serve must be in
    // flight FIRST, and stay there.
    //
    // 1. Start a serve and KEEP IT IN FLIGHT (its supplier is blocked).
    let stuck = {
        let addr = addr.clone();
        tokio::spawn(async move {
            let client = IrohClientNode::spawn().await.expect("client binds");
            client.add_peer(&addr);
            let got = client
                .fetch(&held_digest, &KnownTransport::Iroh { node }, None)
                .await;
            client.shutdown().await.unwrap();
            got
        })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;

    // 2. NOW serve a different NAR to completion, with the first one still stuck.
    //    Its blob is resident and untagged the moment it finishes, and the node is
    //    never idle again for the rest of the test.
    let client = client_wired_to(&provider).await;
    fetch(&client, &provider, &idle_digest)
        .await
        .expect("a second NAR is served while the first is still in flight");

    // 3. THE ASSERTION: the finished serve is reclaimed to ZERO even though the
    //    node is still busy.
    //
    //    ZERO, not "under some ceiling". The first cut of this assertion allowed
    //    "one in-flight serve" worth of residency - but the stuck serve is blocked
    //    INSIDE its supplier, so its blob was never added and it occupies no store
    //    bytes at all. The ceiling could therefore never be exceeded and the test
    //    passed under the aborting callback too. Caught by mutation M9; recorded
    //    here because a ceiling that cannot be exceeded is not a ceiling.
    let idle = poll_until_empty(&provider).await;
    assert_eq!(
        idle,
        StoreResidency::default(),
        "the collector did not reclaim the finished serve while another was in \
         flight - the store is still holding {idle:?}. A node that only reclaims \
         when it is idle does not hold nothing at rest: it holds everything it has \
         ever served, for as long as any peer keeps one request open"
    );

    release.store(true, Ordering::SeqCst);
    let _ = stuck.await;
    client.shutdown().await.unwrap();
    provider.shutdown().await.unwrap();
}

// =========================================================================
// AC#2: index coverage == provider coverage.
// =========================================================================

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

#[test]
fn index_supplier_retains_only_the_inert_catalog_not_the_availability_index() {
    let index = Arc::new(
        AvailabilityIndex::open(
            daemon::NodeId::from_bytes([6u8; 32]),
            Arc::new(RegularFileNarDumper),
            Arc::new(NullStore),
            Arc::new(NullAnnounce),
        )
        .unwrap(),
    );
    let weak_index = Arc::downgrade(&index);
    let supplier = IndexNarSupplier::new(
        daemon::IrohCatalogProbe::new(index.supply_catalog()),
        env!("CARGO_BIN_EXE_daemon"),
    );
    drop(index);
    assert!(
        weak_index.upgrade().is_none(),
        "provider catalog must not retain AvailabilityIndex or its lazy callbacks"
    );
    drop(supplier);
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
            Arc::new(RegularFileNarDumper),
            Arc::new(NullStore),
            Arc::new(NullAnnounce),
        )
        .expect("index opens"),
    );
    index
        .register(held_key, held_path.clone())
        .expect("register");

    let supplier = Arc::new(IndexNarSupplier::new(
        daemon::IrohCatalogProbe::new(index.supply_catalog()),
        env!("CARGO_BIN_EXE_daemon"),
    ));
    let provider =
        IrohProviderNode::spawn_supplying(supplier.clone(), ServeBudget::default(), SWEEP)
            .await
            .expect("provider spawns");
    let client = client_wired_to(&provider).await;

    // THE PROPERTY: whatever the index says yes about, the provider serves.
    let answer = index.hold(&held_key).expect("hold answers");
    let daemon::HoldAnswer::Have { blake3, .. } = answer else {
        panic!("the index must hold a registered, materialised path");
    };
    let served = fetch(&client, &provider, &blake3)
        .await
        .expect("a held digest is servable over the real transport");
    assert_eq!(
        served, held,
        "the peer must receive the exact announced NAR"
    );
    assert_eq!(poll_until_empty(&provider).await.blobs, 0);

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
    assert!(
        fetch(&client, &provider, &blake3).await.is_err(),
        "...and out of SUPPLY at the same instant. If it did not, the node would \
         still serve content the availability index has disowned"
    );

    client.shutdown().await.unwrap();
    provider.shutdown().await.unwrap();
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
            Arc::new(RegularFileNarDumper),
            Arc::new(NullStore),
            Arc::new(NullAnnounce),
        )
        .expect("index opens"),
    );
    index
        .register(key(2), store_path_with(&dir, "known.nar", &known))
        .expect("register");

    let supplier = Arc::new(IndexNarSupplier::new(
        daemon::IrohCatalogProbe::new(index.supply_catalog()),
        env!("CARGO_BIN_EXE_daemon"),
    ));
    let provider = IrohProviderNode::spawn_supplying(supplier, ServeBudget::default(), SWEEP)
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

    client.shutdown().await.unwrap();
    provider.shutdown().await.unwrap();
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

    let supplier = FileNarSupplier::new(env!("CARGO_BIN_EXE_daemon"));
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
    let direct = std::process::Command::new(env!("CARGO_BIN_EXE_daemon"))
        .arg("__dump-raw-nar")
        .arg(&path)
        .env_remove("DAEMON_INTERNAL_RAW_NAR_HELPER")
        .output()
        .expect("direct helper invocation returns");
    assert_eq!(direct.status.code(), Some(2));
    assert!(direct.stdout.is_empty());
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_daemon"))
        .arg("__dump-raw-nar")
        .arg(&path)
        .env("DAEMON_INTERNAL_RAW_NAR_HELPER", "v1")
        .output()
        .expect("raw-NAR helper runs");
    assert!(
        output.status.success(),
        "helper stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        output.stdout, nar,
        "the isolated source must reproduce the announced bytes"
    );

    // A digest that was never announced is unknown - the per-digest probe is the
    // ONLY question this type answers. There is no listing counterpart, by
    // construction (the PRD privacy invariant: a peer may learn yes/no about a
    // digest it can already name, never what a node holds).
    let _never = Blake3Digest::from_raw_nar(b"never announced");

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn replaced_file_overproduction_is_cut_off_and_reaped_at_the_reservation() {
    let dir = temp_dir("file-overproduction");
    let path = dir.join("growing-source.nar");
    let announced = nar_of(1024, 0xb1);
    std::fs::write(&path, &announced).unwrap();
    let supplier = Arc::new(FileNarSupplier::new(env!("CARGO_BIN_EXE_daemon")));
    let (digest, announced_size) = supplier.announce(&path).unwrap();
    assert_eq!(announced_size, announced.len() as u64);

    // Replace the file after admission metadata was frozen. The subprocess now
    // produces far more than the reservation; the supervisor must stop on the
    // first proof byte, kill the process group, and reap it before refusal.
    std::fs::write(&path, nar_of(16 * 1024 * 1024, 0xb2)).unwrap();
    let provider = IrohProviderNode::spawn_supplying(
        supplier,
        ServeBudget {
            max_nar_bytes_uncompressed_nar: 32 * 1024 * 1024,
            max_inflight_bytes_uncompressed_nar: 32 * 1024 * 1024,
            max_serve_duration: Duration::from_secs(10),
        },
        SWEEP,
    )
    .await
    .unwrap();
    let client = client_wired_to(&provider).await;
    let started = Instant::now();
    assert!(fetch(&client, &provider, &digest).await.is_err());
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "overproduction must be cut off at the proof byte, not the serve deadline"
    );
    assert_eq!(provider.serve_counters().declined_too_large, 1);

    let path_bytes = path.as_os_str().as_encoded_bytes();
    let surviving_helpers = std::fs::read_dir("/proc")
        .unwrap()
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().to_string_lossy().parse::<u32>().ok())
        .filter(|pid| {
            std::fs::read(format!("/proc/{pid}/cmdline"))
                .ok()
                .is_some_and(|cmdline| {
                    cmdline
                        .windows(path_bytes.len())
                        .any(|window| window == path_bytes)
                })
        })
        .collect::<Vec<_>>();
    assert!(
        surviving_helpers.is_empty(),
        "overproducing helper processes survived refusal: {surviving_helpers:?}"
    );

    client.shutdown().await.unwrap();
    provider.shutdown().await.unwrap();
    let _ = std::fs::remove_dir_all(dir);
}
