//! TASK-229: the RESPONDER derivation-resource DoS defence, proven by MUTATION.
//!
//! TASK-104 bounded the fresh dumps ONE hold-query MESSAGE may trigger
//! (`MAX_BATCH_DERIVE_WORK`). That is not a DoS defence: it bounds a dump COUNT, not
//! BYTES hashed, and it is per-MESSAGE, so a hostile peer picks the message boundaries
//! (many small batches; single-key `hold`-query probes on the formerly-unlimited path).
//! This suite proves the two residuals are closed AND the single-key path and a Sybil
//! flood are bounded, each by a mutation that reddens the bite:
//!
//!   1. REFUSE-BEFORE-DUMP (R1): a cold probe whose NarSize exceeds the remaining byte
//!      budget is refused WITHOUT dumping (the dump counter stays 0). MUTATION: query
//!      the size AFTER the dump (or drop the byte check) -> the big dump happens ->
//!      `dumper.calls()` becomes 1.
//!   2. PER-PEER AGGREGATE ACROSS MESSAGES (R2): one peer spreading probes over MANY
//!      single-key messages is bounded in aggregate bytes; the probe past its cap is
//!      refused. MUTATION: make the ledger per-message (reset each call) -> every message
//!      admits -> all answer `Have`.
//!   3. SINGLE-KEY hold() UNDER THE BOUND: a single-key `hold`-query FLOOD is bounded
//!      (here by the per-peer dump COUNT). MUTATION: route `answer_for_peer` through the
//!      unlimited local `hold()` -> the flood answers `Have` past the cap.
//!   4. GLOBAL CEILING (Sybil floor): many DISTINCT peers hit the global aggregate
//!      ceiling and are refused past it. MUTATION: remove the global check -> the
//!      many-peer flood all answers `Have`.
//!   5. REPORTED HONESTLY: the operator `--status` surface renders the global
//!      derive-budget as used/CAP integers (no float), read LIVE from the enforcing
//!      ledger. MUTATION: report a mirrored/zero figure -> the used value stops tracking
//!      the ledger.
//!
//! The dump COUNT (`MemoryNarDumper::calls`) is the direct observable for "was work
//! spent"; where multiple DISTINCT held keys are needed (each answerable `Have`) the
//! sealed dumper set forces a real-file dumper, so those bites observe the `Have`/`Absent`
//! frontier and the ledger's own `global_bytes_used` instead.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use daemon_core::{
    AvailabilityIndex, BatchHoldAnswer, BatchHoldQuery, DeriveBudget, HoldAnswer, HoldQuery,
    MemoryNarDumper, NarHashKey, NodeId, NullAnnounce, NullStatusFacts, NullStore, Observability,
    OperatorContract, PeerDeriveLedger, QUERY_SCHEMA_VERSION, RegularFileNarDumper, RuntimeMetrics,
    SharingProfile, StorePath,
};

// ------------------------------------------------------------------ helpers

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
            "nixp2p-derivebudget-{label}-{}-{n}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        TempDir { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// One `nix-archive-1` NAR token (u64-LE length, bytes, zero-pad to 8).
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

fn peer(tag: u8) -> NodeId {
    NodeId::from_bytes([tag; 32])
}

/// A budget with a generous 60 s window (no roll-over inside a test) and the given
/// per-peer/global ceilings.
fn budget(per_peer_bytes: u64, per_peer_dumps: u32, global_bytes: u64) -> DeriveBudget {
    DeriveBudget {
        max_bytes_per_peer_uncompressed_nar: per_peer_bytes,
        max_dumps_per_peer: per_peer_dumps,
        max_bytes_global_uncompressed_nar: global_bytes,
        // Generous global dump ceiling so these responder cases isolate the bound they exercise.
        max_dumps_global: u32::MAX,
        window: Duration::from_secs(60),
    }
}

/// A real-file dumper index. Each held key points at its OWN file whose bytes ARE the
/// raw NAR, so distinct keys are distinct, honestly-held content answerable `Have`
/// (the sealed dumper set means a test cannot inject its own multi-content dumper).
fn real_file_index() -> AvailabilityIndex {
    AvailabilityIndex::open(
        node(),
        Arc::new(RegularFileNarDumper),
        Arc::new(NullStore),
        Arc::new(NullAnnounce),
    )
    .expect("open index")
}

/// Write `content`'s raw NAR to a file, register it under its TRUE NarHash, and return
/// the key plus the exact NarSize (the file's byte length). All callers pass
/// equal-length `content`, so every returned NarSize is identical - clean budget
/// arithmetic.
fn hold_key(
    index: &AvailabilityIndex,
    dir: &TempDir,
    name: &str,
    content: &[u8],
) -> (NarHashKey, u64) {
    let nar = synth_raw_nar(content);
    let path = dir.path.join(name);
    std::fs::write(&path, &nar).expect("write nar file");
    let key = NarHashKey::from_raw_nar(&nar);
    index
        .register(key, StorePath::new(path))
        .expect("register held key");
    (key, nar.len() as u64)
}

fn single(
    index: &AvailabilityIndex,
    key: NarHashKey,
    asker: &NodeId,
    ledger: &PeerDeriveLedger,
) -> HoldAnswer {
    index
        .answer_for_peer(
            &HoldQuery {
                schema_version: QUERY_SCHEMA_VERSION,
                key,
            },
            asker,
            ledger,
        )
        .expect("answer_for_peer")
        .answer
}

// ============================================================ Bite 1: R1 refuse-before-dump

/// A cold probe whose NarSize EXCEEDS the remaining per-peer byte budget is REFUSED
/// with NO dump: the responder pays a stat, not a whole-NAR hash. Observed on the dump
/// counter (`MemoryNarDumper::calls`), which the R1 `NarDumper::nar_size` query does NOT
/// increment.
///
/// MUTATION (red-without): in `AvailabilityIndex::derive`, drop the `nar_size`-seeded
/// `ledger.try_admit` before the dump (or move it AFTER `self.dumper.dump`). The dump
/// then runs before the byte budget can refuse -> `dumper.calls() == 1`.
#[test]
fn refuses_an_oversize_cold_probe_before_dumping() {
    let big = vec![0xAB; 4096]; // one 4 KiB in-memory NAR
    let dumper = Arc::new(MemoryNarDumper::new(big.clone()));
    let index = AvailabilityIndex::open(
        node(),
        dumper.clone(),
        Arc::new(NullStore),
        Arc::new(NullAnnounce),
    )
    .expect("open index");

    let tmp = TempDir::new("r1");
    let store = tmp.path.join("held");
    std::fs::write(&store, b"stand-in; the index dumps via the MemoryNarDumper").unwrap();
    let key = NarHashKey::from_raw_nar(&big);
    index
        .register(key, StorePath::new(store))
        .expect("register");

    // Per-peer byte cap (100) far below the 4096-byte NarSize; global generous.
    let ledger = PeerDeriveLedger::new(budget(100, 1000, 10_000_000));
    let answer = single(&index, key, &peer(1), &ledger);

    assert!(
        matches!(answer, HoldAnswer::Absent),
        "an over-byte-budget cold probe must answer Absent (safe direction), got {answer:?}"
    );
    assert_eq!(
        dumper.calls(),
        0,
        "REFUSE-BEFORE-DUMP: the oversize probe must be refused WITHOUT dumping; \
         a non-zero count means the byte check ran too late (or not at all)"
    );
    // Nothing was hashed, so nothing was charged.
    assert_eq!(ledger.global_bytes_used(), 0);
}

// ============================================================ Bite 2: R2 per-peer aggregate across messages

/// ONE peer spreading single-key probes across MANY messages is bounded in AGGREGATE
/// bytes over the window, not per message. Only as many probes as the per-peer byte
/// budget affords are answered `Have`; the rest are refused `Absent`, and the ledger's
/// global usage reflects only the admitted work.
///
/// MUTATION (red-without): make the ledger per-MESSAGE (e.g. construct a fresh
/// `PeerDeriveLedger` inside `answer_for_peer`, or reset the peer window each call).
/// Every single-key message then gets a full budget -> every key answers `Have`.
#[test]
fn per_peer_budget_bounds_probes_spread_across_messages() {
    let index = real_file_index();
    let tmp = TempDir::new("r2");
    // Five DISTINCT held keys, each the SAME NarSize L (equal-length content).
    let mut keys = Vec::new();
    let mut nar_size = 0;
    for i in 0..5u8 {
        let (k, l) = hold_key(&index, &tmp, &format!("k{i}"), &[0x40 + i; 64]);
        nar_size = l;
        keys.push(k);
    }
    // Budget for EXACTLY TWO NARs per peer; dump-count generous so BYTES are the bound.
    let ledger = PeerDeriveLedger::new(budget(2 * nar_size, 1000, 100 * nar_size));
    let asker = peer(2);

    // Each key is its OWN single-key message from the SAME peer.
    let answers: Vec<HoldAnswer> = keys
        .iter()
        .map(|k| single(&index, *k, &asker, &ledger))
        .collect();
    let haves = answers
        .iter()
        .filter(|a| matches!(a, HoldAnswer::Have { .. }))
        .count();
    assert_eq!(
        haves,
        2,
        "the per-peer byte budget must bound the AGGREGATE across messages to 2 NARs, \
         got {haves} Have of {} messages: {answers:?}",
        keys.len()
    );
    assert_eq!(
        ledger.global_bytes_used(),
        2 * nar_size,
        "only the two admitted probes are charged; the refused three cost nothing"
    );
}

// ============================================================ Bite 3: single-key hold() under the bound

/// A single-key `hold`-query FLOOD from one peer is BOUNDED - here by the per-peer dump
/// COUNT, which bites even when each NAR is tiny (so a byte-only bound would miss it).
///
/// MUTATION (red-without): route `answer_for_peer` through the unlimited LOCAL
/// `self.hold(&query.key)` instead of the peer-gated `hold_budgeted`. The flood then
/// answers `Have` for every key past the cap (the exact formerly-unlimited path).
#[test]
fn single_key_hold_flood_is_bounded_not_unlimited() {
    let index = real_file_index();
    let tmp = TempDir::new("single");
    let keys: Vec<NarHashKey> = (0..6u8)
        .map(|i| hold_key(&index, &tmp, &format!("s{i}"), &[0x10 + i; 32]).0)
        .collect();
    // Per-peer DUMP-COUNT cap of 3; bytes/global generous so COUNT is the bound.
    let ledger = PeerDeriveLedger::new(budget(1 << 40, 3, 1 << 40));
    let asker = peer(3);

    let answers: Vec<HoldAnswer> = keys
        .iter()
        .map(|k| single(&index, *k, &asker, &ledger))
        .collect();
    let haves = answers
        .iter()
        .filter(|a| matches!(a, HoldAnswer::Have { .. }))
        .count();
    assert_eq!(
        haves,
        3,
        "a single-key hold flood must be bounded to the per-peer dump cap (3); \
         {haves} Have of {} means the single-key path is unbounded: {answers:?}",
        keys.len()
    );
}

// ============================================================ Bite 4: global ceiling (Sybil floor)

/// Many DISTINCT authenticated peers (a Sybil flood) are bounded by the GLOBAL byte
/// ceiling even though each is well within its own per-peer budget - the responder's own
/// last line before TASK-205's identity-cost defence.
///
/// MUTATION (red-without): remove the global ceiling check in
/// `PeerDeriveLedger::try_admit` (delete the `RefusedGlobal` branch). Each distinct peer
/// then passes on its generous per-peer budget -> every peer answers `Have`.
#[test]
fn global_ceiling_bounds_a_many_peer_flood() {
    let index = real_file_index();
    let tmp = TempDir::new("global");
    // Five DISTINCT held keys of equal NarSize, one probed per distinct peer.
    let mut keys = Vec::new();
    let mut nar_size = 0;
    for i in 0..5u8 {
        let (k, l) = hold_key(&index, &tmp, &format!("g{i}"), &[0x80 + i; 48]);
        nar_size = l;
        keys.push(k);
    }
    // Per-peer generous (each peer would be fine); GLOBAL bounds the total to 2 NARs.
    let ledger = PeerDeriveLedger::new(budget(100 * nar_size, 1000, 2 * nar_size));

    let answers: Vec<HoldAnswer> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| single(&index, *k, &peer(0x90 + i as u8), &ledger))
        .collect();
    let haves = answers
        .iter()
        .filter(|a| matches!(a, HoldAnswer::Have { .. }))
        .count();
    assert_eq!(
        haves, 2,
        "the GLOBAL ceiling must bound the many-peer flood to 2 NARs regardless of \
         distinct identities; {haves} Have means the Sybil floor is missing: {answers:?}"
    );
    assert_eq!(ledger.global_bytes_used(), 2 * nar_size);
}

/// The BATCH responder path is bounded by the same per-peer ledger (not just the
/// single-key path): a batch naming more cold keys than the byte budget affords answers
/// the surplus `Absent`.
#[test]
fn batch_answer_is_bounded_by_the_per_peer_ledger() {
    let index = real_file_index();
    let tmp = TempDir::new("batch");
    let mut keys = Vec::new();
    let mut nar_size = 0;
    for i in 0..5u8 {
        let (k, l) = hold_key(&index, &tmp, &format!("b{i}"), &[0x20 + i; 40]);
        nar_size = l;
        keys.push(k);
    }
    // Budget for two NARs; the 5-key batch must answer 2 Have + 3 Absent.
    let ledger = PeerDeriveLedger::new(budget(2 * nar_size, 1000, 100 * nar_size));
    let response = index
        .answer_batch_for_peer(
            &BatchHoldQuery {
                schema_version: QUERY_SCHEMA_VERSION,
                keys: keys.clone(),
            },
            &peer(4),
            &ledger,
        )
        .expect("answer_batch_for_peer");
    let haves = response
        .answers
        .iter()
        .filter(|a| matches!(a, BatchHoldAnswer::Have { .. }))
        .count();
    assert_eq!(
        haves, 2,
        "the batch path draws the SAME per-peer byte budget; got {haves} Have: {:?}",
        response.answers
    );
}

// ============================================================ Bite 5: reported honestly via --status

/// The operator `--status` surface renders the GLOBAL derive budget as `used/CAP`
/// INTEGERS, read LIVE from the enforcing ledger, redacted to an aggregate (no per-peer
/// identifier). No float appears in the figure.
///
/// MUTATION (red-without): have `render_status` report a mirrored constant / `0` instead
/// of reading `derive_ledger.global_bytes_used()`. The used value then stops tracking the
/// real charge and the `used == 2*nar_size` assertion reddens.
#[tokio::test]
async fn status_reports_derive_budget_used_over_cap_as_integers() {
    let contract = OperatorContract::for_profile(SharingProfile::PublicShare);
    let cap = contract.caps.derive_max_bytes_global_uncompressed;
    let ledger = Arc::new(PeerDeriveLedger::new(contract.caps.derive_budget()));

    // Drive real charge through the enforcing ledger: two 3000-byte admissions.
    assert!(ledger.try_admit(&peer(1), 3000).is_admitted());
    assert!(ledger.try_admit(&peer(2), 3000).is_admitted());

    let observ = Observability {
        contract,
        node_id_full: "12D3KooWRAWnodeidentity".to_string(),
        metrics: Arc::new(RuntimeMetrics::new()),
        facts: Arc::new(NullStatusFacts),
        announce: None,
        derive_ledger: Some(Arc::clone(&ledger)),
    };

    let status = observ.render_status().await;
    let line = status
        .lines()
        .find(|l| l.starts_with("derive_budget_global_bytes="))
        .expect("status must carry the derive budget line");
    assert_eq!(
        line,
        format!("derive_budget_global_bytes=6000/{cap}"),
        "the status must report the LIVE used/CAP; full status:\n{status}"
    );
    // No float anywhere in the figure: both sides parse as u64 integers.
    let figure = line.trim_start_matches("derive_budget_global_bytes=");
    let (used, caps) = figure.split_once('/').expect("used/cap");
    assert_eq!(used.parse::<u64>().unwrap(), 6000);
    assert_eq!(caps.parse::<u64>().unwrap(), cap);
    // Redaction: the aggregate carries no peer identifier (no NodeId hex leaks here).
    assert!(
        !line.contains("12D3KooW"),
        "the derive figure must be a bare aggregate"
    );
}
