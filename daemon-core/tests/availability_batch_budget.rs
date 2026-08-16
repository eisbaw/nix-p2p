//! task-104: a per-batch DERIVATION budget so ONE hold-query message cannot make a
//! responder spend unbounded `nix-store --dump` work.
//!
//! task-91 caps a batch at `MAX_BATCH_HOLD_KEYS` (256) KEYS, but on a COLD responder
//! each of those keys can cost one `nix-store --dump` of a large NAR - so one message
//! could otherwise trigger up to 256 large dumps and let a single peer pace the
//! responder's disk/CPU. `answer_batch` now answers freely from what is ALREADY
//! derived and triggers at most `MAX_BATCH_DERIVE_WORK` (16) FRESH dumps per batch;
//! once that budget is spent, further COLD keys answer `Absent` WITHOUT dumping (the
//! safe direction, and NO wire change). The under-report is bounded and the RESPONDER
//! cache warms `MAX_BATCH_DERIVE_WORK` cold keys per probe, so a deferred key becomes
//! `Have` on a later probe of the same set. (The discovery resolver does NOT itself
//! re-probe - it falls back upstream; the re-query modelled here is an organic later
//! query, e.g. a subsequent build, not a resolver auto-retry.)
//!
//! ## AC#1 bite (bounded work) and AC#2 bite (self-heal), one oracle
//!
//! `one_batch_message_is_bounded_to_the_derivation_budget_and_self_heals` registers
//! `N = 3*K + 3` COLD keys (K = `MAX_BATCH_DERIVE_WORK`) against a shared
//! `MemoryNarDumper` that COUNTS its dumps, and probes the whole set repeatedly. It
//! asserts the dumper is called EXACTLY `K` times per probe (not `N`), the warm keys
//! are never re-dumped, and one key that starts beyond the first budget flips
//! `Absent -> Have` on the probe whose budget finally reaches it.
//!
//! TO CONFIRM THE BITE BY MUTATION: in `daemon-core/src/availability.rs`, make the
//! batch budget unlimited (e.g. in `answer_batch` build `DeriveBudget::unlimited()`
//! instead of `::limited(MAX_BATCH_DERIVE_WORK)`, or make `DeriveBudget::try_reserve`
//! `return true` always). The FIRST assertion (`dumper.calls() == K after one probe`)
//! then goes RED because one message dumps all `N` keys - the exact monopolisation
//! the budget exists to prevent. (Verified locally: the unlimited mutation makes the
//! probe-1 count `51` instead of `16`.)

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use daemon_core::{
    AvailabilityIndex, BatchHoldAnswer, BatchHoldQuery, Blake3Digest, MAX_BATCH_DERIVE_WORK,
    MemoryNarDumper, NarDumper, NarHashKey, NodeId, NullAnnounce, NullStore, QUERY_SCHEMA_VERSION,
    StorePath,
};

// ------------------------------------------------------------------ helpers

/// A unique temp directory that removes itself on drop.
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
            "nixp2p-batchbudget-{label}-{}-{n}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        TempDir { path }
    }

    /// A materialised stand-in store path. The bytes are irrelevant: the index dumps
    /// via the injected `MemoryNarDumper`, not this file, but the path must EXIST for
    /// the materialisation check in `hold` to pass.
    fn store_file(&self, name: &str) -> StorePath {
        let p = self.path.join(name);
        std::fs::write(&p, b"stand-in store path contents").expect("write store file");
        StorePath::new(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
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

/// A distinct FILLER key that is NOT the valid key. Encodes the index in the digest
/// bytes so every filler is unique.
fn filler_key(i: usize) -> NarHashKey {
    let mut bytes = [0u8; 32];
    bytes[0..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
    bytes[8] = 0xf1; // keep fillers clear of any low-byte valid-key collision
    NarHashKey::from_sha256_bytes(bytes)
}

fn count_have(answers: &[BatchHoldAnswer]) -> usize {
    answers
        .iter()
        .filter(|a| matches!(a, BatchHoldAnswer::Have { .. }))
        .count()
}

#[test]
fn one_batch_message_is_bounded_to_the_derivation_budget_and_self_heals() {
    let k = MAX_BATCH_DERIVE_WORK as usize;
    assert!(k >= 1, "the budget must permit at least one dump");
    let n = 3 * k + 3;

    let tmp = TempDir::new("bound");

    // Every registered path dumps to these SAME bytes (MemoryNarDumper is content-
    // fixed). Exactly one registered key equals their NarHash and so VERIFIES to Have;
    // the rest mismatch and quarantine - but a quarantine still COSTS a counted dump,
    // which is what the budget bounds.
    let nar = synth_raw_nar(b"task-104 batch derivation budget payload");
    let valid_key = NarHashKey::from_raw_nar(&nar);
    let valid_blake3 = Blake3Digest::from_raw_nar(&nar);

    let dumper = Arc::new(MemoryNarDumper::new(nar.clone()));
    let dyn_dumper: Arc<dyn NarDumper> = dumper.clone();
    let index = AvailabilityIndex::open(
        node(),
        dyn_dumper,
        Arc::new(NullStore),
        Arc::new(NullAnnounce),
    )
    .expect("open index");

    // The valid key sits at index `k`: the FIRST key of the SECOND budget frontier.
    // Probe 1's budget (indices 0..k) never reaches it, so it defers; probe 2's budget
    // (indices k..2k) dumps it, so it flips Absent -> Have. This makes the self-heal a
    // concrete, observable transition rather than an inference.
    let valid_index = k;
    let mut all: Vec<NarHashKey> = Vec::with_capacity(n);
    for i in 0..n {
        let key = if i == valid_index {
            valid_key
        } else {
            let fk = filler_key(i);
            assert_ne!(fk, valid_key, "filler must not collide with the valid key");
            fk
        };
        index
            .register(key, tmp.store_file(&format!("nar-{i}")))
            .expect("register");
        all.push(key);
    }
    // Keys must be distinct (the wire forbids duplicates and the index is key-addressed).
    let mut sorted = all.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), n, "all registered keys must be distinct");

    let probe = |i: &AvailabilityIndex| -> Vec<BatchHoldAnswer> {
        i.answer_batch(&BatchHoldQuery {
            schema_version: QUERY_SCHEMA_VERSION,
            keys: all.clone(),
        })
        .expect("answer_batch")
        .answers
    };

    // ----- probe 1: exactly K fresh dumps for the WHOLE message (AC#1 bite) -----
    let a1 = probe(&index);
    assert_eq!(a1.len(), n, "one answer per asked key");
    assert_eq!(
        dumper.calls(),
        k,
        "ONE batch message must trigger at most the derivation budget ({k}) fresh \
         dumps, NOT one per key ({n}). If this is {n}, the budget is not being enforced."
    );
    assert!(
        dumper.calls() < n,
        "a cold {n}-key batch must not dump per key"
    );
    assert!(
        matches!(a1[valid_index], BatchHoldAnswer::Absent {}),
        "the valid key sits past the first budget frontier, so probe 1 defers it (Absent)"
    );
    assert_eq!(
        count_have(&a1),
        0,
        "probe 1's budget covers only mismatching filler keys, so nothing verifies yet"
    );

    // ----- probe 2: frontier advances by K; the deferred valid key flips to Have (AC#2) -----
    let a2 = probe(&index);
    assert_eq!(
        dumper.calls(),
        2 * k,
        "the already-derived first {k} keys are NOT re-dumped; the budget advances to \
         the next {k} cold keys"
    );
    match &a2[valid_index] {
        BatchHoldAnswer::Have { blake3, .. } => assert_eq!(
            *blake3, valid_blake3,
            "the self-healed key answers its real BLAKE3"
        ),
        other => {
            panic!("the valid key must flip Absent -> Have once its dump is in budget: {other:?}")
        }
    }
    assert_eq!(
        count_have(&a2),
        1,
        "exactly the one truly-held key verifies (the rest are mismatched fillers)"
    );

    // ----- probes 3..: the frontier keeps advancing K per probe until every cold key
    // is warm, then NO further dumps (warm keys are never re-derived) -----
    let _ = probe(&index);
    assert_eq!(dumper.calls(), 3 * k, "probe 3 warms the third frontier");
    let _ = probe(&index);
    assert_eq!(
        dumper.calls(),
        n,
        "probe 4 warms the final {} cold keys - every registered key is now derived",
        n - 3 * k
    );
    let a5 = probe(&index);
    assert_eq!(
        dumper.calls(),
        n,
        "once every key is warm, a further probe triggers ZERO dumps - warm keys never \
         re-derive and the budget is spent only on FRESH work"
    );
    assert_eq!(
        count_have(&a5),
        1,
        "the held key stays Have across probes; the mismatched fillers stay Absent"
    );
}
