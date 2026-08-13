//! On-disk DURABLE FLOOR persistence (TASK-176 #1) for the directory's anti-rollback
//! floor and the announcer's per-key announce sequence.
//!
//! The frozen `record_store` module doc names DURABLE SEQUENCE as the BACKEND's
//! obligation: a consumer that restarts and loses its floor can be served a still-valid
//! rolled-back record until it re-observes the newer sequence; a provider that restarts
//! and loses its counter mints a withdrawal at sequence 1 that silently loses. This
//! module is that durability, kept the project's "git-not-db" way: a small, GREPPABLE,
//! line-oriented TEXT file (one slot per line, lowercase hex), atomically replaced
//! (write-temp + rename) so a crash mid-write never leaves a torn file.
//!
//! The floor is an OPTIMISATION/SECURITY cache, not authoritative state: a corrupt or
//! unreadable line costs the anti-rollback guarantee for THAT slot (it degrades to
//! session-fresh, exactly as a restart without persistence would), so a bad line is
//! logged loudly and SKIPPED rather than aborting the load - one poisoned line must not
//! deny a node its whole floor.

use std::fs;
use std::io::Write;
use std::path::Path;

use peer_fabric::{
    ContentKey, NodeId, ProviderAssertion, SlotFloor, decode_provider_assertion,
    encode_provider_record,
};

/// The schema line every floor/sequence file opens with; a version bump lands old files
/// on the SKIP path (unknown format -> start fresh), never a mis-parse.
const FLOOR_HEADER: &str = "# nix-p2p fabric-libp2p directory-floor v1";
const SEQ_HEADER: &str = "# nix-p2p fabric-libp2p announce-seq v1";

/// Lowercase-hex encode (the same canonical form the seam's identities use).
fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit((b >> 4) as u32, 16).expect("nibble"));
        out.push(char::from_digit((b & 0x0f) as u32, 16).expect("nibble"));
    }
    out
}

/// Decode lowercase hex to bytes; `None` on an odd length or a non-hex char (fail
/// closed - a malformed line is skipped, never half-parsed).
fn from_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
        i += 2;
    }
    Some(out)
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    from_hex(s)?.try_into().ok()
}

/// Atomically replace `path`'s contents with `text` (write a sibling temp, then rename).
/// A rename within a directory is atomic on POSIX, so a reader/crash sees either the old
/// or the new file, never a partial one.
///
/// DURABILITY (TASK-185, AC#3): after the rename we fsync the CONTAINING DIRECTORY. A POSIX
/// rename is not guaranteed persisted until the directory entry itself is fsynced, so
/// without this a crash right after a successful `announce` could lose the just-persisted
/// sequence even though this function returned `Ok` - reopening exactly the post-restart
/// rollback window the durable floor exists to close. The temp file's own contents are
/// fsynced (`sync_all`) before the rename, so the rename can only ever expose fully-written
/// bytes.
///
/// CONCURRENCY (honest limit): this save is NOT internally serialized. The announcer
/// snapshots its per-key map under the lock and writes OUTSIDE the lock, so two concurrent
/// `announce` calls (even for different keys) can each take a snapshot and then race the
/// `rename` - a writer holding an OLDER snapshot can land AFTER a newer one and DROP the
/// newer key's durable advance from disk, a lost-update / restart-rollback for that key even
/// though its announce already returned `Ok`. A unique per-write temp name does NOT close
/// this (the lost update is at the rename, not the temp); the real fix is to make the
/// snapshot+write ONE serialized critical section (or a persistence mutex). This is SAFE
/// TODAY only because the shipped provider announce loop (`install_provider`) is strictly
/// sequential - one awaited announce per seed - so no two saves are ever in flight. The
/// serialized-save fix (and the shared-`state_dir` advisory lock) is filed in TASK-188.
fn write_atomic(path: &Path, text: &str) -> std::io::Result<()> {
    let parent = path.parent();
    if let Some(parent) = parent {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    // fsync the parent directory so the rename (the file's new identity) is itself durable.
    if let Some(parent) = parent {
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

// -------------------------------------------------------------------------
// Directory floor: `(ContentKey, NodeId, SlotFloor)` lines.
//   A <key-hex> <record-wire-hex>              (active: the whole frozen-wire record)
//   W <key-hex> <provider-hex> <seq> <expiry>  (tombstone floor)
// -------------------------------------------------------------------------

/// Serialize the exported floors to the durable text form.
pub fn serialize_floors(floors: &[(ContentKey, NodeId, SlotFloor)]) -> String {
    let mut out = String::from(FLOOR_HEADER);
    out.push('\n');
    for (key, provider, floor) in floors {
        match floor {
            SlotFloor::Active(record) => {
                // The whole record goes to disk via the FROZEN wire codec, so reload
                // re-verifies its signature and self-consistency (defense in depth) and no
                // field can drift. `encode` only fails on an over-cap record, which the
                // store never holds (it only ever admitted decoded, in-cap records).
                match encode_provider_record(record) {
                    Ok(bytes) => {
                        out.push_str(&format!(
                            "A {} {}\n",
                            to_hex(key.as_bytes()),
                            to_hex(&bytes)
                        ));
                    }
                    Err(why) => {
                        tracing::error!(%why, "skipping un-encodable active floor on persist");
                    }
                }
            }
            SlotFloor::Withdrawn { sequence, expiry } => {
                out.push_str(&format!(
                    "W {} {} {} {}\n",
                    to_hex(key.as_bytes()),
                    to_hex(provider.as_bytes()),
                    sequence,
                    expiry
                ));
            }
        }
    }
    out
}

/// Parse the durable text form back into floors. Skips (with a warning) any line that is
/// malformed, unknown, or - for an Active line - fails the FROZEN decode, so a poisoned
/// line degrades only its own slot. `now` gates the reload of active records at the
/// codec's expiry check; pass `0` to reload every non-degenerate record (the store's own
/// TTL sweep drops any that are already expired).
pub fn deserialize_floors(text: &str) -> Vec<(ContentKey, NodeId, SlotFloor)> {
    let mut out = Vec::new();
    let mut lines = text.lines();
    match lines.next() {
        Some(FLOOR_HEADER) => {}
        other => {
            tracing::warn!(?other, "unknown provider-floor header; ignoring the file");
            return out;
        }
    }
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        match parse_floor_line(line) {
            Some(entry) => out.push(entry),
            None => tracing::warn!(line, "skipping malformed provider-floor line"),
        }
    }
    out
}

fn parse_floor_line(line: &str) -> Option<(ContentKey, NodeId, SlotFloor)> {
    let mut parts = line.split(' ');
    match parts.next()? {
        "A" => {
            let key = ContentKey::from_bytes(hex32(parts.next()?)?);
            let bytes = from_hex(parts.next()?)?;
            if parts.next().is_some() {
                return None; // trailing field
            }
            // Reload through the FROZEN decode (now=0 so a live-when-saved record is not
            // rejected as stale merely because the reader's clock advanced). WrongKey
            // cannot fire: the stored key IS the record's own key.
            match decode_provider_assertion(&bytes, &key, 0) {
                Ok(ProviderAssertion::Provide(record)) => {
                    let provider = record.provider;
                    Some((key, provider, SlotFloor::Active(record)))
                }
                // A withdrawal was never stored on an `A` line; anything else is malformed.
                _ => None,
            }
        }
        "W" => {
            let key = ContentKey::from_bytes(hex32(parts.next()?)?);
            let provider = NodeId::from_bytes(hex32(parts.next()?)?);
            let sequence: u64 = parts.next()?.parse().ok()?;
            let expiry: u64 = parts.next()?.parse().ok()?;
            if parts.next().is_some() {
                return None;
            }
            Some((key, provider, SlotFloor::Withdrawn { sequence, expiry }))
        }
        _ => None,
    }
}

/// Persist floors to `path` (atomic). Errors are logged, not propagated: a transient
/// write failure costs durability (the in-memory floor still holds this session), and a
/// resolve must not fail because the disk hiccuped.
pub fn save_floors(path: &Path, floors: &[(ContentKey, NodeId, SlotFloor)]) {
    let text = serialize_floors(floors);
    if let Err(why) = write_atomic(path, &text) {
        tracing::error!(%why, path = %path.display(), "could not persist provider floor");
    }
}

/// Load floors from `path`; an absent file is an empty floor (first run), a read error is
/// logged and treated as empty (degrade to session-fresh, never fail startup).
pub fn load_floors(path: &Path) -> Vec<(ContentKey, NodeId, SlotFloor)> {
    match fs::read_to_string(path) {
        Ok(text) => deserialize_floors(&text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(why) => {
            tracing::error!(%why, path = %path.display(), "could not read provider floor; starting fresh");
            Vec::new()
        }
    }
}

// -------------------------------------------------------------------------
// Announcer per-key sequence: `<key-hex> <seq> <expiry>` lines.
// -------------------------------------------------------------------------

/// Serialize the announcer's per-key `(sequence, expiry)` floor.
pub fn serialize_seqs(seqs: &[(ContentKey, u64, u64)]) -> String {
    let mut out = String::from(SEQ_HEADER);
    out.push('\n');
    for (key, sequence, expiry) in seqs {
        out.push_str(&format!(
            "{} {} {}\n",
            to_hex(key.as_bytes()),
            sequence,
            expiry
        ));
    }
    out
}

/// Parse the announcer's per-key `(sequence, expiry)` floor. Skips malformed lines.
pub fn deserialize_seqs(text: &str) -> Vec<(ContentKey, u64, u64)> {
    let mut out = Vec::new();
    let mut lines = text.lines();
    match lines.next() {
        Some(SEQ_HEADER) => {}
        other => {
            tracing::warn!(?other, "unknown announce-seq header; ignoring the file");
            return out;
        }
    }
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        match parse_seq_line(line) {
            Some(entry) => out.push(entry),
            None => tracing::warn!(line, "skipping malformed announce-seq line"),
        }
    }
    out
}

fn parse_seq_line(line: &str) -> Option<(ContentKey, u64, u64)> {
    let mut parts = line.split(' ');
    let key = ContentKey::from_bytes(hex32(parts.next()?)?);
    let sequence: u64 = parts.next()?.parse().ok()?;
    let expiry: u64 = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((key, sequence, expiry))
}

/// Persist the announcer's per-key sequence floor to `path` (atomic; errors logged).
pub fn save_seqs(path: &Path, seqs: &[(ContentKey, u64, u64)]) {
    let text = serialize_seqs(seqs);
    if let Err(why) = write_atomic(path, &text) {
        tracing::error!(%why, path = %path.display(), "could not persist announce sequence");
    }
}

/// Persist the announcer's per-key sequence floor to `path`, PROPAGATING any I/O error
/// (TASK-185, AC#3). The announce path uses THIS - not the logging [`save_seqs`] - so a save
/// failure can FAIL-CLOSED the announce (no DHT publish) rather than silently degrading to
/// non-durable. Includes the parent-dir fsync of [`write_atomic`], so on `Ok` the sequence
/// is durably on disk before the caller publishes.
pub fn save_seqs_checked(path: &Path, seqs: &[(ContentKey, u64, u64)]) -> std::io::Result<()> {
    write_atomic(path, &serialize_seqs(seqs))
}

/// Load the announcer's per-key sequence floor (absent/error -> empty).
pub fn load_seqs(path: &Path) -> Vec<(ContentKey, u64, u64)> {
    match fs::read_to_string(path) {
        Ok(text) => deserialize_seqs(&text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(why) => {
            tracing::error!(%why, path = %path.display(), "could not read announce sequence; starting fresh");
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use peer_fabric::{Blake3Digest, ProviderRecord, TransportOffer, sign_provider_record};

    fn a_record(seed: u8, seq: u64, expiry: u64) -> (ContentKey, NodeId, ProviderRecord) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let provider = NodeId::from_bytes(sk.verifying_key().to_bytes());
        let key = ContentKey::derive_from_signed_nar_hash(&[seed; 32]);
        let record = ProviderRecord {
            key,
            content: Blake3Digest::from_bytes([0xaa; 32]),
            provider,
            offers: vec![TransportOffer::Iroh { node: provider }],
            sequence: seq,
            issued_at: 0,
            expiry,
            signature: [0u8; 64],
        };
        (key, provider, sign_provider_record(&sk, &record))
    }

    #[test]
    fn active_floor_round_trips_through_the_frozen_wire() {
        // BITE: an active floor serialized and re-parsed yields the SAME record (frozen
        // wire, signature re-verified). Corrupt one hex nibble and the decode fails, so
        // the line is skipped - the round-trip loses the slot.
        let (key, provider, record) = a_record(9, 5, 1_000_000);
        let floors = vec![(key, provider, SlotFloor::Active(record.clone()))];
        let text = serialize_floors(&floors);
        let back = deserialize_floors(&text);
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].0, key);
        assert_eq!(back[0].1, provider);
        assert_eq!(back[0].2, SlotFloor::Active(record));
    }

    #[test]
    fn withdrawn_floor_round_trips() {
        let (key, provider, _) = a_record(10, 0, 0);
        let floors = vec![(
            key,
            provider,
            SlotFloor::Withdrawn {
                sequence: 7,
                expiry: 2_000,
            },
        )];
        let text = serialize_floors(&floors);
        let back = deserialize_floors(&text);
        assert_eq!(back.len(), 1);
        assert_eq!(
            back[0].2,
            SlotFloor::Withdrawn {
                sequence: 7,
                expiry: 2_000
            }
        );
    }

    #[test]
    fn a_corrupt_line_is_skipped_not_fatal() {
        // A good line, a garbage line, and an unknown-kind line: only the good one loads.
        let (key, provider, record) = a_record(11, 3, 1_000_000);
        let mut text = serialize_floors(&[(key, provider, SlotFloor::Active(record))]);
        text.push_str("Z not a real line\n");
        text.push_str("A deadbeef zzzz\n");
        assert_eq!(deserialize_floors(&text).len(), 1);
    }

    #[test]
    fn seq_floor_round_trips() {
        let key = ContentKey::derive_from_signed_nar_hash(&[3; 32]);
        let text = serialize_seqs(&[(key, 12, 9_999)]);
        let back = deserialize_seqs(&text);
        assert_eq!(back, vec![(key, 12, 9_999)]);
    }

    #[test]
    fn unknown_header_is_ignored() {
        assert!(deserialize_floors("garbage header\nA x y\n").is_empty());
        assert!(deserialize_seqs("garbage\nx 1 2\n").is_empty());
    }
}
