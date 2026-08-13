//! Transport-SPECIFIC locators and protocol constants (task-48 FREEZE).
//!
//! The counterpart to [`crate::content_id`]: where that module freezes the ONE
//! universal content identity every transport shares, this module freezes the
//! per-transport LOCATORS - the coordinates each transport needs to actually
//! reach a holder, which are NOT derivable from the content identity and differ
//! by transport:
//!   * iroh: a holder [`NodeId`] (an ed25519 public key) + the `IROH_BLOBS_ALPN`
//!     protocol identifier (now in `fabric-iroh`). iroh dials a NodeId and streams the blob addressed by
//!     the universal [`crate::content_id::Blake3Digest`].
//!   * BitTorrent: a [`BitTorrentInfoHash`] naming a swarm/piece-layout. A future
//!     BitTorrent backend addresses the swarm by infohash, then still verifies the
//!     transferred bytes against the SAME `Blake3Digest`. Representable here
//!     (proving a 2nd transport is not a network fork) though no backend exists
//!     yet.
//!
//! This separation is the whole point of the freeze's design constraint: a
//! transport is added by adding its locator type and a claim offer variant (see
//! [`crate::claim::KnownTransport`]) - never by touching the content identity. A
//! BitTorrent locator does not fit in a `NodeId`, and forcing it to would fork the
//! supply network the day BitTorrent ships.
//!
//! ## Where the locator TYPES now live (TASK-141)
//!
//! [`NodeId`] and [`BitTorrentInfoHash`] MOVED to the `peer-fabric` seam crate -
//! the canonical home of every value type that crosses the P2P seam - and are
//! re-exported here (the daemon used to keep byte-compatible DUPLICATES, deleted by
//! TASK-141). `BitTorrentInfoHash` is `peer_fabric::InfoHash` under its
//! daemon-facing name. This module keeps the freeze NARRATIVE (the iroh protocol
//! constant `IROH_BLOBS_ALPN` moved to the `fabric-iroh` backend crate, TASK-146), and a
//! light RE-EXPORT SMOKE TEST proving the daemon path resolves to a working
//! `NodeId`/`BitTorrentInfoHash` with the canonical string/serde forms. (The
//! authoritative codec conformance for these types lives with them in
//! `peer_fabric::ids`; the golden claim-wire JSON in `daemon/tests/golden_vectors.rs`
//! and `claim_wire_golden.rs` is the cross-crate wire anchor.)
//!
//! ## Canonical encodings pinned here
//!
//! [`NodeId`] is the 32 raw ed25519 public-key bytes; its canonical wire string is
//! 64 lowercase hex chars. We canonicalise on the RAW BYTES, not on iroh's own
//! `Display`, on purpose: a backend reconstructs the iroh handle via the stable
//! `iroh::NodeId::from_bytes(&[u8; 32])` byte constructor, so our wire form never
//! depends on which string encoding a given iroh version happens to print. That is
//! how "content identity separated from transport" is made robust against iroh API
//! churn (PRD risk 10).

// NodeId / BitTorrentInfoHash and their canonical-string codecs now live in
// `peer-fabric` (their canonical home; TASK-141). Re-exported here so every daemon
// use-site (`crate::transport::NodeId`, ...) and the freeze narrative above keep
// their home, with a single definition below the seam. `BitTorrentInfoHash` is the
// daemon-facing name of `peer_fabric::InfoHash`.
pub use peer_fabric::{
    InfoHash as BitTorrentInfoHash, InfoHashParseError, NODE_ID_LEN, NodeId, NodeIdParseError,
};

// The iroh-blobs ALPN constant (`IROH_BLOBS_ALPN`) is an iroh-specific value, not a
// cross-seam identity, so it lives in the `fabric-iroh` backend crate (co-located with the
// iroh-blobs get-protocol and the compile-time `IROH_BLOBS_ALPN == iroh_blobs::ALPN`
// assertion). TASK-146 moved this module into the stack-neutral `daemon-core` crate, which
// has NO iroh dependency, so the re-export that used to sit here is gone; the monolith
// `daemon` (and the future `daemon-iroh` binary) re-export `fabric_iroh::IROH_BLOBS_ALPN`
// directly. `fabric-iroh` owns the ALPN freeze test.

#[cfg(test)]
mod tests {
    // RE-EXPORT SMOKE TEST: these exercise the daemon path (the re-exported seam
    // types) to prove the canonical string/serde forms resolve through the daemon.
    // The authoritative codec conformance lives with the types in `peer_fabric::ids`;
    // the golden claim-wire JSON is the cross-crate wire anchor (see module docs).
    use super::*;

    #[test]
    fn node_id_round_trips_as_64_hex() {
        let node = NodeId::from_bytes([0x11; NODE_ID_LEN]);
        let s = node.to_string();
        assert_eq!(s, "11".repeat(32));
        assert_eq!(s.len(), 64);
        assert_eq!(s.parse::<NodeId>().unwrap(), node);
    }

    #[test]
    fn node_id_serde_is_bare_hex() {
        let node = NodeId::from_bytes([0x22; NODE_ID_LEN]);
        let json = serde_json::to_string(&node).unwrap();
        assert_eq!(json, format!("\"{}\"", "22".repeat(32)));
        assert_eq!(serde_json::from_str::<NodeId>(&json).unwrap(), node);
    }

    #[test]
    fn node_id_rejects_wrong_length() {
        assert!("1111".parse::<NodeId>().is_err());
    }

    #[test]
    fn infohash_v1_and_v2_disambiguate_by_length() {
        let v1 = BitTorrentInfoHash::v1([0xaa; 20]);
        let v2 = BitTorrentInfoHash::v2([0xbb; 32]);
        assert_eq!(v1.to_string(), "aa".repeat(20));
        assert_eq!(v2.to_string(), "bb".repeat(32));
        // 40 hex chars -> v1, 64 -> v2, purely from length.
        assert_eq!(v1.to_string().parse::<BitTorrentInfoHash>().unwrap(), v1);
        assert_eq!(v2.to_string().parse::<BitTorrentInfoHash>().unwrap(), v2);
    }

    #[test]
    fn infohash_rejects_a_length_that_is_neither_form() {
        // 24 bytes = 48 hex chars: not a real infohash form.
        let bad = "cc".repeat(24);
        assert_eq!(
            bad.parse::<BitTorrentInfoHash>(),
            Err(InfoHashParseError::WrongLength(24))
        );
    }

    #[test]
    fn infohash_serde_round_trips_both_forms() {
        for hash in [
            BitTorrentInfoHash::v1([0x01; 20]),
            BitTorrentInfoHash::v2([0x02; 32]),
        ] {
            let json = serde_json::to_string(&hash).unwrap();
            assert_eq!(
                serde_json::from_str::<BitTorrentInfoHash>(&json).unwrap(),
                hash
            );
        }
    }
}
