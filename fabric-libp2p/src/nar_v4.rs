//! Canonical `/nar/4` Bao body framing.
//!
//! This module is deliberately transport-agnostic synchronous code. Callers run
//! it in bounded blocking workers and provide ownership-preserving adapters. It
//! uses `bao-tree` geometry and BLAKE3 hazmat primitives, but deliberately mirrors
//! the small full-range preorder authentication-stack subset locally so raw leaf
//! allocations can move to the socket without a `Write`-slice copy. The
//! byte-for-byte encoder and bidirectional decoder differential oracle against
//! `bao-tree` is load-bearing coverage for that duplicated cryptographic subset.

use std::cell::{Cell, RefCell};
use std::io::{self, Read};

use bao_tree::io::outboard::PreOrderOutboard;
use bao_tree::io::sync::{CreateOutboard, Outboard, ReadAt};
use bao_tree::iter::{BaoChunk, ResponseIter};
use bao_tree::{BaoTree, BlockSize, ChunkRanges};
use bytes::Bytes;
#[cfg(test)]
use peer_fabric::compress_zstd;
use peer_fabric::{BoundedZstdDecoder, DecodeError, StreamingZstdEncoder, WireCodec};

/// 64 KiB raw leaves: BLAKE3's 1-KiB chunks grouped by `2^6`.
pub(crate) const BAO_BLOCK_SIZE: BlockSize = BlockSize::from_chunk_log(6);
pub(crate) const COMPLETE_MARKER: &[u8; 4] = b"N4OK";

/// Exact successful `/nar/4` substream byte accounting. These are protocol
/// bytes on the NAR substream, not TCP/IP, Noise, yamux, or retransmission
/// bytes. Every derived total is retained only as an asserted equation over
/// the component fields, so measurements cannot silently change units.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NarV4WireAccounting {
    pub request_protocol_bytes: u64,
    pub response_header_bytes: u64,
    pub proof_bytes: u64,
    pub leaf_count: u64,
    pub leaf_length_prefix_bytes: u64,
    pub encoded_leaf_bytes: u64,
    pub complete_marker_bytes: u64,
    pub response_body_bytes: u64,
    pub response_protocol_bytes: u64,
    pub exchange_protocol_bytes: u64,
}

impl NarV4WireAccounting {
    pub const REQUEST_PROTOCOL_BYTES: u64 = 33;
    pub const RESPONSE_HEADER_BYTES: u64 = 10;
    pub const COMPLETE_MARKER_BYTES: u64 = COMPLETE_MARKER.len() as u64;

    pub fn from_response_protocol_bytes(
        raw_size: u64,
        codec: WireCodec,
        response_protocol_bytes: u64,
    ) -> io::Result<Self> {
        let fixed = Self::RESPONSE_HEADER_BYTES
            .checked_add(Self::COMPLETE_MARKER_BYTES)
            .expect("fixed v4 framing fits u64");
        let framed_bao_bytes = response_protocol_bytes.checked_sub(fixed).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "successful /nar/4 response was {response_protocol_bytes} B, shorter than fixed {fixed} B framing"
                ),
            )
        })?;
        Self::from_framed_bao_bytes(raw_size, codec, framed_bao_bytes)
    }

    pub fn from_framed_bao_bytes(
        raw_size: u64,
        codec: WireCodec,
        framed_bao_bytes: u64,
    ) -> io::Result<Self> {
        let tree = BaoTree::new(raw_size, BAO_BLOCK_SIZE);
        let proof_bytes = tree.outboard_size();
        let leaf_count = raw_size.div_ceil(64 * 1024).max(1);
        let leaf_length_prefix_bytes = match codec {
            WireCodec::Raw => 0,
            WireCodec::Zstd => leaf_count.checked_mul(4).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "v4 leaf-prefix bytes overflow u64",
                )
            })?,
        };
        let fixed_body = proof_bytes
            .checked_add(leaf_length_prefix_bytes)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "v4 proof bytes overflow u64")
            })?;
        let encoded_leaf_bytes = framed_bao_bytes.checked_sub(fixed_body).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "framed Bao body {framed_bao_bytes} B is shorter than proof+prefix geometry {fixed_body} B"
                ),
            )
        })?;
        if codec == WireCodec::Raw && encoded_leaf_bytes != raw_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "raw /nar/4 encoded-leaf bytes {encoded_leaf_bytes} differ from raw_size {raw_size}"
                ),
            ));
        }
        let response_body_bytes = framed_bao_bytes
            .checked_add(Self::COMPLETE_MARKER_BYTES)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "v4 body bytes overflow u64")
            })?;
        let response_protocol_bytes = Self::RESPONSE_HEADER_BYTES
            .checked_add(response_body_bytes)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "v4 response bytes overflow u64")
            })?;
        let exchange_protocol_bytes = Self::REQUEST_PROTOCOL_BYTES
            .checked_add(response_protocol_bytes)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "v4 exchange bytes overflow u64")
            })?;
        let accounting = Self {
            request_protocol_bytes: Self::REQUEST_PROTOCOL_BYTES,
            response_header_bytes: Self::RESPONSE_HEADER_BYTES,
            proof_bytes,
            leaf_count,
            leaf_length_prefix_bytes,
            encoded_leaf_bytes,
            complete_marker_bytes: Self::COMPLETE_MARKER_BYTES,
            response_body_bytes,
            response_protocol_bytes,
            exchange_protocol_bytes,
        };
        accounting.validate()?;
        Ok(accounting)
    }

    pub fn validate(&self) -> io::Result<()> {
        let framed = self
            .proof_bytes
            .checked_add(self.leaf_length_prefix_bytes)
            .and_then(|n| n.checked_add(self.encoded_leaf_bytes));
        let body = framed.and_then(|n| n.checked_add(self.complete_marker_bytes));
        let response = body.and_then(|n| n.checked_add(self.response_header_bytes));
        let exchange = response.and_then(|n| n.checked_add(self.request_protocol_bytes));
        if body != Some(self.response_body_bytes)
            || response != Some(self.response_protocol_bytes)
            || exchange != Some(self.exchange_protocol_bytes)
            || self.request_protocol_bytes != Self::REQUEST_PROTOCOL_BYTES
            || self.response_header_bytes != Self::RESPONSE_HEADER_BYTES
            || self.complete_marker_bytes != Self::COMPLETE_MARKER_BYTES
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "inconsistent /nar/4 protocol-byte accounting",
            ));
        }
        Ok(())
    }
}

/// Worst-case zstd frame for one 64-KiB leaf using the same integer
/// `compressBound` formula as the bounded decoder. The fixed bound is checked
/// before allocating attacker-declared encoded bytes.
pub(crate) const MAX_ENCODED_LEAF_BYTES: usize = (64 * 1024) + ((64 * 1024) / 128) + 512 + 64;

/// zstd accepts window-log ceilings no smaller than 10 (1 KiB). The final Bao
/// leaf may be shorter than that, while every full leaf is exactly 2^16 bytes.
const ZSTD_MIN_WINDOW_LOG: u32 = 10;

fn leaf_window_log_max(raw_size: usize) -> u32 {
    let geometry_log = if raw_size <= 1 {
        0
    } else {
        usize::BITS - (raw_size - 1).leading_zeros()
    };
    geometry_log.clamp(ZSTD_MIN_WINDOW_LOG, 16)
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyItem {
    Parent,
    Leaf(usize),
}

#[cfg(test)]
fn body_items(tree: BaoTree) -> impl Iterator<Item = BodyItem> {
    ResponseIter::new(tree, ChunkRanges::all()).map(|item| match item {
        BaoChunk::Parent { .. } => BodyItem::Parent,
        BaoChunk::Leaf { size, .. } => BodyItem::Leaf(size),
    })
}

pub(crate) fn create_outboard(
    reader: &mut impl Read,
    raw_size: u64,
) -> io::Result<PreOrderOutboard<Vec<u8>>> {
    let mut outboard =
        PreOrderOutboard::<Vec<u8>>::create_sized(&mut *reader, raw_size, BAO_BLOCK_SIZE)?;
    // `create_sized` intentionally consumes exactly the declared geometry. The
    // extra read is load-bearing: a source that grew by even one byte is not an
    // exact replay and must fail before a response header is sent.
    let mut extra = [0u8; 1];
    if reader.read(&mut extra)? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("source produced more than declared raw_size {raw_size}"),
        ));
    }
    // The generic outboard stores only proof pairs; reserve exactly the
    // declared-size-derived geometry and reject an unexpected representation.
    let expected = usize::try_from(outboard.tree.outboard_size()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Bao outboard size does not fit usize",
        )
    })?;
    if outboard.data.len() != expected {
        return Err(io::Error::other(format!(
            "Bao outboard representation was {} B, expected {expected} B",
            outboard.data.len()
        )));
    }
    outboard.data.shrink_to_fit();
    Ok(outboard)
}

/// An ownership-preserving sink for one canonical `/nar/4` wire item. The
/// production implementation transfers each `Vec` to the async socket drain
/// and does not return it until that write completes. This makes socket
/// backpressure structural: the encoder cannot allocate or authenticate the
/// next leaf while a prior leaf is still buffered by the transport.
pub(crate) trait OwnedWireSink {
    /// Transfer `bytes` and return the emptied allocation for reuse.
    fn write_owned(&mut self, bytes: Vec<u8>) -> io::Result<Vec<u8>>;

    fn flush(&mut self) -> io::Result<()>;
}

fn checked_add_bytes(total: u64, increment: usize, context: &'static str) -> io::Result<u64> {
    let increment = u64::try_from(increment).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{context} increment does not fit u64: {increment} B"),
        )
    })?;
    total.checked_add(increment).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{context} overflow: {total} B + {increment} B"),
        )
    })
}

impl OwnedWireSink for Vec<u8> {
    fn write_owned(&mut self, mut bytes: Vec<u8>) -> io::Result<Vec<u8>> {
        self.extend_from_slice(&bytes);
        bytes.clear();
        Ok(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl OwnedWireSink for &mut Vec<u8> {
    fn write_owned(&mut self, mut bytes: Vec<u8>) -> io::Result<Vec<u8>> {
        self.extend_from_slice(&bytes);
        bytes.clear();
        Ok(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn hash_subtree(start_byte: u64, data: &[u8], is_root: bool) -> bao_tree::blake3::Hash {
    use bao_tree::blake3::hazmat::{ChainingValue, HasherExt};

    if is_root {
        debug_assert_eq!(start_byte, 0);
        bao_tree::blake3::hash(data)
    } else {
        let mut hasher = bao_tree::blake3::Hasher::new();
        hasher.set_input_offset(start_byte);
        hasher.update(data);
        let non_root: ChainingValue = hasher.finalize_non_root();
        bao_tree::blake3::Hash::from(non_root)
    }
}

fn parent_hash(
    left: &bao_tree::blake3::Hash,
    right: &bao_tree::blake3::Hash,
    is_root: bool,
) -> bao_tree::blake3::Hash {
    use bao_tree::blake3::hazmat::{
        ChainingValue, Mode, merge_subtrees_non_root, merge_subtrees_root,
    };

    let left: ChainingValue = *left.as_bytes();
    let right: ChainingValue = *right.as_bytes();
    if is_root {
        merge_subtrees_root(&left, &right, Mode::Hash)
    } else {
        bao_tree::blake3::Hash::from(merge_subtrees_non_root(&left, &right, Mode::Hash))
    }
}

fn parse_hash_pair(pair: &[u8; 64]) -> (bao_tree::blake3::Hash, bao_tree::blake3::Hash) {
    let mut left = [0u8; 32];
    let mut right = [0u8; 32];
    left.copy_from_slice(&pair[..32]);
    right.copy_from_slice(&pair[32..]);
    (
        bao_tree::blake3::Hash::from(left),
        bao_tree::blake3::Hash::from(right),
    )
}

fn encoded_leaf(raw: &[u8], level: i32, mut framed: Vec<u8>) -> io::Result<Vec<u8>> {
    framed.clear();
    framed.extend_from_slice(&[0u8; 4]);
    let mut encoder = StreamingZstdEncoder::new(level, Some(raw.len() as u64))?;
    encoder.compress_block(raw, &mut framed)?;
    encoder.finish(&mut framed)?;
    let encoded_len = framed
        .len()
        .checked_sub(4)
        .ok_or_else(|| io::Error::other("zstd leaf framing lost its fixed length prefix"))?;
    if encoded_len > MAX_ENCODED_LEAF_BYTES {
        return Err(io::Error::other(format!(
            "zstd encoded leaf was {encoded_len} B, over fixed {MAX_ENCODED_LEAF_BYTES} B bound"
        )));
    }
    let encoded_len = u32::try_from(encoded_len)
        .map_err(|_| io::Error::other("encoded leaf length does not fit u32"))?;
    framed[..4].copy_from_slice(&encoded_len.to_le_bytes());
    Ok(framed)
}

/// Validate full-range pass-2 data against `outboard` and transfer owned leaf
/// allocations to `writer`. This is deliberately the full-range subset of
/// Bao's preorder algorithm: it retains only the authentication stack, one
/// raw leaf, one encoded leaf, and bounded codec scratch. Keeping ownership at
/// this seam avoids the extra `Write::write_all(&[u8]) -> Vec` copy that would
/// otherwise defeat the transport's leaf-count memory bound.
pub(crate) fn encode_validated<D: ReadAt, O: Outboard, W: OwnedWireSink>(
    data: D,
    outboard: O,
    mut writer: W,
    codec: WireCodec,
    level: i32,
) -> io::Result<(W, u64, u64)> {
    let tree = outboard.tree();
    let mut expected = vec![outboard.root()];
    let mut raw = Vec::with_capacity(BAO_BLOCK_SIZE.bytes());
    let mut framed = Vec::with_capacity(MAX_ENCODED_LEAF_BYTES + 4);
    let mut proof = Vec::with_capacity(64);
    let mut raw_bytes = 0u64;
    let mut wire_bytes = 0u64;

    for item in ResponseIter::new(tree, ChunkRanges::all()) {
        match item {
            BaoChunk::Parent {
                node,
                is_root,
                left,
                right,
                ..
            } => {
                let (left_hash, right_hash) = outboard.load(node)?.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Bao outboard omitted parent {node:?}"),
                    )
                })?;
                let wanted = expected.pop().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "Bao proof stack underflow")
                })?;
                if parent_hash(&left_hash, &right_hash, is_root) != wanted {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Bao parent hash mismatch at {node:?}"),
                    ));
                }
                if right {
                    expected.push(right_hash);
                }
                if left {
                    expected.push(left_hash);
                }
                proof.clear();
                proof.extend_from_slice(left_hash.as_bytes());
                proof.extend_from_slice(right_hash.as_bytes());
                let next_wire_bytes =
                    checked_add_bytes(wire_bytes, proof.len(), "Bao proof wire byte count")?;
                proof = writer.write_owned(proof)?;
                wire_bytes = next_wire_bytes;
            }
            BaoChunk::Leaf {
                start_chunk,
                size,
                is_root,
                ..
            } => {
                raw.resize(size, 0);
                let start_byte = start_chunk.to_bytes();
                data.read_exact_at(start_byte, &mut raw)?;
                let wanted = expected.pop().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "Bao leaf stack underflow")
                })?;
                if hash_subtree(start_byte, &raw, is_root) != wanted {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Bao leaf hash mismatch at byte {start_byte}"),
                    ));
                }
                let next_raw_bytes =
                    checked_add_bytes(raw_bytes, raw.len(), "Bao authenticated raw byte count")?;
                match codec {
                    WireCodec::Raw => {
                        let next_wire_bytes =
                            checked_add_bytes(wire_bytes, raw.len(), "raw leaf wire byte count")?;
                        raw = writer.write_owned(raw)?;
                        wire_bytes = next_wire_bytes;
                    }
                    WireCodec::Zstd => {
                        framed = encoded_leaf(&raw, level, framed)?;
                        let next_wire_bytes = checked_add_bytes(
                            wire_bytes,
                            framed.len(),
                            "zstd leaf wire byte count",
                        )?;
                        framed = writer.write_owned(framed)?;
                        wire_bytes = next_wire_bytes;
                    }
                }
                raw_bytes = next_raw_bytes;
            }
        }
    }
    if !expected.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Bao traversal ended with unconsumed authentication hashes",
        ));
    }
    writer.flush()?;
    Ok((writer, raw_bytes, wire_bytes))
}

struct MonotonicReadAt<'a, R> {
    reader: RefCell<&'a mut R>,
    position: Cell<u64>,
}

impl<R: Read> ReadAt for MonotonicReadAt<'_, R> {
    fn read_at(&self, position: u64, buf: &mut [u8]) -> io::Result<usize> {
        let expected = self.position.get();
        if position != expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "full-range Bao replay requested non-monotonic offset {position}, expected {expected}"
                ),
            ));
        }
        let read = self.reader.borrow_mut().read(buf)?;
        let next = checked_add_bytes(expected, read, "monotonic Bao replay offset")?;
        self.position.set(next);
        Ok(read)
    }
}

/// Validate and frame a forward-only replay. Full-range preorder encoding reads
/// leaf data monotonically; this adapter asserts that property rather than
/// pretending the process stdout is seekable. It also consumes one byte past
/// the declared geometry to prove exact EOF.
pub(crate) fn encode_validated_reader<R, O, W>(
    reader: &mut R,
    outboard: O,
    writer: W,
    codec: WireCodec,
    level: i32,
) -> io::Result<(W, u64, u64)>
where
    R: Read,
    O: Outboard,
    W: OwnedWireSink,
{
    let raw_size = outboard.tree().size();
    let (result, consumed) = {
        let source = MonotonicReadAt {
            reader: RefCell::new(&mut *reader),
            position: Cell::new(0),
        };
        let result = encode_validated(&source, outboard, writer, codec, level)?;
        (result, source.position.get())
    };
    if consumed != raw_size {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("Bao replay consumed {consumed} B, expected {raw_size} B"),
        ));
    }
    let mut extra = [0u8; 1];
    if reader.read(&mut extra)? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Bao replay produced more than declared raw_size {raw_size}"),
        ));
    }
    Ok(result)
}

fn decode_error_to_io(error: DecodeError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

fn read_leaf<R: Read>(reader: &mut R, size: usize, codec: WireCodec) -> io::Result<Vec<u8>> {
    match codec {
        WireCodec::Raw => {
            let mut raw = vec![0u8; size];
            reader.read_exact(&mut raw).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("Bao verification: reading {size}-byte raw leaf: {error}"),
                )
            })?;
            Ok(raw)
        }
        WireCodec::Zstd => {
            let mut len = [0u8; 4];
            reader.read_exact(&mut len).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("Bao verification: reading zstd leaf length: {error}"),
                )
            })?;
            let encoded_len = u32::from_le_bytes(len) as usize;
            if encoded_len > MAX_ENCODED_LEAF_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "encoded leaf length {encoded_len} exceeds fixed bound {MAX_ENCODED_LEAF_BYTES}"
                    ),
                ));
            }
            let mut encoded = vec![0u8; encoded_len];
            reader.read_exact(&mut encoded).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("Bao verification: reading {encoded_len}-byte encoded leaf: {error}"),
                )
            })?;
            // Reject zstd skippable frames explicitly. For a geometry-valid
            // empty leaf, the bounded decoder reports EmptyNar; only a real
            // standard empty frame is accepted below.
            let skippable = encoded
                .get(..4)
                .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
                .map(u32::from_le_bytes)
                .is_some_and(|magic| (0x184D_2A50..=0x184D_2A5F).contains(&magic));
            if skippable {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "zstd skippable frame is not a NAR leaf",
                ));
            }
            let mut decoder =
                BoundedZstdDecoder::with_window_log_max(size as u64, leaf_window_log_max(size))
                    .map_err(decode_error_to_io)?;
            decoder.push(&encoded).map_err(decode_error_to_io)?;
            let raw = match decoder.finish() {
                Ok(raw) => raw,
                Err(DecodeError::EmptyNar) if size == 0 => Vec::new(),
                Err(error) => return Err(decode_error_to_io(error)),
            };
            if raw.len() != size {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "zstd leaf decoded to {} B, geometry requires {size} B",
                        raw.len()
                    ),
                ));
            }
            Ok(raw)
        }
    }
}

/// Verify every leaf and invoke `on_leaf` in order. The final leaf is retained
/// until COMPLETE and clean EOF have both been observed, so a valid Bao body
/// followed by process failure/trailing bytes cannot complete its consumer.
pub(crate) fn decode_verified<R, F>(
    reader: &mut R,
    root: bao_tree::blake3::Hash,
    raw_size: u64,
    codec: WireCodec,
    mut on_leaf: F,
) -> io::Result<u64>
where
    R: Read,
    F: FnMut(Bytes) -> io::Result<()>,
{
    let tree = BaoTree::new(raw_size, BAO_BLOCK_SIZE);
    let mut expected = vec![root];
    let mut final_leaf: Option<Bytes> = None;
    let mut raw_bytes = 0u64;

    for item in ResponseIter::new(tree, ChunkRanges::all()) {
        match item {
            BaoChunk::Parent {
                node,
                is_root,
                left,
                right,
                ..
            } => {
                let mut pair = [0u8; 64];
                reader.read_exact(&mut pair).map_err(|error| {
                    io::Error::new(
                        error.kind(),
                        format!("Bao verification: reading parent pair at {node:?}: {error}"),
                    )
                })?;
                let (left_hash, right_hash) = parse_hash_pair(&pair);
                let wanted = expected.pop().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "Bao proof stack underflow")
                })?;
                if parent_hash(&left_hash, &right_hash, is_root) != wanted {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Bao verification: parent hash mismatch at {node:?}"),
                    ));
                }
                if right {
                    expected.push(right_hash);
                }
                if left {
                    expected.push(left_hash);
                }
            }
            BaoChunk::Leaf {
                start_chunk,
                size,
                is_root,
                ..
            } => {
                let raw = read_leaf(reader, size, codec)?;
                let start_byte = start_chunk.to_bytes();
                let wanted = expected.pop().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "Bao leaf stack underflow")
                })?;
                if hash_subtree(start_byte, &raw, is_root) != wanted {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Bao verification: leaf hash mismatch at byte {start_byte}"),
                    ));
                }
                let next_raw_bytes =
                    checked_add_bytes(raw_bytes, raw.len(), "Bao verified raw byte count")?;
                if next_raw_bytes > raw_size {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "Bao verified raw byte count {next_raw_bytes} B exceeds declared raw_size {raw_size} B"
                        ),
                    ));
                }
                raw_bytes = next_raw_bytes;
                let leaf = Bytes::from(raw);
                if raw_bytes == raw_size {
                    final_leaf = Some(leaf);
                } else {
                    on_leaf(leaf)?;
                }
            }
        }
    }
    if !expected.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Bao traversal ended with unconsumed authentication hashes",
        ));
    }
    let mut marker = [0u8; COMPLETE_MARKER.len()];
    reader.read_exact(&mut marker)?;
    if &marker != COMPLETE_MARKER {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid /nar/4 COMPLETE marker {marker:?}"),
        ));
    }
    let mut trailing = [0u8; 1];
    if reader.read(&mut trailing)? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "trailing byte after /nar/4 COMPLETE marker",
        ));
    }
    if raw_bytes != raw_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("verified {raw_bytes} raw bytes, header declared {raw_size}"),
        ));
    }
    if let Some(final_leaf) = final_leaf {
        on_leaf(final_leaf)?;
    }
    Ok(raw_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deterministic_bytes(size: usize) -> Vec<u8> {
        let mut state = 0x9e37_79b9_u32 ^ size as u32;
        (0..size)
            .map(|_| {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (state >> 24) as u8
            })
            .collect()
    }

    fn encoded(raw: &[u8], codec: WireCodec) -> (PreOrderOutboard<Vec<u8>>, Vec<u8>) {
        let mut source = io::Cursor::new(raw);
        let outboard = create_outboard(&mut source, raw.len() as u64).unwrap();
        let mut body = Vec::new();
        encode_validated(raw, &outboard, &mut body, codec, 3).unwrap();
        (outboard, body)
    }

    #[test]
    fn byte_accounting_overflow_fails_with_context_before_state_advances() {
        assert_eq!(
            checked_add_bytes(u64::MAX - 1, 1, "test byte count").unwrap(),
            u64::MAX
        );
        let error = checked_add_bytes(u64::MAX, 1, "test byte count").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(
            error
                .to_string()
                .contains("test byte count overflow: 18446744073709551615 B + 1 B"),
            "context and both operands must survive: {error}"
        );

        let mut one_byte = io::Cursor::new([0x5au8]);
        let source = MonotonicReadAt {
            reader: RefCell::new(&mut one_byte),
            position: Cell::new(u64::MAX),
        };
        let error = source.read_at(u64::MAX, &mut [0u8; 1]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("monotonic Bao replay offset"));
        assert_eq!(
            source.position.get(),
            u64::MAX,
            "an overflow must not wrap or advance the replay position"
        );

        let body_error =
            NarV4WireAccounting::from_framed_bao_bytes(0, WireCodec::Zstd, u64::MAX).unwrap_err();
        assert!(body_error.to_string().contains("v4 body bytes overflow"));
        let exchange_error =
            NarV4WireAccounting::from_response_protocol_bytes(0, WireCodec::Zstd, u64::MAX)
                .unwrap_err();
        assert!(
            exchange_error
                .to_string()
                .contains("v4 exchange bytes overflow")
        );
    }

    #[test]
    fn owned_full_range_codec_matches_bao_tree_canonical_oracles() {
        const LEAF: usize = 64 * 1024;
        let mut sizes = vec![
            0,
            1,
            LEAF - 1,
            LEAF,
            LEAF + 1,
            (2 * LEAF) - 1,
            2 * LEAF,
            (2 * LEAF) + 1,
            (3 * LEAF) + 17,
            (5 * LEAF) + 123,
        ];
        // Exact powers of two exercise balanced trees; one byte beyond each
        // boundary creates the minimally uneven 9/17/33/65-leaf tree.
        for balanced_leaves in [8usize, 16, 32, 64] {
            sizes.push(balanced_leaves * LEAF);
            sizes.push((balanced_leaves * LEAF) + 1);
        }
        let mut state = 0x6a09_e667_u32;
        for _ in 0..12 {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            sizes.push((state as usize) % ((7 * LEAF) + 1));
        }

        for size in sizes {
            let raw = deterministic_bytes(size);
            let mut source = io::Cursor::new(&raw);
            let outboard = create_outboard(&mut source, size as u64).unwrap();
            let ranges = ChunkRanges::all();

            // Oracle 1: our owned-buffer raw encoder is byte-for-byte Bao's
            // canonical full-range preorder representation.
            let mut canonical = Vec::new();
            bao_tree::io::sync::encode_ranges_validated(
                &raw[..],
                &outboard,
                &ranges,
                &mut canonical,
            )
            .unwrap();
            let mut produced = Vec::new();
            let (_, raw_bytes, wire_bytes) =
                encode_validated(&raw[..], &outboard, &mut produced, WireCodec::Raw, 3).unwrap();
            assert_eq!(produced, canonical, "canonical bytes at size {size}");
            assert_eq!(raw_bytes, size as u64);
            assert_eq!(wire_bytes, canonical.len() as u64);

            // Oracle 2a: Bao's decoder accepts our canonical bytes and yields
            // exactly the source leaves under the outboard root.
            let mut bao_decoded = Vec::new();
            for item in bao_tree::io::sync::DecodeResponseIter::new(
                outboard.root,
                outboard.tree,
                &produced[..],
                &ranges,
            ) {
                if let bao_tree::io::BaoContentItem::Leaf(leaf) = item.unwrap() {
                    bao_decoded.extend_from_slice(&leaf.data);
                }
            }
            assert_eq!(
                bao_decoded, raw,
                "Bao decodes production bytes at size {size}"
            );

            // Oracle 2b: our decoder accepts Bao's canonical bytes and exposes
            // the exact source, including the terminally withheld last leaf.
            canonical.extend_from_slice(COMPLETE_MARKER);
            let mut ours_decoded = Vec::new();
            decode_verified(
                &mut io::Cursor::new(canonical),
                outboard.root,
                size as u64,
                WireCodec::Raw,
                |leaf| {
                    ours_decoded.extend_from_slice(&leaf);
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(
                ours_decoded, raw,
                "production decodes Bao bytes at size {size}"
            );

            // The outer `/nar/4` framing and direct verifier run over the same
            // boundary, uneven-tree, and deterministic-random axis for both
            // response-global codecs. Only Raw can be compared byte-for-byte
            // to Bao's canonical representation; zstd wraps each canonical
            // leaf in its independently bounded frame.
            for codec in [WireCodec::Raw, WireCodec::Zstd] {
                let mut framed = Vec::new();
                encode_validated(&raw[..], &outboard, &mut framed, codec, 3).unwrap();
                framed.extend_from_slice(COMPLETE_MARKER);
                let mut decoded = Vec::new();
                decode_verified(
                    &mut io::Cursor::new(framed),
                    outboard.root,
                    size as u64,
                    codec,
                    |leaf| {
                        decoded.extend_from_slice(&leaf);
                        Ok(())
                    },
                )
                .unwrap();
                assert_eq!(decoded, raw, "{codec:?} outer round trip at size {size}");
            }

            // Both encoders and both decoders must also reject when the claimed
            // root is changed. This exercises empty, one-leaf, balanced, and
            // uneven authentication-stack shapes in both directions.
            let mut wrong_root = outboard.clone();
            wrong_root.root = bao_tree::blake3::hash(b"not the source root");
            let mut upstream_wrong = Vec::new();
            assert!(
                bao_tree::io::sync::encode_ranges_validated(
                    &raw[..],
                    &wrong_root,
                    &ranges,
                    &mut upstream_wrong,
                )
                .is_err(),
                "Bao oracle accepts wrong root at size {size}"
            );
            let mut ours_wrong = Vec::new();
            assert!(
                encode_validated(&raw[..], &wrong_root, &mut ours_wrong, WireCodec::Raw, 3,)
                    .is_err(),
                "production accepts wrong root at size {size}"
            );
            assert!(
                bao_tree::io::sync::DecodeResponseIter::new(
                    wrong_root.root,
                    outboard.tree,
                    &produced[..],
                    &ranges,
                )
                .any(|item| item.is_err()),
                "Bao decoder accepts production bytes under wrong root at size {size}"
            );
            let mut wrong_root_wire = produced.clone();
            wrong_root_wire.extend_from_slice(COMPLETE_MARKER);
            assert!(
                decode_verified(
                    &mut io::Cursor::new(wrong_root_wire),
                    wrong_root.root,
                    size as u64,
                    WireCodec::Raw,
                    |_| Ok(()),
                )
                .is_err(),
                "production decoder accepts Bao bytes under wrong root at size {size}"
            );
        }
    }

    #[test]
    fn exact_wire_accounting_holds_at_leaf_boundaries_for_both_codecs() {
        for size in [0usize, 1, 65_535, 65_536, 65_537] {
            let raw = (0..size).map(|index| index as u8).collect::<Vec<_>>();
            for codec in [WireCodec::Raw, WireCodec::Zstd] {
                let (outboard, framed) = encoded(&raw, codec);
                let accounting = NarV4WireAccounting::from_framed_bao_bytes(
                    size as u64,
                    codec,
                    framed.len() as u64,
                )
                .unwrap();
                assert_eq!(accounting.request_protocol_bytes, 33);
                assert_eq!(accounting.response_header_bytes, 10);
                assert_eq!(accounting.proof_bytes, outboard.data.len() as u64);
                assert_eq!(accounting.leaf_count, (size as u64).div_ceil(65_536).max(1));
                assert_eq!(
                    accounting.leaf_length_prefix_bytes,
                    if codec == WireCodec::Zstd {
                        4 * accounting.leaf_count
                    } else {
                        0
                    }
                );
                if codec == WireCodec::Raw {
                    assert_eq!(accounting.encoded_leaf_bytes, size as u64);
                }
                assert_eq!(accounting.complete_marker_bytes, 4);
                assert_eq!(
                    accounting.response_body_bytes,
                    framed.len() as u64 + COMPLETE_MARKER.len() as u64
                );
                assert_eq!(
                    accounting.response_protocol_bytes,
                    10 + accounting.response_body_bytes
                );
                assert_eq!(
                    accounting.exchange_protocol_bytes,
                    33 + accounting.response_protocol_bytes
                );
                assert_eq!(
                    NarV4WireAccounting::from_response_protocol_bytes(
                        size as u64,
                        codec,
                        accounting.response_protocol_bytes,
                    )
                    .unwrap(),
                    accounting
                );
            }
        }
    }

    fn decode_fails(
        body: Vec<u8>,
        root: bao_tree::blake3::Hash,
        raw_size: u64,
        codec: WireCodec,
    ) -> io::Error {
        decode_verified(
            &mut io::Cursor::new(body),
            root,
            raw_size,
            codec,
            |_| Ok(()),
        )
        .unwrap_err()
    }

    fn raw_leaf_ranges(raw_size: u64) -> Vec<std::ops::Range<usize>> {
        let tree = BaoTree::new(raw_size, BAO_BLOCK_SIZE);
        let mut offset = 0usize;
        let mut leaves = Vec::new();
        for item in body_items(tree) {
            match item {
                BodyItem::Parent => offset += 64,
                BodyItem::Leaf(size) => {
                    leaves.push(offset..offset + size);
                    offset += size;
                }
            }
        }
        leaves
    }

    fn framed_leaf_ranges(
        raw_size: u64,
        codec: WireCodec,
        body: &[u8],
    ) -> Vec<std::ops::Range<usize>> {
        let tree = BaoTree::new(raw_size, BAO_BLOCK_SIZE);
        let mut offset = 0usize;
        let mut leaves = Vec::new();
        for item in body_items(tree) {
            match item {
                BodyItem::Parent => offset += 64,
                BodyItem::Leaf(size) => match codec {
                    WireCodec::Raw => {
                        leaves.push(offset..offset + size);
                        offset += size;
                    }
                    WireCodec::Zstd => {
                        let encoded =
                            u32::from_le_bytes(body[offset..offset + 4].try_into().unwrap())
                                as usize;
                        leaves.push(offset..offset + 4 + encoded);
                        offset += 4 + encoded;
                    }
                },
            }
        }
        leaves
    }

    fn round_trip(raw: &[u8], codec: WireCodec) -> io::Result<Vec<u8>> {
        let mut source = io::Cursor::new(raw);
        let outboard = create_outboard(&mut source, raw.len() as u64)?;
        let mut body = Vec::new();
        let (_writer, encoded_raw, _wire) = encode_validated(raw, &outboard, &mut body, codec, 3)?;
        assert_eq!(encoded_raw, raw.len() as u64);
        body.extend_from_slice(COMPLETE_MARKER);
        let mut decoded = Vec::new();
        decode_verified(
            &mut io::Cursor::new(body),
            outboard.root,
            raw.len() as u64,
            codec,
            |leaf| {
                decoded.extend_from_slice(&leaf);
                Ok(())
            },
        )?;
        Ok(decoded)
    }

    #[test]
    fn boundary_round_trips_are_codec_identical() {
        const LEAF: usize = 64 * 1024;
        for len in [
            0,
            1,
            LEAF - 1,
            LEAF,
            LEAF + 1,
            (2 * LEAF) - 1,
            2 * LEAF,
            (2 * LEAF) + 1,
            (3 * LEAF) + 17,
            (5 * LEAF) + 123,
        ] {
            let raw = (0..len).map(|index| index as u8).collect::<Vec<_>>();
            assert_eq!(round_trip(&raw, WireCodec::Raw).unwrap(), raw);
            assert_eq!(round_trip(&raw, WireCodec::Zstd).unwrap(), raw);
        }
    }

    #[test]
    fn bad_content_fails_before_changed_leaf_is_exposed() {
        let raw = vec![7u8; (64 * 1024) + 1];
        let mut source = io::Cursor::new(&raw);
        let outboard = create_outboard(&mut source, raw.len() as u64).unwrap();
        let mut body = Vec::new();
        encode_validated(&raw[..], &outboard, &mut body, WireCodec::Raw, 3).unwrap();
        body[64] ^= 1; // first leaf follows the root parent pair
        body.extend_from_slice(COMPLETE_MARKER);
        let mut exposed = Vec::new();
        let error = decode_verified(
            &mut io::Cursor::new(body),
            outboard.root,
            raw.len() as u64,
            WireCodec::Raw,
            |leaf| {
                exposed.push(leaf);
                Ok(())
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("Bao verification"), "{error}");
        assert!(exposed.is_empty());
    }

    #[test]
    fn proof_mutation_fails_before_any_leaf_is_exposed() {
        let raw = vec![3u8; (64 * 1024) + 1];
        let (outboard, mut body) = encoded(&raw, WireCodec::Raw);
        body[0] ^= 1;
        body.extend_from_slice(COMPLETE_MARKER);
        let mut exposed = Vec::new();
        let error = decode_verified(
            &mut io::Cursor::new(body),
            outboard.root,
            raw.len() as u64,
            WireCodec::Raw,
            |leaf| {
                exposed.push(leaf);
                Ok(())
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("Bao verification"), "{error}");
        assert!(exposed.is_empty());
    }

    #[test]
    fn duplicated_or_reordered_raw_leaves_fail_authentication() {
        let raw = (0..(3 * 64 * 1024))
            .map(|index| (index / (64 * 1024)) as u8)
            .collect::<Vec<_>>();
        let (outboard, body) = encoded(&raw, WireCodec::Raw);
        let leaves = raw_leaf_ranges(raw.len() as u64);
        assert!(leaves.len() >= 3);
        assert_eq!(leaves[0].len(), leaves[1].len());

        let mut duplicated = body.clone();
        let first = body[leaves[0].clone()].to_vec();
        duplicated[leaves[1].clone()].copy_from_slice(&first);
        duplicated.extend_from_slice(COMPLETE_MARKER);
        assert!(
            decode_fails(duplicated, outboard.root, raw.len() as u64, WireCodec::Raw,)
                .to_string()
                .contains("Bao verification")
        );

        let mut reordered = body;
        let first = reordered[leaves[0].clone()].to_vec();
        let second = reordered[leaves[1].clone()].to_vec();
        reordered[leaves[0].clone()].copy_from_slice(&second);
        reordered[leaves[1].clone()].copy_from_slice(&first);
        reordered.extend_from_slice(COMPLETE_MARKER);
        assert!(
            decode_fails(reordered, outboard.root, raw.len() as u64, WireCodec::Raw,)
                .to_string()
                .contains("Bao verification")
        );
    }

    #[test]
    fn late_leaf_mutations_expose_only_authenticated_prefix_for_raw_and_zstd() {
        let raw = (0..(3 * 64 * 1024))
            .map(|index| (index / (64 * 1024)) as u8)
            .collect::<Vec<_>>();
        for codec in [WireCodec::Raw, WireCodec::Zstd] {
            let (outboard, body) = encoded(&raw, codec);
            let leaves = framed_leaf_ranges(raw.len() as u64, codec, &body);
            assert_eq!(leaves.len(), 3);
            assert_eq!(leaves[1].len(), leaves[2].len());

            let mut mutations = Vec::new();
            let mut corrupt = body.clone();
            let corrupt_at = match codec {
                WireCodec::Raw => leaves[1].start,
                WireCodec::Zstd => leaves[1].start + 4,
            };
            corrupt[corrupt_at] ^= 1;
            mutations.push(("corrupt", corrupt));

            let mut duplicated = body.clone();
            let first = body[leaves[0].clone()].to_vec();
            duplicated.splice(leaves[1].clone(), first);
            mutations.push(("duplicated", duplicated));

            let mut reordered = body.clone();
            let second = body[leaves[1].clone()].to_vec();
            let third = body[leaves[2].clone()].to_vec();
            reordered[leaves[1].clone()].copy_from_slice(&third);
            reordered[leaves[2].clone()].copy_from_slice(&second);
            mutations.push(("reordered", reordered));

            for (mutation, mut mutated) in mutations {
                mutated.extend_from_slice(COMPLETE_MARKER);
                let mut exposed = Vec::new();
                let error = decode_verified(
                    &mut io::Cursor::new(mutated),
                    outboard.root,
                    raw.len() as u64,
                    codec,
                    |leaf| {
                        exposed.push(leaf);
                        Ok(())
                    },
                )
                .expect_err("late mutation must fail");
                assert_eq!(
                    exposed.len(),
                    1,
                    "{codec:?} {mutation}: only leaf1 may cross before leaf2 fails: {error}"
                );
                assert_eq!(
                    &exposed[0][..],
                    &raw[..64 * 1024],
                    "{codec:?} {mutation}: exposed prefix is the authenticated first leaf"
                );
            }
        }
    }

    #[test]
    fn wrong_raw_size_and_truncated_body_fail_closed() {
        let raw = vec![4u8; (64 * 1024) + 7];
        let (outboard, mut body) = encoded(&raw, WireCodec::Raw);
        body.extend_from_slice(COMPLETE_MARKER);
        assert!(
            decode_fails(
                body.clone(),
                outboard.root,
                raw.len() as u64 + 1,
                WireCodec::Raw,
            )
            .to_string()
            .contains("Bao")
        );

        body.truncate(body.len() - COMPLETE_MARKER.len() - 1);
        assert!(
            decode_fails(body, outboard.root, raw.len() as u64, WireCodec::Raw,)
                .to_string()
                .contains("Bao")
        );
    }

    #[test]
    fn oversized_zstd_leaf_length_is_rejected_before_allocation() {
        let raw = vec![5u8; 128];
        let (outboard, mut body) = encoded(&raw, WireCodec::Zstd);
        body[..4].copy_from_slice(&((MAX_ENCODED_LEAF_BYTES as u32) + 1).to_le_bytes());
        let error = decode_fails(body, outboard.root, raw.len() as u64, WireCodec::Zstd);
        assert!(error.to_string().contains("exceeds fixed bound"), "{error}");
    }

    #[test]
    fn zstd_bomb_and_trailing_frame_fail_at_the_leaf_codec() {
        let raw = vec![6u8; 32];
        let (outboard, _) = encoded(&raw, WireCodec::Zstd);

        let bomb = compress_zstd(&vec![0u8; 64 * 1024], 3).unwrap();
        let mut bomb_body = (bomb.len() as u32).to_le_bytes().to_vec();
        bomb_body.extend_from_slice(&bomb);
        bomb_body.extend_from_slice(COMPLETE_MARKER);
        let error = decode_fails(bomb_body, outboard.root, raw.len() as u64, WireCodec::Zstd);
        assert!(error.to_string().contains("decompression bomb"), "{error}");

        let mut two_frames = compress_zstd(&raw, 3).unwrap();
        two_frames.extend_from_slice(&compress_zstd(b"trailing", 3).unwrap());
        let mut trailing_body = (two_frames.len() as u32).to_le_bytes().to_vec();
        trailing_body.extend_from_slice(&two_frames);
        trailing_body.extend_from_slice(COMPLETE_MARKER);
        let error = decode_fails(
            trailing_body,
            outboard.root,
            raw.len() as u64,
            WireCodec::Zstd,
        );
        assert!(error.to_string().contains("trailing"), "{error}");
    }

    #[test]
    fn zstd_leaf_window_is_bounded_by_leaf_geometry() {
        let raw = (0..64 * 1024).map(|index| index as u8).collect::<Vec<_>>();
        let (outboard, _) = encoded(&raw, WireCodec::Zstd);
        let mut encoder = peer_fabric::StreamingZstdEncoder::new(3, None).unwrap();
        let mut wide_window_frame = Vec::new();
        encoder
            .compress_block(&raw, &mut wide_window_frame)
            .unwrap();
        encoder.finish(&mut wide_window_frame).unwrap();
        assert!(wide_window_frame.len() <= MAX_ENCODED_LEAF_BYTES);

        let mut body = (wide_window_frame.len() as u32).to_le_bytes().to_vec();
        body.extend_from_slice(&wide_window_frame);
        body.extend_from_slice(COMPLETE_MARKER);
        let error = decode_fails(body, outboard.root, raw.len() as u64, WireCodec::Zstd);
        assert!(
            error.to_string().contains("too much memory"),
            "geometry-tight window ceiling did not bite: {error}"
        );

        let mut loose = BoundedZstdDecoder::new(raw.len() as u64).unwrap();
        loose.push(&wide_window_frame).unwrap();
        assert_eq!(
            loose.finish().unwrap(),
            raw,
            "the same frame is valid when the geometry-tight window ceiling is absent"
        );
    }

    #[test]
    fn terminal_marker_and_clean_eof_are_mandatory() {
        let raw = vec![9u8; 32];
        let mut source = io::Cursor::new(&raw);
        let outboard = create_outboard(&mut source, raw.len() as u64).unwrap();
        let mut body = Vec::new();
        encode_validated(&raw[..], &outboard, &mut body, WireCodec::Raw, 3).unwrap();
        let mut exposed = Vec::new();
        assert!(
            decode_verified(
                &mut io::Cursor::new(body.clone()),
                outboard.root,
                raw.len() as u64,
                WireCodec::Raw,
                |leaf| {
                    exposed.push(leaf);
                    Ok(())
                },
            )
            .is_err()
        );
        assert!(exposed.is_empty(), "final leaf must be withheld");

        body.extend_from_slice(COMPLETE_MARKER);
        body.push(0);
        assert!(
            decode_verified(
                &mut io::Cursor::new(body),
                outboard.root,
                raw.len() as u64,
                WireCodec::Raw,
                |_| Ok(()),
            )
            .is_err()
        );
    }
}
