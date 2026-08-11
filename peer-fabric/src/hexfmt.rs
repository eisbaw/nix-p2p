//! Lowercase-hex codec for the fixed-width byte identities the seam names.
//!
//! The canonical string form of every 32-byte identity here - the raw-NAR
//! [`crate::Blake3Digest`], the [`crate::NodeId`], a v2 BitTorrent infohash - is
//! lowercase hex. This is the SAME frozen codec the daemon pinned in its
//! `hexfmt` module (task-48): hex is reproducible by any second implementation
//! with no shared table (`b3sum` prints exactly this), fixed-width so a length
//! check alone rejects a truncated value, and independent of any transport
//! crate's `Display`. TASK-141 moved the value types here (their canonical home),
//! so their codec moved with them.
//!
//! FROZEN RULE: the canonical encoding is LOWERCASE hex, and decode REJECTS
//! uppercase - exactly one string encodes each value, so a byte-for-byte wire
//! comparison is exact. Kept tiny and dependency-free on purpose; `pub(crate)` -
//! an encoding utility, not part of the seam's public API.

/// Encode bytes as lowercase hex (2 chars per byte, no separators). Lowercase by
/// construction, so the canonical string form of every identity is unambiguous.
pub(crate) fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit((byte >> 4) as u32, 16).expect("high nibble is 0..16"));
        out.push(char::from_digit((byte & 0x0f) as u32, 16).expect("low nibble is 0..16"));
    }
    out
}

/// Why a hex string was not a valid encoding of `expected_len` bytes. Fail fast
/// and verbosely: the caller (and a log line) can tell a wrong length from a
/// stray non-hex character.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HexError {
    /// The string was not exactly `2 * expected_len` characters.
    WrongLength { expected_chars: usize, found: usize },
    /// A character outside `[0-9a-f]` appeared at `index`. Uppercase is
    /// deliberately rejected: the frozen canonical form is lowercase, so exactly
    /// one string encodes each value.
    NonHexChar { index: usize },
}

impl std::fmt::Display for HexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HexError::WrongLength {
                expected_chars,
                found,
            } => write!(f, "expected {expected_chars} hex characters, found {found}"),
            HexError::NonHexChar { index } => {
                write!(f, "non-hex character at index {index}")
            }
        }
    }
}

/// A single LOWERCASE hex nibble (`0-9a-f`). Uppercase returns `None` on purpose:
/// the frozen canonical form is lowercase, so decode is strict about it.
fn lower_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

/// Decode a LOWERCASE hex string into exactly `N` bytes. The length is checked
/// FIRST so a truncated identity is a clean `WrongLength`, never a silent partial
/// decode; uppercase is rejected as `NonHexChar` (frozen lowercase canonical).
pub(crate) fn decode_fixed<const N: usize>(hex: &str) -> Result<[u8; N], HexError> {
    if hex.len() != N * 2 {
        return Err(HexError::WrongLength {
            expected_chars: N * 2,
            found: hex.len(),
        });
    }
    let mut out = [0u8; N];
    let bytes = hex.as_bytes();
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = lower_nibble(bytes[i * 2]).ok_or(HexError::NonHexChar { index: i * 2 })?;
        let lo = lower_nibble(bytes[i * 2 + 1]).ok_or(HexError::NonHexChar { index: i * 2 + 1 })?;
        *slot = (hi << 4) | lo;
    }
    Ok(out)
}

/// Decode hex of an a-priori-unknown but restricted length (the BitTorrent
/// infohash, 20 or 32 bytes). Returns the raw bytes; the caller validates the
/// length against the forms it admits.
pub(crate) fn decode_var(hex: &str) -> Result<Vec<u8>, HexError> {
    if !hex.len().is_multiple_of(2) {
        return Err(HexError::WrongLength {
            expected_chars: hex.len() + 1,
            found: hex.len(),
        });
    }
    let bytes = hex.as_bytes();
    let mut out = Vec::with_capacity(hex.len() / 2);
    for i in 0..hex.len() / 2 {
        let hi = lower_nibble(bytes[i * 2]).ok_or(HexError::NonHexChar { index: i * 2 })?;
        let lo = lower_nibble(bytes[i * 2 + 1]).ok_or(HexError::NonHexChar { index: i * 2 + 1 })?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_fixed_width() {
        let bytes = [0x00, 0xff, 0x1a, 0xb3];
        let hex = encode(&bytes);
        assert_eq!(hex, "00ff1ab3");
        assert_eq!(decode_fixed::<4>(&hex).unwrap(), bytes);
    }

    #[test]
    fn rejects_wrong_length_before_content() {
        assert_eq!(
            decode_fixed::<32>("aa"),
            Err(HexError::WrongLength {
                expected_chars: 64,
                found: 2
            })
        );
    }

    #[test]
    fn rejects_non_hex_and_reports_a_non_zero_index() {
        // The only test pinning NonHexChar reporting at a NON-zero offset, so a
        // mutation to the `i*2` / `i*2+1` index arithmetic that every frozen
        // identity's FromStr routes through would be caught (not just a bad char
        // at index 0, which `rejects_uppercase_*` already covers).
        assert_eq!(
            decode_fixed::<2>("00zz"),
            Err(HexError::NonHexChar { index: 2 })
        );
        // decode_var walks the same index arithmetic; pin it at a non-zero offset.
        assert_eq!(decode_var("00zz"), Err(HexError::NonHexChar { index: 2 }));
    }

    #[test]
    fn rejects_uppercase_so_canonical_is_lowercase_only() {
        assert_eq!(
            decode_fixed::<2>("AABB"),
            Err(HexError::NonHexChar { index: 0 })
        );
        assert_eq!(decode_fixed::<2>("aabb").unwrap(), [0xaa, 0xbb]);
    }
}
