//! Nix's base-32 encoding - the canonical string form of a `NarHash` (task-48).
//!
//! Nix writes content hashes as `<algo>:<base32>` using its OWN base-32 alphabet
//! (`0123456789abcdfghijklmnpqrsvwxyz` - 32 chars, deliberately omitting `e o u t`
//! to avoid rendering rude words and ambiguous glyphs). This is NOT RFC 4648
//! base32, and NOT hex, so we cannot reuse a plain-hex codec (the lowercase-hex
//! codec for the fixed-width byte identities now lives in the `peer-fabric` seam
//! crate): a `NarHash` is the value Nix SIGNS and a narinfo carries verbatim, so
//! the claim wire key must be
//! byte-identical to what Nix produced. A sha256 is 32 bytes -> exactly 52 base-32
//! chars.
//!
//! The alphabet is entirely lowercase, so decode is lowercase-canonical for free:
//! an uppercase or otherwise off-alphabet character is simply not found and is
//! rejected. Decode also rejects a NON-CANONICAL final char (one whose high bits
//! spill past the 256th bit), so exactly one string encodes each digest - the
//! property a frozen interop key needs.
//!
//! `pub(crate)`: an encoding utility behind the frozen [`crate::claim::NarHashKey`],
//! not itself part of the public API.

/// Nix's base-32 alphabet (lowercase; omits `e o u t`).
const ALPHABET: &[u8; 32] = b"0123456789abcdfghijklmnpqrsvwxyz";

/// The base-32 string length for `byte_len` raw bytes (52 for a 32-byte sha256).
pub(crate) const fn encoded_len(byte_len: usize) -> usize {
    if byte_len == 0 {
        0
    } else {
        (byte_len * 8 - 1) / 5 + 1
    }
}

/// Encode raw bytes in Nix base-32 (the digits emitted high-to-low, matching
/// Nix's `printHash32`).
pub(crate) fn encode(bytes: &[u8]) -> String {
    let len = encoded_len(bytes.len());
    let mut out = String::with_capacity(len);
    for n in (0..len).rev() {
        let bit = n * 5;
        let i = bit / 8;
        let j = bit % 8;
        let here = (bytes[i] as u16) >> j;
        let next = if i + 1 < bytes.len() {
            (bytes[i + 1] as u16) << (8 - j)
        } else {
            0
        };
        out.push(ALPHABET[((here | next) & 0x1f) as usize] as char);
    }
    out
}

/// Why a string was not a canonical Nix base-32 encoding of `N` bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Base32Error {
    /// Not exactly `encoded_len(N)` characters.
    WrongLength { expected: usize, found: usize },
    /// A character outside Nix's base-32 alphabet at `index` (also catches
    /// uppercase, since the alphabet is lowercase).
    BadChar { index: usize },
    /// The final digit carried bits past the digest's last byte - a value that
    /// is well-formed base-32 but does NOT round-trip, so it is not canonical.
    NonCanonicalTail,
}

impl std::fmt::Display for Base32Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Base32Error::WrongLength { expected, found } => {
                write!(f, "expected {expected} base-32 characters, found {found}")
            }
            Base32Error::BadChar { index } => {
                write!(f, "non-base-32 character at index {index}")
            }
            Base32Error::NonCanonicalTail => {
                write!(
                    f,
                    "final base-32 digit is not canonical (spills past the digest)"
                )
            }
        }
    }
}

/// Decode a Nix base-32 string into exactly `N` bytes. Rejects wrong length,
/// off-alphabet characters, and a non-canonical tail.
pub(crate) fn decode_fixed<const N: usize>(s: &str) -> Result<[u8; N], Base32Error> {
    let expected = encoded_len(N);
    if s.len() != expected {
        return Err(Base32Error::WrongLength {
            expected,
            found: s.len(),
        });
    }
    let sb = s.as_bytes();
    let mut out = [0u8; N];
    for n in 0..s.len() {
        // Nix consumes the string in reverse: char at the end is the low digit.
        let c = sb[s.len() - n - 1];
        let digit = ALPHABET
            .iter()
            .position(|&a| a == c)
            .ok_or(Base32Error::BadChar {
                index: s.len() - n - 1,
            })? as u16;
        let bit = n * 5;
        let i = bit / 8;
        let j = bit % 8;
        out[i] |= (digit << j) as u8;
        let carry = digit >> (8 - j);
        if i + 1 < N {
            out[i + 1] |= carry as u8;
        } else if carry != 0 {
            return Err(Base32Error::NonCanonicalTail);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // A known Nix sha256 NarHash and its raw bytes (the task-48 `lib` fixture).
    // Pins the codec against Nix's own output, not against our own arithmetic.
    const KNOWN_B32: &str = "06rgb4vfjsg365xwwdjz12qhjnvg3w0agfvyqfp977hp3yk2bczb";
    const KNOWN_BYTES: [u8; 32] = [
        0xeb, 0xb3, 0x25, 0xa6, 0x1f, 0x17, 0x9e, 0x93, 0xae, 0xc3, 0x7e, 0xbb, 0xa7, 0x00, 0x1f,
        0x6f, 0x5b, 0x09, 0xb1, 0x08, 0x5f, 0x36, 0xce, 0x7b, 0x31, 0xe3, 0x69, 0xe9, 0x36, 0x59,
        0x2f, 0x1b,
    ];

    #[test]
    fn matches_nix_known_vector() {
        assert_eq!(encoded_len(32), 52);
        assert_eq!(encode(&KNOWN_BYTES), KNOWN_B32);
        assert_eq!(decode_fixed::<32>(KNOWN_B32).unwrap(), KNOWN_BYTES);
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(matches!(
            decode_fixed::<32>("abc"),
            Err(Base32Error::WrongLength { .. })
        ));
    }

    #[test]
    fn rejects_uppercase_and_off_alphabet() {
        // 'E' is uppercase; 'e' is not even in Nix's alphabet - both must fail.
        let mut chars: Vec<u8> = KNOWN_B32.bytes().collect();
        chars[10] = b'E';
        let s: String = chars.iter().map(|&b| b as char).collect();
        assert!(matches!(
            decode_fixed::<32>(&s),
            Err(Base32Error::BadChar { .. })
        ));
    }
}
