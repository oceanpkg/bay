//! The [SHA-256] hashing algorithm.
//!
//! [SHA-256]: https://en.wikipedia.org/wiki/SHA-2

use crate::hash::util::HexByte;
use sha2::digest::{FixedOutput, Input};
use std::{
    cmp,
    convert::{TryFrom, TryInto},
    error, fmt, io, str,
};

/// The byte array type.
pub type Bytes = [u8; Sha256::SIZE];

/// The buffer type for writing the hex representation.
pub type HexBuf = [u8; Sha256::HEX_SIZE];

/// A [SHA-256] hash.
///
/// [SHA-256]: https://en.wikipedia.org/wiki/SHA-2
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
// Exposing the entire inner byte array is fine since any 256-bit value is a
// SHA-256 hash.
pub struct Sha256(pub Bytes);

impl Default for Sha256 {
    #[inline]
    fn default() -> Self {
        sha2::Sha256::default().into()
    }
}

impl From<sha2::Sha256> for Sha256 {
    #[inline]
    fn from(s: sha2::Sha256) -> Self {
        Self(s.fixed_result().into())
    }
}

impl TryFrom<&str> for Sha256 {
    type Error = ParseError;

    #[inline]
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl TryFrom<&[u8]> for Sha256 {
    type Error = ParseError;

    fn try_from(hash: &[u8]) -> Result<Self, Self::Error> {
        use cmp::Ordering::*;

        let required_len = Self::HEX_SIZE;
        let hash_len = hash.len();

        match hash_len.cmp(&required_len) {
            Greater => Err(ParseError::TooLong {
                excess_len: hash_len - required_len,
            }),
            Less => Err(ParseError::TooShort {
                remaining_len: required_len - hash_len,
            }),
            Equal => {
                let mut result = Sha256([0; Self::SIZE]);
                let hash = unsafe { &*(hash as *const [u8] as *const HexBuf) };
                let get_nibble = |offset: usize| -> Result<u8, ParseError> {
                    match hash[offset] | 32 {
                        n @ b'a'..=b'z' => Ok(n - b'a' + 0xa),
                        n @ b'0'..=b'9' => Ok(n - b'0'),
                        _ => Err(ParseError::InvalidChar { offset }),
                    }
                };
                for s in 0..Self::SIZE {
                    let i = s * 2;
                    let j = i + 1;
                    result.0[s] = (get_nibble(i)? << 4) | get_nibble(j)?;
                }
                Ok(result)
            }
        }
    }
}

impl str::FromStr for Sha256 {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.as_bytes().try_into()
    }
}

impl fmt::Debug for Sha256 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("Sha256")
            .field(&HexByte::slice(&self.0))
            .finish()
    }
}

impl fmt::Display for Sha256 {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(self, f)
    }
}

impl fmt::LowerHex for Sha256 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.with_hex(false, |hex| fmt::Display::fmt(hex, f))
    }
}

impl fmt::UpperHex for Sha256 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.with_hex(true, |hex| fmt::Display::fmt(hex, f))
    }
}

impl serde::Serialize for Sha256 {
    fn serialize<S>(&self, ser: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.with_hex(false, |hex| hex.serialize(ser))
    }
}

impl<'de> serde::Deserialize<'de> for Sha256 {
    fn deserialize<D>(de: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Sha256;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "a SHA-256 hash")
            }

            fn visit_str<E>(self, hash: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                hash.parse().map_err(E::custom)
            }
        }

        de.deserialize_str(Visitor)
    }
}

impl PartialEq<str> for Sha256 {
    #[inline]
    fn eq(&self, hash: &str) -> bool {
        self.eq_hex(hash)
    }
}

impl PartialEq<Sha256> for str {
    #[inline]
    fn eq(&self, hash: &Sha256) -> bool {
        hash == self
    }
}

impl Sha256 {
    /// The size of the hash in bytes.
    pub const SIZE: usize = 32;

    /// The size of the hash in bytes when represented as hexadecimal.
    pub const HEX_SIZE: usize = Self::SIZE * 2;

    /// The minimum possible hash.
    pub const MIN: Self = Self([0; Self::SIZE]);

    /// The maximum possible hash.
    pub const MAX: Self = Self([u8::max_value(); Self::SIZE]);

    /// Attempts to parse `hash` as a SHA-256 hash.
    #[inline]
    pub fn parse<H>(hash: H) -> Result<Self, ParseError>
    where
        H: TryInto<Self, Error = ParseError>,
    {
        hash.try_into()
    }

    /// Digests `data` as input and returns the computed hash.
    pub fn hash<B: AsRef<[u8]>>(data: B) -> Self {
        sha2::Sha256::default().chain(data).into()
    }

    /// Digests `reader` as input and returns the computed hash.
    pub fn hash_reader<R: io::Read>(mut reader: R) -> io::Result<(Self, u64)> {
        let mut sha256 = sha2::Sha256::default();
        let bytes_read = io::copy(&mut reader, &mut sha256)?;
        Ok((sha256.into(), bytes_read))
    }

    /// Returns whether the hexadecimal (base 16) representation of `self` is
    /// equal to `hash`.
    ///
    /// This comparison is case-insensitive.
    pub fn eq_hex<H: AsRef<[u8]>>(&self, hash: H) -> bool {
        // Monomorphization after cheap size check.
        //
        // This also ensures that no bounds checks are done on `hash` since its
        // size is known at compile-time.
        fn eq(sha256: &Sha256, hash: &HexBuf) -> bool {
            let hex_nibble = |n: u8| -> u8 {
                if n < 0xa {
                    n + b'0'
                } else {
                    n - 0xa + b'a'
                }
            };

            for i in 0..Sha256::SIZE {
                let byte = sha256.0[i];
                let h1 = hex_nibble(byte >> 4);
                let h2 = hex_nibble(byte & 0xf);

                let i = i * 2;
                let ne1 = (hash[i] | 32) ^ h1;
                let ne2 = (hash[i + 1] | 32) ^ h2;

                if ne1 | ne2 != 0 {
                    return false;
                }
            }

            true
        }

        let hash = hash.as_ref();
        if hash.len() == Self::HEX_SIZE {
            eq(self, unsafe { &*(hash.as_ptr() as *const HexBuf) })
        } else {
            false
        }
    }

    /// Writes the hexadecimal representation of `self` to `writer`.
    #[inline]
    pub fn write_hex<W: io::Write>(
        &self,
        uppercase: bool,
        mut writer: W,
    ) -> io::Result<()> {
        self.with_hex(uppercase, |hex| writer.write_all(hex.as_bytes()))
    }

    /// Writes the hexadecimal representation of `self` to `buf`, returning the
    /// resulting UTF-8 string.
    pub fn write_hex_buf<'b>(
        &self,
        uppercase: bool,
        buf: &'b mut HexBuf,
    ) -> &'b mut str {
        let uppercase = if uppercase { b'A' } else { b'a' };
        let hex_nibble = |n: u8| -> u8 {
            if n < 0xa {
                n + b'0'
            } else {
                n - 0xa + uppercase
            }
        };
        for i in 0..Self::SIZE {
            let byte = self.0[i];
            let h1 = hex_nibble(byte >> 4);
            let h2 = hex_nibble(byte & 0xf);

            let i = i * 2;
            buf[i] = h1;
            buf[i + 1] = h2;
        }
        // SAFETY: The above loop writes the string representation of all bytes
        // to `buf`. This operation overwrites all bytes in `buf`.
        unsafe { str::from_utf8_unchecked_mut(buf) }
    }

    /// Calls `f` with a temporary stack-allocated hexadecimal string
    /// representation of `self`.
    #[inline]
    pub fn with_hex<F, T>(&self, uppercase: bool, f: F) -> T
    where
        F: for<'a> FnOnce(&'a mut str) -> T,
    {
        f(self.write_hex_buf(uppercase, &mut [0; Sha256::HEX_SIZE]))
    }
}

/// Indicates [`Sha256::parse`](struct.Sha256.html#method.parse) failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// An invalid character was found.
    InvalidChar {
        /// The offset from 0 where the invalid character was found.
        offset: usize,
    },
    /// The input string was too short.
    TooShort {
        /// The number of bytes that need to be appended in order to be the
        /// correct size.
        remaining_len: usize,
    },
    /// The input string was too long.
    TooLong {
        /// The number of bytes that need to be removed in order to be the
        /// correct size.
        excess_len: usize,
    },
}

impl fmt::Display for ParseError {
    #[rustfmt::skip] // Keeps branch style consistent.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ParseError::InvalidChar { offset } => write!(
                f,
                "SHA-256 hash has an invalid character at byte offset {}",
                offset,
            ),
            ParseError::TooShort { remaining_len } => write!(
                f,
                "SHA-256 hash too short by {} characters",
                remaining_len,
            ),
            ParseError::TooLong { excess_len } => write!(
                f,
                "SHA-256 hash too long by {} characters",
                excess_len,
            ),
        }
    }
}

impl error::Error for ParseError {}

#[cfg(test)]
mod tests {
    use super::*;

    // Simple sanity check to make sure it actually works.
    #[test]
    fn hash_name() {
        let name = "Nikolai Vazquez";
        let hash = "aee72bc3a1e741a4544832c0d99fa40b\
                    e0e2f3377b2f444c8b7de2597732463f";

        let sha = Sha256::hash(name);

        for &hash in [hash, &hash.to_uppercase()].iter() {
            assert_eq!(sha, *hash);
            assert_eq!(Sha256::try_from(hash).as_ref(), Ok(&sha));
        }
    }

    #[test]
    fn eq_hex() {
        for sha in [Sha256::MIN, Sha256::MAX].iter() {
            for &uppercase in [false, true].iter() {
                sha.with_hex(uppercase, |hex| assert_eq!(sha, hex));
            }
        }
    }
}

#[cfg(all(test, has_features))]
mod benches {
    use super::*;

    #[rustfmt::skip] // Easier to read this way.
    const SEQ: Sha256 = Sha256([
        00, 01, 02, 03, 04, 05, 06, 07,
        08, 09, 10, 11, 12, 13, 14, 15,
        16, 17, 18, 19, 20, 21, 22, 23,
        24, 25, 26, 27, 28, 29, 30, 31,
    ]);

    #[inline(never)]
    fn black_box_with_hex(hash: &Sha256) {
        hash.with_hex(false, |hex| {
            test::black_box(hex);
        });
    }

    macro_rules! gen_with_hex {
        ($($name:ident, $hash:expr, $iter:expr;)+) => {
            $(
                #[bench]
                fn $name(b: &mut test::Bencher) {
                    let hash = test::black_box($hash);
                    b.iter(|| {
                        for _ in 0..$iter {
                            black_box_with_hex(test::black_box(&hash));
                        }
                    });
                }
            )+
        };
    }

    gen_with_hex! {
        with_hex_seq_10,   SEQ, 10;
        with_hex_seq_100,  SEQ, 100;
        with_hex_seq_1000, SEQ, 1000;

        with_hex_max_10,   Sha256::MAX, 10;
        with_hex_max_100,  Sha256::MAX, 100;
        with_hex_max_1000, Sha256::MAX, 1000;
    }

    #[inline(never)]
    fn black_box_eq_hex(hash: &Sha256, hex: &[u8]) {
        test::black_box(hash.eq_hex(hex));
    }

    macro_rules! gen_eq_hex {
        ($($name:ident, $hash:expr, $iter:expr;)+) => {
            $(
                #[bench]
                fn $name(b: &mut test::Bencher) {
                    let hash = test::black_box($hash);
                    let hex  = test::black_box(hash.to_string());
                    b.iter(|| {
                        for _ in 0..$iter {
                            black_box_eq_hex(
                                &hash,
                                test::black_box(hex.as_bytes()),
                            );
                        }
                    });
                }
            )+
        };
    }

    gen_eq_hex! {
        eq_hex_seq_10,   SEQ, 10;
        eq_hex_seq_100,  SEQ, 100;
        eq_hex_seq_1000, SEQ, 1000;

        eq_hex_max_10,   Sha256::MAX, 10;
        eq_hex_max_100,  Sha256::MAX, 100;
        eq_hex_max_1000, Sha256::MAX, 1000;
    }
}
