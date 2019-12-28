use std::{
    error::Error,
    fmt,
    iter,
    num::NonZeroUsize,
};
use super::{Hash, offset, range};

/// The error returned when decoding bytes into a [`Hash`] fails.
///
/// [`Hash`]: struct.Hash.html
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The provided bytes are too few to read the length.
    MissingDigestLen,
    /// The amount of bytes provided does not match the amount expected.
    LenMismatch {
        /// The exact amount of bytes that were expected.
        expected_len: usize,
        /// The actual amount of bytes that were provided.
        // Using `NonZeroUsize` makes the type's size be 2 words instead of 3.
        received_len: NonZeroUsize,
    },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::MissingDigestLen => write!(
                f,
                "hash too short to get the digest length",
            ),
            Self::LenMismatch { expected_len, received_len } => write!(
                f,
                "hash expected to be {} bytes but received {} instead",
                expected_len,
                received_len,
            ),
        }
    }
}

impl Error for DecodeError {}

/// The error returned when decoding bytes into a [`HashBuf`] fails.
///
/// [`HashBuf`]: struct.HashBuf.html
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodeBufError {
    /// The reason that `hash` is invalid.
    pub cause: DecodeError,
    /// The hash that could not represent a valid [`Hash`].
    ///
    /// [`Hash`]: struct.Hash.html
    pub hash: Vec<u8>,
}

impl fmt::Display for DecodeBufError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.cause.fmt(f)
    }
}

impl Error for DecodeBufError {
    #[inline]
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.cause)
    }
}

/// An iterator over contiguous [`Hash`]es in a slice of bytes.
///
/// See [`Hash::iter`] for more info.
///
/// [`Hash`]:       struct.Hash.html
/// [`Hash::iter`]: struct.Hash.html#method.iter
#[derive(Clone)]
pub struct DecodeIter<'a> {
    pub(crate) hashes: &'a [u8],
}

impl<'a> Iterator for DecodeIter<'a> {
    type Item = Result<&'a Hash, DecodeError>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let received_len = NonZeroUsize::new(self.hashes.len())?;

        let digest_len = match self.hashes.get(range::DIGEST_LEN) {
            Some(bytes) => unsafe {
                u16::from_le_bytes(*bytes.as_ptr().cast()) as usize
            },
            None => {
                // Make next iteration be `None` to prevent an infinite loop.
                self.hashes = Default::default();
                return Some(Err(DecodeError::MissingDigestLen));
            },
        };

        let expected_len = offset::PAYLOAD + digest_len;

        match self.hashes.get(..expected_len) {
            Some(hash) => {
                self.hashes = &self.hashes[expected_len..];
                Some(Ok(unsafe { Hash::new_unchecked(hash) }))
            },
            None => {
                // Make next iteration be `None` to prevent an infinite loop.
                self.hashes = Default::default();
                Some(Err(DecodeError::LenMismatch {
                    expected_len,
                    received_len,
                }))
            },
        }
    }
}

impl iter::FusedIterator for DecodeIter<'_> {}

/// An iterator over contiguous [`Hash`]es in a slice of bytes that doesn't
/// perform any safety checks.
///
/// See [`Hash::iter_unchecked`] for more info.
///
/// [`Hash`]:                 struct.Hash.html
/// [`Hash::iter_unchecked`]: struct.Hash.html#method.iter_unchecked
#[derive(Clone)]
pub struct DecodeUncheckedIter<'a> {
    pub(crate) hashes: &'a [u8],
}

impl<'a> Iterator for DecodeUncheckedIter<'a> {
    type Item = &'a Hash;

    fn next(&mut self) -> Option<Self::Item> {
        if self.hashes.is_empty() {
            return None;
        }
        unsafe {
            let hash = Hash::new_unchecked(self.hashes);
            self.hashes = self.hashes.get_unchecked(hash.len()..);
            Some(hash)
        }
    }
}

impl iter::FusedIterator for DecodeUncheckedIter<'_> {}
