//! Hashing algorithms.

use std::{
    borrow::Borrow,
    cmp,
    fmt,
    mem,
    num::NonZeroUsize,
    ops,
    ptr,
    slice,
};

pub mod algorithm;
mod decode;
mod util;

mod size {
    use super::*;

    pub const ALGORITHM: usize = 1;
    pub const DIGEST_LEN: usize = mem::size_of::<u16>();
    pub const PTR: usize = mem::size_of::<usize>();

    /// The maximum length allowed for storing the digest in `HashBuf`'s bit
    /// pattern directly.
    pub const INLINE_DIGEST: usize = Algorithm::MAX_SIZE;

    pub const INLINE_HASH: usize = offset::PAYLOAD + INLINE_DIGEST;
}

mod offset {
    use super::*;

    pub const ALGORITHM: usize = 0;
    pub const DIGEST_LEN: usize = ALGORITHM + size::ALGORITHM;

    /// The offset of either:
    ///
    /// - The inline digest.
    ///
    /// - The pointer to a `Hash` with a digest larger than what can be inlined.
    ///   This means the hash is from a newer version of Bay than what is
    ///   currently running.
    pub const PAYLOAD: usize = DIGEST_LEN + size::DIGEST_LEN;

    /// The capacity offset when `HashBuf` is represented by a `Vec<u8>`.
    pub const CAPACITY: usize = PAYLOAD + size::PTR;
}

mod range {
    use super::*;

    pub const DIGEST_LEN: ops::Range<usize>
        = offset::DIGEST_LEN..(offset::DIGEST_LEN + size::DIGEST_LEN);
}

#[doc(inline)]
pub use self::{
    algorithm::Algorithm,
    decode::*,
};

/// A self-describing, forward-compatible hash format that supports multiple
/// algorithms.
///
/// # Layout
///
/// | Part        | Purpose                    | Size (in bytes) |
/// | :---------- | :------------------------- | :-------------- |
/// | Algorithm   | The hashing algorithm used | 1               |
/// | Length      | The size of _Digest_       | 2               |
/// | Digest      | The output of _Algorithm_  | _Length_        |
///
/// # Compared to [`multiformats/multihash`]
///
/// This type is inspired by (but incompatible with) [`multiformats/multihash`].
/// Unlike that representation, this:
///
/// - Uses a fixed-width integer for specifying the algorithm and digest length
///   rather than an [`unsigned-varint`].
///
///   This is done to make encoding/decoding hashes very trivial and thus easier
///   to speed up with explicit or auto vectorization.
///
/// - Continues to work (but is limited in functionality) when the algorithm is
///   unknown, unlike [`rust-multihash`] which is unable to operate over opaque
///   algorithms.
///
/// [`multiformats/multihash`]: https://github.com/multiformats/multihash
/// [`unsigned-varint`]:        https://github.com/multiformats/unsigned-varint
/// [`rust-multihash`]:         https://github.com/multiformats/rust-multihash
pub struct Hash(
    /// Uses a simple zero-sized habitable value in order for `&Hash` to be
    /// 1 word (thin pointer) rather than 2 words (fat pointer: address + size).
    /// This is because the digest length is stored inline at `offset::DIGEST_LEN`.
    ///
    /// See https://doc.rust-lang.org/stable/nomicon/ffi.html#representing-opaque-structs.
    ///
    /// Down the line this type should be expressed via:
    ///
    /// ```ignore
    /// extern "C" {
    ///     type HashInner;
    /// }
    /// ```
    ///
    /// This is how `std::ffi::CStr` is intended to be implemented. See tracking
    /// issue: https://github.com/rust-lang/rust/issues/43467.
    [u8; 0],
);

impl ToOwned for Hash {
    type Owned = HashBuf;

    fn to_owned(&self) -> Self::Owned {
        if self.can_inline() {
            unsafe { HashBuf::new_inline(self.as_bytes()) }
        } else {
            let alg = self.algorithm_tag();
            let len = self.digest_len_bytes();
            let vec = self.as_bytes().to_owned();
            unsafe { HashBuf::new_vec(alg, len, vec) }
        }
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("Hash")
            .field(&util::HexByte::slice(self.as_bytes()))
            .finish()
    }
}

impl PartialEq for Hash {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl<H: AsRef<Hash> + ?Sized> PartialEq<H> for Hash {
    #[inline]
    fn eq(&self, other: &H) -> bool {
        self == other.as_ref()
    }
}

impl Eq for Hash {}

impl PartialOrd for Hash {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<H: AsRef<Hash> + ?Sized> PartialOrd<H> for Hash {
    #[inline]
    fn partial_cmp(&self, other: &H) -> Option<cmp::Ordering> {
        self.partial_cmp(other.as_ref())
    }
}

impl Ord for Hash {
    #[inline]
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.as_bytes().cmp(other.as_bytes())
    }
}

impl std::hash::Hash for Hash {
    #[inline]
    fn hash<H: std::hash::Hasher>(&self, hasher: &mut H) {
        hasher.write(self.as_bytes());
    }
}

impl Hash {
    /// Creates a new instance or returns an error if `hash` is invalid.
    #[inline]
    pub fn new(hash: &[u8]) -> Result<&Self, DecodeError> {
        let digest_len_bytes = hash.get(range::DIGEST_LEN)
            .ok_or(DecodeError::MissingDigestLen)?;

        let digest_len_bytes: [u8; size::DIGEST_LEN] = unsafe {
            *digest_len_bytes.as_ptr().cast()
        };
        let digest_len = u16::from_le_bytes(digest_len_bytes) as usize;

        let expected_len = offset::PAYLOAD + digest_len;

        // SAFETY: `digest_len` can only be retrieved if `hash.len() > 0`.
        let received_len = unsafe { NonZeroUsize::new_unchecked(hash.len()) };

        if received_len.get() == expected_len {
            Ok(unsafe { Self::new_unchecked(hash) })
        } else {
            Err(DecodeError::LenMismatch { expected_len, received_len })
        }
    }

    /// Creates a new instance assuming `hash` to be valid.
    ///
    /// # Safety
    ///
    /// The bytes in `hash` _must_ must correctly match
    /// [`Hash`'s memory layout](struct.Hash.html#layout).
    #[inline]
    pub unsafe fn new_unchecked(hash: &[u8]) -> &Self {
        Self::from_ptr(hash.as_ptr())
    }

    /// Creates a new instance assuming `ptr` to be the start of a valid hash.
    ///
    /// # Safety
    ///
    /// The bytes at `ptr` _must_ must correctly match
    /// [`Hash`'s memory layout](struct.Hash.html#layout).
    #[inline]
    pub unsafe fn from_ptr<'a>(ptr: *const u8) -> &'a Self {
        &*ptr.cast()
    }

    /// Returns an iterator that decodes contiguous `Hash`es from `hashes`.
    ///
    /// # Examples
    ///
    /// Because each iteration returns a [`Result`], the iterator can be
    /// [`collect`]ed into a [`Result`] corresponding to the first invalid hash.
    ///
    /// ```
    /// use bay::hash::Hash;
    ///
    /// let bytes: &[u8] = // ...
    /// # &[255, 0, 0, 255, 1, 0, 0, 255, 2, 0, 0, 0];
    ///
    /// let hashes: Vec<&Hash> = Hash::iter(bytes)
    ///     .collect::<Result<_, _>>()
    ///     .unwrap();
    ///
    /// // Serialize `hashes` into a contiguous buffer.
    /// let hash_bytes: Vec<u8> = hashes.into_iter()
    ///     .map(|h| h.as_bytes().iter().cloned())
    ///     .flatten()
    ///     .collect();
    ///
    /// assert_eq!(hash_bytes, bytes);
    /// ```
    ///
    /// [`collect`]: https://doc.rust-lang.org/std/iter/trait.Iterator.html#method.collect
    /// [`Result`]:  https://doc.rust-lang.org/std/result/enum.Result.html
    #[inline]
    pub const fn iter(hashes: &[u8]) -> DecodeIter<'_> {
        DecodeIter { hashes }
    }

    /// Returns an iterator that decodes contiguous `Hash`es from `hashes` by
    /// blindly trusting reported lengths.
    ///
    /// # Safety
    ///
    /// <span style="color:red;">**The returned iterator is _extremely_ unsafe.
    /// Use at your own risk!**</span>
    ///
    /// This assumes that `hashes` is a contiguous (back-to-back) list of
    /// `Hash`es that all report a valid digest length.
    ///
    /// # Examples
    ///
    /// Unlike with [`iter`](#method.iter), no errors are reported and thus the
    /// hashes can be [`collect`]ed without going through a [`Result`].
    ///
    /// ```
    /// use bay::hash::Hash;
    ///
    /// let bytes: &[u8] = // ...
    /// # &[255, 0, 0, 255, 1, 0, 0, 255, 2, 0, 0, 0];
    ///
    /// let hashes: Vec<&Hash> = unsafe {
    ///     Hash::iter_unchecked(bytes).collect()
    /// };
    ///
    /// // Serialize `hashes` into a contiguous buffer.
    /// let hash_bytes: Vec<u8> = hashes.into_iter()
    ///     .map(|h| h.as_bytes().iter().cloned())
    ///     .flatten()
    ///     .collect();
    ///
    /// assert_eq!(hash_bytes, bytes);
    /// ```
    ///
    /// [`collect`]: https://doc.rust-lang.org/std/iter/trait.Iterator.html#method.collect
    /// [`Result`]:  https://doc.rust-lang.org/std/result/enum.Result.html
    #[inline]
    pub const unsafe fn iter_unchecked(hashes: &[u8]) -> DecodeUncheckedIter<'_> {
        DecodeUncheckedIter { hashes }
    }

    #[inline]
    fn can_inline(&self) -> bool {
        self.digest_len() <= size::INLINE_DIGEST
    }

    /// Returns a pointer to the start of the hash.
    #[inline]
    pub fn as_ptr(&self) -> *const u8 {
        self.0.as_ptr()
    }

    /// Returns the length of the hash in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        offset::PAYLOAD + self.digest_len()
    }

    /// Returns whether the length of the digest of `self` is valid in terms of
    /// [`algorithm`](#method.algorithm).
    ///
    /// For forward-compatibility reasons, this is not automatically checked
    /// when decoding with [`new`](#method.new) or [`iter`](#method.iter).
    #[inline]
    pub fn is_valid_len(&self) -> Option<bool> {
        self.algorithm()
            .map(|alg| self.digest_len() == alg.len())
    }

    #[inline]
    fn algorithm_tag(&self) -> u8 {
        unsafe { *self.as_bytes().get_unchecked(offset::ALGORITHM) }
    }

    /// Returns the hashing algorithm used.
    #[inline]
    pub fn algorithm(&self) -> Option<Algorithm> {
        Algorithm::from_tag(self.algorithm_tag())
    }

    /// Returns the bytes of the digest for the hashing algorithm used.
    #[inline]
    pub fn digest(&self) -> &[u8] {
        unsafe {
            let start = self.as_ptr().add(offset::PAYLOAD);
            slice::from_raw_parts(start, self.digest_len())
        }
    }

    #[inline]
    fn digest_len_bytes(&self) -> [u8; size::DIGEST_LEN] {
        unsafe { *self.0.as_ptr().add(offset::DIGEST_LEN).cast() }
    }

    /// Returns the length of the digest.
    #[inline]
    pub fn digest_len(&self) -> usize {
        // Use consistent endianness on all platforms so that the bytes can be
        // sent between machines of different native endianness. Little endian
        // is used specifically because x86 uses it and thus is very common.
        u16::from_le_bytes(self.digest_len_bytes()) as usize
    }

    /// Returns the bytes of the hash.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.as_ptr(), self.len()) }
    }
}

/// An owned (yet immutable) [`Hash`] representation.
///
/// # Layout
///
/// This type either stores the [`Hash`] inline or through a heap-allocated
/// `Vec<u8>` instance.
///
/// ## Inline
///
/// This representation is almost always what's used because all known hash
/// algorithms are stored inline. Any pointer to an instance is also a valid
/// pointer to a [`Hash`].
///
/// Using inline hashes improves performance due to:
///
/// 1. Better cache locality.
///
/// 2. No need for heap allocation/deallocation.
///
/// ## Heap-Allocated
///
/// This representation exists for forward-compatibility. If a future algorithm
/// is used that does not fit inline, then its [`Hash`] is stored in a
/// `Vec<u8>`.
///
/// [`Hash`]: struct.Hash.html
#[repr(transparent)]
pub struct HashBuf([u8; size::INLINE_HASH]);

impl From<&Hash> for HashBuf {
    #[inline]
    fn from(hash: &Hash) -> Self {
        hash.to_owned()
    }
}

impl From<algorithm::Sha256> for HashBuf {
    #[inline]
    fn from(digest: algorithm::Sha256) -> Self {
        const DIGEST_LEN: usize = mem::size_of::<algorithm::Sha256>();
        const REM_BYTES: usize = size::INLINE_DIGEST - DIGEST_LEN;

        #[repr(C)] // Required to ensure correct field ordering.
        struct Hash {
            algorithm: Algorithm,
            digest_len: [u8; 2],
            digest: algorithm::Sha256,
            remaining: [u8; REM_BYTES],
        }

        let hash = Hash {
            algorithm: Algorithm::Sha256,
            digest_len: [DIGEST_LEN as u8, 0],
            digest,
            remaining: [0u8; REM_BYTES],
        };

        unsafe { mem::transmute(hash) }
    }
}

impl Drop for HashBuf {
    #[inline] // Doing very trivial work outside of dropping `Vec<u8>`.
    fn drop(&mut self) {
        if !self.is_inline() {
            drop(unsafe { self.vec() });
        }
    }
}

impl Clone for HashBuf {
    fn clone(&self) -> Self {
        if self.is_inline() {
            Self(self.0)
        } else {
            unsafe {
                let buf = Self::new_vec(
                    self.algorithm_tag(),
                    self.digest_len_bytes(),
                    self.vec_slice().into(),
                );
                buf
            }
        }
    }
}

impl ops::Deref for HashBuf {
    type Target = Hash;

    #[inline]
    fn deref(&self) -> &Hash {
        self.as_hash()
    }
}

impl AsRef<Hash> for HashBuf {
    #[inline]
    fn as_ref(&self) -> &Hash {
        self
    }
}

impl Borrow<Hash> for HashBuf {
    #[inline]
    fn borrow(&self) -> &Hash {
        self
    }
}

impl fmt::Debug for HashBuf {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("HashBuf")
            .field(&util::HexByte::slice(self.as_bytes()))
            .finish()
    }
}

impl<H: AsRef<Hash> + ?Sized> PartialEq<H> for HashBuf {
    #[inline]
    fn eq(&self, other: &H) -> bool {
        self.as_bytes() == other.as_ref().as_bytes()
    }
}

impl Eq for HashBuf {}

impl<H: AsRef<Hash> + ?Sized> PartialOrd<H> for HashBuf {
    #[inline]
    fn partial_cmp(&self, other: &H) -> Option<cmp::Ordering> {
        Some(self.as_bytes().cmp(other.as_ref().as_bytes()))
    }
}

impl Ord for HashBuf {
    #[inline]
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.as_bytes().cmp(other.as_bytes())
    }
}

impl std::hash::Hash for HashBuf {
    #[inline]
    fn hash<H: std::hash::Hasher>(&self, hasher: &mut H) {
        hasher.write(self.as_bytes());
    }
}

impl HashBuf {
    // SAFETY: Some assumptions are made:
    // - `hash` is valid.
    // - `hash`'s algorithm is equal to `algorithm`.
    // - `hash`'s length is equal to `digest_len`.
    #[inline]
    unsafe fn new_vec(
        algorithm: u8,
        digest_len: [u8; 2],
        mut hash: Vec<u8>,
    ) -> Self {
        let ptr = (hash.as_mut_ptr() as usize).to_ne_bytes();
        let cap = hash.capacity().to_ne_bytes();
        mem::forget(hash);

        let mut buf = mem::zeroed::<Self>();
        buf.0[offset::ALGORITHM] = algorithm;

        let buf_ptr = buf.0.as_mut_ptr();
        ptr::copy_nonoverlapping(
            digest_len.as_ptr(),
            buf_ptr.add(offset::DIGEST_LEN),
            digest_len.len(),
        );
        ptr::copy_nonoverlapping(
            ptr.as_ptr(),
            buf_ptr.add(offset::PAYLOAD),
            ptr.len(),
        );
        ptr::copy_nonoverlapping(
            cap.as_ptr(),
            buf_ptr.add(offset::CAPACITY),
            cap.len(),
        );

        buf
    }

    // SAFETY: Some assumptions are made:
    // - `hash` is valid.
    // - `hash`'s length fits within the inline buffer.
    #[inline]
    unsafe fn new_inline(hash: &[u8]) -> Self {
        // Using an uninitialized instance results in a direct `memcpy` into the
        // value at the return address.
        let mut buf = mem::MaybeUninit::<HashBuf>::uninit();
        ptr::copy_nonoverlapping(
            hash.as_ptr(),
            buf.as_mut_ptr() as *mut u8,
            hash.len(),
        );
        buf.assume_init()
    }

    /// Creates a new instance or returns an error if `hash` is invalid.
    #[inline]
    pub fn new(hash: Vec<u8>) -> Result<Self, DecodeBufError> {
        match Hash::new(&hash) {
            Ok(_) => Ok(unsafe { Self::new_unchecked(hash) }),
            Err(cause) => Err(DecodeBufError { cause, hash }),
        }
    }

    /// Creates a new instance assuming `hash` to be valid.
    ///
    /// # Safety
    ///
    /// The bytes in `hash` _must_ must correctly match
    /// [`Hash`'s memory layout](struct.Hash.html#layout).
    #[inline]
    pub unsafe fn new_unchecked(hash: Vec<u8>) -> Self {
        let digest_len = hash.len() - offset::PAYLOAD;
        if digest_len <= size::INLINE_DIGEST {
            Self::new_inline(hash.as_slice())
        } else {
            Self::new_vec(
                *hash.get_unchecked(0),
                (digest_len as u16).to_le_bytes(),
                hash,
            )
        }
    }

    #[inline]
    fn is_inline(&self) -> bool {
        self.digest_len() <= size::INLINE_DIGEST
    }

    // SAFETY: `self` *must* be backed by a vector representation and the caller
    // *must* take care to only `drop` either `self` or the returned vector.
    #[inline]
    unsafe fn vec(&self) -> Vec<u8> {
        let ptr = self.vec_ptr() as *mut u8;
        let len = self.len();
        let cap = self.capacity();
        Vec::from_raw_parts(ptr, len, cap)
    }

    // SAFETY: `self` *must* be backed by a vector representation.
    #[inline]
    unsafe fn vec_slice(&self) -> &[u8] {
        slice::from_raw_parts(self.vec_ptr(), self.len())
    }

    // The returned value is worthless garbage when `is_inline` is true.
    #[inline]
    fn vec_ptr(&self) -> *const u8 {
        let ptr_bytes: [u8; size::PTR] = unsafe {
            *self.0.as_ptr().add(offset::PAYLOAD).cast()
        };
        // The byte representation of a heap-allocated `HashBuf` will never be
        // sent between machines. As a result, we can use the host platform's
        // native word size and endianness.
        usize::from_ne_bytes(ptr_bytes) as *const u8
    }

    /// Returns a pointer to the start of the hash.
    #[inline]
    pub fn as_ptr(&self) -> *const u8 {
        if self.is_inline() {
            self.0.as_ptr()
        } else {
            self.vec_ptr()
        }
    }

    /// Returns the length of the hash in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        offset::PAYLOAD + self.digest_len()
    }

    /// Returns whether the length of the digest of `self` is valid in terms of
    /// [`algorithm`](#method.algorithm).
    ///
    /// For forward-compatibility reasons, this is not automatically checked
    /// when decoding with [`new`](#method.new).
    // This exists so that---in the case of a non-inline hash---the algorithm
    // and digest length are *always* read from inline data for better cache
    // locality.
    #[inline]
    pub fn is_valid_len(&self) -> Option<bool> {
        self.algorithm()
            .map(|alg| self.digest_len() == alg.len())
    }

    #[inline]
    const fn algorithm_tag(&self) -> u8 {
        self.0[offset::ALGORITHM]
    }

    /// Returns the hashing algorithm used.
    #[inline]
    pub fn algorithm(&self) -> Option<Algorithm> {
        Algorithm::from_tag(self.algorithm_tag())
    }

    /// Returns the bytes of the hashing algorithm.
    // This exists so that---in the case of a non-inline hash---the digest
    // length is *always* read from inline data for better cache locality.
    #[inline]
    pub fn digest(&self) -> &[u8] {
        unsafe {
            let start = self.as_ptr().add(offset::PAYLOAD);
            slice::from_raw_parts(start, self.digest_len())
        }
    }

    #[inline]
    fn digest_len_bytes(&self) -> [u8; size::DIGEST_LEN] {
        unsafe { *self.0.as_ptr().add(offset::DIGEST_LEN).cast() }
    }

    /// Returns the length of the digest.
    // This exists for the same reason as `digest`.
    #[inline]
    pub fn digest_len(&self) -> usize {
        // Use consistent endianness on all platforms so that the bytes can be
        // sent between machines of different native endianness. Little endian
        // is used specifically because x86 uses it and thus is very common.
        u16::from_le_bytes(self.digest_len_bytes()) as usize
    }

    #[inline]
    fn capacity_bytes(&self) -> [u8; size::PTR] {
        // Use `size::PTR` since the capacity may have been derived from a
        // `Vec<u8>` whose length is much smaller than its capacity.
        unsafe { *self.0.as_ptr().add(offset::CAPACITY).cast() }
    }

    // The returned value is worthless garbage when `is_inline` is true.
    #[inline]
    fn capacity(&self) -> usize {
        // The byte representation of a heap-allocated `HashBuf` will never be
        // sent between machines. As a result, we can use the host platform's
        // native word size and endianness.
        usize::from_ne_bytes(self.capacity_bytes())
    }

    /// Returns the bytes of the hash.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.as_ptr(), self.len()) }
    }

    /// Returns a shared reference to the hash that `self` has ownership of.
    #[inline]
    pub fn as_hash(&self) -> &Hash {
        unsafe { &*self.as_ptr().cast() }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn clone() {
        let algorithm = 255u8;

        let mut hash = vec![0u8; size::INLINE_HASH + 1];
        hash[offset::ALGORITHM] = algorithm;

        let digest_len = size::DIGEST_LEN + 1;
        unsafe {
            let ptr = hash.as_mut_ptr()
                .add(offset::DIGEST_LEN)
                .cast::<[u8; size::DIGEST_LEN]>();
            *ptr = (digest_len as u16).to_le_bytes();
        }

        let hash = unsafe { HashBuf::new_unchecked(hash) };

        for _ in 0..10 {
            drop(hash.clone());
        }

        drop(hash);
    }

    #[test]
    fn decode() {
        let mut hash = vec![255, 0, 0];

        for i in 1..=255 {
            // Reassign digest length low byte as digest increases.
            hash[1] = i;
            hash.push(i);

            let hash = hash.as_slice();
            assert_eq!(Hash::new(hash).unwrap().as_bytes(), hash);
        }
    }
}
