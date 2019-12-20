//! Content chunks.

use std::{
    fmt,
    fs::File,
    io,
    ops,
    path::Path,
};
use memmap::Mmap;

/// A content-addressable chunk of data.
///
/// This represents either all or one of multiple parts of a single unit of
/// content-addressable data.
#[derive(serde::Serialize)]
pub struct Chunk([u8]);

// TODO: Implement `serde::Deserialize` for `&Chunk`

impl AsRef<[u8]> for Chunk {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Debug for Chunk {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Chunks can be *very* large, so it doesn't make sense to print out the
        // entire buffer.
        f.debug_struct("Chunk")
            .field("ptr", &self.0.as_ptr())
            .field("len", &self.len())
            .finish()
    }
}

impl Chunk {
    /// Opens the chunk file at `path` as a memory-mapped file.
    ///
    /// This is an alias to `MappedChunk::open`.
    ///
    /// # Safety
    ///
    /// Content of the file at `path` must never be mutated while the returned
    /// chunk is live.
    #[inline]
    pub unsafe fn open<P: AsRef<Path>>(path: P) -> io::Result<MappedChunk> {
        MappedChunk::open(path)
    }

    /// Takes a slice of bytes to be treated as a `Chunk`.
    #[inline]
    pub fn from_bytes(b: &[u8]) -> &Self {
        unsafe { &*(b as *const [u8] as *const Self) }
    }

    /// Returns the underlying bytes of the chunk.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the number of bytes in the chunk.
    #[inline]
    pub const fn len(&self) -> usize {
        self.0.len()
    }
}

/// A [`Chunk`] backed by a memory-mapped file.
///
/// [`Chunk`]: struct.Chunk.html
#[derive(Debug)]
pub struct MappedChunk(Mmap);

impl ops::Deref for MappedChunk {
    type Target = Chunk;

    #[inline]
    fn deref(&self) -> &Chunk {
        Chunk::from_bytes(self.0.as_ref())
    }
}

impl MappedChunk {
    /// Opens the chunk file at `path` as a memory-mapped file.
    ///
    /// # Safety
    ///
    /// Content of the file at `path` must never be mutated while the returned
    /// chunk is live.
    #[inline]
    pub unsafe fn open<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        File::open(path)
            .and_then(|file| Mmap::map(&file))
            .map(Self)
    }

    /// Returns the underlying bytes of the chunk.
    #[inline]
    pub fn as_chunk(&self) -> &Chunk {
        self
    }
}
