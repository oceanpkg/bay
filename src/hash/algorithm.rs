use std::mem;

macro_rules! decl {
    ($(
        $(#[$meta:meta])*
        $alg:ident = $tag:expr,
    )+) => {
        /// An algorithm used for hashing.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
        #[repr(u8)]
        #[non_exhaustive]
        pub enum HashAlgorithm {
            $(
                $(#[$meta])*
                $alg = $tag,
            )+
        }

        impl HashAlgorithm {
            #[inline]
            pub(crate) fn is_valid(tag: u8) -> bool {
                match tag {
                    $($tag)|+ => true,
                    _ => false,
                }
            }

        }
    };
}

decl! {
    /// SHA-2 256-bit.
    Sha256 = 0,
}

impl HashAlgorithm {
    /// The current maximum size known.
    // TODO: Compute by actually getting the largest hash in `decl!`.
    pub(crate) const MAX_SIZE: usize = mem::size_of::<super::Sha256>();

    /// Creates a new instance from `tag` if it represents a known algorithm.
    #[inline]
    pub fn from_tag(tag: u8) -> Option<Self> {
        if Self::is_valid(tag) {
            Some(unsafe { mem::transmute(tag) })
        } else {
            None
        }
    }

    /// Returns the number of bytes needed to store the digest of `self`.
    #[inline]
    pub fn len(&self) -> usize {
        match self {
            HashAlgorithm::Sha256 => 32,
        }
    }
}
