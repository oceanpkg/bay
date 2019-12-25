//! Hashing algorithms.

mod util;

pub mod sha256;

#[doc(inline)]
pub use self::sha256::Sha256;
