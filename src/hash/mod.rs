//! Hashing algorithms.

mod algorithm;
mod util;

pub mod multi;
pub mod sha256;

#[doc(inline)]
pub use self::{
    algorithm::HashAlgorithm,
    multi::{MultiHash, MultiHashBuf},
    sha256::Sha256,
};
