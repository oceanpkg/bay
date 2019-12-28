//! Hashing algorithms.

pub mod algorithm;
mod util;

pub mod multi;

#[doc(inline)]
pub use self::{
    algorithm::HashAlgorithm,
    multi::{MultiHash, MultiHashBuf},
};
