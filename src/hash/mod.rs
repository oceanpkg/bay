//! Hashing algorithms.

pub mod algorithm;
mod util;

pub mod multi;

#[doc(inline)]
pub use self::{
    algorithm::Algorithm,
    multi::{MultiHash, MultiHashBuf},
};
