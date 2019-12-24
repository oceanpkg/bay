//! The content-addressable data store for [Ocean].
//!
//! This project is a work in progress. If you want to help make this a reality,
//! contact [Nikolai Vazquez].
//!
//! # Contributing
//!
//! See [`CONTRIBUTING.md`] for ways to improve Bay and the Ocean ecosystem.
//!
//! All participation must abide by the [Ocean Code of Conduct].
//!
//! # FAQ
//!
//! - **Q:** What is Ocean?
//!
//!   **A:** [Ocean] is a cross-platform package manager that focuses on ease of
//!   use, performance, and flexibility.
//!
//! [Ocean]:                 https://github.com/oceanpkg/ocean
//! [Ocean Code of Conduct]: https://github.com/oceanpkg/ocean/blob/master/CODE_OF_CONDUCT.md
//!
//! [Nikolai Vazquez]: https://twitter.com/NikolaiVazquez
//! [`CONTRIBUTING.md`]: https://github.com/oceanpkg/bay/blob/master/CONTRIBUTING.md

#![cfg_attr(all(test, has_features), feature(test))]
#![deny(missing_docs)]

#[cfg(all(test, has_features))]
extern crate test;

pub mod content;
pub mod hash;
