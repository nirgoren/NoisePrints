//! # CirC
//!
//! A compiler infrastructure for compiling programs to circuits

#![warn(missing_docs)]
#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;
// #![deny(warnings)]
// #![allow(rustdoc::private_intra_doc_links)]
// #![allow(clippy::mutable_key_type)]

#[macro_use]
pub mod ir;
pub mod cfg;
pub mod circify;
pub mod front;
pub mod target;
pub mod util;
pub mod bignat;
pub mod rsa;
pub mod ecdsa;
pub mod convert;
pub mod preproc_utils;
pub mod allocate;
pub mod hash;
pub mod create_input;
pub mod parse_cert;
pub mod user_input;
pub mod commitment;
pub mod poseidon_const;
pub mod parse_zokrates;
pub mod math;
pub mod zkconst;
#[cfg(feature = "spartan")]
pub mod right_field_arithmetic;
pub mod eddsa;
pub mod pcs;