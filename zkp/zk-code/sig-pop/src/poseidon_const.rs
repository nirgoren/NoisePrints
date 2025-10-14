//! This module includes implementations related to constants in Poseidon hash
use lazy_static::lazy_static;
use rug::Integer;
use crate::parse_zokrates::{read_double_array, read_triple_array};

/// DEFAULT_MODULUS_STR
pub const DEFAULT_MODULUS_STR: &str = "52435875175126190479447740508185965837690552500527637822603658699938581184513"; // circ
/// FILEPATH STORING POSEIDON_CONST
pub const POSEIDON_CONST_PATH: &str = "../../sig-pop/third_party/ZoKrates/zokrates_stdlib/stdlib/hashes/poseidon/constants.zok";

lazy_static! {
    /// DEFAULT_MODULUS
    pub static ref DEFAULT_MODULUS: Integer = Integer::from_str_radix(DEFAULT_MODULUS_STR, 10).unwrap();
    /// POSEIDON_C
    pub static ref POSEIDON_C: Vec<Vec<Integer>> = read_double_array(POSEIDON_CONST_PATH).unwrap();
    /// POSEIDON_M
    pub static ref POSEIDON_M: Vec<Vec<Vec<Integer>>> = read_triple_array(POSEIDON_CONST_PATH).unwrap();
}

