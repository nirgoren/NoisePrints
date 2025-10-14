//! This module includes methods that convert variables from one type to another type
use crate::ir::term::{Value,BitVector};
use rug::Integer;
use circ_fields::{FieldT, FieldV};
use rug::integer::ParseIntegerError;
use openssl::bn::BigNumRef;
use rug::rand::MutRandState;

/// Convert Integer to bytes
pub fn integer_to_bytes(input: &Integer) -> [u8; 32] {
    let digits: Vec<u8> = input.to_digits(rug::integer::Order::LsfLe);
    let mut repr: [u8; 32] = [0; 32];
    repr.as_mut()[..digits.len()].copy_from_slice(&digits);
    repr
}

/// Converts a `bool` to a `Value`.
#[allow(unused)]
pub fn bool_to_value(bit: bool) -> Value {
    Value::Bool(bit)
}

// Adapt from https://github.com/PepperSieve/circ/blob/master/examples/run_zok.rs

/// Converts a `u8` to a `Value`.
pub fn u8_to_value(num: u8) -> Value {
    Value::BitVector(BitVector::new(Integer::from(num), 8))
}

/// Converts a `u16` to a `Value`.
pub fn u16_to_value(num: u16) -> Value {
    Value::BitVector(BitVector::new(Integer::from(num), 16))
}

#[allow(unused)]
/// Converts a `u32` to a `Value`.
pub fn u32_to_value(num: u32) -> Value {
    Value::BitVector(BitVector::new(Integer::from(num), 32))
}

/// Converts a `u64` to a `Value`.
pub fn u64_to_value(num: u64) -> Value {
    Value::BitVector(BitVector::new(Integer::from(num), 64))
}

/// Converts a very large integer expressed in string to a field
pub fn str_to_field(s: &str) -> Value {
    let big_int = Integer::from_str_radix(s, 10).unwrap();
    Value::Field(FieldV::new(big_int, FieldT::FBls12381.modulus_arc()))
}

/// Converts Vec<Integer> to Vec<u16>
pub fn vec_int_to_vec_u16(input: Vec<Integer>) -> Vec<u16> {
    let mut result: Vec<u16> = Vec::new();
    for ele in input.iter() {
        result.push(ele.to_u16().unwrap());
    }
    result
}

/// Converts Vec<Integer> to Vec<u32>
pub fn vec_int_to_vec_u32(input: Vec<Integer>) -> Vec<u32> {
    let mut result: Vec<u32> = Vec::new();
    for ele in input.iter() {
        result.push(ele.to_u32().unwrap());
    }
    result
}


/// Converts Vec<Integer> to Vec<u64>
pub fn vec_int_to_vec_u64(input: Vec<Integer>) -> Vec<u64> {
    let mut result: Vec<u64> = Vec::new();
    for ele in input.iter() {
        result.push(ele.to_u64().unwrap());
    }
    result
}

/// Convert String to Vec<u8>
pub fn string_to_vecu8(hex_string: String) -> Vec<u8> {
    // let hex_string = num.to_string_radix(16);
    let mut octet_string = Vec::new();

    // Convert each pair of hexadecimal digits into a byte
    for i in (0..hex_string.len()).step_by(2) {
        if i + 1 < hex_string.len() {
            let byte = u8::from_str_radix(&hex_string[i..i + 2], 16)
                .expect("Failed to convert hexadecimal string to byte");
            octet_string.push(byte);
        }
    }

    octet_string
}

/// Convert Vec<u8> to rug::Integer
pub fn vecu8_to_integer(vec: Vec<u8>) -> Integer {
    let hex_string: String = vec.iter().map(|b| format!("{:02x}", b)).collect();
    Integer::from_str_radix(&hex_string, 16)
        .expect("Failed to convert hexadecimal string to rug::Integer")
}

/// Converts a very large integer expressed in Integer to a field
pub fn integer_to_field(big_int: &Integer) -> Value {
    // let random_value = random_field_element(&mut rand::thread_rng());
    // println!("random_value {:?}", random_value);
    Value::Field(FieldV::new(big_int, FieldT::FBls12381.modulus_arc()))
}

/// Generate a random field element in Bls12381
pub fn rand_field_element(rng: impl rand::RngCore) -> Value {
    let random_value = FieldT::FBls12381.random_v(rng);
    Value::Field(random_value)
}

/// Generate a random field element in Bls12381
pub fn rand_int(rng: &mut dyn MutRandState) -> Integer {
    <rug::Integer as Clone>::clone(&FieldT::FBls12381.modulus_arc()).random_below(rng)
}

/// Converts a `integer` to a vector of `bool`.
pub fn integer_to_bool_vec(integer: &Integer, n_bits: usize) -> Vec<bool> {
    let bits_string = integer.to_string_radix(2);
    let num_zeros = n_bits - bits_string.len();
    assert!(n_bits >= bits_string.len());
    let bits = bits_string.chars().map(|c| c == '1').collect::<Vec<bool>>();
    vec![false; num_zeros].into_iter().chain(bits.into_iter()).collect()
}

/// Converts a vector of `bool` to an usize.
pub fn bool_vec_to_usize(bool_vec: &[bool]) -> usize {
    bool_vec.iter().fold(0, |acc, &bit| (acc << 1) | (bit as usize))
}


/// Converts a vector of `bool` to an `Integer`.
pub fn bool_vec_to_integer(bool_vec: &[bool]) -> Integer {
    let mut integer_string = String::new();

    for &bit in bool_vec {
        if bit {
            integer_string.push('1');
        } else {
            integer_string.push('0');
        }
    }

    Integer::from_str_radix(&integer_string, 2).unwrap()
}

/// Convert BigNumRef to Integer
pub fn bignumref_to_integer(num: &BigNumRef) -> Result<Integer, ParseIntegerError> {
    // Convert the number to a String
    let num_str = num.to_hex_str()
        .expect("Failed to return the hex string representation of the number");

    // Parse the String into an Integer
    let num_integer = Integer::from_str_radix(&num_str, 16)?;

    Ok(num_integer)
}

/// Converts an octet string to a nonnegative integer. https://www.rfc-editor.org/rfc/rfc8017#section-4.2
#[allow(unused)]
pub fn os2ip(u8_bytes: &[u8]) -> Integer {
    let x_len = u8_bytes.len();
    let mut x = Integer::new();

    // Iterate over each octet in signature_bytes
    for (i, &byte) in u8_bytes.iter().enumerate() {
        // Calculate the positional value of the octet
        let power = (x_len - i - 1) * 8;

        // Convert the octet to its integer value and add it to x
        x += Integer::from(byte) << power;
    }

    // Return the resulting nonnegative integer x
    x
}

