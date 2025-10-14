//! Implementations related to sha256
use fxhash::FxHashMap as HashMap;
use crate::ir::term::Value;
use crate::parse_cert::{X509Certificate};
use super::hash::DigestAlgorithm;
use crate::allocate::{map_u32_double_vec, map_u32_vec, map_field_vec}; //,map_u32, map_bool_double_vec_to_single_vec};
#[cfg(feature = "spartan")]
use crate::right_field_arithmetic::alloc::{map_field_vec as map_field_vec_with_modulus};
use rug::Integer;
use crate::bignat::bignatwithlimbmax::BigNatWithLimbMax;

use crate::conditional_print;
use std::time::Instant;
use crate::util::timer::print_time;
use std::sync::Arc;

/// Convert the number of blocks to the length of the message
pub fn n_blocks_to_msg_len(n_block_str: String) -> usize {
    let n_blocks = n_block_str.parse::<usize>().unwrap();
    (n_blocks - 1) * 64 + 4
}

fn convert_message_to_zok_var(message: &Vec<u8>) -> Vec<Vec<BigNatWithLimbMax>> {
    let limb_width = 11;
    let n_limbs = (32 + limb_width - 1) / limb_width;
    let padded: Vec<u8> = DigestAlgorithm::padding(message);
    let padded_zok: Vec<Vec<u32>> = DigestAlgorithm::vecu8_to_doublevecu32(&padded);
    let mut output: Vec<Vec<BigNatWithLimbMax>> = Vec::new();
    for vec in padded_zok.iter() {
        let mut output_inner: Vec<BigNatWithLimbMax> = Vec::new();
        for ele in vec.iter() {
            let big_nat = BigNatWithLimbMax::from_u32(*ele, limb_width, n_limbs, false); // constant = false
            output_inner.push(big_nat);
        }
        output.push(output_inner);
    }
    output
}

fn convert_u32_vec_to_integer_vec(input: &Vec<u32>) -> Vec<Integer> {
    let mut output: Vec<Integer> = Vec::new();
    for ele in input.iter() {
        let integer = Integer::from(*ele);
        output.push(integer);
    }
    output
}

/// Extract first N-bytes message from the certificate
fn extract_message(msg_len: usize) -> Vec<u8> {
    let signed_certificate_path = "./example_cert/_.google.com.cer";
    let issuer_certificate_path = "./example_cert/_GTS_CA_1C3.cer";
    conditional_print!("Path of the signed certificate: {}", signed_certificate_path);
    conditional_print!("Path of the issuer certificate: {}", issuer_certificate_path);
    let cert: X509Certificate = X509Certificate::new(signed_certificate_path, issuer_certificate_path);
    cert.print_signature_algorithm();

    let message: &[u8] = &cert.body[0..msg_len];
    message.to_vec()
}

/// Extract the digest result of first N-bytes message from the certificate
fn extract_hash(msg_len: usize) -> Vec<u32> {
    let message: Vec<u8> = extract_message(msg_len);
    DigestAlgorithm::sha256_to_vecu32(&message)
}

/// Prover input for original sha256
pub fn prover_input_for_sha256_ori(n_block_str: String) -> HashMap<String, Value>{
    let msg_len = n_blocks_to_msg_len(n_block_str);
    let message: Vec<u8> = extract_message(msg_len);
    let start = Instant::now();
    let hash_map = prover_input_for_sha256_ori_inner(&message);
    print_time("Time for Compute prover input", start.elapsed(), true); // verify-ecdsa: 10.522471ms
    hash_map
}

fn prover_input_for_sha256_ori_inner(message: &Vec<u8>) -> HashMap<String, Value>{
    let mut input_map = HashMap::<String, Value>::default();
    let padded: Vec<u8> = DigestAlgorithm::padding(message);
    let padded_zok: Vec<Vec<u32>> = DigestAlgorithm::vecu8_to_doublevecu32(&padded);
    let mut digest_result: Vec<u32> = DigestAlgorithm::sha256_to_vecu32(message);
    conditional_print!("digest_result: {:?}", digest_result);
    digest_result.reverse(); // reverse because of the zokrates original implementation
    map_u32_double_vec(&padded_zok, "padded_message", &mut input_map);
    map_u32_vec(&digest_result, "expected_hash", &mut input_map);
    input_map
}

/// Verifier input for original sha256 // **to do 
pub fn verifier_input_for_sha256_ori(n_block_str: String) -> HashMap<String, Value>{
    let msg_len = n_blocks_to_msg_len(n_block_str);
    let start = Instant::now();
    let mut digest_result: Vec<u32> = extract_hash(msg_len);
    digest_result.reverse(); // reverse because of the zokrates original implementation
    let mut input_map = HashMap::<String, Value>::default();
    map_u32_vec(&digest_result, "expected_hash", &mut input_map);
    print_time("Time for Compute verifier input", start.elapsed(), true);
    input_map
}


/// Prover input for optimized sha256
pub fn prover_input_for_sha256_adv(n_block_str: String, modulus: Option<&Arc<Integer>>) -> HashMap<String, Value>{
    let msg_len = n_blocks_to_msg_len(n_block_str);
    let message: Vec<u8> = extract_message(msg_len);
    let start = Instant::now();
    let mut input_map = HashMap::<String, Value>::default();
    prover_input_for_sha256_adv_inner(&message, true, modulus, &mut input_map);
    print_time("Time for Compute prover input", start.elapsed(), true); // verify-ecdsa: 10.522471ms
    input_map
}

fn print_padded_message(padded_message: &Vec<Vec<BigNatWithLimbMax>>) {
    for vec in padded_message.iter() {
        for ele in vec.iter() {
            println!("{:?}", ele.limb_values);
        }
    }
}
/// Prover input for Optimized SHA256
pub fn prover_input_for_sha256_adv_inner(message: &Vec<u8>, include_digest: bool, modulus: Option<&Arc<Integer>>, input_map: &mut HashMap::<String, Value>){
    let padded_message: Vec<Vec<BigNatWithLimbMax>> = convert_message_to_zok_var(message);
    // allocate padded message
    for (i, vec) in padded_message.iter().enumerate() {
        match modulus {
            #[cfg(feature = "spartan")]
            Some(modulus) => {
                for (j, ele) in vec.iter().enumerate() {
                    ele.alloc_w_custom_mod(modulus, &format!("padded_message.{}.{}", i, j), input_map);
                }
            },
            #[cfg(not(feature = "spartan"))]
            Some(_) => {
                panic!("Changing field is not supported in non-spartan mode");
            },
            None => {
                for (j, ele) in vec.iter().enumerate() {
                    ele.alloc(&format!("padded_message.{}.{}", i, j), input_map);
                }
            }
        }
    }
    if include_digest {
        let mut digest_result: Vec<u32> = DigestAlgorithm::sha256_to_vecu32(message);
        conditional_print!("digest_result: {:?}", digest_result);
        digest_result.reverse(); // reverse because of the zokrates original implementation
        let digest_result_int: Vec<Integer> = convert_u32_vec_to_integer_vec(&digest_result);
        conditional_print!("digest_result_int: {:?}", digest_result_int);
        match modulus {
            #[cfg(feature = "spartan")]
            Some(modulus) => {
                map_field_vec_with_modulus(&digest_result_int, &modulus, "expected_hash", input_map);
            },
            #[cfg(not(feature = "spartan"))]
            Some(_) => {
                panic!("Changing field is not supported in non-spartan mode");
            },
            None => {
                map_field_vec(digest_result_int, "expected_hash", input_map);
            }
        }
    }
}

/// Verifier input for optimized sha256 
pub fn verifier_input_for_sha256_adv(n_block_str: String, modulus: Option<&Arc<Integer>>) -> HashMap<String, Value>{
    let msg_len = n_blocks_to_msg_len(n_block_str);
    let mut digest_result: Vec<u32> = extract_hash(msg_len);
    digest_result.reverse(); // reverse because of the zokrates original implementation
    let start = Instant::now();
    let digest_result_int: Vec<Integer> = convert_u32_vec_to_integer_vec(&digest_result);
    let mut input_map = HashMap::<String, Value>::default();
    match modulus {
        #[cfg(feature = "spartan")]
        Some(modulus) => {
            map_field_vec_with_modulus(&digest_result_int, &modulus, "expected_hash", &mut input_map);
        },
        #[cfg(not(feature = "spartan"))]
        Some(_) => {
            panic!("Changing field is not supported in non-spartan mode");
        },
        None => {
            map_field_vec(digest_result_int, "expected_hash", &mut input_map);
        }
    }
    print_time("Time for Compute verifier input", start.elapsed(), true);
    input_map
}
