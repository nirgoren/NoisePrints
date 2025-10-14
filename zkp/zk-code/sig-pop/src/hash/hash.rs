//! Implementations related to hash
use crate::convert::string_to_vecu8;
use crate::convert::{os2ip, vec_int_to_vec_u16, vec_int_to_vec_u32, vec_int_to_vec_u64};
use openssl::hash::{MessageDigest, hash};
use rug::Integer;
use crate::bignat::bignat::{create_limb_values};
use crate::bignat::bignatwithlimbmax::BigNatWithLimbMax;

const IDENTIFIER_FOR_SHA256: &str = "30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20"; // [48, 49, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 1, 5, 0, 4, 32]


#[derive(Clone, PartialEq, Eq)]
/// Params for describing a digest algorithm
pub struct DigestAlgorithm {
    /// Name of the digest 
    pub name: String,
    /// Identifier
    pub identifier: Vec<u8>,
}

impl DigestAlgorithm {
    /// Define a new DigestAlgorithm instance based on the name of the digest algorithm
    pub fn new(name: &str) -> Result<Self, String> {
        let identifier = match name {
            "sha256" => string_to_vecu8(IDENTIFIER_FOR_SHA256.replace(" ", "")),
            _ => return Err(format!("Unsupported digest algorithm: {}", name)),
        };
        Ok(Self {
            name: name.to_string(),
            identifier: identifier,
        })
    }
    /// Padding for SHA-1, SHA-224 and SHA-256: https://csrc.nist.gov/csrc/media/publications/fips/180/3/archive/2008-10-31/documents/fips180-3_final.pdf
    pub fn padding(message: &Vec<u8>) -> Vec<u8> {
        let message_len = (message.len() as u64) * 8;
        let message_len_plus_1 = (message_len + 1) % 512;
        let num_zero_bits = if 448 >= message_len_plus_1 {(448 - message_len_plus_1) % 512} else {(448+512 - message_len_plus_1) % 512};
        let mut padded_message = message.clone();
        // Append the bit “1” to the end of the message, followed by k zero bits, where k is the smallest, non-negative solution to the equation message_len+1+k = 448 mod 512. 
        padded_message.push(0b10000000);
        for _ in 0..(num_zero_bits-7)/8 {
            padded_message.push(0b00000000);
        } 
        //  Then append the 64-bit block that is equal to binary representation of `message_len`
        for i in (0..8).rev() {
            padded_message.push(((message_len >> (i * 8)) & 0xFF) as u8);
        }
        padded_message
    }

    // Message len = number of bits of the message
    /// Padding for SHA-1, SHA-224 and SHA-256: https://csrc.nist.gov/csrc/media/publications/fips/180/3/archive/2008-10-31/documents/fips180-3_final.pdf
    pub fn pure_padding(message_len: usize) -> Vec<u8> {
        let message_len_plus_1 = (message_len + 1) % 512;
        let num_zero_bits = if 448 >= message_len_plus_1 {(448 - message_len_plus_1) % 512} else {(448+512 - message_len_plus_1) % 512};
        let mut padded_message: Vec<u8> = vec![0; message_len/8];
        // Append the bit “1” to the end of the message, followed by k zero bits, where k is the smallest, non-negative solution to the equation message_len+1+k = 448 mod 512. 
        padded_message.push(0b10000000); // before
        for _ in 0..(num_zero_bits-7)/8 {
            padded_message.push(0b00000000);
        } 
        //  Then append the 64-bit block that is equal to binary representation of `message_len`
        for i in (0..8).rev() {
            padded_message.push(((message_len >> (i * 8)) & 0xFF) as u8);
        }
        padded_message
    }

    /// Convert a `Vec<u8>` to a `Vec<Vec<u32>>` with each inner vector containing 16 u32 values
    pub fn vecu8_to_doublevecu32(message: &[u8]) -> Vec<Vec<u32>> {
        let chunked: Vec<Vec<u32>> = message
        .chunks_exact(64)
        .map(|chunk| {
            let mut inner_vec: Vec<u32> = vec![0; 16];
            for i in 0..16 {
                let start = i * 4;
                // let end = start + 4;
                let array: [u8; 4] = [chunk[start], chunk[start + 1], chunk[start + 2], chunk[start + 3]];
                inner_vec[i] = u32::from_be_bytes(array);
            }
            inner_vec
        })
        .collect();

        chunked
    }

    /// Input a message (before padding) and output sha256 digest of type Integer
    pub fn sha256(message: &Vec<u8>) -> Integer {
        let digest = hash(MessageDigest::sha256(), message);
        let hash_value = match digest {
            Ok(digest_result) => digest_result,
            Err(_) => unreachable!(),
        };
        let digest_result: &[u8] = &hash_value;
 
        os2ip(digest_result)
    }


    /// Input a message (before padding) and output sha256 digest of type Vec<u16>
    pub fn sha256_to_vecu16(message: &Vec<u8>) -> Vec<u16> {
        let digest_result: Integer = Self::sha256(message);
        let limb_values: Vec<Integer> = create_limb_values(&digest_result, 16, 16);
        vec_int_to_vec_u16(limb_values)
    }

    /// Input a message (before padding) and output sha256 digest of type Vec<u32>
    pub fn sha256_to_vecu32(message: &Vec<u8>) -> Vec<u32> {
        let digest_result: Integer = Self::sha256(message);
        let limb_values: Vec<Integer> = create_limb_values(&digest_result, 32, 8);
        vec_int_to_vec_u32(limb_values)
    }

    /// Input a message (before padding) and output sha256 digest of type BigNatWithLimbMax
    pub fn sha256_to_bignat(message: &Vec<u8>, limb_width: usize, n_limbs: usize) -> BigNatWithLimbMax {
        let digest_result: Integer = Self::sha256(message);
        BigNatWithLimbMax::new(&digest_result, limb_width, n_limbs, false)
    }

    /// Input a message (before padding) and output sha256 digest of type Vec<u64>
    pub fn sha256_to_vecu64(message: &Vec<u8>) -> Vec<u64> {
        let digest_result: Integer = Self::sha256(message);
        let limb_values: Vec<Integer> = create_limb_values(&digest_result, 64, 4);
        vec_int_to_vec_u64(limb_values)
    }

}

