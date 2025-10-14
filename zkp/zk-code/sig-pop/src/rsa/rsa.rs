//! Implementations related to rsa signature verification
use rug::Integer;
#[cfg(feature = "debug_prints")]
use openssl::hash::{MessageDigest, hash};
#[cfg(feature = "debug_prints")]
use crate::convert::string_to_vecu8;
// use crate::convert::vecu8_to_integer;
use crate::allocate::{map_bool, map_u8, map_u32_double_vec, map_u32_vec};
use crate::hash::hash::DigestAlgorithm;
use openssl::rsa::Rsa;
use openssl::pkey::Public;
use crate::bignat::bignat::{BigNat, BigNatb};
use std::convert::TryInto;
use fxhash::FxHashMap as HashMap;
use crate::convert::bignumref_to_integer;

use crate::ir::term::Value;

use crate::conditional_print;

/// RSA public key
#[derive(Clone, PartialEq, Eq)]
pub struct RSAPublicKey { 
    /// Modulus
    pub modulus: Integer,
    /// Exponent (usually 65537)
    pub exp: Integer,
}

impl RSAPublicKey {
    #[cfg(feature = "debug_prints")]
    /// Verify RSA signature (RSASSA-PKCS1-V1_5-VERIFY)
    pub fn verify(&self, signature: &Integer, message: &Vec<u8>, digest_algo: &DigestAlgorithm) -> bool {
        // Apply the RSAVP1 verification primitive to the RSA public key and the signature representative to produce an integer message representative m:
        let m = match self.rsavp1(signature) {
            Ok(result) => result,
            Err(_) => unreachable!(),
        };
        let mut m_hex: String = m.to_string_radix(16);
        let removed_char = m_hex.remove(0);
        if removed_char != '1' {return false;}
        let m_octets: Vec<u8> = string_to_vecu8(m_hex.clone());
        // Check that the encoded m has k bits, where k is the number of bits required to represent the modulus
        let len_encodedm = (m_octets.len() + 2) * 8;
        if len_encodedm as u32 != self.modulus.significant_bits() {return false;}

        // Check that the string contains a padding sequence of FF-bytes that ends with a single 00 byte
        let mut start = 0;
        for &octet in &m_octets {
            start += 1;
            if octet == 0 { break;}
            else if octet != 255 { return false;}
        }

        // Check that a short DigestInfo is appended that encodes the name of the hash function (sha256) used to hash `message`
        let digest_info = &m_octets[start..start+digest_algo.identifier.len()];
        assert!(digest_info == digest_algo.identifier.as_slice());

        // Apply the sha256 hash to the message 
        let digest = hash(MessageDigest::sha256(), message);
        let hash_value = match digest {
            Ok(digest_result) => digest_result,
            Err(_) => unreachable!(),
        };
        let digest_result: &[u8] = &hash_value; // digest result for sha256 has 256 bits
        // Check that H(m) is appended finally
        let last_part = &m_octets[start+digest_algo.identifier.len()..];
        if last_part == digest_result {
            // println!("last part is the same as digest result");
            return true;
        }
        false
    }

    /// Doing nothing if the feature is not enabled
    #[cfg(not(feature = "debug_prints"))]
    pub fn verify(&self, _signature: &Integer, _message: &Vec<u8>, _digest_algo: &DigestAlgorithm) -> bool {
        true
    }
    /// Apply the RSAVP1 verification primitive: https://www.rfc-editor.org/rfc/rfc8017#section-5.2.2
    pub fn rsavp1(&self, signature: &Integer) -> Result<Integer, &'static str> {
        // Step 1: Check if signature is within the range [0, modulus - 1]
        let zero = Integer::from(0);

        // Length check
        if signature < &zero || signature >= &self.modulus {
            conditional_print!("signature representative out of range");
            return Err("signature representative out of range");
        }
    
        // Step 2: Calculate m = s^e mod n
        let m = match signature.clone().pow_mod(&self.exp, &self.modulus){
            Ok(power) => power,
            Err(_) => unreachable!(),
        };
        // println!("rsavp1 {:?}", m);
        // Step 3: Output m
        Ok(m)
    }


    /// Allocate issuer key into the circuit
    pub fn allocate_issuer_key(&self, limb_width: usize, n_limbs: usize, name: &str, input_map: &mut HashMap<String, Value>) -> bool {
        let modulus: BigNat = BigNat::new(&(self.modulus), limb_width, n_limbs);
        modulus.alloc_from_nat(name, input_map);
        true
    }

    /// Allocate signatureb (bignatb), modulus (BigNat), padded_message (u32[N][16]) into the circuit
    pub fn generate_witness(&self, limbwidth: usize, n_limbs: usize, signature: &Integer, message: &Vec<u8>, digest_algo: &DigestAlgorithm, name: &str, input_map: &mut HashMap<String, Value>, desired_length: u32, dynamic: bool, hash: bool) -> bool {
        let verify_result: bool = self.verify(signature, message, digest_algo);
        conditional_print!("verify result: {}", verify_result);
        let signature_bignat: BigNat = BigNat::new(signature, limbwidth, n_limbs);
        let signature_bignatb: BigNatb = BigNatb::from_bignat(&signature_bignat);

        let modulus: BigNat = BigNat::new(&(self.modulus), limbwidth, n_limbs);
        
        assert!(self.exp == Integer::from(65537));
        conditional_print!("length of message {}", message.len());

        let append: String = if name.is_empty() {name.to_owned()} else {name.to_owned()+".cert."};

        if hash { // did the hash in the circuit
            let padded_message: Vec<u8> = DigestAlgorithm::padding(message);
            let mut padded_message_double_vec: Vec<Vec<u32>> = DigestAlgorithm::vecu8_to_doublevecu32(&padded_message);
            conditional_print!("The message length is dynamic? {}", dynamic);
            if dynamic {
                let length: u8 = padded_message_double_vec.len().try_into().unwrap();
                conditional_print!("number of inner vec = {}", length);
                let junk_array: Vec<u32> = vec![0; 16]; // This could be anything
                let length_usize: usize = desired_length.try_into().unwrap();
                while padded_message_double_vec.len() < length_usize {
                    padded_message_double_vec.push(junk_array.clone());
                }
                let num_bits_modul = self.modulus.to_string_radix(2).len();
                let modul_type = if num_bits_modul == 4096 {true} else if num_bits_modul == 2048 {false} else {panic!("Modulus should have either 2048 bits or 4096 bits")};
                conditional_print!("Num bits of modulus {}", num_bits_modul);
                if name.is_empty() {
                    map_u8(length, "length", input_map);
                    map_bool(modul_type, "modul_type", input_map);
                } else {
                    map_u8(length, &format!("{}.length", name), input_map);
                    map_bool(modul_type, &format!("{}.modul_type", name), input_map);
                }
            }
            map_u32_double_vec(&padded_message_double_vec, &format!("{}padded_message", name), input_map);
        } else { // input the digest result to the circuit
            if limbwidth == 32 {
                let digest_result: Vec<u32> = DigestAlgorithm::sha256_to_vecu32(message);
                // digest_result.reverse();
                map_u32_vec(&digest_result, &format!("{}digest_result", append), input_map);
            } else {
                unimplemented!("Not support other limbwidth");
            }
        }
        signature_bignatb.alloc_from_natb(&format!("{}signatureb", append), input_map);
        modulus.alloc_from_nat(&format!("{}issuerkey.modulus", append), input_map);

        // if name.is_empty() {
        //     // println!("signature: {:?}", signature_bignatb.limb_values);
        //     signature_bignatb.alloc_from_natb("signatureb", input_map);
        //     modulus.alloc_from_nat("issuerkey.modulus", input_map);
        // } else {
        //     signature_bignatb.alloc_from_natb(&format!("{}.cert.signatureb", name), input_map);
        //     modulus.alloc_from_nat(&format!("{}.cert.issuerkey.modulus", name), input_map);
        // }
        
        verify_result
    }



    /// Extract RSA public key
    pub fn extract_rsa_public_key(rsa_key: Rsa<Public>) -> RSAPublicKey { //modulus: &BigNumRef, exp: &BigNumRef
        // Get a reference to the modulus
        let modulus = rsa_key.n();
        let modulus_integer: Integer = bignumref_to_integer(modulus)
                .expect("Failed to parse modulus into Integer");
        let exp = rsa_key.e();
        let exp_integer: Integer = bignumref_to_integer(exp)
              .expect("Failed to parse exp into Integer");        
        RSAPublicKey {
            modulus: modulus_integer,
            exp: exp_integer,
        }        
    }
}

/// RSA public key
#[derive(Clone, PartialEq, Eq)]
pub struct RSASignature { 
    /// signature
    pub signature: Integer,
}

