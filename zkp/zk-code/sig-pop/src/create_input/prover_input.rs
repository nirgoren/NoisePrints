//! This module creates the prover inputs

use fxhash::FxHashMap as HashMap;
use crate::ir::term::Value;
use rug::Integer;
// use crate::cfg::{
//     clap::{self, ValueEnum},
// };

use crate::bignat::bignat::{BigNat, BigNatModMult};
use crate::bignat::bignatwithlimbmax::{BigNatWithLimbMax, BigNatbWithLimbMax, BigNatModMultWithLimbMax}; //, BigNatExponWithLimbMax};
use crate::parse_cert::{X509Certificate, IssuerKey, Signature};
use crate::convert::{str_to_field, u64_to_value};
// use crate::allocate::{map_bool_double_vec, map_bool_double_arr, map_u8_vec, map_u32_double_vec}; //,map_u32, map_bool_double_vec_to_single_vec};
use crate::allocate::{map_bool_double_vec, map_u8_vec, map_u32_double_vec}; //,map_u32, map_bool_double_vec_to_single_vec};

use crate::hash::hash::DigestAlgorithm;
use crate::hash::sha256::{prover_input_for_sha256_ori, prover_input_for_sha256_adv};
use crate::conditional_print;
use crate::eddsa::sigma::prover_input_for_verifyeddsa_sigma;
// use crate::commitment::{Poseidon, commit_to_point}; //, P256Commit};
// use std::convert::TryInto;
// use crate::ecdsa::ecdsa::{P256Point, BigNatScalarMult, BigNatPointAdd, BigNatPoint, BigNatPointb, BigNatScalarMultCachedWindow, BigNatScalarMultWindow, EllipticCurveP256, ECDSASignatureVar, ECDSASignatureBigNat};
// use crate::ecdsa::sigma::{ECDSASigmaConst, prover_input_for_ecdsa_sigma}; // const
// use crate::user_input::{input_number};

#[cfg(feature = "spartan")]
use crate::right_field_arithmetic::field::{ARC_MOD_T256, ARC_MOD_CURVE25519, ARC_MOD_T25519};
#[cfg(feature = "spartan")]
use crate::ecdsa::prover_input::{prover_input_for_verifyecdsa_rightfield, prover_input_for_spartantest};
use crate::ecdsa::prover_input::{
    prover_input_for_verifyecdsa_sigma, 
    prover_input_for_verifyecdsa_sigma_whole, 
};
#[cfg(feature = "spartan")]
use crate::ecdsa::prover_input::prover_input_for_verifyecdsa_rightfield_whole;

use crate::ecdsa::prover_input::prover_input_for_verifyecdsa;

use crate::ecdsa::prover_input::prover_input_for_verifyecdsa_whole; 

use crate::pcs::pcs::{prover_circuit1, prover_circuit2}; 
// use crate::pcs::pcs::{prover_input_pcs_poseidon, prover_input_pcs_poseidon_preprocess, prover_input_token_revocation}; 
// use crate::ecdsa::convert::{scalar_mult_on_point_g, scalar_mult_on_point_p};
// use crate::ecdsa::right_field::PointAddXFpInit;
// use crate::right_field_arithmetic::alloc::{map_field, map_field_double_vec};
// use std::sync::Arc;

// use crate::ecdsa::right_field::{alloc_prover_input_for_single_modmultiply, ScalarMult};
// use std::time::Instant;
// use crate::util::timer::print_time;
// use core::ops::Mul;
// use std::convert::TryInto;
// use p256::ProjectivePoint;

// use super::create_input::{ComputeType, Party, input_for_verifyscalmul};
use super::create_input::{ComputeType, PfCurve};
// use crate::rsa::rsa_adv::BigNatRSAadv;
// use crate::rsa::prover_input::{prover_input_for_const_modexpon_for_rsa, prover_input_for_verifyrsa, prover_input_for_verifyrsa_adv}; // prover_input_for_modexpon_for_rsa_v3, prover_input_for_modexpon_for_rsa_v4, prover_input_for_modexpon_for_rsa, 
use crate::rsa::prover_input::{prover_input_for_verifyrsa_adv, prover_input_for_verifyrsa_adv_whole}; // prover_input_for_modexpon_for_rsa_v3, prover_input_for_modexpon_for_rsa_v4, prover_input_for_modexpon_for_rsa, 

// fn prover_input_for_unusedvar() -> HashMap<String, Value>{
//     let mut input_map = HashMap::<String, Value>::default();
//     input_map.insert("x0".to_string(), u64_to_value(4));
//     input_map.insert("x1".to_string(), u64_to_value(4));
//     input_map.insert("x2".to_string(), u64_to_value(0));
//     input_map
// }

// fn prover_input_for_fieldmax() -> HashMap<String, Value>{
//     let x = "5883134975370231444140612170814698975570178598892810303949601208329168084134"; 
//     let y = "588313497537023144414061217081469897557017859889281030394960120832916808413";
//     let mut input_map = HashMap::<String, Value>::default();
//     input_map.insert("x".to_string(), str_to_field(x));
//     input_map.insert("y".to_string(), str_to_field(y));
//     input_map
// }

// #[allow(unused)]
// fn prover_input_for_testfun() -> HashMap<String, Value>{
//     let x = "5883134975370231444140612170814698975570178598892810303949601208329168084134";
//     let y = "588313497537023144414061217081469897557017859889281030394960120832916808413";
//     let carry_vec: Vec<Vec<bool>> = vec![vec![true; 11]; 10];
//     let mut input_map = HashMap::<String, Value>::default();
//     input_map.insert("x".to_string(), str_to_field(x));
//     input_map.insert("y".to_string(), str_to_field(y));
//     map_bool_double_arr(&carry_vec, "carry", &mut input_map);
//     input_map
// }

#[allow(unused)]
fn prover_input_for_testfun3() -> HashMap<String, Value>{
    let mut input_map = HashMap::<String, Value>::default();
    input_map.insert("message".to_string(), u64_to_value(4));
    input_map
}

#[allow(unused)]
fn prover_input_for_testfun4() -> HashMap<String, Value>{
    let mut input_map = HashMap::<String, Value>::default();
    let a = "12";
    let b = "34";
    input_map.insert("a".to_string(), str_to_field(a));
    input_map.insert("b".to_string(), str_to_field(b));
    input_map
}


#[allow(unused)]
fn prover_input_for_testpadding() -> HashMap<String, Value>{
    let mut input_map = HashMap::<String, Value>::default();
    // let input: Vec<u8> = vec![123, 0, 0, 0];
    let input: Vec<u8> = vec![1, 2, 3, 4];
    map_u8_vec(&input, "input", &mut input_map);
    // input_map.insert("message".to_string(), u64_to_value(4));
    input_map
}

#[allow(unused)]
fn prover_input_for_testpadding2() -> HashMap<String, Value>{
    let mut input_map = HashMap::<String, Value>::default();
    // let input: Vec<u8> = vec![1, 2, 3, 4];
    let input: Vec<u8> = vec![1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56];
    let padded_input: Vec<u8> = DigestAlgorithm::padding(&input);
    conditional_print!("{:?}", padded_input);
    // conditional_print!("u32::from_be_bytes {}", u32::from_be_bytes([1, 2, 3, 4]));
    let padded_input_zokrates: Vec<Vec<u32>> = DigestAlgorithm::vecu8_to_doublevecu32(&padded_input);
    map_u8_vec(&input, "input", &mut input_map);
    conditional_print!("{:?}", padded_input_zokrates);
    map_u32_double_vec(&padded_input_zokrates, "padded_input", &mut input_map);
    // input_map.insert("message".to_string(), u64_to_value(4));
    input_map
}

#[allow(unused)]
fn prover_input_for_test_bug() -> HashMap<String, Value> {
    let limbwidth = 32;
    let n_limbs = 8;
    let remainder_int: Integer = Integer::from_str_radix("56515219790691171413109057904011688695424810155802929973526481321309856242040", 10).unwrap();
    let remainder: BigNat = BigNat::new(&remainder_int.clone(), limbwidth, n_limbs);
    // let remainderb: BigNatbWithLimbMax = BigNatbWithLimbMax::from_bignat(&remainder);
    let gx: BigNat = BigNat::new(&Integer::from_str_radix("48439561293906451759052585252797914202762949526041747995844080717082404635286", 10).unwrap(), limbwidth, n_limbs);
    let product: BigNat = remainder.create_product_nat(&gx);

    let mut input_map = HashMap::<String, Value>::default();
    BigNatbWithLimbMax::alloc_from_integer(&remainder_int, limbwidth, n_limbs, "remainderb", &mut input_map);
    product.alloc_from_nat("product", &mut input_map);
    input_map
}

#[allow(unused)]
fn prover_input_for_modmultiply(modulus_bits: usize) -> HashMap<String, Value>{
    let limbwidth = 121;
    // let n_limbs = 34;
    let n_limbs = if modulus_bits == 2048 {17} else if modulus_bits == 4096 {34} else {panic!("Unspported modulus type")};
    //let maxword = "5883134975370231444140612170814698975570178598892810303949601208329168084134";
    let a: BigNat = BigNat::new(&Integer::from(10), limbwidth, n_limbs);
    let b: BigNat = BigNat::new(&Integer::from(17), limbwidth, n_limbs);
    let modul: BigNat = BigNat::new(&Integer::from(127), limbwidth, n_limbs);
    inner_prover_input_for_modmultiply(&a, &b, &modul)
}

fn inner_prover_input_for_modmultiply(a: &BigNat, b: &BigNat, modul: &BigNat) -> HashMap<String, Value>{
    let mm: BigNatModMult = BigNatModMult::new(&a, &b, &modul);
    let mut input_map = HashMap::<String, Value>::default();
    a.alloc_from_nat("a", &mut input_map);
    b.alloc_from_nat("b", &mut input_map);
    modul.alloc_from_nat("modul", &mut input_map); 
    mm.z.alloc_from_nat("z", &mut input_map);
    mm.v.alloc_from_nat("v", &mut input_map);
    mm.quotientb.alloc_from_natb("quotientb", &mut input_map);
    mm.remainderb.alloc_from_natb("remainderb", &mut input_map);
    map_bool_double_vec(&mm.carry, "carry", &mut input_map);
    input_map
}

#[allow(unused)]
fn prover_input_for_modmultiply_with_grouping3() -> HashMap<String, Value>{
    let limbwidth = 32;
    let n_limbs = 64;
    let limbs_per_gp = 6;
    let quotient_bits = 2049;
    let signed_certificate_path = "/home/anna/example_cert/_.google.com.cer";
    let issuer_certificate_path = "/home/anna/example_cert/_GTS_CA_1C3.cer";
    let cert: X509Certificate = X509Certificate::new(signed_certificate_path, issuer_certificate_path);
    cert.print_signature_algorithm();
    let a: BigNatWithLimbMax = if let Signature::StructRSA(rsa_signature) = cert.signature {
                            BigNatWithLimbMax::new(&rsa_signature.signature, limbwidth, n_limbs, false)} else {
                                panic!("Signature is not RSA");
                    }; 
    
    let modul: BigNatWithLimbMax = if let IssuerKey::StructRSA(rsa_key) = cert.issuer_key { 
                            BigNatWithLimbMax::new(&rsa_key.modulus, limbwidth, n_limbs, false)} else { // assume the modul is not constant
                                panic!("Issuer key is not RSA");
                        };
    inner_prover_input_for_modmultiply_with_grouping3(&a, &a, &modul, quotient_bits, limbs_per_gp)
}

fn inner_prover_input_for_modmultiply_with_grouping3(a: &BigNatWithLimbMax, b: &BigNatWithLimbMax, modul: &BigNatWithLimbMax, quotient_bits: usize, limbs_per_gp: usize) -> HashMap<String, Value>{
    let mm: BigNatModMultWithLimbMax = BigNatModMultWithLimbMax::new2(&a, &b, &modul, quotient_bits, limbs_per_gp, false);
    
    let mut input_map = HashMap::<String, Value>::default();
    mm.alloc_complete("", &mut input_map);
    // a.alloc_from_nat("a", &mut input_map);
    // b.alloc_from_nat("b", &mut input_map);
    // modul.alloc_from_nat("modul", &mut input_map); 
    // mm.z.alloc_from_nat("z", &mut input_map);
    // mm.v.alloc_from_nat("v", &mut input_map);
    // mm.quotientb.alloc_from_natb_v2("quotientb", &mut input_map);// need to modify
    // mm.remainderb.alloc_from_natb("remainderb", &mut input_map);
    // if let CarryType::CarryOri(carry) = mm.carry {
    //     map_bool_double_vec_to_single_vec(&mm.carry, "carry", &mut input_map);
    // } else {
    //     panic!("Carry is not of type Vec<Vec<bool>>");
    // }
    
    input_map 
}


/// Create prover input
pub fn create_prover_input(compute: ComputeType, aux_input: String, pfcurve: &PfCurve) -> HashMap<String, Value> {
    // let print_msg = true;
    // let start = Instant::now();
    let result = match compute {
        ComputeType::EddsaSigma => {
            let mut message = Vec::new();
            let mlen = aux_input.parse::<usize>().expect("failed to parse message len");
            println!("{}", mlen);
            for i in 0..mlen {
                message.push((i % 256) as u8);
            }
            prover_input_for_verifyeddsa_sigma(message, 5, 55, true)
        }
        // ComputeType::Unusedvar => prover_input_for_unusedvar(),
        // ComputeType::FieldMax => prover_input_for_fieldmax(),
        // ComputeType::ModMultiply => prover_input_for_modmultiply(2048), // modulus has 2048 bits
        // ComputeType::ModMultiply => prover_input_for_modmultiply(4096), // modulus has 4096 bits
        // ComputeType::ModMultiply2 => prover_input_for_modmultiply_with_grouping(),
        // ComputeType::ModMultiply3 => prover_input_for_modmultiply_with_grouping2(),
        // ComputeType::ModMultiply5 => prover_input_for_modmultiply_with_grouping3(),
        // ComputeType::ConstModMultiply => prover_input_for_modmultiply(2048),
        // ComputeType::TestFun => prover_input_for_testfun(),
        // ComputeType::TestFun => prover_input_for_test_bug(),
        // ComputeType::TestFun => prover_input_for_testfun4(), // test ZXI
        // ComputeType::TestFun => prover_input_for_testpadding2(),
        // ComputeType::TestFun => prover_input_for_test_compare2(),
        // ComputeType::TestFun => prover_input_for_pointdouble(),
        // ComputeType::ModExpon => prover_input_for_modexpon(),
        // ComputeType::ModExponRsa2048 => prover_input_for_modexpon_for_rsa(2048),
        // ComputeType::ModExponRsa2048v3 => prover_input_for_modexpon_for_rsa_v3(),
        // ComputeType::ModExponRsa2048v4 => prover_input_for_modexpon_for_rsa_v4(false),
        // ComputeType::ConstModExponRsa2048 => prover_input_for_const_modexpon_for_rsa(),
        // ComputeType::ModExponRsa4096 => prover_input_for_modexpon_for_rsa(4096),
        // ComputeType::VerifyRsa2048 => prover_input_for_verifyrsa(false, true, 2048),
        // ComputeType::VerifyRsa4096 => prover_input_for_verifyrsa(false, true, 4096),
        // ComputeType::VerifyRsaDynamic2048 => prover_input_for_verifyrsa(true, true, 2048),
        // ComputeType::VerifyRsaDynamic4096 => prover_input_for_verifyrsa(true, true, 4096),
        // ComputeType::VerifyRsaDynamic2048WoHash => prover_input_for_verifyrsa(true, false, 2048),
        // ComputeType::VerifyRsaAdv => prover_input_for_verifyrsa_adv(true, false, false, 2048), // ** to test
        ComputeType::VerifyRsaAdvComplete => prover_input_for_verifyrsa_adv(true, false, true, 2048),
        ComputeType::VerifyRsaAdvWhole => prover_input_for_verifyrsa_adv_whole(2048, "", aux_input),
        // ComputeType::VerifyRsaAdv => prover_input_for_verifyrsa_adv(),
        // ComputeType::VerifyRsaChain => prover_input_for_verify_rsachain(true),
        // ComputeType::VerifyECDSA => prover_input_for_verifyecdsa(true, true, false, false), // cached = true; advanced = false
        // ComputeType::VerifyEcdsaAdv => prover_input_for_verifyecdsa(true, true, true, false), // advanced = true; incomplete = false
        ComputeType::VerifyEcdsaAdvIncompl => prover_input_for_verifyecdsa(true, true, true, true), // advanced = true; incomplete = true
        ComputeType::VerifyEcdsaAdvIncomplWhole => prover_input_for_verifyecdsa_whole(aux_input), // same as before but include hashing
        ComputeType::VerifyEcdsaSigma => prover_input_for_verifyecdsa_sigma(),
        ComputeType::VerifyEcdsaSigmaWhole => prover_input_for_verifyecdsa_sigma_whole(aux_input), 
        ComputeType::DotProductMag => prover_circuit1(aux_input),
        ComputeType::Combine => prover_circuit2(aux_input),
        // ComputeType::VerifyPointAdd => prover_input_for_verifypointadd(),
        // ComputeType::VerifyScalMul => input_for_verifyscalmul(Party::Prover),
        #[cfg(feature = "spartan")]
        ComputeType::VerifyEcdsaRight => prover_input_for_verifyecdsa_rightfield(),// prover_input_for_verifyecdsa_right(),
        #[cfg(feature = "spartan")]
        ComputeType::SpartanTest => prover_input_for_spartantest(&ARC_MOD_CURVE25519),
        #[cfg(feature = "spartan")]
        ComputeType::SpartanTestT256 => prover_input_for_spartantest(&ARC_MOD_T256),
        ComputeType::Sha256Ori => prover_input_for_sha256_ori(aux_input),
        ComputeType::Sha256Adv => prover_input_for_sha256_adv(aux_input, None),
        #[cfg(feature = "spartan")]
        ComputeType::Sha256AdvSpartan => {
            match pfcurve {
                PfCurve::Curve25519 => prover_input_for_sha256_adv(aux_input, Some(&ARC_MOD_CURVE25519)),
                PfCurve::T256 => prover_input_for_sha256_adv(aux_input, Some(&ARC_MOD_T256)),
                PfCurve::T25519 => prover_input_for_sha256_adv(aux_input, Some(&ARC_MOD_T25519)),
            }
        },
        #[cfg(feature = "spartan")]
        ComputeType::VerifyEcdsaRightWhole => prover_input_for_verifyecdsa_rightfield_whole(aux_input), // to do
    };
    // print_time("Time for Compute prover input", start.elapsed(), print_msg); // verify-ecdsa: 10.522471ms
    result
}
