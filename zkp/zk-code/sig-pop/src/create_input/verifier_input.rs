//use std::sync::Arc;
use fxhash::FxHashMap as HashMap;
use crate::ir::term::Value;
//use circ::util::field::DFL_T;
// use circ_fields::FieldT;
#[cfg(feature = "spartan")]
use rug::Integer;
// use std::convert::TryInto;
// use rug::ops::Pow;
// use std::assert;
// use circ::cfg::{
//     clap::{self, ValueEnum},
// };
// use crate::cfg::{
//     clap::{self, ValueEnum},
// };
// use std::fs::{File, read_to_string};
// use std::fs::File;
// use std::io::{Read, Result};

// use crate::bignat::{BigNat, BigNatModMult, BigNatb};
// use crate::bignat::bignat::{BigNat, BigNatExpon};
// use crate::bignat::bignatwithlimbmax::{BigNatWithLimbMax, BigNatbWithLimbMax, BigNatModMultWithLimbMax, BigNatExponWithLimbMax};

// use crate::convert::{bool_to_value, str_to_field, u64_to_value};
// use crate::allocate::{map_bool_double_vec, map_bool_double_arr, map_u8, map_u32, map_u8_vec, map_u32_double_vec}; //, map_bool_double_vec_to_single_vec};


// use crate::commitment::{Poseidon, commit_to_scalar, commit_to_point}; //, P256Commit};
// use crate::ecdsa::ecdsa::{P256Point, BigNatScalarMult, BigNatPointAdd, BigNatPoint, BigNatPointb, BigNatScalarMultCachedWindow, BigNatScalarMultWindow, EllipticCurveP256, ECDSASignatureVar, ECDSASignatureBigNat};
// use crate::ecdsa::sigma::{ECDSASigmaConst, prover_input_for_ecdsa_sigma, verifier_input_for_ecdsa_sigma}; // const
use crate::eddsa::sigma::verifier_input_for_eddsa_sigma;
#[cfg(feature = "spartan")]
use crate::right_field_arithmetic::alloc::{map_field_double_vec};
#[cfg(feature = "spartan")]
use crate::right_field_arithmetic::field::{ARC_MOD_CURVE25519, ARC_MOD_T256, ARC_MOD_T25519};
#[cfg(feature = "spartan")]
use crate::ecdsa::verifier_input::{
    verifer_input_for_ecdsa_rightfield,
    verifer_input_for_ecdsa_rightfield_whole
};
// use crate::ecdsa::convert::{scalar_mult_on_point_g, scalar_mult_on_point_p};
// use crate::ecdsa::right_field::PointAddXFpInit;
// use p256::ProjectivePoint;
// use crate::right_field_arithmetic::alloc::map_field;
// use core::ops::Mul;
#[cfg(feature = "spartan")]
use std::sync::Arc;
// use crate::ecdsa::right_field::{self, alloc_prover_input_for_single_modmultiply, ScalarMult};

use super::create_input::{ComputeType, PfCurve};
// use super::create_input::{ComputeType, Party, input_for_verifyscalmul};

// use crate::ecdsa::verifier_input::{verifier_input_for_ecdsa, verifer_input_for_ecdsa_sigma, verifier_input_for_verifypointadd};
use crate::ecdsa::verifier_input::{verifer_input_for_ecdsa_sigma};
use crate::ecdsa::verifier_input::{verifier_input_for_ecdsa};
use crate::hash::sha256::{verifier_input_for_sha256_ori, verifier_input_for_sha256_adv};
use crate::rsa::verifier_input::{verifier_input_for_verifyrsa};
use crate::pcs::pcs::{verifier_circuit1, verifier_circuit2};

// fn verifier_input_for_unusedvar() -> HashMap<String, Value>{
//     let mut input_map = HashMap::<String, Value>::default();
//     input_map.insert("x0".to_string(), u64_to_value(4));
//     input_map.insert("x1".to_string(), u64_to_value(4));
//     input_map.insert("x2".to_string(), u64_to_value(0));
//     input_map.insert("return".to_string(), u64_to_value(16));
//     input_map
// }

// fn verifier_input_for_fieldmax() -> HashMap<String, Value>{
//     let x = "5883134975370231444140612170814698975570178598892810303949601208329168084134";
//     let mut input_map = HashMap::<String, Value>::default();
//     input_map.insert("return".to_string(), str_to_field(x));
//     input_map
// }

// fn verifier_input_for_testfun() -> HashMap<String, Value>{
//     let mut input_map = HashMap::<String, Value>::default();
//     input_map.insert("return".to_string(), bool_to_value(true));
//     input_map
// }

// fn verifier_input_for_modexpon() -> HashMap<String, Value>{
//     let limbwidth = 121;
//     let n_limbs = 34;
//     let modul: BigNat = BigNat::new(&Integer::from_str_radix("127", 10).unwrap(), limbwidth, n_limbs);
//     let mut input_map = HashMap::<String, Value>::default();
//     modul.alloc_from_nat("modul", &mut input_map);
//     input_map.insert("return".to_string(), bool_to_value(true));
//     input_map
// }


// fn verifier_input_return_true() -> HashMap<String, Value>{
//     let mut input_map = HashMap::<String, Value>::default();
//     input_map.insert("return".to_string(), bool_to_value(true));
//     input_map
// }




#[cfg(feature = "spartan")]
fn matrix_multiply_and_conditionally_increment(
    a: &Vec<Vec<Integer>>,
    b: &Vec<Vec<Integer>>,
    c: &Vec<Vec<bool>>,
) -> Vec<Vec<Integer>> {
    let p = a.len(); // Assuming square matrices
    let mut ab = vec![vec![Integer::from(0); p]; p]; // Initialize the result matrix with zeros.

    for i in 0..p {
        for j in 0..p {
            for k in 0..p {
                let product = &a[i][k] * &b[k][j];
                ab[i][j] += product;
            }
            if c[i][j] {
                ab[i][j] += Integer::from(1);
            }
        }
    }
    ab
}

#[cfg(feature = "spartan")]
#[allow(unused)]
fn verifier_input_for_spartantest(modulus: &Arc<Integer>) -> HashMap<String, Value>{
    let p: usize = 19;
    let mut matrix = vec![vec![Integer::from(0); p]; p];
    let mut bool_matrix = vec![vec![false; p]; p];
    for i in 0..p {
        for j in 0..p {
            matrix[i][j] = Integer::from(i*j);
            if i*j % 2 == 1 {
                bool_matrix[i][j] = true;
            }
        }
    }
    let result = matrix_multiply_and_conditionally_increment(&matrix, &matrix, &bool_matrix);
    let mut input_map = HashMap::<String, Value>::default();
    map_field_double_vec(&matrix, modulus, "A", &mut input_map);
    // map_bool_double_vec(&bool_matrix, "C", &mut input_map);
    map_field_double_vec(&result, modulus, "return", &mut input_map);
    // input_map.insert("return".to_string(), bool_to_value(true)); // to do

    input_map
}


/// Create verifier input
pub fn create_verifier_input(compute: ComputeType, aux_input: String, pfcurve: &PfCurve) -> HashMap<String, Value> {
    // let print_msg = true;
    // let start = Instant::now();
    let result = match compute {
        ComputeType::EddsaSigma => {
            verifier_input_for_eddsa_sigma(5, 55)
        }
        // ComputeType::Unusedvar => verifier_input_for_unusedvar(),
        // ComputeType::FieldMax => verifier_input_for_fieldmax(),
        // ComputeType::ModMultiply => verifier_input_return_true(),
        // ComputeType::ModMultiply2 => verifier_input_return_true(),
        // ComputeType::ModMultiply3 => verifier_input_return_true(),
        // ComputeType::ModMultiply5 => verifier_input_return_true(),
        // ComputeType::ConstModMultiply => verifier_input_return_true(),
        // ComputeType::TestFun => verifier_input_return_true(),
        // ComputeType::ModExpon => verifier_input_for_modexpon(),
        // ComputeType::ModExponRsa2048 => verifier_input_for_modexpon_for_rsa(2048),
        // ComputeType::ModExponRsa2048v3 => verifier_input_for_modexpon_for_rsa_v3(),
        // ComputeType::ModExponRsa2048v4 => verifier_input_for_modexpon_for_rsa_v3(),
        // ComputeType::ConstModExponRsa2048 => verifier_input_return_true(),
        // ComputeType::ModExponRsa4096 => verifier_input_for_modexpon_for_rsa(4096),
        // ComputeType::VerifyRsa2048 => verifier_input_for_verifyrsa(false, 2048, "issuerkey.modulus"),
        // ComputeType::VerifyRsa4096 => verifier_input_for_verifyrsa(false, 4096, "issuerkey.modulus"),
        // ComputeType::VerifyRsaDynamic2048 | ComputeType::VerifyRsaDynamic2048WoHash => verifier_input_for_verifyrsa(true, 2048, "issuerkey.modulus"),
        // ComputeType::VerifyRsaDynamic4096 => verifier_input_for_verifyrsa(true, 4096, "issuerkey.modulus"),
        // ComputeType::VerifyRsaAdv | 
        ComputeType::VerifyRsaAdvComplete => verifier_input_for_verifyrsa(false, 2048, ""),
        ComputeType::VerifyRsaAdvWhole => verifier_input_for_verifyrsa(true, 2048, ""), // to do: add aux input to specify the message length
        // ComputeType::VerifyRsaChain => verifier_input_for_verify_rsachain(true),
        // ComputeType::VerifyECDSA => verifier_input_for_ecdsa(32, 8),
        // ComputeType::VerifyECDSA | ComputeType::VerifyEcdsaAdv | ComputeType::VerifyEcdsaAdvIncompl  => verifier_input_for_ecdsa(),
        ComputeType::VerifyEcdsaAdvIncompl | ComputeType::VerifyEcdsaAdvIncomplWhole  => verifier_input_for_ecdsa(), // to fix
        ComputeType::VerifyEcdsaSigma| ComputeType::VerifyEcdsaSigmaWhole => verifer_input_for_ecdsa_sigma(), // to do: add aux input to specify the message length
        ComputeType::DotProductMag => verifier_circuit1(aux_input),
        ComputeType::Combine => verifier_circuit2(aux_input),
        // ComputeType::VerifyEcdsaAdv => verifier_input_for_ecdsa(), // same as VerifyECDSA since the verifier can do range check itself on the issuer key
        // ComputeType::VerifyPointAdd => verifier_input_for_verifypointadd(),
        // ComputeType::VerifyScalMul => input_for_verifyscalmul(Party::Verifier),
        #[cfg(feature = "spartan")]
        ComputeType::VerifyEcdsaRight => verifer_input_for_ecdsa_rightfield(), // to modify
        #[cfg(feature = "spartan")]
        ComputeType::VerifyEcdsaRightWhole => verifer_input_for_ecdsa_rightfield_whole(),
        #[cfg(feature = "spartan")]
        ComputeType::SpartanTest => verifier_input_for_spartantest(&ARC_MOD_CURVE25519),
        #[cfg(feature = "spartan")]
        ComputeType::SpartanTestT256 => verifier_input_for_spartantest(&ARC_MOD_T256),
        ComputeType::Sha256Ori => verifier_input_for_sha256_ori(aux_input),
        ComputeType::Sha256Adv => verifier_input_for_sha256_adv(aux_input, None),
        #[cfg(feature = "spartan")]
        ComputeType::Sha256AdvSpartan => {
            match pfcurve {
                PfCurve::Curve25519 => verifier_input_for_sha256_adv(aux_input, Some(&ARC_MOD_CURVE25519)),
                PfCurve::T256 => verifier_input_for_sha256_adv(aux_input, Some(&ARC_MOD_T256)),
                PfCurve::T25519 => verifier_input_for_sha256_adv(aux_input, Some(&ARC_MOD_T25519)),
            }
        },
    };
    // print_time("Time for Compute verifier input", start.elapsed(), print_msg); // verify-ecdsa: 7.007793ms
    result
}
