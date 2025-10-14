//! This module defines enums required for the prover input and/or the verifier input

//use std::sync::Arc;
use fxhash::FxHashMap as HashMap;
use crate::ir::term::Value;

use rug::Integer;

use crate::cfg::{
    clap::{self, ValueEnum},
};
use std::fs::File;
use std::io::{Read, Result};

// use crate::bignat::bignat::{BigNat, BigNatModMult, BigNatExpon};
use crate::bignat::bignatwithlimbmax::{BigNatbWithLimbMax};

// use crate::parse_cert::{X509Certificate, IssuerKey, Signature};
use crate::convert::{bool_to_value}; // , str_to_field, u64_to_value
// use crate::allocate::{map_u32}; //, map_bool_double_vec_to_single_vec};

// use crate::hash::hash::DigestAlgorithm;
use crate::commitment::{Poseidon, commit_to_point, commit_to_scalar}; //, P256Commit};
// use crate::ecdsa::ecdsa::{P256Point, BigNatPointAdd, EllipticCurveP256, ECDSASignatureVar};
use crate::ecdsa::ecdsa::{BigNatScalarMultCachedWindow, EllipticCurveP256};

use crate::user_input::{input_number};

// const CAPACITY: usize = 254; //number of bits of FieldT::FBls12381.modulus_arc()

/// Create input for verify scalar multiplication
#[allow(unused)]
pub fn input_for_verifyscalmul(party: Party) -> HashMap<String, Value>{
    let limbwidth: usize = input_number("Please enter the limbwidth (16/32/64).").unwrap();
    let n_limbs: usize;
    let limbs_per_gp;
    if limbwidth == 64 {
        n_limbs = 4;
        limbs_per_gp = 2;
    } else if limbwidth == 32 {
        n_limbs = 8;
        limbs_per_gp = 6;
    } else if limbwidth == 16 {
        n_limbs = 16;
        limbs_per_gp = 14;
    } else {
        eprintln!("Unsupported limbwidth");
        return HashMap::<String, Value>::default();
    }
    let quotient_bits = n_limbs * limbwidth + 1;
    // let scalar: Integer = Integer::from_str_radix("1157920892103562487626974469494", 10).unwrap();
    // let scalar: Integer = Integer::from(1);
    // let scalar: Integer = Integer::from(160);
    let scalar: Integer = Integer::from_str_radix("115792089210356248762697446949407573529996955224135760342422259061068512044367", 10).unwrap();
    // let q: Integer = Integer::from_str_radix("115792089210356248762697446949407573529996955224135760342422259061068512044369", 10).unwrap();



    let window_size: usize = input_number("Please enter the window size (5-10).").unwrap();
    // let point_a: P256Point = EllipticCurveP256::new().g;
    // let point_b: P256Point = EllipticCurveP256::new().g.scalar_mult(Integer::from(2));

    inner_input_for_verifyscalmul(party, scalar, limbwidth, n_limbs, quotient_bits, limbs_per_gp, window_size)
}



#[allow(unused)] 
fn inner_input_for_verifyscalmul(party: Party, scalar: Integer, limbwidth: usize, n_limbs: usize, quotient_bits: usize, limbs_per_gp: usize, window_size: usize) -> HashMap<String, Value>{
    let mut input_map = HashMap::<String, Value>::default();
    let scalar_bignatb: BigNatbWithLimbMax = BigNatbWithLimbMax::new(&scalar, limbwidth, n_limbs, false);
    // let a_bignat: BigNatWithLimbMax = BigNatWithLimbMax::new(&a, limbwidth, n_limbs, false);

    let advanced: bool = false;
    let scalar_times_g: BigNatScalarMultCachedWindow = BigNatScalarMultCachedWindow::new(scalar.clone(), EllipticCurveP256::new().g, limbwidth, n_limbs, limbs_per_gp, window_size, advanced);

    let mut openings = vec![Integer::from_str_radix("52323142543543534351", 10).unwrap(), Integer::from_str_radix("3243234546364232323222", 10).unwrap()]; // should be random field element instead
    
    let mut commitments = Vec::new();
    let n_chunks: usize = (256 + window_size - 1) / window_size;
    commitments.push(commit_to_scalar(scalar.clone(), openings[0].clone(), window_size, n_chunks));
    commitments.push(commit_to_point(scalar_times_g.res_point.clone(), openings[1].clone(), limbwidth, n_limbs));

    match party {
        Party::Prover => {
            scalar_bignatb.alloc_from_natb_to_single_vec("scalar", & mut input_map);
            scalar_times_g.alloc("intermediate", & mut input_map);
            Poseidon::alloc(commitments, openings, "", & mut input_map);
        }
        Party::Verifier => {
            Poseidon::alloc_commitments(commitments, "", & mut input_map);
            input_map.insert("return".to_string(), bool_to_value(true));            
        }
    }
    input_map
}

//To DO: 1. group_limbs 2. why L302 output carry[0] = 1
#[derive(PartialEq, Debug, Clone, ValueEnum)]
/// Compute Type
pub enum ComputeType {
    // /// unused_var.zok
    // Unusedvar,
    // /// field_max.zok
    // FieldMax,
    // /// test_fun.zok
    // TestFun,
    // /// Modular multiplication with private modulus
    // ModMultiply,
    // /// Modular multiplication with private modulus with grouping
    // ModMultiply2,
    // /// Modular multiplication with private modulus with grouping and allowing each limb to have different maxword
    // ModMultiply3,
    // /// Modular multiplication with private modulus with grouping and allowing each limb to have different maxword; modify to allocate correct bits to the quotient
    // ModMultiply5,
    // /// Modular exponentiation
    // ModExpon,
    // /// Modular exponentiation for RSA with 2048-bit modulus
    // ModExponRsa2048,
    // /// Modular exponentiation for RSA with 2048-bit modulus with grouping
    // ModExponRsa2048v3,
    // /// Modular exponentiation for RSA with 2048-bit modulus with grouping
    // ModExponRsa2048v4,
    // /// Modular exponentiation for RSA with 2048-bit **hardcoded** modulus with grouping
    // ConstModExponRsa2048,
    // /// Modular exponentiation for RSA with 4096-bit modulus
    // ModExponRsa4096,
    // /// Verify RSA signature for 2048-bit modulus
    // VerifyRsa2048,
    // /// Verify RSA signature for 4096-bit modulus
    // VerifyRsa4096,
    // /// Verify RSA signature with message of dynamic length for 2048-bit modulus
    // VerifyRsaDynamic2048,
    // /// Verify RSA signature with message of dynamic length for 4096-bit modulus
    // VerifyRsaDynamic4096,
    // /// Verify RSA signature with message of dynamic length for 2048-bit modulus without considering hash
    // VerifyRsaDynamic2048WoHash,
    // /// Verify RSA signature with advanced range check (assuming 2048-bit modulus); w/o checking limbwidth of signature nor digest result
    // VerifyRsaAdv,
    /// Verify RSA signature with advanced range check (assuming 2048-bit modulus) without hash computed in the circuit
    VerifyRsaAdvComplete,
    /// Verify RSA signature with advanced range check (assuming 2048-bit modulus) with hash computed in the circuit with hash
    VerifyRsaAdvWhole,
    /// Eddsa sigma protocol
    EddsaSigma,
    // /// Verify a chain of RSA signature
    // VerifyRsaChain,
    // /// Modular multiplication with constant modulus
    // ConstModMultiply,
    // /// Verify Point addition with Poseidon commitments
    // VerifyPointAdd,
    // /// Verify Scalar multiplication on G with Poseidon commitments
    // VerifyScalMul,
    // /// Verify ECDSA signature with message of dynamic length
    // VerifyECDSA,
    // /// Verify ECDSA signature with message of dynamic length with advanced range check
    // VerifyEcdsaAdv,
    /// Verify ECDSA signature with message of dynamic length with advanced range check and incomplete formula
    VerifyEcdsaAdvIncompl,
    /// Verify ECDSA signature with message of dynamic length with advanced range check, incomplete formula and sha256 hashing
    VerifyEcdsaAdvIncomplWhole,    
    /// Verify ECDSA signature with message of dynamic length with advanced range check, incomplete formula and Sigmabus approach
    VerifyEcdsaSigma,
    /// Verify ECDSA signature with message of dynamic length with advanced range check, incomplete formula and Sigmabus approach with hash
    VerifyEcdsaSigmaWhole,
    #[cfg(feature = "spartan")]
    /// Verify ECDSA signature with message of dynamic length with right-field arithmetic (most likely w/o advanced range check)
    VerifyEcdsaRight,
    #[cfg(feature = "spartan")]
    /// Test the cost for original Spartan instantiated by curve25519
    SpartanTest,
    #[cfg(feature = "spartan")]
    /// Test the cost for original Spartan instantiated by t256
    SpartanTestT256,
    /// Test original sha256
    Sha256Ori,
    /// Test optimized sha256
    Sha256Adv,
    #[cfg(feature = "spartan")]
    /// Test optimized sha256 under Spartan with verifier randomness
    Sha256AdvSpartan,
    #[cfg(feature = "spartan")]
    /// ECDSA in right-field approach
    VerifyEcdsaRightWhole,
    //circuit1
    DotProductMag,
    //circuit2
    Combine,
}

/// Prover/Verifier
pub enum Party {
    /// Prover
    Prover,
    /// Verifier
    Verifier,
}

#[derive(PartialEq, Eq, Debug, Clone, ValueEnum)]
/// Curve for Spartan
pub enum PfCurve {
    /// Curve T256
    T256,
    /// Curve25519
    Curve25519,
    /// Curve T25519
    T25519,
}


/// read file
#[allow(unused)]
fn read_file(file_path: &str) -> Result<Vec<u8>> {
    // Open the file
    let mut file = File::open(file_path)?;

    // Read the file contents into a buffer
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    Ok(buffer)
}





