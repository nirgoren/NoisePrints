//! Verifier inputs for ECDSA signature verification
use fxhash::FxHashMap as HashMap;
use crate::ir::term::Value;
use rug::Integer;

use crate::ecdsa::ecdsa::{P256Point, BigNatPointAdd, EllipticCurveP256}; //, ECDSASignatureVar};
use crate::ecdsa::sigma::{ECDSASigmaConst, verifier_input_for_ecdsa_sigma}; // const
#[cfg(feature = "spartan")]
use std::sync::Arc;
use crate::commitment::{Poseidon, commit_to_point}; //, P256Commit};

use crate::parse_cert::{X509Certificate, IssuerKey}; //, Signature};

use p256::ProjectivePoint;
#[cfg(feature = "spartan")]
use crate::ecdsa::right_field::{self};
use crate::user_input::{input_number};

use crate::convert::bool_to_value;
#[cfg(feature = "spartan")]
use crate::right_field_arithmetic::field::ARC_MOD_T256;

use std::path::PathBuf;
use crate::conditional_print;
use std::time::Instant;
use crate::util::timer::print_time;

use crate::target::r1cs::proof::deserialize_from_file;
use elliptic_curve::sec1::FromEncodedPoint;
use p256::EncodedPoint;
use crate::ecdsa::ecdsa::ECDSAPublicKey;
/// Verifier input for ECDSA signature verification
pub fn verifier_input_for_ecdsa() -> HashMap<String, Value> {
    let signed_certificate_path = "./example_cert/cloudflare/www.cloudflare.com.cer";
    let issuer_certificate_path = "./example_cert/cloudflare/Cloudflare_Inc_ECC_CA-3.cer";   
    conditional_print!("Path of the signed certificate: {}", signed_certificate_path);
    conditional_print!("Path of the issuer certificate: {}", issuer_certificate_path);
    let cert: X509Certificate = X509Certificate::new(signed_certificate_path, issuer_certificate_path);
    let limbwidth: usize = 32;
    let n_limbs: usize = if limbwidth == 64 {4} 
                        else if limbwidth == 32 {8} 
                        else if limbwidth == 16 {16} 
                        else {
                            eprintln!("Unsupported limbwidth");
                            1
                        };
    let input_map = verifier_input_for_ecdsa_inner(cert, limbwidth, n_limbs);
    input_map
}

fn verifier_input_for_ecdsa_inner(cert: X509Certificate, limbwidth: usize, n_limbs: usize) -> HashMap<String, Value> {
    let mut input_map = HashMap::<String, Value>::default();
    if let IssuerKey::StructECDSA(ecdsa_key) = &cert.issuer_key {
        let pk_bytes: Vec<u8> = deserialize_from_file("example_cert/ecdsa_public_key").expect("Bytes from public key file"); 
        let pk_encoded = EncodedPoint::from_bytes(pk_bytes).unwrap();
        let issuer_key_pt = P256Point::from_projective_point(
            ProjectivePoint::from_encoded_point(&pk_encoded).unwrap()
        );
        let start = Instant::now();
        ECDSAPublicKey::allocate_issuer_key(&issuer_key_pt, limbwidth, n_limbs, "", &mut input_map);
        print_time("Time for Compute verifier input", start.elapsed(), true);
    }
    input_map
}

/// Verifier input for ECDSA signature verification with sigmabus approach
pub fn verifer_input_for_ecdsa_sigma() -> HashMap<String, Value>{ // to do
    let signed_certificate_path = "./example_cert/cloudflare/www.cloudflare.com.cer";
    let issuer_certificate_path = "./example_cert/cloudflare/Cloudflare_Inc_ECC_CA-3.cer";   
    conditional_print!("Path of the signed certificate: {}", signed_certificate_path);
    conditional_print!("Path of the issuer certificate: {}", issuer_certificate_path);
    let cert: X509Certificate = X509Certificate::new(signed_certificate_path, issuer_certificate_path);
    cert.print_signature_algorithm();
    let limb_width: usize = 32; //input_number("Please enter the limb_width (16/32/64).").unwrap();
    let n_limbs: usize;
    if limb_width == 64 {
        n_limbs = 4;
    } else if limb_width == 32 {
        n_limbs = 8;
    } else if limb_width == 16 {
        n_limbs = 16;
    } else {
        eprintln!("Unsupported limb_width");
        return HashMap::<String, Value>::default();
    }

    let pf_sigma_path = PathBuf::from("pi_sigma");

    let mut input_map = HashMap::<String, Value>::default();
    if let IssuerKey::StructECDSA(_ecdsa_key) = &cert.issuer_key {
        let pk_bytes: Vec<u8> = deserialize_from_file("example_cert/ecdsa_public_key").expect("Bytes from public key file"); 
        let pk_encoded = EncodedPoint::from_bytes(pk_bytes).unwrap();
        let issuer_key_pt = ProjectivePoint::from_encoded_point(&pk_encoded).unwrap();
        let p256_const: ECDSASigmaConst = ECDSASigmaConst::new(limb_width, n_limbs);
        let start = Instant::now();
        verifier_input_for_ecdsa_sigma(
            issuer_key_pt, 
            p256_const, 
            limb_width, 
            n_limbs, 
            pf_sigma_path,
            "", 
            & mut input_map);
        print_time("Time for Compute verifier input", start.elapsed(), true);
    } else {panic!("Didn't implement other signature algorithms");}
    input_map
}

#[cfg(feature = "spartan")]
/// Verifier input for ECDSA signature verification with right field arithemtic
pub fn verifer_input_for_ecdsa_rightfield() -> HashMap<String, Value>{
    let signed_certificate_path = "./example_cert/cloudflare/www.cloudflare.com.cer";
    let issuer_certificate_path = "./example_cert/cloudflare/Cloudflare_Inc_ECC_CA-3.cer"; 
    let is_verbose = false;  

    let cert: X509Certificate = X509Certificate::new(signed_certificate_path, issuer_certificate_path);
    if is_verbose {
        conditional_print!("Path of the signed certificate: {}", signed_certificate_path);
        conditional_print!("Path of the issuer certificate: {}", issuer_certificate_path);
        cert.print_signature_algorithm();
    }

    let mut input_map = HashMap::<String, Value>::default();
    let default_mod: Arc<Integer> = ARC_MOD_T256.clone();

    if let IssuerKey::StructECDSA(ecdsa_key) = &cert.issuer_key {
        let issuer_key_pt: P256Point = ecdsa_key.to_p256point(); // actually we only need projectivepoint
        right_field::inner_verifier_input_for_ecdsa(&issuer_key_pt, &default_mod, "", & mut input_map);
    } else {panic!("Didn't implement other signature algorithms");}
    input_map
}

#[cfg(feature = "spartan")]
/// Verifier input for ECDSA signature verification with right field arithemtic
pub fn verifer_input_for_ecdsa_rightfield_whole() -> HashMap<String, Value>{
    let pk_bytes: Vec<u8> = deserialize_from_file("example_cert/ecdsa_public_key").expect("Bytes from public key file"); 
    let pk_encoded = EncodedPoint::from_bytes(pk_bytes).unwrap();
    let issuer_key_pt = ProjectivePoint::from_encoded_point(&pk_encoded).unwrap();
    let pk_p256_pt = P256Point::from_projective_point(issuer_key_pt); 
    let mut input_map = HashMap::<String, Value>::default();
    let default_mod: Arc<Integer> = ARC_MOD_T256.clone();

    right_field::inner_verifier_input_for_ecdsa(&pk_p256_pt, &default_mod, "", & mut input_map);

    input_map
}


/// Verifier input for verify point add
pub fn verifier_input_for_verifypointadd() -> HashMap<String, Value>{
    let point_1: P256Point = EllipticCurveP256::new().g;
    let point_2: P256Point = EllipticCurveP256::new().g.scalar_mult(Integer::from(2));

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
    let advanced: bool = false;
    let check_point_add: BigNatPointAdd = BigNatPointAdd::new(point_1.clone(), point_2.clone(), limbwidth, n_limbs, limbs_per_gp, advanced);
    let mut commitments = Vec::new();
    let openings = vec![Integer::from_str_radix("52323142543543534351", 10).unwrap(), Integer::from_str_radix("3243234546364232323222", 10).unwrap(), Integer::from_str_radix("24346113123232324565653", 10).unwrap()]; // should be random field element instead
    let points = vec![point_1.clone(), point_2.clone(), check_point_add.res_point.clone()];
    for i in 0..3 {
        commitments.push(commit_to_point(points[i].clone(), openings[i].clone(), limbwidth, n_limbs));
    }
    inner_verifier_input_for_verifypointadd(commitments)
}

fn inner_verifier_input_for_verifypointadd(commitments: Vec<Integer>) -> HashMap<String, Value>{
    let mut input_map = HashMap::<String, Value>::default();
    Poseidon::alloc_commitments(commitments, "", & mut input_map);
    input_map.insert("return".to_string(), bool_to_value(true));
    input_map
}