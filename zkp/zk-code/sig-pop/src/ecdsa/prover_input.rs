//! Prover inputs for ECDSA signature verification

use fxhash::FxHashMap as HashMap;
use crate::ir::term::Value;
use rug::Integer;
use crate::bignat::bignatwithlimbmax::{BigNatWithLimbMax, BigNatbWithLimbMax, BigNatModMultWithLimbMax}; //, BigNatExponWithLimbMax};
use crate::parse_cert::{X509Certificate, IssuerKey, Signature};
#[cfg(feature = "spartan")]
use crate::allocate::{map_bool_double_vec}; //, map_bool_double_arr, map_u8_vec, map_u32_double_vec}; //,map_u32, map_bool_double_vec_to_single_vec};

use crate::hash::hash::DigestAlgorithm;
use crate::commitment::{Poseidon, commit_to_point}; //, P256Commit};

use crate::ecdsa::ecdsa::{P256Point, BigNatScalarMult, BigNatPointAdd, BigNatPoint, BigNatPointb, BigNatScalarMultCachedWindow, BigNatScalarMultWindow, EllipticCurveP256, ECDSASignatureVar};
#[cfg(feature = "spartan")]
use crate::ecdsa::ecdsa::{ECDSASignatureBigNat};
use crate::ecdsa::ecdsa::ProverPrecomputeInput;
use crate::ecdsa::sigma::{ECDSASigmaConst, prover_input_for_ecdsa_sigma}; // const
use crate::user_input::{input_number};

#[cfg(feature = "spartan")]
use crate::right_field_arithmetic::field::{ARC_MOD_T256}; //, ARC_MOD_CURVE25519};
#[cfg(feature = "spartan")]
use crate::ecdsa::convert::{scalar_mult_on_point_g, scalar_mult_on_point_p};
#[cfg(feature = "spartan")]
use crate::ecdsa::right_field::PointAddXFpInit;
#[cfg(feature = "spartan")]
use crate::right_field_arithmetic::alloc::{map_field, map_field_double_vec};
#[cfg(feature = "spartan")]
use std::sync::Arc;

#[cfg(feature = "spartan")]
use crate::ecdsa::right_field::{alloc_prover_input_for_single_modmultiply, ScalarMult};
#[cfg(feature = "spartan")]
use core::ops::Mul;
use p256::ProjectivePoint;
use std::path::PathBuf;

use crate::conditional_print;
use std::time::Instant;
use crate::util::timer::print_time;
use crate::bignat::bignat_adv::BigNatInit;
use crate::hash::sha256::{prover_input_for_sha256_adv_inner, n_blocks_to_msg_len};

use crate::ecdsa::ecdsa::{ECDSAPublicKey, ECDSASignatureOri};   

/// allocate z, v, quotientb and carry
fn inner_prover_input_for_single_modmultiply2(a: &BigNatWithLimbMax, b: &BigNatWithLimbMax, modul: &BigNatWithLimbMax, quotient_bits: usize, limbs_per_gp: usize, name: &str, input_map: &mut HashMap::<String, Value>) {
    let mm: BigNatModMultWithLimbMax = BigNatModMultWithLimbMax::new2(&a, &b, &modul, quotient_bits, limbs_per_gp, false);
    
    mm.alloc(name, input_map)
}

/// Prover input for a Verify point addition circuit
pub fn prover_input_for_verifypointadd() -> HashMap<String, Value>{
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
    let point_a: P256Point = EllipticCurveP256::new().g;
    let point_b: P256Point = EllipticCurveP256::new().g.scalar_mult(Integer::from(2));

    inner_prover_input_for_verifypointadd(point_a, point_b, limbwidth, n_limbs, quotient_bits, limbs_per_gp)
}


#[allow(unused)] // not finish
fn inner_prover_input_for_verifypointadd(point_1: P256Point, point_2: P256Point, limb_width: usize, n_limbs: usize, quotient_bits: usize, limbs_per_gp: usize) -> HashMap<String, Value>{
    let mut input_map = HashMap::<String, Value>::default();
    let bignatpointb_1: BigNatPointb = BigNatPointb::new(&point_1, limb_width, n_limbs, false);
    let bignatpointb_2: BigNatPointb = BigNatPointb::new(&point_2, limb_width, n_limbs, false);
    let advanced: bool = false;
    let check_point_add: BigNatPointAdd = BigNatPointAdd::new(point_1.clone(), point_2.clone(), limb_width, n_limbs, limbs_per_gp, advanced);
    let bignatpointb_ouput: BigNatPointb = BigNatPointb::new(&check_point_add.res_point, limb_width, n_limbs, false);

    bignatpointb_1.alloc("pt1b", & mut input_map);
    bignatpointb_2.alloc("pt2b", & mut input_map);
    bignatpointb_ouput.alloc("outputb", & mut input_map);
    check_point_add.plain_alloc("intermediate", "".to_string(), & mut input_map);

    let mut commitments = Vec::new();
    let mut openings = vec![Integer::from_str_radix("52323142543543534351", 10).unwrap(), Integer::from_str_radix("3243234546364232323222", 10).unwrap(), Integer::from_str_radix("24346113123232324565653", 10).unwrap()]; // should be random field element instead
    let points = vec![point_1.clone(), point_2.clone(), check_point_add.res_point.clone()];
    for i in 0..3 {
        commitments.push(commit_to_point(points[i].clone(), openings[i].clone(), limb_width, n_limbs));
    }
    Poseidon::alloc(commitments, openings, "", & mut input_map);
    input_map
}



/// Prover input for PoK of ECDSA signature with public issuer key
pub fn prover_input_for_verifyecdsa(dynamic: bool, cached: bool, advanced: bool, incomplete: bool) -> HashMap<String, Value>{
    let limbwidth: usize = 32;
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
    let window_size: usize = 6;
    let messagelength = 20;
    let prover_input: ProverPrecomputeInput = ProverPrecomputeInput::generate(messagelength);
    let issuer_key_pt: P256Point = P256Point::from_projective_point(prover_input.public_key);
    let curve = EllipticCurveP256::new();
    let signature: ECDSASignatureOri = prover_input.extract_signatureori(&curve.q);
    let digest_result: Integer = DigestAlgorithm::sha256(&(prover_input.message));


    let quotient_bits = n_limbs * limbwidth + 1;

    let mut input_map = HashMap::<String, Value>::default();
    let start = Instant::now();
    if advanced {
        let subtable_bitwidth: usize = 15;
        let digest_result: Integer = DigestAlgorithm::sha256(&(prover_input.message));
        BigNatInit::alloc_from_integer(&digest_result, limbwidth, n_limbs, subtable_bitwidth, &format!("{}digest_result_init", ""), &mut input_map);
        inner_prover_input_for_single_ecdsa_cert_adv(&issuer_key_pt, &signature, &digest_result, curve, limbwidth, n_limbs, quotient_bits, limbs_per_gp, window_size, subtable_bitwidth, incomplete, "", & mut input_map);
    } else { // not tested
        todo!();
    }
    print_time("Time for Compute prover input", start.elapsed(), true);
    input_map    
}


/// Prover input for PoK of ECDSA signature with public issuer key with SHA256 hashing
pub fn prover_input_for_verifyecdsa_whole(n_block_str: String) -> HashMap<String, Value>{
    let limbwidth: usize = 32;
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
    let window_size: usize = 6;
    let quotient_bits = n_limbs * limbwidth + 1;

    let mut input_map = HashMap::<String, Value>::default();

    let msg_len = n_blocks_to_msg_len(n_block_str);
    let prover_input: ProverPrecomputeInput = ProverPrecomputeInput::generate(msg_len);
    let issuer_key_pt: P256Point = P256Point::from_projective_point(prover_input.public_key);
    let curve = EllipticCurveP256::new();
    let signature: ECDSASignatureOri = prover_input.extract_signatureori(&curve.q);

    let subtable_bitwidth: usize = 15;
    let incomplete: bool = true;
    let start = Instant::now();
    let digest_result: Integer = DigestAlgorithm::sha256(&(prover_input.message));
    prover_input_for_sha256_adv_inner(&prover_input.message, false, None, &mut input_map);
    inner_prover_input_for_single_ecdsa_cert_adv(
        &issuer_key_pt, &signature, &digest_result, curve, limbwidth, n_limbs, quotient_bits, limbs_per_gp, window_size, subtable_bitwidth, incomplete, "", & mut input_map
    ); // to do: remove incomplete and put the digest result out
    
    print_time("Time for Compute prover input", start.elapsed(), true);
    input_map    
}


#[cfg(feature = "spartan")]
/// Prover input for PoK of ECDSA signature with public issuer key with right-field arithmetic
pub fn prover_input_for_verifyecdsa_rightfield_whole(n_block_str: String) -> HashMap<String, Value>{
    let limb_width: usize = 32; // input_number("Please enter the limbwidth (16/32/64).").unwrap();
    let n_limbs: usize = 8;
    let limbs_per_gp = 6;

    let messagelength = 20;
    let quotient_bits = n_limbs * limb_width + 1;

    let mut input_map = HashMap::<String, Value>::default();
    let p256_const: ECDSASigmaConst = ECDSASigmaConst::new(limb_width, n_limbs);
    let msg_len = n_blocks_to_msg_len(n_block_str);
    let prover_input: ProverPrecomputeInput = ProverPrecomputeInput::generate(msg_len);
    let issuer_key_pt: ProjectivePoint = prover_input.public_key;
    let digest_result: Integer = DigestAlgorithm::sha256(&(prover_input.message));
    let signature_var: ECDSASignatureVar = prover_input.signature;
    let r: Integer = prover_input.r;

    let start = Instant::now();

    prover_input_for_sha256_adv_inner(&prover_input.message, false, Some(&ARC_MOD_T256), &mut input_map);
    let digest_result: Integer = DigestAlgorithm::sha256(&(prover_input.message));


    inner_prover_input_for_single_ecdsa_cert_rightfield_whole(
        &digest_result,
        issuer_key_pt,
        signature_var,
        r,
        limb_width, 
        n_limbs, 
        quotient_bits, 
        limbs_per_gp, 
        messagelength, 
        "", 
        & mut input_map
    );

    input_map    
}

#[cfg(feature = "spartan")]
fn inner_prover_input_for_single_ecdsa_cert_rightfield_whole(
    digest_result: &Integer,
    verify_key: ProjectivePoint,
    signature: ECDSASignatureVar, 
    sign_r: Integer, 
    limbwidth: usize, 
    n_limbs: usize, 
    quotient_bits: usize, 
    limbs_per_gp: usize, 
    _messagelength: u32, 
    name: &str, 
    input_map: 
    &mut HashMap::<String, Value>
 ) {
    let default_mod: Arc<Integer> = ARC_MOD_T256.clone();
    let modq: Integer = EllipticCurveP256::new().q;
    let curve = EllipticCurveP256::new();

    let prepend: String = if name.is_empty() {name.to_owned()} else {name.to_owned()+"."};

    let q_bignat: BigNatWithLimbMax = BigNatWithLimbMax::new(&EllipticCurveP256::new().q, limbwidth, n_limbs, true);
    let start = Instant::now();
    let issuer_key: P256Point = P256Point::from_projective_point(verify_key);


    issuer_key.alloc_fp(&default_mod, &format!("{}issuerkey", prepend), input_map);

    let r_inv: Integer = sign_r.clone().invert(&modq).expect("Should be a Integer");
    let alt_signature = ECDSASignatureBigNat {
                            r: BigNatWithLimbMax::new(&sign_r, limbwidth, n_limbs, false),
                            s: BigNatWithLimbMax::new(&signature.z, limbwidth, n_limbs, false),
                        };
    alt_signature.alloc(name, input_map);

    // check e * r = quotient * q + h
    let e: &Integer = &(digest_result.clone().mul(&r_inv) % &modq); // h/r mod q
    let e_bignat: BigNatWithLimbMax = BigNatWithLimbMax::new(e, limbwidth, n_limbs, false);
    e_bignat.alloc_from_nat_w_custom_mod(&default_mod, &format!("{}intermediate.e", prepend), input_map);
    alloc_prover_input_for_single_modmultiply(&e_bignat, &alt_signature.r, &q_bignat, quotient_bits, limbs_per_gp, &default_mod, &format!("{}intermediate.mm_for_e", prepend), input_map);
    // compute R = (pk * G^e)^{1/z}
    let e_times_g: ProjectivePoint = scalar_mult_on_point_g(e);
    let z_times_big_r: ProjectivePoint = verify_key + e_times_g;
    let z_inv: Integer = signature.z.clone().invert(&modq).expect("Should be a Integer");
    let big_r: ProjectivePoint = scalar_mult_on_point_p(&z_inv, z_times_big_r);
    let big_r_p256: P256Point = P256Point::from_projective_point(big_r);

    let mut mm_for_scalmul: Vec<ScalarMult> = Vec::new();
    let e_bignatb: BigNatbWithLimbMax = BigNatbWithLimbMax::from_bignat(&e_bignat);
    mm_for_scalmul.push(ScalarMult::new(&e_bignatb, &curve.g.neg(), &curve));
    let z_bignatb: BigNatbWithLimbMax = BigNatbWithLimbMax::new(&signature.z, limbwidth, n_limbs, false);
    mm_for_scalmul.push(ScalarMult::new(&z_bignatb, &big_r_p256, &curve));
    ScalarMult::alloc_vec_w_modulus(&mm_for_scalmul, &default_mod, &format!("{}intermediate.mm_for_scalmul", prepend), input_map);

    // allocate y-coordinate of R
    map_field(&big_r_p256.y, &default_mod, &format!("{}intermediate.R_y", prepend), input_map);
    
    let right: P256Point = P256Point::from_projective_point(z_times_big_r);
    let left: P256Point = P256Point::from_projective_point(e_times_g.neg());
    let partialadd = PointAddXFpInit::new(&sign_r, &big_r_p256.x, &left, &right, &curve);
    partialadd.alloc(&default_mod, &format!("{}intermediate.partialadd", prepend), input_map);
    print_time("Time for Compute prover input", start.elapsed(), true);
}


#[cfg(feature = "spartan")]
/// Prover input for PoK of ECDSA signature with public issuer key with right-field arithmetic with hashing
pub fn prover_input_for_verifyecdsa_rightfield() -> HashMap<String, Value>{
    let signed_certificate_path = "./example_cert/cloudflare/www.cloudflare.com.cer";
    let issuer_certificate_path = "./example_cert/cloudflare/Cloudflare_Inc_ECC_CA-3.cer";  
    let is_verbose = false;


    let cert: X509Certificate = X509Certificate::new(signed_certificate_path, issuer_certificate_path);
    if is_verbose {
        conditional_print!("Path of the signed certificate: {}", signed_certificate_path);
        conditional_print!("Path of the issuer certificate: {}", issuer_certificate_path);
        cert.print_signature_algorithm();
    }

    let limbwidth: usize = 32; // input_number("Please enter the limbwidth (16/32/64).").unwrap();
    let n_limbs: usize = 8;
    let limbs_per_gp = 6;

    let messagelength = 20;
    let quotient_bits = n_limbs * limbwidth + 1;

    let mut input_map = HashMap::<String, Value>::default();

    let digest_result: Integer = DigestAlgorithm::sha256(&(cert.body));
    BigNatbWithLimbMax::alloc_from_integer(&digest_result, limbwidth, n_limbs, "digest_resultb", &mut input_map);

    inner_prover_input_for_single_ecdsa_cert_rightfield(
        &digest_result,
        &cert, 
        limbwidth, 
        n_limbs, 
        quotient_bits, 
        limbs_per_gp, 
        messagelength, 
        "", 
        & mut input_map
    );

    input_map    
}

#[cfg(feature = "spartan")]
fn inner_prover_input_for_single_ecdsa_cert_rightfield(
    digest_result: &Integer,
    cert: &X509Certificate, 
    limbwidth: usize, 
    n_limbs: usize, 
    quotient_bits: usize, 
    limbs_per_gp: usize, 
    _messagelength: u32, 
    name: &str, 
    input_map: 
    &mut HashMap::<String, Value>
 ) {
    let default_mod: Arc<Integer> = ARC_MOD_T256.clone();
    let modq: Integer = EllipticCurveP256::new().q;
    let curve = EllipticCurveP256::new();

    let prepend: String = if name.is_empty() {name.to_owned()} else {name.to_owned()+"."};

    let q_bignat: BigNatWithLimbMax = BigNatWithLimbMax::new(&EllipticCurveP256::new().q, limbwidth, n_limbs, true);
    if let IssuerKey::StructECDSA(ecdsa_key) = &cert.issuer_key {
        if let Signature::StructECDSA(ecdsa_signature) = &cert.signature {
            let start = Instant::now();
            // preprocess the certificate
            // let digest_result: Integer = DigestAlgorithm::sha256(&(cert.body));
            // BigNatbWithLimbMax::alloc_from_integer(&digest_result, limbwidth, n_limbs, &format!("{}digest_resultb", prepend), input_map);
            let issuer_key: P256Point = ecdsa_key.to_p256point();
            let issuer_key_projective: ProjectivePoint = issuer_key.to_projective_point();


            issuer_key.alloc_fp(&default_mod, &format!("{}issuerkey", prepend), input_map);

            // instead of allocate (r, s), allocate (r, z)
            let r_inv: Integer = ecdsa_signature.r.clone().invert(&modq).expect("Should be a Integer");
            let z: &Integer = &(ecdsa_signature.s.clone().mul(&r_inv) % &modq); // z = s/r mod q
            let alt_signature = ECDSASignatureBigNat {
                                    r: BigNatWithLimbMax::new(&ecdsa_signature.r, limbwidth, n_limbs, false),
                                    s: BigNatWithLimbMax::new(z, limbwidth, n_limbs, false),
                                };
            alt_signature.alloc(name, input_map);

            // check e * r = quotient * q + h
            let e: &Integer = &(digest_result.clone().mul(&r_inv) % &modq); // h/r mod q
            let e_bignat: BigNatWithLimbMax = BigNatWithLimbMax::new(e, limbwidth, n_limbs, false);
            e_bignat.alloc_from_nat_w_custom_mod(&default_mod, &format!("{}intermediate.e", prepend), input_map);
            alloc_prover_input_for_single_modmultiply(&e_bignat, &alt_signature.r, &q_bignat, quotient_bits, limbs_per_gp, &default_mod, &format!("{}intermediate.mm_for_e", prepend), input_map);

            // compute R = (pk * G^e)^{1/z}
            let e_times_g: ProjectivePoint = scalar_mult_on_point_g(e);
            let z_times_big_r: ProjectivePoint = issuer_key_projective + e_times_g;
            let z_inv: Integer = z.clone().invert(&modq).expect("Should be a Integer");
            let big_r: ProjectivePoint = scalar_mult_on_point_p(&z_inv, z_times_big_r);
            let big_r_p256: P256Point = P256Point::from_projective_point(big_r);

            let mut mm_for_scalmul: Vec<ScalarMult> = Vec::new();
            let e_bignatb: BigNatbWithLimbMax = BigNatbWithLimbMax::from_bignat(&e_bignat);
            mm_for_scalmul.push(ScalarMult::new(&e_bignatb, &curve.g.neg(), &curve));
            let z_bignatb: BigNatbWithLimbMax = BigNatbWithLimbMax::new(z, limbwidth, n_limbs, false);
            mm_for_scalmul.push(ScalarMult::new(&z_bignatb, &big_r_p256, &curve));
            ScalarMult::alloc_vec_w_modulus(&mm_for_scalmul, &default_mod, &format!("{}intermediate.mm_for_scalmul", prepend), input_map);

            // allocate y-coordinate of R
            map_field(&big_r_p256.y, &default_mod, &format!("{}intermediate.R_y", prepend), input_map);
            
            let right: P256Point = P256Point::from_projective_point(z_times_big_r);
            let left: P256Point = P256Point::from_projective_point(e_times_g.neg());
            let partialadd = PointAddXFpInit::new(&ecdsa_signature.r, &big_r_p256.x, &left, &right, &curve);
            partialadd.alloc(&default_mod, &format!("{}intermediate.partialadd", prepend), input_map);
            print_time("Time for Compute prover input", start.elapsed(), true);
        }  else { panic!("Didn't implement other signature algorithms")}
    } else {
        panic!("Didn't implement other signature algorithms")
    }
}

/// allocate z, v, quotientb and carry
fn inner_prover_input_for_single_modmultiply_adv(a: &BigNatWithLimbMax, b: &BigNatWithLimbMax, modul: &BigNatWithLimbMax, quotient_bits: usize, limbs_per_gp: usize, subtable_bitwidth: usize, name: &str, input_map: &mut HashMap::<String, Value>) {
    let mm: BigNatModMultWithLimbMax = BigNatModMultWithLimbMax::new2(&a, &b, &modul, quotient_bits, limbs_per_gp, true); // advanced = true
    a.alloc_adv(subtable_bitwidth, &format!("{}.res_init", name), input_map);
    mm.alloc_adv(subtable_bitwidth, name, input_map);
}

// assume we used cached window method instead of windowed method
fn inner_prover_input_for_single_ecdsa_cert_adv(
    ecdsa_key: &P256Point,
    ecdsa_signature: &ECDSASignatureOri,
    digest_result: &Integer, 
    curve: EllipticCurveP256, //ECDSASigmaConst, 
    limbwidth: usize, 
    n_limbs: usize, 
    quotient_bits: usize, 
    limbs_per_gp: usize, 
    window_size: usize, 
    subtable_bitwidth: usize, 
    incomplete: bool, 
    name: &str, 
    input_map: &mut HashMap::<String, Value>
) {
    let prepend: String = if name.is_empty() {name.to_owned()} else {name.to_owned()+"."};

    // Allocate signature (ECDSASign_init), issuer key (BigNat), digest result (BigNat_init) into the circuit
    ECDSAPublicKey::generate_witness_adv(ecdsa_key, limbwidth, n_limbs, subtable_bitwidth, ecdsa_signature, name, input_map);

    let r_bignat: BigNatWithLimbMax = BigNatWithLimbMax::new(&ecdsa_signature.r, limbwidth, n_limbs, true);
    conditional_print!("r_bignat {:?}", r_bignat.limb_values);
    let q_bignat: BigNatWithLimbMax = BigNatWithLimbMax::new(&curve.q, limbwidth, n_limbs, true);
    conditional_print!("q_bignat {:?}", q_bignat.limb_values);
    let s_inv: Integer = ecdsa_signature.s.clone().invert(&curve.q).expect("Should be a Integer");
    // comptue a = H(m)/s mod q <=> check a*s = q*quotient + H(m) (assuming H(m)<q)
    
    conditional_print!("----------------------------a---------------------------------");
    let a: Integer = digest_result.clone() * s_inv.clone() % curve.q.clone();
    let a_bignat: BigNatWithLimbMax = BigNatWithLimbMax::new(&a, limbwidth, n_limbs, false);
    let s_bignat: BigNatWithLimbMax = BigNatWithLimbMax::new(&ecdsa_signature.s, limbwidth, n_limbs, false);
    let digest_result_bignat: BigNatWithLimbMax = BigNatWithLimbMax::new(&digest_result, limbwidth, n_limbs, false);
    inner_prover_input_for_single_modmultiply_adv(&a_bignat, &s_bignat, &q_bignat, quotient_bits, limbs_per_gp, subtable_bitwidth, "interm_init.mm_for_a", input_map);
    // compute b = r/s mod q <=> check b*s = q*quotient + r
    conditional_print!("----------------------------b---------------------------------");
    let b: Integer = ecdsa_signature.r.clone() * s_inv.clone() % curve.q.clone();
    let b_bignat: BigNatWithLimbMax = BigNatWithLimbMax::new(&b, limbwidth, n_limbs, false);
    inner_prover_input_for_single_modmultiply_adv(&b_bignat, &s_bignat, &q_bignat, quotient_bits, limbs_per_gp, subtable_bitwidth, "interm_init.mm_for_b", input_map);
    let g: P256Point = curve.g.clone();

    let pk: P256Point = ecdsa_key.clone(); //ecdsa_key.to_p256point();
    let a_bignatb: BigNatbWithLimbMax = BigNatbWithLimbMax::from_bignat(&a_bignat);

    let advanced: bool = true;
    conditional_print!("Applying cached window method");

    let a_times_g: BigNatScalarMultCachedWindow = if incomplete {BigNatScalarMultCachedWindow::new_incomplete(a.clone(), g.clone(), limbwidth, n_limbs, limbs_per_gp, window_size, advanced)}
                                                    else {BigNatScalarMultCachedWindow::new(a.clone(), g.clone(), limbwidth, n_limbs, limbs_per_gp, window_size, advanced)};
    conditional_print!("================ end cached window method ================");
    a_times_g.alloc_adv(subtable_bitwidth, &format!("{}interm_init.scalarmul_a", prepend), input_map); 
    let a_times_g_res_point = a_times_g.res_point;

    let b_bignatb: BigNatbWithLimbMax = BigNatbWithLimbMax::from_bignat(&b_bignat);
    let b_times_u: BigNatScalarMult = BigNatScalarMult::new(b_bignatb, pk.clone(), limbwidth, n_limbs, limbs_per_gp, advanced); // b*u
    b_times_u.alloc_adv(subtable_bitwidth, &format!("{}interm_init.scalarmul_b", prepend), input_map);
    let a_times_g_bignat_point: BigNatPoint = BigNatPoint::new(&a_times_g_res_point, limbwidth, n_limbs, false);
    let b_times_u_bignat_point: BigNatPoint = BigNatPoint::new(&b_times_u.res_point, limbwidth, n_limbs, false);

    conditional_print!("b_times_pk x: {:?} y: {:?}", b_times_u.res_point.x.clone(), b_times_u.res_point.y.clone());
    let a_times_g_plus_b_times_u: BigNatPointAdd = BigNatPointAdd::new(a_times_g_res_point.clone(), b_times_u.res_point.clone(), limbwidth, n_limbs, limbs_per_gp, advanced);
    
    a_times_g_plus_b_times_u.alloc_for_r_adv(subtable_bitwidth, r_bignat.value.clone().unwrap(), curve.p_minusq_minus1.clone(),  &format!("{}interm_init.mm_for_u_hat", prepend), input_map);

    let r_hat: Integer = a_times_g_plus_b_times_u.res_point.x.clone() % curve.q.clone(); // for debug only
    assert!(r_hat == ecdsa_signature.r.clone()); // for debug only 
}

/// Prover input for PoK of ECDSA signature with public issuer key with sigmabus approach
pub fn prover_input_for_verifyecdsa_sigma() -> HashMap<String, Value>{ // to do
    let signed_certificate_path = "./example_cert/cloudflare/www.cloudflare.com.cer";
    let issuer_certificate_path = "./example_cert/cloudflare/Cloudflare_Inc_ECC_CA-3.cer";   
    conditional_print!("Path of the signed certificate: {}", signed_certificate_path);
    conditional_print!("Path of the issuer certificate: {}", issuer_certificate_path);
    let cert: X509Certificate = X509Certificate::new(signed_certificate_path, issuer_certificate_path);
    cert.print_signature_algorithm();
    let limb_width: usize = 32; // input_number("Please enter the limb_width (16/32/64).").unwrap();
    let n_limbs: usize;
    let limbs_per_gp;
    if limb_width == 64 {
        n_limbs = 4;
        limbs_per_gp = 2;
    } else if limb_width == 32 {
        n_limbs = 8;
        limbs_per_gp = 6;
    } else if limb_width == 16 {
        n_limbs = 16;
        limbs_per_gp = 14;
    } else {
        eprintln!("Unsupported limb_width");
        return HashMap::<String, Value>::default();
    }
    let window_size: usize = 6; // input_number("Please enter the window size (5-10).").unwrap();
    let quotient_bits = n_limbs * limb_width + 1;

    let subtable_bitwidth: usize = 10;
    let pf_sigma_path = PathBuf::from("pi_sigma");

    let mut input_map = HashMap::<String, Value>::default();
    let p256_const: ECDSASigmaConst = ECDSASigmaConst::new(limb_width, n_limbs);
    let prover_input: ProverPrecomputeInput = ProverPrecomputeInput::generate(53);
    let issuer_key_pt: ProjectivePoint = prover_input.public_key;
    let digest_result: Integer = DigestAlgorithm::sha256(&(prover_input.message));
    let signature_var: ECDSASignatureVar = prover_input.signature;
    let r: Integer = prover_input.r;
    let start = Instant::now();
    BigNatInit::alloc_from_integer(&digest_result, limb_width, n_limbs, subtable_bitwidth, format!("{}digest_result_init", "").as_str(), & mut input_map);
    prover_input_for_ecdsa_sigma(
        issuer_key_pt,
        signature_var, 
        r.clone(), 
        digest_result.clone(), 
        p256_const, 
        limb_width, 
        n_limbs, 
        quotient_bits, 
        limbs_per_gp, 
        window_size, 
        subtable_bitwidth, 
        pf_sigma_path,
        "", 
        & mut input_map);
        print_time("Time for Compute prover input", start.elapsed(), true);
    input_map
}

/// Prover input for PoK of ECDSA signature with public issuer key with sigmabus approach with hash
pub fn prover_input_for_verifyecdsa_sigma_whole(n_block_str: String) -> HashMap<String, Value>{ // to do
    let limb_width: usize = 32; // input_number("Please enter the limb_width (16/32/64).").unwrap();
    let n_limbs: usize;
    let limbs_per_gp;
    if limb_width == 64 {
        n_limbs = 4;
        limbs_per_gp = 2;
    } else if limb_width == 32 {
        n_limbs = 8;
        limbs_per_gp = 6;
    } else if limb_width == 16 {
        n_limbs = 16;
        limbs_per_gp = 14;
    } else {
        eprintln!("Unsupported limb_width");
        return HashMap::<String, Value>::default();
    }
    let window_size: usize = 6; // input_number("Please enter the window size (5-10).").unwrap();
    let quotient_bits = n_limbs * limb_width + 1;

    let subtable_bitwidth: usize = 10;
    let pf_sigma_path = PathBuf::from("pi_sigma");

    let mut input_map = HashMap::<String, Value>::default();
    let p256_const: ECDSASigmaConst = ECDSASigmaConst::new(limb_width, n_limbs);
    let msg_len = n_blocks_to_msg_len(n_block_str);
    let prover_input: ProverPrecomputeInput = ProverPrecomputeInput::generate(msg_len);
    let issuer_key_pt: ProjectivePoint = prover_input.public_key;
    let digest_result: Integer = DigestAlgorithm::sha256(&(prover_input.message));
    let signature_var: ECDSASignatureVar = prover_input.signature;
    let r: Integer = prover_input.r;
    let start = Instant::now();
    prover_input_for_sha256_adv_inner(&prover_input.message, false, None, &mut input_map);
    prover_input_for_ecdsa_sigma(
        issuer_key_pt,
        signature_var, 
        r.clone(), 
        digest_result.clone(), 
        p256_const, 
        limb_width, 
        n_limbs, 
        quotient_bits, 
        limbs_per_gp, 
        window_size, 
        subtable_bitwidth, 
        pf_sigma_path,
        "", 
        & mut input_map);
        print_time("Time for Compute prover input", start.elapsed(), true);
    input_map
}

#[cfg(feature = "spartan")]
/// Prover input for a spartan-curve25519 circuit with similar number of constraints as the spartan-t256 circuit
pub fn prover_input_for_spartantest(modulus: &Arc<Integer>) -> HashMap<String, Value>{
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
    let mut input_map = HashMap::<String, Value>::default();
    map_field_double_vec(&matrix, modulus, "A", &mut input_map);
    map_field_double_vec(&matrix, modulus, "B", &mut input_map);
    map_bool_double_vec(&bool_matrix, "C", &mut input_map);

    input_map
}