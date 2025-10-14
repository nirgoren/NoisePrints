//! This module includes implementations related to x509 certificates

use openssl::x509::X509;
use openssl::sign::Verifier;
use openssl::hash::MessageDigest;
use openssl::rsa::Rsa;
use openssl::ec::EcKey;
use ed25519_dalek::Signature as Ed25519Signature;
use ed25519_dalek::VerifyingKey;

use openssl::ecdsa::EcdsaSig;
use openssl::{pkey::{PKey, Public}};
use std::convert::TryInto;

use std::fs::File;
use std::io::{Read, Result};
use std::fs::read; 
use std::process::Command;
use std::str;
use rug::Integer;
use crate::rsa::rsa::{RSAPublicKey,RSASignature};
use crate::ecdsa::ecdsa::{ECDSAPublicKey,ECDSASignature,EllipticCurveP256};
use openssl::ec::EcGroupRef;
use crate::hash::hash::DigestAlgorithm;
use crate::convert::{os2ip, bignumref_to_integer};
use crate::eddsa::{
    verifying::{EDDSAPublicKey},
    signature::{EDDSASignature},
    edwards25519::{Edwards25519Pt},
};
use std::convert::TryFrom;
use curve25519_dalek::edwards::CompressedEdwardsY;
use crate::eddsa::edwards25519::{CurveConfig, Ed25519Config};

use crate::conditional_print;

/// Load certificate from .cer file
#[allow(unused)]
fn load_certificate_from_file(certificate_path: &str) -> X509 {
    let certificate_bytes = read(certificate_path)
        .expect("Failed to read issuer certificate file");
     // let issuer_certificate_bytes = include_bytes!("../example_cert/_GTS_CA_1C3.cer");
    let certificate = X509::from_pem(&certificate_bytes)
        .expect("Failed to load certificate");

    certificate
}

/// Issuer key extracted from the issuer certificate
#[derive(Clone)]
pub enum IssuerKey {
    /// RSA public key
    StructRSA(RSAPublicKey),
    /// ECDSA public key
    StructECDSA(ECDSAPublicKey),
    /// EDDSA public key
    StructEDDSA(EDDSAPublicKey),
}

/// Signature extracted from the signed certificate
// #[derive(Clone)]
pub enum Signature {
    /// RSA signature
    StructRSA(RSASignature),
    /// ECDSA signature
    StructECDSA(ECDSASignature),
    /// EDDSA signature
    StructEDDSA(EDDSASignature),
}


/// Some contents of X509 Certificate
// #[derive(Clone)]
pub struct X509Certificate { 
    /// Public key of the issuer
    pub issuer_key: IssuerKey,
    /// Body part of the signed certificate (message)
    pub body: Vec<u8>,
    /// Signature in the signed certificate
    pub signature: Signature,
    /// Digest algorithm
    pub digest_algorithm: DigestAlgorithm,
    /// Signed certificate
    pub signed_certificate: X509,
}

impl X509Certificate {
    /// Create a new X509Certificate instance
    pub fn new(signed_certificate_path: &str, issuer_certificate_path: &str) -> Self {
        let issuer_certificate: X509 = load_certificate_from_file(issuer_certificate_path);
        // Extract the public key from the issuer certificate
        let issuer_public_key = issuer_certificate.public_key().expect("Failed to extract public key");

        // Extract body part of the signed certificate
        let body_bytes: Vec<u8> = extract_body_data(signed_certificate_path);
        // let rsa_key: Rsa<Public> = issuer_public_key.rsa().unwrap();
        // let decode_rsa_key: RSAPublicKey = Self::extract_rsa_public_key(rsa_key);
        let signed_certificate: X509 = load_certificate_from_file(signed_certificate_path);

        let signature_algorithm = signed_certificate.signature_algorithm().object().to_string(); // https://docs.rs/openssl/latest/openssl/ec/struct.EcKey.html

        let digest_algorithm: DigestAlgorithm = DigestAlgorithm::new("sha256").expect("Failed to create digest algorithm");
        
        let signature_bytes: &[u8] = signed_certificate.signature().as_slice();
        let cert: X509Certificate = if signature_algorithm.contains("RSA") {
                let rsa_key: Rsa<Public> = issuer_public_key.rsa().unwrap();
                let decode_key = RSAPublicKey::extract_rsa_public_key(rsa_key);
                let signature_integer: Integer = os2ip(signature_bytes);      
                let rsa_signature: RSASignature = RSASignature{ signature: signature_integer};
                X509Certificate {
                    issuer_key: IssuerKey::StructRSA(decode_key),
                    body: body_bytes,
                    signature: Signature::StructRSA(rsa_signature),
                    digest_algorithm: digest_algorithm,
                    // issuer_certificate: issuer_certificate,
                    signed_certificate: signed_certificate,
                }
        } else if signature_algorithm.contains("ecdsa"){ // https://search.censys.io/certificates/3e65041447192fd8379f12182581005d7937f000cfe102248de704bb480fa4ec
            let ecdsa_sig: EcdsaSig = EcdsaSig::from_der(&signature_bytes).expect("Failed to parse signature");

            let r = ecdsa_sig.r(); 
            let r_integer: Integer = bignumref_to_integer(r).expect("Failed to parse r into Integer");
            let s = ecdsa_sig.s();
            let s_integer: Integer = bignumref_to_integer(s).expect("Failed to parse s into Integer");
            let signature: ECDSASignature = ECDSASignature {
                r: r_integer, 
                s: s_integer,
                signature: ecdsa_sig
            };
            let ec_key: EcKey<Public> = issuer_public_key.ec_key().unwrap();

            let group: &EcGroupRef = ec_key.group();
            // Print the curve name
            let issuerkey: ECDSAPublicKey = if let Some(curve_name) = group.curve_name() {//P256
                                                let curve_long_name: &'static str = curve_name.long_name().expect("Expect curve name");
                                                if curve_long_name == "prime256v1" {
                                                    ECDSAPublicKey {ec_key: ec_key, curve: EllipticCurveP256::new()}
                                                } else {
                                                    panic!("Curve is not prime256v1")
                                                }
                                            } else {
                                                panic!("Curve Name is not available");
                                            };
            
            X509Certificate {
                issuer_key: IssuerKey::StructECDSA(issuerkey),
                body: body_bytes,
                signature: Signature::StructECDSA(signature),
                digest_algorithm: digest_algorithm,
                signed_certificate: signed_certificate,
            }
        } else if signature_algorithm.contains("ED25519") {
            let raw_pk: Vec<u8> = issuer_public_key.raw_public_key().unwrap();
            let pk_slice: &[u8; 32] = raw_pk.as_slice().try_into().unwrap();
            let pk = VerifyingKey::from_bytes(&pk_slice).expect("Failed to parse public key");
            let signature: Ed25519Signature = Ed25519Signature::from_slice(&signature_bytes).expect("Failed to parse signature");
            let _ = pk.verify_strict(&body_bytes, &signature).expect("Failed to verify signature");
            conditional_print!("verify the Ed25519 signature successfully");
            // try to implement the signature verification myself
            let signature = EDDSASignature::try_from(&signature).unwrap();
            conditional_print!("signature: {:?}", signature);

            // Try to recompute R since it is private
            let pk_compressed: CompressedEdwardsY = CompressedEdwardsY(*pk.as_bytes());
            let eddsa_pk = EDDSAPublicKey(pk_compressed);
            let verify_result: bool = eddsa_pk.verify_strict(&signature, &body_bytes);
            assert!(verify_result, "Failed to verify the signature");
            let generator = curve25519_dalek::constants::ED25519_BASEPOINT_POINT.compress();
            let generator_int = Edwards25519Pt::from_compressed(&generator);
            assert!(generator_int.compress() == generator, "Failed to verify the generator");
            assert!(generator_int == CurveConfig::new().generator, "Failed to verify the generator");
            let double_generator = curve25519_dalek::constants::ED25519_BASEPOINT_POINT + curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
            let double_generator_expect = Edwards25519Pt::from_compressed(&double_generator.compress());
            let generator_int_double = Edwards25519Pt::point_add(&generator_int, &generator_int);
            assert!(generator_int_double == double_generator_expect, "Failed to verify the double generator");
            let test_double_point = generator_int_double.compress();
            assert!(test_double_point == double_generator.compress(), "Failed to verify the double generator");

            X509Certificate {
                issuer_key: IssuerKey::StructEDDSA(EDDSAPublicKey(pk_compressed)),
                body: body_bytes,
                signature: Signature::StructEDDSA(signature),
                digest_algorithm: digest_algorithm,
                signed_certificate: signed_certificate,
            }

        }
        else {
            panic!("This signature algorithm has not been implemented {}", signature_algorithm);
        };
        cert
    }

    /// Create a vector of X509Certificate instances from a vector of certificate paths
    pub fn new_from_paths(cert_paths: Vec<&str>) -> Vec<Self> {
        let mut certificates: Vec<Self> = Vec::new();

        for i in 0..(cert_paths.len()-1) { // cert_paths[0] is the leaf certificate and the last one is the certificate of root CA
            let signed_cert_path = cert_paths[i];
            let issuer_cert_path = cert_paths[i + 1];

            let certificate = X509Certificate::new(signed_cert_path, issuer_cert_path);
            certificates.push(certificate);
        }

        certificates
    }

    #[cfg(feature = "debug_prints")]
    /// Print the certificate for debug only
    pub fn print_for_test(&self) -> bool {
        if let IssuerKey::StructRSA(rsa_key) = &self.issuer_key {
            conditional_print!("Modulus of issuer Key: {:?}", rsa_key.modulus);
            let modulus_hex: String = rsa_key.modulus.to_string_radix(16);
            conditional_print!("Modulus {}", modulus_hex);
            conditional_print!("Exp of issuer Key: {:?}", rsa_key.exp);
        }

        let hex_string: String = self.body
        .iter()
        .map(|byte| format!("{:02X}", byte))
        .collect::<Vec<String>>()
        .join(" ");

        conditional_print!("Body: {}", hex_string);
        if let Signature::StructRSA(rsa_signature) = &self.signature {
            conditional_print!("Signature: {}", rsa_signature.signature.to_string());
        }
        true
    }

    #[cfg(feature = "debug_prints")]
    /// Print signature algorithm of the certificate
    pub fn print_signature_algorithm(&self) -> bool {
        conditional_print!("Signature algorithm: {:?}", self.signed_certificate.signature_algorithm().object());
        if let IssuerKey::StructRSA(rsa_key) = &self.issuer_key {
            conditional_print!("Number of bits of modulus of issuer key: {}", rsa_key.modulus.to_string_radix(2).len());
        }
        true
    }

    #[cfg(not(feature = "debug_prints"))]
    /// NOT Print signature algorithm of the certificate
    pub fn print_signature_algorithm(&self) -> bool {
        true
    }
}


#[allow(unused)]
fn extract_body_data(signed_certificate_path: &str) -> Vec<u8> {
    // Run the openssl command to extract the body part
    let output = Command::new("openssl")
        .arg("asn1parse")
        .arg("-in")
        .arg(signed_certificate_path)
        .output()
        .expect("Failed to execute command");

    // Convert the command output to a string
    let output_str = str::from_utf8(&output.stdout).unwrap();

    // Extract the body part from the command output
    let body_line = output_str.lines().nth(1).unwrap();
    let body_start = body_line.split(':').next().unwrap().trim();

    let _ = Command::new("openssl")
        .arg("asn1parse")
        .arg("-in")
        .arg(signed_certificate_path)
        .arg("-strparse")
        .arg(body_start)
        .arg("-out")
        .arg("/tmp/x509-body.bin") // Temporary file path to store the body data
        .arg("-noout")
        .output()
        .expect("Failed to execute command");

    // Read the body data from the temporary file
    let mut body_data = Vec::new();
    let mut body_file = File::open("/tmp/x509-body.bin").expect("Failed to open file");
    body_file.read_to_end(&mut body_data).expect("Failed to read file");

    body_data
}

// fn inner_parse_cert(signed_certificate_path: &str, issuer_certificate_path: &str) -> Result<(PKey<Public>, &[u8], &[u8])> {
fn inner_parse_cert<'a>(
    signed_certificate_path: &'a str, 
    issuer_certificate_path: &'a str
) -> Result<(PKey<Public>, Vec<u8>, Vec<u8>)> {

    let issuer_certificate_bytes = std::fs::read(issuer_certificate_path)
        .expect("Failed to read issuer certificate file");
    let issuer_certificate = X509::from_pem(&issuer_certificate_bytes)
        .expect("Failed to load certificate");

    // Extract the public key from the issuer certificate
    let issuer_public_key: PKey<Public> = issuer_certificate.public_key().expect("Failed to extract public key");
    // Print the public key
    conditional_print!("Issuer Public Key: {:?}", issuer_public_key);

    let signed_certificate_bytes = std::fs::read(signed_certificate_path)
    .expect("Failed to read issuer certificate file");
    let signed_certificate = X509::from_pem(&signed_certificate_bytes)
            .expect("Failed to load certificate");

    conditional_print!("Signature algorithm: {:?}", signed_certificate.signature_algorithm().object());
    // Extract signature from the signed certificate
    let signature = signed_certificate.signature();
    // let signature_bytes: &[u8] = signature.as_slice();
    let signature_bytes = signature.as_slice().to_vec();

    let body_data = extract_body_data(signed_certificate_path);
    conditional_print!("Length of data: {}", body_data.len());
    Ok((issuer_public_key, body_data, signature_bytes))
}
/// Verify signature in the signed certificate (Assume the issuer it claims is trustworthy)
#[allow(unused)]
pub fn verify_sign_from_cert(signed_certificate_path: &str, issuer_certificate_path: &str) -> bool {
    let (issuer_public_key, body_data, signature_bytes) = inner_parse_cert(
                                                            signed_certificate_path, 
                                                            issuer_certificate_path
                                                        ).unwrap();

    // Verify the data // Assume the message digest is sha256
    let mut verifier = Verifier::new(MessageDigest::sha256(), &issuer_public_key).unwrap();
    verifier.update(&body_data).unwrap();
    let verification_result = verifier.verify(&signature_bytes).unwrap();
    assert!(verification_result, "Failed to verify signature");
    verification_result
}

/// Verify Eddsa signature in the signed certificate
#[allow(unused)]
pub fn verify_eddsa_sign_from_cert(signed_certificate_path: &str, issuer_certificate_path: &str) -> bool {
    let (issuer_public_key, body_data, signature_bytes) = inner_parse_cert(
        signed_certificate_path, 
        issuer_certificate_path
    ).unwrap();
    let mut verifier = Verifier::new_without_digest(&issuer_public_key).unwrap();
    let verification_result = verifier.verify_oneshot(&signature_bytes, &body_data).unwrap();
    verification_result
}
#[cfg(test)]
mod tests {
    use crate::parse_cert::*;
    use crate::bignat::bignat::{BigNat};
    use crate::bignat::bignatwithlimbmax::{BigNatWithLimbMax};
    use fxhash::FxHashMap as HashMap;
    use crate::ir::term::Value;
    use crate::rsa::exp::optimal_k;
    #[test]
    fn test_parse_cert() {
        let signed_certificate_path = "./example_cert/cloudflare/www.cloudflare.com.cer";
        let issuer_certificate_path = "./example_cert/cloudflare/Cloudflare_Inc_ECC_CA-3.cer";
        println!("Path of the signed certificate: {}", signed_certificate_path);
        println!("Path of the issuer certificate: {}", issuer_certificate_path);
        let result = verify_sign_from_cert(signed_certificate_path, issuer_certificate_path);
        println!("Certificate verify result: {}", result);
        let cert: X509Certificate = X509Certificate::new(signed_certificate_path, issuer_certificate_path);
        cert.print_signature_algorithm();
    }

    #[test]
    fn test_parse_eddsa_cert() {
        let signed_certificate_path = "./example_cert/eddsa/bc-java/x509-client-ed25519.pem";
        let issuer_certificate_path = "./example_cert/eddsa/bc-java/x509-ca-ed25519.pem";
        println!("Path of the signed certificate: {}", signed_certificate_path);
        println!("Path of the issuer certificate: {}", issuer_certificate_path);
        let result = verify_eddsa_sign_from_cert(signed_certificate_path, issuer_certificate_path);
        println!("Certificate verify result: {}", result);
        let cert: X509Certificate = X509Certificate::new(signed_certificate_path, issuer_certificate_path);
        cert.print_signature_algorithm();
    }

    #[test]
    fn test_cert_validity () {
            let signed_certificate_path = "./example_cert/cloudflare/www.cloudflare.com.cer";
            let issuer_certificate_path = "./example_cert/cloudflare/Cloudflare_Inc_ECC_CA-3.cer";    
            println!("Path of the signed certificate: {}", signed_certificate_path);
            println!("Path of the issuer certificate: {}", issuer_certificate_path);
            let result = verify_sign_from_cert(signed_certificate_path, issuer_certificate_path);
            println!("Certificate verify result: {}", result);
    }

    #[test]
    fn test_verify_rsa () {
        let signed_certificate_path = "./example_cert/_.google.com.cer";
        let issuer_certificate_path = "./example_cert/_GTS_CA_1C3.cer";
        let cert: X509Certificate = X509Certificate::new(signed_certificate_path, issuer_certificate_path);
        if let IssuerKey::StructRSA(rsa_key) = &cert.issuer_key {
            if let Signature::StructRSA(rsa_signature) = &cert.signature {
                let verify_result: bool = rsa_key.verify(&(rsa_signature.signature), &cert.body, &cert.digest_algorithm);
                println!("verify result: {}", verify_result);
                let limbwidth = 32;
                let n_limbs = 64;
                println!("modulus {:?}", rsa_key.modulus);
                let modul_bignat: BigNat = BigNat::new(&rsa_key.modulus, limbwidth, n_limbs);
                println!("modul_bignat {:?}", modul_bignat.limb_values);
                println!("modulus dec str {:?}", rsa_key.modulus.to_string_radix(10));                
                println!("modulus hex str {:?}", rsa_key.modulus.to_string_radix(16));
            } 
        }
    }

    #[test]
    fn test_verify_ecdsa () {
        let signed_certificate_path = "./example_cert/cloudflare/www.cloudflare.com.cer";
        let issuer_certificate_path = "./example_cert/cloudflare/Cloudflare_Inc_ECC_CA-3.cer";   
        let cert: X509Certificate = X509Certificate::new(signed_certificate_path, issuer_certificate_path);
        if let IssuerKey::StructECDSA(ecdsa_key) = &cert.issuer_key {
            if let Signature::StructECDSA(ecdsa_signature) = &cert.signature {
                ecdsa_key.verify_openssl(&ecdsa_signature, &cert.body, &cert.digest_algorithm);
            } 
        }
    }
    #[test]
    fn test_verify_w_standard_group_operations() {
        println!("-----------------running test_verify_w_standard_group_operations-----------------");
        let signed_certificate_path = "./example_cert/cloudflare/www.cloudflare.com.cer";
        let issuer_certificate_path = "./example_cert/cloudflare/Cloudflare_Inc_ECC_CA-3.cer";   
        let cert: X509Certificate = X509Certificate::new(signed_certificate_path, issuer_certificate_path);
        if let IssuerKey::StructECDSA(ecdsa_key) = &cert.issuer_key {
            if let Signature::StructECDSA(ecdsa_signature) = &cert.signature {
                let result: bool = ecdsa_key.verify_w_group_operations(&ecdsa_signature, &cert.body, &cert.digest_algorithm);
                let limbwidth = 86;
                let n_limbs = 3;
                let dynamic = true;
                let messagelength = 20;
                // let messagelength = 100;

                let mut input_map = HashMap::<String, Value>::default();

                assert!(ecdsa_key.generate_witness(limbwidth, n_limbs, &ecdsa_signature, &(cert.body), &(cert.digest_algorithm), "", &mut input_map, messagelength, dynamic));

                println!("Verrify result: {}", result);
            } 
        }
    }
    #[test]
    fn test_verify_w_group_operations_for_circuit() {
        println!("-----------------running test_verify_w_group_operations_for_circuit-----------------");
        let signed_certificate_path = "./example_cert/cloudflare/www.cloudflare.com.cer";
        let issuer_certificate_path = "./example_cert/cloudflare/Cloudflare_Inc_ECC_CA-3.cer";   
        let cert: X509Certificate = X509Certificate::new(signed_certificate_path, issuer_certificate_path);
        if let IssuerKey::StructECDSA(ecdsa_key) = &cert.issuer_key {
            if let Signature::StructECDSA(ecdsa_signature) = &cert.signature {
                ecdsa_key.verify_w_group_operations_for_circuit(&ecdsa_signature, &cert.body, &cert.digest_algorithm);
            } 
        }
    }

    #[test]
    fn test_exp() {
        let k: usize = optimal_k(256);
        println!("k: {}", k);
    }
    #[test]
    fn test_carry_bits() {
        let max_word: Integer = Integer::from(1)<<64;
        let limb_width = 32;
        let former = ((max_word.to_f64() * 2.0).log2() - limb_width as f64).ceil() as usize;
        let carry_bits = (((max_word.to_f64() * 2.0).log2() - limb_width as f64).ceil()
                + 0.1) as usize;
        let test = 0.1 as usize;
        println!("{} carry_bits {} {}", former, carry_bits, test);
    }
    #[test]
    fn test_gpmaxword1() {
        let n_limbs: usize = 64;
        let limb_width: usize = 32;
        let field_mod: Integer = Integer::from_str_radix("52435875175126190479447740508185965837690552500527637822603658699938581184513", 10).unwrap();
        let a: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(100), limb_width, n_limbs, false);
        let b: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(200), limb_width, n_limbs, false);
        let product_ab: BigNatWithLimbMax = a.create_product_nat(&b);

        let q: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(10), limb_width, n_limbs, false);
        let p: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from_str_radix("115792089210356248762697446949407573529996955224135760342422259061068512044369", 10).unwrap(), limb_width, n_limbs, false);
        let r: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(6), limb_width, n_limbs, false);

        let product: BigNatWithLimbMax = q.create_product_nat(&p);
        let res: BigNatWithLimbMax = product.create_addition_nat(&r);
        let steps: Vec<usize> = res.find_n_limbs_for_each_gp(&product_ab, field_mod.clone()); // a is lhs wheras res is the rhs
        println!("length of steps {:?}", steps.len());
        let gp_res_left: BigNatWithLimbMax = product_ab.group_limbs(6, Some(field_mod.clone()));
        let gp_res_right: BigNatWithLimbMax = res.group_limbs(6, Some(field_mod.clone()));
        let aux_const = gp_res_left.compute_aux_const_for_both(&gp_res_right);
        println!("steps {:?}", steps);
        println!("aux_const with {} {:?}", aux_const.len(), aux_const);
    }

    #[test]
    fn test_gpmaxword2_0() { // compute the gpmaxword for the operation: modular multiplication over Fq
        let n_limbs: usize = 8;
        let limb_width: usize = 32;
        let field_mod: Integer = Integer::from_str_radix("52435875175126190479447740508185965837690552500527637822603658699938581184513", 10).unwrap();
        let a: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(100), limb_width, n_limbs, false);
        let b: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(200), limb_width, n_limbs, false);
        let product_ab: BigNatWithLimbMax = a.create_product_nat(&b);

        let q: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(10), limb_width, n_limbs, false);
        let mod_q: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from_str_radix("115792089210356248762697446949407573529996955224135760342422259061068512044369", 10).unwrap(), limb_width, n_limbs, false);
        let r: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(6), limb_width, n_limbs, false);

        let product: BigNatWithLimbMax = q.create_product_nat(&mod_q);
        let res: BigNatWithLimbMax = product.create_addition_nat(&r);
        let steps: Vec<usize> = res.find_n_limbs_for_each_gp(&product_ab, field_mod.clone()); // a is lhs wheras res is the rhs
        println!("length of steps {:?}", steps.len());
        let gp_res_left: BigNatWithLimbMax = product_ab.group_limbs(6, Some(field_mod.clone()));
        let gp_res_right: BigNatWithLimbMax = res.group_limbs(6, Some(field_mod.clone()));
        let aux_const = gp_res_left.compute_aux_const_for_both(&gp_res_right);
        println!("steps with len {} {:?}", steps.len(), steps);
        println!("aux_const with {} {:?}", aux_const.len(), aux_const);
        // what if I change the limbs_per_group
        println!("-------------- If I set the limbs_per_group to be 5 --------------");
        let steps: Vec<usize> = res.find_n_limbs_for_each_gp2(&product_ab, field_mod.clone());
        println!("steps with len {} {:?}", steps.len(), steps);
        let gp_res_left: BigNatWithLimbMax = product_ab.group_limbs2(steps.clone(), Some(field_mod.clone()));
        let gp_res_right: BigNatWithLimbMax = res.group_limbs2(steps.clone(), Some(field_mod.clone()));

        let aux_const = gp_res_left.compute_aux_const_for_both2(&gp_res_right, steps);
        println!("aux_const with {} {:?}", aux_const.len(), aux_const);
    }
    #[test]
    fn test_gpmaxword2_1() { // compute the gpmaxword for the operation "check 3 * x1 * x1 + curve.a == p*quotient + remainder"
        let n_limbs: usize = 8;
        let limb_width: usize = 32;
        let field_mod: Integer = Integer::from_str_radix("52435875175126190479447740508185965837690552500527637822603658699938581184513", 10).unwrap();
        let a: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from_str_radix("115792089210356248762697446949407573530086143415290314195533631308867097853948", 10).unwrap(), limb_width, n_limbs, false);
        let x1: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(200), limb_width, n_limbs, false);
        let squ_x1: BigNatWithLimbMax = x1.create_product_nat(&x1);
        let three_squ_x1: BigNatWithLimbMax = squ_x1.scalar_mult_nat(&Integer::from(3));
        let res_left: BigNatWithLimbMax = three_squ_x1.create_addition_nat(&a);

        let q: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(10), limb_width, n_limbs, false);
        let modulus_p: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from_str_radix("115792089210356248762697446949407573530086143415290314195533631308867097853951", 10).unwrap(), limb_width, n_limbs, false);
        let r: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(6), limb_width, n_limbs, false);

        let product: BigNatWithLimbMax = q.create_product_nat(&modulus_p);
        let res_right: BigNatWithLimbMax = product.create_addition_nat(&r);
        let steps: Vec<usize> = res_left.find_n_limbs_for_each_gp(&res_right, field_mod.clone()); // a is lhs wheras res is the rhs
        println!("length of steps {:?} {:?}", steps.len(), steps);
        let all_except_last_are_the_same = steps.iter().take(steps.len() - 1).all(|&x| x == 6);
        assert!(all_except_last_are_the_same);
        let gp_res_left: BigNatWithLimbMax = res_left.group_limbs(6, Some(field_mod.clone()));
        let gp_res_right: BigNatWithLimbMax = res_right.group_limbs(6, Some(field_mod.clone()));
        let aux_const = gp_res_left.compute_aux_const_for_both(&gp_res_right);
        println!("aux_const with {} {:?}", aux_const.len(), aux_const);
            }
    #[test]
    fn test_gpmaxword3() { // compute the gpmaxword for the operation "check m*y1*2 = p*quotient + left_x"
        let n_limbs: usize = 8;
        let limb_width: usize = 32;
        let field_mod: Integer = Integer::from_str_radix("52435875175126190479447740508185965837690552500527637822603658699938581184513", 10).unwrap();
        let y1: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from_str_radix("115792089210356248762697446949407573530086143415290314195533631308867097853948", 10).unwrap(), limb_width, n_limbs, false);

        let m: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(200), limb_width, n_limbs, false);
        let m_times_y1: BigNatWithLimbMax = m.create_product_nat(&y1);
        let res_left: BigNatWithLimbMax = m_times_y1.scalar_mult_nat(&Integer::from(2));


        let q: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(10), limb_width, n_limbs, false);
        let modulus_p: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from_str_radix("115792089210356248762697446949407573530086143415290314195533631308867097853951", 10).unwrap(), limb_width, n_limbs, false);
        let r: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(6), limb_width, n_limbs, false);
        let product: BigNatWithLimbMax = q.create_product_nat(&modulus_p);
        let res_right: BigNatWithLimbMax = product.create_addition_nat(&r);
        
        let steps: Vec<usize> = res_left.find_n_limbs_for_each_gp(&res_right, field_mod.clone()); // a is lhs wheras res is the rhs
        println!("length of steps {:?} {:?}", steps.len(), steps);
        let all_except_last_are_the_same = steps.iter().take(steps.len() - 1).all(|&x| x == 6);
        assert!(all_except_last_are_the_same);
        let gp_res_left: BigNatWithLimbMax = res_left.group_limbs(6, Some(field_mod.clone()));

        let gp_res_right: BigNatWithLimbMax = res_right.group_limbs(6, Some(field_mod.clone()));
        let aux_const = gp_res_left.compute_aux_const_for_both(&gp_res_right);
        println!("aux_const with {} {:?}", aux_const.len(), aux_const);
    }
    #[test]
    fn test_gpmaxword4() { // purpose of this function is to compute gp_maxwords and gp_aux_const of the following operation
    // 3. x3 = (m * m - 2 * x) mod p <=> (m * m - 2 * x) = p * quotient + remainder <=> m*m = p * quotient + remainder + 2*x
    // Case 1: m * m - 2 * x < 0; In this case, quotient < 0
    // Case 2: m * m - 2 * x >= 0; In this case, quotient >= 0
    // Note that x < 2*p. Thus, we check "m * m + 2 * (2p-x) = p * quotient + remainder"<=> "m * m + 4 * p = p * quotient' + remainder + 2x" instead, and it is ensured that quotient >= 0.
        println!("------------ check m * m + 4 * p = p * quotient + remainder + 2x ------------");
        let n_limbs: usize = 8;
        let limb_width: usize = 32;
        let field_mod: Integer = Integer::from_str_radix("52435875175126190479447740508185965837690552500527637822603658699938581184513", 10).unwrap();
        let m: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from_str_radix("1157920892103562487626974469494075735300861434152903", 10).unwrap(), limb_width, n_limbs, false);
        let squ_m: BigNatWithLimbMax = m.create_product_nat(&m);
        let modulus_p: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from_str_radix("115792089210356248762697446949407573530086143415290314195533631308867097853951", 10).unwrap(), limb_width, n_limbs, false);
        let quadruple_p: BigNatWithLimbMax = modulus_p.scalar_mult_nat(&Integer::from(4));
        let res_left: BigNatWithLimbMax = squ_m.create_addition_nat(&quadruple_p); // m * m + 4 * p

        let x: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(200), limb_width, n_limbs, false);
        let double_x: BigNatWithLimbMax = x.scalar_mult_nat(&Integer::from(2));
        let quotient: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(10), limb_width, n_limbs, false); // number of bits required for quotient is 255 from "compute_n_bits_quotient.py"
        let remainder: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(6), limb_width, n_limbs, false);
        let remainder_plus_dou_x: BigNatWithLimbMax = remainder.create_addition_nat(&double_x);
        let product: BigNatWithLimbMax = quotient.create_product_nat(&modulus_p);
        let res_right: BigNatWithLimbMax = product.create_addition_nat(&remainder_plus_dou_x); // p * quotient + remainder + 2x

        let steps: Vec<usize> = res_left.find_n_limbs_for_each_gp(&res_right, field_mod.clone()); // a is lhs wheras res is the rhs
        println!("length of steps {:?} {:?}", steps.len(), steps);
        let all_except_last_are_the_same = steps.iter().take(steps.len() - 1).all(|&x| x == 6);
        assert!(all_except_last_are_the_same);
        let gp_res_left: BigNatWithLimbMax = res_left.group_limbs(6, Some(field_mod.clone()));
        let gp_res_right: BigNatWithLimbMax = res_right.group_limbs(6, Some(field_mod.clone()));
        let aux_const = gp_res_left.compute_aux_const_for_both(&gp_res_right);
        println!("aux_const with {} {:?}", aux_const.len(), aux_const);
        
    }

    // Want: compute y' = -(y + m*(x3-x)) % p
    // Approach 1: 1. Compute y3' = y + m * x3 % p; 2. Compute y' = (m*x-y3')% p
    // Approach 2: Directly compute y' = -(y + m*(x3-x)) by checking 2*p*(1+m) + m*x = p*(quotient+2+2*m)+y'+y+m*x3
    #[test]
    fn test_gpmaxword5_1_1() { // purpose of this function is to compute gp_maxwords and gp_aux_const of the following operation
    // 5.1.1. check y + m * x3 = p * quotient + y3'
        println!("------------ check y + m * x3 = p * quotient + y3' ------------");
        let n_limbs: usize = 8;
        let limb_width: usize = 32;
        let field_mod: Integer = Integer::from_str_radix("52435875175126190479447740508185965837690552500527637822603658699938581184513", 10).unwrap();
        let m: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from_str_radix("1157920892103562487626974469494075735300861434152903", 10).unwrap(), limb_width, n_limbs, false);
        let x3: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from_str_radix("12345", 10).unwrap(), limb_width, n_limbs, false);
        let m_times_x3: BigNatWithLimbMax = m.create_product_nat(&x3);
        let y: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from_str_radix("12345", 10).unwrap(), limb_width, n_limbs, false);
        let res_left: BigNatWithLimbMax = y.create_addition_nat(&m_times_x3);

        let modulus_p: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from_str_radix("115792089210356248762697446949407573530086143415290314195533631308867097853951", 10).unwrap(), limb_width, n_limbs, false);
        let quotient: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(10), limb_width, n_limbs, false); // number of bits required for quotient is 255 from "compute_n_bits_quotient.py"
        let y3_prime: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(6), limb_width, n_limbs, false);
        let product: BigNatWithLimbMax = quotient.create_product_nat(&modulus_p);
        let res_right: BigNatWithLimbMax = product.create_addition_nat(&y3_prime); // p * quotient + y3'

        let steps: Vec<usize> = res_left.find_n_limbs_for_each_gp(&res_right, field_mod.clone()); // a is lhs wheras res is the rhs
        println!("length of steps {:?} {:?}", steps.len(), steps);
        let all_except_last_are_the_same = steps.iter().take(steps.len() - 1).all(|&x| x == 6);
        assert!(all_except_last_are_the_same);
        let gp_res_left: BigNatWithLimbMax = res_left.group_limbs(6, Some(field_mod.clone()));
        let gp_res_right: BigNatWithLimbMax = res_right.group_limbs(6, Some(field_mod.clone()));
        let aux_const = gp_res_left.compute_aux_const_for_both(&gp_res_right);
        println!("aux_const with {} {:?}", aux_const.len(), aux_const);
    }
    #[test]
    fn test_gpmaxword5_1_2() { // purpose of this function is to compute gp_maxwords and gp_aux_const of the following operation
    // 5.1.2. check y' = -(y+m*(x3-x))%p <=> m * x - y3' = p*quotient + y' <=> m*x + 2*p = p*(2+quotient) + y' + y3'
        println!("------------ check m*x + 2*p = p*(2+quotient) + y' + y3' ------------");
        let n_limbs: usize = 8;
        let limb_width: usize = 32;
        let field_mod: Integer = Integer::from_str_radix("52435875175126190479447740508185965837690552500527637822603658699938581184513", 10).unwrap();
        let m: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from_str_radix("1157920892103562487626974469494075735300861434152903", 10).unwrap(), limb_width, n_limbs, false);
        let x: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from_str_radix("12345", 10).unwrap(), limb_width, n_limbs, false);
        let m_times_x: BigNatWithLimbMax = m.create_product_nat(&x);
        let modulus_p: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from_str_radix("115792089210356248762697446949407573530086143415290314195533631308867097853951", 10).unwrap(), limb_width, n_limbs, false);
        let double_p: BigNatWithLimbMax = modulus_p.scalar_mult_nat(&Integer::from(2));
        let res_left: BigNatWithLimbMax = m_times_x.create_addition_nat(&double_p);

        let quotient: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(10), limb_width, n_limbs, false); // number of bits required for quotient is 255 from "compute_n_bits_quotient.py"
        let y3_prime: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(6), limb_width, n_limbs, false);
        let y_prime: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(678), limb_width, n_limbs, false);
        let product: BigNatWithLimbMax = quotient.create_product_nat(&modulus_p);
        let res_right: BigNatWithLimbMax = product.create_addition_nat(&y_prime).create_addition_nat(&y3_prime); // p * quotient + y3'

        let steps: Vec<usize> = res_left.find_n_limbs_for_each_gp(&res_right, field_mod.clone()); // a is lhs wheras res is the rhs
        println!("length of steps {:?} {:?}", steps.len(), steps);
        let all_except_last_are_the_same = steps.iter().take(steps.len() - 1).all(|&x| x == 6);
        assert!(all_except_last_are_the_same);
        let gp_res_left: BigNatWithLimbMax = res_left.group_limbs(6, Some(field_mod.clone()));
        let gp_res_right: BigNatWithLimbMax = res_right.group_limbs(6, Some(field_mod.clone()));
        let aux_const = gp_res_left.compute_aux_const_for_both(&gp_res_right);
        println!("aux_const with {} {:?}", aux_const.len(), aux_const);
    }
    #[test] // not finish
    fn test_gpmaxword5_2() { // purpose of this function is to compute gp_maxwords and gp_aux_const of the following operation
    // 5.2. check 2*p*(1+m) + m*x = p*(quotient+2+2*m)+y'+y+m*x3
    // problem: (quotient+2+2*m) can have 257 bits
        println!("------------ check m*x + 2*p = p*(2+quotient) + y' + y3' ------------");
        let n_limbs: usize = 8;
        let limb_width: usize = 32;
        let field_mod: Integer = Integer::from_str_radix("52435875175126190479447740508185965837690552500527637822603658699938581184513", 10).unwrap();
        let m: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from_str_radix("1157920892103562487626974469494075735300861434152903", 10).unwrap(), limb_width, n_limbs, false);
        let x: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from_str_radix("12345", 10).unwrap(), limb_width, n_limbs, false);
        let m_times_x: BigNatWithLimbMax = m.create_product_nat(&x);
        let modulus_p: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from_str_radix("115792089210356248762697446949407573530086143415290314195533631308867097853951", 10).unwrap(), limb_width, n_limbs, false);
        let double_p: BigNatWithLimbMax = modulus_p.scalar_mult_nat(&Integer::from(2));
        let res_left: BigNatWithLimbMax = m_times_x.create_addition_nat(&double_p);

        let quotient: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(10), limb_width, n_limbs, false); // number of bits required for quotient is 255 from "compute_n_bits_quotient.py"
        let y3_prime: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(6), limb_width, n_limbs, false);
        let y_prime: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(678), limb_width, n_limbs, false);
        let product: BigNatWithLimbMax = quotient.create_product_nat(&modulus_p);
        let res_right: BigNatWithLimbMax = product.create_addition_nat(&y_prime).create_addition_nat(&y3_prime); // p * quotient + y3'

        let steps: Vec<usize> = res_left.find_n_limbs_for_each_gp(&res_right, field_mod.clone()); // a is lhs wheras res is the rhs
        println!("length of steps {:?} {:?}", steps.len(), steps);
        let all_except_last_are_the_same = steps.iter().take(steps.len() - 1).all(|&x| x == 6);
        assert!(all_except_last_are_the_same);
        let gp_res_left: BigNatWithLimbMax = res_left.group_limbs(6, Some(field_mod.clone()));
        let gp_res_right: BigNatWithLimbMax = res_right.group_limbs(6, Some(field_mod.clone()));
        let aux_const = gp_res_left.compute_aux_const_for_both(&gp_res_right);
        println!("aux_const with {} {:?}", aux_const.len(), aux_const);
    }
    #[test]
    fn test_gpmaxword6() { // compute the gpmaxword for the operation checking "inv_x * (x1 + p) = p * (quotient + inv_x) + 1 + inv_x * x2"
        let n_limbs: usize = 8;
        let limb_width: usize = 32;
        let field_mod: Integer = Integer::from_str_radix("52435875175126190479447740508185965837690552500527637822603658699938581184513", 10).unwrap();
        let modulus_p: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from_str_radix("115792089210356248762697446949407573530086143415290314195533631308867097853951", 10).unwrap(), limb_width, n_limbs, true); // the modulus is hard-coded

        let inv_x: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(200), limb_width, n_limbs, false);
        let x1: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(200), limb_width, n_limbs, false);
        let x1_plus_p: BigNatWithLimbMax = x1.create_addition_nat(&modulus_p);
        let res_left: BigNatWithLimbMax = inv_x.create_product_nat(&x1_plus_p);

        let q: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(10), limb_width, n_limbs, false);
        let product: BigNatWithLimbMax = q.create_product_nat(&modulus_p);
        let x2: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from_str_radix("115792089210356248762697446949407573530086143415290314195533631308867097853950", 10).unwrap(), limb_width, n_limbs, true); // the modulus is hard-coded
        let inv_x_times_x2: BigNatWithLimbMax = inv_x.create_product_nat(&x2);
        let one: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(1), limb_width, n_limbs, true);
        let remainder: BigNatWithLimbMax = one.create_addition_nat(&inv_x_times_x2);
        let res_right: BigNatWithLimbMax = product.create_addition_nat(&remainder);
        
        let steps: Vec<usize> = res_left.find_n_limbs_for_each_gp(&res_right, field_mod.clone()); // a is lhs wheras res is the rhs
        println!("length of steps {:?} {:?}", steps.len(), steps);
        let all_except_last_are_the_same = steps.iter().take(steps.len() - 1).all(|&x| x == 6);
        assert!(all_except_last_are_the_same);
        let gp_res_left: BigNatWithLimbMax = res_left.group_limbs(6, Some(field_mod.clone()));

        let gp_res_right: BigNatWithLimbMax = res_right.group_limbs(6, Some(field_mod.clone()));
        let aux_const = gp_res_left.compute_aux_const_for_both(&gp_res_right);
        println!("aux_const with {} {:?}", aux_const.len(), aux_const);
    }
    #[test] // x_diff = inverse_mod(x1 - x2, curve.p)
    fn test_gpmaxword7() { // compute the gpmaxword for the operation checking (y1 - y2) * x_diff = p * quotient + m <=> (y1+p) * x_diff = p * (quotient+x_diff) + m + y2 * x_diff
        let n_limbs: usize = 8;
        let limb_width: usize = 32;
        let field_mod: Integer = Integer::from_str_radix("52435875175126190479447740508185965837690552500527637822603658699938581184513", 10).unwrap();
        let modulus_p: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from_str_radix("115792089210356248762697446949407573530086143415290314195533631308867097853951", 10).unwrap(), limb_width, n_limbs, true); // the modulus is hard-coded

        let y1: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(200), limb_width, n_limbs, false);
        let y1_plus_p: BigNatWithLimbMax = y1.create_addition_nat(&modulus_p);
        let x_diff: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(200), limb_width, n_limbs, false);     
        let res_left: BigNatWithLimbMax = y1_plus_p.create_product_nat(&x_diff);

        let q: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(10), limb_width, n_limbs, false);
        let product: BigNatWithLimbMax = q.create_product_nat(&modulus_p);
        let y2: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from_str_radix("115792089210356248762697446949407573530086143415290314195533631308867097853950", 10).unwrap(), limb_width, n_limbs, true); // the modulus is hard-coded
        let y2_times_x_diff: BigNatWithLimbMax = y2.create_product_nat(&x_diff);
        let m: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(200), limb_width, n_limbs, false);     
        let remainder: BigNatWithLimbMax = y2_times_x_diff.create_addition_nat(&m);
        let res_right: BigNatWithLimbMax = product.create_addition_nat(&remainder);
        
        let steps: Vec<usize> = res_left.find_n_limbs_for_each_gp(&res_right, field_mod.clone()); // a is lhs wheras res is the rhs
        println!("length of steps {:?} {:?}", steps.len(), steps);
        let all_except_last_are_the_same = steps.iter().take(steps.len() - 1).all(|&x| x == 6);
        assert!(all_except_last_are_the_same);
        let gp_res_left: BigNatWithLimbMax = res_left.group_limbs(6, Some(field_mod.clone()));

        let gp_res_right: BigNatWithLimbMax = res_right.group_limbs(6, Some(field_mod.clone()));
        let aux_const = gp_res_left.compute_aux_const_for_both(&gp_res_right);
        println!("aux_const with {} {:?}", aux_const.len(), aux_const);
    }
}
// https://docs.rs/ecdsa/latest/ecdsa/