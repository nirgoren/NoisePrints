//! Verifier input related to rsa signature verification

use crate::target::r1cs::proof::deserialize_from_file;
use crate::bignat::bignatwithlimbmax::BigNatWithLimbMax;
use fxhash::FxHashMap as HashMap;
use crate::ir::term::Value;
use crate::convert::{bool_to_value};
use crate::conditional_print;
use std::time::Instant;
use crate::util::timer::print_time;
use rug::Integer;
use crate::parse_cert::{X509Certificate, IssuerKey};
/// Compute verifier input for RSA signature verifications
pub fn verifier_input_for_verifyrsa(whole: bool, modulus_bits: usize, name: &str) -> HashMap<String, Value>{
    let signed_certificate_path = "./example_cert/_.google.com.cer";
    let issuer_certificate_path = "./example_cert/_GTS_CA_1C3.cer";
    conditional_print!("Path of the signed certificate: {}", signed_certificate_path);
    conditional_print!("Path of the issuer certificate: {}", issuer_certificate_path);
    let cert: X509Certificate = X509Certificate::new(signed_certificate_path, issuer_certificate_path);
    let limbwidth = 32;
    let n_limbs = 64;
    if modulus_bits != 2048 {
        todo!("Implement other modulus bits");
    }
    let mut input_map = HashMap::<String, Value>::default();
    if let IssuerKey::StructRSA(rsa_key) = cert.issuer_key {
        let modulus: Integer = if whole {deserialize_from_file("example_cert/rsa_modulus").unwrap()} 
                                else {rsa_key.modulus};
        let start = Instant::now();
        inner_verifier_for_rsa(&modulus, limbwidth, n_limbs, name, &mut input_map);
        print_time("Time for Compute verifier input", start.elapsed(), true);
    } else {
        panic!("The issuer key is not RSA key");
    }
    input_map
}

fn inner_verifier_for_rsa(
    rsa_modulus: &Integer,
    limbwidth: usize, 
    n_limbs: usize, 
    name: &str, 
    input_map: &mut HashMap::<String, Value>
){
    let prepend = if name.is_empty() {name.to_owned()} else {name.to_owned()+"."};
    let modulus_bignat: BigNatWithLimbMax = BigNatWithLimbMax::new(rsa_modulus, limbwidth, n_limbs, false); // assuming the modulus is non-constant
    modulus_bignat.alloc_from_nat(&format!("{}issuerkey", prepend), input_map);
    input_map.insert("return".to_string(), bool_to_value(true));
}