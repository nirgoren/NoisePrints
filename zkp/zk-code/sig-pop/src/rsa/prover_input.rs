//! Prover input related to rsa signature verification

use fxhash::FxHashMap as HashMap;
use crate::ir::term::Value;
use rug::Integer;

use crate::bignat::bignatwithlimbmax::{BigNatWithLimbMax, BigNatExponWithLimbMax};
use crate::parse_cert::{X509Certificate, IssuerKey, Signature};
use crate::allocate::{map_u8};
use std::convert::TryInto;
use crate::rsa::rsa_adv::BigNatRSAadv;
use crate::conditional_print;
use std::time::Instant;
use crate::util::timer::print_time;
use crate::rsa::rsa::RSAPublicKey;
use crate::hash::hash::DigestAlgorithm;

use crate::convert::os2ip;
use openssl::sign::Signer;
use openssl::rsa::Rsa;
use openssl::{pkey::{PKey, Private}};
use openssl::hash::MessageDigest;
use crate::convert::bignumref_to_integer;
use crate::target::r1cs::proof::serialize_into_file;
use crate::hash::sha256::prover_input_for_sha256_adv_inner;
use crate::hash::sha256::n_blocks_to_msg_len;
//new
fn inner_prover_input_for_modexpon_for_rsa_v4(a: &Integer, modul: &Integer, limbwidth: usize, n_limbs: usize, constant: bool, limbs_per_gp: usize) -> HashMap<String, Value>{
    let modul_bignat: BigNatWithLimbMax = BigNatWithLimbMax::new(modul, limbwidth, n_limbs, false);   
    let result: BigNatExponWithLimbMax = BigNatExponWithLimbMax::from_integer_with_grouping_and_diff_maxword(&a, &modul, limbwidth, n_limbs, false, limbs_per_gp); // we set the constant bit to be true only when we can ensure a < modulus
    let mut input_map = HashMap::<String, Value>::default();
    for (i, vec) in result.res.iter().enumerate() {
        if i == 0 {
            let a: BigNatWithLimbMax = BigNatWithLimbMax::from_bignatb(&vec);
            a.alloc_from_nat("a", &mut input_map);
        }
        else if i == 17 {
            let res: BigNatWithLimbMax = BigNatWithLimbMax::from_bignatb(&vec);
            res.alloc_from_nat("res", &mut input_map);
        } else {
            vec.alloc_from_natb(format!("intermediate.mm.{}.res", i-1).as_str(), &mut input_map);
        }
    }  

    for (i, vec) in result.mm.iter().enumerate() {
        if i == 16 {
            vec.alloc_from_natinterexpon2("intermediate", &mut input_map);
        } else {
            vec.alloc_from_natinterexpon2(format!("intermediate.mm.{}", i).as_str(), &mut input_map);
        }
    }
    if !constant {
        modul_bignat.alloc_from_nat("modul", &mut input_map); 
    }
    input_map
}

/// RSA signature verification w/ const modulus (it is done long time ago, and I forgot the details)
pub fn prover_input_for_const_modexpon_for_rsa() -> HashMap<String, Value>{
    let signed_certificate_path = "/home/anna/example_cert/_.google.com.cer";
    let issuer_certificate_path = "/home/anna/example_cert/_GTS_CA_1C3.cer";
    let cert: X509Certificate = X509Certificate::new(signed_certificate_path, issuer_certificate_path);
    cert.print_signature_algorithm();
    let limbwidth = 32;
    let n_limbs = 64;
    let limbs_per_gp = 6;
    let constant = true;
    let modul = Integer::from_str_radix("25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357", 10).unwrap();

    if let Signature::StructRSA(rsa_signature) = cert.signature {
        inner_prover_input_for_modexpon_for_rsa_v4(&rsa_signature.signature, &modul, limbwidth, n_limbs, constant, limbs_per_gp)
    } else {panic!("problem in issuer key");}
}

// dynamic: whether the message length is dynamic
// hash: whether do hashing in the circuit
/// RSA signature verification w/o advanced range check
pub fn prover_input_for_verifyrsa(dynamic: bool, hash: bool, modulus_bits: usize) -> HashMap<String, Value>{
    let signed_certificate_path = "./example_cert/_.google.com.cer";
    let issuer_certificate_path = "./example_cert/_GTS_CA_1C3.cer";
    conditional_print!("Path of the signed certificate: {}", signed_certificate_path);
    conditional_print!("Path of the issuer certificate: {}", issuer_certificate_path);
    let cert: X509Certificate = X509Certificate::new(signed_certificate_path, issuer_certificate_path);
    cert.print_signature_algorithm();
    let limbwidth = 32; //64
    let n_limbs = (modulus_bits as f64 / limbwidth as f64).ceil() as usize;
    let limbs_per_gp = 6; // number of groups for the modular multiplication; number of limbs after multiplication = n_limbs*2-1; number of limbs after modulo = ceil((n_limbs*2-1)/limbs_per_gp)

    let messagelength = 53;
    inner_prover_input_for_verifyrsa(&cert, limbwidth, n_limbs, limbs_per_gp, messagelength, dynamic, hash, modulus_bits)
}

fn inner_prover_input_for_verifyrsa(cert: &X509Certificate, limbwidth: usize, n_limbs: usize, limbs_per_gp: usize, messagelength: u32, dynamic: bool, hash: bool, modulus_bits: usize) -> HashMap<String, Value>{
    let mut input_map = HashMap::<String, Value>::default();
    inner_prover_input_for_single_cert(&cert, limbwidth, n_limbs, limbs_per_gp, messagelength, dynamic, hash, modulus_bits, "", & mut input_map);
    input_map
}

fn inner_prover_input_for_single_cert(cert: &X509Certificate, limbwidth: usize, n_limbs: usize, limbs_per_gp: usize, messagelength: u32, dynamic: bool, hash: bool, modulus_bits: usize, name: &str, input_map: &mut HashMap::<String, Value>) {
    if let IssuerKey::StructRSA(rsa_key) = &cert.issuer_key {
        if let Signature::StructRSA(rsa_signature) = &cert.signature {
            let sign_bignat = BigNatWithLimbMax::new(&rsa_signature.signature, limbwidth, n_limbs, false);
            let modul_bignat = BigNatWithLimbMax::new(&rsa_key.modulus, limbwidth, n_limbs, false); // false because the modulus is not constant
            // Allocate signatureb (bignatb), modulus (BigNat), padded_message/digest result into the circuit
            assert!(rsa_key.generate_witness(limbwidth, n_limbs, &(rsa_signature.signature), &(cert.body), &(cert.digest_algorithm), name, input_map, messagelength, dynamic, hash));


            let differ: u8 = sign_bignat.locate_first_differ_limbs(&modul_bignat).try_into().unwrap();
            let differ_idx: u8 = if modulus_bits == 2048 {differ}
                            else if modulus_bits == 4096 {differ/2}
                            else {panic!("Unsupported modulus type")};
            let append: String = if name.is_empty() {name.to_owned()} else {name.to_owned()+"."};
            map_u8(differ_idx, &format!("{}lessthan_differ", append), input_map);

            let exp_res: BigNatExponWithLimbMax = BigNatExponWithLimbMax::from_integer_with_grouping_and_diff_maxword(&(rsa_signature.signature), &(rsa_key.modulus), limbwidth, n_limbs, false, limbs_per_gp);
            for (i, vec) in exp_res.res.iter().enumerate() {
                if i == 0 {
                    continue;
                } 
                else if i == 17 {
                    continue;
                }
                else {
                    vec.alloc_from_natb(format!("{}intermediate.mm.{}.res", append, i-1).as_str(),input_map);
                }
            }  

            for (i, vec) in exp_res.mm.iter().enumerate() {
                if i == 16 { vec.alloc_from_natinterexpon2(format!("{}intermediate", append).as_str(), input_map);}
                else { vec.alloc_from_natinterexpon2(format!("{}intermediate.mm.{}", append, i).as_str(), input_map);}  
            } 
        

 
        }  else { panic!("Didn't implement other signature algorithms")}
    } else {
        panic!("Didn't implement other signature algorithms")
    }
}

/// RSA signature verification w/ advanced range check w/ hash computed in the circuit
pub fn prover_input_for_verifyrsa_adv_whole(modulus_bits: usize, name: &str, n_block_str: String) -> HashMap<String, Value>{
    let limbwidth = 32; //64
    let n_limbs = (modulus_bits as f64 / limbwidth as f64).ceil() as usize;
    let limbs_per_gp = 6; // number of groups for the modular multiplication; number of limbs after multiplication = n_limbs*2-1; number of limbs after modulo = ceil((n_limbs*2-1)/limbs_per_gp)

    let message_len = n_blocks_to_msg_len(n_block_str);
    let mut input_map = HashMap::<String, Value>::default();
    let prover_inp = ProverPrecomputeInput::generate(message_len); // message length = 53 bytes
    let start = Instant::now();
    prover_input_for_sha256_adv_inner(&prover_inp.message, false, None, &mut input_map);
    inner_prover_input_for_verifyrsa_adv_whole(
        prover_inp, 
        limbwidth, 
        n_limbs, 
        limbs_per_gp, 
        modulus_bits, 
        name, 
        & mut input_map);
    print_time("Time for Compute prover input", start.elapsed(), true);
    input_map
}

fn inner_prover_input_for_verifyrsa_adv_whole(
    prover_inp: ProverPrecomputeInput,
    limbwidth: usize, 
    n_limbs: usize, 
    limbs_per_gp: usize, 
    modulus_bits: usize, 
    name: &str, 
    input_map: &mut HashMap::<String, Value>
) {
    let subtable_bitwidth: usize = 10;
    let complete = true;
    // Allocate remaining input to the circuit
    inner_prover_input_for_single_cert_adv(
        prover_inp, 
        limbwidth, 
        n_limbs, 
        limbs_per_gp, 
        complete, 
        subtable_bitwidth,
        modulus_bits, 
        name, 
        input_map
    );
}


/// RSA signature verification w/ advanced range check
pub fn prover_input_for_verifyrsa_adv(dynamic: bool, hash: bool, complete: bool, modulus_bits: usize) -> HashMap<String, Value>{
    let signed_certificate_path = "./example_cert/_.google.com.cer";
    let issuer_certificate_path = "./example_cert/_GTS_CA_1C3.cer";

    conditional_print!("Path of the signed certificate: {}", signed_certificate_path);
    conditional_print!("Path of the issuer certificate: {}", issuer_certificate_path);
    let cert: X509Certificate = X509Certificate::new(signed_certificate_path, issuer_certificate_path);
    cert.print_signature_algorithm();
    let limbwidth = 32; //64
    let n_limbs = (modulus_bits as f64 / limbwidth as f64).ceil() as usize;
    let limbs_per_gp = 6; // number of groups for the modular multiplication; number of limbs after multiplication = n_limbs*2-1; number of limbs after modulo = ceil((n_limbs*2-1)/limbs_per_gp)

    let messagelength = 53;
    inner_prover_input_for_verifyrsa_adv(&cert, limbwidth, n_limbs, limbs_per_gp, messagelength, dynamic, hash, complete, modulus_bits)
}

fn inner_prover_input_for_verifyrsa_adv(cert: &X509Certificate, limbwidth: usize, n_limbs: usize, limbs_per_gp: usize, _messagelength: u32, _dynamic: bool, _hash: bool, complete: bool, modulus_bits: usize) -> HashMap<String, Value>{
    let mut input_map = HashMap::<String, Value>::default();
    let prover_inp = ProverPrecomputeInput::new(cert);

    let start = Instant::now();
    inner_inner_prover_input_for_verifyrsa_adv(
        prover_inp, 
        limbwidth, 
        n_limbs, 
        limbs_per_gp, 
        complete, 
        modulus_bits, 
        "", 
        & mut input_map);
    print_time("Time for Compute prover input", start.elapsed(), true);
    
    input_map
}

struct ProverPrecomputeInput {
    rsa_modulus: Integer,
    signature: Integer,
    message: Vec<u8>, 
}
impl ProverPrecomputeInput {
    #[allow(unused)]
    /// Create a new ProverPrecomputeInput for RSA signature verification
    pub fn new(cert: &X509Certificate) -> Self {
        if let IssuerKey::StructRSA(rsa_key) = &cert.issuer_key {
            if let Signature::StructRSA(signature) = &cert.signature {
                Self {
                    rsa_modulus: rsa_key.modulus.clone(),
                    signature: signature.signature.clone(),
                    message: cert.body.clone(),
                }
            } else { panic!("Expect RSA signature")}
        } else { panic!("Expect RSA signature verification key") }
    
    }
    /// Generate witness for designated message length
    pub fn generate(message_length: usize) -> Self {
        let keypair = Rsa::generate(2048).unwrap();
        let keypair = PKey::from_rsa(keypair).unwrap();
        let mut signer = Signer::new(MessageDigest::sha256(), &keypair).unwrap();
        let mut message: Vec<u8> = Vec::new();
        for _ in 0..message_length {
            message.push(7);
        }
        signer.update(&message).unwrap();
        let signature = signer.sign_to_vec().unwrap();
        let private_key: Rsa<Private> = keypair.rsa().unwrap();
        let modulus = private_key.n();
        let modulus_integer: Integer = bignumref_to_integer(modulus)
                .expect("Failed to parse modulus into Integer");
        serialize_into_file(&modulus_integer, "example_cert/rsa_modulus").unwrap();
        Self {
            rsa_modulus: modulus_integer,
            signature: os2ip(&signature),
            message: message,
        }
    }
}

fn inner_inner_prover_input_for_verifyrsa_adv(
    prover_inp: ProverPrecomputeInput,
    limbwidth: usize, 
    n_limbs: usize, 
    limbs_per_gp: usize, 
    complete: bool, 
    modulus_bits: usize, 
    name: &str, 
    input_map: &mut HashMap::<String, Value>
) {
    let subtable_bitwidth: usize = 10;
    // allocate digest result into the circuit
    let digest_result = if limbwidth != 32 {
        todo!("Implement limbwidth other than 32 later");
    } else {
        DigestAlgorithm::sha256_to_bignat(&(prover_inp.message), limbwidth, 256/limbwidth)
    };

    let prepend = if name.is_empty() {name.to_owned()} else {name.to_owned()+"."};
    if complete {
        digest_result.alloc_adv(subtable_bitwidth, &format!("{}res", prepend), input_map);
    } else {
        digest_result.alloc_from_nat(&format!("{}res", prepend), input_map);
    }
    // Allocate remaining input to the circuit
    inner_prover_input_for_single_cert_adv(
        prover_inp, 
        limbwidth, 
        n_limbs, 
        limbs_per_gp, 
        complete, 
        subtable_bitwidth,
        modulus_bits, 
        name, 
        input_map
    );
}

fn inner_prover_input_for_single_cert_adv(
    prover_inp: ProverPrecomputeInput,
    limbwidth: usize, 
    n_limbs: usize, 
    limbs_per_gp: usize, 
    complete: bool, 
    subtable_bitwidth: usize,
    modulus_bits: usize, 
    name: &str, 
    input_map: &mut HashMap::<String, Value>
) {
    let prepend = if name.is_empty() {name.to_owned()} else {name.to_owned()+"."};
    
    let sign_bignat = BigNatWithLimbMax::new(&prover_inp.signature, limbwidth, n_limbs, false);
    let modul_bignat = BigNatWithLimbMax::new(&prover_inp.rsa_modulus, limbwidth, n_limbs, false); // false because the modulus is not constant
    let quotient_bits = modulus_bits + 1;
    if modulus_bits != 2048 {
        todo!("Implement rsa signature verification with adv_range_check for other modulus length");
    }
    // Allocate signature (BigNat), modulus (BigNat), digest_result (BigNat) into the circuit
    assert!(RSAPublicKey::generate_witness_adv(
        limbwidth, 
        n_limbs, 
        &prover_inp.rsa_modulus,
        &(prover_inp.signature), 
        name, 
        input_map, 
        if complete {Some(subtable_bitwidth)} else {None}
    ));
    let intermediate = BigNatRSAadv::new(
        &sign_bignat,
        &modul_bignat,
        quotient_bits, // not sure
        limbs_per_gp
    );
    intermediate.alloc(
        subtable_bitwidth, 
        &format!("{}intermediate", prepend), 
        input_map
    );
}