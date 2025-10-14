//! Compare the performance of Spartan-t256 with Spartan-curve25519
use std::io;
use std::path::Path;
use fxhash::FxHashMap as HashMap;
use crate::target::r1cs::*;

use super::t256::MOD_T256;
use crate::right_field_arithmetic::field::{ARC_MOD_CURVE25519};

use super::utils::{read_prover_data, read_simpl_prover_data, read_verifier_data};

use std::time::Instant;
use crate::util::timer::print_time;

use crate::target::r1cs::proof::{serialize_into_file, deserialize_from_file};

use super::spartan::{SpartanProveRes, SpartanSetup};
use super::r1cs::convert_values;

/// Prove to/from files
pub fn prove_fs<P: AsRef<Path>>(
    p_path: P,
    pp_path: P,
    input_map: &HashMap<String, Value>,
    pf_path: P,
) -> std::io::Result<()> {
    let print_msg = true;
    let start = Instant::now();
    let pp: SpartanSetup = deserialize_from_file(pp_path)?;
    print_time("Time for Deserialize public parameter from file", start.elapsed(), print_msg);
    let pf = prove(p_path, pp, input_map, print_msg).unwrap(); // (NIZKGens, Instance, NIZK)
    let start = Instant::now();
    serialize_into_file(&pf, pf_path)?;
    print_time("Time for Serialize proof into file", start.elapsed(), print_msg);
    Ok(())
}

/// verify spartan proof from files
pub fn verify_fs<P: AsRef<Path>>(
    v_path: P,
    pp_path: P,
    inputs_map: &HashMap<String, Value>,
    pf_path: P,
) -> io::Result<()> {
    let print_msg = true;
    let start = Instant::now();
    let pp: SpartanSetup = deserialize_from_file(pp_path)?;
    let pf: SpartanProveRes = deserialize_from_file(pf_path)?;
    print_time("Time for Deserialize public parameter and proof from file", start.elapsed(), print_msg);
    verify(v_path, pp, inputs_map, pf, print_msg)
}

/// Precompute for spartan (Convert ECDSA circuit over spartan-t256 to a similar circuit over spartan-curve25519)
pub fn precompute<P: AsRef<Path>>(
    p_path: P,
    pp_path: P, 
    inputs_map: &HashMap<String, Value>,
) -> std::io::Result<()> {
    let mut prover_data = read_prover_data::<_>(p_path)?;
    let f_mod = prover_data.r1cs.field.modulus();

    let result = if f_mod == (&MOD_T256 as &Integer) {
                    let (gens, inst) = super::hybrid_bench::precompute(&mut prover_data, inputs_map).unwrap();
                    SpartanSetup::Curve25519(gens, inst)
                } else {
                    panic!("Unsupported Curve");
                };
    serialize_into_file(&result, pp_path)?;
    Ok(())
}

/// generate spartan proof
pub fn prove<P: AsRef<Path>>(
    p_path: P,
    pp: SpartanSetup,
    inputs_map: &HashMap<String, Value>,
    print_msg: bool,
) -> io::Result<SpartanProveRes> {
    let start = Instant::now();
    let prover_data = read_simpl_prover_data::<_>(p_path)?;
    print_time("Time for Read prover key", start.elapsed(), print_msg);
    println!("Proving with Spartan");
    println!("Curve: t256 -> Curve: Curve25519");
    let SpartanSetup::Curve25519(gens, inst) = pp else { panic!("Unsupported SpartanSetup") };
    let pf = super::hybrid_bench::prove(prover_data, gens, inst, inputs_map).unwrap();
    Ok(SpartanProveRes::PfCurve25519(pf))
}

/// verify spartan proof; to modify
pub fn verify<P: AsRef<Path>>(
    v_path: P,
    pp: SpartanSetup,
    inputs_map: &HashMap<String, Value>,
    proof_res: SpartanProveRes,
    print_msg: bool,
) -> io::Result<()> {
    let start = Instant::now();
    let verifier_data = read_verifier_data::<_>(v_path)?;
    print_time("Time for Read verifier key", start.elapsed(), print_msg);

    let start = Instant::now();
    let mut values = verifier_data.eval(inputs_map);
    print_time("Time for Process verifier input -- eval inputs_map", start.elapsed(), print_msg);
    convert_values(&mut values, &ARC_MOD_CURVE25519);

    println!("Verifying with Spartan");
    println!("Curve: t256 -> Curve: Curve25519");

    let verify_result = 
        match proof_res {
            SpartanProveRes::PfCurve25519(nizk) => {
                let SpartanSetup::Curve25519(gens, instance) = pp else {panic!("Expect public parameter for spartan-curve25519 only")};
                let result = super::curve25519::verify(&values, &gens, &instance, &nizk);
                result
            }
            _ => {panic!("Expect proof for spartan-curve25519 only")}
        };
    println!("Proof Verification Successful!");
    verify_result
}