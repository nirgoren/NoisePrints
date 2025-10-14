//! Spartan with verifier randomness
use std::io;
use std::path::Path;
use fxhash::FxHashMap as HashMap;
use crate::target::r1cs::*;

use super::curve25519::{MOD_CURVE25519};
use super::t25519::{MOD_T25519};
use super::t256::MOD_T256;
use super::utils::{read_verifier_data};

use std::time::Instant;
use crate::util::timer::print_time;
use serde::{Deserialize, Serialize};
use crate::create_input::PfCurve;

use crate::target::r1cs::proof::{serialize_into_file, deserialize_from_file};
use super::utils::Variable;

use super::curve25519_rand::SpartanRandCurve25519;
use super::t256_rand::SpartanRandT256;
use super::t25519_rand::SpartanRandT25519;

/// A trait from Spartan proofs
pub trait ISpartanProofSystem {
    /// A verifying key. Also used for commitments.
    type VerifierKey: Serialize + for<'a> Deserialize<'a>;
    /// A proving key
    type ProverKey: Serialize + for<'a> Deserialize<'a>;
    /// Precomputed public parameter
    type SetupParameter: Serialize + for<'a> Deserialize<'a>;
    /// A proof
    type Proof: Serialize + for<'a> Deserialize<'a>;

    /// Proving
    fn prove_fs_inner(
        pk_path: impl AsRef<Path>,
        pp: &Self::SetupParameter,
        input_map: &HashMap<String, Value>,
    ) -> std::io::Result<Self::Proof>;

    /// Prove to/from files
    fn prove_fs(
        pk_path: impl AsRef<Path>,
        pp_path: impl AsRef<Path>,
        input_map: &HashMap<String, Value>,
        pf_path: impl AsRef<Path>,
    ) -> std::io::Result<()> {
        let pp: Self::SetupParameter = deserialize_from_file(pp_path)?;
        let proof = Self::prove_fs_inner(pk_path, &pp, input_map)?;
        serialize_into_file(&proof, pf_path)
    }

    /// Verifying
    fn verify(
        pp: &Self::SetupParameter,
        verifier_data: &Self::VerifierKey,
        proof: &Self::Proof,
        inputs_map: &HashMap<String, Value>,
        print_msg: bool,
    ) -> io::Result<()>;

    /// Verify from files
    fn verify_fs<P: AsRef<Path>>(
        pp_path: P,
        vk_path: P,
        pf_path: P,
        inputs_map: &HashMap<String, Value>,
    ) -> io::Result<()> {
        let print_msg = true;

        let pp: Self::SetupParameter = deserialize_from_file(pp_path)?;
        let verifier_data: Self::VerifierKey = deserialize_from_file(vk_path)?;
        let proof: Self::Proof = deserialize_from_file(pf_path)?;
        Self::verify(&pp, &verifier_data, &proof, inputs_map, print_msg)
    }
}



#[derive(Serialize, Deserialize)]
/// Enum for precomputation
pub enum SpartanRandSetup {
    /// Precomputation for spartan over Curve25519
    Curve25519(libdorian::NIZKRandGens, libdorian::Instance),
    /// Precomputation for spartan over T256
    T256(libdoriant256::NIZKRandGens, libdoriant256::Instance),
}

#[derive(Serialize, Deserialize)]
/// Enum for Prove result
pub enum SpartanRandProveRes { // not sure
    /// Prove result for spartan over Curve25519
    PfCurve25519(libdorian::NIZKRand),
    /// Prove result for spartan over T256
    PfT256(libdoriant256::NIZKRand),
}

/// Precompute inner
pub fn precompute_inner(
    prover_data: &ProverData,
    lc_to_v: fn(&Lc, usize, &HashMap<Var, usize>) -> Vec<Variable>,
) -> io::Result<(usize, usize, usize, Vec<(usize, usize, [u8; 32])>, Vec<(usize, usize, [u8; 32])>, Vec<(usize, usize, [u8; 32])>)> {
    // spartan format mapper: CirC -> Spartan
    let mut trans: HashMap<Var, usize> = HashMap::default(); // Circ -> spartan ids
    let mut id = 0;
    for var in prover_data.r1cs.vars.iter() {
        assert!(matches!(var.ty(), VarType::Inst | VarType::Chall | VarType::FinalWit | VarType::RoundWit ));
        match var.ty() {
            VarType::RoundWit => {
                trans.insert(*var, id);
                id += 1;
            },
            _ => {}
        }
    }
    #[cfg(debug_assertions)]
    let num_round_wit = id;
    #[cfg(debug_assertions)]
    println!("num round wit: {}", id);
    for var in prover_data.r1cs.vars.iter() {
        assert!(matches!(var.ty(), VarType::Inst | VarType::Chall | VarType::FinalWit | VarType::RoundWit ));
        match var.ty() {
            VarType::FinalWit => {
                trans.insert(*var, id);
                id += 1;
            },
            _ => {}
        }
    }
    #[cfg(debug_assertions)]
    println!("num final wit: {}", id-num_round_wit);

    let num_wit = id;
    let num_inp = prover_data.r1cs.vars.len()-id;
    #[cfg(debug_assertions)]
    println!("num_inp: {}", num_inp);
    id += 1;
    for var in prover_data.r1cs.vars.iter() {
        assert!(matches!(var.ty(), VarType::Inst | VarType::Chall | VarType::FinalWit | VarType::RoundWit ));
        match var.ty() {
            VarType::Inst => {
                trans.insert(*var, id);
                id += 1;
            },
            _ => {}
        }
    }
    for var in prover_data.r1cs.vars.iter() {
        assert!(matches!(var.ty(), VarType::Inst | VarType::Chall | VarType::FinalWit | VarType::RoundWit ));
        match var.ty() {
            VarType::Chall => {
                trans.insert(*var, id);
                id += 1;
            },
            _ => {}
        }
    }
    assert!(id == prover_data.r1cs.vars.len() + 1);
    let const_id = num_wit;

    let mut m_a: Vec<(usize, usize, [u8; 32])> = Vec::new();
    let mut m_b: Vec<(usize, usize, [u8; 32])> = Vec::new();
    let mut m_c: Vec<(usize, usize, [u8; 32])> = Vec::new();

    let mut i = 0; // constraint #
    for (lc_a, lc_b, lc_c) in prover_data.r1cs.constraints.iter() {
        // circ Lc (const, monomials <Integer>) -> Vec<Variable>
        let a = lc_to_v(lc_a, const_id, &trans);
        let b = lc_to_v(lc_b, const_id, &trans);
        let c = lc_to_v(lc_c, const_id, &trans);

        // constraint # x identifier (vars, 1, inp)
        for Variable { sid, value } in a {
            m_a.push((i, sid, value)); // i = row; sid = col
        }
        for Variable { sid, value } in b {
            m_b.push((i, sid, value));
        }
        for Variable { sid, value } in c {
            m_c.push((i, sid, value));
        }

        i += 1;
    }

    let num_cons = i;
    assert_ne!(num_cons, 0, "No constraints");

    Ok((num_cons, num_wit, num_inp, m_a, m_b, m_c))
}



/// Precompute the polynomials for domain separation for spartan with verifier randomness; TO DO
pub fn precompute<P: AsRef<Path>>(pp_path: P, prover_data: &ProverData, prover_data_rand: &ProverDataSpartanRand) -> std::io::Result<()> {
    let f_mod = prover_data.r1cs.field.modulus();

    let result = if f_mod == (&MOD_CURVE25519 as &Integer) {
                    let (gens, inst) = super::curve25519_rand::precompute(prover_data, prover_data_rand).unwrap();
                    serialize_into_file(&(gens, inst), pp_path)?;
                } else if f_mod == (&MOD_T256 as &Integer) {
                    let (gens, inst) = super::t256_rand::precompute(prover_data, prover_data_rand).unwrap();
                    serialize_into_file(&(gens, inst), pp_path)?;
                } else if f_mod == (&MOD_T25519 as &Integer) {
                    let (gens, inst) = super::t25519_rand::precompute(prover_data, prover_data_rand).unwrap();
                    serialize_into_file(&(gens, inst), pp_path)?;
                } else {
                    panic!("Unsupported modulus");
                };
    Ok(())
}


/// Prove to/from files
pub fn prove_fs<P: AsRef<Path>>(
    p_path: P,
    pp_path: P,
    input_map: &HashMap<String, Value>,
    pf_path: P,
    curvetype: &PfCurve,
) -> std::io::Result<()> {
    match curvetype {
        PfCurve::Curve25519 => {
            SpartanRandCurve25519::prove_fs(
                p_path, pp_path, input_map, pf_path
            )
        }
        PfCurve::T256 => {
            SpartanRandT256::prove_fs(
                p_path, pp_path, input_map, pf_path
            )
        }
        PfCurve::T25519 => {
            SpartanRandT25519::prove_fs(
                p_path, pp_path, input_map, pf_path
            )
        }
    }
}
/// verify spartan proof from files
pub fn verify_fs<P: AsRef<Path>>(
    v_path: P,
    pp_path: P,
    inputs_map: &HashMap<String, Value>,
    pf_path: P,
    curvetype: &PfCurve,
) -> io::Result<()> {
    match curvetype {
        PfCurve::Curve25519 => {
            SpartanRandCurve25519::verify_fs(
                pp_path, v_path, pf_path, inputs_map, 
            )
        }
        PfCurve::T256 => {
            SpartanRandT256::verify_fs(
                pp_path, v_path, pf_path, inputs_map, 
            )
        }
        PfCurve::T25519 => {
            SpartanRandT25519::verify_fs(
                pp_path, v_path, pf_path, inputs_map, 
            )
        }
    }
}

