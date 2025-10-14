//! Spartan
use std::io;
use std::path::Path;
use fxhash::FxHashMap as HashMap;
use crate::target::r1cs::*;

use super::curve25519::{MOD_CURVE25519};
use super::t256::MOD_T256;
use super::t25519::MOD_T25519;
use super::utils::{read_simpl_prover_data, read_verifier_data};

use std::time::Instant;
use crate::util::timer::print_time;
use serde::{Deserialize, Serialize};

use crate::target::r1cs::proof::{serialize_into_file, deserialize_from_file};
use crate::create_input::PfCurve;
use super::t256::SpartanT256;
use super::t25519::SpartanT25519;
use super::curve25519::SpartanCurve25519;

/// A trait from Spartan proofs
pub trait SpartanProofSystem {
    /// A verifying key. Also used for commitments.
    type VerifierKey: Serialize + for<'a> Deserialize<'a>;
    /// A proving key
    type ProverKey: Serialize + for<'a> Deserialize<'a>;
    /// Precomputed public parameter
    type SetupParameter: Serialize + for<'a> Deserialize<'a>;
    /// A proof
    type Proof: Serialize + for<'a> Deserialize<'a>;

    fn prove(
        pp: &Self::SetupParameter,
        pk: &Self::ProverKey,
        input_map: &HashMap<String, Value>,
    ) -> io::Result<Self::Proof>;

    fn verify(
        pp: &Self::SetupParameter,
        vk: &Self::VerifierKey,
        inputs_map: &HashMap<String, Value>,
        proof: &Self::Proof,
    ) -> io::Result<()>;

    /// Prove to/from files
    fn prove_fs(
        pp_path: impl AsRef<Path>,
        pk_path: impl AsRef<Path>,
        input_map: &HashMap<String, Value>,
        pf_path: impl AsRef<Path>,
        // curvetype: PfCurve,
    ) -> std::io::Result<()> {
        let pp: Self::SetupParameter = deserialize_from_file(pp_path)?;
        let pk: Self::ProverKey = deserialize_from_file(pk_path)?;
        let proof = Self::prove(&pp, &pk, input_map)?;
        serialize_into_file(&proof, pf_path)
    }

    /// Verify from files
    fn verify_fs(
        pp_path: impl AsRef<Path>,
        vk_path: impl AsRef<Path>,
        inputs_map: &HashMap<String, Value>,
        pf_path: impl AsRef<Path>,
    ) -> io::Result<()> {
        let pp: Self::SetupParameter = deserialize_from_file(pp_path)?;
        let vk: Self::VerifierKey = deserialize_from_file(vk_path)?;
        let proof: Self::Proof = deserialize_from_file(pf_path)?;
        Self::verify(&pp, &vk, inputs_map, &proof)
    }
}

// use std::path::PathBuf;
#[derive(Serialize, Deserialize)]
/// Enum for precomputation
pub enum SpartanSetup {
    /// Precomputation for spartan over Curve25519
    Curve25519(libdorian::NIZKGens, libdorian::Instance),
    /// Precomputation for spartan over T256
    T256(libdoriant256::NIZKGens, libdoriant256::Instance),
}


#[derive(Serialize, Deserialize)]
/// Enum for Prove result
pub enum SpartanProveRes {
    /// Prove result for spartan over Curve25519
    PfCurve25519(libdorian::NIZK),
    /// Prove result for spartan over T256
    PfT256(libdoriant256::NIZK),
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
            SpartanCurve25519::prove_fs(
                pp_path, p_path, input_map, pf_path
            )
        }
        PfCurve::T25519 => {
            SpartanT25519::prove_fs(
                pp_path, p_path, input_map, pf_path
            )
        }
        PfCurve::T256 => {
            SpartanT256::prove_fs(
                pp_path, p_path, input_map, pf_path
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
            SpartanCurve25519::verify_fs(
                pp_path, v_path, inputs_map, pf_path,
            )
        }
        PfCurve::T25519 => {
            SpartanT25519::verify_fs(
                pp_path, v_path, inputs_map, pf_path,
            )
        }
        PfCurve::T256 => {
            SpartanT256::verify_fs(
                pp_path, v_path, inputs_map, pf_path,
            )
        }
    }
}


/// Precompute for spartan
pub fn precompute<P: AsRef<Path>>(pp_path: P, prover_data: &ProverData) -> std::io::Result<()> {
    let f_mod = prover_data.r1cs.field.modulus();

    if f_mod == (&MOD_CURVE25519 as &Integer) {
        let (gens, inst) = super::curve25519::precompute(prover_data).unwrap();
        serialize_into_file(&(gens, inst), pp_path)?;
    } else if f_mod == (&MOD_T256 as &Integer) {
        let (gens, inst) = super::t256::precompute(prover_data).unwrap();
        serialize_into_file(&(gens, inst), pp_path)?;
    } else if f_mod == (&MOD_T25519 as &Integer) {
        let (gens, inst) = super::t25519::precompute(prover_data).unwrap();
        serialize_into_file(&(gens, inst), pp_path)?;
    } else {
        panic!("Unsupported Curve");
    }
    Ok(())
}