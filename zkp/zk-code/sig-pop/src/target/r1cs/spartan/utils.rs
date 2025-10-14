//! Utils function for Spartan
use crate::target::r1cs::*;
use bincode::{deserialize_from, serialize_into};
use std::fs::File;
use std::io;
use std::io::{BufReader, BufWriter};
use std::path::Path;
use super::spartan;
use super::spartan_rand;
use crate::target::r1cs::proof::serialize_into_file;
/// Hold Spartan variables
#[derive(Debug)]
pub struct Variable {
    /// sid
    pub sid: usize,
    /// value
    pub value: [u8; 32],
}

/// write prover and verifier data to file
pub fn write_data<P1: AsRef<Path>, P2: AsRef<Path>>(
    p_path: P1,
    v_path: P2,
    pp_path: P1,
    p_data: &ProverData,
    v_data: &VerifierData,
) -> io::Result<()> {
    write_prover_data(p_path, p_data)?;
    spartan::precompute(pp_path, p_data)?;
    write_verifier_data(v_path, v_data)?;
    Ok(())
}

#[cfg(feature = "spartan")]
/// write prover and verifier data to file
pub fn write_data_spartan<P1: AsRef<Path>, P2: AsRef<Path>>(
    p_path: P1,
    v_path: P2,
    pp_path: P1,
    p_data: &ProverData,
    v_data: &VerifierData,
) -> io::Result<()> {
    write_prover_data("P_long", p_data)?; // needed by our hybrid circuit for benchmarking; to delete
    let simpl_p_data = ProverDataSpartan::from_prover_data(p_data);
    write_simpl_prover_data(p_path, &simpl_p_data)?;
    spartan::precompute(pp_path, p_data)?;
    write_verifier_data(v_path, v_data)?;
    Ok(())
}

#[cfg(feature = "spartan")]
/// write prover and verifier data to file
pub fn write_data_spartan_rand<P1: AsRef<Path>, P2: AsRef<Path>>( // to do
    p_path: P1,
    v_path: P2,
    pp_path: P1,
    p_data: &ProverData,
    v_data: &VerifierData,
) -> io::Result<()> {
    write_prover_data("P_long", p_data)?; // needed by our hybrid circuit for benchmarking; to delete
    let simpl_p_data = ProverDataSpartanRand::from_prover_data(p_data);
    serialize_into_file(&simpl_p_data, p_path)?;
    spartan_rand::precompute(pp_path, p_data, &simpl_p_data)?; 
    write_verifier_data(v_path, v_data)?;
    Ok(())
}

fn write_prover_data<P: AsRef<Path>>(path: P, data: &ProverData) -> io::Result<()> {
    let mut file = BufWriter::new(File::create(path)?);
    serialize_into(&mut file, &data).unwrap();
    Ok(())
}

/// read prover data
pub fn read_prover_data<P: AsRef<Path>>(path: P) -> io::Result<ProverData> {
    let mut file = BufReader::new(File::open(path)?);
    let data: ProverData = deserialize_from(&mut file).unwrap();
    Ok(data)
}

fn write_simpl_prover_data<P: AsRef<Path>>(path: P, data: &ProverDataSpartan) -> io::Result<()> {
    let mut file = BufWriter::new(File::create(path)?);
    serialize_into(&mut file, &data).unwrap();
    Ok(())
}

/// read simplified prover data
pub fn read_simpl_prover_data<P: AsRef<Path>>(path: P) -> io::Result<ProverDataSpartan> {
    let mut file = BufReader::new(File::open(path)?);
    let data: ProverDataSpartan = deserialize_from(&mut file).unwrap();
    Ok(data)
}

fn write_verifier_data<P: AsRef<Path>>(path: P, data: &VerifierData) -> io::Result<()> {
    let mut file = BufWriter::new(File::create(path)?);
    serialize_into(&mut file, &data).unwrap();
    Ok(())
}

/// read verifier data
pub fn read_verifier_data<P: AsRef<Path>>(path: P) -> io::Result<VerifierData> {
    let mut file = BufReader::new(File::open(path)?);
    let data: VerifierData = deserialize_from(&mut file).unwrap();
    Ok(data)
}