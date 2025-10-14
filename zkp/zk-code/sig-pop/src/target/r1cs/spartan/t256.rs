//! Export circ R1cs to Spartan
use crate::target::r1cs::*;
use circ_fields::t256::{ScalarField as Scalar}; //Config, 

use libdoriant256::{Assignment, InputsAssignment, Instance, NIZKGens, VarsAssignment, NIZK};
use merlin::Transcript;
use rug::Integer;
use std::io;
use super::utils::{Variable};
use circ_fields::t256::utils::helper::SpartanTrait;
use std::time::Instant;
use crate::util::timer::print_time;

use lazy_static::lazy_static;

use ark_ff::PrimeField;
use ark_serialize::CanonicalDeserialize;

use super::spartan::SpartanProofSystem;
lazy_static! {
    /// Order of T256
    pub static ref MOD_T256: Integer = Integer::from_str_radix("115792089210356248762697446949407573530086143415290314195533631308867097853951", 10).unwrap();
}

/// Number of bytes of the modulus
pub const NUM_MODULUS_BYTE: usize = ((Scalar::MODULUS_BIT_SIZE + 7) / 8) as usize;

pub struct SpartanT256;

impl SpartanProofSystem for SpartanT256 {
    type VerifierKey = VerifierData;
    type ProverKey = ProverDataSpartan;
    type SetupParameter = (NIZKGens, Instance);
    type Proof = NIZK;

    fn prove(
        pp: &Self::SetupParameter,
        pk: &Self::ProverKey,
        input_map: &HashMap<String, Value>,
    ) -> io::Result<Self::Proof> {
        prove(pk, &pp.0, &pp.1, input_map)
    }

    fn verify(
        pp: &Self::SetupParameter,
        vk: &Self::VerifierKey,
        inputs_map: &HashMap<String, Value>,
        proof: &Self::Proof,
    ) -> io::Result<()> {
        let values = vk.eval(inputs_map);
        verify(&values, &pp.0, &pp.1, proof)
    }
}

/// generate spartan proof; to do: change it into private
pub fn prove(
    prover_data: &ProverDataSpartan,
    gens: &NIZKGens,
    inst: &Instance,
    inputs_map: &HashMap<String, Value>,
) -> io::Result<NIZK> {
    let print_msg = true;
    let start = Instant::now();
    let (wit, inps) = r1cs_to_spartan_simpl(prover_data, inst, inputs_map);
    print_time("Time for r1cs_to_spartan", start.elapsed(), print_msg);


    // produce proof
    let start = Instant::now();
    let mut prover_transcript = Transcript::new(b"nizk_example");
    let pf = NIZK::prove(inst, wit, &inps, gens, &mut prover_transcript);
    print_time("Time for NIZK::prove", start.elapsed(), print_msg);

    Ok(pf)
}


/// verify spartan proof
pub fn verify(
    values: &Vec<FieldV>,
    gens: &NIZKGens,
    inst: &Instance,
    proof: &NIZK,
) -> io::Result<()> {
    let print_msg = true;
    let start = Instant::now();
    let mut inp = Vec::new();
    for v in values {
        let scalar = int_to_scalar(&v.i());
        inp.push(scalar.to_bytes());
    }
    let inputs = InputsAssignment::new(&inp).unwrap();
    print_time("Time for Process verifier input -- transforming inputs to appropriate form", start.elapsed(), print_msg);

    let start = Instant::now();
    let mut verifier_transcript = Transcript::new(b"nizk_example");
    assert!(proof
        .verify(inst, &inputs, &mut verifier_transcript, gens)
        .is_ok());
    // println!("Time for verifying proof: {:?}", start.elapsed()); // verify-ecdsa: 158.0493ms
    print_time("Time for NIZK::verify", start.elapsed(), print_msg);

    Ok(())
}

/// Precompute inner
pub fn precompute_inner(
    prover_data: &ProverData,
) -> io::Result<(usize, usize, usize, Vec<(usize, usize, [u8; 32])>, Vec<(usize, usize, [u8; 32])>, Vec<(usize, usize, [u8; 32])>)> {
    // spartan format mapper: CirC -> Spartan
    let mut trans: HashMap<Var, usize> = HashMap::default(); // Circ -> spartan ids
    let mut id = 0;
    for var in prover_data.r1cs.vars.iter() {
        assert!(matches!(var.ty(), VarType::Inst | VarType::Chall | VarType::FinalWit | VarType::RoundWit ));
        match var.ty() {
            VarType::FinalWit | VarType::RoundWit => {
                trans.insert(*var, id);
                id += 1;
            },
            _ => {}
        }
    }
    let num_wit = id;
    let num_inp = prover_data.r1cs.vars.len()-id;
    id += 1;
    for var in prover_data.r1cs.vars.iter() {
        assert!(matches!(var.ty(), VarType::Inst | VarType::Chall | VarType::FinalWit | VarType::RoundWit ));
        match var.ty() {
            VarType::Inst | VarType::Chall => {
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
            m_a.push((i, sid, value));
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

/// circ R1cs -> spartan R1CSInstance
pub fn precompute(
    prover_data: &ProverData,
) -> io::Result<(NIZKGens, Instance)> {
    let (num_cons, num_wit, num_inp, m_a, m_b, m_c) = precompute_inner(prover_data).unwrap();

    let inst = Instance::new(num_cons, num_wit, num_inp, &m_a, &m_b, &m_c).unwrap();
    let gens = NIZKGens::new(num_cons, num_wit, num_inp);
    Ok((gens, inst))
}

/// circ R1cs -> spartan R1CSInstance; needed in prove
pub fn r1cs_to_spartan_simpl(
    prover_data: &ProverDataSpartan,
    inst: &Instance,
    inputs_map: &HashMap<String, Value>,
) -> (Assignment, Assignment) {
    // spartan format mapper: CirC -> Spartan
    let mut wit = Vec::new();
    let mut inp = Vec::new();
    let values = prover_data.extend_r1cs_witness(inputs_map);

    // prover_data.r1cs.check_all(&values); // for debug purpose; not working now since prover_data.r1cs is not available
    let var_len = prover_data.pubinp_len + prover_data.wit_len;
    assert_eq!(values.len(), var_len);

    for val in values.iter().take(prover_data.pubinp_len) {
        inp.push(int_to_scalar(&val.i()).to_bytes());
    }

    for val in values.iter().skip(prover_data.pubinp_len) {
        wit.push(int_to_scalar(&val.i()).to_bytes());
    }

    let assn_witness = VarsAssignment::new(&wit).unwrap();
    let assn_inputs = InputsAssignment::new(&inp).unwrap();


    // check if the instance we created is satisfiable
    let res = inst.is_sat(&assn_witness, &assn_inputs);
    assert!(res.unwrap());

    (
        assn_witness,
        assn_inputs,
    )
}

// Convert Integer to Scalar
pub fn int_to_scalar(i: &Integer) -> Scalar {
    let digits: Vec<u8> = i.to_digits(rug::integer::Order::LsfLe);
    let mut repr: [u8; NUM_MODULUS_BYTE] = [0; NUM_MODULUS_BYTE];
    
    repr.as_mut()[..digits.len()].copy_from_slice(&digits);

//     Scalar::from_be_bytes_mod_order(&repr)
    Scalar::deserialize_compressed(&repr[..]).unwrap()
}
// circ Lc (const, monomials <Integer>) -> Vec<Variable>
pub fn lc_to_v(lc: &Lc, const_id: usize, trans: &HashMap<Var, usize>) -> Vec<Variable> {
    let mut v: Vec<Variable> = Vec::new();

    for (k, m) in &lc.monomials {
        let scalar = int_to_scalar(&m.i());

        let var = Variable {
            sid: *trans.get(k).unwrap(),
            value: scalar.to_bytes(),
        };
        v.push(var);
    }
    if lc.constant.i() != 0 {
        let scalar = int_to_scalar(&lc.constant.i());
        let var = Variable {
            sid: const_id,
            value: scalar.to_bytes(),
        };
        v.push(var);
    }
    v
}
