//! Export circ R1cs to Spartan (Convert a R1cs circuit in spartan-t256 to that in spartan-curve25519)
use crate::target::r1cs::*;

use libdorian::{Assignment, InputsAssignment, Instance, NIZKGens, VarsAssignment, NIZK};
use merlin::Transcript;
use std::io;
use super::utils::{Variable};
use std::time::Instant;
use crate::util::timer::print_time;


use super::curve25519::{int_to_scalar as int_to_scalar_curve25519,
                        lc_to_v as lc_to_v_curve25519};  
use crate::right_field_arithmetic::field::{ARC_MOD_CURVE25519};
use super::r1cs::convert_r1cs_v2;
/// generate spartan proof; to do: change it into private
pub fn prove(
    mut prover_data: ProverDataSpartan,
    gens: NIZKGens,
    inst: Instance,
    inputs_map: &HashMap<String, Value>,
) -> io::Result<NIZK> {
    let print_msg = true;
    let start = Instant::now();
    let (wit, inps) =
        r1cs_to_spartan_simpl(&mut prover_data, &inst, inputs_map);
    print_time("Time for r1cs_to_spartan", start.elapsed(), print_msg);

    // produce proof
    let start = Instant::now();
    let mut prover_transcript = Transcript::new(b"nizk_example");
    let pf = NIZK::prove(&inst, wit, &inps, &gens, &mut prover_transcript);
    print_time("Time for NIZK::prove", start.elapsed(), print_msg);

    Ok(pf)
}
/// circ R1cs -> spartan R1CSInstance
pub fn precompute(
    prover_data: &mut ProverData,
    inputs_map: &HashMap<String, Value>, // require because we recompute C based on z
) -> io::Result<(NIZKGens, Instance)> {
    // spartan format mapper: CirC -> Spartan
    let mut values = prover_data.extend_r1cs_witness(inputs_map);
    convert_r1cs_v2(&mut prover_data.r1cs.constraints, &mut values, &ARC_MOD_CURVE25519); // Convert the R1CS circuit in t256 to that in curve25519
    assert_eq!(values.len(), prover_data.r1cs.vars.len());
    prover_data.r1cs.check_all(&values);

    let mut trans: HashMap<Var, usize> = HashMap::default(); // Circ -> spartan ids
    let mut id = 0;
    for var in prover_data.r1cs.vars.iter() {
        assert!(matches!(var.ty(), VarType::Inst | VarType::FinalWit));
        if let VarType::FinalWit = var.ty() {
            trans.insert(*var, id);
            id += 1;
        }
    }
    let num_wit = id;
    let num_inp = prover_data.r1cs.vars.len()-id;
    id += 1;
    for var in prover_data.r1cs.vars.iter() {
        assert!(matches!(var.ty(), VarType::Inst | VarType::FinalWit));
        if let VarType::Inst = var.ty() {
            trans.insert(*var, id);
            id += 1;
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
        let a = lc_to_v_curve25519(lc_a, const_id, &trans);
        let b = lc_to_v_curve25519(lc_b, const_id, &trans);
        let c = lc_to_v_curve25519(lc_c, const_id, &trans);

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

    let inst = Instance::new(num_cons, num_wit, num_inp, &m_a, &m_b, &m_c).unwrap();
    let gens = NIZKGens::new(num_cons, num_wit, num_inp);
    Ok((gens, inst))
}

/// circ R1cs -> spartan R1CSInstance
pub fn r1cs_to_spartan(
    prover_data: &mut ProverData,
    inst: &Instance,
    inputs_map: &HashMap<String, Value>,
) -> (Assignment, Assignment) {
    // spartan format mapper: CirC -> Spartan
    let mut wit = Vec::new();
    let mut inp = Vec::new();

    let mut values = prover_data.extend_r1cs_witness(inputs_map);
    // Change entries in values to the field element in the prime field of curve25519
    for (_, fieldv) in values.iter_mut() {
        fieldv.update_modulus(ARC_MOD_CURVE25519.clone());
    }
    assert_eq!(values.len(), prover_data.r1cs.vars.len());

    for var in prover_data.r1cs.vars.iter() {
        assert!(matches!(var.ty(), VarType::Inst | VarType::FinalWit));
        if let VarType::FinalWit = var.ty() {
            // witness
            let val = values.get(var).expect("missing R1CS value");
            wit.push(int_to_scalar_curve25519(&val.i()).to_bytes());
        }
    }


    for var in prover_data.r1cs.vars.iter() {
        assert!(matches!(var.ty(), VarType::Inst | VarType::FinalWit));
        if let VarType::Inst = var.ty() {
            // input
            let val = values.get(var).expect("missing R1CS value");
            inp.push(int_to_scalar_curve25519(&val.i()).to_bytes());
        }
    }


    let assn_witness = VarsAssignment::new(&wit).unwrap();
    let assn_inputs = InputsAssignment::new(&inp).unwrap();
    // check if the instance we created is satisfiable
    let res = inst.is_sat(&assn_witness, &assn_inputs); // for debug only
    assert!(res.unwrap());
    (
        assn_witness,
        assn_inputs,
    )
}

/// circ R1cs -> spartan R1CSInstance
pub fn r1cs_to_spartan_simpl(
    prover_data: &mut ProverDataSpartan,
    inst: &Instance,
    inputs_map: &HashMap<String, Value>,
) -> (Assignment, Assignment) {
    // spartan format mapper: CirC -> Spartan
    let mut wit = Vec::new();
    let mut inp = Vec::new();

    let mut values = prover_data.extend_r1cs_witness(inputs_map);
    // Change entries in values to the field element in the prime field of curve25519
    for fieldv in values.iter_mut() {
        fieldv.update_modulus(ARC_MOD_CURVE25519.clone());
    }
    let var_len = prover_data.pubinp_len + prover_data.wit_len;
    assert_eq!(values.len(), var_len);

    for val in values.iter().take(prover_data.pubinp_len) {
        inp.push(int_to_scalar_curve25519(&val.i()).to_bytes());
    }

    for val in values.iter().skip(prover_data.pubinp_len) {
        wit.push(int_to_scalar_curve25519(&val.i()).to_bytes());
    }

    let assn_witness = VarsAssignment::new(&wit).unwrap();
    let assn_inputs = InputsAssignment::new(&inp).unwrap();

    // check if the instance we created is satisfiable
    let res = inst.is_sat(&assn_witness, &assn_inputs); // for debug only
    assert!(res.unwrap());
    (
        assn_witness,
        assn_inputs,
    )
}