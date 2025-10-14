//! Export circ R1cs to Spartan
use crate::target::r1cs::*;
use circ_fields::t256::ScalarField as Scalar; //Config,

use crate::util::timer::print_time;
use libdoriant256::scalar::Scalar as OriScalar;
use libdoriant256::DensePolynomial;
use libdoriant256::{
    Assignment, InputsAssignment, Instance, NIZKRand, NIZKRandGens, NIZKRandInter, VarsAssignment,
};
use merlin::Transcript;
use rug::Integer;
use std::io;
use std::time::Instant;

use std::path::Path;
use crate::target::r1cs::proof::deserialize_from_file;

use super::t256::{NUM_MODULUS_BYTE, int_to_scalar, lc_to_v};
use crate::target::r1cs::wit_comp::StagedWitComp;
use ark_serialize::CanonicalDeserialize;

#[cfg(feature = "spartan")]
use circ_fields::t256::utils::helper::SpartanTrait;

use super::spartan_rand::{
    precompute_inner, 
    ISpartanProofSystem, 
};

pub struct SpartanRandT256;

impl ISpartanProofSystem for SpartanRandT256 {
    type VerifierKey = VerifierData;
    type ProverKey = ProverDataSpartanRand;
    type SetupParameter = (NIZKRandGens, Instance);
    type Proof = NIZKRand;

    fn prove_fs_inner(
        pk_path: impl AsRef<Path>,
        pp: &Self::SetupParameter,
        inputs_map: &HashMap<String, Value>,
    ) -> std::io::Result<Self::Proof> {
        let print_msg = true;
        let (pubinp_len, wit_len, rand_list, precompute, field) = {
            let prover_data: Self::ProverKey = deserialize_from_file(pk_path)?;
            #[cfg(debug_assertions)]
            prover_data.check_all(inputs_map);
            R1csToSpartan2Round::parse_prover_data(&prover_data)
        };

        let mut evaluator = R1csToSpartan2Round::from_prover_data_inner(
            &pubinp_len, 
            &wit_len, 
            &rand_list, 
            &precompute, 
            &field
        );
        let (gens, inst) = pp;
        let start = Instant::now();
        let pf = prove(&mut evaluator, gens, inst, inputs_map).unwrap();
        print_time("Time for Proving", start.elapsed(), print_msg);
        Ok(pf)
    }

    fn verify(
        pp: &Self::SetupParameter,
        vk: &Self::VerifierKey,
        proof: &Self::Proof,
        inputs_map: &HashMap<String, Value>,
        print_msg: bool,
    ) -> io::Result<()> {
        let values = vk.eval(inputs_map);
        verify(&values, &pp.0, &pp.1, proof)
    }
}

/// circ IR1cs -> spartan IR1CSInstance
pub fn precompute(
    prover_data: &ProverData,
    prover_data_rand: &ProverDataSpartanRand,
) -> io::Result<(NIZKRandGens, Instance)> {
    let (num_cons, num_wit, num_inp, m_a, m_b, m_c) = precompute_inner(prover_data, lc_to_v).unwrap();

    let inst = Instance::new(num_cons, num_wit, num_inp, &m_a, &m_b, &m_c).unwrap();
    let gens = NIZKRandGens::new(
        num_cons,
        &prover_data_rand.pubinp_len,
        &prover_data_rand.wit_len,
    );
    Ok((gens, inst))
}


/// generate spartan proof; to do: change it into private
pub fn prove(
    evaluator: &mut R1csToSpartan2Round,
    gens: &NIZKRandGens,
    inst: &Instance,
    inputs_map: &HashMap<String, Value>,
) -> io::Result<NIZKRand> {
    let start_whole = Instant::now();
    #[cfg(debug_assertions)]
    assert_eq!(gens.pubinp_len.len(), 2);
    let print_msg = true;

    let (inputs, wit0) = evaluator.inputs_to_wit0(inputs_map);

    // produce proof
    let mut prover_transcript = Transcript::new(b"nizkrand_example");
    let mut intermediate = NIZKRandInter::new(&inputs);
    NIZKRand::prove_00(inst, &inputs, gens, &mut prover_transcript);
    let rand_len = gens.pubinp_len[1];
    let verifier_rand: Vec<OriScalar> = NIZKRand::prove_01(
        inst,
        &wit0,
        rand_len,
        &mut intermediate,
        gens,
        &mut prover_transcript,
    );

    let start = Instant::now();

    let wit1 = evaluator.rand_to_wit1(&verifier_rand);

    print_time("Time for r1cs_to_spartan1,2", start.elapsed(), print_msg);
    let pf = NIZKRand::prove_1(
        inst,
        &wit1,
        &mut intermediate,
        gens,
        &mut prover_transcript,
    );
    print_time("Time for whole prove", start_whole.elapsed(), print_msg);

    Ok(pf)
}

/// verify spartan proof
pub fn verify(
    values: &[FieldV],
    gens: &NIZKRandGens,
    inst: &Instance,
    proof: &NIZKRand,
) -> io::Result<()> {
    let print_msg = true;
    let start = Instant::now();
    let mut inp = Vec::new();
    for v in values {
        let scalar = int_to_scalar(&v.i());
        inp.push(scalar.to_bytes());
    }
    let mut inputs = InputsAssignment::new(&inp).unwrap();
    print_time(
        "Time for Process verifier input -- transforming inputs to appropriate form",
        start.elapsed(),
        print_msg,
    );

    let start = Instant::now();
    let mut verifier_transcript = Transcript::new(b"nizkrand_example");
    assert!(proof
        .verify(inst, &mut inputs, &mut verifier_transcript, gens)
        .is_ok());
    print_time("Time for NIZK::verify", start.elapsed(), print_msg);

    Ok(())
}


enum Step {
    Fresh,
    PostWit0,
    Done,
}

/// A witness evaluator for 2-round Spartan
pub struct R1csToSpartan2Round<'a> {
    pubinp_len: [usize; 2],
    wit_len: [usize; 2],
    rand_list: Vec<String>,
    evaluator: wit_comp::StagedWitCompEvaluator<'a>,
    field: FieldT,
    step: Step,
}

impl<'a> R1csToSpartan2Round<'a> {
    pub fn parse_prover_data(prover_data: &ProverDataSpartanRand)
    -> ([usize; 2],
        [usize; 2],
        Vec<String>,
        StagedWitComp,
        FieldT
    ) {
        assert_eq!(prover_data.pubinp_len.len(), 2);
        assert_eq!(prover_data.precompute.stage_sizes().count(), 3); // one more than the wit
                                                                     // count
        assert_eq!(prover_data.wit_len.len(), 2);
        #[cfg(debug_assertions)]
        prover_data.precompute.type_check();
        let pubinp_len = [prover_data.pubinp_len[0], prover_data.pubinp_len[1]];
        let wit_len = [prover_data.wit_len[0], prover_data.wit_len[1]];
        let rand_list = {
            let idx = prover_data.pubinp_len[0] + prover_data.wit_len[0];
            prover_data.r1cs.vars[idx..idx+prover_data.pubinp_len[1]]
                .iter()
                .map(|var| prover_data.r1cs.names.get(&var).unwrap().clone())
                .collect()
        };
        let precompute = prover_data.precompute.clone();
        let field = prover_data.r1cs.field.clone();
        (pubinp_len, wit_len, rand_list, precompute, field)
    }

    /// Create a new evaluator
    pub fn from_prover_data_inner(pubinp_len: &[usize],
        wit_len: &[usize],
        rand_list: &Vec<String>,
        precompute: &'a StagedWitComp,
        field: &FieldT
    ) -> Self {
        let evaluator = wit_comp::StagedWitCompEvaluator::new(precompute);
        let pubinp_len_copy = [pubinp_len[0], pubinp_len[1]];
        let wit_len_copy = [wit_len[0], wit_len[1]];
        Self {
            pubinp_len: pubinp_len_copy,
            wit_len: wit_len_copy,
            rand_list: rand_list.clone(),
            field: field.clone(),
            evaluator,
            step: Step::Fresh,
        }
    }
    /// Inputs: the prover inputs as a map
    /// Outputs: the public inputs as an array and the first witness
    pub fn inputs_to_wit0(
        &mut self,
        inputs_map: &HashMap<String, Value>,
    ) -> (Assignment, Assignment) {
        let start = Instant::now();
        assert!(matches!(self.step, Step::Fresh));
        self.step = Step::PostWit0;
        // eval twice.
        let start_inner = Instant::now();
        let inputs: Vec<_> = self
            .evaluator
            .eval_stage(inputs_map.clone())
            .into_iter()
            .map(|v| int_to_scalar(&v.as_pf().i()).to_bytes())
            .collect();
        print_time("Time for inputs_to_wit0 inner 0", start_inner.elapsed(), true);
        let start_inner = Instant::now();

        #[cfg(feature = "multicore")]
        let wit0: Vec<_> = self
            .evaluator
            .eval_stage(Default::default())
            .into_par_iter() // Using parallel iterator
            .map(|v| int_to_scalar(&v.as_pf().i()).to_bytes())
            .collect();
        #[cfg(not(feature = "multicore"))]
        let wit0: Vec<_> = self
            .evaluator
            .eval_stage(Default::default())
            .into_iter()
            .map(|v| int_to_scalar(&v.as_pf().i()).to_bytes())
            .collect();
        print_time("Time for inputs_to_wit0 inner 1", start_inner.elapsed(), true);
        assert_eq!(self.wit_len[0], wit0.len());

        print_time("Time for inputs_to_wit0", start.elapsed(), true);

        (
            Assignment::new(&inputs).unwrap(),
            Assignment::new(&wit0).unwrap(),
        )
    }
    /// Inputs: the verifier randomness, as a vector
    /// Outputs: the second witness
    pub fn rand_to_wit1(&mut self, rand: &Vec<OriScalar>) -> Assignment {
        assert!(matches!(self.step, Step::PostWit0));
        self.step = Step::Done;

        let rand_map: HashMap<String, Value> = 
            self.rand_list
                .iter()
                .zip(rand)
                .map(|(var, value)| {
                    (
                        var.clone(),
                        Value::Field(self.field.new_v(scalar_to_int(&value))),
                    )
                })
                .collect(); 

        assert_eq!(self.pubinp_len[1], rand.len());
        #[cfg(feature = "multicore")]
        let wit1: Vec<_> = self
            .evaluator
            .eval_stage(rand_map)
            .into_par_iter() // Using parallel iterator
            .map(|v| int_to_scalar(&v.as_pf().i()).to_bytes())
            .collect();
        #[cfg(not(feature = "multicore"))]
        let wit1: Vec<_> = self
            .evaluator
            .eval_stage(rand_map)
            .into_iter()
            .map(|v| int_to_scalar(&v.as_pf().i()).to_bytes())
            .collect();
        assert_eq!(self.wit_len[1], wit1.len());
        
        Assignment::new(&wit1).unwrap()
    }

}


// Convert Integer to Scalar
fn scalar_to_int(i: &OriScalar) -> Integer {
    Integer::from_digits(&i.to_bytes(), rug::integer::Order::LsfLe)
}

