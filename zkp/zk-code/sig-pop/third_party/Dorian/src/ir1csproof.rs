#![allow(clippy::too_many_arguments)]
use super::commitments::{
  Commitments, 
  // MultiCommitGens
};
use super::dense_mlpoly::{
  DensePolynomial, EqPolynomial, PolyCommitment, 
  PolyCommitmentGens, PolyEvalProof, PolyCommitmentBlinds
};
use super::errors::ProofVerifyError;
use super::group::{CompressedGroup, GroupElement, VartimeMultiscalarMul};
use super::math::Math;
use super::nizk::{EqualityProof, KnowledgeProof, ProductProof};
use super::r1csinstance::R1CSInstance;
use super::random::RandomTape;
use super::scalar::Scalar;
use super::sparse_mlpoly::{SparsePolyEntry, SparsePolynomial};
use super::sumcheck::ZKSumcheckInstanceProof;
use super::timer::Timer;
use super::transcript::{AppendToTranscript, ProofTranscript};
use core::iter;
use merlin::Transcript;
use serde::{Deserialize, Serialize};
use super::r1csproof::{R1CSProof, R1CSSumcheckGens, R1CSGens};

#[cfg(feature = "multicore")]
use rayon::prelude::*;

// use super::group::CompressedGroupExt;

// use crate::{NIZKRandInter, VarsAssignment};

#[derive(Serialize, Deserialize, Debug)]
pub struct IR1CSProof {
  comm_vars_vec: Vec<PolyCommitment>,
  sc_proof_phase1: ZKSumcheckInstanceProof,
  claims_phase2: (
    CompressedGroup,
    CompressedGroup,
    CompressedGroup,
    CompressedGroup,
  ),
  pok_claims_phase2: (KnowledgeProof, ProductProof),
  proof_eq_sc_phase1: EqualityProof,
  sc_proof_phase2: ZKSumcheckInstanceProof,
  comm_vars_at_ry_vec: Vec<CompressedGroup>,
  proof_eval_vars_at_ry_vec: Vec<PolyEvalProof>,
  proof_eq_sc_phase2: EqualityProof,
}

#[derive(Serialize, Deserialize)] 
pub struct IR1CSGens {
  gens_sc: R1CSSumcheckGens,
  gens_pc: PolyCommitmentGens,
  polys: Vec<DensePolynomial>,
  polys_extend: Vec<DensePolynomial>,
}

impl IR1CSGens {
  // pub fn new(label: &'static [u8], _num_cons: usize, wit_len: &Vec<usize>) -> Self {
  pub fn new(label: &'static [u8], _num_cons: usize, wit_len: &[usize]) -> Self {
    let num_vars = wit_len.iter().sum::<usize>();
    let gens = R1CSGens::new(label, _num_cons, num_vars);
    let mut polys = Vec::new();
    let mut start = 0;
    for wit_len in wit_len.iter() {
      let poly = DensePolynomial::new_bool(num_vars, start, start+*wit_len);
      polys.push(poly);
      start += *wit_len;
    }
    if polys.len() == 1 { // without verifier randomness
      let poly = DensePolynomial::new(vec![Scalar::zero(); num_vars]);
      polys.push(poly);
    }
    let mut polys_extend = Vec::new();
    for poly in polys.iter() {
      let mut poly = poly.clone();
      poly.extend(&poly.clone());
      polys_extend.push(poly); // used for the second sum-check
    }
    Self {
      gens_sc: gens.gens_sc,
      gens_pc: gens.gens_pc,
      polys,
      polys_extend,
    }
  }
}


impl IR1CSProof {
  #[inline]
  fn comb_func_sc_two(
      poly_A_comp: &Scalar,
      poly_B0_comp: &Scalar,
      poly_B1_comp: &Scalar,
      poly_C0_comp: &Scalar,
      poly_D_comp: &Scalar
  ) -> Scalar {
      poly_D_comp * (poly_A_comp + (poly_B0_comp - poly_B1_comp) * poly_C0_comp + poly_B1_comp)
  }
  /// Prove phase two
  pub fn prove_phase_two(
    num_rounds: usize,
    claim: &Scalar,
    blind_claim: &Scalar,
    evals_io_one: &mut DensePolynomial,
    // evals_wit: &mut [DensePolynomial; 2],
    evals_wit: (&mut DensePolynomial, &mut DensePolynomial),
    eval_v: &mut DensePolynomial,
    evals_ABC: &mut DensePolynomial,
    gens: &R1CSSumcheckGens,
    transcript: &mut Transcript,
    random_tape: &mut RandomTape,
  ) -> (ZKSumcheckInstanceProof, Vec<Scalar>, Vec<Scalar>, Scalar) {
    let timer = Timer::new("prove_phase_two inner");
    
    // let comb_func = |poly_A_comp: &Scalar,
    //                 poly_B0_comp: &Scalar,
    //                 poly_B1_comp: &Scalar,
    //                 poly_C0_comp: &Scalar,
    //                 poly_D_comp: &Scalar|
    //   -> Scalar { poly_D_comp * 
    //     (poly_A_comp + (poly_B0_comp - poly_B1_comp) * poly_C0_comp + poly_B1_comp) };
    let (sc_proof_phase_two, r, claims, blind_claim_postsc) = ZKSumcheckInstanceProof::prove_cubic_with_four_terms(
      claim,
      blind_claim,
      num_rounds,
      evals_io_one,
      // (&mut evals_wit[0], &mut evals_wit[1]), // Pass as tuple
      evals_wit,
      eval_v,
      evals_ABC,
      // comb_func,
      Self::comb_func_sc_two,
      &gens.gens_1,
      &gens.gens_4, // degree 3 instead of degree 2
      transcript,
      random_tape,
    );
    timer.stop();
    (sc_proof_phase_two, r, claims, blind_claim_postsc)
  }

  fn protocol_name() -> &'static [u8] {
    b"Interactive R1CS proof"
  }

  // fn test_split(vars: &Vec<Scalar>, ry: &Vec<Scalar>) {
  //   println!("test_split");
  //   println!("{:?}", DensePolynomial::new(vars.clone()).evaluate(&ry[1..]));
  //   println!("{:?}", DensePolynomial::new(vars.clone()).evaluate(&ry[1..]));
  //   // let middle: usize = vars.len() - 1;
  //   for i in 0..(1<<ry.len()) {
  //     let mut tmp_ry = Vec::new();
  //     for j in 0..ry.len() {
  //       if i & (1<<j) != 0 {
  //         tmp_ry.push(Scalar::one());
  //       } else {
  //         tmp_ry.push(Scalar::zero());
  //       }
  //     }
  //   }
  // }
  /// Hash the input
  pub fn prove_00(
    input: &[Scalar],
    transcript: &mut Transcript,
  ) {
    transcript.append_protocol_name(IR1CSProof::protocol_name());

    input.append_to_transcript(b"input", transcript);
  }

  /// Hash the committed witness
  pub fn prove_01(
    // vars: &Vec<Scalar>,
    vars: &[Scalar],
    rand_len: usize,
    poly_vars_vec: &mut Vec<DensePolynomial>,
    comm_vars_vec: &mut Vec<PolyCommitment>,
    blinds_vars_vec: &mut Vec<PolyCommitmentBlinds>,
    gens: &IR1CSGens,
    transcript: &mut Transcript,
    random_tape: &mut RandomTape,
  ) -> Vec<Scalar> {
    // create a multilinear polynomial using the supplied assignment for variables
    // let poly_vars = DensePolynomial::new(vars.clone());
    let poly_vars = DensePolynomial::new(vars.to_owned());

    // produce a commitment to the satisfying assignment
    let (comm_vars, blinds_vars) = poly_vars.commit(&gens.gens_pc, Some(random_tape));

    // add the commitment to the prover's transcript
    comm_vars.append_to_transcript(b"poly_commitment", transcript);
    poly_vars_vec.push(poly_vars);
    comm_vars_vec.push(comm_vars);
    blinds_vars_vec.push(blinds_vars);

    transcript.challenge_vector(b"verifier_random", rand_len)
  }

  pub fn prove_1(
    inst: &R1CSInstance,
    vars: &[Scalar], // witness in final round
    wit: &[Scalar],
    input: &[Scalar],
    poly_vars_vec: &mut Vec<DensePolynomial>,
    comm_vars_vec: &mut Vec<PolyCommitment>,
    blinds_vars_vec: &mut Vec<PolyCommitmentBlinds>,
    gens: &IR1CSGens,
    transcript: &mut Transcript,
    random_tape: &mut RandomTape,
  ) -> (IR1CSProof, Vec<Scalar>, Vec<Scalar>) {
    let timer_prove = Timer::new("IR1CSProof::prove1");

    let timer_commit = Timer::new("polycommit");
    
    let z = {
      let num_vars = inst.get_num_vars();
      let wit0_len = wit.len();
      let mut padded_wit = vec![Scalar::zero(); num_vars];
      padded_wit[wit0_len..wit0_len + vars.len()].copy_from_slice(vars);
      let poly_vars = DensePolynomial::new(padded_wit);
      // produce a commitment to the satisfying assignment
      let (comm_vars, blinds_vars) = poly_vars.commit(&gens.gens_pc, Some(random_tape)); // 40 ms
      // add the commitment to the prover's transcript
      comm_vars.append_to_transcript(b"poly_commitment", transcript);

      // let mut z = Vec::with_capacity(num_vars);
      // z.extend_from_slice(wit);
      // z.extend_from_slice(vars);
      // // wit.extend(vars);
      // if z.len() < num_vars {
      //   z.extend(vec![Scalar::zero(); num_vars - wit.len()]);
      // }
      poly_vars_vec.push(poly_vars);
      comm_vars_vec.push(comm_vars);
      blinds_vars_vec.push(blinds_vars.clone());
      let num_inputs = input.len();
      let mut z = vec![Scalar::zero(); num_vars*2];
      z[0..wit0_len].copy_from_slice(wit);
      z[wit0_len..wit0_len+vars.len()].copy_from_slice(vars);
      z[num_vars] = Scalar::one();
      z[num_vars + 1..num_vars + 1 + num_inputs].copy_from_slice(input);
      z
    };

    #[cfg(debug_assertions)]
    {
      let mut witness = wit.to_vec().clone();
      witness.extend(vars);
      if witness.len() < inst.get_num_vars() {
        witness.extend(vec![Scalar::zero(); inst.get_num_vars() - witness.len()]);
      }
      assert!(inst.is_sat(&witness, input));
    }

    timer_commit.stop();

    let timer_sc_proof_phase1 = Timer::new("prove_sc_phase_one");

    // derive the verifier's challenge tau
    let (num_rounds_x, num_rounds_y) = (inst.get_num_cons().log_2(), z.len().log_2());
    let tau = transcript.challenge_vector(b"challenge_tau", num_rounds_x);
    // compute the initial evaluation table for R(\tau, x)
    let mut poly_tau = DensePolynomial::new(EqPolynomial::new(tau).evals());

    let (mut poly_Az, mut poly_Bz, mut poly_Cz) =
      inst.multiply_vec(inst.get_num_cons(), z.len(), &z);
    // let timer_sc_proof_phase1_inner2 = Timer::new("prove_sc_phase_one_inner2");
    let (sc_proof_phase1, rx, _claims_phase1, blind_claim_postsc1) = R1CSProof::prove_phase_one(
      num_rounds_x,
      &mut poly_tau,
      &mut poly_Az,
      &mut poly_Bz,
      &mut poly_Cz,
      &gens.gens_sc,
      transcript,
      random_tape,
    );
    // timer_sc_proof_phase1_inner2.stop();

    // println!("rx {:?}", rx);
    assert_eq!(poly_tau.len(), 1);
    assert_eq!(poly_Az.len(), 1);
    assert_eq!(poly_Bz.len(), 1);
    assert_eq!(poly_Cz.len(), 1);
    timer_sc_proof_phase1.stop();

    let (tau_claim, Az_claim, Bz_claim, Cz_claim) =
      (&poly_tau[0], &poly_Az[0], &poly_Bz[0], &poly_Cz[0]);
    let (Az_blind, Bz_blind, Cz_blind, prod_Az_Bz_blind) = (
      random_tape.random_scalar(b"Az_blind"),
      random_tape.random_scalar(b"Bz_blind"),
      random_tape.random_scalar(b"Cz_blind"),
      random_tape.random_scalar(b"prod_Az_Bz_blind"),
    );

    let (pok_Cz_claim, comm_Cz_claim) = {
      KnowledgeProof::prove(
        &gens.gens_sc.gens_1,
        transcript,
        random_tape,
        Cz_claim,
        &Cz_blind,
      )
    };

    let (proof_prod, comm_Az_claim, comm_Bz_claim, comm_prod_Az_Bz_claims) = {
      let prod = Az_claim * Bz_claim;
      ProductProof::prove(
        &gens.gens_sc.gens_1,
        transcript,
        random_tape,
        Az_claim,
        &Az_blind,
        Bz_claim,
        &Bz_blind,
        &prod,
        &prod_Az_Bz_blind,
      )
    };

    comm_Az_claim.append_to_transcript(b"comm_Az_claim", transcript);
    comm_Bz_claim.append_to_transcript(b"comm_Bz_claim", transcript);
    comm_Cz_claim.append_to_transcript(b"comm_Cz_claim", transcript);
    comm_prod_Az_Bz_claims.append_to_transcript(b"comm_prod_Az_Bz_claims", transcript);

    // prove the final step of sum-check #1
    let taus_bound_rx = tau_claim;
    let blind_expected_claim_postsc1 = taus_bound_rx * (prod_Az_Bz_blind - Cz_blind);
    let claim_post_phase1 = (Az_claim * Bz_claim - Cz_claim) * taus_bound_rx;
    let (proof_eq_sc_phase1, _C1, _C2) = EqualityProof::prove(
      &gens.gens_sc.gens_1,
      transcript,
      random_tape,
      &claim_post_phase1,
      &blind_expected_claim_postsc1,
      &claim_post_phase1,
      &blind_claim_postsc1,
    );

    let timer_sc_proof_phase2 = Timer::new("prove_sc_phase_two");

    // combine the three claims into a single claim
    let r_A = transcript.challenge_scalar(b"challenege_Az");
    let r_B = transcript.challenge_scalar(b"challenege_Bz");
    let r_C = transcript.challenge_scalar(b"challenege_Cz");
    let claim_phase2 = r_A * Az_claim + r_B * Bz_claim + r_C * Cz_claim;
    let blind_claim_phase2 = r_A * Az_blind + r_B * Bz_blind + r_C * Cz_blind;


    let evals_ABC = {
      // let timer_sc_proof_phase2_inner1_1 = Timer::new("prove_sc_phase_two_inner1.1");
      // compute the initial evaluation table for R(\tau, x)
      let evals_rx = EqPolynomial::new(rx.clone()).evals();
      // timer_sc_proof_phase2_inner1_1.stop();
      // let timer_sc_proof_phase2_inner1_2 = Timer::new("prove_sc_phase_two_inner1.2");
      let (evals_A, evals_B, evals_C) =
        inst.compute_eval_table_sparse(inst.get_num_cons(), z.len(), &evals_rx);
      // timer_sc_proof_phase2_inner1_2.stop();

      assert_eq!(evals_A.len(), evals_B.len());
      assert_eq!(evals_A.len(), evals_C.len());
      
      // Pre-allocate the result vector

      #[cfg(feature = "multicore")]
      let result = {
        let mut result = Vec::with_capacity(evals_A.len());
        // Parallelize the map operation
        evals_A.par_iter()
            .zip(evals_B.par_iter())
            .zip(evals_C.par_iter())
            .map(|((a, b), c)| r_A * a + r_B * b + r_C * c)
            .collect_into_vec(&mut result);
        result
      };
      #[cfg(not(feature = "multicore"))]
      let result = (0..evals_A.len())
          .map(|i| r_A * evals_A[i] + r_B * evals_B[i] + r_C * evals_C[i])
          .collect::<Vec<Scalar>>();
      
      result
    };
    // another instance of the sum-check protocol
    let (sc_proof_phase2, ry, claims_phase2, blind_claim_postsc2) = {

      let (mut io_one_poly, mut wit_poly_vec) = {
        let io_one_poly = {
          // let io_one = {
          let num_inputs = input.len();
          // let num_vars = wit.len();
          let num_vars = inst.get_num_vars();
          let mut io_one = vec![Scalar::zero(); 2*num_vars];  // Initialize with zeros directly
          io_one[num_vars] = Scalar::one();  // directly assigning the one after the initial zeros
          io_one[num_vars + 1..num_vars + 1 + num_inputs].copy_from_slice(input);
            // io_one
          // }; // h(ry) = ry[0]\tilde{io, 1}(ry[1:])
          DensePolynomial::new(io_one)
        };
  
        assert_eq!(poly_vars_vec.len(), 2);
        let wit_poly_vec = {
          let ori_len = poly_vars_vec[0].len();
          let mut wit_poly_vec = (
            DensePolynomial::new(vec![Scalar::zero(); 2 * ori_len]),
            DensePolynomial::new(vec![Scalar::zero(); 2 * ori_len]),
          );
          //   DensePolynomial::new(vec![Scalar::zero(); 2 * ori_len]),
          //   DensePolynomial::new(vec![Scalar::zero(); 2 * ori_len]),
          // ];
          
          // wit_poly_vec[0].Z[..ori_len].copy_from_slice(&poly_vars_vec[0].Z);
          // wit_poly_vec[1].Z[..ori_len].copy_from_slice(&poly_vars_vec[1].Z);
          wit_poly_vec.0.Z[..ori_len].copy_from_slice(&poly_vars_vec[0].Z);
          wit_poly_vec.1.Z[..ori_len].copy_from_slice(&poly_vars_vec[1].Z);          
          wit_poly_vec
        };
        (io_one_poly, wit_poly_vec)
      };
    
    
      let (sc_proof_phase2, ry, claims_phase2, blind_claim_postsc2) = IR1CSProof::prove_phase_two(
          num_rounds_y,
          &claim_phase2,
          &blind_claim_phase2,
          // &mut DensePolynomial::new(io_one.clone()),
          &mut io_one_poly,
          (&mut wit_poly_vec.0, &mut wit_poly_vec.1),
          &mut gens.polys_extend[0].clone(),
          &mut DensePolynomial::new(evals_ABC),
          &gens.gens_sc,
          transcript,
          random_tape,
        );

        (sc_proof_phase2, ry, claims_phase2, blind_claim_postsc2)
    }; 

    timer_sc_proof_phase2.stop();

    let timer_polyeval = Timer::new("polyeval");
    // let mut proof_eval_vars_at_ry_vec = Vec::new();
    // let mut comm_vars_at_ry_vec = Vec::new();
    // let mut blind_eval_vec = Vec::new();
    let mut proof_eval_vars_at_ry_vec = Vec::with_capacity(2);
    let mut comm_vars_at_ry_vec = Vec::with_capacity(2);
    let mut blind_eval_vec = Vec::with_capacity(2);
    assert_eq!(poly_vars_vec.len(), blinds_vars_vec.len()); // for debug only

    for (poly_vars, blind_vars) in poly_vars_vec.iter().zip(blinds_vars_vec.iter()) {
      let eval_vars_at_ry = poly_vars.evaluate(&ry[1..]);
      let blind_eval = random_tape.random_scalar(b"blind_eval");
      let (proof_eval_vars_at_ry, comm_vars_at_ry) = PolyEvalProof::prove(
        poly_vars,
        Some(blind_vars),
        &ry[1..],
        &eval_vars_at_ry,
        Some(&blind_eval),
        &gens.gens_pc,
        transcript,
        random_tape,
      );
      proof_eval_vars_at_ry_vec.push(proof_eval_vars_at_ry);
      comm_vars_at_ry_vec.push(comm_vars_at_ry);
      blind_eval_vec.push(blind_eval);
    }

    timer_polyeval.stop();

    // prove the final step of sum-check #2
    let blind_expected_claim_postsc2 = {
      let eval_v0_at_ry = gens.polys[0].evaluate(&ry[1..]);
      // let blind_eval_Z_at_ry = eval_v0_at_ry * blind_eval_vec[0]
      //                           + (Scalar::one() - eval_v0_at_ry) * blind_eval_vec[1];
      let blind_eval_Z_at_ry = (blind_eval_vec[0] - blind_eval_vec[1]) * eval_v0_at_ry + blind_eval_vec[1];
      claims_phase2[4] * blind_eval_Z_at_ry * (Scalar::one() - ry[0]) // claims_phase2[5] = evals_ABC evaluated at ry
    };

    // let actual_z_at_ry = claims_phase2[0] 
    //                     + claims_phase2[1] * claims_phase2[3]
    //                     + claims_phase2[2] * claims_phase2[4];
    let actual_z_at_ry = claims_phase2[0] 
                        + (claims_phase2[1] - claims_phase2[2]) * claims_phase2[3]
                        + claims_phase2[2];                  
    let claim_post_phase2 = actual_z_at_ry * claims_phase2[4];
    let (proof_eq_sc_phase2, _C1, _C2) = EqualityProof::prove(
      &gens.gens_pc.gens.gens_1,
      transcript,
      random_tape,
      &claim_post_phase2,
      &blind_expected_claim_postsc2,
      &claim_post_phase2,
      &blind_claim_postsc2,
    );

    timer_prove.stop();

    (
      IR1CSProof {
        comm_vars_vec: comm_vars_vec.clone(),
        sc_proof_phase1,
        claims_phase2: (
          comm_Az_claim,
          comm_Bz_claim,
          comm_Cz_claim,
          comm_prod_Az_Bz_claims,
        ),
        pok_claims_phase2: (pok_Cz_claim, proof_prod),
        proof_eq_sc_phase1,
        sc_proof_phase2,
        comm_vars_at_ry_vec,
        proof_eval_vars_at_ry_vec,
        proof_eq_sc_phase2,
      },
      rx,
      ry,
    )
  }

  pub fn verify(
    &self,
    num_vars: usize, // might need change
    num_cons: usize,
    pubinp_lens: &[usize], // newlly added
    input: &mut Vec<Scalar>,
    evals: &(Scalar, Scalar, Scalar),
    transcript: &mut Transcript,
    gens: &IR1CSGens,
  ) -> Result<(Vec<Scalar>, Vec<Scalar>), ProofVerifyError> {
    transcript.append_protocol_name(IR1CSProof::protocol_name());

    input.append_to_transcript(b"input", transcript);
    let n = num_vars;
    // add the commitment to the verifier's transcript
    for (rand_len, comm_vars) in pubinp_lens.iter().skip(1)
                                .zip(self.comm_vars_vec.iter().take(self.comm_vars_vec.len()-1)) 
    {
      comm_vars
        .append_to_transcript(b"poly_commitment", transcript);
      let verifier_random = transcript.challenge_vector(b"verifier_random", *rand_len);
      input.extend(&verifier_random);
    }

    self.comm_vars_vec // commitment to the witness in the final round
        .last().unwrap()
        .append_to_transcript(b"poly_commitment", transcript);

    let (num_rounds_x, num_rounds_y) = (num_cons.log_2(), (2 * num_vars).log_2());

    // derive the verifier's challenge tau
    let tau = transcript.challenge_vector(b"challenge_tau", num_rounds_x);
    // verify the first sum-check instance
    let claim_phase1 = Scalar::zero()
      .commit(&Scalar::zero(), &gens.gens_sc.gens_1)
      .compress();
    let (comm_claim_post_phase1, rx) = self.sc_proof_phase1.verify(
      &claim_phase1,
      num_rounds_x,
      3,
      &gens.gens_sc.gens_1,
      &gens.gens_sc.gens_4,
      transcript,
    )?;
    // println!("rx {:?}", rx);
    // perform the intermediate sum-check test with claimed Az, Bz, and Cz
    let (comm_Az_claim, comm_Bz_claim, comm_Cz_claim, comm_prod_Az_Bz_claims) = &self.claims_phase2;
    let (pok_Cz_claim, proof_prod) = &self.pok_claims_phase2;

    pok_Cz_claim.verify(&gens.gens_sc.gens_1, transcript, comm_Cz_claim)?;
    proof_prod.verify(
      &gens.gens_sc.gens_1,
      transcript,
      comm_Az_claim,
      comm_Bz_claim,
      comm_prod_Az_Bz_claims,
    )?;

    comm_Az_claim.append_to_transcript(b"comm_Az_claim", transcript);
    comm_Bz_claim.append_to_transcript(b"comm_Bz_claim", transcript);
    comm_Cz_claim.append_to_transcript(b"comm_Cz_claim", transcript);
    comm_prod_Az_Bz_claims.append_to_transcript(b"comm_prod_Az_Bz_claims", transcript);

    let taus_bound_rx: Scalar = (0..rx.len())
      .map(|i| rx[i] * tau[i] + (Scalar::one() - rx[i]) * (Scalar::one() - tau[i]))
      .product();
    let expected_claim_post_phase1 = (taus_bound_rx
      * (comm_prod_Az_Bz_claims.decompress().unwrap() - comm_Cz_claim.decompress().unwrap()))
    .compress();

    // verify proof that expected_claim_post_phase1 == claim_post_phase1
    self.proof_eq_sc_phase1.verify(
      &gens.gens_sc.gens_1,
      transcript,
      &expected_claim_post_phase1,
      &comm_claim_post_phase1,
    )?;

    // derive three public challenges and then derive a joint claim
    let r_A = transcript.challenge_scalar(b"challenege_Az");
    let r_B = transcript.challenge_scalar(b"challenege_Bz");
    let r_C = transcript.challenge_scalar(b"challenege_Cz");

    // r_A * comm_Az_claim + r_B * comm_Bz_claim + r_C * comm_Cz_claim;
    let comm_claim_phase2 = GroupElement::vartime_multiscalar_mul(
      iter::once(&r_A)
        .chain(iter::once(&r_B))
        .chain(iter::once(&r_C)),
      iter::once(&comm_Az_claim)
        .chain(iter::once(&comm_Bz_claim))
        .chain(iter::once(&comm_Cz_claim))
        .map(|pt| pt.decompress().unwrap())
        .collect::<Vec<GroupElement>>(),
    )
    .compress();

    // verify the joint claim with a sum-check protocol
    let (comm_claim_post_phase2, ry) = self.sc_proof_phase2.verify(
      &comm_claim_phase2,
      num_rounds_y,
      3,
      &gens.gens_sc.gens_1,
      // &gens.gens_sc.gens_3,
      &gens.gens_sc.gens_4,
      transcript,
    )?;

    // verify Z(ry) proof against the initial commitment
    self.comm_vars_at_ry_vec.iter()
      .zip(self.proof_eval_vars_at_ry_vec.iter())
      .zip(self.comm_vars_vec.iter())
      .for_each(|((comm_vars_at_ry, proof_eval_vars_at_ry), comm_vars)| {
        proof_eval_vars_at_ry
          .verify(
            &gens.gens_pc,
            transcript,
            &ry[1..],
            comm_vars_at_ry,
            comm_vars,
          )
          .unwrap();
      });

    let poly_input_eval = {
      // constant term
      let mut input_as_sparse_poly_entries = vec![SparsePolyEntry::new(0, Scalar::one())];
      //remaining inputs
      input_as_sparse_poly_entries.extend(
        (0..input.len())
          .map(|i| SparsePolyEntry::new(i + 1, input[i]))
          .collect::<Vec<SparsePolyEntry>>(),
      );
      SparsePolynomial::new(n.log_2(), input_as_sparse_poly_entries).evaluate(&ry[1..])
    };


    let comm_eval_Z_at_ry = {
      let decompress_comm_vars_at_ry_vec = self.comm_vars_at_ry_vec.iter()
                                            .map(|cm| cm.decompress().unwrap())
                                            .collect::<Vec<GroupElement>>();
      let v0_evaluate_at_ry = gens.polys[0].evaluate(&ry[1..]);
      let vpolys_evaluate_at_ry = [v0_evaluate_at_ry, Scalar::one() - v0_evaluate_at_ry]; 
      
      GroupElement::vartime_multiscalar_mul(
        vpolys_evaluate_at_ry.iter().map(|res| (Scalar::one() - ry[0]) * res)
        // gens.polys.iter().take(decompress_comm_vars_at_ry_vec.len()).map(|poly| (Scalar::one() - ry[0]) * poly.evaluate(&ry[1..])) // to be optimized
          .chain(iter::once(ry[0])), 
        decompress_comm_vars_at_ry_vec.iter()
          .chain(iter::once(
            &poly_input_eval.commit(&Scalar::zero(), &gens.gens_pc.gens.gens_1),
          )),
      )
    };


    // perform the final check in the second sum-check protocol
    let (eval_A_r, eval_B_r, eval_C_r) = evals;
    let expected_claim_post_phase2 =
      ((r_A * eval_A_r + r_B * eval_B_r + r_C * eval_C_r) * comm_eval_Z_at_ry).compress();
    // verify proof that expected_claim_post_phase1 == claim_post_phase1
    self.proof_eq_sc_phase2.verify(
      &gens.gens_sc.gens_1,
      transcript,
      &expected_claim_post_phase2,
      &comm_claim_post_phase2,
    )?;

    Ok((rx, ry))
  }
}