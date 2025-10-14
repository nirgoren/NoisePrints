#![allow(clippy::too_many_arguments)]
#![allow(clippy::type_complexity)]
use super::commitments::{Commitments, MultiCommitGens};
use super::dense_mlpoly::DensePolynomial;
use super::errors::ProofVerifyError;
use super::group::{CompressedGroup, GroupElement, VartimeMultiscalarMul};
use super::nizk::DotProductProof;
use super::random::RandomTape;
use super::scalar::Scalar;
use super::transcript::{AppendToTranscript, ProofTranscript};
use super::unipoly::{CompressedUniPoly, UniPoly};
use core::iter;
use itertools::izip;
use merlin::Transcript;
use serde::{Deserialize, Serialize};

#[cfg(feature = "multicore")]
use rayon::prelude::*;

use crate::Timer;
#[derive(Serialize, Deserialize, Debug)]
pub struct SumcheckInstanceProof {
  compressed_polys: Vec<CompressedUniPoly>,
}

impl SumcheckInstanceProof {
  pub fn new(compressed_polys: Vec<CompressedUniPoly>) -> SumcheckInstanceProof {
    SumcheckInstanceProof { compressed_polys }
  }

  pub fn verify(
    &self,
    claim: Scalar,
    num_rounds: usize,
    degree_bound: usize,
    transcript: &mut Transcript,
  ) -> Result<(Scalar, Vec<Scalar>), ProofVerifyError> {
    let mut e = claim;
    let mut r: Vec<Scalar> = Vec::new();

    // verify that there is a univariate polynomial for each round
    assert_eq!(self.compressed_polys.len(), num_rounds);
    for i in 0..self.compressed_polys.len() {
      let poly = self.compressed_polys[i].decompress(&e);

      // verify degree bound
      assert_eq!(poly.degree(), degree_bound);

      // check if G_k(0) + G_k(1) = e
      assert_eq!(poly.eval_at_zero() + poly.eval_at_one(), e);

      // append the prover's message to the transcript
      poly.append_to_transcript(b"poly", transcript);

      //derive the verifier's challenge for the next round
      let r_i = transcript.challenge_scalar(b"challenge_nextround");

      r.push(r_i);

      // evaluate the claimed degree-ell polynomial at r_i
      e = poly.evaluate(&r_i);
    }

    Ok((e, r))
  }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ZKSumcheckInstanceProof {
  comm_polys: Vec<CompressedGroup>,
  comm_evals: Vec<CompressedGroup>,
  proofs: Vec<DotProductProof>,
}

impl ZKSumcheckInstanceProof {
  pub fn new(
    comm_polys: Vec<CompressedGroup>,
    comm_evals: Vec<CompressedGroup>,
    proofs: Vec<DotProductProof>,
  ) -> Self {
    ZKSumcheckInstanceProof {
      comm_polys,
      comm_evals,
      proofs,
    }
  }

  pub fn verify(
    &self,
    comm_claim: &CompressedGroup,
    num_rounds: usize,
    degree_bound: usize,
    gens_1: &MultiCommitGens,
    gens_n: &MultiCommitGens,
    transcript: &mut Transcript,
  ) -> Result<(CompressedGroup, Vec<Scalar>), ProofVerifyError> {
    // verify degree bound
    assert_eq!(gens_n.n, degree_bound + 1);

    // verify that there is a univariate polynomial for each round
    assert_eq!(self.comm_polys.len(), num_rounds);
    assert_eq!(self.comm_evals.len(), num_rounds);

    let mut r: Vec<Scalar> = Vec::new();
    for i in 0..self.comm_polys.len() {
      let comm_poly = &self.comm_polys[i];

      // append the prover's polynomial to the transcript
      comm_poly.append_to_transcript(b"comm_poly", transcript);

      //derive the verifier's challenge for the next round
      let r_i = transcript.challenge_scalar(b"challenge_nextround");

      // verify the proof of sum-check and evals
      let res = {
        let comm_claim_per_round = if i == 0 {
          comm_claim
        } else {
          &self.comm_evals[i - 1]
        };
        let comm_eval = &self.comm_evals[i];

        // add two claims to transcript
        comm_claim_per_round.append_to_transcript(b"comm_claim_per_round", transcript);
        comm_eval.append_to_transcript(b"comm_eval", transcript);

        // produce two weights
        let w = transcript.challenge_vector(b"combine_two_claims_to_one", 2);

        // compute a weighted sum of the RHS
        let comm_target = GroupElement::vartime_multiscalar_mul(
          w.iter(),
          iter::once(&comm_claim_per_round)
            .chain(iter::once(&comm_eval))
            .map(|pt| pt.decompress().unwrap())
            .collect::<Vec<GroupElement>>(),
        )
        .compress();

        let a = {
          // the vector to use to decommit for sum-check test
          let a_sc = {
            let mut a = vec![Scalar::one(); degree_bound + 1];
            a[0] += Scalar::one();
            a
          };

          // the vector to use to decommit for evaluation
          let a_eval = {
            let mut a = vec![Scalar::one(); degree_bound + 1];
            for j in 1..a.len() {
              a[j] = a[j - 1] * r_i;
            }
            a
          };

          // take weighted sum of the two vectors using w
          assert_eq!(a_sc.len(), a_eval.len());
          (0..a_sc.len())
            .map(|i| w[0] * a_sc[i] + w[1] * a_eval[i])
            .collect::<Vec<Scalar>>()
        };

        self.proofs[i]
          .verify(
            gens_1,
            gens_n,
            transcript,
            &a,
            &self.comm_polys[i],
            &comm_target,
          )
          .is_ok()
      };
      if !res {
        return Err(ProofVerifyError::InternalError);
      }

      r.push(r_i);
    }

    Ok((self.comm_evals[self.comm_evals.len() - 1], r))
  }
}

impl SumcheckInstanceProof {
  pub fn prove_cubic<F>(
    claim: &Scalar,
    num_rounds: usize,
    poly_A: &mut DensePolynomial,
    poly_B: &mut DensePolynomial,
    poly_C: &mut DensePolynomial,
    comb_func: F,
    transcript: &mut Transcript,
  ) -> (Self, Vec<Scalar>, Vec<Scalar>)
  where
    F: Fn(&Scalar, &Scalar, &Scalar) -> Scalar,
  {
    let mut e = *claim;
    let mut r: Vec<Scalar> = Vec::new();
    let mut cubic_polys: Vec<CompressedUniPoly> = Vec::new();
    for _j in 0..num_rounds {
      let mut eval_point_0 = Scalar::zero();
      let mut eval_point_2 = Scalar::zero();
      let mut eval_point_3 = Scalar::zero();

      let len = poly_A.len() / 2;
      for i in 0..len {
        // eval 0: bound_func is A(low)
        eval_point_0 += comb_func(&poly_A[i], &poly_B[i], &poly_C[i]);

        // eval 2: bound_func is -A(low) + 2*A(high)
        let poly_A_bound_point = poly_A[len + i] + poly_A[len + i] - poly_A[i];
        let poly_B_bound_point = poly_B[len + i] + poly_B[len + i] - poly_B[i];
        let poly_C_bound_point = poly_C[len + i] + poly_C[len + i] - poly_C[i];
        eval_point_2 += comb_func(
          &poly_A_bound_point,
          &poly_B_bound_point,
          &poly_C_bound_point,
        );

        // eval 3: bound_func is -2A(low) + 3A(high); computed incrementally with bound_func applied to eval(2)
        let poly_A_bound_point = poly_A_bound_point + poly_A[len + i] - poly_A[i];
        let poly_B_bound_point = poly_B_bound_point + poly_B[len + i] - poly_B[i];
        let poly_C_bound_point = poly_C_bound_point + poly_C[len + i] - poly_C[i];

        eval_point_3 += comb_func(
          &poly_A_bound_point,
          &poly_B_bound_point,
          &poly_C_bound_point,
        );
      }

      let evals = vec![eval_point_0, e - eval_point_0, eval_point_2, eval_point_3];
      let poly = UniPoly::from_evals(&evals);

      // append the prover's message to the transcript
      poly.append_to_transcript(b"poly", transcript);

      //derive the verifier's challenge for the next round
      let r_j = transcript.challenge_scalar(b"challenge_nextround");
      r.push(r_j);
      // bound all tables to the verifier's challenege
      poly_A.bound_poly_var_top(&r_j);
      poly_B.bound_poly_var_top(&r_j);
      poly_C.bound_poly_var_top(&r_j);
      e = poly.evaluate(&r_j);
      cubic_polys.push(poly.compress());
    }

    (
      SumcheckInstanceProof::new(cubic_polys),
      r,
      vec![poly_A[0], poly_B[0], poly_C[0]],
    )
  }

  pub fn prove_cubic_batched<F>(
    claim: &Scalar,
    num_rounds: usize,
    poly_vec_par: (
      &mut Vec<&mut DensePolynomial>,
      &mut Vec<&mut DensePolynomial>,
      &mut DensePolynomial,
    ),
    poly_vec_seq: (
      &mut Vec<&mut DensePolynomial>,
      &mut Vec<&mut DensePolynomial>,
      &mut Vec<&mut DensePolynomial>,
    ),
    coeffs: &[Scalar],
    comb_func: F,
    transcript: &mut Transcript,
  ) -> (
    Self,
    Vec<Scalar>,
    (Vec<Scalar>, Vec<Scalar>, Scalar),
    (Vec<Scalar>, Vec<Scalar>, Vec<Scalar>),
  )
  where
    F: Fn(&Scalar, &Scalar, &Scalar) -> Scalar,
  {
    let (poly_A_vec_par, poly_B_vec_par, poly_C_par) = poly_vec_par;
    let (poly_A_vec_seq, poly_B_vec_seq, poly_C_vec_seq) = poly_vec_seq;

    //let (poly_A_vec_seq, poly_B_vec_seq, poly_C_vec_seq) = poly_vec_seq;
    let mut e = *claim;
    let mut r: Vec<Scalar> = Vec::new();
    let mut cubic_polys: Vec<CompressedUniPoly> = Vec::new();

    for _j in 0..num_rounds {
      let mut evals: Vec<(Scalar, Scalar, Scalar)> = Vec::new();

      for (poly_A, poly_B) in poly_A_vec_par.iter().zip(poly_B_vec_par.iter()) {
        let mut eval_point_0 = Scalar::zero();
        let mut eval_point_2 = Scalar::zero();
        let mut eval_point_3 = Scalar::zero();

        let len = poly_A.len() / 2;
        for i in 0..len {
          // eval 0: bound_func is A(low)
          eval_point_0 += comb_func(&poly_A[i], &poly_B[i], &poly_C_par[i]);

          // eval 2: bound_func is -A(low) + 2*A(high)
          let poly_A_bound_point = poly_A[len + i] + poly_A[len + i] - poly_A[i];
          let poly_B_bound_point = poly_B[len + i] + poly_B[len + i] - poly_B[i];
          let poly_C_bound_point = poly_C_par[len + i] + poly_C_par[len + i] - poly_C_par[i];
          eval_point_2 += comb_func(
            &poly_A_bound_point,
            &poly_B_bound_point,
            &poly_C_bound_point,
          );

          // eval 3: bound_func is -2A(low) + 3A(high); computed incrementally with bound_func applied to eval(2)
          let poly_A_bound_point = poly_A_bound_point + poly_A[len + i] - poly_A[i];
          let poly_B_bound_point = poly_B_bound_point + poly_B[len + i] - poly_B[i];
          let poly_C_bound_point = poly_C_bound_point + poly_C_par[len + i] - poly_C_par[i];

          eval_point_3 += comb_func(
            &poly_A_bound_point,
            &poly_B_bound_point,
            &poly_C_bound_point,
          );
        }

        evals.push((eval_point_0, eval_point_2, eval_point_3));
      }

      for (poly_A, poly_B, poly_C) in izip!(
        poly_A_vec_seq.iter(),
        poly_B_vec_seq.iter(),
        poly_C_vec_seq.iter()
      ) {
        let mut eval_point_0 = Scalar::zero();
        let mut eval_point_2 = Scalar::zero();
        let mut eval_point_3 = Scalar::zero();
        let len = poly_A.len() / 2;
        for i in 0..len {
          // eval 0: bound_func is A(low)
          eval_point_0 += comb_func(&poly_A[i], &poly_B[i], &poly_C[i]);
          // eval 2: bound_func is -A(low) + 2*A(high)
          let poly_A_bound_point = poly_A[len + i] + poly_A[len + i] - poly_A[i];
          let poly_B_bound_point = poly_B[len + i] + poly_B[len + i] - poly_B[i];
          let poly_C_bound_point = poly_C[len + i] + poly_C[len + i] - poly_C[i];
          eval_point_2 += comb_func(
            &poly_A_bound_point,
            &poly_B_bound_point,
            &poly_C_bound_point,
          );
          // eval 3: bound_func is -2A(low) + 3A(high); computed incrementally with bound_func applied to eval(2)
          let poly_A_bound_point = poly_A_bound_point + poly_A[len + i] - poly_A[i];
          let poly_B_bound_point = poly_B_bound_point + poly_B[len + i] - poly_B[i];
          let poly_C_bound_point = poly_C_bound_point + poly_C[len + i] - poly_C[i];
          eval_point_3 += comb_func(
            &poly_A_bound_point,
            &poly_B_bound_point,
            &poly_C_bound_point,
          );
        }
        evals.push((eval_point_0, eval_point_2, eval_point_3));
      }

      let evals_combined_0 = (0..evals.len()).map(|i| evals[i].0 * coeffs[i]).sum();
      let evals_combined_2 = (0..evals.len()).map(|i| evals[i].1 * coeffs[i]).sum();
      let evals_combined_3 = (0..evals.len()).map(|i| evals[i].2 * coeffs[i]).sum();

      let evals = vec![
        evals_combined_0,
        e - evals_combined_0,
        evals_combined_2,
        evals_combined_3,
      ];
      let poly = UniPoly::from_evals(&evals);

      // append the prover's message to the transcript
      poly.append_to_transcript(b"poly", transcript);

      //derive the verifier's challenge for the next round
      let r_j = transcript.challenge_scalar(b"challenge_nextround");
      r.push(r_j);

      // bound all tables to the verifier's challenege
      for (poly_A, poly_B) in poly_A_vec_par.iter_mut().zip(poly_B_vec_par.iter_mut()) {
        poly_A.bound_poly_var_top(&r_j);
        poly_B.bound_poly_var_top(&r_j);
      }
      poly_C_par.bound_poly_var_top(&r_j);

      for (poly_A, poly_B, poly_C) in izip!(
        poly_A_vec_seq.iter_mut(),
        poly_B_vec_seq.iter_mut(),
        poly_C_vec_seq.iter_mut()
      ) {
        poly_A.bound_poly_var_top(&r_j);
        poly_B.bound_poly_var_top(&r_j);
        poly_C.bound_poly_var_top(&r_j);
      }

      e = poly.evaluate(&r_j);
      cubic_polys.push(poly.compress());
    }

    let poly_A_par_final = (0..poly_A_vec_par.len())
      .map(|i| poly_A_vec_par[i][0])
      .collect();
    let poly_B_par_final = (0..poly_B_vec_par.len())
      .map(|i| poly_B_vec_par[i][0])
      .collect();
    let claims_prod = (poly_A_par_final, poly_B_par_final, poly_C_par[0]);

    let poly_A_seq_final = (0..poly_A_vec_seq.len())
      .map(|i| poly_A_vec_seq[i][0])
      .collect();
    let poly_B_seq_final = (0..poly_B_vec_seq.len())
      .map(|i| poly_B_vec_seq[i][0])
      .collect();
    let poly_C_seq_final = (0..poly_C_vec_seq.len())
      .map(|i| poly_C_vec_seq[i][0])
      .collect();
    let claims_dotp = (poly_A_seq_final, poly_B_seq_final, poly_C_seq_final);

    (
      SumcheckInstanceProof::new(cubic_polys),
      r,
      claims_prod,
      claims_dotp,
    )
  }
}

impl ZKSumcheckInstanceProof {
  pub fn prove_quad<F>(
    claim: &Scalar,
    blind_claim: &Scalar,
    num_rounds: usize,
    poly_A: &mut DensePolynomial,
    poly_B: &mut DensePolynomial,
    comb_func: F,
    gens_1: &MultiCommitGens,
    gens_n: &MultiCommitGens,
    transcript: &mut Transcript,
    random_tape: &mut RandomTape,
  ) -> (Self, Vec<Scalar>, Vec<Scalar>, Scalar)
  where
    F: Fn(&Scalar, &Scalar) -> Scalar,
  {
    let (blinds_poly, blinds_evals) = (
      random_tape.random_vector(b"blinds_poly", num_rounds),
      random_tape.random_vector(b"blinds_evals", num_rounds),
    );
    let mut claim_per_round = *claim;
    let mut comm_claim_per_round = claim_per_round.commit(blind_claim, gens_1).compress();

    let mut r: Vec<Scalar> = Vec::new();
    let mut comm_polys: Vec<CompressedGroup> = Vec::new();
    let mut comm_evals: Vec<CompressedGroup> = Vec::new();
    let mut proofs: Vec<DotProductProof> = Vec::new();

    for j in 0..num_rounds {
      let (poly, comm_poly) = {
        let mut eval_point_0 = Scalar::zero();
        let mut eval_point_2 = Scalar::zero();

        let len = poly_A.len() / 2;
        for i in 0..len {
          // eval 0: bound_func is A(low)
          eval_point_0 += comb_func(&poly_A[i], &poly_B[i]);

          // eval 2: bound_func is -A(low) + 2*A(high)
          let poly_A_bound_point = poly_A[len + i] + poly_A[len + i] - poly_A[i];
          let poly_B_bound_point = poly_B[len + i] + poly_B[len + i] - poly_B[i];
          eval_point_2 += comb_func(&poly_A_bound_point, &poly_B_bound_point);
        }

        let evals = vec![eval_point_0, claim_per_round - eval_point_0, eval_point_2];
        let poly = UniPoly::from_evals(&evals);
        let comm_poly = poly.commit(gens_n, &blinds_poly[j]).compress();
        (poly, comm_poly)
      };

      // append the prover's message to the transcript
      comm_poly.append_to_transcript(b"comm_poly", transcript);
      comm_polys.push(comm_poly);

      //derive the verifier's challenge for the next round
      let r_j = transcript.challenge_scalar(b"challenge_nextround");

      // bound all tables to the verifier's challenege
      poly_A.bound_poly_var_top(&r_j);
      poly_B.bound_poly_var_top(&r_j);

      // produce a proof of sum-check and of evaluation
      let (proof, claim_next_round, comm_claim_next_round) = {
        let eval = poly.evaluate(&r_j);
        let comm_eval = eval.commit(&blinds_evals[j], gens_1).compress();

        // we need to prove the following under homomorphic commitments:
        // (1) poly(0) + poly(1) = claim_per_round
        // (2) poly(r_j) = eval

        // Our technique is to leverage dot product proofs:
        // (1) we can prove: <poly_in_coeffs_form, (2, 1, 1, 1)> = claim_per_round
        // (2) we can prove: <poly_in_coeffs_form, (1, r_j, r^2_j, ..) = eval
        // for efficiency we batch them using random weights

        // add two claims to transcript
        comm_claim_per_round.append_to_transcript(b"comm_claim_per_round", transcript);
        comm_eval.append_to_transcript(b"comm_eval", transcript);

        // produce two weights
        let w = transcript.challenge_vector(b"combine_two_claims_to_one", 2);

        // compute a weighted sum of the RHS
        let target = w[0] * claim_per_round + w[1] * eval;
        let comm_target = GroupElement::vartime_multiscalar_mul(
          w.iter(),
          iter::once(&comm_claim_per_round)
            .chain(iter::once(&comm_eval))
            .map(|pt| pt.decompress().unwrap())
            .collect::<Vec<GroupElement>>(),
        )
        .compress();

        let blind = {
          let blind_sc = if j == 0 {
            blind_claim
          } else {
            &blinds_evals[j - 1]
          };

          let blind_eval = &blinds_evals[j];

          w[0] * blind_sc + w[1] * blind_eval
        };
        assert_eq!(target.commit(&blind, gens_1).compress(), comm_target);

        let a = {
          // the vector to use to decommit for sum-check test
          let a_sc = {
            let mut a = vec![Scalar::one(); poly.degree() + 1];
            a[0] += Scalar::one();
            a
          };

          // the vector to use to decommit for evaluation
          let a_eval = {
            let mut a = vec![Scalar::one(); poly.degree() + 1];
            for j in 1..a.len() {
              a[j] = a[j - 1] * r_j;
            }
            a
          };

          // take weighted sum of the two vectors using w
          assert_eq!(a_sc.len(), a_eval.len());
          (0..a_sc.len())
            .map(|i| w[0] * a_sc[i] + w[1] * a_eval[i])
            .collect::<Vec<Scalar>>()
        };

        let (proof, _comm_poly, _comm_sc_eval) = DotProductProof::prove(
          gens_1,
          gens_n,
          transcript,
          random_tape,
          &poly.as_vec(),
          &blinds_poly[j],
          &a,
          &target,
          &blind,
        );

        (proof, eval, comm_eval)
      };

      claim_per_round = claim_next_round;
      comm_claim_per_round = comm_claim_next_round;

      proofs.push(proof);
      r.push(r_j);
      comm_evals.push(comm_claim_per_round);
    }

    (
      ZKSumcheckInstanceProof::new(comm_polys, comm_evals, proofs),
      r,
      vec![poly_A[0], poly_B[0]],
      blinds_evals[num_rounds - 1],
    )
  }

  fn bound_four_polynomial (
    poly_A: &mut DensePolynomial,
    poly_B: &mut DensePolynomial,
    poly_C: &mut DensePolynomial,
    poly_D: &mut DensePolynomial,
    r_j: &Scalar,
  ) {
    poly_A.bound_poly_var_top(r_j);
    poly_B.bound_poly_var_top(r_j);
    poly_C.bound_poly_var_top(r_j);
    poly_D.bound_poly_var_top(r_j);
  }

  #[cfg(feature = "multicore")]
  fn bound_four_polynomial_parallel(
      poly_A: &mut DensePolynomial,
      poly_B: &mut DensePolynomial,
      poly_C: &mut DensePolynomial,
      poly_D: &mut DensePolynomial,
      r_j: &Scalar,
  ) {
      rayon::join(
          || poly_A.bound_poly_var_top(r_j),
          || rayon::join(
              || poly_B.bound_poly_var_top(r_j),
              || rayon::join(
                  || poly_C.bound_poly_var_top(r_j),
                  || poly_D.bound_poly_var_top(r_j),
              )
          )
      );
  }

  pub fn prove_cubic_with_additive_term<F>(
    claim: &Scalar,
    blind_claim: &Scalar,
    num_rounds: usize,
    poly_A: &mut DensePolynomial,
    poly_B: &mut DensePolynomial,
    poly_C: &mut DensePolynomial,
    poly_D: &mut DensePolynomial,
    comb_func: F,
    gens_1: &MultiCommitGens,
    gens_n: &MultiCommitGens,
    transcript: &mut Transcript,
    random_tape: &mut RandomTape,
  ) -> (Self, Vec<Scalar>, Vec<Scalar>, Scalar)
  where
    F: Fn(&Scalar, &Scalar, &Scalar, &Scalar) -> Scalar,
  {
    let (blinds_poly, blinds_evals) = (
      random_tape.random_vector(b"blinds_poly", num_rounds),
      random_tape.random_vector(b"blinds_evals", num_rounds),
    );

    let mut claim_per_round = *claim;
    let mut comm_claim_per_round = claim_per_round.commit(blind_claim, gens_1).compress();

    let mut r: Vec<Scalar> = Vec::new();
    let mut comm_polys: Vec<CompressedGroup> = Vec::new();
    let mut comm_evals: Vec<CompressedGroup> = Vec::new();
    let mut proofs: Vec<DotProductProof> = Vec::new();


    for j in 0..num_rounds {

      let (poly, comm_poly) = {
        let mut eval_point_0 = Scalar::zero();
        let mut eval_point_2 = Scalar::zero();
        let mut eval_point_3 = Scalar::zero();

        let len = poly_A.len() / 2;
        // let timer = Timer::new("cubic_with_additive_term_inner");

        for i in 0..len {
          // eval 0: bound_func is A(low)
          eval_point_0 += comb_func(&poly_A[i], &poly_B[i], &poly_C[i], &poly_D[i]);

          // eval 2: bound_func is -A(low) + 2*A(high)
          let poly_A_bound_point = poly_A[len + i] + poly_A[len + i] - poly_A[i];
          let poly_B_bound_point = poly_B[len + i] + poly_B[len + i] - poly_B[i];
          let poly_C_bound_point = poly_C[len + i] + poly_C[len + i] - poly_C[i];
          let poly_D_bound_point = poly_D[len + i] + poly_D[len + i] - poly_D[i];
          eval_point_2 += comb_func(
            &poly_A_bound_point,
            &poly_B_bound_point,
            &poly_C_bound_point,
            &poly_D_bound_point,
          );

          // eval 3: bound_func is -2A(low) + 3A(high); computed incrementally with bound_func applied to eval(2)
          let poly_A_bound_point = poly_A_bound_point + poly_A[len + i] - poly_A[i];
          let poly_B_bound_point = poly_B_bound_point + poly_B[len + i] - poly_B[i];
          let poly_C_bound_point = poly_C_bound_point + poly_C[len + i] - poly_C[i];
          let poly_D_bound_point = poly_D_bound_point + poly_D[len + i] - poly_D[i];
          eval_point_3 += comb_func(
            &poly_A_bound_point,
            &poly_B_bound_point,
            &poly_C_bound_point,
            &poly_D_bound_point,
          );
        }
        // timer.stop();

        let evals = vec![
          eval_point_0,
          claim_per_round - eval_point_0,
          eval_point_2,
          eval_point_3,
        ];
        let poly = UniPoly::from_evals(&evals);
        let comm_poly = poly.commit(gens_n, &blinds_poly[j]).compress();
        (poly, comm_poly)
      };

      // append the prover's message to the transcript
      comm_poly.append_to_transcript(b"comm_poly", transcript);
      comm_polys.push(comm_poly);

      //derive the verifier's challenge for the next round
      let r_j = transcript.challenge_scalar(b"challenge_nextround");

      // #[cfg(not(feature = "multicore"))]
      // Self::bound_four_polynomial(poly_A, poly_B, poly_C, poly_D, &r_j);
      // #[cfg(feature = "multicore")]
      // Self::bound_four_polynomial_parallel(poly_A, poly_B, poly_C, poly_D, &r_j);

      // bound all tables to the verifier's challenege
      poly_A.bound_poly_var_top(&r_j);
      poly_B.bound_poly_var_top(&r_j);
      poly_C.bound_poly_var_top(&r_j);
      poly_D.bound_poly_var_top(&r_j);

      // produce a proof of sum-check and of evaluation
      let (proof, claim_next_round, comm_claim_next_round) = {
        let eval = poly.evaluate(&r_j);
        let comm_eval = eval.commit(&blinds_evals[j], gens_1).compress();

        // we need to prove the following under homomorphic commitments:
        // (1) poly(0) + poly(1) = claim_per_round
        // (2) poly(r_j) = eval

        // Our technique is to leverage dot product proofs:
        // (1) we can prove: <poly_in_coeffs_form, (2, 1, 1, 1)> = claim_per_round
        // (2) we can prove: <poly_in_coeffs_form, (1, r_j, r^2_j, ..) = eval
        // for efficiency we batch them using random weights

        // add two claims to transcript
        comm_claim_per_round.append_to_transcript(b"comm_claim_per_round", transcript);
        comm_eval.append_to_transcript(b"comm_eval", transcript);

        // produce two weights
        let w = transcript.challenge_vector(b"combine_two_claims_to_one", 2);

        // compute a weighted sum of the RHS
        let target = w[0] * claim_per_round + w[1] * eval;
        let comm_target = GroupElement::vartime_multiscalar_mul(
          w.iter(),
          iter::once(&comm_claim_per_round)
            .chain(iter::once(&comm_eval))
            .map(|pt| pt.decompress().unwrap())
            .collect::<Vec<GroupElement>>(),
        )
        .compress();

        let blind = {
          let blind_sc = if j == 0 {
            blind_claim
          } else {
            &blinds_evals[j - 1]
          };

          let blind_eval = &blinds_evals[j];

          w[0] * blind_sc + w[1] * blind_eval
        };

        assert_eq!(target.commit(&blind, gens_1).compress(), comm_target);

        let a = {
          // the vector to use to decommit for sum-check test
          let a_sc = {
            let mut a = vec![Scalar::one(); poly.degree() + 1];
            a[0] += Scalar::one();
            a
          };

          // the vector to use to decommit for evaluation
          let a_eval = {
            let mut a = vec![Scalar::one(); poly.degree() + 1];
            for j in 1..a.len() {
              a[j] = a[j - 1] * r_j;
            }
            a
          };

          // take weighted sum of the two vectors using w
          assert_eq!(a_sc.len(), a_eval.len());
          (0..a_sc.len())
            .map(|i| w[0] * a_sc[i] + w[1] * a_eval[i])
            .collect::<Vec<Scalar>>()
        };

        let (proof, _comm_poly, _comm_sc_eval) = DotProductProof::prove(
          gens_1,
          gens_n,
          transcript,
          random_tape,
          &poly.as_vec(),
          &blinds_poly[j],
          &a,
          &target,
          &blind,
        );

        (proof, eval, comm_eval)
      };

      proofs.push(proof);
      claim_per_round = claim_next_round;
      comm_claim_per_round = comm_claim_next_round;
      r.push(r_j);
      comm_evals.push(comm_claim_per_round);

    }

    (
      ZKSumcheckInstanceProof::new(comm_polys, comm_evals, proofs),
      r,
      vec![poly_A[0], poly_B[0], poly_C[0], poly_D[0]],
      blinds_evals[num_rounds - 1],
    )
  }

  fn bound_five_polynomial(
    poly_A: &mut DensePolynomial,
    poly_B0: &mut DensePolynomial,
    poly_B1: &mut DensePolynomial,
    poly_C: &mut DensePolynomial,
    poly_D: &mut DensePolynomial,
    r_j: &Scalar,
  ) {
    poly_A.bound_poly_var_top(r_j);
    poly_B0.bound_poly_var_top(r_j);
    poly_B1.bound_poly_var_top(r_j);
    // for poly_B in polys_B.iter_mut() {
    //   poly_B.bound_poly_var_top(r_j);
    // }
    poly_C.bound_poly_var_top(r_j);
    poly_D.bound_poly_var_top(r_j);
  }
  
  #[cfg(feature = "multicore")]
  fn bound_five_polynomial_parallel(
    poly_A: &mut DensePolynomial,
    poly_B0: &mut DensePolynomial,
    poly_B1: &mut DensePolynomial,
    poly_C: &mut DensePolynomial,
    poly_D: &mut DensePolynomial,
    r_j: &Scalar,
  ) {
      rayon::join(
          || poly_A.bound_poly_var_top(r_j),
          || rayon::join(
              || poly_B0.bound_poly_var_top(r_j),
              || rayon::join(
                  || poly_B1.bound_poly_var_top(r_j),
                  || rayon::join(
                      || poly_C.bound_poly_var_top(r_j),
                      || poly_D.bound_poly_var_top(r_j)
                  )
              )
          )
      );
  }

  fn prove_cubic_with_four_terms_inner<F>(
    poly_A: &DensePolynomial,
    // polys_B: &[DensePolynomial; 2],
    poly_B0: &DensePolynomial,
    poly_B1: &DensePolynomial,
    poly_C: &DensePolynomial,
    poly_D: &DensePolynomial,
    comb_func: F,
    len: usize,
  ) -> (Scalar, Scalar, Scalar) 
  where
    F: Fn(&Scalar, &Scalar, &Scalar, &Scalar, &Scalar) -> Scalar + Sync,
  {
    let mut eval_point_0 = Scalar::zero();
    let mut eval_point_2 = Scalar::zero();
    let mut eval_point_3 = Scalar::zero();
    for i in 0..len {
      // eval 0: bound_func is A(low)
      eval_point_0 += comb_func(&poly_A[i], 
                        &poly_B0[i], 
                        &poly_B1[i], 
                        &poly_C[i], 
                        &poly_D[i],
                      );

      // eval 2: bound_func is -A(low) + 2*A(high)
      let poly_A_bound_point = poly_A[len + i] + poly_A[len + i] - poly_A[i];
      // let poly_B_bound_points = {
      //   let mut poly_B_bound_points = [Scalar::zero(); 2];
      //   for k in 0..2 {
      //     poly_B_bound_points[k] = polys_B[k][len + i] + polys_B[k][len + i] - polys_B[k][i];
      //   }
      //   poly_B_bound_points
      // };
      let poly_B_bound_points = [
        poly_B0[len + i] + poly_B0[len + i] - poly_B0[i],
        poly_B1[len + i] + poly_B1[len + i] - poly_B1[i],
      ];

      let poly_C_bound_point = poly_C[len + i] + poly_C[len + i] - poly_C[i];

      let poly_D_bound_point = poly_D[len + i] + poly_D[len + i] - poly_D[i];
      eval_point_2 += comb_func(
        &poly_A_bound_point,
        &poly_B_bound_points[0],
        &poly_B_bound_points[1],
        &poly_C_bound_point,
        &poly_D_bound_point,
      );

      // eval 3: bound_func is -2A(low) + 3A(high); computed incrementally with bound_func applied to eval(2)
      let poly_A_bound_point = poly_A_bound_point + poly_A[len + i] - poly_A[i];
      // let poly_B_bound_points = {
      //   let mut cur_points = [Scalar::zero(); 2];
      //   for k in 0..2 {
      //     cur_points[k] = poly_B_bound_points[k] + polys_B[k][len + i] - polys_B[k][i];
      //   }
      //   cur_points
      // };
      let poly_B_bound_points = [
        poly_B_bound_points[0] + poly_B0[len + i] - poly_B0[i],
        poly_B_bound_points[1] + poly_B1[len + i] - poly_B1[i],
      ];
      let poly_C_bound_point = poly_C_bound_point + poly_C[len + i] - poly_C[i];

      
      // println!("sum: {:?}", poly_C_bound_points[0]+poly_C_bound_points[1]);
      let poly_D_bound_point = poly_D_bound_point + poly_D[len + i] - poly_D[i];
      eval_point_3 += comb_func(
        &poly_A_bound_point,
        &poly_B_bound_points[0],
        &poly_B_bound_points[1],
        &poly_C_bound_point,
        &poly_D_bound_point,
      );
    }
    (eval_point_0, eval_point_2, eval_point_3)
  }

  #[cfg(feature = "multicore")]
  fn prove_cubic_with_four_terms_inner_parallel<F>(
    poly_A: &DensePolynomial,
    // polys_B: &[DensePolynomial; 2],
    // polys_B: (&DensePolynomial, &DensePolynomial),
    poly_B0: &DensePolynomial,
    poly_B1: &DensePolynomial,
    poly_C: &DensePolynomial,
    poly_D: &DensePolynomial,
    comb_func: F,
    len: usize,
  ) -> (Scalar, Scalar, Scalar) 
  where
    F: Fn(&Scalar, &Scalar, &Scalar, &Scalar, &Scalar) -> Scalar + Sync,
  {
    (0..len).into_par_iter().map(|i| {
      let eval_0 = comb_func(
          &poly_A[i],
          &poly_B0[i],
          &poly_B1[i],
          &poly_C[i],
          &poly_D[i],
      );

      let poly_A_bound_point = poly_A[len + i] + poly_A[len + i] - poly_A[i];
      let poly_B_bound_points = [
          poly_B0[len + i] + poly_B0[len + i] - poly_B0[i],
          poly_B1[len + i] + poly_B1[len + i] - poly_B1[i],
      ];
      // let poly_B_bound_points: [Scalar; 2] = {
      //     let mut poly_B_bound_points = [Scalar::zero(); 2];
      //     for k in 0..2 {
      //         poly_B_bound_points[k] = polys_B[k][len + i] + polys_B[k][len + i] - polys_B[k][i];
      //     }
      //     poly_B_bound_points
      // };

      let poly_C_bound_point = poly_C[len + i] + poly_C[len + i] - poly_C[i];
      let poly_D_bound_point = poly_D[len + i] + poly_D[len + i] - poly_D[i];
      let eval_2 = comb_func(
          &poly_A_bound_point,
          &poly_B_bound_points[0],
          &poly_B_bound_points[1],
          &poly_C_bound_point,
          &poly_D_bound_point,
      );

      let poly_A_bound_point = poly_A_bound_point + poly_A[len + i] - poly_A[i];
      // let poly_B_bound_points: [Scalar; 2] = {
      //     let mut cur_points = [Scalar::zero(); 2];
      //     for k in 0..2 {
      //         cur_points[k] = poly_B_bound_points[k] + polys_B[k][len + i] - polys_B[k][i];
      //     }
      //     cur_points
      // };
      let poly_B_bound_points = [
          poly_B_bound_points[0] + poly_B0[len + i] - poly_B0[i],
          poly_B_bound_points[1] + poly_B1[len + i] - poly_B1[i],
      ];

      let poly_C_bound_point = poly_C_bound_point + poly_C[len + i] - poly_C[i];
      let poly_D_bound_point = poly_D_bound_point + poly_D[len + i] - poly_D[i];
      let eval_3 = comb_func(
          &poly_A_bound_point,
          &poly_B_bound_points[0],
          &poly_B_bound_points[1],
          &poly_C_bound_point,
          &poly_D_bound_point,
      );

      (eval_0, eval_2, eval_3)
    }).reduce(
        || (Scalar::zero(), Scalar::zero(), Scalar::zero()),
        |(acc0, acc2, acc3), (eval_0, eval_2, eval_3)| (acc0 + eval_0, acc2 + eval_2, acc3 + eval_3),
    )
  }
  // polys_B[0]*polys_C[0] + polys_B[1]*polys_C[1] + poly_A 
  pub fn prove_cubic_with_four_terms<F>(
    claim: &Scalar,
    blind_claim: &Scalar,
    num_rounds: usize,
    poly_A: &mut DensePolynomial,
    // polys_B: &mut [DensePolynomial; 2],
    polys_B: (&mut DensePolynomial, &mut DensePolynomial),
    poly_C: &mut DensePolynomial,
    poly_D: &mut DensePolynomial,
    comb_func: F,
    gens_1: &MultiCommitGens,
    gens_n: &MultiCommitGens,
    transcript: &mut Transcript,
    random_tape: &mut RandomTape,
  ) -> (Self, Vec<Scalar>, Vec<Scalar>, Scalar)
  where
    F: Fn(&Scalar, &Scalar, &Scalar, &Scalar, &Scalar) -> Scalar + Sync,
  {
    let (blinds_poly, blinds_evals) = (
      random_tape.random_vector(b"blinds_poly", num_rounds),
      random_tape.random_vector(b"blinds_evals", num_rounds),
    );

    let mut claim_per_round = *claim;
    let mut comm_claim_per_round = claim_per_round.commit(blind_claim, gens_1).compress();

    let mut r: Vec<Scalar> = Vec::new();
    // let mut comm_polys: Vec<CompressedGroup> = Vec::new();
    // let mut comm_evals: Vec<CompressedGroup> = Vec::new();
    // let mut proofs: Vec<DotProductProof> = Vec::new();

    let mut comm_polys: Vec<CompressedGroup> = Vec::with_capacity(num_rounds);
    let mut comm_evals: Vec<CompressedGroup> = Vec::with_capacity(num_rounds);
    let mut proofs: Vec<DotProductProof> = Vec::with_capacity(num_rounds);

    // let timer_sc_inner_outside = Timer::new("prove_sc_phase_two_inner_outside_forloop");

    for j in 0..num_rounds {
      let (poly, comm_poly) = {

        let len = poly_A.len() / 2;
        #[cfg(not(feature = "multicore"))]
        let (eval_point_0, eval_point_2, eval_point_3) = 
          Self::prove_cubic_with_four_terms_inner(poly_A, polys_B.0, polys_B.1, poly_C, poly_D, &comb_func, len);

        #[cfg(feature = "multicore")]
        let (eval_point_0, eval_point_2, eval_point_3) = 
        if j > 2 {
          Self::prove_cubic_with_four_terms_inner(poly_A, polys_B.0, polys_B.1, poly_C, poly_D, &comb_func, len)
        }
        else {
          Self::prove_cubic_with_four_terms_inner_parallel(poly_A, polys_B.0, polys_B.1, poly_C, poly_D, &comb_func, len)
        };

        let evals = vec![
          eval_point_0,
          claim_per_round - eval_point_0,
          eval_point_2,
          eval_point_3,
        ];
        let poly = UniPoly::from_evals(&evals);
        let comm_poly = poly.commit(gens_n, &blinds_poly[j]).compress();

        (poly, comm_poly)
      };

      // append the prover's message to the transcript
      comm_poly.append_to_transcript(b"comm_poly", transcript);
      comm_polys.push(comm_poly);

      //derive the verifier's challenge for the next round
      let r_j = transcript.challenge_scalar(b"challenge_nextround");

      // let timer = Timer::new("cubic_with_cubic_term_inner");

      // bound all tables to the verifier's challenege
      #[cfg(not(feature = "multicore"))]
      Self::bound_five_polynomial(poly_A, polys_B.0, polys_B.1, poly_C, poly_D, &r_j);
      #[cfg(feature = "multicore")]
      {
        // if j > 2 {
        //   Self::bound_five_polynomial(poly_A, polys_B.0, polys_B.1, poly_C, poly_D, &r_j);
        // } else {
          Self::bound_five_polynomial_parallel(poly_A, polys_B.0, polys_B.1, poly_C, poly_D, &r_j);
        // }
      }
      // let timer_sc_inner2 = Timer::new("prove_sc_phase_two_inner_forloop2");
      // timer.stop();
      // produce a proof of sum-check and of evaluation
      let (proof, claim_next_round, comm_claim_next_round) = {
        let eval = poly.evaluate(&r_j);
        let comm_eval = eval.commit(&blinds_evals[j], gens_1).compress();
        // we need to prove the following under homomorphic commitments:
        // (1) poly(0) + poly(1) = claim_per_round
        // (2) poly(r_j) = eval

        // Our technique is to leverage dot product proofs:
        // (1) we can prove: <poly_in_coeffs_form, (2, 1, 1, 1)> = claim_per_round
        // (2) we can prove: <poly_in_coeffs_form, (1, r_j, r^2_j, ..) = eval
        // for efficiency we batch them using random weights

        // add two claims to transcript
        comm_claim_per_round.append_to_transcript(b"comm_claim_per_round", transcript);
        comm_eval.append_to_transcript(b"comm_eval", transcript);

        // produce two weights
        let w = transcript.challenge_vector(b"combine_two_claims_to_one", 2);

        // compute a weighted sum of the RHS
        let target = w[0] * claim_per_round + w[1] * eval;
        let comm_target = GroupElement::vartime_multiscalar_mul(
          w.iter(),
          iter::once(&comm_claim_per_round)
            .chain(iter::once(&comm_eval))
            .map(|pt| pt.decompress().unwrap())
            .collect::<Vec<GroupElement>>(),
        )
        .compress();

        let blind = {
          let blind_sc = if j == 0 {
            blind_claim
          } else {
            &blinds_evals[j - 1]
          };

          let blind_eval = &blinds_evals[j];

          w[0] * blind_sc + w[1] * blind_eval
        };

        assert_eq!(target.commit(&blind, gens_1).compress(), comm_target);


        let a = {
          // the vector to use to decommit for sum-check test
          let a_sc = {
            let mut a = vec![Scalar::one(); poly.degree() + 1];
            a[0] += Scalar::one();
            a
          };

          // the vector to use to decommit for evaluation
          let a_eval = {
            let mut a = vec![Scalar::one(); poly.degree() + 1];
            for j in 1..a.len() {
              a[j] = a[j - 1] * r_j;
            }
            a
          };

          // take weighted sum of the two vectors using w
          assert_eq!(a_sc.len(), a_eval.len());
          (0..a_sc.len())
            .map(|i| w[0] * a_sc[i] + w[1] * a_eval[i])
            .collect::<Vec<Scalar>>()
        };

        let (proof, _comm_poly, _comm_sc_eval) = DotProductProof::prove(
          gens_1,
          gens_n,
          transcript,
          random_tape,
          &poly.as_vec(),
          &blinds_poly[j],
          &a,
          &target,
          &blind,
        );

        (proof, eval, comm_eval)
      };

      // timer_sc_inner2.stop();

      proofs.push(proof);
      claim_per_round = claim_next_round;
      comm_claim_per_round = comm_claim_next_round;
      r.push(r_j);
      comm_evals.push(comm_claim_per_round);
    }
    // timer_sc_inner_outside.stop();

    let mut polys_vec = vec![poly_A[0]];
    polys_vec.push(polys_B.0[0]);
    polys_vec.push(polys_B.1[0]);
    // for poly_B in polys_B.iter() {
    //   polys_vec.push(poly_B[0]);
    // }
    polys_vec.push(poly_C[0]);
    // polys_vec.push(Scalar::one()-poly_C[0]);
    polys_vec.push(poly_D[0]);
    (
      ZKSumcheckInstanceProof::new(comm_polys, comm_evals, proofs),
      r,
      polys_vec,
      blinds_evals[num_rounds - 1],
    )
  }
}
