//! This module includes implementations related to ecdsa signature verification with sigma protocol

use fxhash::FxHashMap as HashMap;
use crate::ir::term::Value;
use crate::commitment::{Poseidon};
use p256::ProjectivePoint;
use super::convert::{integer_to_scalar, scalar_to_integer};
use super::ecdsa::{EllipticCurveP256, ECDSASignatureVar, BigNatScalarMultCachedWindow, P256Point, BigNatPointAdd, ECDSASignature};
use crate::commitment::P256Commit;
use rug::Integer;
use p256::Scalar;
use crate::allocate::map_field_vec;
use crate::bignat::bignatwithlimbmax::{BigNatWithLimbMax, BigNatModMultWithLimbMax};
use crate::bignat::bignatwithlimbmax::{FIELD_MOD};
use crate::bignat::bignat_adv::{BigNatInit, BigNatModAdv};

use crate::ecdsa::transcript::SigmaTranscript;
use merlin::Transcript;
use crate::convert::{integer_to_bytes};

use elliptic_curve::PrimeField;

use std::path::Path;
use crate::target::r1cs::proof::{serialize_into_file, deserialize_from_file};
use serde::{Serialize, Deserialize};
use super::group::ECPoint;
use super::group::P256Scalar;

use crate::convert::rand_int;
// use rand::thread_rng;
use rug::rand::RandState;
use rand::SeedableRng;
use rand_core::RngCore;
use super::random::gen_rand_scalars;

use crate::conditional_print;
/// check s_i = e_i * c + gamma; allocate the intermediate variables related to this check to the circuit
fn check_response(
    modul: &BigNatWithLimbMax, 
    maxword_vec: &Vec<Integer>, 
    expo_bignat: &BigNatWithLimbMax, 
    gamma: &Integer, 
    c_bignat: &BigNatWithLimbMax, 
    response_scalar: &Scalar, 
    limb_width: usize, 
    n_limbs: usize, 
    quotient_bits: usize, 
    limbs_per_gp: usize, 
    subtable_bitwidth: usize, 
    name: &str, 
    input_map: &mut HashMap::<String, Value>
) {
    let response: Integer = scalar_to_integer(response_scalar);
    assert!(response.clone() == (expo_bignat.clone().value.unwrap() * c_bignat.clone().value.unwrap() + gamma.clone()) % modul.clone().value.unwrap()); // for debug only
    let response_bignat = BigNatWithLimbMax::new(&response, limb_width, n_limbs, false);
    let gamma_bignat = BigNatWithLimbMax::new(gamma, limb_width, n_limbs, false);
    let product: BigNatWithLimbMax = expo_bignat.create_product_nat(&c_bignat);
    let left: BigNatWithLimbMax = product.create_addition_nat(&gamma_bignat); // e_i * c + gamma 
    let mm = BigNatModAdv::new_with_maxword(&left, &modul, &response_bignat, maxword_vec, quotient_bits, limbs_per_gp); 
    mm.alloc_adv(&product, subtable_bitwidth, name, input_map);
}
/// Compute prover inputs for proof of possesion of ECDSA signatures
pub fn prover_input_for_ecdsa_sigma<P: AsRef<Path>>(
    verify_key: ProjectivePoint,
    signature: ECDSASignatureVar, 
    sign_r: Integer, 
    digest_result: Integer, 
    p256_const: ECDSASigmaConst, 
    limb_width: usize, 
    n_limbs: usize, 
    quotient_bits: usize, 
    limbs_per_gp: usize, 
    window_size: usize, 
    subtable_bitwidth: usize, 
    pf_path: P, 
    name: &str, 
    input_map: &mut HashMap::<String, Value>
) {
    let mut rng_scalar = rand::rngs::StdRng::from_seed([0u8; 32]); // seed ensures reproducibility
    let prepend: String = if name.is_empty() {name.to_owned()} else {name.to_owned()+"."};

    let comm_point_r: P256Commit = P256Commit::new(signature.point_r, p256_const.hash_g, &mut rng_scalar);
    // Allocate ECDSASign_init<NQ_, Lp1> signature_init to the circuit
    ECDSASignature::alloc_sigma(&comm_point_r.opening, &sign_r, limb_width, n_limbs, subtable_bitwidth, name, input_map);
    // Allocate BigNat_init<NP_, Lp1> digest_result_init to the circuit
    let modq: Integer = p256_const.p256_curve.q.clone();
    let exponents = [signature.z.clone(), 
                    signature.z.clone() * comm_point_r.opening.clone() % modq.clone(), 
                    digest_result.clone() * sign_r.clone().invert(&modq.clone()).expect("fail to compute inverse of r") % modq.clone()];
    let g_inv: ProjectivePoint = ProjectivePoint::GENERATOR.neg();

    let sigma: ECDSASigma = ECDSASigma::new(
                                verify_key,
                                exponents.clone(), 
                                comm_point_r.comm, 
                                p256_const.hash_g.neg(), 
                                g_inv, 
                                limb_width, 
                                modq.clone(),
                                &mut rng_scalar
                            );
    let part_commit: P256Point = P256Point::from_projective_point(comm_point_r.comm);
    // alloc sigma into the circuit
    sigma.alloc(limb_width, n_limbs, subtable_bitwidth, name, input_map);

    // Prover input for the constraints for exponents
    let exponents_bignat = [
        BigNatWithLimbMax::new(&exponents[0], limb_width, n_limbs, false),
        BigNatWithLimbMax::new(&exponents[1], limb_width, n_limbs, false),
        BigNatWithLimbMax::new(&exponents[2], limb_width, n_limbs, false),
    ];
    // e_1 = e_0 * v
    let v_bignat = BigNatWithLimbMax::new(&comm_point_r.opening, limb_width, n_limbs, false);
    BigNatModMultWithLimbMax::prover_input_for_single_modmultiply_adv(&exponents_bignat[0], &v_bignat, &p256_const.q_bignat, quotient_bits, limbs_per_gp, subtable_bitwidth, format!("{}init.exp_represent.0", prepend).as_str(), input_map);
    // e_2 * r = H(m)
    let r_bignat = BigNatWithLimbMax::new(&sign_r, limb_width, n_limbs, false);
    BigNatModMultWithLimbMax::prover_input_for_single_modmultiply_adv(&exponents_bignat[2], &r_bignat, &p256_const.q_bignat, quotient_bits, limbs_per_gp, subtable_bitwidth, format!("{}init.exp_represent.1", prepend).as_str(), input_map);
    // check response = rand + expo * challenge
    let c_upper_bound: Integer = modq.clone() - Integer::from(1); // We are sure that c < q since we can check that out of the circuit
    let c_bignat = BigNatWithLimbMax::new_with_upper_bound(&scalar_to_integer(&sigma.challenge), limb_width, n_limbs, c_upper_bound);
    for i in 0..3 {
        check_response(&p256_const.q_bignat, 
                        &p256_const.maxwords_modq, 
                        &exponents_bignat[i], 
                        &sigma.witnesses.scalars[i+3], 
                        &c_bignat, 
                        &sigma.public_input.responses[i].0, 
                        limb_width, 
                        n_limbs, 
                        quotient_bits, 
                        limbs_per_gp, 
                        subtable_bitwidth,
                        format!("{}init.prover_comp.{}", prepend, i).as_str(), 
                        input_map
        );
    }

    // Prover input for K^v where K is hash of G // To do: COmpute K^{-1} instead
    conditional_print!("Applying cached windowed method");
    let v_times_hash_g: BigNatScalarMultCachedWindow = BigNatScalarMultCachedWindow::new_incomplete(comm_point_r.opening.clone(), p256_const.hash_g_neg.clone(), limb_width, n_limbs, limbs_per_gp, window_size, true); // advanced = true; to do: further optimized
    v_times_hash_g.alloc_adv(subtable_bitwidth, format!("{}init.scalarmul", prepend).as_str(), input_map);
    let mask: P256Point = v_times_hash_g.res_point;

    // Check R = (K^{-1})^v C^{(1)} 
    let advanced = true;
    let mask_plus_part_comm: BigNatPointAdd = BigNatPointAdd::new(mask.clone(), part_commit.clone(), limb_width, n_limbs, limbs_per_gp, advanced);
    mask_plus_part_comm.alloc_for_r_adv(subtable_bitwidth, sign_r.clone(), p256_const.p256_curve.p_minusq_minus1.clone(),  &format!("{}init.partialadd", prepend), input_map);
    // Write the sigma transcript into a file
    let _ = serialize_into_file(&sigma.public_input, pf_path);
}

/// Compute verifier inputs for proof of possesion of ECDSA signatures; to do
pub fn verifier_input_for_ecdsa_sigma<P: AsRef<Path>>(
    verify_key: ProjectivePoint, 
    p256_const: ECDSASigmaConst, 
    limb_width: usize, 
    n_limbs: usize, 
    pf_path: P, 
    name: &str, 
    input_map: &mut HashMap::<String, Value>
) {
    let prepend: String = if name.is_empty() {name.to_owned()} else {name.to_owned()+"."};

    let sigma: ECDSASigmaPublic = deserialize_from_file(pf_path)
                                    .expect("Failed to read file `pi_sigma`");
    let params: ECDSASigmaSetupParams = ECDSASigmaSetupParams::new(p256_const);
    // check the size of the communication in the sigma protocol
    conditional_print!("Size of the communication in the sigma protocol = {:?} bits", ECDSASigmaPublic::size());
    // actual verifier
    sigma.inner_verifier(params, verify_key, limb_width, n_limbs, format!("{}pub", prepend).as_str(), input_map);
}

/// Constants for ECDSA signature verification with hybrid approach
pub struct ECDSASigmaConst {
    /// Parameters for the curve P256
    pub p256_curve: EllipticCurveP256,
    /// prime field of P256
    pub q_bignat: BigNatWithLimbMax,
    /// Hash of the generator of P256 in P256Point struct
    pub hash_g_neg: P256Point, 
    /// Hash of the generator of P256 in projective form
    pub hash_g: ProjectivePoint,
    /// Maxword vector for modular operations
    pub maxwords_modq: Vec<Integer>,
}

impl ECDSASigmaConst {
    /// Create an instance of ECDSASigmaConst
    pub fn new(limb_width: usize, n_limbs: usize) -> Self {
        let p256_curve: EllipticCurveP256 = EllipticCurveP256::new();
        let q_bignat: BigNatWithLimbMax = BigNatWithLimbMax::new(&p256_curve.q, limb_width, n_limbs, true);
        let hash_g: P256Point = P256Point::hash_of_generator();
        let hash_g_neg: P256Point = hash_g.neg();
        let hash_g_project: ProjectivePoint = hash_g.to_projective_point();
        let maxwords_modq: Vec<Integer> = Self::find_gpmaxword_for_modq(&q_bignat, limb_width, n_limbs);
        Self {
            p256_curve: p256_curve,
            q_bignat: q_bignat,
            hash_g_neg: hash_g_neg,
            hash_g: hash_g_project,
            maxwords_modq: maxwords_modq,
        }
    }

    /// Find maxword for a*b = q*quotient + remainder
    fn find_gpmaxword_for_modq(modq: &BigNatWithLimbMax, limb_width: usize, n_limbs: usize) -> Vec<Integer> {

        let a: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(100), limb_width, n_limbs, false);
        let left: BigNatWithLimbMax = a.create_product_nat(&a);
        let quotient_upper_bound: Integer = (Integer::from(1) << (n_limbs*limb_width+1)) - 1;
        let quotient: BigNatWithLimbMax = BigNatWithLimbMax::new_with_upper_bound(&Integer::from(10), limb_width, n_limbs+1, quotient_upper_bound);
        let product: BigNatWithLimbMax = quotient.create_product_nat(modq);
        let right: BigNatWithLimbMax = product.create_addition_nat(&a);
        Self::find_gpmaxword(&left, &right)
    }

    // to modify
    fn find_gpmaxword(left: &BigNatWithLimbMax, right: &BigNatWithLimbMax) -> Vec<Integer> {
        let field_mod: Integer = FIELD_MOD.clone();
        let steps: Vec<usize> = left.find_n_limbs_for_each_gp(&right, field_mod.clone());
        let all_except_last_are_the_same = steps.iter().take(steps.len() - 1).all(|&x| x == steps[0]);
        assert!(all_except_last_are_the_same);

        let gp_res_left: BigNatWithLimbMax = left.group_limbs(steps[0], Some(field_mod.clone()));
        let gp_res_right: BigNatWithLimbMax = right.group_limbs(steps[0], Some(field_mod.clone()));
    
        gp_res_left.compute_maxvalues(&gp_res_right)
    }
}

/// Public parameters for the (partial) sigma proof for ECDSA signature verification
pub struct ECDSASigmaSetupParams {
    /// Hash of the generator of P256 in projective form
    pub hash_g: ProjectivePoint,
    /// generator of P256 in projective form
    pub g: ProjectivePoint,
}

impl ECDSASigmaSetupParams {
    /// Create an instance of ECDSASigmaSetupParams
    pub fn new(sigma_const: ECDSASigmaConst) -> Self {
        Self {
            hash_g: sigma_const.hash_g,
            g: ProjectivePoint::GENERATOR,
        }
    }
}
/// Params for the (partial) sigma proof for ECDSA signature verification
pub struct ECDSASigma {
    /// Public inputs
    pub public_input: ECDSASigmaPublic,
    /// Challenge
    pub challenge: Scalar,
    /// Witness
    pub witnesses: ECDSASigmaWitness,
}

impl ECDSASigma {
    /// Create variables needed for the sigma protocol
    pub fn new(
        verify_key: ProjectivePoint,
        exponents: [Integer; 3], 
        partial_comm: ProjectivePoint, 
        hash_g_inv: ProjectivePoint, 
        g_inv: ProjectivePoint, 
        limb_width: usize, 
        _modq: Integer,
        mut rng_scalar: impl RngCore
    ) -> Self {
        let mut rng = RandState::new_mersenne_twister();
        rng.seed(&Integer::from(42)); // seed ensures reproducibility
        let randexp_scalar: Vec<Scalar> = gen_rand_scalars(3, &mut rng_scalar);
        let mut randexp: [Integer; 3] = [Integer::default(), Integer::default(), Integer::default()];
        let mut exp_scalar: [Scalar; 3] = [Scalar::default(), Scalar::default(), Scalar::default()];
        for (i, rand) in randexp_scalar.iter().enumerate() {
            randexp[i] = scalar_to_integer(rand);
            exp_scalar[i] = integer_to_scalar(&exponents[i]);
        }
        let openings: [Integer; 2] = [rand_int(&mut rng), rand_int(&mut rng)]; // the same value for every iterations
        let poseidon: [Integer; 2] = [Poseidon::commit_to_three_exp(exponents.clone(), openings[0].clone(), limb_width), 
                                        Poseidon::commit_to_three_exp(randexp.clone(), openings[1].clone(), limb_width)];
        let scalars: [Integer; 6] = [exponents[0].clone(), exponents[1].clone(), exponents[2].clone(), 
                                        randexp[0].clone(), randexp[1].clone(), randexp[2].clone()];
        // Compute randexp[0] * partial_comm + randexp[1] * HASH_G_INV + randexp[2] * G_INV 

        let rand_comm: ProjectivePoint = (partial_comm * randexp_scalar[0]) + (hash_g_inv * randexp_scalar[1]) + (g_inv * randexp_scalar[2]);
        let comm: [ECPoint; 2] = [ECPoint(partial_comm), ECPoint(rand_comm)];

        let challenge: Scalar = ECDSASigmaPublic::compute_challenge(&verify_key, &poseidon, &comm);
        let mut responses: [P256Scalar; 3] = [P256Scalar::default(), P256Scalar::default(), P256Scalar::default()];
        for (i, (exp, rexp)) in exp_scalar.iter().zip(randexp_scalar.iter()).enumerate() {
            responses[i] = P256Scalar((exp * &challenge) + rexp);
        }  

        let public_input: ECDSASigmaPublic = ECDSASigmaPublic {
            poseidon: poseidon,
            responses: responses,
            comm: comm,
        };

        let witnesses: ECDSASigmaWitness = ECDSASigmaWitness {
            openings: openings,
            scalars: scalars, // [e1, e2, e3, e1', e2', e3's]
        };
        Self {
            public_input,
            challenge,
            witnesses,
        }
    }

    /// Allocate struct ECDSASigma to the circuit
    fn alloc(&self, limb_width: usize, n_limbs: usize, subtable_bitwidth: usize, name: &str, input_map: &mut HashMap<String, Value>) {
        let prepend: String = if name.is_empty() {name.to_owned()} else {name.to_owned()+"."};
        self.public_input.alloc(&self.challenge, limb_width, n_limbs, format!("{}pub", prepend).as_str(), input_map);
        self.witnesses.alloc(limb_width, n_limbs, subtable_bitwidth, format!("{}init", prepend).as_str(), input_map);
    }
    
}

#[derive(Serialize, Deserialize)]
/// Public inputs for the (partial) sigma proof for ECDSA signature verification
pub struct ECDSASigmaPublic {
    /// Verifier inputs related to Poseidon commitments to the scalars
    pub poseidon: [Integer; 2],
    /// Responses
    pub responses: [P256Scalar; 3],
    /// Commitment on EC point in the sigma protocol; comm: [partial_comm, sigma.comm]
    pub comm: [ECPoint; 2],
}

impl ECDSASigmaPublic {

    /// Compute the size of ECDSASigmaPublic excluding the challenge (since it will be computed locally by the verifier)
    pub fn size() -> usize {
        let size_of_point = 256 + 1; // number of bits in x-coordinate + 1 bit for y-coordinate
        // 2 * Len of poseidon commitment (a field element) + 3 * Len of response (a field element) + 2 * Len of ProjectivePoint (a P256 point)
        5 * 256 + 2 * size_of_point // to modify
    }

    /// Compute the challenge
    pub fn compute_challenge(verify_key: &ProjectivePoint, poseidon: &[Integer; 2], comm: &[ECPoint; 2]) -> Scalar {
        let mut transcript = Transcript::new(b"ecdsa_sigma");
        transcript.append_point(b"pk", verify_key);
        transcript.append_message(b"cm", &integer_to_bytes(&poseidon[0]));
        transcript.append_message(b"cm'", &integer_to_bytes(&poseidon[1]));
        transcript.append_point(b"C^{(1)}", &comm[0].0);
        transcript.append_point(b"U", &comm[1].0);
        let challenge_bytes = transcript.challenge_scalar(b"challenge");
        Scalar::from_repr(challenge_bytes.into()).expect("Failed to create scalar")
    }

    fn verifier_check_sigma(&self, challenge: &Scalar, params: ECDSASigmaSetupParams, verify_key: ProjectivePoint) { //** to do
        let rhs = self.comm[1] + (verify_key * challenge.clone());
        let lhs = (self.comm[0] * self.responses[0]) 
                    + (params.hash_g.neg() * self.responses[1]) 
                    + (params.g.neg() * self.responses[2]);
        assert!(rhs == lhs);
        conditional_print!("Sigma protocol is verified successfully!");
    }
    fn inner_verifier(&self, 
                    params: ECDSASigmaSetupParams, 
                    verify_key: ProjectivePoint, 
                    limb_width: usize, 
                    n_limbs: usize, 
                    name: &str, 
                    input_map: &mut HashMap<String, Value>
    ) {
        let challenge: Scalar = Self::compute_challenge(&verify_key, &self.poseidon, &self.comm);
        self.verifier_check_sigma(&challenge, params, verify_key);
        // to do: Check comm[1]
        self.alloc(&challenge, limb_width, n_limbs, name, input_map);
    }
    /// Allocate struct ECDSASigma_public to the circuit;
    fn alloc(&self, challenge: &Scalar, limb_width: usize, n_limbs: usize, name: &str, input_map: &mut HashMap<String, Value>) {
        let prepend: String = if name.is_empty() {name.to_owned()} else {name.to_owned()+"."};
        let partial_comm_r: P256Point = P256Point::from_projective_point(self.comm[0].0);
        partial_comm_r.alloc(limb_width, n_limbs, format!("{}partial_commit", prepend).as_str(), input_map);
        map_field_vec(self.poseidon.to_vec(), format!("{}hcommit", prepend).as_str(), input_map);
        for (i, resp) in self.responses.iter().enumerate() {
            let resp_int: Integer = scalar_to_integer(&resp.0);
            BigNatWithLimbMax::alloc_from_integer(&resp_int, limb_width, n_limbs, format!("{}responses.{}", prepend, i).as_str(), input_map);
        }
        BigNatWithLimbMax::alloc_from_integer(&scalar_to_integer(challenge), limb_width, n_limbs, format!("{}responses.{}", prepend, 3).as_str(), input_map);
    }
}

/// Witness for the (partial) sigma proof for ECDSA signature verification
pub struct ECDSASigmaWitness {
    /// Openings for Poseidon commitments
    pub openings: [Integer; 2],
    /// Scalars
    pub scalars: [Integer; 6], // first three are exponents; last three are random values to hide exponents
}

impl ECDSASigmaWitness {
    /// Allocate struct ECDSASigma_witness to the circuit;
    fn alloc(&self, limb_width: usize, n_limbs: usize, subtable_bitwidth: usize, name: &str, input_map: &mut HashMap<String, Value>) {
        let prepend: String = if name.is_empty() {name.to_owned()} else {name.to_owned()+"."};
        // Allocate the scalars to the circuit
        for (i, exp) in self.scalars.iter().enumerate() {
            BigNatInit::alloc_from_integer(&exp, limb_width, n_limbs, subtable_bitwidth, format!("{}exp_init.{}", prepend, i).as_str(), input_map);
        }
        // Allocate the openings to the circuit
        map_field_vec(self.openings.to_vec(), format!("{}openings", prepend).as_str(), input_map);
    }
}

