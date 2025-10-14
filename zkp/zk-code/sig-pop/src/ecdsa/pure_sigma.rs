//! This module includes implementations for ECDSA signature verification using sigma protocol

use p256::ProjectivePoint;
use super::convert::{integer_to_scalar, bytes_to_scalar}; //, scalar_to_integer};
use rug::Integer;
use p256::Scalar;

use super::ecdsa::{P256Point};
use crate::ecdsa::transcript::SigmaTranscript;
use merlin::Transcript;

use elliptic_curve::PrimeField;
use super::ecdsa::{ECDSASignatureVar};
use super::random::gen_rand_scalars;

use std::path::Path;
use crate::target::r1cs::proof::{serialize_into_file, deserialize_from_file};
use serde::{Serialize, Deserialize};
use super::group::ECPoint;
use super::group::P256Scalar;
use crate::commitment::PointCommit;
use rug::rand::RandState;
use rand_core::RngCore;
use rand::SeedableRng;


use crate::hash::hash::DigestAlgorithm;
use crate::parse_cert::{X509Certificate, IssuerKey, Signature};
use super::ecdsa::EllipticCurveP256;
use elliptic_curve::point::AffineCoordinates;

use std::time::Instant;
use crate::util::timer::print_time;
use lazy_static::lazy_static;

use crate::conditional_print;

lazy_static! {
    static ref MODQ: Integer = Integer::from_str_radix("115792089210356248762697446949407573529996955224135760342422259061068512044369", 10).unwrap();
}
/// Prover for proof of possesion of ECDSA signatures in prior setting (committed pk, public R and public m)
pub fn prover<P: AsRef<Path>>(pf_path: P) {
    let signed_certificate_path = "./example_cert/cloudflare/www.cloudflare.com.cer";
    let issuer_certificate_path = "./example_cert/cloudflare/Cloudflare_Inc_ECC_CA-3.cer";   
    conditional_print!("Path of the signed certificate: {}", signed_certificate_path);
    conditional_print!("Path of the issuer certificate: {}", issuer_certificate_path);
    let cert: X509Certificate = X509Certificate::new(signed_certificate_path, issuer_certificate_path);
    cert.print_signature_algorithm();
    let params = ECDSASigmaSetupParamsPrior::new();
    if let IssuerKey::StructECDSA(ecdsa_key) = &cert.issuer_key {
        if let Signature::StructECDSA(ecdsa_signature) = cert.signature {
            // to do: extract (R, z)
            let digest_result: Integer = DigestAlgorithm::sha256(&(cert.body));
            let issuer_key_pt: ProjectivePoint = ecdsa_key
                                                    .to_p256point()
                                                    .to_projective_point(); // actually we only need projectivepoint
            let signature_var: ECDSASignatureVar = ECDSASignatureVar::from_ecdsasignature(&ecdsa_signature, digest_result.clone(), issuer_key_pt, EllipticCurveP256::new().q.clone());
            let print_msg = true;
            let start = Instant::now();
            inner_prover(
                issuer_key_pt,
                signature_var, 
                &cert.body,
                params,
                pf_path,
            );
            print_time("Time for Proving", start.elapsed(), print_msg); // verify-ecdsa: 10.522471ms
            conditional_print!("Proof has been written to file `pi_sigma`");
        } else { panic!("Didn't implement other signature algorithms");}
    } else {panic!("Didn't implement other signature algorithms");}
}

/// Verifier for proof of possesion of ECDSA signatures in prior setting (committed pk, public R and public m)
pub fn verifier<P: AsRef<Path>>(pf_path: P) {
    let signed_certificate_path = "./example_cert/cloudflare/www.cloudflare.com.cer";
    let issuer_certificate_path = "./example_cert/cloudflare/Cloudflare_Inc_ECC_CA-3.cer";   
    conditional_print!("Path of the signed certificate: {}", signed_certificate_path);
    conditional_print!("Path of the issuer certificate: {}", issuer_certificate_path);
    let cert: X509Certificate = X509Certificate::new(signed_certificate_path, issuer_certificate_path);
    cert.print_signature_algorithm();
    let params = ECDSASigmaSetupParamsPrior::new();
    let start = Instant::now();
    inner_verifier(
        &cert.body,
        params,
        pf_path,
    );
    print_time("Time for Verifying", start.elapsed(), true); // verify-ecdsa: 10.522471ms
    conditional_print!("Proof has been verified");
}
/// Inner Prover for proof of possesion of ECDSA signatures in prior setting (committed pk, public R and public m)
pub fn inner_prover<P: AsRef<Path>>(
    verify_key: ProjectivePoint,
    signature: ECDSASignatureVar, 
    message: &Vec<u8>,
    params: ECDSASigmaSetupParamsPrior,
    pf_path: P,
) {
    let digest_result: Integer = DigestAlgorithm::sha256(message);
    let mut rng_scalar = rand::rngs::StdRng::from_seed([0u8; 32]); // seed ensures reproducibility

    let comm_pk: PointCommit = PointCommit::new(
        &verify_key,
        &[params.hash_hash_g, params.hash_g],  // L = params.hash_hash_g, K = params.hash_g
        &mut rng_scalar);

    // Obtain x-coordinate of R under truncation to Fq
    let x = signature.point_r.to_affine().x();
    let r_scalar: Scalar = bytes_to_scalar(&x); // scalar in Fq
    let sigma: ECDSASigmaPrior = ECDSASigmaPrior::new(
        comm_pk, 
        &digest_result, 
        &r_scalar, 
        signature, 
        params, 
        &mut rng_scalar
    );

    let _ = serialize_into_file(&sigma.public_input, pf_path);
}

/// Inner Verifier for proof of possesion of ECDSA signatures in prior setting (committed pk, public R and public m)
pub fn inner_verifier<P: AsRef<Path>>(
    message: &Vec<u8>,
    params: ECDSASigmaSetupParamsPrior,
    pf_path: P, 
) {
    let digest_result: Integer = DigestAlgorithm::sha256(message);
    let sigma: ECDSASigmaPublicPrior = deserialize_from_file(pf_path)
                                    .expect("Failed to read file `pi_sigma`");
    sigma.verify(
        &digest_result, 
        params); // abort if verification fails
}
/// Public parameters for the (partial) sigma proof for ECDSA signature verification
pub struct ECDSASigmaSetupParamsPrior {
    /// Hash of the generator of P256 in projective form
    pub hash_g: ProjectivePoint, // Corresponds to K in the paper
    /// Hash of K in projective form
    pub hash_hash_g: ProjectivePoint, // Corresponds to L in the paper
    /// generator of P256 in projective form
    pub g: ProjectivePoint,
}

impl ECDSASigmaSetupParamsPrior {
    /// Create an instance of ECDSASigmaSetupParams
    pub fn new() -> Self {
        let hash_g: P256Point = P256Point::hash_of_generator();
        let hash_g_project: ProjectivePoint = hash_g.to_projective_point();
        Self {
            hash_g: hash_g_project,
            hash_hash_g: hash_g_project,
            g: ProjectivePoint::GENERATOR,
        }
    }
}

#[derive(Serialize, Deserialize)]
/// Public inputs for the proof for ECDSA signature verification under prior setting (Commited public key, Public R and Public m)
pub struct ECDSASigmaPublicPrior {
    /// Responses
    pub responses: [P256Scalar; 4],
    /// Commitments
    pub comm: [ECPoint; 4],
    /// Commitments to public key
    pub cm_pk: [ECPoint; 2],
    /// Partial Signature; The random elliptic curve point
    pub pt_r: ECPoint,
}

impl ECDSASigmaPublicPrior {
    /// Compute E_0 = `cm_pk[0]` and E_1 = `cm_pk[1] + (H(m)/r) * G` from commited public key, message and R
    pub fn precompute(
        cm_pk: [ProjectivePoint; 2],
        digest_result: &Integer,
        r: &Scalar,
    ) -> [ProjectivePoint; 2] {
        let digest_result_scalar = integer_to_scalar(digest_result);
        // let r_scalar = integer_to_scalar(r);
        let e_1 = cm_pk[1] + 
                    ProjectivePoint::GENERATOR * (digest_result_scalar * r.invert().expect("Cannot find multiplicative inverse of r"));
                    // ProjectivePoint::GENERATOR * (digest_result_scalar * r_scalar.invert().expect("Cannot find multiplicative inverse of r"));
        [cm_pk[0], e_1]
    }

    /// Compute the challenge for the sigma protocol
    pub fn compute_challenge(
        pts_e: &[ProjectivePoint; 2], 
        pt_r: &ProjectivePoint, 
        comm: &[ECPoint; 4]
    ) -> Scalar {
        let mut transcript = Transcript::new(b"ECDSA_Sigma_Prior");
        for (i, pt) in pts_e.iter().enumerate() {
            let label = match i {
                0 => b"E_0",
                1 => b"E_1",
                _ => panic!("Invalid index"),
            };
            transcript.append_point(label, pt);
        }
        transcript.append_point(b"R", pt_r);
        for (i, pt) in comm.iter().enumerate() {
            let label = match i {
                0 => b"comm_0",
                1 => b"comm_1",
                2 => b"comm_2",
                3 => b"comm_3",
                _ => panic!("Invalid index"),
            };
            transcript.append_point(label, &pt.0);
        }
        let challenge_bytes = transcript.challenge_scalar(b"challenge");
        Scalar::from_repr(challenge_bytes.into()).expect("Failed to create scalar")
    }

    /// Verify the sigma proof; Abort if verification fails
    pub fn verify(&self, 
        // cm_pk: [ProjectivePoint; 2], 
        digest_result: &Integer, 
        // r: &Scalar, 
        // pt_r: ProjectivePoint,
        params: ECDSASigmaSetupParamsPrior
    ) {
        let x = self.pt_r.0.to_affine().x();
        let r: Scalar = bytes_to_scalar(&x);
        assert_ne!(r, Scalar::ZERO);

        let pts_e: [ProjectivePoint; 2] = ECDSASigmaPublicPrior::precompute(
                                                [self.cm_pk[0].0, self.cm_pk[1].0], 
                                                digest_result, 
                                                &r
                                            ); // Compute E_0 = `cm_pk[0]` and E_1 = `cm_pk[1] + (H(m)/r) * G`
        let challenge: Scalar = ECDSASigmaPublicPrior::compute_challenge(
                                    &pts_e,
                                    &self.pt_r.0,
                                    &self.comm,
                                );
        let pt_l: ProjectivePoint = params.hash_hash_g;
        let pt_k: ProjectivePoint = params.hash_g;
        assert_eq!(pt_l * self.responses[0],
                    self.comm[0].0 + pts_e[0] * challenge);
        assert_eq!(self.pt_r.0 * self.responses[1] + pt_k * self.responses[0],
                    self.comm[1].0 + pts_e[1] * challenge);
        assert_eq!(pts_e[0] * self.responses[2] + pt_l * self.responses[3],
                    self.comm[2].0);
        assert_eq!(pts_e[1] * self.responses[2] + pt_k * self.responses[3],
                    self.comm[3].0 + self.pt_r.0 * challenge);
    }
}
/// Params for the proof for ECDSA signature verification under prior setting (Commited public key, Public R and Public m)
pub struct ECDSASigmaPrior {
    /// Public inputs
    pub public_input: ECDSASigmaPublicPrior,
    /// Challenge
    pub challenge: Scalar,
}

impl ECDSASigmaPrior {
    /// Create variables needed for the sigma protocol; ** to do
    pub fn new( 
        cm_pk: PointCommit, // Commitment to the public key with opening
        digest_result: &Integer,
        r: &Scalar,
        sign_var: ECDSASignatureVar,
        params: ECDSASigmaSetupParamsPrior,
        mut rng_scalar: impl RngCore
    ) -> Self {
        let pts_e: [ProjectivePoint; 2] = ECDSASigmaPublicPrior::precompute(
                                                cm_pk.comm, 
                                                digest_result, 
                                                r
                                            ); // Compute E_0 = `cm_pk[0]` and E_1 = `cm_pk[1] + (H(m)/r) * G`

        let mut rng = RandState::new_mersenne_twister();
        rng.seed(&Integer::from(42)); // seed ensures reproducibility

        // Commitment phase in the sigma protocol
        let randexp_scalar: Vec<Scalar> = gen_rand_scalars(4, &mut rng_scalar);
        let mut comm: [ECPoint; 4] = [ECPoint::default(); 4];
        // L = params.hash_hash_g; K = params.hash_g
        comm[0] = ECPoint(params.hash_hash_g * randexp_scalar[0]);
        comm[1] = ECPoint(sign_var.point_r * randexp_scalar[1] + params.hash_g * randexp_scalar[0]);
        comm[2] = ECPoint(pts_e[0] * randexp_scalar[2] + params.hash_hash_g * randexp_scalar[3]);
        comm[3] = ECPoint(pts_e[1] * randexp_scalar[2] + params.hash_g * randexp_scalar[3]);

        // Challenge phase in the sigma protocol
        let challenge: Scalar = ECDSASigmaPublicPrior::compute_challenge(
                                    &pts_e,
                                    &sign_var.point_r,
                                    &comm,
                                );

        // Response phase in the sigma protocol
        let z_scalar: Scalar = integer_to_scalar(&sign_var.z);
        let z_inv: Scalar = z_scalar.invert().expect("Cannot find multiplicative inverse of z");
        let exp_scalar: [Scalar; 4] = [
            cm_pk.opening,
            z_scalar,
            z_inv,
            -cm_pk.opening * z_inv,
        ];
        let mut responses: [P256Scalar; 4] = [P256Scalar::default(), P256Scalar::default(), P256Scalar::default(), P256Scalar::default()];
        for (i, (exp, rexp)) in exp_scalar.iter().zip(randexp_scalar.iter()).enumerate() {
            responses[i] = P256Scalar((exp * &challenge) + rexp);
        }  

        let public_input: ECDSASigmaPublicPrior = ECDSASigmaPublicPrior {
            responses: responses,
            comm: comm,
            cm_pk: [ECPoint(cm_pk.comm[0]), ECPoint(cm_pk.comm[1])],
            pt_r: ECPoint(sign_var.point_r),
        };

        Self {
            public_input,
            challenge,
        }
    }
}