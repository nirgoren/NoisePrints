//! Verifying keys for the EdDSA signature scheme.
use super::signature::EDDSASignature;
use super::hash::compute_challenge;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};

/// Public signatue verification key of Eddsaq
#[derive(Clone)]
pub struct EDDSAPublicKey(pub CompressedEdwardsY);

impl EDDSAPublicKey {
    /// Strictly verify a signature on a message with this keypair’s public key; From https://docs.rs/ed25519-dalek/latest/src/ed25519_dalek/verifying.rs.html#402-425
    pub fn verify_strict(&self, signature: &EDDSASignature, message: &[u8]) -> bool {
        let pk_compressed: CompressedEdwardsY = self.0;
        let k = compute_challenge(None, &signature.R, &pk_compressed, message);
        let neg_pk: EdwardsPoint = -(pk_compressed.decompress().unwrap());

        let expected_big_r = k * neg_pk + signature.s * ED25519_BASEPOINT_POINT;
        signature.R == expected_big_r.compress()
    }
}
