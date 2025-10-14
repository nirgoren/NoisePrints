//! Implement hash functions for EDDSA

use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use sha2::Digest;
use sha2::Sha512;
/// From https://docs.rs/ed25519-dalek/latest/src/ed25519_dalek/verifying.rs.html
#[allow(non_snake_case)]
pub fn compute_challenge(
    context: Option<&[u8]>,
    R: &CompressedEdwardsY,
    A: &CompressedEdwardsY,
    M: &[u8],
) -> Scalar {
    let mut h = Sha512::new();
    if let Some(c) = context {
        h.update(b"SigEd25519 no Ed25519 collisions");
        h.update([1]); // Ed25519ph
        h.update([c.len() as u8]);
        h.update(c);
    }
    h.update(R.as_bytes());
    h.update(A.as_bytes());
    h.update(M);

    let mut output = [0u8; 64];
    output.copy_from_slice(h.finalize().as_slice());

    Scalar::from_bytes_mod_order_wide(&output)
}
