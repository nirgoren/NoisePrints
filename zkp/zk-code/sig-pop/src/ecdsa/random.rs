//! Functions to generate random scalars
use p256::Scalar;
use rand::RngCore;
use elliptic_curve::Field;

/// Generate random scalars
pub fn gen_rand_scalars(num: usize, mut rng: impl RngCore) -> Vec<Scalar> {
    // let mut rng = rand::thread_rng();
    let mut scalars = Vec::new();
    for _ in 0..num {
        scalars.push(Scalar::random(&mut rng));
    }
    scalars
}