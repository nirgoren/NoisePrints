use crate::t256::Config;
use ark_ec::{models::CurveConfig};
use ark_serialize::CanonicalSerialize;

/// Trait for Spartan
pub trait SpartanTrait {
    /// Convert to bytes
    fn to_bytes(&self) -> [u8; 32];
}

impl SpartanTrait for <Config as CurveConfig>::ScalarField {
    /// Convert Scalar to bytes
    fn to_bytes(&self) -> [u8; 32] {
        let mut array_bytes = [0u8; 32];
        self.serialize_compressed(&mut &mut array_bytes[..]).unwrap();
        array_bytes
    }
}