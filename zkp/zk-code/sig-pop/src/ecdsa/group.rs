//! This module includes implementations related to Elliptic curve points
use p256::{Scalar, ProjectivePoint};
use elliptic_curve::group::GroupEncoding; 
use core::ops::{Mul, Add};

use serde::{Serializer, Serialize}; // ser/de for sigma proof
use serde::{Deserialize, Deserializer}; // ser/de for sigma proof
use p256::elliptic_curve::generic_array::GenericArray;
use elliptic_curve::PrimeField;

use std::borrow::Borrow;


/// Elliptic curve point over P256
#[derive(PartialEq, Clone, Copy)]
pub struct ECPoint(pub ProjectivePoint);

#[derive(Clone, Copy)]
/// Elliptic curve scalar over P256
pub struct P256Scalar(pub Scalar);


impl ECPoint {
    /// Default
    pub fn default() -> ECPoint {
        ECPoint(ProjectivePoint::default())
    }
}
impl Mul<Scalar> for ECPoint {
    type Output = ECPoint;

    fn mul(self, scalar: Scalar) -> ECPoint { 
        ECPoint(self.0 * scalar)
    }
}

// implement Add for ECPoint
impl Add<ProjectivePoint> for ECPoint {
    type Output = ECPoint;
  
    fn add(self, other: ProjectivePoint) -> Self::Output {
        ECPoint(self.0 + other)
    }
}

impl Mul<P256Scalar> for ECPoint {
    type Output = ECPoint;

    fn mul(self, scalar: P256Scalar) -> ECPoint { 
        ECPoint(self.0 * scalar.0)
    }
}

// Implement Serialize for ECPoint
impl Serialize for ECPoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.0.to_bytes(); 
        bytes.serialize(serializer)
    }
}

// Implement Deserialize for ECPoint
impl<'de> Deserialize<'de> for ECPoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        let generic_bytes: &<ProjectivePoint as GroupEncoding>::Repr = GenericArray::from_slice(&bytes);

        let point = ProjectivePoint::from_bytes(generic_bytes);
        Ok(ECPoint(point.unwrap()))
    }
}

impl Borrow<Scalar> for P256Scalar {
    fn borrow(&self) -> &Scalar {
        &self.0
    }
}

impl P256Scalar {
    /// Default
    pub fn default() -> P256Scalar {
        P256Scalar(Scalar::default())
    }
}
// Implement Serialize for P256Scalar
impl Serialize for P256Scalar {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.0.to_repr(); 
        bytes.serialize(serializer)
    }
}

// Implement Deserialize for P256Scalar
impl<'de> Deserialize<'de> for P256Scalar {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        let generic_bytes: &<Scalar as PrimeField>::Repr = GenericArray::from_slice(&bytes);
        let scalar = Scalar::from_repr(*generic_bytes).expect("Failed to create scalar");
        Ok(P256Scalar(scalar))
    }
}