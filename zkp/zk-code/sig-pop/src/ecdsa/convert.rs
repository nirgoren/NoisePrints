//! Convert functions for EC operations
use p256::elliptic_curve::group::ff::PrimeField;
use p256::Scalar;
use p256::ProjectivePoint;

use rug::Integer;
use std::convert::TryInto;

/// Convert bytes to p256::Scalar
pub fn bytes_to_scalar(input: &[u8]) -> Scalar {
    let mut bytes = input.to_vec();
    while bytes.len() < 32 {
        bytes.insert(0, 0);
    }
    let bytes_array: [u8; 32] = bytes.try_into().expect("Invalid length");
    Scalar::from_repr(bytes_array.into()).expect("Failed to create scalar")
}

/// Convert rug::Integer to p256::Scalar
pub fn integer_to_scalar(input: &Integer) -> Scalar {
    let mut bytes = input.to_digits(rug::integer::Order::MsfBe);
    // The P-256 field size is 32 bytes. Pad the byte array if needed.
    while bytes.len() < 32 {
        bytes.insert(0, 0);
    }
    let bytes_array: [u8; 32] = bytes.try_into().expect("Invalid length");
    Scalar::from_repr(bytes_array.into()).expect("Failed to create scalar")
}


/// Convert p256::Scalar to rug::Integer
pub fn scalar_to_integer(input: &Scalar) -> Integer {
    let bytes = input.to_repr();
    Integer::from_digits(&bytes, rug::integer::Order::MsfBe)
}

/// Input scalar of type rug::Integer; Output G^{scalar}
pub fn scalar_mult_on_point_g(scalar: &Integer) -> ProjectivePoint {
    let scalar_p256: Scalar = integer_to_scalar(&scalar);
    ProjectivePoint::GENERATOR * scalar_p256
}

/// Input scalar of type rug::Integer; Output P^{scalar}
pub fn scalar_mult_on_point_p(scalar: &Integer, point: ProjectivePoint) -> ProjectivePoint {
    let scalar_p256: Scalar = integer_to_scalar(&scalar);
    point * scalar_p256
}
