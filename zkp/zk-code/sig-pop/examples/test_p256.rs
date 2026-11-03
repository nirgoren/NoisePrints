use rug::{Integer};
use p256::elliptic_curve::group::ff::PrimeField;
use p256::Scalar;
use std::convert::TryInto;
use p256::{ProjectivePoint, AffinePoint};
use p256::elliptic_curve::point::AffineCoordinates;
use circ::ecdsa::ecdsa::{P256Point};
use p256::elliptic_curve::group::GroupEncoding;
use p256::elliptic_curve::generic_array::{GenericArray, typenum::U33};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use elliptic_curve::{
    Error, Result,
};
use elliptic_curve::sec1::Coordinates;
use elliptic_curve::Field;

/// Convert p256::ProjectivePoint to P256Point
fn ProjectivePoint_to_P256Point(input: ProjectivePoint) -> P256Point {
    let encoded_point = input.to_encoded_point(false);
    let result = match encoded_point.coordinates() {
        Coordinates::Uncompressed { x, y } => {
            // let x_bytes = x.as_bytes();
            let x_integer = Integer::from_digits(&x, rug::integer::Order::MsfBe);
            let y_integer = Integer::from_digits(&y, rug::integer::Order::MsfBe);
            println!("x {:?} y {:?} x_bytes {:?} {:?}", x, y, x_integer, y_integer);
            let result = P256Point{x: x_integer, y: y_integer, empty: false};
            Ok(result)
        }
        _ => Err(Error),
    };
    result.unwrap()
}
/// Convert P256Point to p256::ProjectivePoint
fn P256Point_to_ProjectivePoint(input: P256Point) -> ProjectivePoint {
    let mut bytes = input.x.to_digits(rug::integer::Order::MsfBe);
    if input.y.is_odd() {
        bytes.insert(0, 0x03);
    } else {
        bytes.insert(0, 0x02);
    }
    let generic_bytes: &<ProjectivePoint as GroupEncoding>::Repr = GenericArray::from_slice(&bytes);
    ProjectivePoint::from_bytes(generic_bytes).expect("Fail to convert bytes to ProjectivePoint")

}

fn integer_to_scalar(input: Integer) -> Scalar {
    let mut bytes = input.to_digits(rug::integer::Order::MsfBe);
    // The P-256 field size is 32 bytes. Pad the byte array if needed.
    while bytes.len() < 32 {
        bytes.insert(0, 0);
    }
    let bytes_array: [u8; 32] = bytes.try_into().expect("Invalid length");
    Scalar::from_repr(bytes_array.into()).expect("Failed to create scalar")
}
fn scalar_to_integer(input: Scalar) -> Integer {
    let bytes = input.to_repr();
    Integer::from_digits(&bytes, rug::integer::Order::MsfBe)
}

fn test_rand_scalar() {
    let scalar = Scalar::random(&mut rand::thread_rng());
    println!("Random scalar {:?}", scalar);
}
fn main() {
    test_rand_scalar();
    println!("Result of G: {:?}", AffinePoint::GENERATOR);
    println!("(Projective) Result of G: {:?}", ProjectivePoint::GENERATOR);
    let point = ProjectivePoint_to_P256Point(ProjectivePoint::GENERATOR);
    println!("point {:?}", point);

}

