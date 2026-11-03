use ark_ec::{
    models::CurveConfig,
    short_weierstrass::{self as sw, SWCurveConfig},
    AffineRepr, CurveGroup,
};
use ark_ff::BigInteger;
use circ_fields::t256::{Config, Affine, Projective, ScalarField}; //Config, 
use circ_fields::t256::curves::BASEPOINT_COMPRESSED;
use circ_fields::t256::utils::helper::SpartanTrait;
use ark_serialize::CanonicalSerialize;
use ark_serialize::CanonicalDeserialize;
use ark_ec::VariableBaseMSM;
use ark_ff::fields::PrimeField;  
use gmp_mpfr_sys::gmp::limb_t;
use bincode::{deserialize_from, serialize_into};
use ark_ec::hashing::curve_maps::swu::{SWUMap, SWUConfig};  
use ark_ec::hashing::HashToCurve;      
use circ_fields::t256::hash_to_curve::create_curvebased_hasher;

type Scalar = ScalarField;

use ark_ff::{fields::Field, Zero, One}; // needed for Scalar::zero(), Scalar::one()
use rug::Integer;
use rand_core::OsRng;
use ark_ec::Group;

use circ::convert::integer_to_field;

use circ_fields::{FieldV, FieldT};
use std::convert::TryInto;
use elliptic_curve::consts::U512;
use ark_ff::BigInteger256;

fn int_to_bytes(i: &Integer) -> [u8; 32] {
    let scalar = int_to_scalar(i);
    scalar.to_bytes()
}

fn int_to_bytes_v2(i: &Integer) -> [u8; 32] {
    let digits: Vec<u8> = i.to_digits(rug::integer::Order::LsfLe);
    let mut repr: [u8; 32] = [0; 32];
    repr.as_mut()[..digits.len()].copy_from_slice(&digits);
    repr
}

fn int_to_scalar(i: &Integer) -> Scalar { 
    let mut accumulator = Scalar::zero();
    let limb_bits = (std::mem::size_of::<limb_t>() as u64) << 3;
    assert_eq!(limb_bits, 64);

    let two: u64 = 2;
    let mut m = Scalar::from(two.pow(63));
    m *= Scalar::from(two);

    // as_ref yeilds a least-significant-first array.
    for digit in i.as_ref().iter().rev() {
        accumulator *= m;
        accumulator += Scalar::from(*digit);
    }
    accumulator
}

fn int_to_scalar_v2(i: &Integer) -> Scalar {
    let digits: Vec<u8> = i.to_digits(rug::integer::Order::MsfLe);
    const num_modulus_bytes: usize = ((Scalar::MODULUS_BIT_SIZE + 7) / 8) as usize;
    assert!(digits.len() <= num_modulus_bytes);
    let mut repr: [u8; num_modulus_bytes] = [0; num_modulus_bytes];
    
    repr.as_mut()[num_modulus_bytes-digits.len()..].copy_from_slice(&digits);

    Scalar::from_be_bytes_mod_order(&repr)
}

fn int_to_scalar_v3(i: &Integer) -> Scalar {
    let digits: Vec<u8> = i.to_digits(rug::integer::Order::LsfLe);
    const num_modulus_bytes: usize = ((Scalar::MODULUS_BIT_SIZE + 7) / 8) as usize;
    let mut repr: [u8; num_modulus_bytes] = [0; num_modulus_bytes];
    
    repr.as_mut()[..digits.len()].copy_from_slice(&digits);

    Scalar::deserialize_compressed(&repr[..]).unwrap()
}

fn bytes_to_point(bytes: &[u8; 33]) -> Projective {
    Projective::deserialize_compressed(&bytes[..]).unwrap()
}


fn point_to_bytes(point: Affine) -> Vec<u8> {
    let mut compressed_bytes = Vec::new();
    point.serialize_compressed(&mut compressed_bytes).unwrap();
    compressed_bytes
}

fn test_msm() {
    let scalars = vec![Scalar::from(1), Scalar::from(2), Scalar::from(3)];

    let generator = <Config as SWCurveConfig>::GENERATOR;
    let points = vec![
        generator,
        generator,
        generator,
    ];
    let result = Projective::msm(&points, &scalars).unwrap();
    println!("test msm {:?}", result);

    assert_eq!(result, generator * Scalar::from(6));
}

fn test_generator() {
    let generator = <Config as SWCurveConfig>::GENERATOR;
    let generator_projective = Projective::from(generator);
    println!("generator_projective {:?}", generator_projective);
    let generator_from_fun = Projective::generator();
    println!("generator_from_fun {:?}", generator_from_fun);
}

fn test_projective_to_affine() {
    let generator = <Config as SWCurveConfig>::GENERATOR;
    let generator_projective = Projective::from(generator);
    let generator_affine = generator_projective.into_affine();
    println!("generator_affine {:?}", generator_affine);
}

fn test_hash_to_curve_parameters() {
    let zeta = Config::ZETA;
    // Verifying that ZETA is a non-square
    debug_assert!(
        Config::ZETA.legendre().is_qnr(),
        "ZETA should be a quadratic non-residue for the SWU map"
    );

    // Verifying the prerequisite for applicability  of SWU map
    debug_assert!(!Config::COEFF_A.is_zero() && !Config::COEFF_B.is_zero(),
		"Simplified SWU requires a * b != 0 in the short Weierstrass form of y^2 = x^3 + a*x + b ");
    println!("The check for hash to curve passes!");
}

fn test_integer_to_scalar() {
    println!("========= test_integer_to_scalar =========");
    for i in 1..100 {
        let test_integer = Integer::from(1)<< i;
        let scalar1 = int_to_scalar(&test_integer);
        let scalar2 = int_to_scalar_v2(&test_integer);
        let scalar3 = int_to_scalar_v3(&test_integer);
        assert!(scalar1 == scalar2);
        assert!(scalar3 == scalar2);

    }
    println!("Pass the test for integer to scalar!");
}

fn test_integer_to_bytes() {
    println!("========= test_integer_to_bytes =========");

    for i in 1..100 {
        let test_integer = Integer::from(1)<< i;
        let bytes = int_to_bytes(&test_integer);
        let bytes2 = int_to_bytes_v2(&test_integer);

        assert!(bytes == bytes2);
    }
}


fn test_hash_to_curve() {
    println!("========= test_hash_to_curve =========");
    let label: [u8; 4] = [1, 2, 3, 4];
    let mut bytes = [0u8; 64];
    bytes[0] = 33;
    let hasher = create_curvebased_hasher(&[]); 

    let result: Affine = hasher.hash(&bytes).unwrap();
    println!("result of hash to curve = {:?}", result);
}


fn main() {
    let generator = <Config as SWCurveConfig>::GENERATOR;

    test_projective_to_affine();
    test_hash_to_curve();

    test_hash_to_curve_parameters();
    test_integer_to_scalar();
    test_integer_to_bytes();

}