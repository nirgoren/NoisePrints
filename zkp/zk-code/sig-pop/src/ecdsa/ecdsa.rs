//! This module includes implementations related to ecdsa signature verification
use rug::Integer;
use openssl::ec::EcKey;
use openssl::pkey::Public;  
use openssl::hash::{MessageDigest, hash};
use openssl::ecdsa::EcdsaSig;
use openssl::ec::EcGroupRef;
use openssl::ec::{EcPoint};
use openssl::bn::{BigNum, BigNumContext};
use crate::allocate::map_u8; 

use crate::hash::hash::DigestAlgorithm;
use crate::convert::{os2ip, bignumref_to_integer, bool_vec_to_usize, integer_to_bool_vec};
use crate::convert::{integer_to_field};
use super::convert::integer_to_scalar;

use std::convert::TryInto;
use crate::bignat::bignat::{BigNat, BigNatb};
use crate::bignat::bignatwithlimbmax::{BigNatWithLimbMax, BigNatbWithLimbMax, BigNatModWithLimbMax}; //, inner_prover_input_for_single_mod, inner_prover_input_for_single_mod_w_remainder};
use crate::allocate::{map_u16_vec, map_u32_vec, map_u64_vec}; 

use fxhash::FxHashMap as HashMap;
use crate::ir::term::Value;


use crate::bignat::bignat_adv::{BigNatInit};
use crate::preproc_utils::{double_vec_point_to_str, double_vec_point_to_plain_str, vec_point_to_str, vec_point_to_plain_str, is_values_defined_in_file, write_to_file};
use crate::preproc_utils::{double_vec_p256point_to_str, vec_p256point_to_str};
use crate::user_input::confirm_append;
use p256::{Scalar, ProjectivePoint};
use p256::elliptic_curve::{group::GroupEncoding, generic_array::GenericArray};
use lazy_static::lazy_static;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use elliptic_curve::{Error};
use elliptic_curve::sec1::Coordinates;

use openssl::sign::Signer;
use openssl::{pkey::{PKey, Private}};
use openssl::nid::Nid;
use openssl::ec::{EcGroup};
use crate::target::r1cs::proof::serialize_into_file;


#[cfg(feature = "spartan")]
use std::sync::Arc;
#[cfg(feature = "spartan")]
use crate::right_field_arithmetic::alloc::map_field;

use crate::conditional_print;

lazy_static! {
    /// Prime field of P256
    pub static ref MODP: Integer = EllipticCurveP256::new().p;
    /// Hash of the generator of P256
    pub static ref HASH_G: P256Point = P256Point::hash_of_generator();
    /// Hash of the generator of P256 in projective form
    pub static ref HASH_G_PROJECT: ProjectivePoint = HASH_G.to_projective_point();

    /// H(G)^{-1}
    pub static ref HASH_G_INV: ProjectivePoint = HASH_G_PROJECT.neg();
}

/// Some contents of X509 Certificate
#[derive(Clone)]
pub struct ECDSAPublicKey { 
    /// EC key
    pub ec_key: EcKey<Public>,
    /// curve
    pub curve: EllipticCurveP256,
}

impl ECDSAPublicKey {
    /// Use openssl function to verify ECDSA signature
    pub fn verify_openssl(&self, signature: &ECDSASignature, message: &Vec<u8>, _digest_algo: &DigestAlgorithm){
        let digest = hash(MessageDigest::sha256(), message);
        let hash_value = match digest {
            Ok(digest_result) => digest_result,
            Err(_) => unreachable!(),
        };
        let digest_result: &[u8] = &hash_value;
        let _result = signature.signature.verify(digest_result, &self.ec_key).expect("Failed to verify ECDSA signature");
        conditional_print!("Verification result: {}", _result);
    }
    /// verify using the group operations (check R == m s^(-1)*G + r s^{-1} * Qa)
    pub fn verify_w_group_operations(&self, signature: &ECDSASignature, message: &Vec<u8>, _digest_algo: &DigestAlgorithm) -> bool {
       assert!(signature.r != 0);
       assert!(signature.s != 0);

       let group: &EcGroupRef = self.ec_key.group();
        // Print the curve name
        if let Some(_curve_name) = group.curve_name() {//P256
           conditional_print!("Curve Name {:?}", _curve_name.long_name());
       } else {
           conditional_print!("Curve Name is not available");
        }
       // Create a BigNum object to store the order
       let mut order: BigNum = BigNum::new().unwrap();
       // Create a BigNumContext object
       let mut ctx = BigNumContext::new().unwrap();
       // Call the order method on the EcGroupRef object
       group.order(&mut order, &mut ctx).unwrap();
       
       // 115792089210356248762697446949407573529996955224135760342422259061068512044369 vs 115792089210356248762697446949407573530086143415290314195533631308867097853951
       let order_integer: Integer = Integer::from_str_radix(&order.to_dec_str().unwrap(), 10).unwrap();

       conditional_print!("order: {:?}", order_integer);
       let s_inv: Integer = signature.s.clone().invert(&order_integer).expect("Should be a Integer");
       conditional_print!("s_inv: {:?}", s_inv);

       let b: Integer = signature.r.clone() * s_inv.clone() % order_integer.clone();
       let b_bignum = BigNum::from_dec_str(&b.to_string_radix(10)).unwrap();
       conditional_print!("b: {:?}", b);

       let digest = hash(MessageDigest::sha256(), message);
       let hash_value = match digest {
           Ok(digest_result) => digest_result,
           Err(_) => unreachable!(),
       };
       let digest_result: &[u8] = &hash_value;
       let a: Integer = os2ip(digest_result) * s_inv.clone() % order_integer.clone();
       conditional_print!("a: {:?}", a);

       let a_bignum = BigNum::from_dec_str(&a.to_string_radix(10)).unwrap();
       // Compute the sum of the two points: a * G + b * public_key
       let mut mula: EcPoint = EcPoint::new(&group).expect("initialize an ecpoint");
       let mut mulb: EcPoint = EcPoint::new(&group).expect("initialize an ecpoint");
       let mut sum: EcPoint = EcPoint::new(&group).expect("initialize an ecpoint");
       let mut bn_ctx = BigNumContext::new().unwrap();

       mula.mul_generator(&group, &a_bignum, &bn_ctx).expect("compute a * G"); // storing result in self

       mulb.mul(&group, self.ec_key.public_key(), &b_bignum, &bn_ctx).expect("compute b * u");
       sum.add(group, &mula, &mulb, &mut bn_ctx).expect("compute a * G + b * u");

       // Extract the x-coordinate of the resulting point
       let mut x_coord = BigNum::new().unwrap();
       let mut y_coord = BigNum::new().unwrap();
       let mut bn_ctx_mut = BigNumContext::new().unwrap();
       sum.affine_coordinates_gfp(&group, &mut x_coord, &mut y_coord, &mut bn_ctx_mut).expect("compute the x-coordinate");
       conditional_print!("x_coord {:?}", x_coord);
       let x_coord_int: Integer = bignumref_to_integer(&x_coord).expect("convert x coordinate from bignum to integer");
       x_coord_int == signature.r
    }

    /// verify using the group operations (Check s*T + U == Qa)
    pub fn verify_w_group_operations_for_circuit(&self, signature: &ECDSASignature, message: &Vec<u8>, _digest_algo: &DigestAlgorithm){
        assert!(signature.r != 0);
        assert!(signature.s != 0);
 
        let group: &EcGroupRef = self.ec_key.group();
            // Print the curve name
            if let Some(_curve_name) = group.curve_name() {//P256
                conditional_print!("Curve Name {:?}", _curve_name.long_name());
            } else {
                conditional_print!("Curve Name is not available");
            }
        // Create a BigNum object to store the order
        let mut order: BigNum = BigNum::new().unwrap();
        // Create a BigNumContext object
        let mut ctx = BigNumContext::new().unwrap();
        // Call the order method on the EcGroupRef object
        group.order(&mut order, &mut ctx).unwrap();
        
        // 115792089210356248762697446949407573529996955224135760342422259061068512044369 vs 115792089210356248762697446949407573530086143415290314195533631308867097853951
        let order_integer: Integer = Integer::from_str_radix(&order.to_dec_str().unwrap(), 10).unwrap();
        conditional_print!("order: {:?}", order_integer);
        let s_inv: Integer = signature.s.clone().invert(&order_integer).expect("Should be a Integer");
 
        let b: Integer = signature.r.clone() * s_inv.clone() % order_integer.clone();
 
        let digest = hash(MessageDigest::sha256(), message);
        let hash_value = match digest {
            Ok(digest_result) => digest_result,
            Err(_) => unreachable!(),
        };
        let digest_result: &[u8] = &hash_value;
        let a: Integer = os2ip(digest_result) * s_inv.clone() % order_integer.clone();

        let curve = EllipticCurveP256::new();
        let mula: P256Point = curve.g.scalar_mult(a.clone());
        let pk_ecpoint: EcPoint = self.ec_key.public_key().to_owned(group).unwrap();
        let pk: P256Point = P256Point::extract_coordinate(&pk_ecpoint, group);
        let mulb: P256Point = pk.scalar_mult(b.clone());
        let sum: P256Point = P256Point::point_add(Some(mula), Some(mulb));
        let x_under_modq: Integer = sum.x.clone() % order_integer.clone();
        assert!(x_under_modq == signature.r, 
            "R.x != r mod q: R.x = {:?}; r = {:?}", x_under_modq, signature.r);
    }


    /// Allocate signature (ECDSASign_init), issuer key (BigNat), digest result (BigNat_init) into the circuit with advanced range check 
    pub fn generate_witness_adv(pk: &P256Point, limbwidth: usize, n_limbs: usize, subtable_bitwidth: usize, signature: &ECDSASignatureOri, name: &str, input_map: &mut HashMap<String, Value>) {
        let append: String = if name.is_empty() {name.to_owned()} else {name.to_owned()+"."};
        Self::allocate_issuer_key(pk, limbwidth, n_limbs, name, input_map);
        signature.allocate_signature_adv(limbwidth, n_limbs, subtable_bitwidth, name, input_map);
    }

    /// Allocate issuer key into the circuit
    pub fn allocate_issuer_key(pk: &P256Point, limb_width: usize, n_limbs: usize, name: &str, input_map: &mut HashMap<String, Value>) -> bool {
        let prepend: String = if name.is_empty() {name.to_owned()} else {name.to_owned()+"."};
        let pk_bignat: BigNatPoint = BigNatPoint::new(pk, limb_width, n_limbs, false);
        conditional_print!("pk_bignat x {:?} y{:?}", pk_bignat.x.limb_values.clone().unwrap(), pk_bignat.y.limb_values.clone().unwrap());
        pk_bignat.alloc(&format!("{}issuerkey", prepend), input_map);
        true
    }
    /// Convert key to type of P256Point
    pub fn to_p256point(&self) -> P256Point {
        let group: &EcGroupRef = self.ec_key.group();
        let pk_ecpoint: EcPoint = self.ec_key.public_key().to_owned(group).unwrap();
        P256Point::extract_coordinate(&pk_ecpoint, group)
    }
}

/// ECDSA Signature
pub struct ECDSASignature { 
    /// r
    pub r: Integer,
    /// s
    pub s: Integer,
    /// the whole signature,
    pub signature: EcdsaSig,
}

impl ECDSASignature {
    fn allocate_signature(&self, limbwidth: usize, n_limbs: usize, name: &str, input_map: &mut HashMap<String, Value>) {
        let r_bignat: BigNat = BigNat::new(&self.r, limbwidth, n_limbs);
        let r_bignatb: BigNatb = BigNatb::from_bignat(&r_bignat);
        let s_bignat: BigNat = BigNat::new(&self.s, limbwidth, n_limbs);
        let s_bignatb: BigNatb = BigNatb::from_bignat(&s_bignat);
        if name.is_empty() {
            r_bignatb.alloc_from_natb("signatureb.r", input_map);
            s_bignatb.alloc_from_natb("signatureb.s", input_map);
        } else {
            r_bignatb.alloc_from_natb(&format!("{}.signatureb.r", name), input_map);
            s_bignatb.alloc_from_natb(&format!("{}.signatureb.s", name), input_map);
        }
    }


    fn allocate_signature_adv(&self, limbwidth: usize, n_limbs: usize, subtable_bitwidth: usize, name: &str, input_map: &mut HashMap<String, Value>) {
        let append: String = if name.is_empty() {name.to_owned()} else {name.to_owned()+"."};
        BigNatInit::alloc_from_integer(&self.r, limbwidth, n_limbs, subtable_bitwidth, &format!("{}signature_init.r", append), input_map);
        BigNatInit::alloc_from_integer(&self.s, limbwidth, n_limbs, subtable_bitwidth, &format!("{}signature_init.s", append), input_map);
    }

    /// Allocate ECDSASign_init (s <- v, r <- r) to the circuit
    pub fn alloc_sigma(v: &Integer, r: &Integer, limbwidth: usize, n_limbs: usize, subtable_bitwidth: usize, name: &str, input_map: &mut HashMap<String, Value>) {
        let append: String = if name.is_empty() {name.to_owned()} else {name.to_owned()+"."};
        BigNatInit::alloc_from_integer(r, limbwidth, n_limbs, subtable_bitwidth, &format!("{}signature_init.r", append), input_map);
        BigNatInit::alloc_from_integer(v, limbwidth, n_limbs, subtable_bitwidth, &format!("{}signature_init.s", append), input_map);
    }
}

/// ECDSA Signature
pub struct ECDSASignatureBigNat { 
    /// r
    pub r: BigNatWithLimbMax,
    /// s
    pub s: BigNatWithLimbMax,
}

impl ECDSASignatureBigNat {
    /// Create an ECDSASignatureBigNat instance from an ECDSASignature instance
    pub fn from_ecdsasignature(signature: ECDSASignature, limbwidth: usize, n_limbs: usize) -> Self {
        Self {
            r: BigNatWithLimbMax::new(&signature.r, limbwidth, n_limbs, false), // true?
            s: BigNatWithLimbMax::new(&signature.s, limbwidth, n_limbs, false),
        }
    }

    /// Allocate an ECDSASignatureBigNat instance to the circuit; to do
    pub fn alloc(&self, name: &str, input_map: &mut HashMap<String, Value>) { // ** to do
        let prepend: String = if name.is_empty() {name.to_owned()} else {name.to_owned()+"."};
        let r_bignatb: BigNatbWithLimbMax = BigNatbWithLimbMax::from_bignat(&self.r);
        let s_bignatb: BigNatbWithLimbMax = BigNatbWithLimbMax::from_bignat(&self.s);
        r_bignatb.alloc_from_natb(&format!("{}signatureb.r", prepend), input_map);
        s_bignatb.alloc_from_natb(&format!("{}signatureb.s", prepend), input_map);
    }
}

/// Prover input for ECDSA signature verification
pub struct ProverPrecomputeInput {
    /// Public key
    pub public_key: ProjectivePoint,
    /// Signature
    pub signature: ECDSASignatureVar,
    /// r
    pub r: Integer,
    /// Message
    pub message: Vec<u8>, 
}

impl ProverPrecomputeInput {
    /// Generate witness for designated message length
    pub fn generate(message_length: usize) -> Self {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ecdsa_keypair = EcKey::generate(&group).unwrap();
        let private_key = PKey::from_ec_key(ecdsa_keypair.clone()).unwrap();

        let mut signer = Signer::new(MessageDigest::sha256(), &private_key).unwrap();
        let mut message: Vec<u8> = Vec::new();
        for _ in 0..message_length {
            message.push(7);
        }
        signer.update(&message).unwrap();
        let signature_der = signer.sign_to_vec().unwrap();
        let signature = EcdsaSig::from_der(&signature_der).unwrap();


        let private_key: EcKey<Private> = private_key.ec_key().unwrap();
        let group: &EcGroupRef = private_key.group();
        let pk_ecpoint: EcPoint = private_key.public_key().to_owned(group).unwrap();
        // let decode_key = RSAPublicKey::extract_rsa_public_key(public_key);
        let pk: P256Point = P256Point::extract_coordinate(&pk_ecpoint, group);
        let pk_projective: ProjectivePoint = pk.to_projective_point();

        let r: Integer = bignumref_to_integer(signature.r()).expect("Failed to parse r into Integer");
        let signature_var: ECDSASignatureVar = ECDSASignatureVar::from_ecdsasig(
            signature, 
            &message, 
            pk_projective);
        
        let pk_encoded = pk_projective.to_encoded_point(true);
        let pk_bytes = pk_encoded.as_bytes();
        serialize_into_file(&pk_bytes, "example_cert/ecdsa_public_key").unwrap();
        Self {
            public_key: pk_projective,
            signature: signature_var,
            r: r,
            message: message,
        }
    }

    /// Extract the signature in form of (r, s)
    pub fn extract_signatureori(&self, modulus: &Integer) -> ECDSASignatureOri {
        ECDSASignatureOri {
            r: self.r.clone(),
            s: (self.signature.z.clone() * self.r.clone()) % modulus.clone(),
        }
    }
}

/// ECDSA Signature in original format
pub struct ECDSASignatureOri { 
    /// r
    pub r: Integer,
    /// s
    pub s: Integer,
}

impl ECDSASignatureOri {
    fn allocate_signature_adv(&self, limbwidth: usize, n_limbs: usize, subtable_bitwidth: usize, name: &str, input_map: &mut HashMap<String, Value>) {
        let append: String = if name.is_empty() {name.to_owned()} else {name.to_owned()+"."};
        BigNatInit::alloc_from_integer(&self.r, limbwidth, n_limbs, subtable_bitwidth, &format!("{}signature_init.r", append), input_map);
        BigNatInit::alloc_from_integer(&self.s, limbwidth, n_limbs, subtable_bitwidth, &format!("{}signature_init.s", append), input_map);
    }
}
/// ECDSA Signature in another format
pub struct ECDSASignatureVar { 
    /// z
    pub z: Integer,
    /// R
    pub point_r: ProjectivePoint,
}

impl ECDSASignatureVar {
    /// Convert ECDSASignature to ECDSASignatureVar
    pub fn from_ecdsasignature(signature: &ECDSASignature, digest_result: Integer, vk: ProjectivePoint, modq: Integer) -> Self { // not sure if we should input vk as ProjectivePoint
        let s_inv: Integer = signature.s.clone().invert(&modq).expect("Fail to compute the inverse of s");
        let z_inv: Integer = s_inv.clone() * signature.r.clone() % modq.clone();
        let hash_times_s_inv: Integer = digest_result * s_inv.clone() % modq.clone();
        let z_inv_scalar: Scalar = integer_to_scalar(&z_inv);
        let hash_times_s_inv_scalar: Scalar = integer_to_scalar(&hash_times_s_inv);
        let point_r: ProjectivePoint = (ProjectivePoint::GENERATOR * hash_times_s_inv_scalar) + (vk * z_inv_scalar);
        Self {
            z: z_inv.invert(&modq).expect("Fail to compute the inverse of z_inv"),
            point_r: point_r,
        }
    }
    /// From EcdsaSig
    pub fn from_ecdsasig(signature: EcdsaSig, message: &Vec<u8>, vk: ProjectivePoint) -> Self {
        let digest_result: Integer = DigestAlgorithm::sha256(message);
        let modq = EllipticCurveP256::new().q.clone();
        let r = signature.r(); 
        let r_integer: Integer = bignumref_to_integer(r).expect("Failed to parse r into Integer");
        let s = signature.s();
        let s_integer: Integer = bignumref_to_integer(s).expect("Failed to parse s into Integer");
        let ecdsa_signature: ECDSASignature = ECDSASignature {
            r: r_integer,
            s: s_integer,
            signature: signature,
        };
        Self::from_ecdsasignature(&ecdsa_signature, digest_result, vk, modq)
    }
}

#[derive(Clone)]
/// P-256 curve
pub struct EllipticCurveP256 {
    /// Curve coefficients
    pub a: Integer,
    /// Curve coefficients
    pub b: Integer,
    /// Field characteristic
    pub p: Integer,
    /// Subgroup order
    pub q: Integer,
    /// Base point
    pub g: P256Point,
    /// for checking x(R) = r mod q and r < q
    pub p_minusq_minus1: Integer,

}

impl EllipticCurveP256 {
    /// set up parameters for curve P256
    pub fn new() -> Self {
        let a: Integer = Integer::from_str_radix("-3", 10).unwrap();
        let b: Integer = Integer::from_str_radix("41058363725152142129326129780047268409114441015993725554835256314039467401291", 10).unwrap();
        let p: Integer = Integer::from_str_radix("115792089210356248762697446949407573530086143415290314195533631308867097853951", 10).unwrap();
        let q: Integer = Integer::from_str_radix("115792089210356248762697446949407573529996955224135760342422259061068512044369", 10).unwrap();
        
        let gx: Integer = Integer::from_str_radix("48439561293906451759052585252797914202762949526041747995844080717082404635286", 10).unwrap();
        let gy: Integer = Integer::from_str_radix("36134250956749795798585127919587881956611106672985015071877198253568414405109", 10).unwrap();
        
        let p_minusq_minus1: Integer = p.clone() - q.clone() - Integer::from(0);
        EllipticCurveP256 {
            a: a,
            b: b,
            p: p,
            q: q,
            g: P256Point {
                x: gx,
                y: gy,
                empty: false,
            },
            p_minusq_minus1: p_minusq_minus1,
        }
    }

}

#[derive(Clone, PartialEq, Eq, Debug)]
/// Point on P256 curve
pub struct P256Point {
    /// x-coordinate
    pub x: Integer,
    /// y-coordinate
    pub y: Integer,
    /// true: point at infinity; false: not point at infinity; this field is only used for compute witnesses
    pub empty: bool,
}

impl P256Point {
    /// Negation of the point
    pub fn neg(&self) -> Self {
        let modp: Integer = MODP.clone();
        Self {
            x: self.x.clone(),
            y: (modp.clone() - self.y.clone()) % modp.clone(),
            empty: self.empty,
        }
    }

    /// create a point at infinity
    pub fn create_point_at_infinity(&self) -> Self {
        Self {
            x: self.x.clone(),
            y: self.y.clone(),
            empty: true,
        }
    }

    fn is_on_curve(&self) -> bool {
        let curve: EllipticCurveP256 = EllipticCurveP256::new();
        let check_integer: Integer = (self.y.clone() * self.y.clone() - self.x.clone() * self.x.clone() * self.x.clone() - curve.a.clone() * self.x.clone() - curve.b.clone()) % curve.p.clone();
        check_integer == 0
    }

    /// Check if two points equal to each other
    pub fn is_equal(&self, point2: &Self) -> bool {
        let x_equal: bool = self.x == point2.x;
        assert!(!(x_equal && self.y != point2.y) || self.empty || point2.empty);
        x_equal && (self.empty == point2.empty)
    }

    /// Hash of the generator of P256
    pub fn hash_of_generator() -> Self {
        let x: Integer = Integer::from_str_radix("22275546478013928845421778156819724388979498085958565250610071188208345353045", 10).unwrap(); // obtain from https://github.com/armfazh/h2c-rust-ref.git; how: convert x, y coordintates of the generator h into a bit string and output the EC point on P256
        let y: Integer = Integer::from_str_radix("87038901988042843095391562964749027457570902217912243630656660389794851490605", 10).unwrap();
        Self {
            x: x.clone(),
            y: y.clone(),
            empty: false,
        }
    }

    /// Convert p256::ProjectivePoint to P256Point
    pub fn from_projective_point(input: ProjectivePoint) -> Self {
        let encoded_point = input.to_encoded_point(false);
        let result = match encoded_point.coordinates() {
            Coordinates::Uncompressed { x, y } => {
                // let x_bytes = x.as_bytes();
                let x_integer = Integer::from_digits(&x, rug::integer::Order::MsfBe);
                let y_integer = Integer::from_digits(&y, rug::integer::Order::MsfBe);
                let result = P256Point{x: x_integer, y: y_integer, empty: false};
                Ok(result)
            }
            _ => Err(Error),
        };
        result.unwrap()
    }

    /// Convert P256Point to p256::ProjectivePoint
    pub fn to_projective_point(&self) -> ProjectivePoint {
        let mut bytes = self.x.to_digits(rug::integer::Order::MsfBe);
        if self.y.is_odd() {
            bytes.insert(0, 0x03);
        } else {
            bytes.insert(0, 0x02);
        }
        let generic_bytes: &<ProjectivePoint as GroupEncoding>::Repr = GenericArray::from_slice(&bytes);
        ProjectivePoint::from_bytes(generic_bytes).expect("Fail to convert bytes to ProjectivePoint")
    }
    
    /// adding two points over P256 curve
    pub fn point_add(point1: Option<Self>, point2: Option<Self>) -> Self { // return self + point2
        let curve: EllipticCurveP256 = EllipticCurveP256::new();
        let pt1;
        let pt2;
        match point1 {
            Some(point) => {
                assert!(point.is_on_curve());
                pt1 = point;
            }
            None => {  //if point1 is None:
                match point2 {
                    Some(point) => {
                        assert!(point.is_on_curve());
                        return point;
                    }
                    None => { panic!("Both point1 and point2 are None"); }            
                };
            }
        };
        match point2 {
            Some(point) => {
                assert!(point.is_on_curve());
                pt2 = point;
            }
            None => { return pt1; }  //if point2 is None:          
        };

        if pt1.x == pt2.x && pt1.y != pt2.y {
            panic!("Unimplemented error");
        }
        let m: Integer = if pt1.x == pt2.x { // the case that self == pt2
                            let double_y1: Integer = 2 * pt1.y.clone();
                            let invert_double_y1: Integer = double_y1.invert(&(curve.p)).expect("invert of 2*y1");
                            (3 * pt1.x.clone() * pt1.x.clone() + curve.a.clone()) * invert_double_y1
                        } else { // the case that pt1 != pt2
                            let differ_x: Integer = pt1.x.clone() - pt2.x.clone();
                            let invert_differ_x: Integer = differ_x.invert(&(curve.p)).expect("Invert of x1-x2");
                            (pt1.y.clone() - pt2.y.clone()) * invert_differ_x
                        };
        let x3: Integer = m.clone() * m.clone() - pt1.x.clone() - pt2.x.clone();
        let y3: Integer = pt1.y.clone() + m.clone() * (x3.clone() - pt1.x.clone());
        let result = P256Point {
            x: x3 % curve.p.clone(),
            y: (((-y3) % curve.p.clone()) + curve.p.clone()) % curve.p.clone(),
            empty: false,
        };
        assert!(result.is_on_curve());
        result
    } 

    /// compute k * self over P256 curve
    pub fn scalar_mult(self, k: Integer) -> Self { // return k * self 
        let curve: EllipticCurveP256 = EllipticCurveP256::new();
        assert!(self.is_on_curve());
        if k.clone() % curve.q == 0 { panic!("Unimplemented Error for p256 curve")};
        if k.clone() < 0 { panic!("Unimplemented Error for p256 curve")};
        let mut addend: P256Point = self.clone();
        let mut result: Option<P256Point> = None;
        let mut scalar: Integer = k.clone();
        while scalar != 0 {
            if scalar.is_odd() {
                result = Some(Self::point_add(result, Some(addend.clone())));
            }
            addend = Self::point_add(Some(addend.clone()), Some(addend.clone()));
            scalar = scalar>>1;
        }
        let res: P256Point = result.expect("should be of type P256Point");
        assert!(res.is_on_curve());
        res
    }
    
    fn extract_coordinate(point: &EcPoint, group: &EcGroupRef) -> Self {
        let mut ctx = BigNumContext::new().unwrap();
        let mut x_coord = BigNum::new().unwrap();
        let mut y_coord = BigNum::new().unwrap();
        
        point.affine_coordinates_gfp(group, &mut x_coord, &mut y_coord, &mut ctx).expect("compute the x, y-coordinate");
        let x_coord_int: Integer = bignumref_to_integer(&x_coord).expect("convert x coordinate from bignum to integer");
        let y_coord_int: Integer = bignumref_to_integer(&y_coord).expect("convert x coordinate from bignum to integer");
        Self {
            x: x_coord_int,
            y: y_coord_int,
            empty: false,
        }
    }

    /// Allocate a variable of type ECPoint to the circuit
    pub fn alloc(&self, limb_width: usize, n_limbs: usize, name: &str, input_map: &mut HashMap<String, Value>) {
        let prepend: String = if name.is_empty() {name.to_owned()} else {name.to_owned()+"."};
        BigNatWithLimbMax::alloc_from_integer(&self.x, limb_width, n_limbs, &format!("{}x", prepend), input_map);
        BigNatWithLimbMax::alloc_from_integer(&self.y, limb_width, n_limbs, &format!("{}y", prepend), input_map);
    }

    #[cfg(feature = "spartan")]
    /// Allocate a variable of type ECPoint_Fp to the circuit ** to do
    pub fn alloc_fp(&self, modulus: &Arc<Integer>, name: &str, input_map: &mut HashMap<String, Value>) {
        let prepend: String = if name.is_empty() {name.to_owned()} else {name.to_owned()+"."};
        map_field(&self.x, modulus, &format!("{}x", prepend), input_map);
        map_field(&self.y, modulus, &format!("{}y", prepend), input_map);
    } 
}

/// Point on P256 curve using the struct BigNatbWithLimbMax to record the coordinates
pub struct BigNatPointb { // assume the point is not at infinity
    /// x-coordinate
    pub x: BigNatbWithLimbMax,
    /// y-coordinate
    pub y: BigNatbWithLimbMax,
}

impl BigNatPointb {
    /// Initiate a BigNatPoint instance 
    pub fn new(point: &P256Point, limb_width: usize, n_limbs: usize, constant: bool) -> Self {
        Self {
            x: BigNatbWithLimbMax::new(&point.x, limb_width, n_limbs, constant), 
            y: BigNatbWithLimbMax::new(&point.y, limb_width, n_limbs, constant),
        }
    }
    /// Allocate a BigNatPointb instance to the circuit
    pub fn alloc(&self, name: &str, input_map: &mut HashMap<String, Value>) {
        let prepend: String = if name.is_empty() {name.to_owned()} else {name.to_owned()+"."};
        self.x.alloc_from_natb(&format!("{}x", prepend), input_map);
        self.y.alloc_from_natb(&format!("{}y", prepend), input_map);
    }
}

#[derive(Clone, Debug)]
/// Point on P256 curve using the struct BigNatWithLimbMax to record the coordinates
pub struct BigNatPoint {
    /// x-coordinate
    pub x: BigNatWithLimbMax,
    /// y-coordinate
    pub y: BigNatWithLimbMax,
    /// true: point at infinity; false: not point at infinity; this field is only used for compute witnesses
    pub empty: bool, 
}

impl BigNatPoint {
    /// Initiate a BigNatPoint instance 
    pub fn new(point: &P256Point, limb_width: usize, n_limbs: usize, constant: bool) -> Self {
        let y: BigNatWithLimbMax = BigNatWithLimbMax::new(&point.y, limb_width, n_limbs, constant);
        let x: BigNatWithLimbMax = BigNatWithLimbMax::new(&point.x, limb_width, n_limbs, constant);
        Self {
            x: x, 
            y: y,
            empty: point.empty,
        }
    }
    /// Allocate a BigNatPoint instance to the circuit
    pub fn alloc(&self, name: &str, input_map: &mut HashMap<String, Value>) {
        let prepend: String = if name.is_empty() {name.to_owned()} else {name.to_owned()+"."};
        self.x.alloc_from_nat(&format!("{}x", prepend), input_map);
        self.y.alloc_from_nat(&format!("{}y", prepend), input_map);
    }
}

/// Representations of intermediate values for verifying point double over P256 curve
#[derive(Clone, PartialEq, Eq)]
pub struct BigNatPointDouble {
    /// Products
    pub products: Vec<BigNatWithLimbMax>,
    /// Intermediate values
    pub remainders: Vec<BigNatWithLimbMax>, // Vec<BigNatbWithLimbMax>,
    /// Intermediate for modulation
    pub intermediate_mod: Vec<BigNatModWithLimbMax>,
    /// resultant point
    pub res_point: P256Point,
}

impl BigNatPointDouble {
    /// compute the intermediate input for doubling the point on the circuit
    pub fn new_v2(point: P256Point, limbwidth: usize, n_limbs: usize, limbs_per_gp: usize, advanced: bool) -> Self {
        let mut products: Vec<BigNatWithLimbMax> = Vec::new();
        let mut remainders: Vec<BigNatWithLimbMax> = Vec::new();
        // let mut remainders: Vec<BigNatbWithLimbMax> = Vec::new();
        let mut intermediate_mod: Vec<BigNatModWithLimbMax> = Vec::new();
        let curve: EllipticCurveP256 = EllipticCurveP256::new();
        let pt: BigNatPoint = BigNatPoint::new(&point, limbwidth, n_limbs, false);
        let p_bignat: BigNatWithLimbMax = BigNatWithLimbMax::new(&curve.p, limbwidth, n_limbs, true);
        let squ_p: Integer = curve.p.clone() * curve.p.clone();
        let squ_p_bignat: BigNatWithLimbMax = BigNatWithLimbMax::new(&squ_p, limbwidth, 2*n_limbs, true);

        // 1. check 2*y*m + 12*p*p = p*(quotient+12p) + 3*x*x + a // quotient bits = 260
        let double_y: BigNatWithLimbMax = pt.y.scalar_mult_nat(&Integer::from(2));
        let double_y_inv: Integer = double_y.clone().value.unwrap().invert(&curve.p).expect("Should be a Integer");
        let m: Integer = ((3*point.x.clone()*point.x.clone()+curve.a.clone()+curve.p.clone())*double_y_inv.clone()) % curve.p.clone();

        let m_bignat: BigNatWithLimbMax = BigNatWithLimbMax::new(&m, limbwidth, n_limbs, false);
        // remainders.push(BigNatbWithLimbMax::new(&m, limbwidth, n_limbs, false));
        remainders.push(m_bignat.clone());
        let double_y_times_m: BigNatWithLimbMax = m_bignat.create_product_nat_for_circ(&double_y, &mut products); // m*(2y)
        let twelve_squ_p: BigNatWithLimbMax = squ_p_bignat.scalar_mult_nat(&Integer::from(12)); // 12*p*p
        let res_left0: BigNatWithLimbMax = double_y_times_m.create_addition_nat(&twelve_squ_p);

        let three_x: BigNatWithLimbMax = pt.x.scalar_mult_nat(&Integer::from(3)); // 3*x
        let three_x_times_x: BigNatWithLimbMax = three_x.create_product_nat_for_circ(&pt.x, &mut products); // 3x * x
        let curve_a: Integer = (curve.a.clone()+curve.p.clone()) % curve.p.clone();
        let curve_a_bignat: BigNatWithLimbMax = BigNatWithLimbMax::new(&curve_a, limbwidth, n_limbs, true);
        let res_right: BigNatWithLimbMax = three_x_times_x.create_addition_nat(&curve_a_bignat); // 3*x*x + a
        let mod_res: BigNatModWithLimbMax = BigNatModWithLimbMax::new_w_remainder2(&res_left0, &p_bignat, &curve_a_bignat, &res_right, 260, limbs_per_gp, advanced);
        intermediate_mod.push(mod_res.clone());

        // 3. check x3 = (m * m - 2 * x) mod p <=> (m * m - 2 * x) = p * quotient + x3 <=> m * m + 4 * p = p * (quotient+4) + x3 + 2 * x
        let x3: Integer = (m.clone() * m.clone() - 2 * point.x.clone() + 4 * curve.p.clone()) % curve.p.clone(); // x3 = (m * m - 2 * x) mod p
        let x3_bignat: BigNatWithLimbMax = BigNatWithLimbMax::new(&x3, limbwidth, n_limbs, false);
        // remainders.push(BigNatbWithLimbMax::new(&x3, limbwidth, n_limbs, false));
        remainders.push(x3_bignat.clone());
        let dou_x: BigNatWithLimbMax = pt.x.scalar_mult_nat(&Integer::from(2)); // 2*x
        let x3_plus_dou_x: BigNatWithLimbMax = x3_bignat.create_addition_nat(&dou_x); // x3 + 2 * x
        let squ_m_bignat: BigNatWithLimbMax = m_bignat.create_product_nat_for_circ(&m_bignat, &mut products);
        let quadruple_p: BigNatWithLimbMax = p_bignat.scalar_mult_nat(&Integer::from(4));
        let res_left3: BigNatWithLimbMax = squ_m_bignat.create_addition_nat(&quadruple_p); // m * m + 4 * p
        let mod_res3: BigNatModWithLimbMax = BigNatModWithLimbMax::new_w_remainder2(&res_left3, &p_bignat, &x3_bignat, &x3_plus_dou_x, 257, limbs_per_gp, advanced);
        intermediate_mod.push(mod_res3.clone().clone());

        // 4. compute y3 = -y1 + m * (x1 - x3) % p
        // <=> y3 = p*quotient -y1 + m * (x1 - x3) <=> y3 + y1 + m*x3 + 4*p*p = p*(quotient+4*p) + m*x1
        let y3: Integer = (2*curve.p.clone()-point.y.clone() + m.clone() * (point.x.clone() - x3.clone() + 2*curve.p.clone())) % curve.p.clone();

        let y3_bignat: BigNatWithLimbMax = BigNatWithLimbMax::new(&y3, limbwidth, n_limbs, false);
        // remainders.push(BigNatbWithLimbMax::new(&y3, limbwidth, n_limbs, false));
        remainders.push(y3_bignat.clone());
        let y1_plus_y3: BigNatWithLimbMax = pt.y.create_addition_nat(&y3_bignat); // y1+y3
        let m_times_x3: BigNatWithLimbMax = m_bignat.create_product_nat_for_circ(&x3_bignat, &mut products); // m*x3
        let res_left4_0: BigNatWithLimbMax = y1_plus_y3.create_addition_nat(&m_times_x3); // y1+y3+m*x3
        let squ_p: Integer = p_bignat.value.clone().unwrap() * p_bignat.value.clone().unwrap();
        let squ_p_bignat: BigNatWithLimbMax = BigNatWithLimbMax::new(&squ_p, limbwidth, 2*n_limbs, true);
        let four_squ_p: BigNatWithLimbMax = squ_p_bignat.scalar_mult_nat(&Integer::from(4)); // 4*p*p
        let res_left4_1: BigNatWithLimbMax = res_left4_0.create_addition_nat(&four_squ_p); // y1 + y3 + m*x3 + 4*p*p

        let res_right4: BigNatWithLimbMax = m_bignat.create_product_nat_for_circ(&pt.x, &mut products); // m*x1
        let mod_res4: BigNatModWithLimbMax = BigNatModWithLimbMax::new_w_remainder2(&res_left4_1, &p_bignat, &y3_bignat, &res_right4, 259, limbs_per_gp, advanced);
        intermediate_mod.push(mod_res4.clone());


        let res_point = P256Point {
            x: x3.clone(),
            y: y3.clone(),
            empty: point.empty, // newly added
        };
        assert!(res_point.is_on_curve());
        Self {
            products, remainders, intermediate_mod, res_point
        }
    }
    /// Allocate a BigNatPointDouble instance to the circuit
    pub fn alloc_v3(&self, name: &str, append: String, input_map: &mut HashMap<String, Value>) {
        let prepend: String = name.to_owned();

        for (i, product) in self.products.iter().enumerate() {
            product.alloc_from_nat(&format!("{}.mm_for_pd{}.products.{}", prepend, append, i), input_map);
        }

        for (i, remainder) in self.remainders.iter().enumerate() {
            BigNatbWithLimbMax::alloc_from_bignat(&remainder, &format!("{}.mm_for_pd{}.remainders.{}", prepend, append, i), input_map);
            // remainder.alloc_from_natb(&format!("{}.mm_for_pd{}.remainders.{}", prepend, append, i), input_map);
        }

        for (i, ele) in self.intermediate_mod.iter().enumerate() {
            ele.alloc2(format!("{}.mm_for_pd{}.intermediate_mod.{}", prepend, append, i).as_str(), input_map);
        }
    }

    /// Allocate a BigNatPointDouble instance to the circuit with adanced range check
    pub fn alloc_adv(&self, subtable_bitwidth: usize, name: &str, input_map: &mut HashMap<String, Value>) {
        let prepend: String = if name.is_empty() {name.to_owned()} else {name.to_owned()+"."};
        
        for (i, product) in self.products.iter().enumerate() {
            product.alloc_from_nat(&format!("{}products.{}", prepend, i), input_map); // mm_for_pd
        }

        for (i, remainder) in self.remainders.iter().enumerate() {
            remainder.alloc_adv(subtable_bitwidth, &format!("{}intermediate_mod.{}.res_init", prepend, i), input_map); // mm_for_pd
            // BigNatbWithLimbMax::alloc_from_bignat(&remainder, &format!("{}mm_for_pd{}.remainders.{}", prepend, append, i), input_map);
        }

        for (i, ele) in self.intermediate_mod.iter().enumerate() {
            ele.alloc_adv(subtable_bitwidth, format!("{}intermediate_mod.{}", prepend, i).as_str(), input_map); // allocate v, quotient_init and carry_init
            // ele.alloc2(format!("{}mm_for_pd{}.intermediate_mod.{}", prepend, append, i).as_str(), input_map);
        }
    }
}

/// Representations of intermediate values for verifying point double over P256 curve
#[derive(Clone, PartialEq, Eq)]
pub struct BigNatPointAdd {
    /// Products
    pub products: Vec<BigNatWithLimbMax>,
    /// Intermediate values
    pub remainders: Vec<BigNatWithLimbMax>, //Vec<BigNatbWithLimbMax>,
    /// Intermediate for modulation
    pub intermediate_mod: Vec<BigNatModWithLimbMax>,
    /// resultant point
    pub res_point: P256Point,
}

impl BigNatPointAdd {
    /// compute the intermediate input for adding two points (they might be the same or different) on the circuit
    pub fn new(point1: P256Point, point2: P256Point, limbwidth: usize, n_limbs: usize, limbs_per_gp: usize, advanced: bool) -> Self {
        let mut products: Vec<BigNatWithLimbMax> = Vec::new();
        let mut remainders: Vec<BigNatWithLimbMax> = Vec::new();
        let mut intermediate_mod: Vec<BigNatModWithLimbMax> = Vec::new();
        let curve: EllipticCurveP256 = EllipticCurveP256::new();
        let pt1: BigNatPoint = BigNatPoint::new(&point1, limbwidth, n_limbs, false);
        let pt2: BigNatPoint = BigNatPoint::new(&point2, limbwidth, n_limbs, false);
        let p_bignat: BigNatWithLimbMax = BigNatWithLimbMax::new(&curve.p, limbwidth, n_limbs, true);
        let curve_a: Integer = (curve.a.clone()+curve.p.clone()) % curve.p.clone();
        let curve_a_bignat: BigNatWithLimbMax = BigNatWithLimbMax::new(&curve_a, limbwidth, n_limbs, true);
        let squ_p: Integer = curve.p.clone() * curve.p.clone();
        let squ_p_bignat: BigNatWithLimbMax = BigNatWithLimbMax::new(&squ_p, limbwidth, 2*n_limbs, true);

        // println!("is point equal {}", point1.is_equal(&point2));
        // Compute m1 and m2
        let double_y: Integer = 2*point1.y.clone();
        let double_y_inv: Integer = double_y.clone().invert(&curve.p).expect("Should be a Integer"); // 1/(2*y1) mod p
        let m2: Integer = ((3*point1.x.clone()*point2.x.clone()+curve.a.clone()+curve.p.clone())*double_y_inv.clone()) % curve.p.clone();
        let m1: Integer = if point1.is_equal(&point2) {
                            // println!("Opps point1 equals point2");
                            m2.clone()
                        } else {
                            let inv_x: Integer = (point1.x.clone() - point2.x.clone()).invert(&curve.p).expect("Should be a Integer");
                            ((point1.y.clone() - point2.y.clone() + 2*curve.p.clone()) * inv_x) % curve.p.clone()
                        };
        // 1.1 Case for different points: compute m = (y1 - y2) * inverse_mod(x1 - x2, curve.p) 
        // <=> check m*(x1+2*p) + y2 == p*(quotient + 2*m) + y1 + m*x2
        let m1_bignat: BigNatWithLimbMax = BigNatWithLimbMax::new(&m1, limbwidth, n_limbs, false);
        remainders.push(m1_bignat.clone());
        let two_p: BigNatWithLimbMax = p_bignat.scalar_mult_nat(&Integer::from(2)); // 2*p
        let x1_plus_2p: BigNatWithLimbMax = pt1.x.create_addition_nat(&two_p); // x1+2*p
        let res_left0: BigNatWithLimbMax = m1_bignat.create_product_nat_for_circ(&x1_plus_2p, &mut products); // m1*(x1+2*p)
        let res_left1: BigNatWithLimbMax = res_left0.create_addition_nat(&pt2.y); // m1*(x1+2*p) + y2
    
        let m_times_x2: BigNatWithLimbMax = m1_bignat.create_product_nat_for_circ(&pt2.x, &mut products); // m1*x2
        let res_right: BigNatWithLimbMax = m_times_x2.create_addition_nat(&pt1.y); // m1*x2 + y1
        let mod_res1: BigNatModWithLimbMax = BigNatModWithLimbMax::new_w_remainder2(&res_left1, &p_bignat, &m1_bignat, &res_right, 258, limbs_per_gp, advanced);
        intermediate_mod.push(mod_res1.clone());

        // 1.2 Case for same point: Compute m2 = (3 * x1 * x1 + curve.a) * inverse_mod(2 * y1, curve.p) 
        // <=> check 2*y*m + 12*p*p = p*(quotient+12p) + 3*x*x + a // quotient bits = 260
        let double_y_bignat: BigNatWithLimbMax = pt1.y.scalar_mult_nat(&Integer::from(2));
        assert!(double_y_bignat.clone().value.unwrap().invert(&curve.p).expect("Should be a Integer") == double_y_inv.clone());
        let m2_bignat: BigNatWithLimbMax = BigNatWithLimbMax::new(&m2, limbwidth, n_limbs, false);
        remainders.push(m2_bignat.clone());
        let double_y_times_m: BigNatWithLimbMax = m2_bignat.create_product_nat_for_circ(&double_y_bignat, &mut products); // m2*(2y)
        let twelve_squ_p: BigNatWithLimbMax = squ_p_bignat.scalar_mult_nat(&Integer::from(12)); // 12*p*p
        let res_left0: BigNatWithLimbMax = double_y_times_m.create_addition_nat(&twelve_squ_p);

        let three_x: BigNatWithLimbMax = pt1.x.scalar_mult_nat(&Integer::from(3)); // 3*x
        let three_x_times_x: BigNatWithLimbMax = three_x.create_product_nat_for_circ(&pt2.x, &mut products); // 3x * x
        let res_right: BigNatWithLimbMax = three_x_times_x.create_addition_nat(&curve_a_bignat); // 3*x*x + a
        let mod_res: BigNatModWithLimbMax = BigNatModWithLimbMax::new_w_remainder2(&res_left0, &p_bignat, &curve_a_bignat, &res_right, 260, limbs_per_gp, advanced);
        intermediate_mod.push(mod_res.clone());

        
        let m_bignat: BigNatWithLimbMax = if point1.is_equal(&point2) { m2_bignat.clone()} else { m1_bignat.clone()};
        let m: Integer = m_bignat.clone().value.unwrap();
        // 2. compute x3 = m * m - x1 - x2 % p
        // <=> check m*m - x1 - x2 == p*quotient + x3 <=> m*m + 4*p == p*(quotient+4) + x3 + x1 + x2
        let squ_m: BigNatWithLimbMax = m_bignat.create_product_nat_for_circ(&m_bignat, &mut products); // m*m
        let four_p: BigNatWithLimbMax = p_bignat.scalar_mult_nat(&Integer::from(4)); // 4*p
        let res_left2: BigNatWithLimbMax = squ_m.create_addition_nat(&four_p); // m*m + 4*p
    
        let x1_plus_x2: BigNatWithLimbMax = pt1.x.create_addition_nat(&pt2.x);
        let x3: Integer = (m.clone() * m.clone() - point1.x.clone() - point2.x.clone() + 4 * curve.p.clone()) % curve.p.clone();
        let x3_bignat: BigNatWithLimbMax = BigNatWithLimbMax::new(&x3, limbwidth, n_limbs, false);
        remainders.push(x3_bignat.clone());
        let res_right2: BigNatWithLimbMax = x1_plus_x2.create_addition_nat(&x3_bignat); // x1 + x2 + x3
        let mod_res2: BigNatModWithLimbMax = BigNatModWithLimbMax::new_w_remainder2(&res_left2, &p_bignat, &x3_bignat, &res_right2, 257, limbs_per_gp, advanced);
        intermediate_mod.push(mod_res2.clone());

        // 3. compute y3 = -y1 + m * (x1 - x3) % p
        // <=> y3 = p*quotient -y1 + m * (x1 - x3) <=> y3 + y1 + m*x3 + 4*p*p = p*(quotient+4*p) + m*x1
        let y3: Integer = (2*curve.p.clone()-point1.y.clone() + m.clone() * (point1.x.clone() - x3.clone() + 2*curve.p.clone())) % curve.p.clone();
        let y3_bignat: BigNatWithLimbMax = BigNatWithLimbMax::new(&y3, limbwidth, n_limbs, false);
        remainders.push(y3_bignat.clone());
        let y1_plus_y3: BigNatWithLimbMax = pt1.y.create_addition_nat(&y3_bignat); // y1+y3
        let m_times_x3: BigNatWithLimbMax = m_bignat.create_product_nat_for_circ(&x3_bignat, &mut products); // m*x3
        let res_left3_0: BigNatWithLimbMax = y1_plus_y3.create_addition_nat(&m_times_x3); // y1+y3+m*x3
        let squ_p: Integer = p_bignat.value.clone().unwrap() * p_bignat.value.clone().unwrap();
        let squ_p_bignat: BigNatWithLimbMax = BigNatWithLimbMax::new(&squ_p, limbwidth, 2*n_limbs, true);
        let four_squ_p: BigNatWithLimbMax = squ_p_bignat.scalar_mult_nat(&Integer::from(4)); // 4*p*p
        let res_left3_1: BigNatWithLimbMax = res_left3_0.create_addition_nat(&four_squ_p); // y1 + y3 + m*x3 + 4*p*p

        let res_right3: BigNatWithLimbMax = m_bignat.create_product_nat_for_circ(&pt1.x, &mut products); // m*x1
        let mod_res3: BigNatModWithLimbMax = BigNatModWithLimbMax::new_w_remainder2(&res_left3_1, &p_bignat, &y3_bignat, &res_right3, 259, limbs_per_gp, advanced);
        intermediate_mod.push(mod_res3.clone());

        let res_point = if point1.empty {point2.clone()} 
                        else if point2.empty {point1.clone()} 
                        else {P256Point { x: x3.clone(),
                                          y: y3.clone(),
                                          empty: false,}
                            };
        assert!(res_point.is_on_curve());
    
        Self {
            products, remainders, intermediate_mod, res_point
        }
    }

    /// compute the intermediate input for adding two points using incomplete formula on the circuit (assuming two points are different); basically the same as Self::new except that it skips the computations related to m2
    // not finish
    pub fn new_incomplete(point1: P256Point, point2: P256Point, limbwidth: usize, n_limbs: usize, limbs_per_gp: usize, advanced: bool) -> Self {
        let mut products: Vec<BigNatWithLimbMax> = Vec::new();
        let mut remainders: Vec<BigNatWithLimbMax> = Vec::new();
        let mut intermediate_mod: Vec<BigNatModWithLimbMax> = Vec::new();
        let curve: EllipticCurveP256 = EllipticCurveP256::new();
        let pt1: BigNatPoint = BigNatPoint::new(&point1, limbwidth, n_limbs, false);
        let pt2: BigNatPoint = BigNatPoint::new(&point2, limbwidth, n_limbs, false);
        let p_bignat: BigNatWithLimbMax = BigNatWithLimbMax::new(&curve.p, limbwidth, n_limbs, true);
        assert!(!point1.is_equal(&point2)); // for debug purpose
        let inv_x: Integer = (point1.x.clone() - point2.x.clone()).invert(&curve.p).expect("Should be a Integer");
        let m1: Integer = ((point1.y.clone() - point2.y.clone() + 2*curve.p.clone()) * inv_x) % curve.p.clone();
        let m1_bignat: BigNatWithLimbMax = BigNatWithLimbMax::new(&m1, limbwidth, n_limbs, false);
        remainders.push(m1_bignat.clone());
        let two_p: BigNatWithLimbMax = p_bignat.scalar_mult_nat(&Integer::from(2)); // 2*p
        let x1_plus_2p: BigNatWithLimbMax = pt1.x.create_addition_nat(&two_p); // x1+2*p
        let res_left0: BigNatWithLimbMax = m1_bignat.create_product_nat_for_circ(&x1_plus_2p, &mut products); // m1*(x1+2*p)
        let res_left1: BigNatWithLimbMax = res_left0.create_addition_nat(&pt2.y); // m1*(x1+2*p) + y2
    
        let m_times_x2: BigNatWithLimbMax = m1_bignat.create_product_nat_for_circ(&pt2.x, &mut products); // m1*x2
        let res_right: BigNatWithLimbMax = m_times_x2.create_addition_nat(&pt1.y); // m1*x2 + y1
        let mod_res1: BigNatModWithLimbMax = BigNatModWithLimbMax::new_w_remainder2(&res_left1, &p_bignat, &m1_bignat, &res_right, 258, limbs_per_gp, advanced);
        intermediate_mod.push(mod_res1.clone());

        let m_bignat: BigNatWithLimbMax = m1_bignat.clone();
        let m: Integer = m1.clone();
        // 2. compute x3 = m * m - x1 - x2 % p
        // <=> check m*m - x1 - x2 == p*quotient + x3 <=> m*m + 4*p == p*(quotient+4) + x3 + x1 + x2
        let squ_m: BigNatWithLimbMax = m_bignat.create_product_nat_for_circ(&m_bignat, &mut products); // m*m
        let four_p: BigNatWithLimbMax = p_bignat.scalar_mult_nat(&Integer::from(4)); // 4*p
        let res_left2: BigNatWithLimbMax = squ_m.create_addition_nat(&four_p); // m*m + 4*p
    
        let x1_plus_x2: BigNatWithLimbMax = pt1.x.create_addition_nat(&pt2.x);
        let x3: Integer = (m.clone() * m.clone() - point1.x.clone() - point2.x.clone() + 4 * curve.p.clone()) % curve.p.clone();
        let x3_bignat: BigNatWithLimbMax = BigNatWithLimbMax::new(&x3, limbwidth, n_limbs, false);
        remainders.push(x3_bignat.clone());
        let res_right2: BigNatWithLimbMax = x1_plus_x2.create_addition_nat(&x3_bignat); // x1 + x2 + x3
        let mod_res2: BigNatModWithLimbMax = BigNatModWithLimbMax::new_w_remainder2(&res_left2, &p_bignat, &x3_bignat, &res_right2, 257, limbs_per_gp, advanced);
        intermediate_mod.push(mod_res2.clone());

        // 3. compute y3 = -y1 + m * (x1 - x3) % p
        // <=> y3 = p*quotient -y1 + m * (x1 - x3) <=> y3 + y1 + m*x3 + 4*p*p = p*(quotient+4*p) + m*x1
        let y3: Integer = (2*curve.p.clone()-point1.y.clone() + m.clone() * (point1.x.clone() - x3.clone() + 2*curve.p.clone())) % curve.p.clone();
        let y3_bignat: BigNatWithLimbMax = BigNatWithLimbMax::new(&y3, limbwidth, n_limbs, false);
        remainders.push(y3_bignat.clone());
        let y1_plus_y3: BigNatWithLimbMax = pt1.y.create_addition_nat(&y3_bignat); // y1+y3
        let m_times_x3: BigNatWithLimbMax = m_bignat.create_product_nat_for_circ(&x3_bignat, &mut products); // m*x3
        let res_left3_0: BigNatWithLimbMax = y1_plus_y3.create_addition_nat(&m_times_x3); // y1+y3+m*x3
        let squ_p: Integer = p_bignat.value.clone().unwrap() * p_bignat.value.clone().unwrap();
        let squ_p_bignat: BigNatWithLimbMax = BigNatWithLimbMax::new(&squ_p, limbwidth, 2*n_limbs, true);
        let four_squ_p: BigNatWithLimbMax = squ_p_bignat.scalar_mult_nat(&Integer::from(4)); // 4*p*p
        let res_left3_1: BigNatWithLimbMax = res_left3_0.create_addition_nat(&four_squ_p); // y1 + y3 + m*x3 + 4*p*p

        let res_right3: BigNatWithLimbMax = m_bignat.create_product_nat_for_circ(&pt1.x, &mut products); // m*x1
        let mod_res3: BigNatModWithLimbMax = BigNatModWithLimbMax::new_w_remainder2(&res_left3_1, &p_bignat, &y3_bignat, &res_right3, 259, limbs_per_gp, advanced);
        intermediate_mod.push(mod_res3.clone());

        let res_point = if point1.empty {point2.clone()} 
                        else if point2.empty {point1.clone()} 
                        else {P256Point { x: x3.clone(),
                                          y: y3.clone(),
                                          empty: false,}
                            };
        assert!(res_point.is_on_curve());
    
        Self {
            products, remainders, intermediate_mod, res_point
        }
    }
    /// Allocate a BigNatPointAdd instance to the circuit
    pub fn plain_alloc(&self, name: &str, append: String, input_map: &mut HashMap<String, Value>) {
        let prepend: String = name.to_owned();
        for (i, product) in self.products.iter().enumerate() {
            product.alloc_from_nat(&format!("{}{}.products.{}", prepend, append, i), input_map);
        }

        for (i, remainder) in self.remainders.iter().enumerate() {
            BigNatbWithLimbMax::alloc_from_bignat(&remainder, &format!("{}{}.remainders.{}", prepend, append, i), input_map);
            // remainder.alloc_from_natb(&format!("{}{}.remainders.{}", prepend, append, i), input_map);
        }

        for (i, ele) in self.intermediate_mod.iter().enumerate() {
            ele.alloc2(format!("{}{}.intermediate_mod.{}", prepend, append, i).as_str(), input_map);
        }
    }

    /// Allocate a BigNatPointAdd instance to the circuit with advanced range check
    pub fn alloc_adv(&self, subtable_bitwidth: usize, name: &str, input_map: &mut HashMap<String, Value>) {
        let prepend: String = if name.is_empty() {name.to_owned()} else {name.to_owned()+"."};

        for (i, product) in self.products.iter().enumerate() {
            product.alloc_from_nat(&format!("{}products.{}", prepend, i), input_map);
        }

        for (i, remainder) in self.remainders.iter().enumerate() {
            // allocate res_init in the struct `BigNatModMult_init`
            remainder.alloc_adv(subtable_bitwidth, &format!("{}intermediate_mod.{}.res_init", prepend, i), input_map);
        }

        for (i, ele) in self.intermediate_mod.iter().enumerate() {
            ele.alloc_adv(subtable_bitwidth, format!("{}intermediate_mod.{}", prepend, i).as_str(), input_map); // allocate v, quotient_init and carry_init
        }
    }

    /// Allocate a BigNatPointAdd instance to the circuit
    pub fn alloc_v2(&self, name: &str, append: String, input_map: &mut HashMap<String, Value>) {
        let prepend: String = if name.is_empty() {name.to_owned()} else {name.to_owned()+"."};
        for (i, product) in self.products.iter().enumerate() {
            product.alloc_from_nat(&format!("{}mm_for_pa{}.products.{}", prepend, append, i), input_map);
        }

        for (i, remainder) in self.remainders.iter().enumerate() {
            BigNatbWithLimbMax::alloc_from_bignat(&remainder, &format!("{}mm_for_pa{}.remainders.{}", prepend, append, i), input_map);
            // remainder.alloc_from_natb(&format!("{}mm_for_pa{}.remainders.{}", prepend, append, i), input_map);
        }

        for (i, ele) in self.intermediate_mod.iter().enumerate() {
            ele.alloc2(format!("{}mm_for_pa{}.intermediate_mod.{}", prepend, append, i).as_str(), input_map);
        }
    }


    /// Allocate a BigNatPointAdd instance to the circuit // only for checking r
    pub fn alloc_for_r(&self, r: Integer, p_minusq_minus1: Integer, name: &str, input_map: &mut HashMap<String, Value>) {
        let prepend: String = if name.is_empty() {name.to_owned()} else {name.to_owned()+"."};
        let carry_r: Integer = Integer::from(0).max(p_minusq_minus1.clone()-r.clone());
        conditional_print!("r < p-q? {}", r.clone() < p_minusq_minus1.clone());
        conditional_print!("carry_r {:?}", carry_r.clone());

        for (i, product) in self.products.iter().enumerate() {
            product.alloc_from_nat(&format!("{}products.{}", prepend, i), input_map);
        }

        for (i, remainder) in self.remainders.iter().enumerate() {
            BigNatbWithLimbMax::alloc_from_bignat(&remainder, &format!("{}remainders.{}", prepend, i), input_map);
        }

        for (i, ele) in self.intermediate_mod.iter().enumerate() {
            ele.alloc2(format!("{}intermediate_mod.{}", prepend, i).as_str(), input_map);
        }

        input_map.insert(format!("{}carry_r", prepend), integer_to_field(&carry_r));

    }

    /// Allocate a BigNatPointAdd instance to the circuit with advanced range checks // only for checking r
    pub fn alloc_for_r_adv(&self, subtable_bitwidth: usize, r: Integer, p_minusq_minus1: Integer, name: &str, input_map: &mut HashMap<String, Value>) {
        let prepend: String = if name.is_empty() {name.to_owned()} else {name.to_owned()+"."};
        let carry_r: Integer = Integer::from(0).max(p_minusq_minus1.clone()-r.clone());
        conditional_print!("r < p-q? {}", r.clone() < p_minusq_minus1.clone());
        conditional_print!("carry_r {:?}", carry_r.clone());

        for (i, product) in self.products.iter().enumerate() {
            product.alloc_from_nat(&format!("{}products.{}", prepend, i), input_map); // no changes
        }

        for (i, remainder) in self.remainders.iter().enumerate().take(2) {
            remainder.alloc_adv(subtable_bitwidth, &format!("{}intermediate_mod.{}.res_init", prepend, i), input_map);
        }

        for (i, ele) in self.intermediate_mod.iter().enumerate().take(2) {
            ele.alloc_adv(subtable_bitwidth, format!("{}intermediate_mod.{}", prepend, i).as_str(), input_map); // allocate v, quotient_init and carry_init
        }

        self.intermediate_mod[2].alloc_adv(subtable_bitwidth, format!("{}last_intermediate", prepend).as_str(), input_map); 

        let n_bits: usize = 127; // number of bits required by p-q-1
        BigNatInit::alloc_one_integer(&carry_r, n_bits, subtable_bitwidth, &format!("{}carry_r", prepend), input_map);
    }
}

/// Representations of intermediate values for verifying scalar multiply over P256 curve
#[derive(Clone, PartialEq, Eq)]
pub struct BigNatScalarMult {
    /// Intermediate for point addition
    pub point_add: Vec<Vec<BigNatPointAdd>>,
    /// Intermediate for point double
    pub point_double: Vec<Vec<BigNatPointDouble>>,
    /// resultant point
    pub res_point: P256Point,
}

impl BigNatScalarMult {
    /// Create a new instance for BigNatScalarMult
    pub fn new(scalar: BigNatbWithLimbMax, point: P256Point, limbwidth: usize, n_limbs: usize, limbs_per_gp: usize, advanced: bool) -> Self {
        let mut point_add: Vec<Vec<BigNatPointAdd>> = Vec::new();
        let mut point_double: Vec<Vec<BigNatPointDouble>> = Vec::new();
        let mut initial: bool = true;
        let mut result: P256Point = point.clone();
        let mut addend: P256Point = point.clone();


        for (_i, vec) in scalar.limb_values.iter().enumerate() {
            let mut point_add_inner: Vec<BigNatPointAdd> = Vec::new();
            let mut point_double_inner: Vec<BigNatPointDouble> = Vec::new();
            for (_j, b) in vec.iter().rev().enumerate() {
                let check_point_add: BigNatPointAdd = BigNatPointAdd::new(result.clone(), addend.clone(), limbwidth, n_limbs, limbs_per_gp, advanced);
                point_add_inner.push(check_point_add.clone());
                if *b {
                    if initial {
                        result = addend.clone();
                        initial = false;
                    } else {
                        result = check_point_add.res_point.clone();
                    }
                }

                let check_point_double: BigNatPointDouble = BigNatPointDouble::new_v2(addend.clone(), limbwidth, n_limbs, limbs_per_gp, advanced);
                point_double_inner.push(check_point_double.clone());
                addend = check_point_double.res_point.clone();
            }
            point_add.push(point_add_inner);
            point_double.push(point_double_inner);
        }
        Self { 
            point_add: point_add, 
            point_double: point_double,
            res_point: result.clone(),
        }
    }


    /// Allocate a BigNatScalarMult instance to the circuit
    pub fn alloc(&self, name: &str, input_map: &mut HashMap<String, Value>) {
        for (i, vec) in self.point_add.iter().enumerate() {
            for (j, ele) in vec.iter().enumerate() {
                let append: String = format!(".{}.{}", i, j);
                ele.alloc_v2(name, append, input_map);
            }
        }
        for (i, vec) in self.point_double.iter().enumerate() {
            for (j, ele) in vec.iter().enumerate() {
                let append: String = format!(".{}.{}", i, j);
                ele.alloc_v3(name, append, input_map);
            }
        }
    }

    /// Allocate a BigNatScalarMult instance to the circuit with advanced range checks
    pub fn alloc_adv(&self, subtable_bitwidth: usize, name: &str, input_map: &mut HashMap<String, Value>) {
        for (i, vec) in self.point_add.iter().enumerate() {
            for (j, ele) in vec.iter().enumerate() {
                ele.alloc_adv(subtable_bitwidth, &format!("{}.mm_for_pa.{}.{}", name, i, j), input_map);
            }
        }
        for (i, vec) in self.point_double.iter().enumerate() {
            for (j, ele) in vec.iter().enumerate() {
                ele.alloc_adv(subtable_bitwidth, &format!("{}.mm_for_pd.{}.{}", name, i, j), input_map);
            }
        }
    }
}

/// Representations of intermediate values for verifying scalar multiply over P256 curve (with window method)
#[derive(Clone, PartialEq, Eq)]
pub struct BigNatScalarMultWindow {
    /// Intermediate for point addition
    pub point_add: Vec<BigNatPointAdd>,
    /// Intermediate for point double
    pub point_double: Vec<BigNatPointDouble>,
    /// resultant point
    pub res_point: P256Point,
}

impl BigNatScalarMultWindow {
    fn compute_base_power(value: P256Point, window_size: usize) -> Vec<P256Point> { // compute [value, ..., value^{(1<<k)-1}] // note: do not include the infinity point in this function
        let mut base_powers: Vec<P256Point> = vec![value.create_point_at_infinity(), value.clone()];
        for _ in 2..(1<<window_size) {
            let next_push: P256Point = P256Point::point_add(base_powers.last().cloned(), Some(value.clone()));
            base_powers.push(next_push.clone());
        }    
        base_powers
    }

    /// Create a new instance for BigNatScalarMultWindow
    pub fn new(scalar: BigNatbWithLimbMax, point: P256Point, limbwidth: usize, n_limbs: usize, limbs_per_gp: usize, window_size: usize) -> Self {
        // initialization
        let mut point_add: Vec<BigNatPointAdd> = Vec::new();
        let mut point_double: Vec<BigNatPointDouble> = Vec::new();
        let mut result: P256Point = point.clone();

        // step 1: split scalar into chunks 
        let scalar_bits: Vec<bool> = integer_to_bool_vec(&scalar.value.unwrap(), 256);
        let chunked_vec = scalar_bits.chunks(window_size);

        // step 2: Apply the window method
        let mut cur_window_size: usize = window_size;
        let base_powers: Vec<P256Point> = Self::compute_base_power(point.clone(), window_size);
        for (i, chunk) in chunked_vec.clone().enumerate() {
            let chunk_val: usize = bool_vec_to_usize(&chunk); // should be a usize instead
            if i == 0 { 
                result = base_powers[chunk_val].clone();
                continue;
            } else if i == chunked_vec.len() - 1 {
                cur_window_size = (limbwidth*n_limbs)%window_size;
            };
            let advanced: bool = false;

            for _ in 0..cur_window_size {
                let check_point_double: BigNatPointDouble = BigNatPointDouble::new_v2(result.clone(), limbwidth, n_limbs, limbs_per_gp, advanced);
                point_double.push(check_point_double.clone());
                result = check_point_double.res_point.clone();
            }
            let check_point_add: BigNatPointAdd = BigNatPointAdd::new(result.clone(), base_powers[chunk_val].clone(), limbwidth, n_limbs, limbs_per_gp, advanced);
            point_add.push(check_point_add.clone());
            result = check_point_add.res_point.clone();
        }

        Self { 
            point_add: point_add, 
            point_double: point_double,
            res_point: result.clone(),
        }
    }

    /// Allocate a BigNatScalarMultWindow instance to the circuit
    pub fn alloc(&self, name: &str, input_map: &mut HashMap<String, Value>) {
        for (i, ele) in self.point_add.iter().enumerate() {
            let append: String = format!(".{}", i);
            ele.alloc_v2(name, append, input_map);
        }
        for (i, ele) in self.point_double.iter().enumerate() {
            let append: String = format!(".{}", i);
            ele.alloc_v3(name, append, input_map);
        }        
    }
}

/// Representations of intermediate values for verifying scalar multiply over P256 curve (with cached window method)
#[derive(Clone, PartialEq, Eq)]
pub struct BigNatScalarMultCachedWindow {
    /// Intermediate for point addition
    pub point_add: Vec<BigNatPointAdd>,
    /// resultant point
    pub res_point: P256Point,
}

impl BigNatScalarMultCachedWindow {
    fn compute_base_power(value: P256Point, limbwidth: usize, n_limbs: usize, stride: usize) -> Vec<Vec<P256Point>> { // compute [value, ..., value^{(1<<k)-1}] // note: do not include the infinity point in this function
        let mut base_powers: Vec<Vec<P256Point>> = Vec::new(); // Gpow[i][j] = j * (2 ** (i * stride)) * G for j = 1, ..., 2**stride - 1
        let n_vec: usize = (n_limbs*limbwidth+stride-1)/stride; // number of vectors of base powers
        conditional_print!("n_vec {}", n_vec);
        for i in 0..n_vec {
            let initial_point: P256Point = if i == n_vec-1 {value.clone()} 
                                        else {value.clone().scalar_mult(Integer::from(1)<<(n_limbs*limbwidth-(i+1)*stride))}; // (2 ** (256 - (i+1) * stride)) * value
            let mut base_powers_inner: Vec<P256Point> = vec![initial_point.create_point_at_infinity(), initial_point.clone()];
            let cur_stride: usize = if i == n_vec-1 {
                                        if (n_limbs*limbwidth)%stride == 0 {stride} else {(n_limbs*limbwidth)%stride}
                                    } else {stride};            
            for _ in 2..(1<<cur_stride) {
                let next_push: P256Point = P256Point::point_add(base_powers_inner.last().cloned(), Some(initial_point.clone()));
                base_powers_inner.push(next_push.clone());
            }
            base_powers.push(base_powers_inner);
        }
        base_powers
    }
    /// Create a new instance for BigNatScalarMultCachedWindow
    pub fn new(scalar: Integer, point: P256Point, limbwidth: usize, n_limbs: usize, limbs_per_gp: usize, window_size: usize, advanced: bool) -> Self {
        // initialization
        let mut point_add: Vec<BigNatPointAdd> = Vec::new();
        let mut result: P256Point = point.clone();

        // step 1: split scalar into chunks
        let scalar_bits: Vec<bool> = integer_to_bool_vec(&scalar, 256);
        let chunked_vec = scalar_bits.chunks(window_size);

        // step 2: Apply the cached window method
        let base_powers: Vec<Vec<P256Point>> = Self::compute_base_power(point.clone(), limbwidth, n_limbs, window_size);
        for (i, chunk) in chunked_vec.clone().enumerate() {
            let chunk_val: usize = bool_vec_to_usize(&chunk); // should be a usize instead
            if i == 0 { 
                result = base_powers[0][chunk_val].clone();
                continue;
            } 
            let check_point_add: BigNatPointAdd = BigNatPointAdd::new(result.clone(), base_powers[i][chunk_val].clone(), limbwidth, n_limbs, limbs_per_gp, advanced);
            point_add.push(check_point_add.clone());
            result = check_point_add.res_point.clone();
        }
        Self { 
            point_add: point_add, 
            res_point: result.clone(),
        }
    }

    /// Create a new instance for (incomplete) BigNatScalarMultCachedWindow
    pub fn new_incomplete(scalar: Integer, point: P256Point, limbwidth: usize, n_limbs: usize, limbs_per_gp: usize, window_size: usize, advanced: bool) -> Self {
        // initialization
        let mut point_add: Vec<BigNatPointAdd> = Vec::new();
        let mut result: P256Point = point.clone();

        // step 1: split scalar into chunks
        let scalar_bits: Vec<bool> = integer_to_bool_vec(&scalar, 256);
        let chunked_vec = scalar_bits.chunks(window_size);

        // step 2: Apply the cached window method
        let base_powers: Vec<Vec<P256Point>> = Self::compute_base_power(point.clone(), limbwidth, n_limbs, window_size);
        for (i, chunk) in chunked_vec.clone().enumerate() {
            let chunk_val: usize = bool_vec_to_usize(&chunk); // should be a usize instead
            if i == 0 { 
                result = base_powers[0][chunk_val].clone();
                continue;
            } 
            let check_point_add: BigNatPointAdd = BigNatPointAdd::new_incomplete(result.clone(), base_powers[i][chunk_val].clone(), limbwidth, n_limbs, limbs_per_gp, advanced);
            point_add.push(check_point_add.clone());
            result = check_point_add.res_point.clone();
        }
        Self { 
            point_add: point_add, 
            res_point: result.clone(),
        }
    }

    /// Allocate a BigNatScalarMultCachedWindow instance to the circuit
    pub fn alloc(&self, name: &str, input_map: &mut HashMap<String, Value>) {
        for (i, ele) in self.point_add.iter().enumerate() {
            let append: String = format!(".{}", i);
            ele.plain_alloc(name, append, input_map);
        }      
    }
    /// Allocate a BigNatScalarMultCachedWindow instance to the circuit with advanced range check
    pub fn alloc_adv(&self, subtable_bitwidth: usize, name: &str, input_map: &mut HashMap<String, Value>) {
        for (i, ele) in self.point_add.iter().enumerate() {
            ele.alloc_adv(subtable_bitwidth, &format!("{}.{}", name, i), input_map); // *** to do
        }      
    }
}

/// Enum for EC point type
pub enum BigNatPointType {
    /// corresponding to ECPointv2 in Zokrates
    ECPointv2,
    /// corresponding to ECPointplain in Zokrates
    ECPointplain,
}

impl BigNatPointType {
    /// Write the lookup table to the zokrate file
    pub fn write_table_to_zokrates_file(&self, n_limbs: usize, base_powers_bignat: Vec<Vec<BigNatPoint>>, last_base_powers_bignat: Vec<BigNatPoint>, file_path: &str) {
        let base_powers_str: String = match self {
            Self::ECPointv2 => double_vec_point_to_str(base_powers_bignat.clone()),
            Self::ECPointplain => double_vec_point_to_plain_str(base_powers_bignat.clone()),
        };
        let last_base_powers_str: String = match self {
            Self::ECPointv2 => vec_point_to_str(last_base_powers_bignat.clone()),
            Self::ECPointplain => vec_point_to_plain_str(last_base_powers_bignat.clone()),
        };

        let mut write_str: Vec<String> = Vec::new();
        match self {
            Self::ECPointv2 => {
                write_str.push(format!("const BasePowers<{}, {}, {}, {}> Gpow = BasePowers {{", n_limbs, base_powers_bignat.len(), base_powers_bignat[0].len(), last_base_powers_bignat.len()).to_string());
            }
            Self::ECPointplain => {
                write_str.push(format!("const BasePowers_plain<{}, {}, {}, {}> Gpow = BasePowers_plain {{", n_limbs, base_powers_bignat.len(), base_powers_bignat[0].len(), last_base_powers_bignat.len()).to_string());
            }
        }
        write_str.push(format!("    base_powers: {},", base_powers_str).to_string());
        write_str.push(format!("    last_base_powers: {},", last_base_powers_str).to_string());
        write_str.push("}".to_string());

        let is_auxconst_contained_in_file: bool = is_values_defined_in_file(&write_str[0], file_path);
        if !is_auxconst_contained_in_file {
            if confirm_append("Do you want to append this line? (y/n)").unwrap() == "y" {
                conditional_print!("File path: {}", file_path);
                let _result = write_to_file(write_str, file_path);
            } else {
                conditional_print!("Base powers were not appended because you entered n.");
            }
        } else {
            conditional_print!("Base powers were not appended since they have been contained in file {}.", file_path);
        }


        conditional_print!("length of base powers = {}", base_powers_bignat.len());
    }
    /// Write the lookup table to the zokrate file; to test
    pub fn write_fptable_to_zokrates_file(&self, base_powers_bignat: &Vec<Vec<P256Point>>, last_base_powers_bignat: &Vec<P256Point>, file_path: &str) {
        let base_powers_str: String = double_vec_p256point_to_str(base_powers_bignat);
        let last_base_powers_str: String = vec_p256point_to_str(last_base_powers_bignat);

        let mut write_str: Vec<String> = vec![format!("const BasePowers_Fp<{}, {}, {}> Gpow = BasePowers_Fp {{", base_powers_bignat.len(), base_powers_bignat[0].len(), last_base_powers_bignat.len()).to_string()];
        write_str.push(format!("    base_powers: {},", base_powers_str).to_string());
        write_str.push(format!("    last_base_powers: {},", last_base_powers_str).to_string());
        write_str.push("}".to_string());

        let is_auxconst_contained_in_file: bool = is_values_defined_in_file(&write_str[0], file_path);
        if !is_auxconst_contained_in_file {
            if confirm_append("Do you want to append this line? (y/n)").unwrap() == "y" {
                conditional_print!("File path: {}", file_path);
                let _result = write_to_file(write_str, file_path);
            } else {
                conditional_print!("Base powers were not appended because you entered n.");
            }
        } else {
            conditional_print!("Base powers were not appended since they have been contained in file {}.", file_path);
        }

        conditional_print!("length of base powers = {}", base_powers_bignat.len());
    }
    /// Compute the table for cached window method
    pub fn compute_table_for_cached_window_method(&self, value: P256Point, n_limbs: usize, limb_width: usize, stride: usize, file_path: &str) { // compute [value, ..., value^{(1<<k)-1}] // note: do not include the infinity point in this function
        let mut base_powers: Vec<Vec<P256Point>> = Vec::new();
        // Gpow[i][j] = j * (2 ** (i * stride)) * G for j = 1, ..., 2**stride - 1
        // question: what is Gpow[i][0]
        let n_vec: usize = (n_limbs*limb_width+stride-1)/stride; // number of vectors of base powers
        conditional_print!("n_vec {}", n_vec);
        for i in 0..n_vec {
            let initial_point: P256Point = if i == n_vec-1 {value.clone()} 
                                        else {value.clone().scalar_mult(Integer::from(1)<<(n_limbs*limb_width-(i+1)*stride))}; // (2 ** (256 - (i+1) * stride)) * value
            let mut base_powers_inner: Vec<P256Point> = vec![initial_point.create_point_at_infinity(), initial_point.clone()];
            let cur_stride: usize = if i == n_vec-1 {
                                        if (n_limbs*limb_width)%stride == 0 {stride} else {(n_limbs*limb_width)%stride}
                                    } else {stride};
            for _ in 2..(1<<cur_stride) {
                let next_push: P256Point = P256Point::point_add(base_powers_inner.last().cloned(), Some(initial_point.clone()));
                base_powers_inner.push(next_push.clone());
            }
            base_powers.push(base_powers_inner);
        }

        let mut base_powers_bignat: Vec<Vec<BigNatPoint>> = Vec::new();
        for vec in base_powers.iter().take(base_powers.len()-1) {
            let mut base_powers_bignat_inner: Vec<BigNatPoint> = Vec::new();
            for point in vec.iter() {
                base_powers_bignat_inner.push(BigNatPoint::new(&point, limb_width, n_limbs, true));
            }
            base_powers_bignat.push(base_powers_bignat_inner);
        }

        let mut last_base_powers_bignat: Vec<BigNatPoint> = Vec::new();
        for point in base_powers.last().unwrap().iter() {
            last_base_powers_bignat.push(BigNatPoint::new(&point, limb_width, n_limbs, true));
        }
        self.write_table_to_zokrates_file(n_limbs, base_powers_bignat, last_base_powers_bignat, file_path)
    }
    /// Compute the table for cached window method; Different from above: we dont include entry for j = 0
    pub fn compute_table_for_cached_window_method_v2(&self, value: P256Point, n_limbs: usize, limb_width: usize, stride: usize, file_path: &str) { // compute [value, ..., value^{(1<<k)-1}] // note: do not include the infinity point in this function
        let mut base_powers: Vec<Vec<P256Point>> = Vec::new();
        // Gpow[i][j-1] = j * (2 ** (i * stride)) * G for j = 1, ..., 2**stride - 1
        let n_vec: usize = (n_limbs*limb_width+stride-1)/stride; // number of vectors of base powers
        conditional_print!("n_vec {}", n_vec);
        for i in 0..n_vec {
            let initial_point: P256Point = if i == n_vec-1 {value.clone()} 
                                        else {value.clone().scalar_mult(Integer::from(1)<<(n_limbs*limb_width-(i+1)*stride))}; // (2 ** (256 - (i+1) * stride)) * value
            let mut base_powers_inner: Vec<P256Point> = vec![initial_point.clone()]; //vec![initial_point.create_point_at_infinity(), initial_point.clone()];
            let cur_stride: usize = if i == n_vec-1 {
                                        if (n_limbs*limb_width)%stride == 0 {stride} else {(n_limbs*limb_width)%stride}
                                    } else {stride};
            for _ in 2..(1<<cur_stride) {
                let next_push: P256Point = P256Point::point_add(base_powers_inner.last().cloned(), Some(initial_point.clone()));
                base_powers_inner.push(next_push.clone());
            }
            base_powers.push(base_powers_inner);
        }

        let mut base_powers_bignat: Vec<Vec<BigNatPoint>> = Vec::new();
        for vec in base_powers.iter().take(base_powers.len()-1) {
            let mut base_powers_bignat_inner: Vec<BigNatPoint> = Vec::new();
            for point in vec.iter() {
                base_powers_bignat_inner.push(BigNatPoint::new(&point, limb_width, n_limbs, true));
            }
            base_powers_bignat.push(base_powers_bignat_inner);
        }

        let mut last_base_powers_bignat: Vec<BigNatPoint> = Vec::new();
        for point in base_powers.last().unwrap().iter() {
            last_base_powers_bignat.push(BigNatPoint::new(&point, limb_width, n_limbs, true));
        }
        self.write_table_to_zokrates_file(n_limbs, base_powers_bignat, last_base_powers_bignat, file_path)
    }
    /// Compute the table for cached window method with right-field arithmetic for Fp; to do 
    pub fn compute_table_for_cached_window_method_fp(&self, value: P256Point, n_limbs: usize, limb_width: usize, stride: usize, file_path: &str) { // compute [value, ..., value^{(1<<k)-1}] // note: do not include the infinity point in this function
        let mut base_powers: Vec<Vec<P256Point>> = Vec::new();
        // Gpow[i][j] = j * (2 ** (i * stride)) * G for j = 1, ..., 2**stride - 1
        // question: what is Gpow[i][0]
        let n_vec: usize = (n_limbs*limb_width+stride-1)/stride; // number of vectors of base powers
        conditional_print!("n_vec {}", n_vec);

        for i in 0..n_vec {
            let initial_point: P256Point = if i == n_vec-1 {value.clone()} 
                                        else {value.clone().scalar_mult(Integer::from(1)<<(n_limbs*limb_width-(i+1)*stride))}; // (2 ** (256 - (i+1) * stride)) * value
            let mut base_powers_inner: Vec<P256Point> = vec![initial_point.create_point_at_infinity(), initial_point.clone()];
            let cur_stride: usize = if i == n_vec-1 {
                                        if (n_limbs*limb_width)%stride == 0 {stride} else {(n_limbs*limb_width)%stride}
                                    } else {stride};
            for _ in 2..(1<<cur_stride) {
                let next_push: P256Point = P256Point::point_add(base_powers_inner.last().cloned(), Some(initial_point.clone()));
                base_powers_inner.push(next_push.clone());
            }
            base_powers.push(base_powers_inner);
        }

        let last_idx = base_powers.len()-1;
        self.write_fptable_to_zokrates_file(&base_powers[..last_idx].to_vec(), &base_powers[last_idx], file_path)
    }
}
