//! Group operations for right-field arithmetic
use rug::Integer;
use super::ecdsa::{P256Point, EllipticCurveP256};
use std::sync::Arc;
use fxhash::FxHashMap as HashMap;
use crate::ir::term::{Value};
use crate::right_field_arithmetic::alloc::map_field;
use core::ops::{Sub, Add};
use core::cmp::PartialEq;

use crate::convert::bool_to_value;
use crate::bignat::bignatwithlimbmax::{BigNatWithLimbMax, BigNatbWithLimbMax, BigNatModMultWithLimbMax};
use crate::right_field_arithmetic::alloc::map_field_double_vec;
/// allocate z, v, quotientb and carry
pub fn alloc_prover_input_for_single_modmultiply(a: &BigNatWithLimbMax, b: &BigNatWithLimbMax, modul: &BigNatWithLimbMax, quotient_bits: usize, limbs_per_gp: usize, default_mod: &Arc<Integer>, name: &str, input_map: &mut HashMap::<String, Value>) {
    let mm: BigNatModMultWithLimbMax = BigNatModMultWithLimbMax::new2(&a, &b, &modul, quotient_bits, limbs_per_gp, false);
    mm.alloc_w_custom_mod(default_mod, name, input_map)
}

/// Compute verifier inputs for proof of possesion of ECDSA signatures; to do
pub fn inner_verifier_input_for_ecdsa(issuer_key: &P256Point, default_mod: &Arc<Integer>, name: &str, input_map: &mut HashMap::<String, Value>) {
    let prepend: String = if name.is_empty() {name.to_owned()} else {name.to_owned()+"."};
    issuer_key.alloc_fp(default_mod, &format!("{}issuerkey", prepend), input_map);
    input_map.insert("return".to_string(), bool_to_value(true));
}

impl P256Point {
    /// doubling a point and output the intermediate value m
    pub fn point_double_w_m(&mut self, curve: &EllipticCurveP256) -> Integer {
        let double_y: Integer = Integer::from(2) * &self.y;
        let double_y_inv: Integer = double_y.invert(&curve.p).expect("Should be a Integer");
        let m: Integer = ((Integer::from(3) * &self.x * &self.x + &curve.a + &curve.p) * &double_y_inv) % &curve.p;
        let x3: Integer = (&m * &m + (&curve.p - Integer::from(2)) * &self.x) % &curve.p;
        self.y = (m.clone() * (self.x.clone() - x3.clone() + curve.p.clone()) - self.y.clone() + curve.p.clone()) % &curve.p; // ((&m * &(self.x.sub(&x3)).add(&curve.p)).sub(&self.y) + &curve.p) % &curve.p; 
        self.x = x3.clone();
        assert!(self.y.clone() >= 0);
        assert!(self.x.clone() >= 0);
        m
    }
}
/// Representations of intermediate values for verifying point addition over P256 curve
#[derive(Clone, PartialEq, Eq)]
pub struct PointAddXFpInit {
    /// m1
    pub m1: Integer,
    /// m2
    pub m2: Integer,
    /// carry_r
    pub carry_r: Integer,
}

impl PointAddXFpInit {
    /// Compute all possible m for point addition
    pub fn compute_m(left: &P256Point, right: &P256Point, curve: &EllipticCurveP256) -> [Integer; 2] {
        let double_y: Integer = Integer::from(2) * &left.y;
        let double_y_inv: Integer = double_y.invert(&curve.p).expect("Should be a Integer");
        // m2 is the case that left == right
        let m2: Integer = ((Integer::from(3) * &left.x * &right.x + &curve.a + &curve.p) * &double_y_inv) % &curve.p;
        let m1: Integer = if left.is_equal(&right) {
                                m2.clone()
                            }
                            else { // in the case that left != right
                                let inv_x: Integer = (left.x.clone().sub(&right.x)).invert(&curve.p)
                                                        .expect("Should be a Integer");
                                ((left.y.clone() - right.y.clone() + 2*curve.p.clone()) * inv_x) % &curve.p
                            };
        [m1, m2]
    }
    /// Create a new instance of PointAddXFpInit
    pub fn new(r: &Integer, r_x: &Integer, left: &P256Point, right: &P256Point, curve: &EllipticCurveP256) -> Self {
        let sum_r_q: Integer = r.add(&curve.q).into();
        let carry_r: Integer = if &sum_r_q == r_x {
                                    (&curve.p_minusq_minus1-r).into()
                                } else {
                                    Integer::from(0)
                                };
        let m_list: [Integer; 2] = Self::compute_m(left, right, curve);
        Self {
            m1: m_list[0].clone(),
            m2: m_list[1].clone(),
            carry_r: carry_r
        }
    }

    /// Allocate a PointAddXFpInit instance to the circuit
    pub fn alloc(&self, modulus: &Arc<Integer>, name: &str, input_map: &mut HashMap<String, Value>) {
        let prepend: String = if name.is_empty() {name.to_owned()} else {name.to_owned()+"."};
        map_field(&self.m1, modulus, &format!("{}m1", prepend), input_map);
        map_field(&self.m2, modulus, &format!("{}m2", prepend), input_map);
        map_field(&self.carry_r, modulus, &format!("{}carry_r", prepend), input_map);
    }
}


/// Representations of intermediate values for verifying scalar multiplication over P256 curve
#[derive(Clone, PartialEq, Eq)]
pub struct ScalarMult {
    /// mm_for_double
    pub mm_for_double: Vec<Vec<Integer>>,
}

impl ScalarMult {
    /// Create a new ScalarMult instance; refer to L1255 of src/ecdsa/ecdsa.rs // ** to do
    pub fn new(scalar: &BigNatbWithLimbMax, point: &P256Point, curve: &EllipticCurveP256) -> Self {
        let mut mm_for_double: Vec<Vec<Integer>> = Vec::new();
        let mut addend: P256Point = point.clone();

        for vec in scalar.limb_values.iter() {
            let mut inner_mm_for_double: Vec<Integer> = Vec::new();
            for _bit in vec.iter().rev() {
                let m: Integer = addend.point_double_w_m(curve);
                inner_mm_for_double.push(m);
            }
            mm_for_double.push(inner_mm_for_double);
        }

        Self {
            mm_for_double
        }
    }

    /// Allocate ScalarMult instance to the circuit
    pub fn alloc_w_modulus(&self, modulus: &Arc<Integer>, name: &str, input_map: &mut HashMap<String, Value>) {
        map_field_double_vec(&self.mm_for_double, modulus, &format!("{}.mm_for_double", name), input_map);
    }

    /// Allocate a vector of ScalarMult instance to the circuit
    pub fn alloc_vec_w_modulus(input: &Vec<Self>, modulus: &Arc<Integer>, name: &str, input_map: &mut HashMap<String, Value>) {
        for (i, ele) in input.iter().enumerate() {
            ele.alloc_w_modulus(modulus, &format!("{}.{}", name, i), input_map)
        }
    }
}
