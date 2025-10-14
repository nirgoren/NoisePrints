//! This module includes the structures for very big natural numbers

use fxhash::FxHashMap as HashMap;
use crate::ir::term::{Value};
use std::cmp::max;
use rug::Integer;

use std::assert;

use crate::convert::{integer_to_bool_vec, bool_vec_to_integer, integer_to_field};
use crate::allocate::{map_bool_double_vec, map_bool_double_vec_to_single_vec};

/// Split a very large integer `value` into #n_limbs limbs where each limb has `limbwidth` bits
pub fn create_limb_values(value: &Integer, limbwidth: usize, n_limbs: usize) -> Vec<Integer> {
    let target_base = Integer::from(1) << limbwidth as u32;
    let mut remainder = value.clone();
    let mut limb_values = Vec::new();
    while remainder > 0 {
        let limb = remainder.clone() % &target_base;
        limb_values.push(limb);
        remainder = remainder/target_base.clone();
    }
    if limb_values.clone().len() < n_limbs {
        let padded_n_limbs = n_limbs - limb_values.clone().len();
        for _i in 0..padded_n_limbs {
            limb_values.push(Integer::from(0));
        }
    }
    if limb_values.clone().len() != n_limbs {
        println!("Problem in create_limb_values: limb_values.clone().len() = {}; n_limbs = {}", limb_values.clone().len(), n_limbs);
    }
    assert!(limb_values.clone().len() == n_limbs);

    limb_values
}

#[derive(Clone, PartialEq, Eq)]
/// Params for describing a very large natural number
pub struct BigNatParams {
    /// Number of limbs
    pub n_limbs: usize,
    /// Maximum value of each limb
    pub max_word: Integer,
    /// Limbwidth of each limb
    pub limb_width: usize,
}


impl BigNatParams {
    /// Create a new BigNatParams instance
    pub fn new(limb_width: usize, n_limbs: usize) -> Self {
        let mut max_word = Integer::from(1) << limb_width;
        max_word -= 1;
        BigNatParams {
            max_word,
            n_limbs,
            limb_width,
        }
    }
}

/// A representation of a large natural number (a member of {0, 1, 2, ... })
#[derive(Clone, PartialEq, Eq)]
pub struct BigNat {
    /// The witness values for each limb (filled at witness-time)
    pub limb_values: Option<Vec<Integer>>,
    /// The value of the whole number (filled at witness-time)
    pub value: Option<Integer>,
    /// Parameters
    pub params: BigNatParams,
}

impl BigNat {
    /// Create a new BigNat instance
    pub fn new(value: &Integer, limb_width: usize, n_limbs: usize) -> Self {
        let limb_values: Vec<Integer> = create_limb_values(value, limb_width, n_limbs);
        BigNat {
            limb_values: Some(limb_values.clone()),
            value: Some(value.clone()),
            params: BigNatParams::new(limb_width, n_limbs),
        }
    }
    
    /// Create a BigNat instance from a BigNatb instance
    pub fn from_bignatb(big_natb: &BigNatb) -> Self {
        let value: Integer = big_natb.value.clone().unwrap();
        BigNat::new(&value, big_natb.params.limb_width, big_natb.params.n_limbs)
    }

    /// Allocate a BigNat instance to the circuit
    pub fn alloc_from_nat(&self, name: &str, input_map: &mut HashMap<String, Value>) {
        if let Some(values) = self.limb_values.as_ref() {
            for (i, value) in values.iter().enumerate() {
                input_map.insert(format!("{}.limbs.{}", name, i), integer_to_field(value));
            }
        }
    }

    /// Allocate a BigNat instance to the circuit
    pub fn alloc_from_nat_with_range(&self, start: usize, end: usize, name: &str, input_map: &mut HashMap<String, Value>) {
        if let Some(values) = self.limb_values.as_ref() {
            let mut idx = 0;
            for i in start..=end {
                if let Some(value) = values.get(i) {
                    input_map.insert(format!("{}.limbs.{}", name, idx), integer_to_field(value));
                    idx += 1;
                }
            }
        }
    }

    /// Start from the most significant limb, locate the first limb where self and other differ
    pub fn locate_first_differ_limbs(&self, other: &BigNat) -> usize {
        if let Some(self_values) = self.limb_values.as_ref() {
            if let Some(other_values) = other.limb_values.as_ref() {
                // Ensure both slices have the same length
                if self_values.len() != other_values.len() {
                    panic!("Number slices must have the same length.");
                }

                let n_limbs: usize = self_values.len();
                for i in 0..n_limbs {
                    // Compare the elements
                    let idx: usize = n_limbs-1-i;
                    if self_values[idx] < other_values[idx] {
                        return idx;
                    } else if self_values[idx] > other_values[idx] {
                        panic!("self should be smaller than other");
                    }
                }
            }
        }
        panic!("self should not equal other");
    }

    /// Compute the polynomial multiplication of self and other represented by BigNat
    pub fn create_product_nat(&self, other: &BigNat) -> BigNat{
        let max_word: Integer = Integer::from(self.params.n_limbs.min(other.params.n_limbs)) * self.params.max_word.clone() * other.params.max_word.clone();
        let params = BigNatParams {n_limbs: self.params.n_limbs+other.params.n_limbs, max_word: max_word.clone(), limb_width: self.params.limb_width};
        let mut limb_values: Vec<Integer> = vec![Integer::default(); params.n_limbs];
        let value: Option<Integer> = self.value.clone().zip(other.value.clone()).map(|(x, y)| x * y); // use map() to perform multiplication on contained Integer values
        if let Some(self_values) = self.limb_values.as_ref() {
            if let Some(other_values) = other.limb_values.as_ref() {
                for (i, self_val) in self_values.iter().enumerate() {
                    for (j, other_val) in other_values.iter().enumerate() {
                        limb_values[i+j] += self_val * other_val;
                    }
                }
            }
        }

        BigNat {
            limb_values: Some(limb_values),
            value: value,
            params: params,
        }

    }

    /// Multiply by scalar for each limbs of self
    pub fn scalar_mult_nat(&self, scalar: &Integer) -> BigNat{
        let mut limb_values: Vec<Integer> = self.limb_values.as_ref().unwrap().to_vec();
        for value in limb_values.iter_mut() {
            *value *= scalar.clone();
        }        
        let value: Option<Integer> = self.value.clone().zip(Some(scalar.clone())).map(|(x, y)| x * y);
        BigNat {
            limb_values: Some(limb_values),
            value: value,
            params: self.params.clone(),
        }        
    }

    /// Compute the addition of polynomials `self` and `other`
    pub fn create_addition_nat(&self, other: &BigNat) -> BigNat{
        let max_word: Integer = self.params.max_word.clone() + other.params.max_word.clone();
        let params = BigNatParams {n_limbs: self.params.n_limbs.max(other.params.n_limbs), max_word: max_word.clone(), limb_width: self.params.limb_width};
        let bigger_nat = if self.params.n_limbs >= other.params.n_limbs { self.clone() } else { other.clone()};
        let smaller_nat = if self.params.n_limbs >= other.params.n_limbs { other.clone() } else { self.clone()};
        let mut limb_values: Vec<Integer> = bigger_nat.limb_values.as_ref().unwrap().to_vec();
        let value: Option<Integer> = self.value.clone().zip(other.value.clone()).map(|(x, y)| x + y); // use map() to perform multiplication on contained Integer values
        if let Some(values) = smaller_nat.limb_values.as_ref() {
            for (i, val) in values.iter().enumerate() {
                limb_values[i] += val;
            }
        }

        BigNat {
            limb_values: Some(limb_values),
            value: value,
            params: params,
        }
    }

    /// Compute carry for verifying modular multiplication and represent it in BigNat
    pub fn create_carry(&self, other: &BigNat) -> Vec<Vec<bool>> {
        let mut carry: Vec<Vec<bool>> = Vec::new();
        let max_word: Integer = max(self.params.max_word.clone(), other.params.max_word.clone());
        println!("gp_max_word {:?}", max_word);
        let carry_bits = ((max_word.to_f64() * 2.0).log2() - self.params.limb_width as f64).ceil() as usize;
        let n_limbs: usize = self.params.n_limbs.min(other.params.n_limbs);
        let left_values: Vec<Integer> = self.limb_values.as_ref().unwrap().to_vec();
        let right_values: Vec<Integer> = other.limb_values.as_ref().unwrap().to_vec();
        let mut carry_in: Integer = Integer::from(0);
        for i in 0..n_limbs {
            let carry_value: Integer = (left_values[i].clone() + carry_in.clone() + max_word.clone() - right_values[i].clone()) >> self.params.limb_width;
            carry.push(integer_to_bool_vec(&carry_value, carry_bits));
            if i == n_limbs - 1 {
                let max_word2: Integer = Integer::from_str_radix("5070602399750772729068233162815", 10).unwrap();
                let _carry_value2: Integer = (left_values[i].clone() + carry_in.clone() + max_word2.clone() - right_values[i].clone()) >> self.params.limb_width;
            }
            carry_in = carry_value;
        }

        

        carry
    }

    /// Compute carry for verifying modular multiplication and represent it in BigNat
    pub fn create_carry_for_grouping(&self, other: &BigNat) -> Vec<Vec<bool>> {
        let mut carry: Vec<Vec<bool>> = Vec::new();
        let max_word: Integer = max(self.params.max_word.clone(), other.params.max_word.clone());
        println!("gp_max_word {:?}", max_word);
        let carry_bits = ((max_word.to_f64() * 2.0).log2() - self.params.limb_width as f64).ceil() as usize;
        let n_limbs: usize = self.params.n_limbs.min(other.params.n_limbs);
        let left_values: Vec<Integer> = self.limb_values.as_ref().unwrap().to_vec();
        let right_values: Vec<Integer> = other.limb_values.as_ref().unwrap().to_vec();
        let mut carry_in: Integer = Integer::from(0);
        for i in 0..n_limbs {
            let carry_value: Integer = (left_values[i].clone() + carry_in.clone() + max_word.clone() - right_values[i].clone()) >> self.params.limb_width;
            carry.push(integer_to_bool_vec(&carry_value, carry_bits));
            if i == n_limbs - 1 {
                let max_word2: Integer = Integer::from_str_radix("5070602399750772729068233162815", 10).unwrap();
                let _carry_value2: Integer = (left_values[i].clone() + carry_in.clone() + max_word2.clone() - right_values[i].clone()) >> self.params.limb_width;
            }
            carry_in = carry_value;
        }
        carry
    }

    /// Compute carry for verifying modular multiplication and represent it in BigNat; here we set an upper bound to each limb
    pub fn create_postgp_carry(&self, other: &BigNat, gp_maxword_vec: Vec<Integer>) -> Vec<Vec<bool>> {
        let mut carry: Vec<Vec<bool>> = Vec::new();

        let left_values: Vec<Integer> = self.limb_values.as_ref().unwrap().to_vec();
        let right_values: Vec<Integer> = other.limb_values.as_ref().unwrap().to_vec();
        let mut carry_in: Integer = Integer::from(0);
        for (i, gp_maxword) in gp_maxword_vec.iter().enumerate().take(gp_maxword_vec.len() - 1) {
            let carry_bits = ((gp_maxword.to_f64() * 2.0).log2() - self.params.limb_width as f64).ceil() as usize;
            let carry_value: Integer = (left_values[i].clone() + carry_in.clone() + gp_maxword.clone() - right_values[i].clone()) >> self.params.limb_width;
            carry.push(integer_to_bool_vec(&carry_value, carry_bits));
            carry_in = carry_value;
        }
        carry
    }

    /// Maximum bits of a number represented by a BigNat instance
    pub fn n_bits(&self) -> usize {
        assert!(self.params.n_limbs > 0);
        let sig_bits = self.params.max_word.significant_bits() as usize;
        self.params.limb_width * (self.params.n_limbs - 1) as usize
            + sig_bits
    }

    #[allow(unused)]
    fn value(&self) -> Option<&Integer> {
        self.value.as_ref()
    }

    /// gp_limbs = number of limbs per group
    fn group_limbs(&self, limbs_per_gp: usize) -> Self {

        let mut limb_values = Vec::new();
        let mut shift = Integer::from(1);
        let base: Integer = Integer::from(1) << self.params.limb_width;
        if let Some(values) = self.limb_values.as_ref() {
            let mut current_val = Integer::from(0);
            shift = Integer::from(1);
            for (i, value) in values.iter().enumerate() {
                current_val = current_val.clone() + value.clone() * shift.clone();
                if (i+1) % limbs_per_gp == 0 || i ==  values.len()-1 {
                    shift = Integer::from(1);
                    limb_values.push(current_val.clone());
                    current_val = Integer::from(0);
                } else {
                    shift = shift.clone() * base.clone();
                }
            }
        }

        let mut gp_maxword: Integer = Integer::from(0);

        for _ in 0..limbs_per_gp {
            gp_maxword = gp_maxword.clone() + self.params.max_word.clone() * shift.clone();
            shift = shift.clone() * base.clone();
        }

        let bp = BigNatParams {
                    n_limbs: limb_values.len(),
                    max_word: gp_maxword.clone(),
                    limb_width: self.params.limb_width * limbs_per_gp,
                };

        BigNat {
            limb_values: Some(limb_values.clone()),
            value: self.value.clone(),
            params: bp,
        }
    }
    
}

/// Representations of intermediate values for verifying modular multiplicaton (a * b = quotient * modul + remainder)
pub struct BigNatModMult {
    /// a
    pub a: BigNat,
    /// b
    pub b: BigNat,
    /// modul
    pub modul: BigNat,
    /// The polynomial multiplication of a and b
    pub z: BigNat,
    /// The polynomial multiplication of quotient and modul
    pub v: BigNat,
    /// Boolean representation of quotient
    pub quotientb: BigNatb,
    /// Remainder
    pub remainder: BigNat,
    /// Boolean representation of remainder
    pub remainderb: BigNatb,
    /// Boolean double array used to check modular multiplicato
    pub carry: Vec<Vec<bool>>,
}

impl BigNatModMult {
    /// Create a new BigNatModMult instance
    pub fn new(a: &BigNat, b: &BigNat, modul: &BigNat) -> BigNatModMult{
        let n_limbs = modul.params.n_limbs;
        assert!(a.params.limb_width == b.params.limb_width);
        let product = a.create_product_nat(b); //left hand side
        let quotient_val = product.value.clone().zip(modul.value.clone()).map(|(z, q)| z / q).unwrap();
        let limbwidth = a.params.limb_width;
        let quotient = BigNat::new(&quotient_val, limbwidth, n_limbs); 
        let quotientb = BigNatb::from_bignat(&quotient);
        let remainder_val = product.value.clone().zip(modul.value.clone()).map(|(z, q)| z % q).unwrap();
        let remainder = BigNat::new(&remainder_val, limbwidth, n_limbs);
        let remainderb = BigNatb::from_bignat(&remainder);
        let v = quotient.create_product_nat(modul);
        let right = v.create_addition_nat(&remainder);

        let carry: Vec<Vec<bool>> = product.create_carry(&right);
        BigNatModMult {
            a: a.clone(),
            b: b.clone(),
            modul: modul.clone(),
            z: product,
            v: v,
            quotientb: quotientb,
            remainder: remainder,
            remainderb: remainderb,
            carry: carry,
        }    
    }
    /// Create a new BigNatModMult instance
    pub fn new_with_grouping(a: &BigNat, b: &BigNat, modul: &BigNat, limbs_per_gp: usize) -> BigNatModMult{
        let n_limbs = modul.params.n_limbs;
        assert!(a.params.limb_width == b.params.limb_width);
        let product = a.create_product_nat(b); //left hand side
        let quotient_val = product.value.clone().zip(modul.value.clone()).map(|(z, q)| z / q).unwrap();
        let limbwidth = a.params.limb_width;
        let quotient = BigNat::new(&quotient_val, limbwidth, n_limbs); 
        let quotientb = BigNatb::from_bignat(&quotient);
        let remainder_val = product.value.clone().zip(modul.value.clone()).map(|(z, q)| z % q).unwrap();
        let remainder = BigNat::new(&remainder_val, limbwidth, n_limbs);
        let remainderb = BigNatb::from_bignat(&remainder);
        let v = quotient.create_product_nat(modul);
        let right = v.create_addition_nat(&remainder);
        let group_right = right.group_limbs(limbs_per_gp);
        let group_left = product.group_limbs(limbs_per_gp);

    
        let carry: Vec<Vec<bool>> = group_left.create_carry(&group_right);

        let bp = BigNatModMult {
            a: a.clone(),
            b: b.clone(),
            modul: modul.clone(),
            z: product,
            v: v,
            quotientb: quotientb,
            remainder: remainder,
            remainderb: remainderb,
            carry: carry,
        };

        bp
    }

    /// Create a new BigNatModMult instance for a% modul
    pub fn new_mod(a: &BigNat, modul: &BigNat) -> BigNatModMult{
        let n_limbs = modul.params.n_limbs;
        let quotient_val = a.value.clone().zip(modul.value.clone()).map(|(z, q)| z / q).unwrap();
        let limbwidth = a.params.limb_width;
        let quotient = BigNat::new(&quotient_val, limbwidth, n_limbs); 
        let quotientb = BigNatb::from_bignat(&quotient);
        let remainder_val = a.value.clone().zip(modul.value.clone()).map(|(z, q)| z % q).unwrap();
        let remainder = BigNat::new(&remainder_val, limbwidth, n_limbs);
        let remainderb = BigNatb::from_bignat(&remainder);
        let v = quotient.create_product_nat(modul);
        let right = v.create_addition_nat(&remainder);
        let carry: Vec<Vec<bool>> = a.create_carry(&right);
        BigNatModMult {
            a: a.clone(),
            b: BigNat::new(&Integer::from(1), limbwidth, n_limbs),
            modul: modul.clone(),
            z: a.clone(),
            v: v,
            quotientb: quotientb,
            remainder: remainder,
            remainderb: remainderb,
            carry: carry,
        } 
    }

    /// compute the post-group maxword for each limb
    pub fn compute_gpmaxword(n_limbs: usize, limb_width: usize, limbs_per_group: usize) -> Vec<Integer> {
        let base: Integer = Integer::from(1) << limb_width;
        let init_maxword: Integer = base.clone() - Integer::from(1);
        let mut maxword_vec: Vec<Integer> = Vec::new();

        for i in 0..(2*n_limbs-1) {
            let num_cross_term: usize;
            if i < n_limbs {
                num_cross_term = i+1;
            }
            else {
                num_cross_term = 2*n_limbs-i-1;
            }
            let maxword: Integer = Integer::from(num_cross_term) * init_maxword.clone() * init_maxword.clone() + init_maxword.clone();
            maxword_vec.push(maxword.clone());
        }

        let mut multiple_base_vec: Vec<Integer> = Vec::new();
        multiple_base_vec.push(Integer::from(1));
        for i in 1..limbs_per_group{
            multiple_base_vec.push(multiple_base_vec[i-1].clone()*base.clone());
        }

        let mut gp_maxword_vec: Vec<Integer> = Vec::new();
        let mut cur_gpmaxword = Integer::from(0);
        for (i, maxword) in maxword_vec.iter().enumerate() {
            cur_gpmaxword = cur_gpmaxword + maxword.clone() * multiple_base_vec[i%limbs_per_group].clone();
            if (i+1) % limbs_per_group == 0 || i == maxword_vec.len()-1 {
                gp_maxword_vec.push(cur_gpmaxword.clone());
                cur_gpmaxword = Integer::from(0);
            }
        }

        gp_maxword_vec
    }
    /// create auxiliary constants based on n_limbs and limb_width, where n_limbs is the double of the original n_limbs
    pub fn compute_aux_const(n_limbs: usize, limb_width: usize, max_word: &Integer) -> Vec<Integer> {

        let target_base = Integer::from(1) << limb_width;
        let mut aux_const: Vec<Integer> = Vec::new();
        let mut accumulated_extra: Integer = Integer::from(0);
        for _i in 0..n_limbs {
            accumulated_extra += max_word.clone();
            aux_const.push(accumulated_extra.clone() % target_base.clone());
            accumulated_extra >>= limb_width;
        }
        aux_const.push(accumulated_extra);
        aux_const
    }

    /// create auxiliary constants based on n_limbs and limb_width, where n_limbs is the double of the original n_limbs
    pub fn compute_aux_const2(n_limbs: usize, limb_width: usize, max_word: &Integer, max_word2: &Integer) -> Vec<Integer> {

        let target_base = Integer::from(1) << limb_width;
        let mut aux_const: Vec<Integer> = Vec::new();
        let mut accumulated_extra: Integer = Integer::from(0);
        for i in 0..n_limbs {
            if i < n_limbs - 1 {
                accumulated_extra += max_word.clone();
            }
            else {
                accumulated_extra += max_word2.clone();
            }
            aux_const.push(accumulated_extra.clone() % target_base.clone());
            accumulated_extra >>= limb_width;
        }
        aux_const.push(accumulated_extra);
        aux_const
    }

    /// verify z == v + remainder in circuit
    pub fn verify_equal_when_carried(&self) -> bool {
        println!("z {:?}", self.z.limb_values);
        let z_right: BigNat = self.v.create_addition_nat(&self.remainder);
        println!("z_right {:?}", z_right.limb_values);

        let n_limbs: usize = self.z.params.n_limbs; // assume z.params.n_limbs <= v.params.n_limbs
        let limb_width: usize = z_right.params.limb_width;
        let max_word: Integer = max(self.z.params.max_word.clone(), z_right.params.max_word.clone());
        println!("max word z max_word {:?}", self.z.params.max_word.clone());
        println!("max word z_right max_word {:?}", z_right.params.max_word.clone());
        println!("max word = {:?}", max_word);
        let target_base = Integer::from(1) << self.z.params.limb_width as u32;
        println!("target base = {:?}", target_base);
        let mut carry_in: Integer = Integer::from(0);
        let aux_const: Vec<Integer> = Self::compute_aux_const(n_limbs, limb_width, &max_word);
        println!("aux const {:?}", aux_const);

        let tmp_max_word: Vec<Integer> = vec![Integer::from(2), Integer::from_str_radix("232113757366008801543585787", 10).unwrap()];
        let left_values: Vec<Integer> = self.z.limb_values.as_ref().unwrap().to_vec();
        let right_values: Vec<Integer> = z_right.limb_values.as_ref().unwrap().to_vec();        
        for i in 0..n_limbs-1 {
            let carry_cur: Integer = carry_in.clone();
            carry_in = bool_vec_to_integer(&self.carry[i]);
            println!("carry_in[{}] {:?}", i, carry_cur);
            let left: Integer = left_values[i].clone()+carry_cur.clone()+(tmp_max_word[1].clone()-carry_in.clone())*target_base.clone()-right_values[i].clone();
            let right: Integer = aux_const[i].clone()-tmp_max_word[0].clone();
            println!("left {} {:?}" ,i, left);
            println!("right {} {:?}" ,i, right);
            println!("left assert {} {:?}", i, left_values[i].clone()+carry_cur.clone()-carry_in.clone()*target_base.clone()+max_word.clone()-right_values[i].clone());
            println!("right assert {} {:?}", i, aux_const[i].clone());

            assert!(left_values[i].clone()+carry_cur.clone()-carry_in.clone()*target_base.clone()+max_word.clone()-right_values[i].clone() == aux_const[i].clone());
        }
        //check last limb of carry equal last limb of aux_const
        // assert!(left_values[n_limbs].clone()+carry_in.clone()-aux_const[n_limbs+1].clone()*target_base.clone()+max_word.clone()-right_values[n_limbs].clone() == aux_const[n_limbs].clone());

    // assert(left.limbs[ZG]+carry_in+( - aux_const[Z]) * target_base -right.limbs[ZG] == aux_const[ZG])
        true
    }

    /// verify (grouped) z == (grouped) (v + remainder) in circuit
    pub fn verify_equal_when_carried_with_grouping(&self, group_left: &BigNat, group_right: &BigNat) -> bool {

        let gp_n_limbs: usize = group_left.params.n_limbs; // assume group_left.params.n_limbs <= group_right.params.n_limbs
        println!("gp_n_limbs {}", gp_n_limbs);
        let gp_limb_width: usize = group_right.params.limb_width;
        let gp_max_word: Integer = max(group_left.params.max_word.clone(), group_right.params.max_word.clone());
        println!("gp_max word = {:?}", gp_max_word);
        let target_base = Integer::from(1) << gp_limb_width as u32;
        println!("target base = {:?}", target_base);
        let mut carry_in: Integer = Integer::from(0);
        let aux_const: Vec<Integer> = Self::compute_aux_const(gp_n_limbs, gp_limb_width, &gp_max_word);
        println!("len {} aux const {:?}", aux_const.len(), aux_const);

        let tmp_max_word: Vec<Integer> = vec![Integer::from_str_radix("6277101735386680763835789423207666416102355444189156606015", 10).unwrap(), Integer::from_str_radix("274877906880", 10).unwrap()];
        let left_values: Vec<Integer> = group_left.limb_values.as_ref().unwrap().to_vec();
        println!("gp_left {:?}", left_values);
        assert!(left_values[0] == Integer::from_str_radix("53517696743745302063462426018289839866587323232503667780692373773361", 10).unwrap());
        let right_values: Vec<Integer> = group_right.limb_values.as_ref().unwrap().to_vec(); 
        println!("gp_right {:?}", right_values);       
        for i in 0..gp_n_limbs-1 {
            let carry_cur: Integer = carry_in.clone();
            carry_in = bool_vec_to_integer(&self.carry[i]);
            println!("carry_in[{}] {:?}", i, carry_cur);
            let left: Integer = left_values[i].clone()+carry_cur.clone()+(tmp_max_word[1].clone()-carry_in.clone())*target_base.clone()-right_values[i].clone();
            let right: Integer = aux_const[i].clone()-tmp_max_word[0].clone();
            println!("left {} {:?}" ,i, left);
            println!("right {} {:?}" ,i, right);
            println!("left assert {} {:?}", i, left_values[i].clone()+carry_cur.clone()-carry_in.clone()*target_base.clone()+gp_max_word.clone()-right_values[i].clone());
            println!("right assert {} {:?}", i, aux_const[i].clone());

            assert!(left_values[i].clone()+carry_cur.clone()-carry_in.clone()*target_base.clone()+gp_max_word.clone()-right_values[i].clone() == aux_const[i].clone());
        }
        //check last limb of carry equal last limb of aux_const
        let left: Integer = left_values[gp_n_limbs-1].clone()+carry_in.clone()-aux_const[gp_n_limbs].clone()*target_base.clone()+gp_max_word.clone()-right_values[gp_n_limbs-1].clone();
        println!("left {} {:?}" ,gp_n_limbs-1, left);
        assert!(left_values[gp_n_limbs-1].clone()+carry_in.clone()-aux_const[gp_n_limbs].clone()*target_base.clone()+gp_max_word.clone()-right_values[gp_n_limbs-1].clone() == aux_const[gp_n_limbs-1].clone());
        true
    }

    /// verify (grouped) z == (grouped) (v + remainder) in circuit
    pub fn verify_equal_when_carried_with_grouping2(&self, group_left: &BigNat, group_right: &BigNat) -> bool {

        let gp_n_limbs: usize = group_left.params.n_limbs; // assume group_left.params.n_limbs <= group_right.params.n_limbs
        println!("gp_n_limbs {}", gp_n_limbs);
        let gp_limb_width: usize = group_right.params.limb_width;
        let gp_max_word: Integer = max(group_left.params.max_word.clone(), group_right.params.max_word.clone());
        println!("gp_max word = {:?}", gp_max_word);
        let target_base = Integer::from(1) << gp_limb_width as u32;
        println!("target base = {:?}", target_base);
        // original size of carry = NG_ - 1; current size of carry = NG_ -1 -1
        let mut carry_in: Integer = Integer::from(0);
        let gp_max_word2: Integer = Integer::from_str_radix("5070602399750772729068233162815", 10).unwrap();
        let aux_const: Vec<Integer> = Self::compute_aux_const2(gp_n_limbs, gp_limb_width, &gp_max_word, &gp_max_word2);
        println!("len {} aux const {:?}", aux_const.len(), aux_const);

        let tmp_max_word: Vec<Integer> = vec![Integer::from_str_radix("6277101735386680763835789423207666416102355444189156606015", 10).unwrap(), Integer::from_str_radix("274877906880", 10).unwrap()];
        let left_values: Vec<Integer> = group_left.limb_values.as_ref().unwrap().to_vec();
        assert!(left_values[0] == Integer::from_str_radix("53517696743745302063462426018289839866587323232503667780692373773361", 10).unwrap());
        let right_values: Vec<Integer> = group_right.limb_values.as_ref().unwrap().to_vec(); 
        for i in 0..gp_n_limbs-2 {
            let carry_cur: Integer = carry_in.clone();
            carry_in = bool_vec_to_integer(&self.carry[i]);
            println!("carry_in[{}] {:?}", i, carry_cur);
            let left: Integer = left_values[i].clone()+carry_cur.clone()+(tmp_max_word[1].clone()-carry_in.clone())*target_base.clone()-right_values[i].clone();
            let right: Integer = aux_const[i].clone()-tmp_max_word[0].clone();
            println!("left {} {:?}" ,i, left);
            println!("right {} {:?}" ,i, right);
            println!("left assert {} {:?}", i, left_values[i].clone()+carry_cur.clone()-carry_in.clone()*target_base.clone()+gp_max_word.clone()-right_values[i].clone());
            println!("right assert {} {:?}", i, aux_const[i].clone());

            assert!(left_values[i].clone()+carry_cur.clone()-carry_in.clone()*target_base.clone()+gp_max_word.clone()-right_values[i].clone() == aux_const[i].clone());
        }

        assert!(left_values[gp_n_limbs-2].clone()+carry_in.clone()+gp_max_word.clone()-right_values[gp_n_limbs-2].clone() == aux_const[gp_n_limbs-2].clone());

        true
    }
}


/// A boolean representation of a large natural number (a member of {0, 1, 2, ... })
#[derive(Clone, PartialEq, Eq)]
pub struct BigNatb {
    /// A double boolean array where each element is a limb represented in boolean form
    pub limb_values: Vec<Vec<bool>>,
    /// The value of the whole number (filled at witness-time)
    pub value: Option<Integer>,
    /// Paramaters of BigNatb
    pub params: BigNatParams,
}

impl BigNatb {
    /// Create a BigNatb instance
    pub fn new(value: &Integer, limb_width: usize, n_limbs: usize) -> Self {
        let bignat_res: BigNat = BigNat::new(value, limb_width, n_limbs);
        Self::from_bignat(&bignat_res)
    }

    /// Create a BigNatb instance from a BigNat instance
    pub fn from_bignat(big_nat: &BigNat) -> Self {
        let mut limb_values: Vec<Vec<bool>> = Vec::new();
        if let Some(values) = big_nat.limb_values.as_ref() {
            for (_i, val) in values.iter().enumerate() {
                limb_values.push(integer_to_bool_vec(val, big_nat.params.limb_width));
            }
        }
        BigNatb {
            limb_values: limb_values,
            value: big_nat.value.clone(),
            params: big_nat.params.clone(),
        }
    }
    
    /// Allocate a BigNatb instance to the circuit
    pub fn alloc_from_natb(&self, name: &str, input_map: &mut HashMap<String, Value>) {
        map_bool_double_vec(&self.limb_values, &format!("{}.limbs", name), input_map);
    }

    /// Allocate a BigNatb instance to the circuit
    pub fn alloc_from_integer(value: &Integer, limb_width: usize, n_limbs: usize, name: &str, input_map: &mut HashMap<String, Value>) {
        let bignat_res: BigNat = BigNat::new(value, limb_width, n_limbs);
        let bignatb_res: BigNatb = Self::from_bignat(&bignat_res);        
        map_bool_double_vec(&bignatb_res.limb_values, &format!("{}.limbs", name), input_map);
    }
}

/// Representations of intermediate value for verifying modular multiplicaton (a * b = quotient * modul + remainder)
#[derive(Clone, PartialEq, Eq)]
pub struct BigNatInterExpon { // called BigNatModMult in big_nat.zok
    /// The polynomial multiplication of a and b
    pub z: BigNat,
    /// The polynomial multiplication of quotient and modul
    pub v: BigNat,
    /// Boolean representation of quotient
    pub quotientb: BigNatb,
    /// Boolean double array used to check modular multiplicato
    pub carry: Vec<Vec<bool>>,
}

impl BigNatInterExpon {
    /// Create a new BigNatInterExpon instance
    pub fn new() -> Self {
        BigNatInterExpon {
            z: BigNat::new(&Integer::from(0), 121, 34),
            v: BigNat::new(&Integer::from(0), 121, 34),
            quotientb: BigNatb::new(&Integer::from(0), 121, 34),
            carry: Vec::new(),
        }        
    }

    /// Create a new BigNatInterExpon instance based on a BigNatModMult instance
    pub fn from_bignatmodmult(mm: &BigNatModMult) -> Self {
        BigNatInterExpon {
            z: mm.z.clone(),
            v: mm.v.clone(),
            quotientb: mm.quotientb.clone(),
            carry: mm.carry.clone(),
        }
    }

    /// Allocate a BigNatInterExpon instance in the circuit
    pub fn alloc_from_natinterexpon(&self, name: &str, input_map: &mut HashMap<String, Value>) {
        self.z.alloc_from_nat(format!("{}.z", name).as_str(), input_map);
        self.v.alloc_from_nat(format!("{}.v", name).as_str(), input_map);
        self.quotientb.alloc_from_natb(format!("{}.quotientb", name).as_str(), input_map);
        map_bool_double_vec(&self.carry, &format!("{}.carry", name), input_map);
    }

    /// Allocate a BigNatInterExpon instance in the circuit (We allow maxword for different limb is different)
    pub fn alloc_from_natinterexpon2(&self, name: &str, input_map: &mut HashMap<String, Value>) {
        self.z.alloc_from_nat(format!("{}.z", name).as_str(), input_map);
        self.v.alloc_from_nat(format!("{}.v", name).as_str(), input_map);
        self.quotientb.alloc_from_natb(format!("{}.quotientb", name).as_str(), input_map);
        map_bool_double_vec_to_single_vec(&self.carry, &format!("{}.carry", name), input_map);
    }
}

/// Representations of intermediate values for verifying modular exponentiation
pub struct BigNatExpon {
    /// Intermediate values
    pub mm: Vec<BigNatInterExpon>, //[BigNatInterExpon; 17],
    /// Original a and results of each modular multiplication
    pub res: Vec<BigNatb>, //[BigNatb; 18],
}

impl BigNatExpon {
    /// Create a new BigNatExpon instance for a^e mod modul where e = 2^16 + 1
    pub fn new(a: &BigNat, modul: &BigNat) -> Self {
        let mut mm = Vec::with_capacity(17);
        let mut res = Vec::with_capacity(18);
        res.push(BigNatb::from_bignat(&a));
        let mut cur_x: BigNat = a.clone();

        for _ in 0..16 { // 0, 1, ..., 15
            let intermediate = BigNatModMult::new(&cur_x, &cur_x, &modul);
            mm.push(BigNatInterExpon::from_bignatmodmult(&intermediate));
            res.push(intermediate.remainderb);
            cur_x = intermediate.remainder;
        }

        let finalval = BigNatModMult::new(&a, &cur_x, &modul);
        mm.push(BigNatInterExpon::from_bignatmodmult(&finalval));
        res.push(finalval.remainderb);

        BigNatExpon {
            mm,
            res,
        }    
    }

    /// Create a new BigNatExpon instance for a^e mod modul where e = 2^16 + 1
    pub fn from_integer(a: &Integer, modul: &Integer, limbwidth: usize, n_limbs: usize) -> Self {
        let a_bignat: BigNat = BigNat::new(&a, limbwidth, n_limbs);
        let modul_bignat: BigNat = BigNat::new(&modul, limbwidth, n_limbs);
        BigNatExpon::new(&a_bignat, &modul_bignat)
    }
        
    /// Create a new BigNatExpon instance for a^e mod modul where e = 2^16 + 1
    pub fn new_with_grouping(a: &BigNat, modul: &BigNat, limbs_per_gp: usize) -> Self {
        let mut mm = Vec::with_capacity(17);
        let mut res = Vec::with_capacity(18);
        res.push(BigNatb::from_bignat(&a));
        let mut cur_x: BigNat = a.clone();

        for _ in 0..16 { // 0, 1, ..., 15
            let intermediate = BigNatModMult::new_with_grouping(&cur_x, &cur_x, &modul, limbs_per_gp);
            mm.push(BigNatInterExpon::from_bignatmodmult(&intermediate));
            res.push(intermediate.remainderb);
            cur_x = intermediate.remainder;
        }

        let finalval = BigNatModMult::new_with_grouping(&a, &cur_x, &modul, limbs_per_gp);
        mm.push(BigNatInterExpon::from_bignatmodmult(&finalval));
        res.push(finalval.remainderb);

        BigNatExpon {
            mm,
            res,
        }    
    }


    /// Create a new BigNatExpon instance for a^e mod modul where e = 2^16 + 1
    pub fn from_integer_with_grouping(a: &Integer, modul: &Integer, limbwidth: usize, n_limbs: usize, limbs_per_gp: usize) -> Self {
        let a_bignat: BigNat = BigNat::new(&a, limbwidth, n_limbs);
        let modul_bignat: BigNat = BigNat::new(&modul, limbwidth, n_limbs);
        BigNatExpon::new_with_grouping(&a_bignat, &modul_bignat, limbs_per_gp)
    }

}

/// Representations of intermediate values for verifying modular multiplicaton (a * b = quotient * modul + remainder)
pub struct BigNatModMultCirc {
    /// The polynomial multiplication of a and b
    pub z: BigNat,
    /// The polynomial multiplication of quotient and modul
    pub v: BigNat,
    /// Boolean representation of quotient
    pub quotientb: BigNatb,
    /// Boolean representation of remainder
    pub remainderb: BigNatb,
    /// Boolean double array used to check modular multiplicato
    pub carry: Vec<Vec<bool>>,
}

impl BigNatModMultCirc {
    /// Create a new BigNatModMultCirc instance based on a BigNatModMult instance
    pub fn from_bignatmodmult(mm: &BigNatModMult) -> Self {
        BigNatModMultCirc {
            z: mm.z.clone(),
            v: mm.v.clone(),
            quotientb: mm.quotientb.clone(),
            remainderb: mm.remainderb.clone(),
            carry: mm.carry.clone(),
        }
    }
    /// Allocate a BigNatModMultCirc instance in the circuit
    pub fn alloc_from_natmodmult(&self, name: &str, input_map: &mut HashMap<String, Value>) {
        self.z.alloc_from_nat(format!("{}.z", name).as_str(), input_map);
        self.v.alloc_from_nat(format!("{}.v", name).as_str(), input_map);
        self.quotientb.alloc_from_natb(format!("{}.quotientb", name).as_str(), input_map);
        self.remainderb.alloc_from_natb(format!("{}.res", name).as_str(), input_map);
        map_bool_double_vec(&self.carry, &format!("{}.carry", name), input_map);
    }
    /// Allocate a BigNatMod instance in the circuit
    pub fn alloc_bignatmod_from_natmodmult(&self, name: &str, input_map: &mut HashMap<String, Value>) {
        self.v.alloc_from_nat(format!("{}.v", name).as_str(), input_map);
        self.quotientb.alloc_from_natb(format!("{}.quotientb", name).as_str(), input_map);
        self.remainderb.alloc_from_natb(format!("{}.res", name).as_str(), input_map);
        map_bool_double_vec(&self.carry, &format!("{}.carry", name), input_map);
    }
}