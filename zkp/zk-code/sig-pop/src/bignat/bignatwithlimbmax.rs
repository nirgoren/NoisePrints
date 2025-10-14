//! This module includes the structures for very big natural numbers and we allow different limbs have different max values

use fxhash::FxHashMap as HashMap;
use crate::ir::term::{Value};
use rug::Integer;
use std::assert;
use super::bignat::{create_limb_values};
use crate::convert::{integer_to_bool_vec, integer_to_field, bool_vec_to_integer};
use crate::allocate::{map_bool_arr, map_bool_double_vec, map_bool_double_vec_to_single_vec, map_field_double_vec};
use super::bignat_adv::{CarryType, BigNatCarryInit, BigNatInit};
#[cfg(feature = "spartan")]
use crate::right_field_arithmetic::alloc;
#[allow(unused_imports)]
use std::sync::Arc;

use lazy_static::lazy_static;

use crate::conditional_print;

lazy_static! {
    /// H(G)^{-1}
    pub static ref FIELD_MOD: Integer = Integer::from_str_radix("52435875175126190479447740508185965837690552500527637822603658699938581184513", 10).unwrap();
}
#[derive(Clone, PartialEq, Eq, Debug)]
/// Params for describing a very large natural number
pub struct BigNatParamsWithLimbMax {
    /// Number of limbs
    pub n_limbs: usize,
    /// Maximum value of each limb
    pub max_values: Vec<Integer>,
    /// Limbwidth of each limb
    pub limb_width: usize,
}


impl BigNatParamsWithLimbMax {
    /// Create a new BigNatParams instance
    pub fn new(limb_width: usize, n_limbs: usize, value: Option<Integer>) -> Self {
        let max_values: Vec<Integer> = match value {
            Some(value) => {
                create_limb_values(&value, limb_width, n_limbs)
            }
            None => {
                let max_value: Integer = (Integer::from(1) << limb_width) - 1;
                vec![max_value.clone(); n_limbs]
            }
        };

        Self {
            n_limbs,
            max_values,
            limb_width,
        }
    }

}

/// A representation of a large natural number (a member of {0, 1, 2, ... })
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BigNatWithLimbMax {
    /// The witness values for each limb (filled at witness-time)
    pub limb_values: Option<Vec<Integer>>,
    /// The value of the whole number (filled at witness-time)
    pub value: Option<Integer>,
    /// Parameters
    pub params: BigNatParamsWithLimbMax,
}

impl BigNatWithLimbMax {
    /// Create a new BigNat instance
    pub fn new(value: &Integer, limb_width: usize, n_limbs: usize, constant: bool) -> Self {
        assert!(value.clone() >= 0);
        let limb_values: Vec<Integer> = create_limb_values(value, limb_width, n_limbs);
        let value_input_to_params: Option<Integer> = if constant {Some(value.clone())} else {None};

        BigNatWithLimbMax {
            limb_values: Some(limb_values.clone()),
            value: Some(value.clone()),
            params: BigNatParamsWithLimbMax::new(limb_width, n_limbs, value_input_to_params),
        }
    }
    /// Create a new BigNat instance with an upper bound
    pub fn new_with_upper_bound(value: &Integer, limb_width: usize, n_limbs: usize, upper_bound: Integer) -> Self {
        assert!(value.clone() >= 0);
        let limb_values: Vec<Integer> = create_limb_values(value, limb_width, n_limbs);
        assert!(value.clone() <= upper_bound);
        BigNatWithLimbMax {
            limb_values: Some(limb_values.clone()),
            value: Some(value.clone()),
            params: BigNatParamsWithLimbMax::new(limb_width, n_limbs, Some(upper_bound)),
        }
    }

    /// Create a new BigNat instance from u32
    pub fn from_u32(value: u32, limb_width: usize, n_limbs: usize, constant: bool) -> Self {
        let value: Integer = Integer::from(value);
        BigNatWithLimbMax::new(&value, limb_width, n_limbs, constant)
    }

    /// Create a BigNat instance from a BigNatb instance
    pub fn from_bignatb(big_natb: &BigNatbWithLimbMax) -> Self {
        let value: Integer = big_natb.value.clone().unwrap();
        let limb_values: Vec<Integer> = create_limb_values(&value, big_natb.params.limb_width, big_natb.params.n_limbs);
        Self {
            limb_values: Some(limb_values.clone()),
            value: Some(value.clone()),
            params: big_natb.params.clone(),
        }
    }

    /// Return the i-th limb; For example, if limbs = [0, 1, 2] and idx = 1, return Some(0)
    pub fn get_i_th_limb(&self, idx: usize) -> Option<Integer> {
        self.limb_values.clone().and_then(|vec| vec.get(idx).cloned())
    }

    /// Count the number of non-zero elements in the front of the limbs_values
    pub fn count_non_zero(&self) -> usize {
        match self.limb_values.clone() {
            Some(vec) => vec.iter().take_while(|&&ref x| x != &Integer::from(0)).count(),
            None => 0,
        }
    }
    
    /// Allocate a BigNat instance to the circuit
    pub fn alloc(&self, name: &str, input_map: &mut HashMap<String, Value>) {
        if let Some(values) = self.limb_values.as_ref() {
            for (i, value) in values.iter().enumerate() {
                input_map.insert(format!("{}.{}", name, i), integer_to_field(value));
            }
        }
    }

    /// Allocate a BigNat instance to the circuit
    pub fn alloc_from_integer(input: &Integer, limb_width: usize, n_limbs: usize, name: &str, input_map: &mut HashMap<String, Value>) {
        let limb_values: Vec<Integer> = create_limb_values(input, limb_width, n_limbs);
        for (i, value) in limb_values.iter().enumerate() {
            input_map.insert(format!("{}.limbs.{}", name, i), integer_to_field(value));
        }
    }

    /// Allocate a BigNat instance to the circuit
    pub fn alloc_from_nat(&self, name: &str, input_map: &mut HashMap<String, Value>) {
        if let Some(values) = self.limb_values.as_ref() {
            for (i, value) in values.iter().enumerate() {
                input_map.insert(format!("{}.limbs.{}", name, i), integer_to_field(value));
            }
        }
    }

    #[cfg(feature = "spartan")]
    /// Allocate a BigNat instance to the circuit as field[]; 
    pub fn alloc_w_custom_mod(&self, ark_modulus: &Arc<Integer>, name: &str, input_map: &mut HashMap<String, Value>) {
        if let Some(values) = self.limb_values.as_ref() {
            alloc::map_field_vec(values, ark_modulus, &format!("{}", name), input_map);
        }
    }

    #[cfg(feature = "spartan")]
    /// Allocate a BigNat instance to the circuit; to modify
    pub fn alloc_from_nat_w_custom_mod(&self, ark_modulus: &Arc<Integer>, name: &str, input_map: &mut HashMap<String, Value>) {
        if let Some(values) = self.limb_values.as_ref() {
            alloc::map_field_vec(values, ark_modulus, &format!("{}.limbs", name), input_map);
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

    /// Allocate an instance of type `BigNat_init` to the circuit
    pub fn alloc_adv(&self, subtable_bitwidth: usize, name: &str, input_map: &mut HashMap<String, Value>) {
        let append: String = if name.is_empty() {name.to_owned()} else {name.to_owned()+"."};
        let split_limb_values: Vec<Vec<Integer>> = BigNatInit::limb_values_to_chunks(self.limb_values.clone().unwrap(), self.params.limb_width, subtable_bitwidth);
        map_field_double_vec(split_limb_values, &format!("{}limbs", append), input_map);  
    }

    /// Allocate an instance of type `BigNat_init_quotient` to the circuit
    pub fn alloc_quotient_adv(&self, subtable_bitwidth: usize, name: &str, input_map: &mut HashMap<String, Value>) {
        let mut split_limb_values: Vec<Vec<Integer>> = BigNatInit::limb_values_to_chunks(self.limb_values.clone().unwrap(), self.params.limb_width, subtable_bitwidth);
        let last_vector: Vec<Integer> = split_limb_values.pop().unwrap(); // remove the last vector of split_limb_values
        BigNatInit::alloc_chunks(split_limb_values, name, input_map);
        input_map.insert(format!("{}.last_limb", name), integer_to_field(&last_vector[0])); 
        assert!(last_vector.iter().enumerate().all(|(idx, value)| idx == 0 || value.clone() == 0), "Not all elements except the first are zero.");

    }

    /// Compute the polynomial multiplication of self and other represented by BigNat
    pub fn create_product_nat(&self, other: &Self) -> Self{
        assert!(self.params.limb_width == other.params.limb_width);
        let product_n_limbs: usize = self.params.n_limbs+other.params.n_limbs-1;
        let mut max_values: Vec<Integer> = vec![Integer::from(0); product_n_limbs];
        let mut limb_values: Vec<Integer> = vec![Integer::default(); product_n_limbs];

        let value: Option<Integer> = self.value.clone().zip(other.value.clone()).map(|(x, y)| x * y); // use map() to perform multiplication on contained Integer values
        if let Some(self_values) = self.limb_values.as_ref() {
            if let Some(other_values) = other.limb_values.as_ref() {
                for (i, self_val) in self_values.iter().enumerate() {
                    for (j, other_val) in other_values.iter().enumerate() {
                        limb_values[i+j] += self_val * other_val;
                        max_values[i+j] += self.params.max_values[i].clone() * other.params.max_values[j].clone(); // fix bugs
                        // cross_term[i+j] += 1;
                    }
                }
            }
        }

        let params = BigNatParamsWithLimbMax {n_limbs: product_n_limbs, max_values: max_values, limb_width: self.params.limb_width};

        Self {
            limb_values: Some(limb_values),
            value: value,
            params: params,
        }

    }

    /// Compute the polynomial multiplication of self and other represented by BigNat; Also, modify the variable input to the circuit
    pub fn create_product_nat_for_circ(&self, other: &Self, products: &mut Vec::<BigNatWithLimbMax>) -> Self{
        let product: BigNatWithLimbMax = self.create_product_nat(&other);
        products.push(product.clone());
        product
    }

    /// Multiply by scalar for each limbs of self
    pub fn scalar_mult_nat(&self, scalar: &Integer) -> Self {
        let mut limb_values: Vec<Integer> = self.limb_values.as_ref().unwrap().to_vec();
        for value in limb_values.iter_mut() {
            *value *= scalar.clone();
        }

        let mut max_values: Vec<Integer> = self.params.max_values.clone();
        for max_value in max_values.iter_mut() {
            *max_value *= scalar.clone();
        }

        let params = BigNatParamsWithLimbMax {n_limbs: self.params.n_limbs, max_values: max_values, limb_width: self.params.limb_width};
    
        let value: Option<Integer> = self.value.clone().zip(Some(scalar.clone())).map(|(x, y)| x * y);

        Self {
            limb_values: Some(limb_values),
            value: value,
            params: params,
        }        
    }

    /// Compute the addition of polynomials `self` and `other`
    pub fn create_addition_nat(&self, other: &Self) -> Self {
        assert!(self.params.limb_width == other.params.limb_width);
        let mut limbs1: Vec<Integer> = self.limb_values.as_ref().unwrap().to_vec();
        let mut limbs2: Vec<Integer> = other.limb_values.as_ref().unwrap().to_vec();
        let mut maxvalues1: Vec<Integer> = self.params.max_values.clone();
        let mut maxvalues2: Vec<Integer> = other.params.max_values.clone();

        let addition_n_limbs = self.params.n_limbs.max(other.params.n_limbs);

        if self.params.n_limbs < addition_n_limbs {
            let num_zeros_to_append = addition_n_limbs - self.params.n_limbs;
            for _ in 0..num_zeros_to_append {
                limbs1.push(Integer::from(0));
                maxvalues1.push(Integer::from(0));
            }
        }
        else if other.params.n_limbs < addition_n_limbs {
            let num_zeros_to_append = addition_n_limbs - other.params.n_limbs;
            for _ in 0..num_zeros_to_append {
                limbs2.push(Integer::from(0));
                maxvalues2.push(Integer::from(0));
            }            
        }

        for i in 0..addition_n_limbs {
            limbs1[i] += limbs2[i].clone();
            maxvalues1[i] += maxvalues2[i].clone();
        }

        let params: BigNatParamsWithLimbMax = BigNatParamsWithLimbMax {n_limbs: addition_n_limbs, max_values: maxvalues1, limb_width: self.params.limb_width};
        let value: Option<Integer> = self.value.clone().zip(other.value.clone()).map(|(x, y)| x + y); // use map() to perform multiplication on contained Integer values

        Self {
            limb_values: Some(limbs1),
            value: value,
            params: params,
        }
    }


    /// Compute carry for verifying modular multiplication and represent it in BigNat; here we set an upper bound to each limb
    pub fn create_postgp_carry(&self, other: &Self) -> Vec<Vec<bool>> {
        assert!(self.params.n_limbs == other.params.n_limbs);
        let gp_maxword_vec: Vec<Integer> = {
            let mut gp_maxword_vec: Vec<Integer> = Vec::new();
            for (max_val1, max_val2) in self.params.max_values.iter().zip(other.params.max_values.iter()) {
                gp_maxword_vec.push(max_val1.max(max_val2).clone());
            }
            gp_maxword_vec
        };

        let mut carry_bits_vec: Vec<usize> = Vec::new(); // for test only

        let left_values: Vec<Integer> = self.limb_values.as_ref().unwrap().to_vec();
        let right_values: Vec<Integer> = other.limb_values.as_ref().unwrap().to_vec();
        let mut carry: Vec<Vec<bool>> = Vec::new();
        let mut carry_in: Integer = Integer::from(0);
        for (i, gp_maxword) in gp_maxword_vec.iter().enumerate().take(gp_maxword_vec.len() - 1) {
            let carry_bits = ((gp_maxword.to_f64() * 2.0).log2() - self.params.limb_width as f64).ceil() as usize;
            carry_bits_vec.push(carry_bits); // for test only   
            let carry_value: Integer = (left_values[i].clone() + carry_in.clone() + gp_maxword.clone() - right_values[i].clone()) >> self.params.limb_width;
            carry.push(integer_to_bool_vec(&carry_value, carry_bits));
            carry_in = carry_value;
        }
        carry
    }

    /// Basically same as above except the output type is different
    pub fn create_postgp_carry_adv(&self, other: &Self) -> Vec<BigNatCarryInit> {
        assert!(self.params.n_limbs == other.params.n_limbs);
        let gp_maxword_vec: Vec<Integer> = {
            let mut gp_maxword_vec: Vec<Integer> = Vec::new();
            for (max_val1, max_val2) in self.params.max_values.iter().zip(other.params.max_values.iter()) {
                gp_maxword_vec.push(max_val1.max(max_val2).clone());
            }
            gp_maxword_vec
        };
        let mut carry_vec: Vec<BigNatCarryInit> = Vec::new();

        let left_values: Vec<Integer> = self.limb_values.as_ref().unwrap().to_vec();
        let right_values: Vec<Integer> = other.limb_values.as_ref().unwrap().to_vec();
        let mut carry_in: Integer = Integer::from(0);
        for (i, gp_maxword) in gp_maxword_vec.iter().enumerate().take(gp_maxword_vec.len() - 1) {
            let carry_bits = ((gp_maxword.to_f64() * 2.0).log2() - self.params.limb_width as f64).ceil() as usize;
            let carry_value: Integer = (left_values[i].clone() + carry_in.clone() + gp_maxword.clone() - right_values[i].clone()) >> self.params.limb_width;
            carry_vec.push(BigNatCarryInit::new(carry_value.clone(), carry_bits));
            carry_in = carry_value.clone();
        }
        carry_vec
    }

    /// Basically same as above except that we allow maxword to be larger
    pub fn create_postgp_carry_adv_w_maxwords(&self, other: &Self, gp_maxwords: Vec<Integer>) -> Vec<BigNatCarryInit> {
        assert!(self.params.n_limbs == other.params.n_limbs);
        let mut carry_vec: Vec<BigNatCarryInit> = Vec::new();

        let left_values: Vec<Integer> = self.limb_values.as_ref().unwrap().to_vec();
        let right_values: Vec<Integer> = other.limb_values.as_ref().unwrap().to_vec();
        let mut carry_in: Integer = Integer::from(0);
        for (i, gp_maxword) in gp_maxwords.iter().enumerate().take(gp_maxwords.len() - 1) {
            let carry_bits = ((gp_maxword.to_f64() * 2.0).log2() - self.params.limb_width as f64).ceil() as usize;
            let carry_value: Integer = (left_values[i].clone() + carry_in.clone() + gp_maxword.clone() - right_values[i].clone()) >> self.params.limb_width;
            carry_vec.push(BigNatCarryInit::new(carry_value.clone(), carry_bits));
            carry_in = carry_value.clone();
        }
        carry_vec
    }

    /// Compute the maximum among the max words of self and other; note: self and other need to be grouped
    pub fn compute_maxvalues(&self, other: &Self) -> Vec<Integer> {
        assert!(self.params.limb_width == other.params.limb_width);
        // make sure maxvalues1 and maxvalues2 have the same length by appending zero if necessary
        let mut maxvalues1: Vec<Integer> = self.params.max_values.clone();
        let mut maxvalues2: Vec<Integer> = other.params.max_values.clone();
        let n_limbs = self.params.n_limbs.max(other.params.n_limbs);
        if self.params.n_limbs < n_limbs {
            let num_zeros_to_append = n_limbs - self.params.n_limbs;
            for _ in 0..num_zeros_to_append {
                maxvalues1.push(Integer::from(0));
            }
        }
        else if other.params.n_limbs < n_limbs {
            let num_zeros_to_append = n_limbs - other.params.n_limbs;
            for _ in 0..num_zeros_to_append {
                maxvalues2.push(Integer::from(0));
            }            
        }

        let mut gp_maxvalues: Vec<Integer> = Vec::new();
        for (maxval1, maxval2) in maxvalues1.iter().zip(maxvalues2.iter()) {
            gp_maxvalues.push(maxval1.max(maxval2).clone());
        }
        gp_maxvalues
    }

    /// Compute the number of bits required for each limb in carry
    pub fn compute_cw(&self, other: &Self) -> Vec<usize> {
        let mut cw_list: Vec<usize> = Vec::new();
        let gp_maxvalues: Vec<Integer> = self.compute_maxvalues(other);
        for maxval in gp_maxvalues.iter().take(gp_maxvalues.len() - 1) {
            let carry_bits = (((maxval.to_f64() * 2.0).log2() - self.params.limb_width as f64).ceil() + 0.1) as usize;
            cw_list.push(carry_bits);
        }
        cw_list
    }

    /// find the maximum number of limbs that a group can contain
    pub fn find_n_limbs_for_each_gp(&self, other: &Self, field_mod: Integer) -> Vec<usize> {
        assert!(self.params.limb_width == other.params.limb_width);
        let mut current_maxval: Integer = Integer::from(0);
        let mut steps: Vec<usize> = Vec::new();
        let mut gp_maxvalues: Vec<Integer> = Vec::new();
        let mut step: usize = 0;
        let base: Integer = Integer::from(1) << self.params.limb_width;
        let mut shift = Integer::from(1);

        // make sure maxvalues1 and maxvalues2 have the same length by appending zero if necessary
        let mut maxvalues1: Vec<Integer> = self.params.max_values.clone();
        let mut maxvalues2: Vec<Integer> = other.params.max_values.clone();
        let n_limbs = self.params.n_limbs.max(other.params.n_limbs);
        if self.params.n_limbs < n_limbs {
            let num_zeros_to_append = n_limbs - self.params.n_limbs;
            for _ in 0..num_zeros_to_append {
                maxvalues1.push(Integer::from(0));
            }
        }
        else if other.params.n_limbs < n_limbs {
            let num_zeros_to_append = n_limbs - other.params.n_limbs;
            for _ in 0..num_zeros_to_append {
                maxvalues2.push(Integer::from(0));
            }            
        }
        
        for (i, (maxval1, maxval2)) in maxvalues1.iter().zip(maxvalues2.iter()).enumerate() {
            let maxval = maxval1.max(maxval2);
            let next_maxval: Integer = current_maxval.clone() + maxval.clone() * shift.clone();
            if next_maxval >= field_mod {
                steps.push(step);
                gp_maxvalues.push(current_maxval.clone());
                step = 0;
                current_maxval = Integer::from(0);
                shift = Integer::from(1);
            }
            current_maxval += maxval.clone() * shift.clone();
            step += 1;
            shift *= base.clone();
            if i+1 == self.params.n_limbs {
                steps.push(step);
                gp_maxvalues.push(current_maxval.clone());
            }
        }

        steps
    }
    /// find the maximum number of limbs that a group can contain; let the last group has maximum number of limbs
    pub fn find_n_limbs_for_each_gp2(&self, other: &Self, field_mod: Integer) -> Vec<usize> {
        assert!(self.params.limb_width == other.params.limb_width);
        let mut current_maxval: Integer = Integer::from(0);
        let mut steps: Vec<usize> = Vec::new();
        let mut gp_maxvalues: Vec<Integer> = Vec::new();
        let mut step: usize = 0;
        let base: Integer = Integer::from(1) << self.params.limb_width;

        // make sure maxvalues1 and maxvalues2 have the same length by appending zero if necessary
        let mut maxvalues1: Vec<Integer> = self.params.max_values.clone();
        let mut maxvalues2: Vec<Integer> = other.params.max_values.clone();
        let n_limbs = self.params.n_limbs.max(other.params.n_limbs);
        if self.params.n_limbs < n_limbs {
            let num_zeros_to_append = n_limbs - self.params.n_limbs;
            for _ in 0..num_zeros_to_append {
                maxvalues1.push(Integer::from(0));
            }
        }
        else if other.params.n_limbs < n_limbs {
            let num_zeros_to_append = n_limbs - other.params.n_limbs;
            for _ in 0..num_zeros_to_append {
                maxvalues2.push(Integer::from(0));
            }            
        }
        conditional_print!("n_limbs = {}", n_limbs);
        
        for (i, (maxval1, maxval2)) in maxvalues1.iter().zip(maxvalues2.iter()).rev().enumerate() {
            let maxval = maxval1.max(maxval2);
            let next_maxval: Integer = current_maxval.clone()*base.clone() + maxval.clone();
            if next_maxval >= field_mod {
                steps.push(step);
                gp_maxvalues.push(current_maxval.clone());
                step = 0;
                current_maxval = maxval.clone();
            } else {
                current_maxval = next_maxval.clone();
            }
            step += 1;
            // shift *= base.clone();
            if i+1 == self.params.n_limbs {
                steps.push(step);
                gp_maxvalues.push(current_maxval.clone());
            }
        }
        conditional_print!("gp_maxvalues = {:?}", gp_maxvalues);
        // the following is for test
        steps.iter().rev().cloned().collect()
    }

    /// create auxiliary constants based on n_limbs and limb_width
    pub fn compute_aux_const(&self) -> Vec<Integer> {
        let target_base = Integer::from(1) << self.params.limb_width;
        let mut aux_const: Vec<Integer> = Vec::new();
        let mut accumulated_extra: Integer = Integer::from(0);
        for max_val in self.params.max_values.iter() {
            accumulated_extra += max_val.clone();
            aux_const.push(accumulated_extra.clone() % target_base.clone());
            accumulated_extra >>= self.params.limb_width;
        }
        aux_const.push(accumulated_extra);
        aux_const
    }
    /// create auxiliary constants based on n_limbs and limb_width
    pub fn compute_aux_const_for_both(&self, other: &Self) -> Vec<Integer> {
        assert!(self.params.limb_width == other.params.limb_width);
        let target_base = Integer::from(1) << self.params.limb_width;
        let mut aux_const: Vec<Integer> = Vec::new();
        let mut accumulated_extra: Integer = Integer::from(0);
        let mut cw_list: Vec<usize> = Vec::new();
        let max_values: Vec<Integer> = self.compute_maxvalues(other);
        for max_val in max_values.iter() {
            let carry_bits = (((max_val.to_f64() * 2.0).log2() - self.params.limb_width as f64).ceil()
            + 0.1) as usize;
            cw_list.push(carry_bits);
            accumulated_extra += max_val;
            aux_const.push(accumulated_extra.clone() % target_base.clone());
            accumulated_extra >>= self.params.limb_width;
        }

        aux_const.push(accumulated_extra);
        aux_const
    }
    /// create auxiliary constants based on n_limbs and limb_width; not finish
    pub fn compute_aux_const_for_both2(&self, other: &Self, steps: Vec<usize>) -> Vec<Integer> {
        assert!(self.params.limb_width == other.params.limb_width);
        let target_base = Integer::from(1) << self.params.limb_width;
        let mut aux_const: Vec<Integer> = Vec::new();
        let mut accumulated_extra: Integer = Integer::from(0);
        let mut cw_list: Vec<usize> = Vec::new();
        for ((max_val1, max_val2), step) in self.params.max_values.iter().zip(other.params.max_values.iter()).zip(steps.iter()) {
            let max_val: Integer = max_val1.max(max_val2).clone();
            let carry_bits = (((max_val.to_f64() * 2.0).log2() - (self.params.limb_width*step) as f64).ceil()
            + 0.1) as usize;
            cw_list.push(carry_bits);
            accumulated_extra += max_val1.max(max_val2);
            aux_const.push(accumulated_extra.clone() % target_base.clone());
            accumulated_extra >>= self.params.limb_width;
        }

        aux_const.push(accumulated_extra);
        aux_const
    }
    /// gp_limbs = number of limbs per group
    pub fn group_limbs(&self, limbs_per_gp: usize, field_mod: Option<Integer>) -> Self {
        let default_modulus: Integer = match field_mod {
            Some(integer) => integer,
            None => Integer::from_str_radix("52435875175126190479447740508185965837690552500527637822603658699938581184513", 10).unwrap(),
        };
        let mut limb_values = Vec::new();
        let mut gp_maxvalues:Vec<Integer> = Vec::new();
        let base: Integer = Integer::from(1) << self.params.limb_width;
        if let Some(values) = self.limb_values.as_ref() {
            let mut current_val = Integer::from(0);
            let mut current_maxval: Integer = Integer::from(0);
            let mut shift = Integer::from(1);
            for (i, (value, maxval)) in values.iter().zip(self.params.max_values.iter()).enumerate() {
                current_val = current_val.clone() + value.clone() * shift.clone();
                current_maxval += maxval.clone() * shift.clone();
                if (i+1) % limbs_per_gp == 0 || i ==  values.len()-1 {
                    shift = Integer::from(1);
                    limb_values.push(current_val.clone());
                    gp_maxvalues.push(current_maxval.clone());
                    current_val = Integer::from(0);
                    current_maxval = Integer::from(0);
                } else {
                    shift = shift.clone() * base.clone();
                }
            }
        }

        // Check if each element in gp_maxvalues is smaller than field_mod
        let all_elements_smaller = gp_maxvalues.iter().all(|value| value.clone() < default_modulus.clone());
        assert!(all_elements_smaller);

        let bp = BigNatParamsWithLimbMax {
                    n_limbs: limb_values.len(),
                    max_values: gp_maxvalues.clone(),
                    limb_width: self.params.limb_width * limbs_per_gp,
                };

        BigNatWithLimbMax {
            limb_values: Some(limb_values.clone()),
            value: self.value.clone(),
            params: bp,
        }
    }

    /// gp_limbs = number of limbs per group
    pub fn group_limbs2(&self, steps: Vec<usize>, field_mod: Option<Integer>) -> Self { // allow each group has different number of limbs
        let default_modulus: Integer = match field_mod {
            Some(integer) => integer,
            None => Integer::from_str_radix("52435875175126190479447740508185965837690552500527637822603658699938581184513", 10).unwrap(),
        };
        let mut limb_values = Vec::new();
        let mut gp_maxvalues:Vec<Integer> = Vec::new();
        let base: Integer = Integer::from(1) << self.params.limb_width;

        let mut target_n_limbs = steps[0];
        let mut idx = 0;

        if let Some(values) = self.limb_values.as_ref() {
            let mut current_val = Integer::from(0);
            let mut current_maxval: Integer = Integer::from(0);
            let mut shift = Integer::from(1);
            for (i, (value, maxval)) in values.iter().zip(self.params.max_values.iter()).enumerate() {
                current_val = current_val.clone() + value.clone() * shift.clone();
                current_maxval += maxval.clone() * shift.clone();
                if (i+1) == target_n_limbs || i ==  values.len()-1 {
                    shift = Integer::from(1);
                    limb_values.push(current_val.clone());
                    gp_maxvalues.push(current_maxval.clone());
                    current_val = Integer::from(0);
                    current_maxval = Integer::from(0);
                    idx += 1;
                    if i !=  values.len()-1 {target_n_limbs += steps[idx];}
                } else {
                    shift = shift.clone() * base.clone();
                }
            }
        }

        // Check if each element in gp_maxvalues is smaller than field_mod
        let all_elements_smaller = gp_maxvalues.iter().all(|value| value.clone() < default_modulus.clone());
        assert!(all_elements_smaller);

        let bp = BigNatParamsWithLimbMax {
                    n_limbs: limb_values.len(),
                    max_values: gp_maxvalues.clone(),
                    limb_width: self.params.limb_width// * limbs_per_gp, // not true; might cause problems
                };

        BigNatWithLimbMax {
            limb_values: Some(limb_values.clone()),
            value: self.value.clone(),
            params: bp,
        }
    }

    /// Start from the most significant limb, locate the first limb where self and other differ
    pub fn locate_first_differ_limbs(&self, other: &Self) -> usize {
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
}

/// Representations of intermediate values for verifying modular multiplicaton (a * b = quotient * modul + remainder)
pub struct BigNatModMultWithLimbMax {
    /// a
    pub a: BigNatWithLimbMax,
    /// b
    pub b: BigNatWithLimbMax,
    /// modul
    pub modul: BigNatWithLimbMax,
    /// The polynomial multiplication of a and b
    pub z: BigNatWithLimbMax,
    /// The polynomial multiplication of quotient and modul
    pub v: BigNatWithLimbMax,
    /// Quotient,
    pub quotient: BigNatWithLimbMax,
    /// Boolean representation of quotient
    pub quotientb: Option<BigNatbWithLimbMax>,
    /// Remainder
    pub remainder: BigNatWithLimbMax,
    /// Boolean representation of remainder
    pub remainderb: BigNatbWithLimbMax,
    /// Boolean double array used to check modular multiplicato
    pub carry: CarryType,
}

impl BigNatModMultWithLimbMax {
    /// Create a new BigNatModMult instance // not finish // previous name: new_with_grouping_and_diff_maxword
    pub fn new(a: &BigNatWithLimbMax, b: &BigNatWithLimbMax, modul: &BigNatWithLimbMax, limbs_per_gp: usize) -> Self {
        let n_limbs = modul.params.n_limbs;
        assert!(a.params.limb_width == b.params.limb_width);
        let product = a.create_product_nat(b); //left hand side
        let quotient_val = product.value.clone().zip(modul.value.clone()).map(|(z, q)| z / q).unwrap();
        let limbwidth = a.params.limb_width;
        let quotient = BigNatWithLimbMax::new(&quotient_val, limbwidth, n_limbs, false); 
        let quotientb = BigNatbWithLimbMax::from_bignat(&quotient);
        let remainder_val = product.value.clone().zip(modul.value.clone()).map(|(z, q)| z % q).unwrap();
        let remainder = BigNatWithLimbMax::new(&remainder_val, limbwidth, n_limbs, false);
        let remainderb = BigNatbWithLimbMax::from_bignat(&remainder);
        let v = quotient.create_product_nat(modul);
        let right = v.create_addition_nat(&remainder);

        let group_right = right.group_limbs(limbs_per_gp, None);
        let group_left = product.group_limbs(limbs_per_gp, None);

        let carry = CarryType::CarryOri(group_left.create_postgp_carry(&group_right));

        let bp = Self {
            a: a.clone(),
            b: b.clone(),
            modul: modul.clone(),
            z: product,
            v: v,
            quotient: quotient, // newly add
            quotientb: Some(quotientb),
            remainder: remainder,
            remainderb: remainderb,
            carry: carry,
        };

        bp

    }

    /// Create a new BigNatModMult instance
    pub fn new2(a: &BigNatWithLimbMax, b: &BigNatWithLimbMax, modul: &BigNatWithLimbMax, quotient_bits: usize, limbs_per_gp: usize, advanced: bool) -> Self {
        let n_limbs = modul.params.n_limbs;
        assert!(a.params.limb_width == b.params.limb_width);
        let product = a.create_product_nat(b); //left hand side
        let quotient_val = product.value.clone().zip(modul.value.clone()).map(|(z, q)| z / q).unwrap();
        let limbwidth = a.params.limb_width;
        let quotient_upper_bound: Integer = (Integer::from(1) << quotient_bits) - 1;
        let quotient = BigNatWithLimbMax::new_with_upper_bound(&quotient_val, limbwidth, n_limbs+1, quotient_upper_bound); // usually quotient requires limbwidth*n_limbs+1 bits
        let quotientb = if advanced {None} else {Some(BigNatbWithLimbMax::from_bignat_v2(&quotient, quotient_bits))};
        let remainder_val = product.value.clone().zip(modul.value.clone()).map(|(z, q)| z % q).unwrap();
        let remainder = BigNatWithLimbMax::new(&remainder_val, limbwidth, n_limbs, false);
        let remainderb = BigNatbWithLimbMax::from_bignat(&remainder);
        let v = quotient.create_product_nat(modul);
        let right = v.create_addition_nat(&remainder);

        let group_right = right.group_limbs(limbs_per_gp, None);
        let group_left = product.group_limbs(limbs_per_gp, None);

        let carry = if advanced {
                        CarryType::CarryAdv(group_left.create_postgp_carry_adv(&group_right))
                    }
                    else {
                        CarryType::CarryOri(group_left.create_postgp_carry(&group_right))
                    };


        let bp = Self {
            a: a.clone(),
            b: b.clone(),
            modul: modul.clone(),
            z: product,
            v: v,
            quotient: quotient, // newly added
            quotientb: quotientb,
            remainder: remainder,
            remainderb: remainderb,
            carry: carry,
        };

        bp
    }

    /// Prover input for one modular multiplication with advanced range check
    pub fn prover_input_for_single_modmultiply_adv(a: &BigNatWithLimbMax, b: &BigNatWithLimbMax, modul: &BigNatWithLimbMax, quotient_bits: usize, limbs_per_gp: usize, subtable_bitwidth: usize, name: &str, input_map: &mut HashMap::<String, Value>) {
        let mm: Self = Self::new2(&a, &b, &modul, quotient_bits, limbs_per_gp, true); // advanced = true
        a.alloc_adv(subtable_bitwidth, &format!("{}.res_init", name), input_map); // not sure
        mm.alloc_adv(subtable_bitwidth, name, input_map);
    }
    /// verify (grouped) z == (grouped) (v + remainder) in circuit // not finish
    pub fn verify_equal_when_carried(&self, group_left: &BigNatWithLimbMax, group_right: &BigNatWithLimbMax) -> bool {
        conditional_print!("----------------- begin verify_equal_when_carried -----------------");
        let mut group_maxword: Vec<Integer> = Vec::new();
        for (max_val1, max_val2) in group_left.params.max_values.iter().zip(group_right.params.max_values.iter()) {
            group_maxword.push(max_val1.max(max_val2).clone());
        }
        conditional_print!("group_maxword in verify_equal_when_carried {:?}", group_maxword);
        assert!(group_left.params.limb_width == group_right.params.limb_width);

        let gp_n_limbs: usize = group_left.params.n_limbs; // assume group_left.params.n_limbs <= group_right.params.n_limbs
        let gp_limb_width: usize = group_right.params.limb_width;
        let target_base = Integer::from(1) << gp_limb_width as u32;
        let mut carry_in: Integer = Integer::from(0);
        let aux_const: Vec<Integer> = group_left.compute_aux_const_for_both(&group_right);
        conditional_print!("len {} aux const {:?}", aux_const.len(), aux_const);

        let left_values: Vec<Integer> = group_left.limb_values.as_ref().unwrap().to_vec();
        conditional_print!("gp_left {:?}", left_values);
        let right_values: Vec<Integer> = group_right.limb_values.as_ref().unwrap().to_vec(); 
        conditional_print!("gp_right {:?}", right_values);       
        let carry_list: Vec<Vec<bool>> = self.carry.output_carry_ori();
        for (i, max_val) in group_maxword.iter().take(group_maxword.len() - 1).enumerate() {
            let carry_cur: Integer = carry_in.clone();
            carry_in = bool_vec_to_integer(&carry_list[i]);
            conditional_print!("carry_in[{}] {:?}", i, carry_cur);
            let left: Integer = left_values[i].clone()+carry_cur.clone()-carry_in.clone()*target_base.clone()-right_values[i].clone()+max_val.clone();
            let right: Integer = aux_const[i].clone();
            conditional_print!("left {} {:?}" ,i, left);
            conditional_print!("right {} {:?}" ,i, right);
            assert!(left == right);
        }
        //check last limb of carry equal last limb of aux_const
        let left: Integer = left_values[gp_n_limbs-1].clone()+carry_in.clone()-aux_const[gp_n_limbs].clone()*target_base.clone()+group_maxword.last().unwrap().clone()-right_values[gp_n_limbs-1].clone();
        conditional_print!("left {} {:?}" ,gp_n_limbs-1, left);
        assert!(left == aux_const[gp_n_limbs-1].clone());
        conditional_print!("----------------- end verify_equal_when_carried -----------------");
        true
    }

    /// Allocate BigNatModMultWithLimbMax instance to the circuit
    pub fn alloc(&self, name: &str, input_map: &mut HashMap<String, Value>) {
        let append: String = if name.is_empty() {name.to_owned()} else {name.to_owned()+"."};
        self.z.alloc_from_nat(&format!("{}z", append), input_map);
        self.v.alloc_from_nat(&format!("{}v", append), input_map);
        self.quotientb.clone().unwrap().alloc_from_natb_v2(&format!("{}quotientb", append), input_map);
        self.carry.alloc_carry_ori(name, input_map);
    }

    #[cfg(feature = "spartan")]
    /// Allocate BigNatModMultWithLimbMax instance to the circuit
    pub fn alloc_w_custom_mod(&self, ark_modulus: &Arc<Integer>, name: &str, input_map: &mut HashMap<String, Value>) {
        let append: String = if name.is_empty() {name.to_owned()} else {name.to_owned()+"."};
        self.z.alloc_from_nat_w_custom_mod(ark_modulus, &format!("{}z", append), input_map);
        self.v.alloc_from_nat_w_custom_mod(ark_modulus, &format!("{}v", append), input_map);
        self.quotientb.clone().unwrap().alloc_from_natb_v2(&format!("{}quotientb", append), input_map); // unchanged since allocation for boolean is the same for any modulus
        self.carry.alloc_carry_ori(name, input_map); // unchanged because carry is allocated as boolean
    }

    /// Allocate BigNatModMultWithLimbMax instance to the circuit with advanced range check
    pub fn alloc_adv(&self, subtable_bitwidth: usize, name: &str, input_map: &mut HashMap<String, Value>) {
        let append: String = if name.is_empty() {name.to_owned()} else {name.to_owned()+"."};
        self.z.alloc_from_nat(&format!("{}z", append), input_map); // same as before
        self.v.alloc_from_nat(&format!("{}v", append), input_map); // same as before
        self.quotient.alloc_quotient_adv(subtable_bitwidth, &format!("{}quotient_init", append), input_map);
        self.carry.alloc_carry_adv(subtable_bitwidth, name, input_map);
    }

    /// Allocate BigNatModMultWithLimbMax instance to the circuit
    pub fn alloc_complete(&self, name: &str, input_map: &mut HashMap<String, Value>) {
        let append: String = if name.is_empty() {name.to_owned()} else {name.to_owned()+"."};
        self.a.alloc_from_nat("a", input_map);
        self.b.alloc_from_nat("b", input_map);
        self.modul.alloc_from_nat("modul", input_map); 
        self.z.alloc_from_nat(&format!("{}z", append), input_map);
        self.v.alloc_from_nat(&format!("{}v", append), input_map);
        self.quotientb.clone().unwrap().alloc_from_natb_v2(&format!("{}quotientb", append), input_map);
        self.carry.alloc_carry_ori(name, input_map);
    }
}

#[derive(Clone, PartialEq, Eq)]
/// Representations of intermediate values for verifying mod operation (left = quotient * modul + remainder)
pub struct BigNatModWithLimbMax {
    /// left hand side
    pub left: BigNatWithLimbMax,
    /// modul
    pub modul: BigNatWithLimbMax,
    /// The polynomial multiplication of quotient and modul
    pub v: BigNatWithLimbMax,
    /// Quotient,
    pub quotient: BigNatWithLimbMax,
    /// Boolean representation of quotient
    pub quotientb: Option<BigNatbWithLimbMax>,
    /// Remainder
    pub remainder: BigNatWithLimbMax,
    /// Boolean representation of remainder
    pub remainderb: BigNatbWithLimbMax,
    /// Boolean double array used to check modular multiplicato
    pub carry: CarryType, // Vec<Vec<bool>>,
}

impl BigNatModWithLimbMax {
    /// Create a new BigNatMod instance with remainder provided (check left == quotient * modul + remainder, where remainder might not be well-aligned but ori_remainder must be well-alligned)
    pub fn new_w_remainder2(left: &BigNatWithLimbMax, modul: &BigNatWithLimbMax, ori_remainder: &BigNatWithLimbMax, remainder: &BigNatWithLimbMax, quotient_bits: usize, limbs_per_gp: usize, advanced: bool) -> Self {
        let n_limbs = modul.params.n_limbs;
        let limbwidth = modul.params.limb_width;
        assert!(left.params.limb_width == modul.params.limb_width);
        let quotient_val: Integer = (left.value.clone().unwrap() - remainder.value.clone().unwrap()) / modul.value.clone().unwrap(); // left.value.clone().zip(modul.value.clone()).map(|(z, q)| z / q).unwrap();
        let quotient_upper_bound: Integer = (Integer::from(1) << quotient_bits) - 1;
        let quotient = BigNatWithLimbMax::new_with_upper_bound(&quotient_val, limbwidth, n_limbs+1, quotient_upper_bound);
        let quotientb = if advanced {None} else {Some(BigNatbWithLimbMax::from_bignat_v2(&quotient, quotient_bits))};

        if left.value.clone().unwrap() != quotient_val.clone() * modul.value.clone().unwrap() + remainder.value.clone().unwrap() {
            conditional_print!("left {:?}", left.value.clone().unwrap());
            conditional_print!("quotient_val {:?} {:?}", quotient_val.clone(), modul.value.clone().unwrap());
            conditional_print!("remainder {:?}", remainder.value.clone().unwrap());
        }
        assert!(left.value.clone().unwrap() == quotient_val.clone() * modul.value.clone().unwrap() + remainder.value.clone().unwrap());
        let remainderb = BigNatbWithLimbMax::from_bignat(&ori_remainder);
        let v = quotient.create_product_nat(modul);
        let right = v.create_addition_nat(&remainder); // quotient * modul + remainder
        let group_right = right.group_limbs(limbs_per_gp, None);
        let group_left = left.group_limbs(limbs_per_gp, None);

        let carry = if advanced {
            CarryType::CarryAdv(group_left.create_postgp_carry_adv(&group_right))
        }
        else {
            CarryType::CarryOri(group_left.create_postgp_carry(&group_right))
        };

        let bp = Self {
            left: left.clone(),
            modul: modul.clone(),
            v: v,
            quotient: quotient, // newly added
            quotientb: quotientb,
            remainder: remainder.clone(), // remainder for the new remainder
            remainderb: remainderb, // the remainderb for the original remainder
            carry: carry,
        };

        bp
    }   

    /// Allocate a BigNatModWithLimbMax instance to the circuit; allow the last limb of quotient has fewer bits than other limbs of quotient
    pub fn alloc2(&self, name: &str, input_map: &mut HashMap::<String, Value>) {
        let append: String = if name.is_empty() {name.to_owned()} else {name.to_owned()+"."};
        self.v.alloc_from_nat(&format!("{}v", append), input_map);
        self.quotientb.clone().expect("quotientb not found").alloc_from_natb_v2(&format!("{}quotientb", append), input_map);
        self.carry.alloc_carry_ori(name, input_map);
    }

    /// Allocate a BigNatModWithLimbMax instance to the circuit with advanced range check
    pub fn alloc_adv(&self, subtable_bitwidth: usize, name: &str, input_map: &mut HashMap<String, Value>) {
        let prepend: String = if name.is_empty() {name.to_owned()} else {name.to_owned()+"."};
        self.v.alloc_from_nat(&format!("{}v", prepend), input_map); // same as before
        self.quotient.alloc_quotient_adv(subtable_bitwidth, &format!("{}quotient_init", prepend), input_map);
        self.carry.alloc_carry_adv(subtable_bitwidth, name, input_map);
    }

    /// verify (grouped) z == (grouped) (v + remainder) in circuit // not finish
    pub fn verify_equal_when_carried(&self, group_left: &BigNatWithLimbMax, group_right: &BigNatWithLimbMax) -> bool {
        conditional_print!("----------------- begin verify_equal_when_carried -----------------");
        let mut group_maxword: Vec<Integer> = Vec::new();
        for (max_val1, max_val2) in group_left.params.max_values.iter().zip(group_right.params.max_values.iter()) {
            group_maxword.push(max_val1.max(max_val2).clone());
        }
        conditional_print!("group_maxword in verify_equal_when_carried {:?}", group_maxword);
        assert!(group_left.params.limb_width == group_right.params.limb_width);

        let gp_n_limbs: usize = group_left.params.n_limbs; // assume group_left.params.n_limbs <= group_right.params.n_limbs
        let gp_limb_width: usize = group_right.params.limb_width;
        let target_base = Integer::from(1) << gp_limb_width as u32;
        let mut carry_in: Integer = Integer::from(0);
        let aux_const: Vec<Integer> = group_left.compute_aux_const_for_both(&group_right);
        conditional_print!("len {} aux const {:?}", aux_const.len(), aux_const);

        let left_values: Vec<Integer> = group_left.limb_values.as_ref().unwrap().to_vec();
        conditional_print!("gp_left {:?}", left_values);
        let right_values: Vec<Integer> = group_right.limb_values.as_ref().unwrap().to_vec(); 
        conditional_print!("gp_right {:?}", right_values);       
        let carry_list: Vec<Vec<bool>> = self.carry.output_carry_ori();
        for (i, max_val) in group_maxword.iter().take(group_maxword.len() - 1).enumerate() {
            let carry_cur: Integer = carry_in.clone();
            carry_in = bool_vec_to_integer(&carry_list[i]);
            conditional_print!("carry_in[{}] {:?}", i, carry_cur);
            let left: Integer = left_values[i].clone()+carry_cur.clone()-carry_in.clone()*target_base.clone()-right_values[i].clone()+max_val.clone();
            let right: Integer = aux_const[i].clone();
            conditional_print!("left {} {:?}" ,i, left);
            conditional_print!("right {} {:?}" ,i, right);
            assert!(left == right);
        }
        //check last limb of carry equal last limb of aux_const
        let left: Integer = left_values[gp_n_limbs-1].clone()+carry_in.clone()-aux_const[gp_n_limbs].clone()*target_base.clone()+group_maxword.last().unwrap().clone()-right_values[gp_n_limbs-1].clone();
        conditional_print!("left {} {:?}" ,gp_n_limbs-1, left);
        assert!(left == aux_const[gp_n_limbs-1].clone());
        conditional_print!("----------------- end verify_equal_when_carried -----------------");
        true
    }
}

/// A boolean representation of a large natural number (a member of {0, 1, 2, ... })
#[derive(Clone, PartialEq, Eq)]
pub struct BigNatbWithLimbMax {
    /// A double boolean array where each element is a limb represented in boolean form
    pub limb_values: Vec<Vec<bool>>,
    /// The value of the whole number (filled at witness-time)
    pub value: Option<Integer>,
    /// Paramaters of BigNatb
    pub params: BigNatParamsWithLimbMax,
}

impl BigNatbWithLimbMax {
    /// Create a BigNatb instance
    pub fn new(value: &Integer, limb_width: usize, n_limbs: usize, constant: bool) -> Self {
        let bignat_res: BigNatWithLimbMax = BigNatWithLimbMax::new(value, limb_width, n_limbs, constant);
        Self::from_bignat(&bignat_res)
    }

    /// Create a BigNatb instance from a BigNat instance
    pub fn from_bignat(big_nat: &BigNatWithLimbMax) -> Self {
        let mut limb_values: Vec<Vec<bool>> = Vec::new();
        if let Some(values) = big_nat.limb_values.as_ref() {
            for (_i, val) in values.iter().enumerate() {
                limb_values.push(integer_to_bool_vec(val, big_nat.params.limb_width));
            }
        }
        BigNatbWithLimbMax {
            limb_values: limb_values,
            value: big_nat.value.clone(),
            params: big_nat.params.clone(),
        }
    }
    
    /// Create a BigNatb instance from a BigNat instance; with a specific n_bits
    pub fn from_bignat_v2(big_nat: &BigNatWithLimbMax, n_bits: usize) -> Self {
        let mut limb_values: Vec<Vec<bool>> = Vec::new();
        if let Some(values) = big_nat.limb_values.as_ref() {
            for (_i, val) in values.iter().take(values.len() - 1).enumerate() {
                limb_values.push(integer_to_bool_vec(val, big_nat.params.limb_width));
            }
            assert!(n_bits > big_nat.params.limb_width * (values.len() - 1));
            let last_limb_width: usize = n_bits - big_nat.params.limb_width * (values.len() - 1);
            // conditional_print!("from_bignat_v2 - last_limb_width {} values[values.len() - 1] {:?}", last_limb_width, values[values.len() - 1].clone());

            limb_values.push(integer_to_bool_vec(&values[values.len() - 1], last_limb_width));
        }
        
        BigNatbWithLimbMax {
            limb_values: limb_values,
            value: big_nat.value.clone(),
            params: big_nat.params.clone(),
        }
    }

    /// Allocate a BigNatb instance to the circuit; should work for any modulus since we only allocate boolean
    pub fn alloc_from_natb(&self, name: &str, input_map: &mut HashMap<String, Value>) {
        map_bool_double_vec(&self.limb_values, &format!("{}.limbs", name), input_map);
    }


    /// Allocate a BigNatb instance to the circuit
    pub fn alloc_from_natb_v2(&self, name: &str, input_map: &mut HashMap<String, Value>) {
        let last_idx: usize = self.limb_values.len() - 1;
        map_bool_double_vec(&self.limb_values[..last_idx].to_vec(), &format!("{}.limbs", name), input_map);
        map_bool_arr(&self.limb_values[last_idx], &format!("{}.limb", name), input_map);
        // conditional_print!("last limb in quotient {:?}", self.limb_values[last_idx]);
    }

    /// Allocate a BigNatb instance to the circuit
    pub fn alloc_from_natb_to_single_vec(&self, name: &str, input_map: &mut HashMap<String, Value>) {
        let bool_vec: Vec<bool> = integer_to_bool_vec(&self.value.clone().unwrap(), self.params.limb_width*self.params.n_limbs);

        map_bool_arr(&bool_vec, &format!("{}", name), input_map);
    }

    /// Allocate a BigNatb instance to the circuit
    pub fn alloc_from_bignat(input: &BigNatWithLimbMax, name: &str, input_map: &mut HashMap<String, Value>) {
        let res: Self = Self::from_bignat(input);     
        map_bool_double_vec(&res.limb_values, &format!("{}.limbs", name), input_map);
    }

    /// Allocate a BigNatb instance to the circuit
    pub fn alloc_from_integer(value: &Integer, limb_width: usize, n_limbs: usize, name: &str, input_map: &mut HashMap<String, Value>) {
        let res: Self = Self::new(value, limb_width, n_limbs, false);     
        map_bool_double_vec(&res.limb_values, &format!("{}.limbs", name), input_map);
    }
}

/// Representations of intermediate value for verifying modular multiplicaton (a * b = quotient * modul + remainder)
#[derive(Clone, PartialEq, Eq)]
pub struct BigNatInterExponWithLimbMax { // called BigNatModMult in big_nat.zok
    /// The polynomial multiplication of a and b
    pub z: BigNatWithLimbMax,
    /// The polynomial multiplication of quotient and modul
    pub v: BigNatWithLimbMax,
    /// Boolean representation of quotient
    pub quotientb: BigNatbWithLimbMax,
    /// Boolean double array used to check modular multiplicato
    pub carry: Vec<Vec<bool>>,
}

impl BigNatInterExponWithLimbMax {
    /// Create a new BigNatInterExpon instance based on a BigNatModMult instance
    pub fn from_bignatmodmult(mm: &BigNatModMultWithLimbMax) -> Self {
        Self {
            z: mm.z.clone(),
            v: mm.v.clone(),
            quotientb: mm.quotientb.clone().unwrap(),
            carry: mm.carry.output_carry_ori(),
        }
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
pub struct BigNatExponWithLimbMax {
    /// Intermediate values
    pub mm: Vec<BigNatInterExponWithLimbMax>, //[BigNatInterExpon; 17],
    /// Original a and results of each modular multiplication
    pub res: Vec<BigNatbWithLimbMax>, //[BigNatb; 18],
    // pub modul: BigNat,
}

impl BigNatExponWithLimbMax {
    /// Create a new BigNatExpon instance for a^e mod modul where e = 2^16 + 1
    pub fn new_with_grouping2(a: &BigNatWithLimbMax, modul: &BigNatWithLimbMax, limbs_per_gp: usize) -> Self {
        let mut mm = Vec::with_capacity(17);
        let mut res = Vec::with_capacity(18);
        // let res = [BigNatb::new(&Integer::from(0), modul.params.limb_width, modul.params.n_limbs); 18];
        res.push(BigNatbWithLimbMax::from_bignat(&a));
        let mut cur_x: BigNatWithLimbMax = a.clone();
        for _ in 0..16 { // 0, 1, ..., 15
            let intermediate = BigNatModMultWithLimbMax::new(&cur_x, &cur_x, &modul, limbs_per_gp);
            mm.push(BigNatInterExponWithLimbMax::from_bignatmodmult(&intermediate)); // need fix
            res.push(intermediate.remainderb);
            cur_x = intermediate.remainder;
        }
        let finalval = BigNatModMultWithLimbMax::new(&a, &cur_x, &modul, limbs_per_gp);
        mm.push(BigNatInterExponWithLimbMax::from_bignatmodmult(&finalval)); // need fix
        res.push(finalval.remainderb);

        Self {
            mm,
            res,
        }    
    }

    /// Create a new BigNatExpon instance for a^e mod modul where e = 2^16 + 1 (we allow each limb has different maxword)
    pub fn from_integer_with_grouping_and_diff_maxword(a: &Integer, modul: &Integer, limbwidth: usize, n_limbs: usize, constant: bool, limbs_per_gp: usize) -> Self {
        let a_bignat: BigNatWithLimbMax = BigNatWithLimbMax::new(&a, limbwidth, n_limbs, false);
        let modul_bignat: BigNatWithLimbMax = BigNatWithLimbMax::new(&modul, limbwidth, n_limbs, constant); // if constant = true, the modul is hard-coded to the circuit
        Self::new_with_grouping2(&a_bignat, &modul_bignat, limbs_per_gp)
    }

}
