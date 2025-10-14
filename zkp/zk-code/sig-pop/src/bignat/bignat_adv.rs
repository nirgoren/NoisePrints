//! This module includes the structures related to range checks for very big natural numbers 

use fxhash::FxHashMap as HashMap;
use crate::ir::term::{Value};

use rug::Integer;

use std::assert;

use super::bignat::{create_limb_values};
use crate::convert::{integer_to_field};
use crate::allocate::{map_bool_double_vec_to_single_vec, map_field_vec, map_field_double_vec};//{map_bool_arr, map_bool_double_vec, map_bool_double_vec_to_single_vec};
use crate::math::{ceil_div};
use super::bignatwithlimbmax::BigNatWithLimbMax;
use crate::conditional_print;

#[derive(Clone, PartialEq, Eq, Debug)]
/// Struct related to range check for carry
pub struct BigNatCarryInit {
    /// single limb
    pub limb: Integer,
    /// Bitwidth of this limb,
    pub bitwidth: usize,
}

impl BigNatCarryInit {
    /// Create a new BigNatCarryInit instance
    pub fn new(limb: Integer, bitwidth: usize) -> Self {
        Self {
            limb: limb,
            bitwidth: bitwidth,
        }
    }

    /// Allocate the carries to the circuit with advanced range check
    pub fn alloc_vec(input: Vec<Self>, subtable_bitwidth: usize, name: &str, input_map: &mut HashMap<String, Value>) {
        let append: String = if name.is_empty() {name.to_owned()} else {name.to_owned()+"."};

        for (i, carry) in input.iter().enumerate() {
            let n_chunks: usize = ceil_div(carry.bitwidth, subtable_bitwidth);
            let chunks: Vec<Integer> = create_limb_values(&carry.limb, subtable_bitwidth, n_chunks);
            map_field_vec(chunks, &format!("{}carry_init.limbs.{}", append, i), input_map);
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
/// Structs for carries
pub enum CarryType {
    /// Original carry
    CarryOri(Vec<Vec<bool>>),
    /// Carry for advanced range check
    CarryAdv(Vec<BigNatCarryInit>),
}

impl CarryType {
    /// output carry of type Vec<Vec<bool>>
    pub fn output_carry_ori(&self) -> Vec<Vec<bool>> {
        if let CarryType::CarryOri(carry) = self {
            return carry.clone();    
        } else {
            panic!("Carry is not of type Vec<Vec<bool>>");
        }
    }
    /// Allocate the carries to the circuit without advanced range check
    pub fn alloc_carry_ori(&self, name: &str, input_map: &mut HashMap<String, Value>) {
        let append: String = if name.is_empty() {name.to_owned()} else {name.to_owned()+"."};
        if let CarryType::CarryOri(carry) = self {
            map_bool_double_vec_to_single_vec(&carry, &format!("{}carry", append), input_map);    
        } else {
            panic!("Carry is not of type Vec<Vec<bool>>");
        }
    }
    /// Allocate the carries to the circuit with advanced range check
    pub fn alloc_carry_adv(&self, subtable_bitwidth: usize, name: &str, input_map: &mut HashMap<String, Value>) {
        if let CarryType::CarryAdv(carry) = self {
            BigNatCarryInit::alloc_vec(carry.to_vec(), subtable_bitwidth, name, input_map);
        } else {
            panic!("Carry is not of type Vec<Vec<igNatCarryInit>>");
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
/// Params for describing a very large natural number
pub struct BigNatParamsAdv {
    /// Number of limbs
    pub n_limbs: usize,
    /// Number of chunks in one limb,
    pub n_chunks: usize,
    /// Maximum value of each limb
    pub max_values: Vec<Integer>,
    /// Limbwidth of each limb
    pub limb_width: usize,
    /// Subtable bit-widtn,
    pub subtable_bitwidth: usize,
}

impl BigNatParamsAdv {
    /// Create a new BigNatParamsAdv instance
    pub fn new(limb_width: usize, n_limbs: usize, value: Option<Integer>, subtable_bitwidth: usize) -> Self {

        let n_chunks: usize = ceil_div(limb_width, subtable_bitwidth);
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
            n_limbs: n_limbs,
            n_chunks: n_chunks,
            max_values: max_values,
            limb_width: limb_width,
            subtable_bitwidth: subtable_bitwidth
        }
    }
}

/// A representation of a large natural number for range check
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BigNatInit {
    /// The witness values for each limb (filled at witness-time)
    pub limb_values: Vec<Vec<Integer>>,
    /// The value of the whole number (filled at witness-time)
    pub value: Option<Integer>,
    /// Parameters
    pub params: BigNatParamsAdv,
}

impl BigNatInit {
    /// Create a new BigNatInit instance
    pub fn new(value: &Integer, limb_width: usize, n_limbs: usize, constant: bool, subtable_bitwidth: usize) -> Self {
        assert!(value.clone() >= 0);
        let split_limb_values: Vec<Vec<Integer>> = Self::value_to_chunks(value, limb_width, n_limbs, subtable_bitwidth);
        let value_input_to_params: Option<Integer> = if constant {Some(value.clone())} else {None};

        BigNatInit {
            limb_values: split_limb_values.clone(),
            value: Some(value.clone()),
            params: BigNatParamsAdv::new(limb_width, n_limbs, value_input_to_params, subtable_bitwidth),
        }
    }

    /// Convert one `Integer` to chunks; n_bits is the number of maximum bits required by this number
    pub fn one_value_to_chunks(input: Integer, n_bits: usize, subtable_bitwidth: usize) -> Vec<Integer> {
        let n_chunks: usize = ceil_div(n_bits, subtable_bitwidth);
        conditional_print!("Number of chunks for one {}-bit number = {}", n_bits, n_chunks);
        create_limb_values(&input, subtable_bitwidth, n_chunks)
    }

    /// Convert a `Vec<Integer>` to a vector of chunks
    pub fn limb_values_to_chunks(input: Vec<Integer>, limb_width: usize, subtable_bitwidth: usize) -> Vec<Vec<Integer>> {
        let mut chunks: Vec<Vec<Integer>> = Vec::new();
        let n_chunks: usize = ceil_div(limb_width, subtable_bitwidth);
        for limb in input.iter() {
            chunks.push(create_limb_values(&limb, subtable_bitwidth, n_chunks));
        }
        chunks
    }

    /// Split a `Integer` element to chunks of bitwidth = `bitwidth`
    pub fn value_to_chunks(value: &Integer, limb_width: usize, n_limbs: usize, subtable_bitwidth: usize) -> Vec<Vec<Integer>> {
        let limb_values: Vec<Integer> = create_limb_values(value, limb_width, n_limbs);
        Self::limb_values_to_chunks(limb_values, limb_width, subtable_bitwidth)
    }

    /// Allocate chunks of limbs to the circuit
    pub fn alloc_chunks(input: Vec<Vec<Integer>>, name: &str, input_map: &mut HashMap<String, Value>) {
        let append: String = if name.is_empty() {name.to_owned()} else {name.to_owned()+"."};
        map_field_double_vec(input, &format!("{}limbs", append), input_map);
    }

    /// Allocate a BigNatInit instance to the circuit
    pub fn alloc(&self, name: &str, input_map: &mut HashMap<String, Value>) {
        let append: String = if name.is_empty() {name.to_owned()} else {name.to_owned()+"."};
        for (i, chunks) in self.limb_values.iter().enumerate() {
            for (j, chunk) in chunks.iter().enumerate() {
                input_map.insert(format!("{}limbs.{}.{}", append, i, j), integer_to_field(chunk));
            }
        }
    }


    /// Allocate a BigNatInit instance to the circuit
    pub fn alloc_from_integer(value: &Integer, limb_width: usize, n_limbs: usize, subtable_bitwidth: usize, name: &str, input_map: &mut HashMap<String, Value>) {
        let split_limb_values: Vec<Vec<Integer>> = Self::value_to_chunks(value, limb_width, n_limbs, subtable_bitwidth);
        // map_field_double_vec(split_limb_values, "limbs", input_map);
        Self::alloc_chunks(split_limb_values, name, input_map);
    }

    /// Allocate a big number to the circuit; Difference from alloc_from_integer: we does not consider limb_width here; n_bits is the number of bits required by this number
    pub fn alloc_one_integer(value: &Integer, n_bits: usize, subtable_bitwidth: usize, name: &str, input_map: &mut HashMap<String, Value>) {
        let chunks: Vec<Integer> = Self::one_value_to_chunks(value.clone(), n_bits, subtable_bitwidth);
        map_field_vec(chunks, name, input_map);
    }
}

/// Check left = quotient * modul + remainder where v = quotient * modul
pub struct BigNatModAdv {
    /// left hand side
    pub left: BigNatWithLimbMax,
    /// The polynomial multiplication of quotient and modul
    pub v: BigNatWithLimbMax,
    /// Quotient,
    pub quotient: BigNatWithLimbMax,
    /// Boolean double array used to check modular multiplicato
    pub carry: Vec<BigNatCarryInit>, // CarryType, // Vec<Vec<bool>>,
}

impl BigNatModAdv {
    /// Create a new BigNatModAdv instance
    pub fn new(left: &BigNatWithLimbMax, modul: &BigNatWithLimbMax, remainder: &BigNatWithLimbMax, quotient_bits: usize, limbs_per_gp: usize) -> Self {
        let n_limbs = modul.params.n_limbs;
        let limbwidth = modul.params.limb_width;
        assert!(left.params.limb_width == modul.params.limb_width);
        let quotient_val: Integer = (left.value.clone().unwrap() - remainder.value.clone().unwrap()) / modul.value.clone().unwrap(); // left.value.clone().zip(modul.value.clone()).map(|(z, q)| z / q).unwrap();
        let quotient_upper_bound: Integer = (Integer::from(1) << quotient_bits) - 1;
        let quotient = BigNatWithLimbMax::new_with_upper_bound(&quotient_val, limbwidth, n_limbs+1, quotient_upper_bound);
        assert!(left.value.clone().unwrap() == quotient_val.clone() * modul.value.clone().unwrap() + remainder.value.clone().unwrap());
        let v = quotient.create_product_nat(modul);
        let right = v.create_addition_nat(&remainder); // quotient * modul + remainder
        let group_right = right.group_limbs(limbs_per_gp, None);
        let group_left = left.group_limbs(limbs_per_gp, None);

        let carry = group_left.create_postgp_carry_adv(&group_right);

        let bp = Self {
            left: left.clone(),
            v: v,
            quotient: quotient, // newly added
            carry: carry,
        };
        bp
    }  
    /// Create a new BigNatModAdv instance with a list of larger maxwords
    pub fn new_with_maxword(left: &BigNatWithLimbMax, modul: &BigNatWithLimbMax, remainder: &BigNatWithLimbMax, maxword_vec: &Vec<Integer>, quotient_bits: usize, limbs_per_gp: usize) -> Self {
        let n_limbs = modul.params.n_limbs;
        let limbwidth = modul.params.limb_width;
        assert!(left.params.limb_width == modul.params.limb_width);
        let quotient_val: Integer = (left.value.clone().unwrap() - remainder.value.clone().unwrap()) / modul.value.clone().unwrap(); // left.value.clone().zip(modul.value.clone()).map(|(z, q)| z / q).unwrap();
        let quotient_upper_bound: Integer = (Integer::from(1) << quotient_bits) - 1;
        let quotient = BigNatWithLimbMax::new_with_upper_bound(&quotient_val, limbwidth, n_limbs+1, quotient_upper_bound);
        assert!(left.value.clone().unwrap() == quotient_val.clone() * modul.value.clone().unwrap() + remainder.value.clone().unwrap());
        let v = quotient.create_product_nat(modul);
        let right = v.create_addition_nat(&remainder); // quotient * modul + remainder
        let group_right = right.group_limbs(limbs_per_gp, None);
        let group_left = left.group_limbs(limbs_per_gp, None);

        let carry = group_left.create_postgp_carry_adv_w_maxwords(&group_right, maxword_vec.clone());

        let bp = Self {
            left: left.clone(),
            v: v,
            quotient: quotient, // newly added
            carry: carry,
        };
        bp
    }  
    /// Allocate BigNatModAdv instance to the circuit with advanced range check (corresponding to BigNatModMultwores_init in zokrates)
    pub fn alloc_adv(&self, product: &BigNatWithLimbMax, subtable_bitwidth: usize, name: &str, input_map: &mut HashMap<String, Value>) {
        let append: String = if name.is_empty() {name.to_owned()} else {name.to_owned()+"."};
        product.alloc_from_nat(&format!("{}z", append), input_map); 
        self.v.alloc_from_nat(&format!("{}v", append), input_map); // same as before
        self.quotient.alloc_quotient_adv(subtable_bitwidth, &format!("{}quotient_init", append), input_map);
        CarryType::CarryAdv(self.carry.clone()).alloc_carry_adv(subtable_bitwidth, name, input_map);
    }
}

#[derive(Clone, PartialEq, Eq)]
/// Check a * b = quotient * modul + remainder
pub struct BigNatModMultadv {
    /// left-hand side: The polynomial multiplication of a and b
    pub z: BigNatWithLimbMax,
    /// The polynomial multiplication of quotient and modul
    pub v: BigNatWithLimbMax,
    /// Quotient
    pub quotient: BigNatWithLimbMax,
    /// Should be BigNat_init
    pub carry: Vec<BigNatCarryInit>,
    /// Remainder
    pub remainder: Option<BigNatWithLimbMax>,
}

impl BigNatModMultadv {
    /// Create a new BigNatModMultadv instance; Similar to BigNatModMultWithLimbMax except with fewer elements
    pub fn new(
        a: &BigNatWithLimbMax, 
        b: &BigNatWithLimbMax, 
        modul: &BigNatWithLimbMax, 
        quotient_bits: usize, 
        limbs_per_gp: usize
    ) -> Self {
        let n_limbs = modul.params.n_limbs;
        let limbwidth = modul.params.limb_width;
        let z = a.create_product_nat(b);

        let quotient_val: Integer = z.value.clone().zip(modul.value.clone()).map(|(z, q)| z / q).unwrap();
        let quotient_upper_bound: Integer = (Integer::from(1) << quotient_bits) - 1;
        let quotient = BigNatWithLimbMax::new_with_upper_bound(&quotient_val, limbwidth, n_limbs+1, quotient_upper_bound); // assuming the quotient requires `n_limbs+1` limbs
        let v = quotient.create_product_nat(modul);
        let remainder_val: Integer = z.value.clone().zip(modul.value.clone()).map(|(z, q)| z % q).unwrap();
        let remainder = BigNatWithLimbMax::new(&remainder_val, limbwidth, n_limbs, false);
        let right = v.create_addition_nat(&remainder); // quotient * modul + remainder

        let group_right = right.group_limbs(limbs_per_gp, None);
        let group_z = z.group_limbs(limbs_per_gp, None);

        let carry = group_z.create_postgp_carry_adv(&group_right);

        let bp = Self {
            z: z,
            v: v,
            quotient: quotient,
            carry: carry,
            remainder: Some(remainder), // if include_remainder {Some(remainder)} else {None},
        };
        bp
    }

    /// Allocate BigNatModMultAdv instance to the circuit with advanced range check (corresponding to BigNatModMultadv in zokrates)
    pub fn alloc_adv(&self, subtable_bitwidth: usize, includ_remainder: bool, name: &str, input_map: &mut HashMap<String, Value>) {
        let prepend: String = if name.is_empty() {name.to_owned()} else {name.to_owned()+"."};
        self.z.alloc_from_nat(&format!("{}z", prepend), input_map); 
        self.v.alloc_from_nat(&format!("{}v", prepend), input_map); // same as before
        self.quotient.alloc_quotient_adv(subtable_bitwidth, &format!("{}quotient_init", prepend), input_map);
        CarryType::CarryAdv(self.carry.clone()).alloc_carry_adv(subtable_bitwidth, name, input_map);
        if includ_remainder {
            match &self.remainder {
                Some(remainder) => {
                    remainder.alloc_adv(subtable_bitwidth, &format!("{}res_init", prepend), input_map); // not sure
                }
                None => {}
            }
        }
    }
}