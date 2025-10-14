//! This module includes methods that allocate variables to the circuits
use fxhash::FxHashMap as HashMap;
use crate::ir::term::Value;
use crate::convert::{str_to_field, bool_to_value, u8_to_value, u16_to_value, u32_to_value, u64_to_value, integer_to_field};
use rug::Integer;

/// Allocate a `bool` to the circuit.
#[allow(unused)]
pub fn map_bool(input: bool, name: &str, input_map: &mut HashMap::<String, Value>) {
    input_map.insert(format!("{}", name), bool_to_value(input.clone() as bool));
}

/// Allocate each element in a `bool` array to the circuit.
#[allow(unused)]
pub fn map_bool_arr(bool_arr: &[bool], name: &str, input_map: &mut HashMap::<String, Value>) {
    for (i, b) in bool_arr.iter().enumerate() {
        input_map.insert(format!("{}.{}", name, i), bool_to_value(b.clone() as bool));
    }
}

/// Allocate each element in a `bool` double array to the circuit.
pub fn map_bool_double_arr<DoubleArray: AsRef<[Row]>, Row: AsRef<[bool]>>(bool_double_arr: DoubleArray, name: &str, input_map: &mut HashMap::<String, Value>) {
    for (i, arr) in bool_double_arr.as_ref().iter().enumerate() {
        for (j, b) in arr.as_ref().iter().enumerate() {
            input_map.insert(format!("{}.{}.{}", name, i, j), bool_to_value(b.clone() as bool));
        }
    }
}

/// Allocate each element in a `bool` double vec to the circuit.
pub fn map_bool_double_vec(bool_double_vec: &Vec<Vec<bool>>, name: &str, input_map: &mut HashMap::<String, Value>) {
    for (i, vec) in bool_double_vec.iter().enumerate() {
        for (j, b) in vec.iter().enumerate() {
            input_map.insert(format!("{}.{}.{}", name, i, j), bool_to_value(*b));
        }
    }
}

/// Allocate each element in a `bool` double vec to the circuit.
pub fn map_bool_double_vec_to_single_vec(bool_double_vec: &Vec<Vec<bool>>, name: &str, input_map: &mut HashMap::<String, Value>) {
    let mut start = 0;
    for (_i, vec) in bool_double_vec.iter().enumerate() {
        for (j, b) in vec.iter().enumerate() {
            input_map.insert(format!("{}.{}", name, start+j), bool_to_value(*b));
        }
        start = start + vec.len();
    }
}


/// Allocate a u8 into the circuit
pub fn map_u8(input: u8, name: &str, input_map: &mut HashMap::<String, Value>) {
    input_map.insert(format!("{}", name), u8_to_value(input));
}


/// Allocate a u32 into the circuit
pub fn map_u32(input: u32, name: &str, input_map: &mut HashMap::<String, Value>) {
    input_map.insert(format!("{}", name), u32_to_value(input));
}

/// Allocate each element in a `u8` vector to the circuit.
pub fn map_u8_vec(vec: &[u8], name: &str, input_map: &mut HashMap::<String, Value>) {
    for (i, ele) in vec.iter().enumerate() {
        input_map.insert(format!("{}.{}", name, i), u8_to_value(ele.clone()));
    }
}

/// Allocate each element in a `u16` vector to the circuit.
pub fn map_u16_vec(vec: &[u16], name: &str, input_map: &mut HashMap::<String, Value>) {
    for (i, ele) in vec.iter().enumerate() {
        input_map.insert(format!("{}.{}", name, i), u16_to_value(ele.clone()));
    }
}

/// Allocate each element in a `u32` vector to the circuit.
pub fn map_u32_vec(vec: &[u32], name: &str, input_map: &mut HashMap::<String, Value>) {
    for (i, ele) in vec.iter().enumerate() {
        input_map.insert(format!("{}.{}", name, i), u32_to_value(ele.clone()));
    }
}

/// Allocate each element in a `u64` vector to the circuit.
pub fn map_u64_vec(vec: &[u64], name: &str, input_map: &mut HashMap::<String, Value>) {
    for (i, ele) in vec.iter().enumerate() {
        input_map.insert(format!("{}.{}", name, i), u64_to_value(ele.clone()));
    }
}


/// Allocate each element in a `u32` double vec to the circuit.
pub fn map_u32_double_vec(u32_double_vec: &Vec<Vec<u32>>, name: &str, input_map: &mut HashMap::<String, Value>) {
    for (i, vec) in u32_double_vec.iter().enumerate() {
        for (j, b) in vec.iter().enumerate() {
            input_map.insert(format!("{}.{}.{}", name, i, j), u32_to_value(*b));
        }
    }
}


/// Allocate each element in a `field` vec to the circuit.
pub fn map_field_vec(vec: Vec<Integer>, name: &str, input_map: &mut HashMap::<String, Value>) {
    for (i, value) in vec.iter().enumerate() {
        input_map.insert(format!("{}.{}", name, i), integer_to_field(value));
    }
}

/// Allocate each element in a `field` double vec to the circuit.
pub fn map_field_double_vec(double_vec: Vec<Vec<Integer>>, name: &str, input_map: &mut HashMap::<String, Value>) {
    for (i, vec) in double_vec.iter().enumerate() {
        for (j, value) in vec.iter().enumerate() {
            input_map.insert(format!("{}.{}.{}", name, i, j), integer_to_field(value));
        }
    }
}

#[allow(unused)]
/// Allocate each element in a `str` array to the circuit.
fn map_string_arr(str_arr: &[&str], name: &str, input_map: &mut HashMap::<String, Value>) {
    for (i, string) in str_arr.iter().enumerate() {
        input_map.insert(format!("{}.{}", name, i), str_to_field(&string));
    }
}

