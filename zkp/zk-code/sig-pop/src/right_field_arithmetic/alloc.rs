use super::convert::{integer_to_field}; // ARC_MOD_T256, ARC_MOD_SECQ256K1, 
use std::sync::Arc;
use crate::ir::term::{Value};
use rug::Integer;
use fxhash::FxHashMap as HashMap;


/// Allocate a `field` element to the circuit.
pub fn map_field(input: &Integer, modulus: &Arc<Integer>, name: &str, input_map: &mut HashMap::<String, Value>) {
    input_map.insert(name.to_string(), integer_to_field(input, modulus.clone()));
}

/// Allocate each element in a `field` vec to the circuit.
pub fn map_field_vec(vec: &Vec<Integer>, modulus: &Arc<Integer>, name: &str, input_map: &mut HashMap::<String, Value>) {
    for (i, value) in vec.iter().enumerate() {
        input_map.insert(format!("{}.{}", name, i), integer_to_field(value, modulus.clone()));
    }
}

/// Allocate each element in a `field` double vec to the circuit.
pub fn map_field_double_vec(double_vec: &Vec<Vec<Integer>>, modulus: &Arc<Integer>, name: &str, input_map: &mut HashMap::<String, Value>) {
    for (i, vec) in double_vec.iter().enumerate() {
        map_field_vec(&vec, modulus, &format!("{}.{}", name, i), input_map);
    }
}
