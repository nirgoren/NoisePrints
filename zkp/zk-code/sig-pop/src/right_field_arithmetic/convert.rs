use std::sync::Arc;
use circ_fields::{FieldV}; // FieldT, 
use crate::ir::term::{Value}; // ,BitVector
use rug::Integer;



/// Converts Integer to a value in the scalar field
pub fn integer_to_field(big_int: &Integer, ark_modulus: Arc<Integer>) -> Value {
    Value::Field(FieldV::new(big_int, ark_modulus))
}
