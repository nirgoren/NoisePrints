//! Check that the R1CS is satisfied by the given witness and instance.
use crate::target::r1cs::*;
use rug::Integer;
use std::sync::Arc;
use circ_fields::FieldT::IntField;

/// Change the prime field used in Lc (from prime field of t256 to prime field of curve25519)
fn update_modulus(lc: &mut Lc, new_modulus: &Arc<Integer>) {
    lc.modulus = IntField(new_modulus.clone());
    lc.constant.update_modulus(new_modulus.clone());
    for (_, fieldv) in &mut lc.monomials {
        fieldv.update_modulus(new_modulus.clone());
    }
}

fn inner_product(lc: &Lc, values: &HashMap<Var, FieldV>) -> FieldV { // inner product of a row in r1cs matrix and z
    let mut acc = lc.constant.clone(); // lc.constant.clone() * the entry with value 1 in z
    
    for (var, coeff) in &lc.monomials {

        let val = values // an entry in z
            .get(var)
            .unwrap_or_else(|| panic!("Missing value in R1cs::eval for variable {:?}", var))
            .clone();
        acc += val * coeff;
    }
    acc
}

/// Convert values in prime field of t256 to that in prime field of curve25519
pub fn convert_values(values: &mut Vec<FieldV>, new_modulus: &Arc<Integer>) {
    for fieldv in values.iter_mut() {
        fieldv.update_modulus(new_modulus.clone());
    }
}

/// Convert a r1cs instances in t256 to a r1cs instances in curve25519
pub fn convert_r1cs(
    r1cs_inst: &mut Vec<(Lc, Lc, Lc)>,
    values: &mut HashMap<Var, FieldV>,
    new_modulus: &Arc<Integer>,
) {
    // Change entries in values to the field element in the prime field of curve25519
    for (_, fieldv) in values.iter_mut() {
        fieldv.update_modulus(new_modulus.clone());
    }

    for (lc_a, lc_b, lc_c) in r1cs_inst.iter_mut() { // a row in matric A, B, C
        // Change entries in r1cs_inst to the field element in the prime field of curve25519
        update_modulus(lc_a, new_modulus);
        update_modulus(lc_b, new_modulus);
        update_modulus(lc_c, new_modulus);
        let av = inner_product(lc_a, &values);
        let bv = inner_product(lc_b, &values);
        let cv = inner_product(lc_c, &values);
        let new_c_entry = (av.clone() * &bv) - cv.clone() + lc_c.constant.clone(); // imply cv - lc_c.constant.clone() + new_c_entry = av*bv
        lc_c.constant.update_val(new_c_entry.i()); // Compute the new column for matrix C
    }
}

fn update_lc_c(
    lc_a: &Lc,
    lc_b: &Lc,
    lc_c: &mut Lc,
    values: &HashMap<Var, FieldV>,
    new_modulus: &Integer,
) {
    let av = inner_product(lc_a, &values);
    let bv = inner_product(lc_b, &values);
    let cv = inner_product(lc_c, &values);
    let mut update: bool = false;
    if lc_c.constant.is_zero() {
        for (var, fieldv) in &mut lc_c.monomials {
            if !fieldv.is_zero() {
                let val = values // an entry in z
                    .get(var)
                    .unwrap_or_else(|| panic!("Missing value in R1cs::eval for variable {:?}", var))
                    .clone();
                if !val.is_zero() {
                    assert!(!update, "Error: more than one non-zero entry in z");
                    let val_inv: Integer = val.i().invert(&new_modulus).unwrap();
                    // println!("fieldv {:?}", fieldv);
                    let mut field_val_inv = fieldv.clone();
                    field_val_inv.update_val(val_inv);
                    // println!("fieldv {:?}", fieldv);
                    let new_c_entry = ((av.clone() * &bv) - cv.clone() + (fieldv.clone() * &val)).clone() * &field_val_inv; 
                    fieldv.update_val(new_c_entry.i()); // Compute the new column for matrix C
                    update = true;
                    break;
                } 
            }
        }
    }

    if !update { // the corresponding entry of z is always 1
        let new_c_entry = (av.clone() * &bv) - cv.clone() + lc_c.constant.clone(); // imply cv - lc_c.constant.clone() + new_c_entry = av*bv
        lc_c.constant.update_val(new_c_entry.i()); // Compute the new column for matrix C
        update = true;
    } 
    assert!(update, "Error: lc is not updated");
}
/// Convert a r1cs instances in t256 to a r1cs instances in curve25519
pub fn convert_r1cs_v2(
    r1cs_inst: &mut Vec<(Lc, Lc, Lc)>,
    values: &mut HashMap<Var, FieldV>,
    new_modulus: &Arc<Integer>,
) {
    // Change entries in values to the field element in the prime field of curve25519
    for (_, fieldv) in values.iter_mut() {
        fieldv.update_modulus(new_modulus.clone());
    }

    for (lc_a, lc_b, lc_c) in r1cs_inst.iter_mut() { // a row in matric A, B, C
        // Change entries in r1cs_inst to the field element in the prime field of curve25519
        update_modulus(lc_a, new_modulus);
        update_modulus(lc_b, new_modulus);
        update_modulus(lc_c, new_modulus);
        update_lc_c(lc_a, lc_b, lc_c, values, &new_modulus);
        // Below for debug purpose
        let av = inner_product(lc_a, &values);
        let bv = inner_product(lc_b, &values);
        let cv = inner_product(lc_c, &values);
        assert!(av.clone() * &bv == cv);
    }
}