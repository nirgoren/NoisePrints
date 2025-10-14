//! This module includes functions related to preprocess data
use std::fs::{OpenOptions, File}; 
use std::io::{BufRead, BufReader, Result, Write};
use crate::bignat::bignatwithlimbmax::BigNatWithLimbMax;
use crate::bignat::bignatwithlimbmax::FIELD_MOD;

use rug::Integer;
use crate::ecdsa::ecdsa::{BigNatPoint, P256Point};

/// Check if the values are defined in the file
pub fn is_values_defined_in_file(search_str: &str, file_path: &str) -> bool {
    if let Ok(file) = File::open(file_path) {
        let reader = BufReader::new(file);
        for line in reader.lines() {
            if let Ok(line) = line {
                if line.contains(search_str) {
                    let term_before_equal = line.split_whitespace().nth(2).unwrap();
                    println!("{}", term_before_equal);
                    return true;
                }
            }
        }
    }
    false
}

/// Append the line in vec_write to the file in path `file_path`
pub fn write_to_file(vec_write: Vec<String>, file_path: &str) -> Result<()> {
    println!("Writing to {}", file_path);
    // open the file
    let mut file = OpenOptions::new()
                    .append(true)
                    .create(true)
                    .open(file_path)
                    .expect("cannot open file");
    for line in vec_write {
        // Write each line to the file
        writeln!(file, "{}", line)?;
    }

    Ok(())
}


/// Convert Vec<Integer> to str
pub fn vec_int_to_str(vec_int: Vec<Integer>) -> String {
    let vec_str: Vec<String> = vec_int.iter()
        .map(|num| num.to_string())
        .collect();
    let joined_str = vec_str.join(", ");
    let vec_as_str: String = format!("[{}]", joined_str);
    vec_as_str
}

/// Convert Vec<usize> to str
pub fn vec_usize_to_str(vec_usize: Vec<usize>) -> String {
    let vec_str: Vec<String> = vec_usize.iter()
        .map(ToString::to_string)
        .collect();
    let joined_str = vec_str.join(", ");
    let vec_as_str: String = format!("[{}]", joined_str);
    vec_as_str
}

/// Convert BigNatWithLimbMax to str
pub fn bignat_to_str(bignat: BigNatWithLimbMax) -> String {
    let vec_as_str: String = format!("BigNat {{limbs: {}}}", vec_int_to_str(bignat.limb_values.unwrap()));
    vec_as_str
}

/// Convert BigNatPoint to str
pub fn bignatpoint_to_str(point: BigNatPoint) -> String {
    let x_vec_as_string: String = bignat_to_str(point.x);
    let y_vec_as_string: String = bignat_to_str(point.y);
    let vec_as_str: String = format!("ECPoint_v2 {{ x: {}, y: {}, empty: {}}}", x_vec_as_string, y_vec_as_string, point.empty);
    vec_as_str
}

/// Convert Vec<BigNatWithLimbMax> to str
pub fn vec_bignat_to_str(vec_bignat: Vec<BigNatWithLimbMax>) -> String {
    let vec_str: Vec<String> = vec_bignat.iter()
        .map(|vec| bignat_to_str(vec.clone())) 
        .collect();
    let joined_str = vec_str.join(", ");
    let vec_as_str: String = format!("[{}]", joined_str);
    vec_as_str
}

/// Convert Vec<BigNatPoint> to str
pub fn vec_point_to_str(vec_point: Vec<BigNatPoint>) -> String {
    let vec_str: Vec<String> = vec_point.iter()
        .map(|vec| bignatpoint_to_str(vec.clone()))
        .collect();
    let joined_str = vec_str.join(", ");
    let vec_as_str: String = format!("[{}]", joined_str);
    vec_as_str
}

/// Convert Vec<Vec<BigNatPoint>> to str
pub fn double_vec_point_to_str(double_vec_point: Vec<Vec<BigNatPoint>>) -> String {
    let vec_str: Vec<String> = double_vec_point.iter()
        .map(|vec| vec_point_to_str(vec.clone()))
        .collect();
    let joined_str = vec_str.join(", ");
    let double_vec_as_str: String = format!("[{}]", joined_str);
    double_vec_as_str
}


/// Convert Vec<BigNatPoint> to str (w/o empty variable)
pub fn vec_point_to_plain_str(vec_point: Vec<BigNatPoint>) -> String {
    let vec_str: Vec<String> = vec_point.iter()
        .map(|vec| bignatpoint_to_plain_str(vec.clone())) 
        .collect();
    let joined_str = vec_str.join(", ");
    let vec_as_str: String = format!("[{}]", joined_str);
    vec_as_str
}

/// Convert Vec<Vec<BigNatPoint>> to str
pub fn double_vec_point_to_plain_str(double_vec_point: Vec<Vec<BigNatPoint>>) -> String {
    let vec_str: Vec<String> = double_vec_point.iter()
        .map(|vec| vec_point_to_plain_str(vec.clone()))
        .collect();
    let joined_str = vec_str.join(", ");
    let double_vec_as_str: String = format!("[{}]", joined_str);
    double_vec_as_str
}

/// Convert BigNatPoint to str (w/o empty variable)
pub fn bignatpoint_to_plain_str(point: BigNatPoint) -> String {
    let x_vec_as_string: String = vec_int_to_str(point.x.limb_values.unwrap()); 
    let y_vec_as_string: String = vec_int_to_str(point.y.limb_values.unwrap());
    if point.empty {
        println!("Point is empty!");
    }
    let vec_as_str: String = format!("ECPoint_plain {{ x: {}, y: {}}}", x_vec_as_string, y_vec_as_string);
    vec_as_str
}


/// Convert P256Point to str (w/o empty variable) ; Note: for estimating the saving only
pub fn p256point_to_str(point: &P256Point) -> String {
    if (point.x.clone() >= FIELD_MOD.clone()) || (point.y.clone() >= FIELD_MOD.clone()) {
        println!("{:?} exceed the field", point.clone());
    }
    let x: Integer = point.x.clone() % FIELD_MOD.clone();
    let y: Integer = point.y.clone() % FIELD_MOD.clone();
    let x_as_str: String = x.to_string();
    let y_as_str: String = y.to_string();
    let point_as_str: String = format!("ECPoint_Fp {{ x: {}, y: {}}}", x_as_str, y_as_str);
    point_as_str
}

/// Convert Vec<String> to String
pub fn vec_str_to_str(vec_str: &Vec<String>) -> String {
    let joined_str = vec_str.join(", ");
    let vec_as_str: String = format!("[{}]", joined_str);
    vec_as_str 
}
/// Convert Vec<P256Point> to str (w/o empty variable)
pub fn vec_p256point_to_str(vec_point: &Vec<P256Point>) -> String {
    let vec_str: Vec<String> = vec_point.iter()
        .map(|point| p256point_to_str(&point)) 
        .collect();
    vec_str_to_str(&vec_str)
}

/// Convert Vec<Vec<P256Point>> to str
pub fn double_vec_p256point_to_str(double_vec_point: &Vec<Vec<P256Point>>) -> String {
    let vec_str: Vec<String> = double_vec_point.iter()
        .map(|vec| vec_p256point_to_str(&vec))
        .collect();
    vec_str_to_str(&vec_str)
}