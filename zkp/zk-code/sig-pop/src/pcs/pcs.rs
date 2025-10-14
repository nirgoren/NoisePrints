/// run_zk example
use fxhash::FxHashMap as HashMap;
use crate::ir::term::Value;
use crate::convert::integer_to_field;
use crate::convert::str_to_field;
use std::fs::read_to_string;
use rug::{Integer, rand::RandState};
use crate::commitment::{poseidon_hash, pack_vector};
use crate::convert::rand_int;
// https://doc.rust-lang.org/rust-by-example/std_misc/file/read_lines.html
fn read_lines(filename: &str) -> Vec<String> {
    let mut result = Vec::new();
    for line in read_to_string(filename).unwrap().lines() {
        result.push(line.to_string())
    }
    result
}


pub fn prover_circuit1(x: String) -> HashMap<String, Value> {
    let contents = read_lines(&x);
    let mut map = HashMap::<String, Value>::default();

    let counter = &contents[0];
    map.insert(format!("counter"), str_to_field(&counter.clone()));

    let seed1 = &contents[1];
    map.insert(format!("seed1"), str_to_field(&seed1.clone()));

    let vec2_mag = &contents[2][1..contents[2].len() - 1];
    let vec2_mag_items: Vec<&str> = vec2_mag.split(',').collect();
    
    for (index, word) in vec2_mag_items.iter().enumerate()  {
        map.insert(format!("vec2_mag.{}", index), str_to_field(&word.clone()));
    }
    
    let vec2_sign = &contents[3][1..contents[3].len() - 1];
    let vec2_sign_items: Vec<&str> = vec2_sign.split(',').collect();
    
    for (index, word) in vec2_sign_items.iter().enumerate()  {
        map.insert(format!("vec2_sign.{}", index), str_to_field(&word.clone()));
    }

    let commitment = &contents[4];
    map.insert(format!("commitment"), str_to_field(&commitment.clone()));

    let randomness = &contents[5];
    map.insert(format!("randomness"), str_to_field(&randomness.clone()));

    map
}

pub fn verifier_circuit1(x: String) -> HashMap<String, Value> {
    let contents = read_lines(&x);
    let mut map = HashMap::<String, Value>::default();

    let counter = &contents[0];
    map.insert(format!("counter"), str_to_field(&counter.clone()));

    // let seed1 = &contents[1];
    // map.insert(format!("seed1"), str_to_field(&seed1.clone()));

    let vec2_mag = &contents[2][1..contents[2].len() - 1];
    let vec2_mag_items: Vec<&str> = vec2_mag.split(',').collect();
    
    for (index, word) in vec2_mag_items.iter().enumerate()  {
        map.insert(format!("vec2_mag.{}", index), str_to_field(&word.clone()));
    }
    
    let vec2_sign = &contents[3][1..contents[3].len() - 1];
    let vec2_sign_items: Vec<&str> = vec2_sign.split(',').collect();
    
    for (index, word) in vec2_sign_items.iter().enumerate()  {
        map.insert(format!("vec2_sign.{}", index), str_to_field(&word.clone()));
    }

    let commitment = &contents[4];
    map.insert(format!("commitment"), str_to_field(&commitment.clone()));

    // let randomness = &contents[5];
    // map.insert(format!("randomness"), str_to_field(&randomness.clone()));

    map
}

pub fn prover_circuit2(x: String) -> HashMap<String, Value> {
    let contents = read_lines(&x);
    let mut map = HashMap::<String, Value>::default();

    let all_commitments = &contents[0][1..contents[0].len() - 1];
    let all_commitments_items: Vec<&str> = all_commitments.split(',').collect();
    
    for (index, word) in all_commitments_items.iter().enumerate()  {
        map.insert(format!("all_commitments.{}", index), str_to_field(&word.clone()));
    }
    
    let all_randomness = &contents[1][1..contents[1].len() - 1];
    let all_randomness_items: Vec<&str> = all_randomness.split(',').collect();
    
    for (index, word) in all_randomness_items.iter().enumerate()  {
        map.insert(format!("all_randomness.{}", index), str_to_field(&word.clone()));
    }

    let all_dot_product = &contents[2][1..contents[2].len() - 1];
    let all_dot_product_items: Vec<&str> = all_dot_product.split(',').collect();
    
    for (index, word) in all_dot_product_items.iter().enumerate()  {
        map.insert(format!("all_dot_product.{}", index), str_to_field(&word.clone()));
    }

    let all_mag1_sq = &contents[3][1..contents[3].len() - 1];
    let all_mag1_sq_items: Vec<&str> = all_mag1_sq.split(',').collect();
    
    for (index, word) in all_mag1_sq_items.iter().enumerate()  {
        map.insert(format!("all_mag1_sq.{}", index), str_to_field(&word.clone()));
    }

    let mag1_sq_root = &contents[4];
    map.insert(format!("mag1_sq_root"), str_to_field(&mag1_sq_root.clone()));

    let cosine_angle = &contents[5];
    map.insert(format!("cosine_angle"), str_to_field(&cosine_angle.clone()));

    let mag2_sq_root = &contents[6];
    map.insert(format!("mag2_sq_root"), str_to_field(&mag2_sq_root.clone()));

    let threshold = &contents[7];
    map.insert(format!("threshold"), str_to_field(&threshold.clone()));
    map
}

pub fn verifier_circuit2(x: String) -> HashMap<String, Value> {
    let contents = read_lines(&x);
    let mut map = HashMap::<String, Value>::default();

    let all_commitments = &contents[0][1..contents[0].len() - 1];
    let all_commitments_items: Vec<&str> = all_commitments.split(',').collect();
    
    for (index, word) in all_commitments_items.iter().enumerate()  {
        map.insert(format!("all_commitments.{}", index), str_to_field(&word.clone()));
    }
    
    // let all_randomness = &contents[1][1..contents[1].len() - 1];
    // let all_randomness_items: Vec<&str> = all_randomness.split(',').collect();
    
    // for (index, word) in all_randomness_items.iter().enumerate()  {
    //     map.insert(format!("all_randomness.{}", index), str_to_field(&word.clone()));
    // }

    // let all_dot_product = &contents[2][1..contents[2].len() - 1];
    // let all_dot_product_items: Vec<&str> = all_dot_product.split(',').collect();
    
    // for (index, word) in all_dot_product_items.iter().enumerate()  {
    //     map.insert(format!("all_dot_product.{}", index), str_to_field(&word.clone()));
    // }

    // let all_mag1_sq = &contents[3][1..contents[3].len() - 1];
    // let all_mag1_sq_items: Vec<&str> = all_mag1_sq.split(',').collect();
    
    // for (index, word) in all_mag1_sq_items.iter().enumerate()  {
    //     map.insert(format!("all_mag1_sq.{}", index), str_to_field(&word.clone()));
    // }

    // let mag1_sq_root = &contents[4];
    // map.insert(format!("mag1_sq_root"), str_to_field(&mag1_sq_root.clone()));

    // let cosine_angle = &contents[5];
    // map.insert(format!("cosine_angle"), str_to_field(&cosine_angle.clone()));

    let mag2_sq_root = &contents[6];
    map.insert(format!("mag2_sq_root"), str_to_field(&mag2_sq_root.clone()));

    let threshold = &contents[7];
    map.insert(format!("threshold"), str_to_field(&threshold.clone()));
    map
}
