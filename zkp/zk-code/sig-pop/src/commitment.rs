//! This module includes implementations related to Poseidon hash
use crate::convert::integer_to_field;
use crate::ecdsa::convert::{scalar_to_integer}; //, integer_to_scalar};
use crate::ecdsa::ecdsa::{P256Point};

// use crate::convert::{os2ip, vec_int_to_vec_u16, vec_int_to_vec_u32, vec_int_to_vec_u64};
// use openssl::hash::{MessageDigest, hash};
use rug::Integer;
// use crate::bignat::{create_limb_values};
use fxhash::FxHashMap as HashMap;
use crate::ir::term::{Value};
use crate::poseidon_const::{DEFAULT_MODULUS, POSEIDON_C, POSEIDON_M};
// use crate::parse_zokrates::{read_double_array, read_triple_array};
use p256::{Scalar, ProjectivePoint};
use crate::zkconst::MAX_BITWIDTH;
use rand_core::RngCore;
use elliptic_curve::Field;

use crate::conditional_print;

// The `ark` function in Rust.
fn ark(state: &mut Vec<Integer>, c: &Vec<Integer>, it: usize) {
    for i in 0..state.len() {
        state[i] = (state[i].clone() + c[it + i].clone()) % DEFAULT_MODULUS.clone();
    }
}

// The `sbox` function in Rust.
fn sbox(state: &mut Vec<Integer>, f: usize, p: usize, r: usize) {
    state[0] = state[0].clone().pow_mod(&Integer::from(5), &DEFAULT_MODULUS).unwrap();
    for i in 1..state.len() {
        if r < f / 2 || r >= f / 2 + p {
            state[i] = state[i].clone().pow_mod(&Integer::from(5), &DEFAULT_MODULUS).unwrap();
        }
    }
}

// The `mix` function in Rust.
fn mix(state: &Vec<Integer>, m: &Vec<Vec<Integer>>) -> Vec<Integer> {
    let n = state.len();
    let mut out = vec![Integer::new(); n];

    for i in 0..n {
        let mut acc = Integer::new();
        for j in 0..n {
            acc = (acc.clone() + state[j].clone() * m[i][j].clone()) % DEFAULT_MODULUS.clone();
        }
        out[i] = acc;
    }

    out
}

// The `main` function in Rust.
// fn poseidon_hash(inputs: Vec<Integer>, poseidon_c: Vec<Vec<Integer>>, poseidon_m: Vec<Vec<Vec<Integer>>>) -> Integer {
pub fn poseidon_hash(inputs: Vec<Integer>) -> Integer {
    let n: usize = inputs.len();
    assert!(n > 0 && n <= 6); // max 6 inputs

    let t = n + 1;
    let rounds_p: Vec<usize> = vec![56, 57, 56, 60, 60, 63, 64, 63];

    let f = 8;
    let p = rounds_p[t - 2];

    let c: Vec<Integer> = POSEIDON_C[t - 2].to_vec();
    let m: Vec<Vec<Integer>> = POSEIDON_M[t - 2].to_vec();

    let mut state = vec![Integer::new(); t];
    for i in 1..t {
        state[i] = inputs[i - 1].clone();
    }

    for r in 0..f + p {
        ark(&mut state, &c, r * t);
        sbox(&mut state, f, p, r);
        state = mix(&state, &m);
    }

    state[0].clone()
}

/// Commit to scalar
pub fn commit_to_scalar(scalar: Integer, opening: Integer, window_size: usize, n_chunks: usize) -> Integer {
    let mut input = vec![opening.clone()];
    let shift: usize = if 256 % window_size == 0 {
        window_size*(n_chunks-1)
    } else {
        window_size*(n_chunks-2) + (256%window_size)
    };
    conditional_print!("n_chunks = {}", n_chunks);
    input.push(scalar.clone() % (Integer::from(1) << shift));
    input.push(scalar.clone() >> shift);
    return Poseidon::new(input).output;
}


/// Commit to point
pub fn commit_to_point(point: P256Point, opening: Integer, limb_width: usize, n_limbs: usize) -> Integer {
    let mut input = vec![opening.clone()];
    let base = Integer::from(1) << limb_width;
    input.push((point.y.clone() >> (limb_width*(n_limbs-1)))*base + (point.x.clone() >> (limb_width*(n_limbs-1))));
    input.push(point.x.clone() % (Integer::from(1) << (limb_width*(n_limbs-1))));
    input.push(point.y.clone() % (Integer::from(1) << (limb_width*(n_limbs-1))));
    return Poseidon::new(input).output;
}

fn ceil_div(a: usize, b: usize) -> usize {
    (a + b - 1) / b
}

fn zero_pad(inputs: Vec<Integer>, padded_size: usize) -> Vec<Integer>{
    let n: usize = inputs.len();
    assert!(padded_size >= n);
    let mut padded = vec![Integer::from(0); padded_size];
    for i in 0..n {
        padded[i] = inputs[i].clone();
    }
    padded
}


pub fn pack_words(inputs: Vec<Integer>) -> Integer {
    let mut base: Integer = Integer::from(1);
    //each elem is a byte
    let shift: Integer = Integer::from(256);
    let mut output: Integer = Integer::from(0);
    for input in inputs{
        output = output + input * base.clone();
        base = base * shift.clone();
    }
    output
}

pub fn pack_vector(inputs: Vec<Integer>, new_size: usize, old_size: usize) -> Vec<Integer>{
    let n: usize = inputs.len();
    let words_per_field: usize = new_size / old_size;
    let outsize: usize = ceil_div(n,words_per_field);
    let padded_size: usize = outsize * words_per_field;
    let padded_inputs: Vec<Integer> = zero_pad(inputs, padded_size);
    let mut out = vec![Integer::from(0); outsize];

    for i in 0..outsize{
        out[i] = pack_words(padded_inputs[words_per_field*i..words_per_field*(i+1)].to_vec());
    }
    out
}


/// Params for describing a Poseidon hashing
pub struct Poseidon {
    /// Input to the Poseidon hashing
    pub input: Vec<Integer>,
    /// Digest result
    pub output: Integer,
}

impl Poseidon {
    /// Create a new instance of Poseidon
    pub fn new(input: Vec<Integer>) -> Self {
        Self {
            input: input.clone(),
            output: poseidon_hash(input.clone()),
        }
    }

    /// Poseidon commitment to three exponents; to test
    pub fn commit_to_three_exp(exponents: [Integer; 3], opening: Integer, limb_width: usize) -> Integer { //Self {
        assert!(limb_width == 32);
        let mut poseidon_input: Vec<Integer> = Vec::new();
        let mut remain_expo: Integer = Integer::from(0); // combine the last limb of the three exponents together
        let first_bitwidth: usize = (MAX_BITWIDTH / limb_width) * limb_width;
        assert!(first_bitwidth == 224);
        for (i, expo) in exponents.iter().enumerate() {
            let remain: Integer = expo.clone() >> first_bitwidth;
            remain_expo = remain_expo.clone() + (remain.clone() << (i*limb_width));
            poseidon_input.push(expo.clone() - (remain.clone()<<first_bitwidth));
        }
        poseidon_input.push(remain_expo.clone());
        poseidon_input.push(opening.clone());
        poseidon_hash(poseidon_input)
    }
    /// Alloc a bunch of commitments and openings
    pub fn alloc(commitments: Vec<Integer>, openings: Vec<Integer>, name: &str, input_map: &mut HashMap<String, Value>) {
        let append: String = if name.is_empty() {name.to_owned()} else {name.to_owned()+"."};
        for (i, value) in commitments.iter().enumerate() {
            input_map.insert(format!("{}commitments.{}", append, i), integer_to_field(value));
        }
        for (i, value) in openings.iter().enumerate() {
            input_map.insert(format!("{}openings.{}", append, i), integer_to_field(value));
        }
    }

    /// Alloc a bunch of commitments
    pub fn alloc_commitments(commitments: Vec<Integer>, name: &str, input_map: &mut HashMap<String, Value>) {
        let append: String = if name.is_empty() {name.to_owned()} else {name.to_owned()+"."};
        for (i, value) in commitments.iter().enumerate() {
            input_map.insert(format!("{}commitments.{}", append, i), integer_to_field(value));
        }
    }


}


/// Commitment to a P256 point
pub struct P256Commit { // Commit(P, o) = (HCommit(v, o), P K^v); We do not compute HCommit(v, o) here because we want to commit the scalars at once
    /// v, Opening to comm 
    pub opening: Integer,
    /// Second part of the commitment (an EC point)
    pub comm: ProjectivePoint,
}

impl P256Commit {
    /// Commit to an P256 Point
    pub fn new(point: ProjectivePoint, base_point: ProjectivePoint, mut rng: impl RngCore) -> Self {
        // let v: Scalar = integer_to_scalar(&Integer::from(56)); // need fix
        let v: Scalar = Scalar::random(&mut rng);
        let comm: ProjectivePoint = (base_point * v) + point; // not sure
        Self {
            opening: scalar_to_integer(&v),
            comm: comm,
        }
    }
}

/// Commitment to ProjectivePoint
pub struct PointCommit {
    /// v, Opening to comm 
    pub opening: Scalar,
    /// El-Gamal-like commitment (two EC point)
    pub comm: [ProjectivePoint; 2],
}

impl PointCommit {
    /// Commit to an EC point
    pub fn new(point: &ProjectivePoint, pp: &[ProjectivePoint; 2], mut rng: impl RngCore) -> Self {
        let v: Scalar = Scalar::random(&mut rng);
        Self {
            opening: v,
            comm: [pp[0] * v, pp[1] * v + point],
        }
    }
}