/// input generattion for sigma protocol
use fxhash::FxHashMap as HashMap;

use crate::ir::term::Value;
use ed25519_dalek::{SigningKey,Signer,VerifyingKey};
use rand::SeedableRng;
//use rand_core0_5::RngCore;
use rug::{Integer, integer::Order};
use rug::ops::Pow;
use rand_core;
use rand;

use curve25519_dalek::edwards::{EdwardsPoint, CompressedEdwardsY};
use crate::eddsa::edwards25519::{CurveConfig, Edwards25519Pt, Ed25519Config};
use curve25519_dalek::scalar::Scalar;
use crate::convert::integer_to_field;
use sha2::{Sha512, Digest};
use rug::rand::RandState;
use crate::convert::rand_int;
use crate::commitment::Poseidon;
use merlin::Transcript;
use crate::convert::integer_to_bytes;
use itertools::Itertools;
use std::time::Instant;
use std::path::PathBuf;
use crate::target::r1cs::proof::{serialize_into_file, deserialize_from_file};
use serde::{Serialize, Deserialize};
use std::str::FromStr;
use curve25519_dalek;
use std::cell::{RefCell,Ref};
//use std::borrow::{Borrow, BorrowMut};

const Q_SIZE: usize = 253;

/// Commitment to a P256 point
pub struct Ed25519Commit { // Commit(P, o) = (HCommit(v, o), P K^v); We do not compute HCommit(v, o) here because we want to commit the scalars at once
    /// v, Opening to comm 
    pub opening: Scalar,
    /// Second part of the commitment (an EC point)
    pub comm: EdwardsPoint,
}

/// represent el gamal commit
impl Ed25519Commit {
    /// Commit to an ed25519 Point
    pub fn new(point: EdwardsPoint, base_point: EdwardsPoint, mut rng: impl rand_core::CryptoRngCore) -> Self {
        let opening = Scalar::random(&mut rng);
        Self {
            opening,
            comm: base_point * opening + point,
        }
    }
}


/// convert scalar to integer
fn scalar_to_integer(s: &Scalar) -> Integer {
    Integer::from_digits(s.as_bytes(), Order::LsfLe)
}

/// convert integer to scalar
fn integer_to_scalar(int: &Integer) -> Scalar {
    let mut bytes_array: [u8; 32] = [0; 32];
    for (i, byte) in int.to_digits::<u8>(Order::LsfLe).iter().enumerate() {
        bytes_array[i] = *byte; 
    }
    Scalar::from_canonical_bytes(bytes_array).unwrap()
}

fn shape_m(arr: &[u8]) -> Vec<Vec<Vec<Integer>>> {
    let nblocks = arr.len() / 128;
    let mut output = Vec::with_capacity(nblocks);
    for i in 0..nblocks {
        let mut block = Vec::with_capacity(16);
        for j in 0..16 {
            let mut u_64 = Integer::from(0);
            for k in 0..8 {
                u_64 += Integer::from(arr[128*i + 8*j + k]) * Integer::from(2).pow(8*(7-k) as u32);
            }
            block.push(integer_to_limbs_gen(u_64, &[7,7,7,7,11,11,11,3]));
        }
        output.push(block);
    }
    output
}

struct PublicParams {
    k: EdwardsPoint,
    g: EdwardsPoint,
}

impl PublicParams {
    fn new() -> Self {
        let k = Edwards25519Pt {
            x: Integer::from_str_radix("1762111443891090791368278727835417445876156968440962720682012045122899982082",10).unwrap(),
            y: Integer::from_str_radix("47240211860419521472386239205418660784548983831370547238086037072188890696733",10).unwrap(),
        }.to_edwards_point();
        PublicParams {
            k,
            g: curve25519_dalek::constants::ED25519_BASEPOINT_POINT,
        }
    }
}

/// public info for prover and verifier
#[derive(Serialize, Deserialize)]
struct Ed25519SigmaPublic {
    comm: [EdwardsPoint; 2],
    hcommit: [Integer; 2],
    pk: EdwardsPoint,
    responses_cell: RefCell<[Scalar; 3]>,
    #[serde(skip)]
    challenge: RefCell<Option<Scalar>>,
}


impl Ed25519SigmaPublic {
    /// create new public info
    fn new(comm: [EdwardsPoint; 2], hcommit: [Integer; 2], pk: EdwardsPoint) -> Ed25519SigmaPublic {
        Ed25519SigmaPublic {
            comm,
            hcommit,
            pk,
            responses_cell: Default::default(),
            challenge: Default::default(),
        }
    }

    /// fill in responses and return challenge
    fn fill_responses(&self, exponents: &[Scalar; 3], randexps: &[Scalar; 3]) {
        
        let challenge = self.challenge_scalar();  
        {
            let mut responses = self.responses_cell.borrow_mut();
            for (i, (exp, rexp)) in exponents.iter().zip(randexps.iter()).enumerate() {
                responses[i] = (exp * challenge) + rexp 
            }
        }
    }

    fn responses(&self) -> Ref<[Scalar; 3]> {
        self.responses_cell.borrow()
    }

    /// generate challenge scalar
    fn challenge_scalar(&self) -> Scalar {
        let early = self.challenge.borrow().is_some();
        if !early {
            let mut transcript = Transcript::new(b"eddsa_sigma");
            transcript.append_message(b"pk", self.pk.compress().as_bytes().as_slice());
            transcript.append_message(b"cm", &integer_to_bytes(&self.hcommit[0]));
            transcript.append_message(b"cm'", &integer_to_bytes(&self.hcommit[1]));
            transcript.append_message(b"C^{(1)}", self.comm[0].compress().as_bytes().as_slice());
            transcript.append_message(b"U", self.comm[1].compress().as_bytes().as_slice());
            let mut buf = [0; 64];
            transcript.challenge_bytes(b"challenge", &mut buf);
            *self.challenge.borrow_mut() = Some(Scalar::from_bytes_mod_order_wide(&buf));
        }
        self.challenge.borrow().clone().unwrap()
    }

    fn verify(&self, params: &PublicParams) -> bool {
        let challenge = self.challenge_scalar();
        let responses = self.responses();
        let rhs = self.comm[1] + (self.pk * challenge);
        let lhs = (self.comm[0] * responses[0]) + (params.k * responses[1]) + (params.g * responses[2]);
        rhs == lhs
    }

    fn alloc(&self, name: &str, n_limbs: usize, limbwidth: usize, input_map: &mut HashMap<String, Value>) {
        
        let (c1_x, c1_y) = edwards_coords(&self.comm[0]);
        let c1_x_limbs = integer_to_limbs(c1_x, n_limbs, limbwidth);
        let c1_y_limbs = integer_to_limbs(c1_y, n_limbs, limbwidth);

        for (i, (x_i, y_i)) in c1_x_limbs.into_iter().zip(c1_y_limbs.into_iter()).enumerate() {
            input_map.insert(format!("{}.C1.x.limbs.{}", name, i), x_i);
            input_map.insert(format!("{}.C1.y.limbs.{}", name, i), y_i);
        }
        let pk_bits = bytes_to_bits(self.pk.compress().as_bytes());
        for (i, bit) in pk_bits.into_iter().pad_using(256, |_| false).enumerate() {
            input_map.insert(format!("pk.{}", i), Value::Bool(bit));
        }

        for (i, hcommit) in self.hcommit.iter().enumerate() {
            input_map.insert(format!("{}.hcommit.{}", name, i), integer_to_field(hcommit));
        }

        let challenge = self.challenge_scalar();
        assert!(integer_to_scalar(&scalar_to_integer(&challenge)) == challenge);
        for (i, limb) in scalar_to_limbs(&challenge, n_limbs, limbwidth).into_iter().enumerate() {
            input_map.insert(format!("pub_i.challenge.limbs.{}", i), limb);
        }
        for (i, response) in self.responses().iter().enumerate() {
            for (j, limb) in scalar_to_limbs(response, n_limbs, limbwidth).into_iter().enumerate() {
                input_map.insert(format!("pub_i.responses.{}.limbs.{}", i, j), limb);
            }
        }

    }
}

/// pad a message like sha512 would
fn sha512_pad(msg: &[u8]) -> Vec<u8> {
    let mut msg_array = msg.to_vec();
    let mdi = msg_array.len() % 128;
    let padding_len = if mdi < 112 {119 - mdi} else {247 - mdi};
    let ending = ((msg_array.len() as u64) << 3).to_be_bytes();
    msg_array.push(0x80);
    for _ in 0..padding_len {
        msg_array.push(0);
    }
    msg_array.extend(ending);
    msg_array
}

// convert bytes to little endian bits
fn bytes_to_bits(bytes: &[u8]) -> Vec<bool> {
    //let output1 = Integer::from_digits(bytes, Order::LsfLe).to_digits::<bool>(Order::LsfLe).into_iter().pad_using(bytes.len() * 8, |_| false).collect::<Vec<bool>>();
    let mut output = Vec::with_capacity(bytes.len() * 8);
    for byte in bytes {
        for i in 0..8 {
            output.push((byte & (1 << i)) != 0);
        }
    }
    output
}

/// convert integer to n_limbs limbs of size limbwidth
fn integer_to_limbs(mut int: Integer, n_limbs: usize, limbwidth: usize) -> Vec<Value> {
    let mut limbs = vec![integer_to_field(&Integer::from(0)); n_limbs];
    if int == 0 {
        return limbs;
    }
    let base = Integer::from(2).pow(limbwidth as u32);
    for i in 0..n_limbs {
        let limb = int.clone() % &base;
        limbs[i] = integer_to_field(&limb);
        int /= &base;
    }
    limbs
}


/// convert integer to n_limbs limbs of size limbwidth
fn integer_to_limbs_gen(mut int: Integer, limbwidth: &[usize]) -> Vec<Integer> {
    let n_limbs = limbwidth.len();
    let mut limbs = vec![Integer::from(0); n_limbs];
    if int == 0 {
        return limbs;
    }
    for (i, lw) in limbwidth.iter().enumerate() {
        let base = Integer::from(2).pow(*lw as u32);
        let limb = int.clone() % &base;
        limbs[i] = limb; //integer_to_field(&limb);
        int /= &base;
    }
    limbs
}

/// convert scalar to field limbs
fn scalar_to_limbs(s: &Scalar, n_limbs: usize, limbwidth: usize) -> Vec<Value> {
    integer_to_limbs(scalar_to_integer(s), n_limbs, limbwidth)
}

/// get coords from EdwardsPoint
fn edwards_coords(pt: &EdwardsPoint) -> (Integer, Integer) {
    let pt_prime = Edwards25519Pt::from_compressed(&pt.compress());
    (pt_prime.x, pt_prime.y)
}

/// generate prover input 
pub fn prover_input_for_verifyeddsa_sigma(message: Vec<u8>, n_limbs: usize, limbwidth: usize, w_hash: bool) -> HashMap<String, Value> {
    let now = Instant::now();
    let params = PublicParams::new();



    assert!(message.len() % 8 == 0);
    let mut input_map: HashMap<String,Value> = HashMap::default();
    let mut csprng = rand::rngs::StdRng::from_seed([0u8; 32]);
    let signing_key: SigningKey = SigningKey::generate(&mut csprng);
    let pk = signing_key.verifying_key();
    let signature = signing_key.sign(&message);
    let encoded_r = bytes_to_bits(signature.r_bytes());
    let r_point = CompressedEdwardsY(signature.r_bytes().clone()).decompress().unwrap();
    let (r_x, r_y) = edwards_coords(&r_point);
    let r_x_bits = r_x.to_digits::<bool>(Order::LsfLe).into_iter().pad_using(255, |_| false).collect::<Vec<_>>();
    assert!(r_x_bits.len() == 255);
    assert!(r_x_bits[0] == encoded_r[255]);
    let s_val = Scalar::from_canonical_bytes(signature.s_bytes().clone()).unwrap();



    for (i, bit) in r_x_bits.into_iter().pad_using(255, |_| false).enumerate() {
        input_map.insert(format!("r_x.{}", i), Value::Bool(bit));
    }

    for (i, bit) in encoded_r.into_iter().pad_using(256, |_| false).enumerate() {
        input_map.insert(format!("encoded_r.{}", i), Value::Bool(bit));
    }

    for (i, limb) in scalar_to_limbs(&s_val, n_limbs, limbwidth).into_iter().enumerate() {
        input_map.insert(format!("priv_i.s.limbs.{}", i), limb);
    }

    let c1 = Ed25519Commit::new(r_point, params.k.clone(), &mut csprng);
    let (c1_x, c1_y) = edwards_coords(&c1.comm);
    let c1_x_limbs = integer_to_limbs(c1_x, n_limbs, limbwidth);
    let c1_y_limbs = integer_to_limbs(c1_y, n_limbs, limbwidth);
    //assert!(c1_x.len() == n_limbs && c1_y.len() == n_limbs);
    for (i, (x_i, y_i)) in c1_x_limbs.into_iter().zip(c1_y_limbs.into_iter()).enumerate() {
        input_map.insert(format!("pub_i.C1.x.limbs.{}", i), x_i);
        input_map.insert(format!("pub_i.C1.y.limbs.{}", i), y_i);

    }
    let v_int = scalar_to_integer(&c1.opening);
    let v_bits = v_int.to_digits::<bool>(Order::LsfLe);
    for (i, bit) in v_bits.into_iter().pad_using(Q_SIZE, |_| false).enumerate() {
        input_map.insert(format!("priv_i.v_bits.{}", i), Value::Bool(bit));
    }

    let mut hasher = Sha512::new();
    hasher.update(signature.r_bytes());
    hasher.update(pk.as_bytes());
    hasher.update(&message);
    let h_val = Scalar::from_bytes_mod_order_wide(&From::from(hasher.finalize()));
    let h_inv = h_val.invert();
    //let h_inv = Integer::from_digits(&h_bits, Order::LsfLe).invert(&config.order).unwrap();
    let exponents = [-h_inv.clone(), h_inv.clone() * c1.opening, s_val*h_inv];
    let pk_point = CompressedEdwardsY(pk.to_bytes()).decompress().unwrap();
    for (i,e) in exponents.iter().enumerate() {
        for (j, limb) in scalar_to_limbs(e, n_limbs, limbwidth).into_iter().enumerate() {
            input_map.insert(format!("priv_i.exponents.{}.limbs.{}", i,j), limb);
        }
    }

    let mut randexp = [Default::default(), Default::default(), Default::default()];
    let mut randexp_scalar = [Default::default(), Default::default(), Default::default()];
    let mut exp_ints = [Default::default(), Default::default(), Default::default()];
    for i in 0..3 {
        randexp_scalar[i] = Scalar::random(&mut csprng);
        randexp[i] = scalar_to_integer(&randexp_scalar[i]);
        exp_ints[i] = scalar_to_integer(&exponents[i]);
    }

    let mut rng = RandState::new_mersenne_twister();
    rng.seed(&Integer::from(42));
    let openings = [rand_int(&mut rng), rand_int(&mut rng)];
    let hcommit0 = Poseidon::new(vec![exp_ints[0].clone(), exp_ints[1].clone(), exp_ints[2].clone(), randexp[0].clone(), openings[0].clone()]);
    let hcommit1 = Poseidon::new(vec![randexp[1].clone(), randexp[2].clone(), v_int, Integer::from(0), openings[1].clone()]);
    let hcommits = [hcommit0.output, hcommit1.output];



    let rand_comm = (c1.comm * randexp_scalar[0]) + (params.k * randexp_scalar[1]) + (params.g * randexp_scalar[2]);

    let full_comm = [c1.comm, rand_comm];
    let public = Ed25519SigmaPublic::new(full_comm, hcommits.clone(), pk_point);
    public.fill_responses(&exponents, &randexp_scalar);
    assert!(public.verify(&params));
    public.alloc("pub_i", n_limbs, limbwidth, &mut input_map);

    for (i, rexp) in randexp.iter().enumerate() {
        for (j, limb) in integer_to_limbs(rexp.clone(), n_limbs, limbwidth).into_iter().enumerate() {
            input_map.insert(format!("priv_i.exponents.{}.limbs.{}", i+3, j), limb);
        }
    }
    for (i, opening) in openings.iter().enumerate() {
        input_map.insert(format!("priv_i.openings.{}", i), integer_to_field(opening));
    }

    if w_hash {
        for (i, limb) in scalar_to_limbs(&h_val, n_limbs, limbwidth).into_iter().enumerate() {

            input_map.insert(format!("h_u.limbs.{}", i), limb);
        }
    }

    let mut new_message = vec![0; 64];
    new_message.extend_from_slice(&message);

    let padded_message = sha512_pad(&new_message);
    let shaped = shape_m(&padded_message);
    // println!("MLEN {}", message.len()+64);
    // println!("M {}", shaped.len());
    
    for (i, outer_arr) in shaped.into_iter().enumerate() {
        for (j, inner_arr) in outer_arr.into_iter().enumerate() {
            for (k, val) in inner_arr.into_iter().enumerate() {
                input_map.insert(format!("m.{}.{}.{}", i, j, k), integer_to_field(&val));
            }
        }
    }


    println!("Time for Compute prover input: {}ms", now.elapsed().as_millis());
    let serialize_path = PathBuf::from_str("pi_sigma").unwrap();
    let _ = serialize_into_file(&public, &serialize_path);
    input_map
}

/// Generate verifier input for eddsa sigma algorithm and verify sigma protocol
pub fn verifier_input_for_eddsa_sigma(n_limbs: usize, limbwidth: usize) -> HashMap<String, Value> {
    let mut input_map = HashMap::default();
    let now = Instant::now();
    let pf_path = PathBuf::from_str("pi_sigma").unwrap();
    let sigma: Ed25519SigmaPublic = deserialize_from_file(pf_path).expect("Failed to read pi_sigma");
    let params = PublicParams::new();
    assert!(sigma.verify(&params));
    sigma.alloc("pub_i", n_limbs, limbwidth, &mut input_map);
    println!("Verifier input time {}ms", now.elapsed().as_millis());
    input_map
}
