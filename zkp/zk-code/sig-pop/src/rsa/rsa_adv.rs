//! Implementations related to rsa signature verification with advanced range checks
use rug::Integer;
use super::rsa::RSAPublicKey;
use crate::bignat::bignatwithlimbmax::{BigNatWithLimbMax};
use crate::bignat::bignat_adv::{BigNatModMultadv};
use fxhash::FxHashMap as HashMap;

use crate::ir::term::Value;
use crate::conditional_print;

impl RSAPublicKey {
    /// Allocate signature (BigNat), modulus (BigNat), digest_result (BigNat) into the circuit
    pub fn generate_witness_adv(
        limbwidth: usize, 
        n_limbs: usize, 
        modulus: &Integer,
        signature: &Integer, 
        name: &str,
        input_map: &mut HashMap<String, Value>, 
        subtable_bitwidth: Option<usize>
    ) -> bool {
        conditional_print!("verify result: {}", verify_result); // for debug only

        let modulus: BigNatWithLimbMax = BigNatWithLimbMax::new(modulus, limbwidth, n_limbs, false); // assuming the modulus is non-constant
        let signature_bn: BigNatWithLimbMax = BigNatWithLimbMax::new(signature, limbwidth, n_limbs, false);

        // allocate variables into the circuit
        let prepend: String = if name.is_empty() {name.to_owned()} else {name.to_owned()+"."};
        modulus.alloc_from_nat(&format!("{}issuerkey", prepend), input_map);
        match subtable_bitwidth {
            Some(bw) => {
                signature_bn.alloc_adv(bw, &format!("{}signature", prepend), input_map);
            },
            None => {
                signature_bn.alloc_from_nat(&format!("{}signature", prepend), input_map);
            }
        }
        true
    }
}

/// Intermediate values for RSA signature verification
pub struct BigNatRSAadv {
    /// intermediate values for modular multiplication; usually the length is 17
    pub intermediate: Vec<BigNatModMultadv>
}

impl BigNatRSAadv {
    /// Create a new BigNatRSAadv for a^e mod modul where e = 2^16 + 1v
    pub fn new(
        a: &BigNatWithLimbMax, 
        modul: &BigNatWithLimbMax, 
        quotient_bits: usize, 
        limbs_per_gp: usize
    ) -> Self {
        let mut mm: Vec<BigNatModMultadv> = Vec::with_capacity(17);
        let mut cur_res: BigNatWithLimbMax = a.clone();
        for _ in 0..16 { // 0, 1, ..., 15
            let intermediate = BigNatModMultadv::new(
                &cur_res, 
                &cur_res, 
                modul, 
                quotient_bits,
                limbs_per_gp
            );
            mm.push(intermediate.clone());
            cur_res = intermediate.remainder.clone().unwrap();
        }
        mm.push(BigNatModMultadv::new(
            &a, 
            &cur_res, 
            modul, 
            quotient_bits,
            limbs_per_gp
        ));
        Self {
            intermediate: mm,
        }
    }

    /// Allocate intermediate values for modular multiplication into the circuit
    pub fn alloc(
        &self, 
        subtable_bitwidth: usize, 
        name: &str, 
        input_map: &mut HashMap<String, Value>
    ) {
        for (i, inter) in self.intermediate.iter().take(self.intermediate.len() - 1).enumerate() {

            inter.alloc_adv(
                subtable_bitwidth, 
                true, // allocate remainder into the circuit
                &format!("{}.mm.{}", name, i), 
                input_map
            );
        }
        self.intermediate.last().unwrap().alloc_adv(
            subtable_bitwidth,
            false, // do not allocate remainder into the circuit
            name, 
            input_map
        );
    }
}