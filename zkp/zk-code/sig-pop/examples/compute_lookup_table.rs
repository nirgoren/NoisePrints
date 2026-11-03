//! This module computes the lookup table for cached windowed method
use std::fs::{OpenOptions, read_to_string, File};
use std::io::{BufReader, BufRead};
use rug::Integer;
use circ::ecdsa::ecdsa::{P256Point, BigNatPoint, EllipticCurveP256, BigNatPointType};
use circ::user_input::{input_number, confirm_append};

const REPO_PATH: &str = ".";

fn main() {
    // ========================= compute the table for cached windowed method
    let n_limbs: usize = 8;
    let limb_width: usize = 32;
    let window_size: usize = input_number("Please enter the window size (5-10).").unwrap();
    let pointtype: BigNatPointType = BigNatPointType::ECPointplain;
    
    let base_power: P256Point = P256Point::hash_of_generator().scalar_mult(EllipticCurveP256::new().q - 1); // K^{-1}
    let test: P256Point = EllipticCurveP256::new().g.scalar_mult(EllipticCurveP256::new().q - 1); // G^{-1}
    println!("G inv {:?}", test);
    assert!(false);
    let base_power_file_path: String = match pointtype {
        BigNatPointType::ECPointv2 => format!("{}/zok_src/ecdsa/const/v2/basepower_{}_{}.zok", REPO_PATH, limb_width, window_size).to_string(),
        // BigNatPointType::ECPointplain => format!("{}/zok_src/ecdsa/const/advanced/basepower_{}_{}.zok", REPO_PATH, limb_width, window_size).to_string(),
        BigNatPointType::ECPointplain => format!("{}/zok_src/ecdsa/advanced/const/basepower_sigma_{}_{}.zok", REPO_PATH, limb_width, window_size).to_string(),
    };
    let mut import_strs: Vec<String> = match pointtype { 
        BigNatPointType::ECPointv2 => vec![format!("from \"../../struct/ecdsastruct\" import ECPoint_v2").to_string(), format!("from \"../../../zok_utils/big_nat\" import BigNat").to_string()],
        BigNatPointType::ECPointplain => vec![format!("from \"../../struct/ecdsastruct\" import ECPoint_plain").to_string()],
    };

    let base_power_file_path: String = format!("{}/zok_src/ecdsa/Fp-estimate/const/basepower_sigma_{}_{}.zok", REPO_PATH, limb_width, window_size).to_string();
    // pointtype.compute_table_for_cached_window_method_v2(EllipticCurveP256::new().g, n_limbs, limb_width, window_size, &base_power_file_path);
    // pointtype.compute_table_for_cached_window_method(base_power, n_limbs, limb_width, window_size, &base_power_file_path);
    pointtype.compute_table_for_cached_window_method_fp(base_power, n_limbs, limb_width, window_size, &base_power_file_path);
}