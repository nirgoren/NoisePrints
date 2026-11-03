//! This module converts the rust implementation of modular operations to zokrate implementation
use circ::bignat::bignatwithlimbmax::{BigNatWithLimbMax};
use std::fs::{OpenOptions, read_to_string, File};
use std::io::{BufReader, BufRead};
use std::io::{Write, Result, stdin, Error};
use rug::Integer;
use regex::Regex;
use circ::ecdsa::ecdsa::{P256Point, BigNatPoint, EllipticCurveP256, BigNatPointType};
use circ::user_input::{input_number, confirm_append};
use circ::preproc_utils::{vec_int_to_str, vec_usize_to_str, bignat_to_str, bignatpoint_to_str, vec_bignat_to_str, vec_point_to_str, double_vec_point_to_str, write_to_file, is_values_defined_in_file};
use circ::hash::hash::{DigestAlgorithm};
use circ::hash::sha256::{n_blocks_to_msg_len};

const DEFAULT_MODULUS_STR: &str = "52435875175126190479447740508185965837690552500527637822603658699938581184513";
const REPO_PATH: &str = ".";
const CW2: usize = 75;

fn generate_sha256_padding(n_blocks: usize, limbwidth: &[usize], file_path: &str) {
    let msg_len = n_blocks_to_msg_len(n_blocks.to_string());
    let padded_msg = generate_sha256_padding_inner(msg_len*8, limbwidth);
    let append_lines: Vec<String> = vec![
        format!("const field[{}][16][{}] PAD{} = {:?}", n_blocks, limbwidth.len(), n_blocks, padded_msg),
    ];
    write_to_file(append_lines, &file_path);
}

fn split_limbs(ele: u32, limbwidth: &[usize]) -> Vec<Integer> {
    let mut output: Vec<Integer> = Vec::new();
    let mut cur_ele = ele;
    for width in limbwidth.iter() {
        let limb: Integer = Integer::from(cur_ele) % (Integer::from(1) << *width);
        output.push(limb);
        cur_ele >>= *width;
    }
    output
}

fn generate_sha256_padding_inner(
    message_len: usize, 
    limbwidth: &[usize]
) -> Vec<Vec<Vec<Integer>>> {
    let padding: Vec<u8> = DigestAlgorithm::pure_padding(message_len);
    let pad_doublevec: Vec<Vec<u32>> = DigestAlgorithm::vecu8_to_doublevecu32(&padding);
    let mut pad_trivec: Vec<Vec<Vec<Integer>>> = Vec::new();
    for vec in pad_doublevec.iter() {
        let mut pad_inner: Vec<Vec<Integer>> = Vec::new();
        for ele in vec.iter() {
            let pad_inner_inner: Vec<Integer> = split_limbs(*ele, limbwidth);
            pad_inner.push(pad_inner_inner);
        }
        pad_trivec.push(pad_inner);
    }
    pad_trivec
}

fn generate_index_to_append(filename: &str, varname: &str) -> Result<u32> {
    let mut max_index = 0;
    let content = read_to_string(filename).expect("Error in read_to_string");

    for captures in Regex::new(&format!(r"{}(\d+)", varname)).expect("Error in regex").captures_iter(&content) {
        let index: u32 = captures[1].parse().expect("Cannot extract index");
        max_index = max_index.max(index);
    }

    let next_index = max_index + 1;

    Ok(next_index)
}


// not finish
fn append_basic_const_to_constzokfile(n_limbs: usize, limb_width: usize, num_gp: usize, window_size: usize, file_path: &str) {
    let append_lines: Vec<String> = vec![
        format!("const u32 P = {}", n_limbs),
        format!("const u32 Q = {}", n_limbs),
        "const u32 P_SQU = 2*P".to_string(),
        format!("const u32 W = {}", limb_width),       
        format!("const u32 NG = {}", num_gp),
        "const u32 ZG = NG - 1".to_string(),
        "const u32 AC = NG + 1".to_string(),
        format!("const field SHIFT = {:?}", Integer::from(1)<<limb_width),
        format!("const u32 WS = {}", window_size),
        "const u32 Nm1 = ((P*W+WS-1) / WS) - 1 // ceil(256 / stride)-1".to_string(),
        "const u32 S = 1<<WS // 1024 // 2 ** stride".to_string(),
        "const u32 LS = 1<<((P*W)%WS) // 64 // 2**(256%stride)".to_string()
    ];
    let is_contained_in_file: bool = is_values_defined_in_file("const u32 P_SQU = 2*P", &file_path);
    if !is_contained_in_file {
        write_to_file(append_lines, &file_path);
    } else {
        println!("Basic constants are already contained in the const file {}", &file_path);
    }
}

fn append_bignat_to_constzokfile(name: &str, input: BigNatWithLimbMax, file_path: &str) {
    let input_str: String = bignat_to_str(input.clone());
    let is_contained_in_file: bool = is_values_defined_in_file(input_str.as_str(), &file_path);
    if !is_contained_in_file {
        let line = format!(
            "const BigNat<{}> {} = {}",
            input.params.n_limbs,
            name,
            input_str
        );
        write_to_file(vec![line], &file_path);
    } else {
        println!("{} is already contained in the const file {}", name, &file_path);
    }
}

fn append_point_to_constzokfile(name: &str, input: BigNatPoint, file_path: &str) {
    let input_str: String = bignatpoint_to_str(input.clone());
    let line = format!(
        "const ECPoint_v2<{}> {} = {}",
        input.x.params.n_limbs,
        name,
        input_str
    );
    let is_contained_in_file: bool = is_values_defined_in_file(&line, &file_path);
    if !is_contained_in_file {
        write_to_file(vec![line], &file_path);
    } else {
        println!("{} is already contained in the const file {}", name, &file_path);
    }
}

/// Append gp_maxvalues, gp_auxconst and gp_cwlist to the constzokfile if they are not defined in the constzokfile
fn append_to_constzokfile(gp_maxvalues: Vec<Integer>, gp_auxconst: Vec<Integer>, gp_cwlist: Vec<usize>, file_path: &str) {
    // open the file
    let mut file = OpenOptions::new()
    .append(true)
    .open(file_path)
    .expect("cannot open file");

    // write CW list to the file in `file_path`
    let gp_cwlist_as_str: String = vec_usize_to_str(gp_cwlist.clone());
    let is_cwlist_contained_in_file: bool = is_values_defined_in_file(gp_cwlist_as_str.as_str(), file_path);
    let line = "\n";
    file.write_all(line.as_bytes()).expect("write failed");
    let mut modified_string = String::new();
    if !is_cwlist_contained_in_file {
        let next_idx_for_cwlist: u32 = generate_index_to_append(file_path, "P256_CW").expect("Error in computing the next index");
        let line = format!(
            "const u8[{}] P256_CW{} = {:?}\n",
            gp_cwlist.len(),
            next_idx_for_cwlist,
            gp_cwlist
        );
        file.write_all(line.as_bytes()).expect("write failed");
        // println!("P256_CW{}", next_idx_for_cwlist);
        modified_string.push_str(&format!("P256_CW{}", next_idx_for_cwlist));
    }


    // write gp_maxvalues to the file in `file_path`
    let gp_maxvalues_as_str: String = vec_int_to_str(gp_maxvalues.clone());
    let is_maxvalues_contained_in_file: bool = is_values_defined_in_file(gp_maxvalues_as_str.as_str(), file_path);
    if !is_maxvalues_contained_in_file {
        let next_idx_for_maxval: u32 = generate_index_to_append(file_path, "P256_MAXWORD").expect("Error in computing the next index");
        let line = format!(
            "const field[{}] P256_MAXWORD{} = {:?}\n",
            gp_maxvalues.len(),
            next_idx_for_maxval,
            gp_maxvalues
        );
        file.write_all(line.as_bytes()).expect("write failed");
        if !modified_string.is_empty() {
            modified_string.push_str(", ");
        }
        modified_string.push_str(&format!("P256_MAXWORD{}", next_idx_for_maxval));
    }

    let gp_auxconst_as_str: String = vec_int_to_str(gp_auxconst.clone());
    let is_auxconst_contained_in_file: bool = is_values_defined_in_file(gp_auxconst_as_str.as_str(), file_path);

    if !is_auxconst_contained_in_file {
        let next_idx_for_auxconst: u32 = generate_index_to_append(file_path, "P256_AUXCONST").expect("Error in computing the next index");
        let line = format!(
            "const field[{}] P256_AUXCONST{} = {:?}\n",
            gp_auxconst.len(),
            next_idx_for_auxconst,
            gp_auxconst
        );
        file.write_all(line.as_bytes()).expect("write failed");
        if !modified_string.is_empty() {
            modified_string.push_str(", ");
        }
        modified_string.push_str(&format!("P256_AUXCONST{}", next_idx_for_auxconst));
    }
    println!("{}", modified_string);
    println!("is_cwlist_contained_in_file: {}", is_cwlist_contained_in_file);
    println!("is_maxvalues_contained_in_file {}", is_maxvalues_contained_in_file);
    println!("is_auxconst_contained_in_file {}", is_auxconst_contained_in_file);
}

fn total_len_of_cw(gp_cwlist: Vec<usize>) -> usize {
    let mut total_len_of_cw: usize = 0;
    for cw in gp_cwlist.iter() {
        total_len_of_cw += cw;
    }
    total_len_of_cw
}



fn ceil_div(numerator: usize, denominator: usize) -> usize {
    if denominator == 0 {
        panic!("Division by zero");
    }
    (numerator + denominator - 1) / denominator
}

// decide if we can increase our carry width to the next multiple of our sub-table bitwidth
fn can_increase_carrybitwidth(gp_res_left: BigNatWithLimbMax, gp_res_right: BigNatWithLimbMax, field_mod: Integer, subtable_bitwidth: usize) -> Result<()> {
    println!("hello can_increase_carrybitwidth");
    let gp_maxvalues: Vec<Integer> = gp_res_left.compute_maxvalues(&gp_res_right);
    let gpleft_maxvalues: Vec<Integer> = gp_res_left.params.max_values.clone();
    let gp_auxconst: Vec<Integer> = gp_res_left.compute_aux_const_for_both(&gp_res_right); 
    let gp_cwlist: Vec<usize> = gp_res_left.compute_cw(&gp_res_right); 
    assert!(gp_res_left.params.limb_width == gp_res_right.params.limb_width);
    let limbwidth = gp_res_left.params.limb_width;
    let base: Integer = Integer::from(1) << limbwidth;

    let mut carry_upperbound: Vec<Integer> = vec![Integer::from(0)];

    let gp_n_limbs: usize = gp_maxvalues.len();

    for i in 0..gp_n_limbs {
        if i != gp_n_limbs-1 {
            let cw_upperbound: usize = ceil_div(gp_cwlist[i], subtable_bitwidth) * subtable_bitwidth;
            carry_upperbound.push((Integer::from(1) << cw_upperbound) - Integer::from(1)); // i+1th element
        }
        else {
            carry_upperbound.push(gp_auxconst[i+1].clone()); // carry[n-1] = aux[n]
            // The last check is: left[i] - right[i] + carry[i-1] + maxword[i] = ac[i] + ac[i+1]*base
        }
        let rhs: Integer = gp_auxconst[i].clone() + carry_upperbound[i+1].clone() * base.clone(); // rhs[i] = ac[i] + carry[i]* base (carry[0] = 0)
        assert!(rhs.clone() < field_mod.clone());
        let lhs: Integer = gpleft_maxvalues[i].clone() + carry_upperbound[i].clone() + gp_maxvalues[i].clone();
        assert!(lhs.clone() < field_mod.clone());
    }
    println!("carry_upperbouund {:?}", carry_upperbound);
    assert!(gp_maxvalues.len() == gp_res_left.params.n_limbs);
    Ok(())
}

fn assert_equality_for_zokrates(res_left: &BigNatWithLimbMax, res_right: &BigNatWithLimbMax, field_mod: Integer, file_path: &str) -> Result<()> {
    let steps: Vec<usize> = res_left.find_n_limbs_for_each_gp(&res_right, field_mod.clone());
    println!("length of steps {:?} {:?}", steps.len(), steps);
    let all_except_last_are_the_same = steps.iter().take(steps.len() - 1).all(|&x| x == steps[0]);
    assert!(all_except_last_are_the_same);
    let gp_res_left: BigNatWithLimbMax = res_left.group_limbs(steps[0], Some(field_mod.clone()));

    let gp_res_right: BigNatWithLimbMax = res_right.group_limbs(steps[0], Some(field_mod.clone()));

    let gp_maxvalues: Vec<Integer> = gp_res_left.compute_maxvalues(&gp_res_right);
    let gp_auxconst: Vec<Integer> = gp_res_left.compute_aux_const_for_both(&gp_res_right); 
    let gp_cwlist: Vec<usize> = gp_res_left.compute_cw(&gp_res_right); 
    let total_len_of_cw: usize = total_len_of_cw(gp_cwlist.clone());
    if total_len_of_cw > CW2 {
        println!("*** CW has {} bits. You might need to change CW2 in verifyecdsa.zok ***", total_len_of_cw);
    }

    if confirm_append("Do you want to append this line? (y/n)").unwrap() == "y" {
        println!("File path: {}", file_path);
        append_to_constzokfile(gp_maxvalues, gp_auxconst, gp_cwlist, file_path);
    } else {
        println!("Line was not appended.");
        println!("const u8[{}] P256_CW = {:?}", gp_cwlist.len(), gp_cwlist);
        println!("const field[{}] P256_MAXWORD = {:?}", gp_maxvalues.len(), gp_maxvalues);
        println!("const field[{}] P256_AUXCONST = {:?}", gp_auxconst.len(), gp_auxconst);
    }
    Ok(())
}

fn assert_equality_for_zokrates_w_adv_rangecheck(res_left: &BigNatWithLimbMax, res_right: &BigNatWithLimbMax, field_mod: Integer, subtable_bitwidth: usize, file_path: &str) -> Result<()> {
    let steps: Vec<usize> = res_left.find_n_limbs_for_each_gp(&res_right, field_mod.clone());
    println!("length of steps {:?} {:?}", steps.len(), steps);
    let all_except_last_are_the_same = steps.iter().take(steps.len() - 1).all(|&x| x == steps[0]);
    assert!(all_except_last_are_the_same);
    let gp_res_left: BigNatWithLimbMax = res_left.group_limbs(steps[0], Some(field_mod.clone()));

    let gp_res_right: BigNatWithLimbMax = res_right.group_limbs(steps[0], Some(field_mod.clone()));

    can_increase_carrybitwidth(gp_res_left.clone(), gp_res_right.clone(), field_mod.clone(), subtable_bitwidth); // added to check if we can increase the bitwidth for carry
    let gp_maxvalues: Vec<Integer> = gp_res_left.compute_maxvalues(&gp_res_right);
    let gp_auxconst: Vec<Integer> = gp_res_left.compute_aux_const_for_both(&gp_res_right); 
    let gp_cwlist: Vec<usize> = gp_res_left.compute_cw(&gp_res_right); 
    let total_len_of_cw: usize = total_len_of_cw(gp_cwlist.clone());
    if total_len_of_cw > CW2 {
        println!("*** CW has {} bits. You might need to change CW2 in verifyecdsa.zok ***", total_len_of_cw);
    }

    if confirm_append("Do you want to append this line? (y/n)").unwrap() == "y" {
        println!("File path: {}", file_path);
        append_to_constzokfile(gp_maxvalues, gp_auxconst, gp_cwlist, file_path);
    } else {
        println!("Line was not appended.");
        println!("const u8[{}] P256_CW = {:?}", gp_cwlist.len(), gp_cwlist);
        println!("const field[{}] P256_MAXWORD = {:?}", gp_maxvalues.len(), gp_maxvalues);
        println!("const field[{}] P256_AUXCONST = {:?}", gp_auxconst.len(), gp_auxconst);
    }
    Ok(())
}

fn rsamodmultiply(default_mod: &Integer, subtable_bitwidth: usize, file_path: &str) { // the value of BigNat does not matter; only max values matter
    let n_limbs: usize = 64;
    let limb_width: usize = 32;
    let a: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(100), limb_width, n_limbs, false);
    let b: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(200), limb_width, n_limbs, false);
    let product_ab: BigNatWithLimbMax = a.create_product_nat(&b);

    let q_upper_bound: Integer = (Integer::from(1) << (n_limbs*limb_width+1)) - 1;
    let q: BigNatWithLimbMax = BigNatWithLimbMax::new_with_upper_bound(&Integer::from(10), limb_width, n_limbs+1, q_upper_bound);

    let rsa_modulus: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from_str_radix("115792089210356248762697446949407573529996955224135760342422259061068512044369", 10).unwrap(), limb_width, n_limbs, false);
    let r: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(6), limb_width, n_limbs, false);

    let product: BigNatWithLimbMax = q.create_product_nat(&rsa_modulus);
    let res: BigNatWithLimbMax = product.create_addition_nat(&r);
    println!("product_ab.params.n_limbs {}", product_ab.params.n_limbs);
    println!("test1 res.params.n_limbs {}", res.params.n_limbs);
    let _ = assert_equality_for_zokrates_w_adv_rangecheck(&res, &product_ab, default_mod.clone(), subtable_bitwidth, file_path);
}

fn operation1(n_limbs: usize, limb_width: usize, default_mod: &Integer, subtable_bitwidth: usize, file_path: &str) {
    println!("======================= operation1: Mod mult over Fq =======================");
    let a: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(100), limb_width, n_limbs, false);
    let b: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(200), limb_width, n_limbs, false);
    let product_ab: BigNatWithLimbMax = a.create_product_nat(&b);

    let q_upper_bound: Integer = (Integer::from(1) << (n_limbs*limb_width+1)) - 1;
    let q: BigNatWithLimbMax = BigNatWithLimbMax::new_with_upper_bound(&Integer::from(10), limb_width, n_limbs+1, q_upper_bound);
    let mod_q: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from_str_radix("115792089210356248762697446949407573529996955224135760342422259061068512044369", 10).unwrap(), limb_width, n_limbs, true);
    let r: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(6), limb_width, n_limbs, false);

    let product: BigNatWithLimbMax = q.create_product_nat(&mod_q);
    let res: BigNatWithLimbMax = product.create_addition_nat(&r);
    let _ = assert_equality_for_zokrates_w_adv_rangecheck(&res, &product_ab, default_mod.clone(), subtable_bitwidth, file_path);
}

fn sigma_operation(n_limbs: usize, limb_width: usize, default_mod: &Integer, subtable_bitwidth: usize, file_path: &str) {
    println!("======================= sigma operation: gamma_i + e_i * c = q * quotient + remainder =======================");
    let mod_q: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from_str_radix("115792089210356248762697446949407573529996955224135760342422259061068512044369", 10).unwrap(), limb_width, n_limbs, true);

    let a: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(100), limb_width, n_limbs, false);
    let c_upper_bound: Integer = mod_q.value.clone().unwrap() - Integer::from(1);
    let c: BigNatWithLimbMax = BigNatWithLimbMax::new(&c_upper_bound, limb_width, n_limbs, true);
    let product_ab: BigNatWithLimbMax = a.create_product_nat(&c);
    let res_left: BigNatWithLimbMax = product_ab.create_addition_nat(&a);

    let q_upper_bound: Integer = (Integer::from(1) << (n_limbs*limb_width+1)) - 1; // quotient bitwidth = 257
    let q: BigNatWithLimbMax = BigNatWithLimbMax::new_with_upper_bound(&Integer::from(10), limb_width, n_limbs+1, q_upper_bound);
    let r: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(6), limb_width, n_limbs, false);

    let product: BigNatWithLimbMax = q.create_product_nat(&mod_q);
    let res: BigNatWithLimbMax = product.create_addition_nat(&r);
    let _ = assert_equality_for_zokrates_w_adv_rangecheck(&res, &res_left, default_mod.clone(), subtable_bitwidth, file_path);
}

// for point addition
// compute the gpmaxword for the operation "check m*(x1+2*p) + y2 == p*(quotient + 2*m) + y1 + m*x2"
fn operation3(n_limbs: usize, limb_width: usize, p_bignat: BigNatWithLimbMax, default_mod: &Integer, subtable_bitwidth: usize, file_path: &str) { 
    println!("======================= Point add operation1.1: check m*(x1+2*p) + y2 == p*(quotient + 2*m) + y1 + m*x2 =======================");
    let m: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from_str_radix("1157920892103562487626974469494075735300861434152903", 10).unwrap(), limb_width, n_limbs, false);
    let x1: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(200), limb_width, n_limbs, false);
    let two_p: BigNatWithLimbMax = p_bignat.scalar_mult_nat(&Integer::from(2)); // 2*p
    let x1_plus_2p: BigNatWithLimbMax = x1.create_addition_nat(&two_p); // x1+2*p
    let res_left0: BigNatWithLimbMax = m.create_product_nat(&x1_plus_2p); // m*(x1+2*p)
    let y2: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(100), limb_width, n_limbs, false);
    let res_left1: BigNatWithLimbMax = res_left0.create_addition_nat(&y2); // m*(x1+2*p) + y2

    let x2: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(200), limb_width, n_limbs, false);
    let m_times_x2: BigNatWithLimbMax = m.create_product_nat(&x2); // m*x2
    let y1: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(20), limb_width, n_limbs, false);
    let remainder: BigNatWithLimbMax = m_times_x2.create_addition_nat(&y1); // m*x2 + y1
    let q_upper_bound: Integer = (Integer::from(1) << (n_limbs*limb_width+2)) - 1; // quotient bits 258
    let quotient: BigNatWithLimbMax = BigNatWithLimbMax::new_with_upper_bound(&Integer::from(10), limb_width, n_limbs+1, q_upper_bound);
    let product: BigNatWithLimbMax = quotient.create_product_nat(&p_bignat);
    let res_right: BigNatWithLimbMax = product.create_addition_nat(&remainder); // p*quotient + remainder

    let _ = assert_equality_for_zokrates_w_adv_rangecheck(&res_right, &res_left1, default_mod.clone(), subtable_bitwidth, file_path);
}

// compute the gpmaxword for the operation "check m*m + 4*p == p*(quotient+4) + x3 + x1 + x2"
fn operation4(n_limbs: usize, limb_width: usize, p_bignat: BigNatWithLimbMax, default_mod: &Integer, subtable_bitwidth: usize, file_path: &str) { 
    println!("======================= Point add operation2: check m*m + 4*p == p*(quotient+4) + x3 + x1 + x2 =======================");
    let m: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from_str_radix("1157920892103562487626974469494075735300861434152903", 10).unwrap(), limb_width, n_limbs, false);
    let squ_m: BigNatWithLimbMax = m.create_product_nat(&m); // m*m
    let four_p: BigNatWithLimbMax = p_bignat.scalar_mult_nat(&Integer::from(4)); // 4*p
    let res_left: BigNatWithLimbMax = squ_m.create_addition_nat(&four_p); // m*m + 4*p

    let x1: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(200), limb_width, n_limbs, false);
    let x2: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(200), limb_width, n_limbs, false);
    let x3: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(200), limb_width, n_limbs, false);
    let x1_plus_x2: BigNatWithLimbMax = x1.create_addition_nat(&x2);
    let remainder: BigNatWithLimbMax = x1_plus_x2.create_addition_nat(&x3); // x1 + x2 + x3

    let q_upper_bound: Integer = (Integer::from(1) << (n_limbs*limb_width+1)) - 1; // quotient bits 257
    let quotient: BigNatWithLimbMax = BigNatWithLimbMax::new_with_upper_bound(&Integer::from(10), limb_width, n_limbs+1, q_upper_bound);
    let product: BigNatWithLimbMax = quotient.create_product_nat(&p_bignat);
    let res_right: BigNatWithLimbMax = product.create_addition_nat(&remainder); // p*quotient + remainder

    let _ = assert_equality_for_zokrates_w_adv_rangecheck(&res_right, &res_left, default_mod.clone(), subtable_bitwidth, file_path);
}

// compute the gpmaxword for the operation "check y3 = p*quotient -y1 + m * (x1 - x3) <=> y3 + y1 + m*x3 + 4*p*p = p*(quotient+4*p) + m*x1"
fn operation4_2(n_limbs: usize, limb_width: usize, p_bignat: BigNatWithLimbMax, default_mod: &Integer, subtable_bitwidth: usize, file_path: &str) { 
    println!("======================= Point add operation3: check y3 + y1 + m*x3 + 4*p*p = p*(quotient+4*p) + m*x1 =======================");
    let m: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from_str_radix("1157920892103562487626974469494075735300861434152903", 10).unwrap(), limb_width, n_limbs, false);
    let x1: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(200), limb_width, n_limbs, false);
    let x3: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(200), limb_width, n_limbs, false);    
    let y1: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(200), limb_width, n_limbs, false);
    let y3: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(200), limb_width, n_limbs, false);    

    let y1_plus_y3: BigNatWithLimbMax = y1.create_addition_nat(&y3); // y1+y3
    let m_times_x3: BigNatWithLimbMax = m.create_product_nat(&x3); // m*x3
    let res_left0: BigNatWithLimbMax = y1_plus_y3.create_addition_nat(&m_times_x3); // y1+y3+m*x3
    let squ_p: Integer = p_bignat.value.clone().unwrap() * p_bignat.value.clone().unwrap();
    let squ_p_bignat: BigNatWithLimbMax = BigNatWithLimbMax::new(&squ_p, limb_width, 2*n_limbs, true);
    let four_squ_p: BigNatWithLimbMax = squ_p_bignat.scalar_mult_nat(&Integer::from(4)); // 4*p*p
    let res_left1: BigNatWithLimbMax = res_left0.create_addition_nat(&four_squ_p); // y1 + y3 + m*x3 + 4*p*p

    let remainder: BigNatWithLimbMax = m.create_product_nat(&x1); // m*x1

    let q_upper_bound: Integer = (Integer::from(1) << (n_limbs*limb_width+3)) - 1; // quotient bits 259
    let quotient: BigNatWithLimbMax = BigNatWithLimbMax::new_with_upper_bound(&Integer::from(10), limb_width, n_limbs+1, q_upper_bound);
    let product: BigNatWithLimbMax = quotient.create_product_nat(&p_bignat);
    let res_right: BigNatWithLimbMax = product.create_addition_nat(&remainder); // p*quotient + remainder

    let _ = assert_equality_for_zokrates_w_adv_rangecheck(&res_right, &res_left1, default_mod.clone(), subtable_bitwidth, file_path);
}

// goal: m = (3 * x * x + curve.a) * inverse_mod(2 * y, curve.p)
//  compute the gpmaxword for the operation "2*y*m + 12*p*p = p*(quotient+12p) + 3*x*x + a"
fn point_double_operation(n_limbs: usize, limb_width: usize, p_bignat: BigNatWithLimbMax, default_mod: &Integer, subtable_bitwidth: usize, file_path: &str) { 
    println!("======================= Point double operation1.2: check 2*y*m + 12*p*p = p*(quotient+12p) + 3*x*x + a =======================");
    let m: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from_str_radix("1157920892103562487626974469494075735300861434152903", 10).unwrap(), limb_width, n_limbs, false);
    let y: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(200), limb_width, n_limbs, false);
    let x: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(200), limb_width, n_limbs, false);    
    
    let a: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from_str_radix("115792089210356248762697446949407573530086143415290314195533631308867097853948", 10).unwrap(), limb_width, n_limbs, true); // p-3
    let squ_p: Integer = p_bignat.value.clone().unwrap() * p_bignat.value.clone().unwrap();
    let squ_p_bignat: BigNatWithLimbMax = BigNatWithLimbMax::new(&squ_p, limb_width, 2*n_limbs, true);

    let two_y: BigNatWithLimbMax = y.scalar_mult_nat(&Integer::from(2)); // 2*y
    let m_times_two_y: BigNatWithLimbMax = m.create_product_nat(&two_y); // m*(2*y)
    let twelve_squ_p: BigNatWithLimbMax = squ_p_bignat.scalar_mult_nat(&Integer::from(12)); // 12*p*p
    let res_left: BigNatWithLimbMax = twelve_squ_p.create_addition_nat(&m_times_two_y); // 12*p*p + m*(2*y)
    let three_x: BigNatWithLimbMax = x.scalar_mult_nat(&Integer::from(3)); // 3*x
    let three_x_times_x: BigNatWithLimbMax = three_x.create_product_nat(&x); // 3x * x
    let remainder: BigNatWithLimbMax = three_x_times_x.create_addition_nat(&a); // 3x*x + a

    let q_upper_bound: Integer = (Integer::from(1) << (n_limbs*limb_width+4)) - 1; // quotient bits 260
    let quotient: BigNatWithLimbMax = BigNatWithLimbMax::new_with_upper_bound(&Integer::from(10), limb_width, n_limbs+1, q_upper_bound);
    let product: BigNatWithLimbMax = quotient.create_product_nat(&p_bignat);
    let res_right: BigNatWithLimbMax = product.create_addition_nat(&remainder); // p*quotient + remainder

    let _ = assert_equality_for_zokrates_w_adv_rangecheck(&res_right, &res_left, default_mod.clone(), subtable_bitwidth, file_path);
}

// compute the gpmaxword for the operation "check m*m + 4*p == p*(quotient+4) + q*quotient'+r + x1 + x2" where quotient' = 0 or 1
fn operation_check_ut(n_limbs: usize, limb_width: usize, p_bignat: BigNatWithLimbMax, q_bignat: BigNatWithLimbMax, default_mod: &Integer, subtable_bitwidth: usize, file_path: &str) { 
    let m: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from_str_radix("1157920892103562487626974469494075735300861434152903", 10).unwrap(), limb_width, n_limbs, false);
    let squ_m: BigNatWithLimbMax = m.create_product_nat(&m); // m*m
    let four_p: BigNatWithLimbMax = p_bignat.scalar_mult_nat(&Integer::from(4)); // 4*p
    let res_left: BigNatWithLimbMax = squ_m.create_addition_nat(&four_p); // m*m + 4*p
    let r: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from_str_radix("115792089210356248762697446949407573530", 10).unwrap(), limb_width, n_limbs, false);



    let x1: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(200), limb_width, n_limbs, false);
    let x2: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(200), limb_width, n_limbs, false);
    let x3: BigNatWithLimbMax = q_bignat.create_addition_nat(&r); // q+r
    let x1_plus_x2: BigNatWithLimbMax = x1.create_addition_nat(&x2);
    let remainder: BigNatWithLimbMax = x1_plus_x2.create_addition_nat(&x3); // x1 + x2 + x3

    let q_upper_bound: Integer = (Integer::from(1) << (n_limbs*limb_width+1)) - 1; // quotient bits 257
    let quotient: BigNatWithLimbMax = BigNatWithLimbMax::new_with_upper_bound(&Integer::from(10), limb_width, n_limbs+1, q_upper_bound);
    let product: BigNatWithLimbMax = quotient.create_product_nat(&p_bignat);
    let res_right: BigNatWithLimbMax = product.create_addition_nat(&remainder); // p*quotient + remainder

    let _ = assert_equality_for_zokrates_w_adv_rangecheck(&res_right, &res_left, default_mod.clone(), subtable_bitwidth, file_path);
}

fn modmultiply_operation(n_limbs: usize, limb_width: usize, default_mod: &Integer, desire_mod: &Integer, quotient_bit: usize, subtable_bitwidth: usize, file_path: &str) {
    println!("======================= Mod multiply operation: Mod mult over Fq =======================");
    let a: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(100), limb_width, n_limbs, false);
    let b: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(200), limb_width, n_limbs, false);
    let product_ab: BigNatWithLimbMax = a.create_product_nat(&b);

    let q_upper_bound: Integer = (Integer::from(1) << quotient_bit) - 1;
    let q: BigNatWithLimbMax = BigNatWithLimbMax::new_with_upper_bound(&Integer::from(10), limb_width, n_limbs+1, q_upper_bound);
    let r: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from(6), limb_width, n_limbs, false);

    let desire_mod_bignat = BigNatWithLimbMax::new(desire_mod, limb_width, n_limbs, true);
    let product: BigNatWithLimbMax = q.create_product_nat(&desire_mod_bignat);
    let res: BigNatWithLimbMax = product.create_addition_nat(&r);
    let _ = assert_equality_for_zokrates_w_adv_rangecheck(&res, &product_ab, default_mod.clone(), subtable_bitwidth, file_path);
}

fn compute_parameters_for_window_method(n_limbs: usize, limb_width: usize, window_size: usize) {
    println!("const u32 WS_ = {}", window_size);
    println!("const u32 BP_ = {}", 1<<window_size);
    println!("const u32 PA_ = {}", (n_limbs*limb_width)/window_size);
    println!("const u32 PD_ = {}", n_limbs*limb_width-window_size);
}

fn compute_base_power(value: P256Point, n_limbs: usize, limb_width: usize, k: usize, file_path: &str) { // compute [value, ..., value^{(1<<k)-1}] // note: do not include the infinity point in this function
    let mut base_powers: Vec<P256Point> = vec![value.create_point_at_infinity(), value.clone()];
    for i in 2..(1<<k) {
        let next_push: P256Point = P256Point::point_add(base_powers.last().cloned(), Some(value.clone()));
        base_powers.push(next_push.clone());
    }    
    let mut base_powers_bignat: Vec<BigNatPoint> = Vec::new();
    for point in base_powers.iter() {
        base_powers_bignat.push(BigNatPoint::new(&point, limb_width, n_limbs, true));
    }
    println!("length of base powers = {}", base_powers_bignat.len());
    
    let write_str: String = format!("const ECPoint_v2<{}>[{}] BASE_POWERS = {}", n_limbs, base_powers_bignat.len(), vec_point_to_str(base_powers_bignat));
    let is_auxconst_contained_in_file: bool = is_values_defined_in_file(&write_str, file_path);
    if !is_auxconst_contained_in_file {
        if confirm_append("Do you want to append this line? (y/n)").unwrap() == "y" {
            println!("File path: {}", file_path);
            write_to_file(vec![write_str], file_path);
        } else {
            println!("Base powers were not appended because you entered n.");
        }
    } else {
        println!("Base powers were not appended since they have been contained in file {}.", file_path);
    }
}

fn compute_base_power_for_cached_window_method(value: P256Point, n_limbs: usize, limb_width: usize, stride: usize, file_path: &str) { // compute [value, ..., value^{(1<<k)-1}] // note: do not include the infinity point in this function
    let mut base_powers: Vec<Vec<P256Point>> = Vec::new();
    // Gpow[i][j] = j * (2 ** (i * stride)) * G for j = 1, ..., 2**stride - 1

    let n_vec: usize = (n_limbs*limb_width+stride-1)/stride; // number of vectors of base powers
    println!("n_vec {}", n_vec);

    for i in 0..n_vec {
        let initial_point: P256Point = if i == n_vec-1 {value.clone()} 
                                       else {value.clone().scalar_mult(Integer::from(1)<<(n_limbs*limb_width-(i+1)*stride))}; // (2 ** (256 - (i+1) * stride)) * value
        let mut base_powers_inner: Vec<P256Point> = vec![initial_point.create_point_at_infinity(), initial_point.clone()];
        let cur_stride: usize = if i == n_vec-1 {
                                    if (n_limbs*limb_width)%stride == 0 {stride} else {(n_limbs*limb_width)%stride}
                                } else {stride};
        for j in 2..(1<<cur_stride) {
            let next_push: P256Point = P256Point::point_add(base_powers_inner.last().cloned(), Some(initial_point.clone()));
            base_powers_inner.push(next_push.clone());
        }
        base_powers.push(base_powers_inner);
    }

    let mut base_powers_bignat: Vec<Vec<BigNatPoint>> = Vec::new();
    for vec in base_powers.iter().take(base_powers.len()-1) {
        let mut base_powers_bignat_inner: Vec<BigNatPoint> = Vec::new();
        for point in vec.iter() {
            base_powers_bignat_inner.push(BigNatPoint::new(&point, limb_width, n_limbs, true));
        }
        base_powers_bignat.push(base_powers_bignat_inner);
    }
    let base_powers_str: String = double_vec_point_to_str(base_powers_bignat.clone());
    let mut last_base_powers_bignat: Vec<BigNatPoint> = Vec::new();
    for point in base_powers.last().unwrap().iter() {
        last_base_powers_bignat.push(BigNatPoint::new(&point, limb_width, n_limbs, true));
    }
    let last_base_powers_str: String = vec_point_to_str(last_base_powers_bignat.clone());

    let mut write_str: Vec<String> = Vec::new();
    write_str.push(format!("const BasePowers<{}, {}, {}, {}> Gpow = BasePowers {{", n_limbs, base_powers_bignat.len(), base_powers_bignat[0].len(), last_base_powers_bignat.len()).to_string());
    write_str.push(format!("    base_powers: {},", base_powers_str).to_string());
    write_str.push(format!("    last_base_powers: {},", last_base_powers_str).to_string());
    write_str.push("}".to_string());

    let is_auxconst_contained_in_file: bool = is_values_defined_in_file(&write_str[0], file_path);
    if !is_auxconst_contained_in_file {
        if confirm_append("Do you want to append this line? (y/n)").unwrap() == "y" {
            println!("File path: {}", file_path);
            write_to_file(write_str, file_path);
        } else {
            println!("Base powers were not appended because you entered n.");
        }
    } else {
        println!("Base powers were not appended since they have been contained in file {}.", file_path);
    }


    println!("length of base powers = {}", base_powers_bignat.len());
}

fn write_str_converting_bignatb_to_bool_array(n_limbs: usize, limb_width: usize, file_path: &str) -> Result<()> {
    println!("replacing a line in {}", file_path);
    let mut vec_str: Vec<String> = Vec::new();
    for i in 0..n_limbs {
        vec_str.push(format!("...intermediate.a.limbs[{}]", n_limbs-1-i));
    }
    let joined_str = vec_str.join(", ");
    let final_str = format!("bool[TOTAL] list_a = [{}]", joined_str);
    println!("{}", final_str);


    Ok(())
}

fn aux_func_for_multiplexer(n_limbs: usize, limb_width: usize, window_size: usize) {

    let mut start: usize = 0;
    let n_chunks: usize = (n_limbs * limb_width + window_size - 1) / window_size;
    let mut j: usize = n_limbs - 1;
    let mut record: Vec<(usize, usize, usize)> = Vec::new(); // for each j, compute the starting index and the number of iterations
    let mut cur_start = 0;
    let mut cur_n_iter = 0;
    println!("n_chunks = {}", n_chunks);
    for i in 0..(n_chunks-1) { // iterate from the most significant chunk
        if start+window_size > limb_width {
            println!("{}:{}-{}; {}:{}-{}", j, start, limb_width, j-1, 0, window_size-limb_width+start);
        } else {
            cur_n_iter += 1;
            println!("{}:{}-{}", j, start, start+window_size);
        }
        if start+window_size >= limb_width {
            record.push((j, cur_start, cur_n_iter));
            cur_start = window_size-limb_width+start;
            start = cur_start;
            cur_n_iter = 0;
            j = j-1;
        } else {
            start = start+window_size;
        }
    }
    println!("{:?}", record);

}


fn main () {
    // let default_mod: Integer = Integer::from_str_radix(DEFAULT_MODULUS_STR, 10).unwrap();
    // // let limb_width: usize = input_number("Please enter the limbwidth (16/32/64).").unwrap();
    // // let n_limbs: usize;
    // // let num_gp: usize;

    // // if limb_width == 64 {
    // //     n_limbs = 4;
    // //     num_gp = 4;
    // // } else if limb_width == 32 {
    // //     n_limbs = 8;
    // //     num_gp = 3;
    // // } else if limb_width == 16 {
    // //     n_limbs = 16;
    // //     num_gp = 3;
    // // } else {
    // //     eprintln!("Unsupported limbwidth");
    // //     return;
    // // }
    // let n_limbs: usize = 64;
    // let limb_width: usize = 32;
    // let subtable_bitwidth: usize = 10;
    // // let num_gp: usize = 3;

    // // let n_limbs: usize = 4;
    // // let limb_width: usize = 64;
    // // let num_gp: usize = 4;

    // // let n_limbs: usize = 16;
    // // let limb_width: usize = 16;
    // // let num_gp: usize = 3;


    // // // Q: how to caculate the number of limbs of p_squ


    // let file_path: String = format!("{}/test_rsa{}.zok", REPO_PATH, limb_width).to_string();
    // // let base_power_file_path: String = format!("{}/zok_src/ecdsa/const/basepower_{}_{}.zok", REPO_PATH, limb_width, window_size).to_string();
    // // let base_power_window_file_path: String = format!("{}/zok_src/ecdsa/const/basepower_window_{}_{}.zok", REPO_PATH, limb_width, window_size).to_string();
    // // // let gp_op_file_path: String = format!("{}/zok_src/ecdsa/group_operation_{}.zok", REPO_PATH, limb_width).to_string();
    // // // append_basic_const_to_constzokfile(n_limbs, limb_width, num_gp, window_size, &file_path);
    // // // append_bignat_to_constzokfile("Q_MODULUS", q_bignat, &file_path);
    // // // append_bignat_to_constzokfile("P_MODULUS", p_bignat.clone(), &file_path);
    // // // append_bignat_to_constzokfile("P_MODULUS_SQU", p_squ_bignat, &file_path);
    // // // append_bignat_to_constzokfile("P256_a", bignat_a, &file_path);
    // // // append_point_to_constzokfile("P256_G", bignat_g, &file_path);
    // // // compute_base_power_for_cached_window_method(EllipticCurveP256::new().g, n_limbs, limb_width, window_size, &base_power_file_path);

    // // // let result = write_str_converting_bignatb_to_bool_array(n_limbs, limb_width, &gp_op_file_path);

    // // // // print_str_converting_bignatb_to_bool_array(n_limbs, limb_width);
    // // operation1(n_limbs, limb_width, &default_mod, &file_path);
    // // // operation3(n_limbs, limb_width, p_bignat.clone(), &default_mod, &file_path); // 1st operstion for point addition
    // // // point_double_operation(n_limbs, limb_width, p_bignat.clone(), &default_mod, &file_path);
    // // // operation4(n_limbs, limb_width, p_bignat.clone(), &default_mod, &file_path);
    // // // operation4_2(n_limbs, limb_width, p_bignat.clone(), &default_mod, &file_path);
    // let file_path: String = format!("{}/test_ecdsa{}_dec_27.zok", REPO_PATH, limb_width).to_string();

    // // ========================= check for ECDSA signature verification
    // let n_limbs: usize = 8;
    // let limb_width: usize = 32;
    // let subtable_bitwidth: usize = 15;
    // let p: Integer = Integer::from_str_radix("115792089210356248762697446949407573530086143415290314195533631308867097853951", 10).unwrap();
    // let p_bignat: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from_str_radix("115792089210356248762697446949407573530086143415290314195533631308867097853951", 10).unwrap(), limb_width, n_limbs, true);
    // let q_bignat: BigNatWithLimbMax = BigNatWithLimbMax::new(&Integer::from_str_radix("115792089210356248762697446949407573529996955224135760342422259061068512044369", 10).unwrap(), limb_width, n_limbs, true);

    // let p_squ_bignat: BigNatWithLimbMax = BigNatWithLimbMax::new(&(p.clone()*p.clone()), limb_width, 2*n_limbs, true);
    // let p256_curve: EllipticCurveP256 = EllipticCurveP256::new();
    // let bignat_g = BigNatPoint::new(&p256_curve.g, limb_width, n_limbs, true);
    // let bignat_a: BigNatWithLimbMax = BigNatWithLimbMax::new(&((p256_curve.a+p.clone())%p.clone()), limb_width, n_limbs, true);

    // let subtable_bitwidth: usize = 10;
    // // operation1(n_limbs, limb_width, &default_mod, subtable_bitwidth, &file_path);
    // // operations related to incomplete point addition: operation3, operation4, operation4_2
    // // operation3(n_limbs, limb_width,  p_bignat.clone(), &default_mod, subtable_bitwidth, &file_path);
    // // operation4(n_limbs, limb_width,  p_bignat.clone(), &default_mod, subtable_bitwidth, &file_path);
    // // operation4_2(n_limbs, limb_width,  p_bignat.clone(), &default_mod, subtable_bitwidth, &file_path);
    // // point_double_operation(n_limbs, limb_width,  p_bignat.clone(), &default_mod, subtable_bitwidth, &file_path);
    // // operation_check_ut(n_limbs, limb_width,  p_bignat.clone(), q_bignat.clone(), &default_mod, subtable_bitwidth, &file_path);
    // // operation1(n_limbs, limb_width, &default_mod, subtable_bitwidth, &file_path);
    // // sigma_operation(n_limbs, limb_width, &default_mod, subtable_bitwidth, &file_path);
    // // operation1(n_limbs: usize, limb_width: usize, default_mod: &Integer, subtable_bitwidth: usize, file_path: &str)
    // println!("*** Check for modular multiplication on 2048-rsa signature verification ***");
    // rsamodmultiply(&default_mod, subtable_bitwidth, &file_path);
    // // // operation_check_ut(n_limbs, limb_width, p_bignat, q_bignat, &default_mod);
    
    // // /// Check for modular multiplication on the scalar field of P256
    // // println!("*** Check for modular multiplication on the scalar field of P256 ***");
    // // let base_field_p256 = Integer::from_str_radix("115792089210356248762697446949407573530086143415290314195533631308867097853951", 10).unwrap();
    // // let scalar_field_p256 = Integer::from_str_radix("115792089210356248762697446949407573529996955224135760342422259061068512044369", 10).unwrap();
    // // let quotient_bit: usize = 257;
    // // modmultiply_operation(n_limbs, limb_width, &base_field_p256, &scalar_field_p256, quotient_bit, subtable_bitwidth, &file_path);
    // // // fn modmultiply_operation(n_limbs: usize, limb_width: usize, default_mod: &Integer, desire_mod: &Integer, quotient_bit: usize, subtable_bitwidth: usize, file_path: &str) {

    // // /// Check for modular multiplication on the scalar field of Secp256k1
    // // println!("*** Check for modular multiplication on the scalar field of Secp256k1 ***");
    // // let base_field_secp256k1 = Integer::from_str_radix("115792089237316195423570985008687907853269984665640564039457584007908834671663", 10).unwrap();
    // // let scalar_field_secp256k1 = Integer::from_str_radix("115792089237316195423570985008687907852837564279074904382605163141518161494337", 10).unwrap();
    // // let quotient_bit: usize = 256;
    // // modmultiply_operation(n_limbs, limb_width, &base_field_secp256k1, &scalar_field_secp256k1, quotient_bit, subtable_bitwidth, &file_path);
    
    // generate padding constants for SHA256
    let limbwidth = vec![11, 11, 10];
    let n_blocks = 1;
    let file_path = "zok_src/hash/sha256/const/const".to_owned() + &n_blocks.to_string() + ".zok";
    generate_sha256_padding(n_blocks, &limbwidth, &file_path);
}