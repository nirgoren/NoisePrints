//! This module includes implementations related to parsing ZoKrates

use rug::Integer;
use std::fs::{File};
use std::io::{BufReader, BufRead, Result};

/// Convert double array constant in ZoKrates to constant in rust
pub fn read_double_array(filename: &str) -> Result<Vec<Vec<Integer>>> {
    let file = File::open(filename)?;
    let reader = BufReader::new(file);

    let mut vec_vec_constants = Vec::new();
    let mut vec_constants = Vec::new(); // inner vector
    let nested = 2;
    let mut current_nested = 0;
    for line in reader.lines() {
        let line = line?;

        if line.contains("const field[") {
            if current_nested == nested {
                break;
            }
            current_nested += 1;
            continue;
        }
        if current_nested != nested && line.contains("[") {
            current_nested += 1;
            continue;
        }

        if current_nested == nested {
            if line.contains("...[") {
                let trimmed = line.trim();
                let inner_parts: Vec<&str> = trimmed
                                                .trim_matches(|c: char| c == '.' || c == '[' || c == ']')
                                                .split(';')
                                                .map(|s| s.trim())
                                                .collect();
                if inner_parts.len() == 2 {
                    if let (Ok(val), Ok(repeat)) = (inner_parts[0].parse::<i32>(), inner_parts[1].parse::<usize>()) {
                        vec_constants.extend(vec![Integer::from(val); repeat]);
                    }
                }
            }
            else if line.contains("]") && vec_constants.len() != 0 {
                vec_vec_constants.push(vec_constants);
                vec_constants = Vec::new();
            }
            else {
                let numbers: Vec<Integer> = line
                .split(',')
                .filter_map(|s| {
                    let num_str = s.trim_matches(|c: char| !c.is_numeric() && c != '-');
                    if !num_str.is_empty() {
                        Some(Integer::from_str_radix(num_str, 10).unwrap())
                    } else {
                        None
                    }
                })
                .collect();
                vec_constants.extend(numbers);
            }

        }
    }

    Ok(vec_vec_constants)
}

/// Convert triple array constant in ZoKrates to constant in rust
pub fn read_triple_array(filename: &str) -> Result<Vec<Vec<Vec<Integer>>>> {
    let file = File::open(filename)?;
    let reader = BufReader::new(file);

    let mut vec_vec_vec_constants = Vec::new();
    let mut vec_vec_constants = Vec::new();
    let mut vec_constants = Vec::new(); // inner vector
    let nested = 3;
    let mut current_nested = 0;
    let mut is_reading = false;
    for line in reader.lines() {
        let line = line?;
        if line.contains("POSEIDON_M") {
            is_reading = true;
        }
        if is_reading {
            if line.contains("const field[") {
                if current_nested == nested {
                    break;
                }
                current_nested += 1;
                continue;
            }
            if current_nested != nested && line.contains("[") && !line.contains("...[") {
                if current_nested == nested-1 && line.contains("[0;") { // handle [0; 7]
                    let trimmed = line.trim();
                    let inner_parts: Vec<&str> = trimmed
                                                    .trim_matches(|c: char| c == '.' || c == '[' || c == ']')
                                                    .split(';')
                                                    .map(|s| s.trim())
                                                    .collect();
                    if inner_parts.len() == 2 {
                        if let (Ok(val), Ok(repeat)) = (inner_parts[0].parse::<i32>(), inner_parts[1].parse::<usize>()) {
                            vec_vec_constants.push(vec![Integer::from(val); repeat]);
                        }
                        continue;
                    }                    
                }
                current_nested += 1;
                continue;
            }

            if current_nested == nested-1 && line.contains("...[") { // assume of the form ...[[0, x]; y]
                let trimmed = line.trim();

                let inner_parts: Vec<&str> = trimmed
                .trim_matches(|c: char| c == '.')
                .split('[') // Split by '[' to handle nested structure
                .flat_map(|s| s.split(';')) // Split by ';' to get individual numbers
                .flat_map(|s| s.split(']')) // Split by ']' to get individual numbers
                .map(|s| s.trim()) // Trim whitespace from each part
                .filter(|s| !s.is_empty()) // Remove empty strings resulting from split
                .collect();                
                // Check if there are two parts and the first part is a valid integer
                if inner_parts.len() == 3 {
                    if let (Ok(val), Ok(inner_repeat), Ok(outer_repeat)) = (
                        inner_parts[0].parse::<i32>(),
                        inner_parts[1].parse::<usize>(),
                        inner_parts[2].parse::<usize>(),
                    ) {
                        vec_vec_constants.extend(vec![vec![Integer::from(val); inner_repeat]; outer_repeat]);
                    }
                }

            } else if current_nested == nested-1 && line.contains("]") {
                if vec_vec_constants.len() != 0 {
                    vec_vec_vec_constants.push(vec_vec_constants);
                    vec_vec_constants = Vec::new();
                }
            }

            if current_nested == nested {
                if line.contains("]") && vec_constants.len() != 0 {
                    vec_vec_constants.push(vec_constants);
                    vec_constants = Vec::new();
                    current_nested -= 1;
                }
                else {
                    let numbers: Vec<Integer> = line
                    .split(',')
                    .filter_map(|s| {
                        let num_str = s.trim_matches(|c: char| !c.is_numeric() && c != '-');
                        if !num_str.is_empty() {
                            Some(Integer::from_str_radix(num_str, 10).unwrap())
                        } else {
                            None
                        }
                    })
                    .collect();
                    vec_constants.extend(numbers);
                }
    
            }
        }

    }

    Ok(vec_vec_vec_constants)
}