//! This module includes implementations related to reading user inputs
use std::io::{stdin};
use std::io::{Result};

/// Read user input
pub fn input_number(prompt: &str) -> Option<usize> {
    // Create a new mutable string to store the user's input
    let mut input = String::new();

    // Prompt the user to enter a number
    println!("{}", prompt);

    // Read the user's input from the console
    stdin()
        .read_line(&mut input)
        .expect("Failed to read line");

    // Convert the input to a number (in this case, a 32-bit integer)
    match input.trim().parse() {
        Ok(num) => Some(num),
        Err(_) => None,
    }
}

/// Ask user if they want to append the line(s) to the file
pub fn confirm_append(prompt: &str) -> Result<String> {
    println!("{}", prompt);
    let mut input = String::new();
    stdin().read_line(&mut input)?;

    Ok(input.trim().to_lowercase())
}