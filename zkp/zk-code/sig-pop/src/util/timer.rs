//! Timer for benchmark
use std::time::{Duration};

/// Print the time
pub fn print_time(message: &str, duration: Duration, print_msg: bool) {
    if print_msg {
        println!("{}: {:?}", message, duration);
    }
    else {
        println!("{:?}", duration);
    }
}
