//! This module includes simple math functions

/// Division over usize
pub fn ceil_div(dividend: usize, divisor: usize) -> usize {
    assert!(divisor != 0);
    (dividend + divisor - 1) / divisor
}
