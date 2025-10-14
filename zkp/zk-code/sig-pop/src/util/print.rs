#[macro_export]
/// Conditional print
macro_rules! conditional_print {
    ($($arg:tt)*) => {
        #[cfg(feature = "debug_prints")]
        {
            println!($($arg)*);
        }
    };
}