#![macro_use]
#![allow(missing_docs)]
// from arkworks
// print-trace requires std, so these imports are well-defined
pub use std::{
    format, println,
    string::{String, ToString},
    sync::atomic::{AtomicUsize, Ordering},
    time::Instant,
};

thread_local! {
    static IS_ON: std::cell::Cell<Option<bool>> = None.into();
}

pub fn on() -> bool {
    IS_ON.with(|i| {
        if i.get().is_none() {
            i.set(Some(std::env::var("TRACE").is_ok()));
        }
        i.get().unwrap()
    })
}

pub static NUM_INDENT: AtomicUsize = AtomicUsize::new(0);
pub const PAD_CHAR: &str = "·";

pub struct TimerInfo {
    pub msg: String,
    pub time: Instant,
}

#[macro_export]
macro_rules! start_timer {
    ($msg:expr) => {{
        use $crate::util::trace::{compute_indent, Instant, Ordering, ToString, NUM_INDENT};

        let msg = $msg();
        let start_info = "Start:";
        let indent_amount = 2 * NUM_INDENT.fetch_add(0, Ordering::Relaxed);
        let indent = compute_indent(indent_amount);

        if $crate::util::trace::on() {
            $crate::util::trace::println!("{}{:8} {}", indent, start_info, msg);
        }
        NUM_INDENT.fetch_add(1, Ordering::Relaxed);
        $crate::util::trace::TimerInfo {
            msg: msg.to_string(),
            time: Instant::now(),
        }
    }};
}

#[macro_export]
macro_rules! end_timer {
    ($time:expr) => {{
        $crate::end_timer!($time, || "");
    }};
    ($time:expr, $msg:expr) => {{
        use $crate::util::trace::{compute_indent, format, Ordering, NUM_INDENT};

        if $crate::util::trace::on() {
            let time = $time.time;
            let final_time = time.elapsed();
            let final_time = {
                let secs = final_time.as_secs();
                let millis = final_time.subsec_millis();
                let micros = final_time.subsec_micros() % 1000;
                let nanos = final_time.subsec_nanos() % 1000;
                if secs != 0 {
                    format!("{}.{:03}s", secs, millis)
                } else if millis > 0 {
                    format!("{}.{:03}ms", millis, micros)
                } else if micros > 0 {
                    format!("{}.{:03}µs", micros, nanos)
                } else {
                    format!("{}ns", final_time.subsec_nanos())
                }
            };

            let end_info = "End:";
            let message = format!("{} {}", $time.msg, $msg());

            NUM_INDENT.fetch_sub(1, Ordering::Relaxed);
            let indent_amount = 2 * NUM_INDENT.fetch_add(0, Ordering::Relaxed);
            let indent = compute_indent(indent_amount);

            // Todo: Recursively ensure that *entire* string is of appropriate
            // width (not just message).
            $crate::util::trace::println!(
                "{}{:8} {:.<pad$}{}",
                indent,
                end_info,
                message,
                final_time,
                pad = 75 - indent_amount
            );
        }
    }};
}

pub fn compute_indent_whitespace(indent_amount: usize) -> String {
    let mut indent = String::new();
    for _ in 0..indent_amount {
        indent.push_str(" ");
    }
    indent
}

pub fn compute_indent(indent_amount: usize) -> String {
    let mut indent = String::new();
    for _ in 0..indent_amount {
        indent.push_str(&PAD_CHAR);
    }
    indent
}
