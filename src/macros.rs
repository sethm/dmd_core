#[macro_export]
macro_rules! trace {
    ($($arg:expr),*) => {{
      println!("[{:?}] {}", Instant::now(), format!($($arg),*));
    }};
}
