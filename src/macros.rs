#[macro_export]
macro_rules! trace {
    ($($arg:expr),*) => {{
      println!("[{:?}] {}", $crate::START_TIME.elapsed(), format!($($arg),*));
    }};
}
