use std::sync::OnceLock;

use tftp_dus::std_compat::time::Instant;

/// Monotonic, unlike SystemTime which would underflow `Instant::elapsed` when
/// the clock is stepped backwards.
pub fn instant_callback() -> Instant {
    static START: OnceLock<std::time::Instant> = OnceLock::new();
    Instant::from_time(|| {
        START
            .get_or_init(std::time::Instant::now)
            .elapsed()
            .as_micros() as u64
    })
}
