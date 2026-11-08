use tftp_dus::std_compat::time::Instant;

#[cfg(feature = "std")]
pub fn instant_callback() -> Instant {
    Instant::now()
}

/// Monotonic, unlike SystemTime which would underflow `Instant::elapsed` when
/// the clock is stepped backwards.
#[cfg(not(feature = "std"))]
pub fn instant_callback() -> Instant {
    use std::sync::OnceLock;

    static START: OnceLock<std::time::Instant> = OnceLock::new();
    Instant::from_time(|| {
        START
            .get_or_init(std::time::Instant::now)
            .elapsed()
            .as_micros() as u64
    })
}
