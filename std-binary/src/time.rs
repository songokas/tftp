use tftp_dus::std_compat::time::Instant;

pub fn instant_callback() -> Instant {
    Instant::now()
}
