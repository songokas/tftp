use core::fmt::Write;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use log::LevelFilter;
use log::Log;
use log::Metadata;
use log::Record;

use crate::stderr::Stderr;

struct StderrLogger;

static LOGGER: StderrLogger = StderrLogger;

impl Log for StderrLogger {
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }

    fn log(&self, record: &Record<'_>) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let _ = writeln!(
            Stderr,
            "[{}.{:03} {}] {}",
            now.as_secs(),
            now.subsec_millis(),
            record.level(),
            record.args()
        );
    }

    fn flush(&self) {}
}

pub fn init(level: LevelFilter) {
    if log::set_logger(&LOGGER).is_ok() {
        log::set_max_level(level);
    }
}
