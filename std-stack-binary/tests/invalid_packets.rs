//! Runs the binary against the malformed packets in `test-packets`. The binary
//! aborts on any heap allocation or panic, so a pass also shows it stayed up.

const BIN: &str = env!("CARGO_BIN_EXE_tftp-dus-stack-only");

include!("../../test-packets/invalid_packets.rs");
