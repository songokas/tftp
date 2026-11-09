//! Runs the binary against the malformed packets in `test-packets`.

const BIN: &str = env!("CARGO_BIN_EXE_tftp-dus");

include!("../../test-packets/invalid_packets.rs");
