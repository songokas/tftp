use core::{ops::Div, time::Duration};

use log::debug;

use crate::{std_compat::time::Instant, time::InstantCallback};

pub struct RateControl {
    // bytes/s
    avg_transmit_rate: u32,

    // for measuring rtt
    current_rtt: Instant,
    rtt_for_packet: u16,
    rtt_estimate: f64,
    //
    // for packet loss rate
    total_packets: u32,
    error_packets: u32,
    //

    // for speed estimations
    start: Instant,
    // bytes
    total_send: u64,
    // bytes
    total_received: u64,
    //
    instant: InstantCallback,
}

impl RateControl {
    pub fn new(instant: InstantCallback) -> Self {
        Self {
            rtt_for_packet: 0,
            rtt_estimate: 0.0,
            total_send: 0,
            total_received: 0,
            instant,
            start: instant(),
            current_rtt: instant(),
            error_packets: 0,
            avg_transmit_rate: 0,
            total_packets: 0,
        }
    }

    pub fn increment_errors(&mut self) {
        self.error_packets += 1;
    }

    pub fn start_rtt(&mut self, block: u16) {
        if self.current_rtt.elapsed().as_secs() > 1 {
            self.rtt_for_packet = 0;
        }
        if self.rtt_for_packet != 0 {
            return;
        }
        self.rtt_for_packet = block;
        self.current_rtt = (self.instant)();
    }

    pub fn end_rtt(&mut self, block: u16) {
        if self.rtt_for_packet == block {
            if self.rtt_estimate == 0.0 {
                self.rtt_estimate = self.current_rtt.elapsed().as_secs_f64();
            } else {
                self.rtt_estimate = smooth_rtt_estimate(
                    self.rtt_estimate,
                    self.current_rtt.elapsed().as_secs_f64(),
                );
            }
        }
        self.rtt_for_packet = 0;
    }

    pub fn data_sent(&mut self, size: usize) {
        self.total_send += size as u64;
        self.total_packets += 1;
    }

    pub fn data_received(&mut self, size: usize) {
        self.total_received += size as u64;
    }

    pub fn calculate_transmit_rate(
        &mut self,
        block_size: u16,
        window_size: u16,
        retransmission_timeout: f64,
    ) {
        let loss_event_rate = self.error_packets as f64 / self.total_packets as f64;
        self.avg_transmit_rate = average_transmit_rate(
            self.rtt_estimate,
            block_size as f64,
            window_size as f64,
            loss_event_rate,
            retransmission_timeout,
        );
    }

    pub fn print_info(&self) {
        debug!(
            "Expected rate: {} bytes/s Current rrt: {} Average send speed: {} bytes/s Average receive speed: {} bytes/s Total packets: {} Errors: {}",
            self.avg_transmit_rate,
            self.rtt_estimate,
            self.average_send_speed(),
            self.average_receive_speed(),
            self.total_packets,
            self.error_packets
        )
    }

    pub fn average_send_speed(&self) -> u64 {
        let passed = self.start.elapsed();
        if passed.as_secs() > 0 {
            self.total_send / passed.as_secs()
        } else {
            0
        }
    }

    pub fn average_receive_speed(&self) -> u64 {
        let passed = self.start.elapsed();
        if passed.as_secs() > 0 {
            self.total_received / passed.as_secs()
        } else {
            0
        }
    }

    /// send_window is in milliseconds and must be less than a second
    #[allow(dead_code)]
    pub fn packets_to_send(&self, send_window: u32, block_size: u32) -> u32 {
        packets_to_send(self.avg_transmit_rate, send_window, block_size)
    }
}

fn packets_to_send(avg_rate: u32, send_window: u32, block_size: u32) -> u32 {
    if avg_rate > 0 {
        let mut packets = (avg_rate / block_size / (1000 / send_window)) * 2;
        if packets == 0 {
            packets = 1;
        }
        packets
    } else {
        u32::MAX
    }
}

fn smooth_rtt_estimate(rtt_estimate: f64, current_rrt: f64) -> f64 {
    0.9 * rtt_estimate + (1_f64 - 0.9) * current_rrt
}

// loss_event_rate = error_packets / total_packets;
fn average_transmit_rate(
    round_trip_time: f64,
    block_size: f64,
    window_size: f64,
    loss_event_rate: f64,
    retransmission_timeout: f64,
) -> u32 {
    (block_size
        / (round_trip_time * f64::sqrt(2_f64 * window_size * loss_event_rate / 3_f64)
            + (retransmission_timeout
                * (3_f64
                    * f64::sqrt(3_f64 * window_size * loss_event_rate / 8_f64)
                    * loss_event_rate
                    * (1_f64 + 32_f64 * loss_event_rate.powf(2.0)))))) as u32
}

#[test]
fn test_average_transmit() {
    let result = average_transmit_rate(0.01, 512_f64, 1_f64, 0_f64, 1_f64);
    assert_eq!(result, 4294967295);

    let result = average_transmit_rate(0.01, 512_f64, 1_f64, 0.001_f64, 1_f64);
    assert_eq!(result, 1618739);

    let result = average_transmit_rate(0.01, 512_f64, 8_f64, 0.001_f64, 1_f64);
    assert_eq!(result, 572310);
}

#[test]
fn test_packets_to_send() {
    assert_eq!(446, packets_to_send(572310, 200, 512));
    assert_eq!(1264, packets_to_send(1618739, 200, 512));
    // send 1677721 packets * 512 / 1024 / 1024 = 819Mb in 200ms
    assert_eq!(1677721 * 2, packets_to_send(4294967295, 200, 512));
    assert_eq!(4294967295, packets_to_send(0, 200, 512));
    assert_eq!(1, packets_to_send(1, 200, 512));
    assert_eq!(1, packets_to_send(128, 200, 512));
    assert_eq!(6, packets_to_send(10000, 200, 512));
}

#[test]
fn test_smooth_rrt_estimate() {
    assert_eq!(0.275, smooth_rtt_estimate(0.25, 0.5));
    assert_eq!(0.55, smooth_rtt_estimate(0.5, 1.0));
    assert_eq!(0.46, smooth_rtt_estimate(0.5, 0.1));
    assert_eq!(0.45, smooth_rtt_estimate(0.5, 0.0));
}
