use core::cmp::max;
use core::cmp::min;
use core::time::Duration;

use log::debug;
#[cfg(not(feature = "std"))]
#[allow(unused_imports)]
use micromath::F32Ext;

use crate::std_compat::time::Instant;
use crate::time::InstantCallback;

// const MSS: u16 = MAX_DATA_BLOCK_SIZE;
const INITIAL_TCP_WINDOW: u16 = 4380;

pub struct RateControl {
    // bytes/s
    allowed_transmit_rate: u32,

    // for measuring rtt
    current_rtt: Instant,
    rtt_for_packet: u16,
    rtt_estimate: f32,
    //
    // for packet loss rate
    total_acknoledged_packets: u32,
    error_packets: u32,
    //

    // bytes
    total_data_sent: u32,
    // bytes
    total_acknoledged_data: u32,
    //
    instant: InstantCallback,

    // received bytes per second
    receive_set: [u32; 3],

    new_loss: bool,
    no_feedback_timer: Duration,
    feedback_timer_expired: bool,
    data_limited: bool,
}

impl RateControl {
    pub fn new(instant: InstantCallback) -> Self {
        let mut receive_set = [0; 3];
        receive_set[0] = u32::MAX;
        Self {
            rtt_for_packet: 0,
            rtt_estimate: 0.0,
            total_data_sent: 0,
            total_acknoledged_data: 0,
            instant,
            current_rtt: instant(),
            error_packets: 0,
            // allowed_transmit_rate: initial_rate(MSS) as u32,
            allowed_transmit_rate: u32::MAX,
            total_acknoledged_packets: 0,
            receive_set,
            new_loss: false,
            feedback_timer_expired: false,
            data_limited: false,
            no_feedback_timer: Duration::from_secs(2),
        }
    }

    #[allow(dead_code)]
    pub fn increment_errors(&mut self) {
        self.error_packets += 1;
        self.new_loss = true;
    }

    #[allow(dead_code)]
    pub fn mark_as_data_limited(&mut self) {
        self.data_limited = true;
    }

    pub fn start_rtt(&mut self, block: u16) {
        if self.current_rtt.elapsed() >= self.no_feedback_timer {
            self.rtt_for_packet = 0;
            self.feedback_timer_expired = true;
        }
        if self.rtt_for_packet != 0 {
            return;
        }
        self.rtt_for_packet = block;
        self.current_rtt = (self.instant)();
    }

    pub fn end_rtt(&mut self, block: u16) -> Option<Duration> {
        let mut elapsed_duration = None;
        if self.rtt_for_packet == block {
            let elapsed = self.current_rtt.elapsed();
            if self.rtt_estimate == 0.0 {
                self.rtt_estimate = elapsed.as_secs_f32();
            } else {
                self.rtt_estimate = smooth_rtt_estimate(self.rtt_estimate, elapsed.as_secs_f32());
            }
            elapsed_duration = elapsed.into()
        }
        self.rtt_for_packet = 0;
        elapsed_duration
    }

    pub fn data_sent(&mut self, size: usize) {
        self.total_data_sent += size as u32;
    }

    pub fn acknowledged_data(&mut self, size: usize, packets: u32) {
        self.total_acknoledged_data += size as u32;
        self.total_acknoledged_packets += packets;
    }

    pub fn timeout_interval(&self, min_retry_timeout: Duration, block_size: u16) -> Duration {
        if self.rtt_estimate == 0.0 {
            return min_retry_timeout;
        }
        let timeout = (4.0 * self.rtt_estimate)
            .max(2.0 * block_size as f32 / self.allowed_transmit_rate as f32);
        max(Duration::from_secs_f32(timeout), min_retry_timeout)
    }

    pub fn calculate_transmit_rate(
        &mut self,
        block_size: u16,
        window_size: u16,
        min_retry_timeout: Duration,
        received_in: Duration,
    ) -> u32 {
        let mut received = if self.feedback_timer_expired {
            initial_rate(block_size) as u32
        } else {
            if self.total_acknoledged_data == 0 {
                self.allowed_transmit_rate = 1;
            }
            (self.total_acknoledged_data as f32 / received_in.as_secs_f32()) as u32
        };

        let recv_limit = if self.data_limited {
            if self.new_loss || self.feedback_timer_expired {
                for v in self.receive_set.iter_mut().filter(|v| **v > 0) {
                    *v /= 2;
                }
                received = (0.85 * (received as f32)) as u32;
                self.maximize_set(received);
                self.receive_set.iter().max().copied().unwrap_or_default()
            } else {
                self.maximize_set(received);
                2_u32.saturating_mul(self.receive_set.iter().max().copied().unwrap_or_default())
            }
        } else {
            self.update_set(received);
            2_u32.saturating_mul(self.receive_set.iter().max().copied().unwrap_or_default())
        };
        let loss_event_rate =
            1_f32.min(self.error_packets as f32 / max(self.total_acknoledged_packets, 1) as f32);
        let timeout_interval = self.timeout_interval(min_retry_timeout, block_size);

        if loss_event_rate > 0.0 {
            let avg_transmit_rate = average_transmit_rate(
                self.rtt_estimate,
                block_size as f32,
                window_size as f32,
                loss_event_rate,
                timeout_interval.as_secs_f32(),
            );
            let minimum_rate = block_size as u32 / 64;
            self.allowed_transmit_rate = max(min(avg_transmit_rate, recv_limit), minimum_rate);
        } else {
            self.allowed_transmit_rate = max(
                min(2_u32.saturating_mul(self.allowed_transmit_rate), recv_limit),
                initial_rate(block_size) as u32,
            );
        }

        debug!(
            "Allowed rate {} bytes/s Rtt {}s Loss rate {loss_event_rate} Received {received} bytes Receive limit {recv_limit} bytes Data {} bytes Packets {} Errors {}",
            self.allowed_transmit_rate, timeout_interval.as_secs_f32(), self.total_acknoledged_data, self.total_acknoledged_packets, self.error_packets
        );

        self.no_feedback_timer = timeout_interval;
        self.new_loss = false;
        self.feedback_timer_expired = false;
        self.total_acknoledged_data = 0;
        self.total_acknoledged_packets = 0;
        self.error_packets = 0;
        self.data_limited = false;

        self.allowed_transmit_rate
    }

    #[allow(dead_code)]
    pub fn packets_to_send(&self, time_window: Duration, block_size: u16) -> u32 {
        packets_to_send(self.allowed_transmit_rate, time_window, block_size)
    }

    fn maximize_set(&mut self, received: u32) {
        let mut max_value = self.receive_set.iter().max().copied().unwrap_or_default();
        if received > max_value || max_value == u32::MAX {
            max_value = received;
        }
        self.receive_set = [0; 3];
        self.receive_set[0] = max_value;
    }

    fn update_set(&mut self, received: u32) {
        self.receive_set[2] = self.receive_set[1];
        self.receive_set[1] = self.receive_set[0];
        self.receive_set[0] = received;
    }
}

fn packets_to_send(allowed_rate: u32, time_window: Duration, block_size: u16) -> u32 {
    if allowed_rate > 0 {
        (allowed_rate as f32 / block_size as f32 * time_window.as_secs_f32()) as u32
    } else {
        u32::MAX
    }
}

fn smooth_rtt_estimate(rtt_estimate: f32, current_rrt: f32) -> f32 {
    0.9 * rtt_estimate + (1_f32 - 0.9) * current_rrt
}

// loss_event_rate = error_packets / total_packets;
fn average_transmit_rate(
    round_trip_time: f32,
    block_size: f32,
    window_size: f32,
    loss_event_rate: f32,
    retransmission_timeout: f32,
) -> u32 {
    (block_size
        / (round_trip_time * f32::sqrt(2.0 * window_size * loss_event_rate / 3.0)
            + (retransmission_timeout
                * (3.0
                    * f32::sqrt(3.0 * window_size * loss_event_rate / 8.0)
                    * loss_event_rate
                    * (1.0 + 32.0 * loss_event_rate * loss_event_rate))))) as u32
}

fn initial_rate(block_size: u16) -> u16 {
    min(4 * block_size, max(2 * block_size, INITIAL_TCP_WINDOW))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "std")]
    #[test]
    fn measure_rtt() {
        use std::thread::sleep;

        let mut rate = RateControl::new(std::time::Instant::now);
        rate.start_rtt(1);
        assert!(rate.rtt_estimate == 0.0);
        assert!(rate.end_rtt(1).is_some());
        assert!(rate.end_rtt(1).is_none());
        assert!(rate.rtt_estimate > 0.0);

        rate.start_rtt(2);
        assert!(rate.end_rtt(1).is_none());

        rate.start_rtt(2);
        assert!(rate.end_rtt(3).is_none());
        assert!(rate.end_rtt(2).is_none());

        let current = rate.rtt_estimate;
        rate.start_rtt(8);
        sleep(Duration::from_millis(10));
        assert!(rate.end_rtt(8).is_some());
        assert_ne!(rate.rtt_estimate, current);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_timeout_interval() {
        use std::thread::sleep;

        let mut rate = RateControl::new(std::time::Instant::now);

        let result = rate.timeout_interval(Duration::from_millis(80), 512);
        assert_eq!(result.as_millis(), 80);

        rate.start_rtt(1);
        sleep(result);
        rate.end_rtt(1);

        let transmit_rate =
            rate.calculate_transmit_rate(512, 8, result, Duration::from_millis(1000));
        assert_eq!(transmit_rate, 2048);

        let result = rate.timeout_interval(Duration::from_millis(80), 512);
        assert_eq!(500, result.as_millis());

        rate.feedback_timer_expired = true;
        rate.data_limited = true;

        let transmit_rate =
            rate.calculate_transmit_rate(512, 8, result, Duration::from_millis(1000));
        assert_eq!(transmit_rate, 4096);

        let result = rate.timeout_interval(Duration::from_millis(80), 512);
        assert!([320_u128, 321].contains(&result.as_millis()));

        // timeout depends on data or rtt
        rate.start_rtt(1);
        sleep(Duration::from_millis(1));
        rate.end_rtt(1);

        rate.acknowledged_data(8000, 8);
        let _transmit_rate = rate.calculate_transmit_rate(
            512,
            8,
            Duration::from_millis(80),
            Duration::from_millis(200),
        );

        let result = rate.timeout_interval(Duration::from_millis(80), 512);
        assert!([288_u128, 289].contains(&result.as_millis()));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_transmit_rate() {
        use std::thread::sleep;

        let mut rate = RateControl::new(std::time::Instant::now);

        rate.start_rtt(1);
        sleep(Duration::from_millis(1));
        rate.end_rtt(1);

        rate.acknowledged_data(8000, 8);
        let transmit_rate = rate.calculate_transmit_rate(
            512,
            8,
            Duration::from_millis(80),
            Duration::from_millis(200),
        );
        assert_eq!(transmit_rate, 4294967295);

        rate.acknowledged_data(8000, 8);
        let transmit_rate = rate.calculate_transmit_rate(
            512,
            8,
            Duration::from_millis(80),
            Duration::from_millis(200),
        );
        assert_eq!(transmit_rate, 4294967295);

        rate.acknowledged_data(8000, 8);
        let transmit_rate = rate.calculate_transmit_rate(
            512,
            8,
            Duration::from_millis(80),
            Duration::from_millis(200),
        );
        assert_eq!(transmit_rate, 80000);

        rate.acknowledged_data(8000, 8);
        let transmit_rate = rate.calculate_transmit_rate(
            512,
            8,
            Duration::from_millis(80),
            Duration::from_millis(200),
        );
        assert_eq!(transmit_rate, 80000);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_transmit_rate_doubles() {
        use std::thread::sleep;

        let mut rate = RateControl::new(std::time::Instant::now);

        rate.start_rtt(1);
        sleep(Duration::from_millis(1));
        rate.end_rtt(1);

        rate.acknowledged_data(512, 8);
        rate.calculate_transmit_rate(
            512,
            8,
            Duration::from_millis(80),
            Duration::from_millis(200),
        );

        rate.acknowledged_data(512, 8);
        let transmit_rate = rate.calculate_transmit_rate(
            512,
            8,
            Duration::from_millis(80),
            Duration::from_millis(200),
        );
        assert_eq!(transmit_rate, 4294967295);

        rate.acknowledged_data(512, 8);
        let transmit_rate = rate.calculate_transmit_rate(
            512,
            8,
            Duration::from_millis(80),
            Duration::from_millis(200),
        );
        assert_eq!(transmit_rate, 5120);
        let result = rate.timeout_interval(Duration::from_millis(80), 512);
        assert_eq!(200, result.as_millis());

        rate.acknowledged_data(512, 8);
        rate.acknowledged_data(512, 8);
        let transmit_rate = rate.calculate_transmit_rate(
            512,
            8,
            Duration::from_millis(80),
            Duration::from_millis(200),
        );
        let result = rate.timeout_interval(Duration::from_millis(80), 512);
        assert_eq!(100, result.as_millis());
        assert_eq!(transmit_rate, 10240);

        rate.acknowledged_data(512, 8);
        rate.acknowledged_data(512, 8);
        rate.acknowledged_data(512, 8);
        rate.acknowledged_data(512, 8);
        let transmit_rate = rate.calculate_transmit_rate(
            512,
            8,
            Duration::from_millis(80),
            Duration::from_millis(200),
        );
        assert_eq!(transmit_rate, 20480);
        let result = rate.timeout_interval(Duration::from_millis(80), 512);
        assert_eq!(80, result.as_millis());

        // we have not received anything
        let transmit_rate = rate.calculate_transmit_rate(
            512,
            8,
            Duration::from_millis(80),
            Duration::from_millis(200),
        );
        assert_eq!(transmit_rate, 2048);
        let result = rate.timeout_interval(Duration::from_millis(80), 512);
        assert_eq!(500, result.as_millis());
        let transmit_rate = rate.calculate_transmit_rate(
            512,
            8,
            Duration::from_millis(80),
            Duration::from_millis(200),
        );
        assert_eq!(transmit_rate, 2048);
        let result = rate.timeout_interval(Duration::from_millis(80), 512);
        assert_eq!(500, result.as_millis());
    }

    #[test]
    fn test_average_transmit() {
        let result = average_transmit_rate(0.01, 512_f32, 1_f32, 0_f32, 1_f32);
        assert_eq!(result, 4294967295);

        let result = average_transmit_rate(0.01, 512_f32, 1_f32, 0_f32, 0.001);
        assert_eq!(result, 4294967295);

        let result = average_transmit_rate(0.01, 512_f32, 1_f32, 0.001, 1_f32);
        assert_eq!(result, 1618739);

        let result = average_transmit_rate(0.01, 512_f32, 8_f32, 0.001, 1_f32);
        assert_eq!(result, 572310);

        let result = average_transmit_rate(0.080_099_8, 512_f32, 8_f32, 0.001, 0.080);
        assert_eq!(result, 87330);

        let result = average_transmit_rate(0.080_099_8, 512_f32, 8_f32, 0.0, 0.080);
        assert_eq!(result, 4294967295);

        let result = average_transmit_rate(0.380_099_8, 1400.0, 8.0, 25.0 / 158.0, 0.080);
        assert_eq!(result, 3532);

        let result = average_transmit_rate(0.011, 1400.0, 8.0, 1.0, 0.080);
        assert_eq!(result, 101);

        let result = average_transmit_rate(0.127, 1400.0, 8.0, 1.0, 0.080);
        assert_eq!(result, 99);
    }

    #[test]
    fn test_packets_to_send() {
        assert_eq!(
            223,
            packets_to_send(572310, Duration::from_millis(200), 512)
        );
        assert_eq!(
            632,
            packets_to_send(1618739, Duration::from_millis(200), 512)
        );
        assert_eq!(
            1677721,
            packets_to_send(4294967295, Duration::from_millis(200), 512)
        );
        assert_eq!(
            4294967295,
            packets_to_send(0, Duration::from_millis(200), 512)
        );
        assert_eq!(0, packets_to_send(1, Duration::from_millis(200), 512));
        assert_eq!(0, packets_to_send(128, Duration::from_millis(200), 512));
        assert_eq!(3, packets_to_send(10000, Duration::from_millis(200), 512));

        assert_eq!(19, packets_to_send(10000, Duration::from_millis(1000), 512));
    }

    #[test]
    fn test_smooth_rrt_estimate() {
        assert_eq!(0.275, smooth_rtt_estimate(0.25, 0.5));
        assert_eq!(0.55, smooth_rtt_estimate(0.5, 1.0));
        assert_eq!(0.45999998, smooth_rtt_estimate(0.5, 0.1));
        assert_eq!(0.45, smooth_rtt_estimate(0.5, 0.0));
    }
}
