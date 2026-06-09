use core::cmp::max;
use core::time::Duration;

use log::debug;
#[cfg(not(feature = "std"))]
#[allow(unused_imports)]
use micromath::F32Ext;

use crate::std_compat::time::Instant;
use crate::time::InstantCallback;

pub(crate) const FLOW_CONTROL_PERIOD: Duration = Duration::from_millis(200);

// Initial congestion window: 20 packets worth of bytes/s
const INITIAL_CWND_PACKETS: u32 = 40;
// EWMA smoothing: keep 90 % of the old estimate, blend in 10 % of each new sample
const RTT_SMOOTH_ALPHA: f32 = 0.9;
const RTT_SMOOTH_BETA: f32 = 0.1;
// RTO = max(4 × rtt_estimate, 2 × one-way propagation time)
const RTO_RTT_FACTOR: f32 = 4.0;
const RTO_PROP_FACTOR: f32 = 2.0;
// Half of the 16-bit block-number space; used for wrapping comparison:
// `a.wrapping_sub(b) < BLOCK_SEQ_HALF` is true iff a is at or ahead of b in
// the circular sequence, handling the 65535 → 0 rollover correctly.
const BLOCK_SEQ_HALF: u16 = u16::MAX / 2 + 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    SlowStart,
    CongestionAvoidance,
    FastRecovery { recovery_block: u16 },
}

pub struct RateControl {
    // Congestion window: maximum bytes/s allowed in flight (rate-based, not packet-count-based)
    pub(crate) cwnd_rate: u32,
    // Slow-start threshold: cwnd transitions from exponential to linear growth at this rate
    pub(crate) ssthresh: u32,
    pub(crate) phase: Phase,

    current_rtt: Instant,
    pub(crate) rtt_for_packet: u16,
    pub(crate) rtt_estimate: f32,

    dup_ack_count: u8,
    last_acked_block: u16,

    instant: InstantCallback,
}

impl RateControl {
    pub fn new(instant: InstantCallback) -> Self {
        Self {
            cwnd_rate: u32::MAX,
            ssthresh: u32::MAX,
            phase: Phase::SlowStart,
            rtt_for_packet: 0,
            rtt_estimate: 0.0,
            current_rtt: instant(),
            dup_ack_count: 0,
            last_acked_block: 0,
            instant,
        }
    }

    pub fn configure(&mut self, block_size: u16, window_size: u16) {
        self.cwnd_rate = initial_rate(block_size, window_size);
        self.ssthresh = u32::MAX;
        self.phase = Phase::SlowStart;
        self.dup_ack_count = 0;
        self.last_acked_block = 0;
    }

    pub fn start_rtt(&mut self, block: u16) {
        self.rtt_for_packet = block;
        self.current_rtt = (self.instant)();
    }

    pub fn end_rtt(&mut self, block: u16) -> Option<Duration> {
        if self.rtt_for_packet != block {
            return None;
        }
        let elapsed = self.current_rtt.elapsed();
        if self.rtt_estimate == 0.0 {
            self.rtt_estimate = elapsed.as_secs_f32();
        } else {
            self.rtt_estimate = smooth_rtt_estimate(self.rtt_estimate, elapsed.as_secs_f32());
        }
        self.rtt_for_packet = 0;
        Some(elapsed)
    }

    pub fn on_rtt_complete(&mut self, block_size: u16, acked_block: u16) {
        match self.phase {
            Phase::SlowStart => {
                self.cwnd_rate = self.cwnd_rate.saturating_mul(2);
                if self.cwnd_rate >= self.ssthresh {
                    self.phase = Phase::CongestionAvoidance;
                }
            }
            Phase::CongestionAvoidance => {
                self.cwnd_rate = self.cwnd_rate.saturating_add(block_size as u32);
            }
            Phase::FastRecovery { recovery_block } => {
                if acked_block.wrapping_sub(recovery_block) < BLOCK_SEQ_HALF {
                    self.cwnd_rate = self.ssthresh;
                    self.phase = Phase::CongestionAvoidance;
                    self.dup_ack_count = 0;
                }
            }
        }
        debug!(
            "cwnd={} ssthresh={} phase={:?} rtt={}s",
            self.cwnd_rate, self.ssthresh, self.phase, self.rtt_estimate
        );
    }

    pub fn on_loss(&mut self, block_size: u16, recovery_block: u16, window_size: u16) {
        self.ssthresh = max(self.cwnd_rate / 2, 2 * block_size as u32);
        if matches!(self.phase, Phase::FastRecovery { .. }) {
            self.cwnd_rate = initial_rate(block_size, window_size);
            self.phase = Phase::SlowStart;
        } else {
            self.cwnd_rate = self.ssthresh;
            self.phase = Phase::FastRecovery { recovery_block };
        }
        debug!(
            "Loss: cwnd={} ssthresh={} phase={:?}",
            self.cwnd_rate, self.ssthresh, self.phase
        );
    }

    pub fn on_dup_ack(&mut self, block: u16, block_size: u16, window_size: u16) -> bool {
        if matches!(self.phase, Phase::FastRecovery { .. }) {
            return false;
        }
        if block != self.last_acked_block {
            self.last_acked_block = block;
            self.dup_ack_count = 1;
            return false;
        }
        self.dup_ack_count += 1;
        if self.dup_ack_count >= 3 {
            debug!(
                "3 duplicate ACKs for block {block}: entering fast retransmit cwnd={} ssthresh={}",
                self.cwnd_rate, self.ssthresh
            );
            self.on_loss(block_size, block, window_size);
            return true;
        }
        false
    }

    pub fn timeout_interval(&self, min_retry_timeout: Duration, block_size: u16) -> Duration {
        if self.rtt_estimate == 0.0 {
            return min_retry_timeout;
        }
        let timeout = (RTO_RTT_FACTOR * self.rtt_estimate)
            .max(RTO_PROP_FACTOR * block_size as f32 / self.cwnd_rate as f32);
        max(Duration::from_secs_f32(timeout), min_retry_timeout)
    }

    pub fn packets_to_send(&self, time_window: Duration, block_size: u16) -> u32 {
        packets_to_send(self.cwnd_rate, time_window, block_size)
    }
}

fn packets_to_send(allowed_rate: u32, time_window: Duration, block_size: u16) -> u32 {
    if allowed_rate > 0 {
        (allowed_rate as f32 / block_size as f32 * time_window.as_secs_f32()) as u32
    } else {
        u32::MAX
    }
}

fn smooth_rtt_estimate(rtt_estimate: f32, current_rtt: f32) -> f32 {
    RTT_SMOOTH_ALPHA * rtt_estimate + RTT_SMOOTH_BETA * current_rtt
}

fn initial_rate(block_size: u16, window_size: u16) -> u32 {
    max(
        INITIAL_CWND_PACKETS * block_size as u32,
        window_size as u32 * block_size as u32 * 5,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn test_initial_rate_uses_max_of_cwnd_packets_and_window() {
        // Small window: INITIAL_CWND_PACKETS dominates
        assert_eq!(initial_rate(512, 1), INITIAL_CWND_PACKETS * 512);
        // Large window: window term dominates (20 * 512 * 5 = 51200 > INITIAL_CWND_PACKETS*512)
        assert_eq!(initial_rate(512, 20), 20 * 512 * 5);
        // Threshold: window_size=8 → 8*512*5 = 40*512 = INITIAL_CWND_PACKETS*512 (tie)
        assert_eq!(initial_rate(512, 8), INITIAL_CWND_PACKETS * 512);
        // window_size=9 → 9*512*5=23040 exceeds INITIAL_CWND_PACKETS*512=20480
        assert_eq!(initial_rate(512, 9), 9 * 512 * 5);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_configure_window_size_1_uses_packet_based_initial_rate() {
        let mut rate = RateControl::new(std::time::Instant::now);
        rate.configure(512, 1);
        assert_eq!(rate.cwnd_rate, INITIAL_CWND_PACKETS * 512);
        assert_eq!(rate.ssthresh, u32::MAX);
        assert_eq!(rate.phase, Phase::SlowStart);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_configure_large_window_size_scales_initial_rate() {
        let mut rate = RateControl::new(std::time::Instant::now);
        rate.configure(512, 16);
        // 16 * 512 * 5 = 40960 > 20 * 512 = 10240
        assert_eq!(rate.cwnd_rate, 16 * 512 * 5);
        assert_eq!(rate.phase, Phase::SlowStart);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_slow_start_doubles_cwnd_per_rtt() {
        let mut rate = RateControl::new(std::time::Instant::now);
        rate.configure(512, 1);
        let initial = rate.cwnd_rate;
        assert!(initial > 0);
        assert_eq!(rate.phase, Phase::SlowStart);

        rate.start_rtt(1);
        let _ = rate.end_rtt(1);
        rate.on_rtt_complete(512, 1);

        assert_eq!(rate.cwnd_rate, initial.saturating_mul(2));
        assert_eq!(rate.phase, Phase::SlowStart);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_slow_start_transitions_to_congestion_avoidance() {
        let mut rate = RateControl::new(std::time::Instant::now);
        rate.configure(512, 1);
        rate.ssthresh = rate.cwnd_rate.saturating_mul(3);

        rate.start_rtt(1);
        let _ = rate.end_rtt(1);
        rate.on_rtt_complete(512, 1);
        assert_eq!(rate.phase, Phase::SlowStart);

        rate.start_rtt(2);
        let _ = rate.end_rtt(2);
        rate.on_rtt_complete(512, 2);
        assert_eq!(rate.phase, Phase::CongestionAvoidance);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_congestion_avoidance_linear_growth() {
        let mut rate = RateControl::new(std::time::Instant::now);
        rate.configure(512, 1);
        rate.ssthresh = rate.cwnd_rate;
        rate.phase = Phase::CongestionAvoidance;
        let before = rate.cwnd_rate;

        rate.start_rtt(1);
        let _ = rate.end_rtt(1);
        rate.on_rtt_complete(512, 1);

        assert_eq!(rate.cwnd_rate, before + 512);
        assert_eq!(rate.phase, Phase::CongestionAvoidance);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_on_loss_resets_cwnd_and_sets_ssthresh() {
        let mut rate = RateControl::new(std::time::Instant::now);
        rate.configure(512, 1);
        rate.cwnd_rate = 100_000;
        rate.phase = Phase::CongestionAvoidance;

        rate.on_loss(512, 3, 1);

        assert_eq!(rate.ssthresh, 50_000);
        assert_eq!(rate.cwnd_rate, 50_000);
        assert!(matches!(
            rate.phase,
            Phase::FastRecovery { recovery_block: 3 }
        ));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_on_loss_ssthresh_minimum() {
        let mut rate = RateControl::new(std::time::Instant::now);
        rate.configure(512, 1);
        rate.cwnd_rate = 100;

        rate.on_loss(512, 1, 1);

        assert_eq!(rate.ssthresh, 2 * 512);
        assert_eq!(rate.cwnd_rate, 2 * 512);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_fast_recovery_exit_on_full_ack() {
        let mut rate = RateControl::new(std::time::Instant::now);
        rate.configure(512, 1);
        rate.phase = Phase::FastRecovery { recovery_block: 10 };
        rate.cwnd_rate = 50_000;
        rate.ssthresh = 50_000;

        rate.start_rtt(10);
        let _ = rate.end_rtt(10);
        rate.on_rtt_complete(512, 10);

        assert_eq!(rate.cwnd_rate, 50_000);
        assert_eq!(rate.phase, Phase::CongestionAvoidance);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_fast_recovery_stay_on_partial_ack() {
        let mut rate = RateControl::new(std::time::Instant::now);
        rate.configure(512, 1);
        rate.phase = Phase::FastRecovery { recovery_block: 10 };
        rate.cwnd_rate = 50_000;
        rate.ssthresh = 50_000;

        rate.start_rtt(8);
        let _ = rate.end_rtt(8);
        rate.on_rtt_complete(512, 8);

        assert_eq!(rate.cwnd_rate, 50_000);
        assert!(matches!(
            rate.phase,
            Phase::FastRecovery { recovery_block: 10 }
        ));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_fast_recovery_block_wraparound() {
        // recovery_block = 65535, ACK arrives at block 1 (wrapped) — must exit recovery
        let mut rate = RateControl::new(std::time::Instant::now);
        rate.configure(512, 1);
        rate.phase = Phase::FastRecovery {
            recovery_block: 65535,
        };
        rate.cwnd_rate = 50_000;
        rate.ssthresh = 50_000;

        rate.start_rtt(1);
        let _ = rate.end_rtt(1);
        rate.on_rtt_complete(512, 1);

        assert_eq!(rate.phase, Phase::CongestionAvoidance);
        assert_eq!(rate.cwnd_rate, 50_000);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_fast_recovery_entry() {
        let mut rate = RateControl::new(std::time::Instant::now);
        rate.configure(512, 1);
        rate.cwnd_rate = 100_000;
        rate.phase = Phase::CongestionAvoidance;

        rate.on_loss(512, 5, 1);

        assert_eq!(rate.ssthresh, 50_000);
        assert_eq!(rate.cwnd_rate, 50_000);
        assert!(matches!(
            rate.phase,
            Phase::FastRecovery { recovery_block: 5 }
        ));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_fast_recovery_rto() {
        let mut rate = RateControl::new(std::time::Instant::now);
        rate.configure(512, 1);
        rate.phase = Phase::FastRecovery { recovery_block: 5 };
        rate.cwnd_rate = 50_000;
        rate.ssthresh = 50_000;

        rate.on_loss(512, 7, 1);

        assert_eq!(rate.ssthresh, 25_000);
        assert_eq!(rate.cwnd_rate, initial_rate(512, 1));
        assert_eq!(rate.phase, Phase::SlowStart);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_fast_recovery_rto_window_size_affects_reset_rate() {
        // RTO during fast recovery resets cwnd to initial_rate(block, window) — window matters
        let mut rate = RateControl::new(std::time::Instant::now);
        rate.configure(512, 16);
        rate.phase = Phase::FastRecovery { recovery_block: 5 };
        rate.cwnd_rate = 50_000;
        rate.ssthresh = 50_000;

        rate.on_loss(512, 7, 16);

        assert_eq!(rate.cwnd_rate, initial_rate(512, 16));
        assert_eq!(rate.phase, Phase::SlowStart);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_rtt_measurement() {
        use std::thread::sleep;

        let mut rate = RateControl::new(std::time::Instant::now);
        rate.start_rtt(1);
        assert_eq!(rate.rtt_estimate, 0.0);
        assert!(rate.end_rtt(1).is_some());
        assert!(rate.end_rtt(1).is_none());
        assert!(rate.rtt_estimate >= 0.0);

        rate.start_rtt(2);
        assert!(rate.end_rtt(1).is_none());

        rate.start_rtt(2);
        assert!(rate.end_rtt(3).is_none()); // wrong block — measurement NOT abandoned
        assert!(rate.end_rtt(2).is_some()); // correct block — measurement completes

        let current = rate.rtt_estimate;
        rate.start_rtt(8);
        sleep(Duration::from_millis(10));
        assert!(rate.end_rtt(8).is_some());
        assert_ne!(rate.rtt_estimate, current);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_timeout_interval_uses_rtt() {
        use std::thread::sleep;

        let mut rate = RateControl::new(std::time::Instant::now);
        assert_eq!(
            rate.timeout_interval(Duration::from_millis(80), 512)
                .as_millis(),
            80
        );

        rate.start_rtt(1);
        sleep(Duration::from_millis(20));
        rate.end_rtt(1);

        let timeout = rate.timeout_interval(Duration::from_millis(80), 512);
        assert!(timeout.as_millis() >= 80);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_dup_ack_first_two_calls_do_not_trigger() {
        let mut rate = RateControl::new(std::time::Instant::now);
        rate.configure(512, 4);
        rate.cwnd_rate = 100_000;
        rate.phase = Phase::CongestionAvoidance;

        assert!(!rate.on_dup_ack(5, 512, 4));
        assert!(!rate.on_dup_ack(5, 512, 4));
        assert_eq!(rate.phase, Phase::CongestionAvoidance);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_dup_ack_third_call_triggers_fast_recovery() {
        let mut rate = RateControl::new(std::time::Instant::now);
        rate.configure(512, 4);
        rate.cwnd_rate = 100_000;
        rate.phase = Phase::CongestionAvoidance;

        assert!(!rate.on_dup_ack(5, 512, 4));
        assert!(!rate.on_dup_ack(5, 512, 4));
        assert!(rate.on_dup_ack(5, 512, 4));
        assert_eq!(rate.ssthresh, 50_000);
        assert_eq!(rate.cwnd_rate, 50_000);
        assert!(matches!(
            rate.phase,
            Phase::FastRecovery { recovery_block: 5 }
        ));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_dup_ack_new_block_resets_counter_and_does_not_trigger() {
        let mut rate = RateControl::new(std::time::Instant::now);
        rate.configure(512, 4);
        rate.cwnd_rate = 100_000;
        rate.phase = Phase::CongestionAvoidance;

        assert!(!rate.on_dup_ack(5, 512, 4));
        assert!(!rate.on_dup_ack(5, 512, 4));
        // different block resets the counter
        assert!(!rate.on_dup_ack(6, 512, 4));
        assert_eq!(rate.phase, Phase::CongestionAvoidance);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_dup_ack_counter_resets_allows_retriggering() {
        let mut rate = RateControl::new(std::time::Instant::now);
        rate.configure(512, 4);
        rate.cwnd_rate = 100_000;
        rate.phase = Phase::CongestionAvoidance;

        rate.on_dup_ack(5, 512, 4); // 1st with block 5
        rate.on_dup_ack(5, 512, 4); // 2nd with block 5
        assert!(!rate.on_dup_ack(6, 512, 4)); // reset to block 6
        assert!(!rate.on_dup_ack(6, 512, 4)); // 2nd with block 6
        assert!(rate.on_dup_ack(6, 512, 4)); // 3rd with block 6 → trigger
        assert!(matches!(
            rate.phase,
            Phase::FastRecovery { recovery_block: 6 }
        ));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_dup_ack_no_trigger_during_fast_recovery() {
        let mut rate = RateControl::new(std::time::Instant::now);
        rate.configure(512, 4);
        rate.cwnd_rate = 50_000;
        rate.ssthresh = 50_000;
        rate.phase = Phase::FastRecovery { recovery_block: 5 };

        assert!(!rate.on_dup_ack(5, 512, 4));
        assert!(!rate.on_dup_ack(5, 512, 4));
        assert!(!rate.on_dup_ack(5, 512, 4));
        // phase and cwnd unchanged — no second loss event
        assert_eq!(rate.cwnd_rate, 50_000);
        assert!(matches!(
            rate.phase,
            Phase::FastRecovery { recovery_block: 5 }
        ));
    }
}
