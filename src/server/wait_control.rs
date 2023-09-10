use core::time::Duration;

pub struct WaitControl {
    idle: u8,
    sending: bool,
    receiving: bool,
}

impl WaitControl {
    pub fn new() -> Self {
        Self {
            idle: 0,
            sending: false,
            receiving: false,
        }
    }

    pub fn sending(&mut self, sent: bool) {
        if sent {
            self.idle = 0;
            self.sending = true;
        } else {
            self.idle = self.idle.wrapping_add(1);
            self.sending = false;
        }
    }

    pub fn receiver_idle(&mut self) {
        self.idle = self.idle.wrapping_add(1);
        self.receiving = false;
    }

    pub fn receiving(&mut self) {
        self.idle = 0;
        self.receiving = true;
    }

    pub fn wait_for(&self, client_size: usize) -> Option<Duration> {
        if client_size == 0 {
            Duration::from_millis(500).into()
        } else if !self.sending && !self.receiving {
            Duration::from_millis(self.idle as u64).into()
        } else {
            None
        }
    }
}
