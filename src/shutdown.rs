//! Cooperative shutdown: a Ctrl+C flag plus an interruptible interval wait.

use std::error::Error;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::{Duration, Instant};

/// Installs the Ctrl+C handler and returns the flag that is cleared on signal.
pub fn install_ctrlc_handler() -> Result<Arc<AtomicBool>, Box<dyn Error>> {
    let running = Arc::new(AtomicBool::new(true));
    let handler_flag = Arc::clone(&running);
    let monitor_thread = thread::current();
    ctrlc::set_handler(move || {
        handler_flag.store(false, Ordering::SeqCst);
        monitor_thread.unpark();
    })?;
    Ok(running)
}

/// Sleeps for `interval`, returning false if shutdown was requested first.
///
/// The flag is rechecked after every wakeup because `park_timeout` may return
/// spuriously.
pub fn wait_for_interval(interval: Duration, running: &AtomicBool) -> bool {
    let started = Instant::now();
    while running.load(Ordering::SeqCst) {
        let remaining = interval.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return true;
        }
        thread::park_timeout(remaining);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn interval_wait_handles_cancellation_and_spurious_wakeups() {
        let running = AtomicBool::new(false);
        assert!(!wait_for_interval(Duration::from_secs(60), &running));

        running.store(true, Ordering::SeqCst);
        thread::current().unpark();
        let started = Instant::now();
        let interval = Duration::from_millis(10);
        assert!(wait_for_interval(interval, &running));
        assert!(started.elapsed() >= interval);
    }

    #[test]
    fn interval_wait_returns_immediately_for_zero_interval() {
        let running = AtomicBool::new(true);
        let started = Instant::now();
        assert!(wait_for_interval(Duration::ZERO, &running));
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
