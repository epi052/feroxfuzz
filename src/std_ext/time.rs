use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// get current time since unix epoch
#[must_use]
#[inline]
pub fn current_time() -> Duration {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
}
