//! Exponential backoff for retrying failed requests.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use std::time::Duration;

/// Exponential backoff generator.
#[derive(Copy, Clone, Debug)]
pub(super) struct Backoff {
    /// Initial backoff duration.
    initial: Duration,
    /// Maximum backoff duration.
    /// If the backoff duration exceeds this value, it will be clamped to this value.
    max: Duration,
    /// Backoff multiplier.
    mult: u32,
    /// Maximum number of retries.
    /// If the retry count exceeds this value, the backoff generator will return `None`.
    /// If this value is `0`, the backoff generator will never return `None`.
    max_count: u32,
    /// Current backoff duration.
    current: Duration,
    /// Current retry count.
    count: u32,
}

impl Backoff {
    /// Create a new backoff generator.
    #[must_use]
    pub const fn new(initial: Duration, max: Duration, mult: u32, max_count: u32) -> Self {
        Self {
            initial,
            max,
            mult,
            max_count,
            current: initial,
            count: 0,
        }
    }

    /// Advance to the next backoff duration and return the previous duration.
    pub fn advance(&mut self) -> Option<Duration> {
        if self.max_count != 0 && self.count >= self.max_count {
            return None;
        }
        self.count += 1;

        let old = self.current.min(self.max);
        self.current = old * self.mult;
        Some(old)
    }

    /// Reset the backoff generator.
    pub fn reset(&mut self) {
        self.current = self.initial;
        self.count = 0;
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_backoff() {
        let mut backoff = Backoff::new(Duration::from_millis(10), Duration::from_secs(1), 2, 5);
        assert_eq!(backoff.advance(), Some(Duration::from_millis(10)));
        assert_eq!(backoff.advance(), Some(Duration::from_millis(20)));
        assert_eq!(backoff.advance(), Some(Duration::from_millis(40)));
        assert_eq!(backoff.advance(), Some(Duration::from_millis(80)));
        assert_eq!(backoff.advance(), Some(Duration::from_millis(160)));
        assert_eq!(backoff.advance(), None);
        backoff.reset();
        assert_eq!(backoff.advance(), Some(Duration::from_millis(10)));
        backoff.reset();
        assert_eq!(backoff.advance(), Some(Duration::from_millis(10)));
        assert_eq!(backoff.advance(), Some(Duration::from_millis(20)));
        assert_eq!(backoff.advance(), Some(Duration::from_millis(40)));
        assert_eq!(backoff.advance(), Some(Duration::from_millis(80)));
        assert_eq!(backoff.advance(), Some(Duration::from_millis(160)));
        assert_eq!(backoff.advance(), None);
        assert_eq!(backoff.advance(), None);
        let mut backoff = Backoff::new(Duration::from_secs(10), Duration::from_secs(1), 2, 0);
        assert_eq!(backoff.advance(), Some(Duration::from_secs(1)));
        assert_eq!(backoff.advance(), Some(Duration::from_secs(1)));
        assert_eq!(backoff.advance(), Some(Duration::from_secs(1)));
    }
}
