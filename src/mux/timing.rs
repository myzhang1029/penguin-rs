//! Various timing utilities.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use std::{
    fmt::{self, Debug},
    time::Duration,
};

/// Exponential backoff for retrying failed requests.
#[derive(Copy, Clone, Debug)]
pub struct Backoff {
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
    pub const fn reset(&mut self) {
        self.current = self.initial;
        self.count = 0;
    }
}

/// An optional duration: an empty duration means that there should be no timeout,
/// or that an interval should be infinite.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct OptionalDuration(Option<Duration>);

impl OptionalDuration {
    /// The special constant representing "no timeout" or "indefinite".
    pub const NONE: Self = Self(None);

    /// Convenience method to create an `OptionalDuration` of the given number of seconds
    #[must_use]
    pub const fn from_secs(duration: u64) -> Self {
        Self(Some(Duration::from_secs(duration)))
    }

    /// Use the optional duration to timeout a future
    ///
    /// # Errors
    /// Returns an `Err` variant if the future does not finish in the specified duration.
    pub async fn timeout<T>(&self, future: T) -> Result<T::Output, tokio::time::error::Elapsed>
    where
        T: std::future::Future,
    {
        match self.0 {
            Some(duration) => tokio::time::timeout(duration, future).await,
            None => Ok(future.await),
        }
    }
}

impl std::str::FromStr for OptionalDuration {
    type Err = std::num::ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let value = s.parse::<u64>()?;
        if value == 0 {
            Ok(Self(None))
        } else {
            Ok(Self::from_secs(value))
        }
    }
}

impl fmt::Display for OptionalDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(duration) => duration.fmt(f),
            None => write!(f, "indefinite"),
        }
    }
}

/// An optional interval
#[derive(Debug)]
pub struct OptionalInterval(Option<tokio::time::Interval>);

impl OptionalInterval {
    /// Defines the behavior of the internal [`tokio::time::Interval`] when it misses a tick.
    pub fn set_missed_tick_behavior(&mut self, behavior: tokio::time::MissedTickBehavior) {
        if let Some(interval) = &mut self.0 {
            interval.set_missed_tick_behavior(behavior);
        }
    }

    /// Completes when the next instant in the interval has been reached.
    pub async fn tick(&mut self) -> tokio::time::Instant {
        if let Some(interval) = &mut self.0 {
            interval.tick().await
        } else {
            // We shall never resolve
            std::future::pending::<tokio::time::Instant>().await
        }
    }
}

impl From<OptionalDuration> for OptionalInterval {
    fn from(dur: OptionalDuration) -> Self {
        Self(dur.0.map(tokio::time::interval))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::FutureExt;

    #[test]
    fn test_backoff() {
        crate::tests::setup_logging();
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

    #[test]
    fn test_optional_duration() {
        crate::tests::setup_logging();
        let dur = OptionalDuration::from_secs(10);
        assert_eq!(dur.to_string(), "10s");
        let dur_none = OptionalDuration::NONE;
        assert_eq!(dur_none.to_string(), "indefinite");
        let parsed: OptionalDuration = "20".parse().unwrap();
        assert_eq!(parsed.to_string(), "20s");
        let parsed_none: OptionalDuration = "0".parse().unwrap();
        assert_eq!(parsed_none, OptionalDuration::NONE);
    }

    #[tokio::test]
    async fn test_optional_interval() {
        crate::tests::setup_logging();
        let dur = OptionalDuration::from_secs(2);
        let mut interval = OptionalInterval::from(dur);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        assert!(interval.tick().now_or_never().is_none());
        tokio::time::sleep(Duration::from_secs(3)).await;
        let instant = interval.tick().now_or_never().unwrap();
        assert!(instant < tokio::time::Instant::now());
    }
}
