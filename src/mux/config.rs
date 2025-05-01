//! Multiplexor configuration
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

/// Configuration parameters for the multiplexor.
/// See each method for details on the parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    pub(crate) keepalive_interval: crate::timing::OptionalDuration,
    pub(crate) datagram_buffer_size: usize,
    pub(crate) stream_buffer_size: usize,
    pub(crate) bind_buffer_size: usize,
    pub(crate) max_flow_id_retries: usize,
    pub(crate) rwnd: u32,
    pub(crate) default_rwnd_threshold: u32,
}

impl Default for Options {
    fn default() -> Self {
        Self::new()
    }
}

impl Options {
    /// Create a new [`Options`] instance with default values.
    #[must_use]
    pub const fn new() -> Self {
        const DATAGRAM_BUFFER_SIZE: usize = 1 << 9;
        const STREAM_BUFFER_SIZE: usize = 1 << 4;
        const MAX_FLOW_ID_RETRIES: usize = 3;

        #[cfg(not(test))]
        const RWND: u32 = 1 << 9;
        #[cfg(test)]
        const RWND: u32 = 4;
        #[cfg(not(test))]
        const DEFAULT_RWND_THRESHOLD: u32 = 1 << 8;
        #[cfg(test)]
        const DEFAULT_RWND_THRESHOLD: u32 = RWND;
        Self {
            keepalive_interval: crate::timing::OptionalDuration::NONE,
            datagram_buffer_size: DATAGRAM_BUFFER_SIZE,
            stream_buffer_size: STREAM_BUFFER_SIZE,
            bind_buffer_size: 0,
            max_flow_id_retries: MAX_FLOW_ID_RETRIES,
            rwnd: RWND,
            default_rwnd_threshold: DEFAULT_RWND_THRESHOLD,
        }
    }

    /// Sets the interval at which to send [`Ping`](crate::ws::Message::Ping) frames.
    #[must_use]
    pub const fn keepalive_interval(mut self, interval: crate::timing::OptionalDuration) -> Self {
        self.keepalive_interval = interval;
        self
    }

    /// Number of datagram frames to buffer in the channels on the receiving end.
    /// If the buffer is not read fast enough, excess datagrams will be dropped.
    ///
    /// # Panics
    /// Panics if the buffer size is not positive.
    #[must_use]
    pub const fn datagram_buffer_size(mut self, size: usize) -> Self {
        assert!(size > 0, "datagram_buffer_size must be greater than 0");
        self.datagram_buffer_size = size;
        self
    }

    /// Number of `MuxStream`s to buffer in the channels on the receiving end.
    /// Since there is a handshake to obtain `MuxStream`s, there should be no
    /// need to have a crazy high buffer size.
    ///
    /// # Panics
    /// Panics if the buffer size is not positive.
    #[must_use]
    pub const fn stream_buffer_size(mut self, size: usize) -> Self {
        assert!(size > 0, "stream_buffer_size must be greater than 0");
        self.stream_buffer_size = size;
        self
    }

    /// Number of [`Bind`](crate::frame::OpCode::Bind) requests to buffer
    /// in the channels on the receiving end.
    /// Setting this to zero disallows the multiplexor from accepting any
    /// `Bind` requests from the other end and
    /// is the default. Make sure the security implications are understood
    /// before enabling this.
    #[must_use]
    pub const fn bind_buffer_size(mut self, size: usize) -> Self {
        self.bind_buffer_size = size;
        self
    }

    /// Number of retries for establishing a connection if the other end rejects our flow_id selection.
    ///
    /// # Panics
    /// Panics if the number of retries is not positive.
    #[must_use]
    pub const fn max_flow_id_retries(mut self, retries: usize) -> Self {
        assert!(retries > 0, "max_flow_id_retries must be greater than 0");
        self.max_flow_id_retries = retries;
        self
    }

    /// Number of `StreamFrame`s to buffer in `MuxStream`'s channels before blocking.
    ///
    /// # Panics
    /// Panics if the buffer size is not positive or does not fit in a `usize`.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub const fn rwnd(mut self, rwnd: u32) -> Self {
        // Make sure this value fits in a usize
        assert!((rwnd as usize) as u32 == rwnd, "rwnd must fit in a usize");
        assert!(rwnd > 0, "rwnd must be greater than 0");
        self.rwnd = rwnd;
        self
    }

    /// Number of [`Push`](crate::frame::OpCode::Push) frames between [`Acknowledge`](crate::frame::OpCode::Acknowledge)s:
    /// If too low, `Acknowledge`s will consume too much bandwidth;
    /// If too high, writers may block.
    ///
    /// Note that if the peer indicates a lower `rwnd` value in the handshake,
    /// this value will be ignored for that connection.
    ///
    /// # Panics
    /// Panics if the value is not positive.
    #[must_use]
    pub const fn default_rwnd_threshold(mut self, threshold: u32) -> Self {
        assert!(
            threshold > 0,
            "default_rwnd_threshold must be greater than 0"
        );
        self.default_rwnd_threshold = threshold;
        self
    }
}
