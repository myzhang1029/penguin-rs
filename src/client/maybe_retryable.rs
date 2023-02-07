//! Identify whether an error is fatal or retryable.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

pub(super) trait MaybeRetryableError: std::error::Error {
    /// Returns true if we should retry the connection.
    fn retryable(&self) -> bool;
}

impl MaybeRetryableError for std::io::Error {
    fn retryable(&self) -> bool {
        self.kind() == std::io::ErrorKind::AddrNotAvailable
            || self.kind() == std::io::ErrorKind::BrokenPipe
            || self.kind() == std::io::ErrorKind::ConnectionReset
            || self.kind() == std::io::ErrorKind::ConnectionRefused
            || self.kind() == std::io::ErrorKind::ConnectionAborted
            || self.kind() == std::io::ErrorKind::NotConnected
            || self.kind() == std::io::ErrorKind::TimedOut
            || self.kind() == std::io::ErrorKind::UnexpectedEof
    }
}

impl MaybeRetryableError for tungstenite::error::ProtocolError {
    fn retryable(&self) -> bool {
        matches!(
            self,
            Self::ReceivedAfterClosing
                | Self::ResetWithoutClosingHandshake
                | Self::SendAfterClosing
        )
    }
}

impl MaybeRetryableError for tungstenite::Error {
    fn retryable(&self) -> bool {
        match self {
            Self::Io(e) => e.retryable(),
            // `tungstenite` says that `AlreadyClosed`
            // "indicates your code tries to operate on the connection when it really
            // shouldn't anymore, so this really indicates a programmer error on your part."
            // But I really don't care about its difference with `ConnectionClosed`
            // because I dislike another indicator variable for closing.
            Self::AlreadyClosed | Self::ConnectionClosed => true,
            Self::Protocol(e) => e.retryable(),
            _ => false,
        }
    }
}

impl MaybeRetryableError for crate::mux::Error {
    fn retryable(&self) -> bool {
        match self {
            Self::SendDatagram(e)
            | Self::SendStreamFrame(e)
            | Self::SendPing(e)
            | Self::Next(e)
            | Self::Flush(e) => e.retryable(),
            Self::Closed => true,
            _ => false,
        }
    }
}

impl MaybeRetryableError for super::ws_connect::Error {
    fn retryable(&self) -> bool {
        match self {
            Self::Tungstenite(e) => e.retryable(),
            Self::Tls(_) => false,
        }
    }
}
