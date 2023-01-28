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
            tungstenite::error::ProtocolError::ReceivedAfterClosing
                | tungstenite::error::ProtocolError::ResetWithoutClosingHandshake
        )
    }
}

impl MaybeRetryableError for tungstenite::Error {
    fn retryable(&self) -> bool {
        match self {
            tungstenite::Error::Io(e) => e.retryable(),
            tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed => true,
            tungstenite::Error::Protocol(e) => e.retryable(),
            _ => false,
        }
    }
}

impl MaybeRetryableError for crate::mux::Error {
    fn retryable(&self) -> bool {
        match self {
            crate::mux::Error::Io(e) => e.retryable(),
            crate::mux::Error::Tungstenite(e) => e.retryable(),
            crate::mux::Error::StreamTxClosed => true,
            _ => false,
        }
    }
}

impl MaybeRetryableError for super::ws_connect::Error {
    fn retryable(&self) -> bool {
        match self {
            super::ws_connect::Error::Tungstenite(e) => e.retryable(),
            super::ws_connect::Error::Tls(_) => false,
        }
    }
}
