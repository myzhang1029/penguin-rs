//! A wrapper around `tokio_tungstenite::WebSocketStream` that uses locking
//! to ensure that only one task is writing to the sink at a time.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::frame::{Frame, StreamFrame};
use futures_util::{Sink as FutureSink, SinkExt};
use std::collections::LinkedList;
use std::sync::Mutex;
use std::task::{ready, Waker};
use std::{cell::UnsafeCell, task::Poll};
use thiserror::Error;
use tokio::sync::{Semaphore, SemaphorePermit, TryAcquireError};
use tracing::{debug, trace};
use tungstenite::Message;

#[derive(Debug, Error)]
pub enum SinkError {
    #[error(transparent)]
    InvalidFrame(#[from] <Message as TryFrom<Frame>>::Error),
    #[error(transparent)]
    Tungstenite(#[from] tungstenite::Error),
}

impl From<SinkError> for std::io::Error {
    fn from(e: SinkError) -> Self {
        match e {
            SinkError::InvalidFrame(e) => std::io::Error::new(std::io::ErrorKind::InvalidData, e),
            SinkError::Tungstenite(e) => tungstenite_error_to_io_error(e),
        }
    }
}

pub(super) fn tungstenite_error_to_io_error(e: tungstenite::Error) -> std::io::Error {
    match e {
        tungstenite::Error::Io(e) => e,
        e => std::io::Error::new(std::io::ErrorKind::Other, e),
    }
}

/// `Sink` of frames with locking.
#[derive(Debug)]
pub(super) struct LockedMessageSink<Sink> {
    /// The sink to write to.
    sink: UnsafeCell<Sink>,
    /// Semaphore to ensure that only one task is writing to the sink at a time.
    semaphore: Semaphore,
    /// List of wakers to wake when the lock is available.
    /// There is no need to use `tokio::sync::Mutex` here, since we don't need
    /// to hold the lock across an `.await`.
    waiters: Mutex<LinkedList<Waker>>,
}

// As long as `Sink: Send + Sync`, it's fine to send and share
// `LockedMessageSink<Sink>` between threads.
// If `Sink` were not `Send`, sending and sharing a `LockedMessageSink<Sink>`
// would be bad, since you canaccess `Sink` through `LockedMessageSink<Sink>`.
// - from `tokio::sync::RwLock`
unsafe impl<T> Send for LockedMessageSink<T> where T: Send {}
unsafe impl<T> Sync for LockedMessageSink<T> where T: Send + Sync {}

impl<Sink> LockedMessageSink<Sink> {
    /// Create a new `LockedMessageSink` from a `Sink`.
    pub fn new(sink: Sink) -> Self {
        let semaphore = Semaphore::new(1);
        Self {
            sink: UnsafeCell::new(sink),
            semaphore,
            waiters: Mutex::new(LinkedList::new()),
        }
    }
}

impl<Sink: FutureSink<Message, Error = tungstenite::Error> + Unpin> LockedMessageSink<Sink> {
    /// Lock, or wake when lock is available.
    fn try_lock(&self, cx: &mut std::task::Context<'_>) -> Poll<SemaphorePermit> {
        match self.semaphore.try_acquire() {
            Ok(guard) => {
                trace!("acquired the lock");
                Poll::Ready(guard)
            }
            Err(TryAcquireError::NoPermits) => {
                trace!("waiting for the lock");
                // `unwrap`: panic if the lock is poisoned
                self.waiters.lock().unwrap().push_back(cx.waker().clone());
                // `pending`: if we return here, `cx` is woken up
                Poll::Pending
            }
            Err(TryAcquireError::Closed) => unreachable!("Semaphore lives through `self`"),
        }
    }

    /// Wake the next waiter if there is one.
    fn wake_next_waiter(&self) {
        trace!("lock released");
        // `unwrap`: panic if the lock is poisoned
        let mut waiters = self.waiters.lock().unwrap();
        if let Some(waker) = waiters.pop_front() {
            debug!("waking up a waiter");
            waker.wake();
        }
    }

    /// Lock and run `sink.start_send` on the underlying `Sink`.
    #[tracing::instrument(skip(self, cx, buf), level = "trace")]
    pub fn poll_send_stream_buf(
        &self,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
        our_port: u16,
        their_port: u16,
    ) -> Poll<Result<(), SinkError>> {
        let frame = Frame::Stream(StreamFrame::new_psh(our_port, their_port, buf.to_owned()));
        self.poll_send_message(cx, frame.try_into()?)
            .map_err(|e| e.into())
    }

    /// Lock and send a message
    #[tracing::instrument(skip(self, cx), level = "trace")]
    pub fn poll_send_message(
        &self,
        cx: &mut std::task::Context<'_>,
        msg: Message,
    ) -> Poll<Result<(), tungstenite::Error>> {
        // `ready`: if we return here, nothing happens
        let guard = ready!(self.try_lock(cx));
        // Safety: access protected by `semaphore`
        let sink = unsafe { &mut *self.sink.get() };
        match sink.poll_ready_unpin(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => {
                // `guard` is implicitly dropped here
                self.wake_next_waiter();
                return Poll::Ready(Err(e.into()));
            }
            Poll::Pending => {
                // `guard` is implicitly dropped here
                self.wake_next_waiter();
                return Poll::Pending;
            }
        }
        let result = sink.start_send_unpin(msg).map_err(|e| e.into());
        trace!("message sent");
        // So that `guard` is not dead code
        drop(guard);
        self.wake_next_waiter();
        Poll::Ready(result)
    }

    /// Lock and send a message
    #[tracing::instrument(skip_all, level = "trace")]
    pub async fn send_message(&self, msg: Message) -> Result<(), tungstenite::Error> {
        std::future::poll_fn(move |cx| self.poll_send_message(cx, msg.to_owned())).await
    }

    /// Lock and run `sink.poll_flush` on the underlying `Sink`.
    #[tracing::instrument(skip(self, cx), level = "trace")]
    pub fn poll_flush(
        &self,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), tungstenite::Error>> {
        // `ready`: if we return here, nothing happens
        let guard = ready!(self.try_lock(cx));
        // Safety: access protected by `semaphore`
        let sink = unsafe { &mut *self.sink.get() };
        let result = sink.poll_flush_unpin(cx).map_err(|e| e.into());
        // So that `guard` is not dead code
        drop(guard);
        self.wake_next_waiter();
        result
    }

    /// Lock and run `sink.poll_flush` on the underlying `Sink`.
    #[tracing::instrument(skip(self), level = "trace")]
    pub async fn flush(&self) -> Result<(), tungstenite::Error> {
        std::future::poll_fn(|cx| self.poll_flush(cx)).await
    }

    /// Lock and run `sink.poll_close` on the underlying `Sink`.
    #[tracing::instrument(skip(self, cx), level = "trace")]
    pub fn poll_close(
        &self,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), tungstenite::Error>> {
        // `ready`: if we return here, nothing happens
        let guard = ready!(self.try_lock(cx));
        // Safety: access protected by `semaphore`
        let sink = unsafe { &mut *self.sink.get() };
        let result = sink.poll_close_unpin(cx);
        // So that `guard` is not dead code
        drop(guard);
        self.wake_next_waiter();
        result.map_err(|e| e.into())
    }

    /// Lock and run `sink.poll_close` on the underlying `Sink`.
    #[tracing::instrument(skip(self), level = "trace")]
    pub async fn close(&self) -> Result<(), tungstenite::Error> {
        std::future::poll_fn(|cx| self.poll_close(cx)).await
    }
}

// Isn't very reasonable to test this file directly
