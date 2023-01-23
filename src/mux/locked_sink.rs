//! A wrapper around `tokio_tungstenite::WebSocketStream` that uses locking
//! to ensure that only one task is writing to the sink at a time.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::frame::{Frame, StreamFrame};
use futures_util::{Sink as FutureSink, SinkExt};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::task::{ready, Waker};
use std::{cell::UnsafeCell, task::Poll};
use thiserror::Error;
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
    /// To ensure that only one task is writing to the sink at a time.
    in_use: AtomicBool,
    /// List of wakers to wake when the lock is available.
    /// There is no need to use `tokio::sync::Mutex` here, since we don't need
    /// to hold the lock across an `.await`.
    waiters: Mutex<VecDeque<Waker>>,
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
        Self {
            sink: UnsafeCell::new(sink),
            in_use: AtomicBool::new(false),
            waiters: Mutex::new(VecDeque::new()),
        }
    }
}

// N.B.: Make sure all return paths call `unlock`!
impl<Sink: FutureSink<Message, Error = tungstenite::Error> + Unpin> LockedMessageSink<Sink> {
    /// Lock, or wake when lock is available.
    fn try_lock(&self, cx: &mut std::task::Context<'_>) -> Poll<()> {
        if self.in_use.swap(true, Ordering::Acquire) {
            // Someone else is using the sink, so we need to wait.
            // `unwrap`: panic if the lock is poisoned
            self.waiters.lock().unwrap().push_back(cx.waker().clone());
            Poll::Pending
        } else {
            // `ready`: if we return here, `cx` is not woken up
            trace!("acquired the lock");
            Poll::Ready(())
        }
    }

    /// Unlock and wake the next waiter if there is one.
    fn unlock(&self) {
        self.in_use.store(false, Ordering::Release);
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
            .map_err(std::convert::Into::into)
    }

    /// Lock and send a message
    #[tracing::instrument(skip(self, cx), level = "trace")]
    pub fn poll_send_message(
        &self,
        cx: &mut std::task::Context<'_>,
        msg: Message,
    ) -> Poll<Result<(), tungstenite::Error>> {
        // `ready`: if we return here, nothing happens
        ready!(self.try_lock(cx));
        // Safety: access protected by `semaphore`
        let sink = unsafe { &mut *self.sink.get() };
        match sink.poll_ready_unpin(cx) {
            Poll::Ready(Ok(())) => {}
            result @ Poll::Ready(Err(_)) => {
                self.unlock();
                return result;
            }
            Poll::Pending => {
                self.unlock();
                return Poll::Pending;
            }
        }
        let result = sink.start_send_unpin(msg);
        trace!("message sent");
        self.unlock();
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
        ready!(self.try_lock(cx));
        // Safety: access protected by `semaphore`
        let sink = unsafe { &mut *self.sink.get() };
        let result = sink.poll_flush_unpin(cx);
        self.unlock();
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
        ready!(self.try_lock(cx));
        // Safety: access protected by `semaphore`
        let sink = unsafe { &mut *self.sink.get() };
        let result = sink.poll_close_unpin(cx);
        self.unlock();
        result
    }

    /// Lock and run `sink.poll_close` on the underlying `Sink`.
    #[tracing::instrument(skip(self), level = "trace")]
    pub async fn close(&self) -> Result<(), tungstenite::Error> {
        std::future::poll_fn(|cx| self.poll_close(cx)).await
    }
}

// Isn't very reasonable to test this file directly
