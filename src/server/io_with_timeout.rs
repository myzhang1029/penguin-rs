use std::{
    pin::Pin,
    task::{Poll, ready},
    time::{Duration, Instant},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct IoWithTimeout<S> {
    stream: S,
    timeout: Option<Duration>,
    deadline: Option<Instant>,
}

impl<S> IoWithTimeout<S> {
    pub fn new(stream: S, timeout: Option<Duration>) -> Self {
        let deadline = timeout.map(|dur| Instant::now() + dur);
        IoWithTimeout {
            stream,
            timeout,
            deadline,
        }
    }

    fn reset(&mut self) {
        if let Some(dur) = self.timeout {
            self.deadline = Some(Instant::now() + dur);
        }
    }

    fn elapsed(&self) -> bool {
        if let Some(deadline) = self.deadline {
            Instant::now() > deadline
        } else {
            false
        }
    }
}

impl<S: AsyncRead + Send + Unpin> AsyncRead for IoWithTimeout<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.elapsed() {
            return Poll::Ready(Err(std::io::ErrorKind::TimedOut.into()));
        }
        let this = self.get_mut();
        let stream = Pin::new(&mut this.stream);
        let result = ready!(stream.poll_read(cx, buf));
        // If the read operation is `Ready`, reset the deadline
        this.reset();
        Poll::Ready(result)
    }
}

impl<S: AsyncWrite + Send + Unpin> AsyncWrite for IoWithTimeout<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.elapsed() {
            return Poll::Ready(Err(std::io::ErrorKind::TimedOut.into()));
        }
        let this = self.get_mut();
        let stream = Pin::new(&mut this.stream);
        let result = ready!(stream.poll_write(cx, buf));
        // If the write operation is `Ready`, reset the deadline
        this.reset();
        Poll::Ready(result)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.elapsed() {
            return Poll::Ready(Err(std::io::ErrorKind::TimedOut.into()));
        }
        let this = self.get_mut();
        let stream = Pin::new(&mut this.stream);
        let result = ready!(stream.poll_flush(cx));
        // If the flush operation is `Ready`, reset the deadline
        this.reset();
        Poll::Ready(result)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.elapsed() {
            return Poll::Ready(Err(std::io::ErrorKind::TimedOut.into()));
        }
        let this = self.get_mut();
        let stream = Pin::new(&mut this.stream);
        let result = ready!(stream.poll_shutdown(cx));
        // If the shutdown operation is `Ready`, reset the deadline
        this.reset();
        Poll::Ready(result)
    }
}
