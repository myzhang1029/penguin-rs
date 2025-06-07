use penguin_mux::timing::OptionalDuration;
use std::{
    pin::Pin,
    task::{Poll, ready},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A wrapper around an `AsyncRead` with a read timeout.
pub struct IoWithTimeout<S> {
    stream: S,
    timeout: OptionalDuration,
    deadline: Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
}

impl<S> IoWithTimeout<S> {
    pub fn new(stream: S, timeout: OptionalDuration) -> Self {
        let deadline = Box::pin(timeout.sleep());
        IoWithTimeout {
            stream,
            timeout,
            deadline,
        }
    }

    pub fn into_inner(self) -> S {
        self.stream
    }

    #[inline]
    fn reset(&mut self) {
        self.deadline = Box::pin(self.timeout.sleep());
    }

    #[inline]
    fn poll_elapsed(&mut self, cx: &mut std::task::Context<'_>) -> Poll<()> {
        self.deadline.as_mut().poll(cx)
    }
}

impl<S: AsyncRead + Send + Unpin> AsyncRead for IoWithTimeout<S> {
    #[inline]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.poll_elapsed(cx).is_ready() {
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
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let stream = Pin::new(&mut this.stream);
        let result = ready!(stream.poll_write(cx, buf));
        // If the write operation is `Ready`, reset the deadline
        this.reset();
        Poll::Ready(result)
    }

    #[inline]
    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let stream = Pin::new(&mut this.stream);
        let result = ready!(stream.poll_flush(cx));
        // If the flush operation is `Ready`, reset the deadline
        this.reset();
        Poll::Ready(result)
    }

    #[inline]
    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let stream = Pin::new(&mut this.stream);
        let result = ready!(stream.poll_shutdown(cx));
        // If the shutdown operation is `Ready`, reset the deadline
        this.reset();
        Poll::Ready(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_read_will_timeout() {
        let (reader, mut writer) = tokio::io::simplex(1024);
        let mut io = IoWithTimeout::new(reader, Duration::from_millis(100).into());

        tokio::spawn(async move {
            // Delay the write more than the timeout
            tokio::time::sleep(Duration::from_secs(1)).await;
            let _ = writer.write_all(b"hello").await;
        });

        let mut buf = vec![0; 5];
        let result = io.read_exact(&mut buf).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_read_will_timeout_long() {
        let (reader, mut writer) = tokio::io::simplex(1024);
        let mut io = IoWithTimeout::new(reader, Duration::from_secs(2).into());

        tokio::spawn(async move {
            // Delay the write more than the timeout
            tokio::time::sleep(Duration::from_secs(3)).await;
            let _ = writer.write_all(b"hello").await;
        });

        let mut buf = vec![0; 5];
        let result = io.read_exact(&mut buf).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_read_can_succeed() {
        let (reader, mut writer) = tokio::io::simplex(1024);
        let mut io = IoWithTimeout::new(reader, Duration::from_secs(1).into());

        tokio::spawn(async move {
            // Write before the timeout
            let _ = writer.write_all(b"hello").await;
        });

        let mut buf = vec![0; 5];
        let result = io.read_exact(&mut buf).await;
        assert!(result.is_ok());
        assert_eq!(&buf, b"hello");
    }

    #[tokio::test]
    async fn test_write_also_reset_deadline() {
        let (us, mut task) = tokio::io::duplex(1024);
        let mut io = IoWithTimeout::new(us, Duration::from_secs(1).into());

        tokio::spawn(async move {
            let mut buf = vec![0; 5];
            // Read from our end
            let _ = task.read_exact(&mut buf).await;
            // Delay a bit more
            tokio::time::sleep(Duration::from_millis(600)).await;
            // Write to the writer
            let _ = task.write_all(b"hello").await;
        });

        let mut buf = vec![0; 5];
        // Delay a little
        tokio::time::sleep(Duration::from_millis(500)).await;
        // Write to reset the deadline
        let result = io.write_all(b"hello").await;
        assert!(result.is_ok());
        // Now read and check if it succeeds
        let result = io.read_exact(&mut buf).await;
        assert!(result.is_ok());
        assert_eq!(&buf, b"hello");
    }
}
