//! Synchronization primitives selector.

#[cfg(all(test, loom))]
pub(crate) use loom::{
    future::AtomicWaker as LoomAtomicWaker,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex as LoomMutex,
    },
};

#[cfg(not(all(test, loom)))]
pub(crate) use ::{
    futures_util::task::AtomicWaker,
    parking_lot::Mutex,
    std::sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
};

#[cfg(all(test, loom))]
#[inline]
pub(crate) fn spawn<F>(f: F) -> JoinHandle<<F as std::future::Future>::Output>
where
    F: std::future::Future + Send + 'static,
{
    JoinHandle(loom::thread::spawn(move || loom::future::block_on(f)))
}

#[cfg(not(all(test, loom)))]
#[inline]
pub(crate) fn spawn<F>(f: F) -> JoinHandle<<F as std::future::Future>::Output>
where
    F: std::future::Future + Send + 'static,
    <F as std::future::Future>::Output: Send,
{
    JoinHandle(tokio::spawn(f))
}

pub(crate) struct JoinHandle<T>(
    #[cfg(all(test, loom))] loom::thread::JoinHandle<T>,
    #[cfg(not(all(test, loom)))] tokio::task::JoinHandle<T>,
);

impl<T> JoinHandle<T> {
    /// The `loom` part really should only be used in tests
    /// because it is blocking.
    #[cfg(all(test, loom))]
    #[inline]
    pub(crate) async fn join(self) -> std::thread::Result<T> {
        self.0.join()
    }

    #[cfg(not(all(test, loom)))]
    #[allow(dead_code)]
    #[inline]
    pub(crate) async fn join(self) -> Result<T, tokio::task::JoinError> {
        self.0.await
    }
}

/// A `loom::sync::Mutex` that panics on poisoning.
#[cfg(all(test, loom))]
#[derive(Debug)]
pub(crate) struct Mutex<T>(LoomMutex<T>);

#[cfg(all(test, loom))]
impl<T> Mutex<T> {
    #[inline]
    pub(crate) fn new(t: T) -> Self {
        Self(LoomMutex::new(t))
    }
    #[inline]
    pub(crate) fn lock(&self) -> loom::sync::MutexGuard<'_, T> {
        self.0.lock().expect("loom mutex poisoned")
    }
}

/// A `loom::future::AtomicWaker` that uses `register_by_ref` as `register`.
#[cfg(all(test, loom))]
#[derive(Debug)]
pub(crate) struct AtomicWaker(LoomAtomicWaker);

#[cfg(all(test, loom))]
impl AtomicWaker {
    #[inline]
    pub(crate) fn new() -> Self {
        Self(LoomAtomicWaker::new())
    }
    #[inline]
    pub(crate) fn register(&self, waker: &std::task::Waker) {
        self.0.register_by_ref(waker)
    }
    #[inline]
    pub(crate) fn wake(&self) {
        self.0.wake()
    }
}

#[cfg(all(test, loom))]
macro_rules! exec_test {
    ($tt:expr) => {
        ::loom::model(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on($tt)
        })
    };
}

#[cfg(not(loom))]
#[cfg(test)]
macro_rules! exec_test {
    ($tt:expr) => {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on($tt)
    };
}

#[cfg(test)]
pub(crate) use exec_test;
