#[cfg(all(loom, test))]
pub use self::lock::{AtomicWaker, Mutex, RwLock};
#[cfg(not(all(loom, test)))]
pub use futures_util::task::AtomicWaker;
#[cfg(all(loom, test))]
pub use loom::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU32, Ordering},
};
#[cfg(not(all(loom, test)))]
pub use parking_lot::{Mutex, RwLock};
#[cfg(not(all(loom, test)))]
pub use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU32, Ordering},
};

#[cfg(all(loom, test))]
mod lock {
    #[derive(Debug)]
    pub struct Mutex<T>(loom::sync::Mutex<T>);
    impl<T> Mutex<T> {
        pub fn new(t: T) -> Self {
            Self(loom::sync::Mutex::new(t))
        }
        pub fn lock(&self) -> loom::sync::MutexGuard<'_, T> {
            self.0.lock().expect("Poisoned `Mutex`")
        }
    }

    #[derive(Debug)]
    pub struct RwLock<T>(loom::sync::RwLock<T>);
    impl<T> RwLock<T> {
        pub fn new(t: T) -> Self {
            Self(loom::sync::RwLock::new(t))
        }
        pub fn read(&self) -> loom::sync::RwLockReadGuard<'_, T> {
            self.0.read().expect("Poisoned `RwLock`")
        }
        pub fn write(&self) -> loom::sync::RwLockWriteGuard<'_, T> {
            self.0.write().expect("Poisoned `RwLock`")
        }
    }

    #[derive(Debug)]
    pub struct AtomicWaker(loom::future::AtomicWaker);
    impl AtomicWaker {
        pub fn new() -> Self {
            Self(loom::future::AtomicWaker::new())
        }
        pub fn register(&self, waker: &std::task::Waker) {
            self.0.register_by_ref(waker)
        }
        pub fn wake(&self) {
            self.0.wake()
        }
    }
}
