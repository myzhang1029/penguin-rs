//! Inspired by facebook/gazebo's `Dupe`

pub trait Dupe: Clone {
    /// A cheap clone of the object.
    #[inline]
    fn dupe(&self) -> Self {
        self.clone()
    }
}

impl<T> Dupe for &T {}
impl<T> Dupe for std::sync::Arc<T> {}
impl<T> Dupe for std::rc::Rc<T> {}
impl<T> Dupe for tokio::sync::mpsc::Sender<T> {}
impl Dupe for std::task::Waker {}
impl Dupe for axum_server::tls_rustls::RustlsConfig {}

impl<T: Dupe> Dupe for Option<T> {}
