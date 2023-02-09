//! Inspired by facebook/gazebo's `Dupe`.

/// Marker trait for types that can be cheaply cloned.
pub trait Dupe {
    /// A cheap clone of the object.
    #[must_use]
    fn dupe(&self) -> Self;
}

macro_rules! impl_dupe_as_clone {
    ($($t:ty),*) => {
        $(
            impl Dupe for $t {
                fn dupe(&self) -> Self {
                    self.clone()
                }
            }
        )*
    };
}

impl_dupe_as_clone!{
    bytes::Bytes
}

impl<T> Dupe for std::sync::Arc<T> {
    fn dupe(&self) -> Self {
        std::sync::Arc::clone(self)
    }
}

impl<T> Dupe for tokio::sync::mpsc::Sender<T> {
    fn dupe(&self) -> Self {
        self.clone()
    }
}

impl<T> Dupe for tokio::sync::mpsc::UnboundedSender<T> {
    fn dupe(&self) -> Self {
        self.clone()
    }
}
