//! Marker trait for types that can be cheaply cloned.
//!
//! Inspired by facebook/gazebo's `Dupe`.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

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

impl_dupe_as_clone! {
    bytes::Bytes
}

impl<T> Dupe for std::sync::Arc<T> {
    fn dupe(&self) -> Self {
        Self::clone(self)
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
