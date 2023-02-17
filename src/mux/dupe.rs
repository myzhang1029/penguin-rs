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
    ($t:ty => $($g:ident),* $(,)?) => {
            impl<$($g),*> Dupe for $t {
                fn dupe(&self) -> Self {
                    self.clone()
                }
            }
    };
    ($($t:ty => ($($g:ident),* $(,)?)),* $(,)?) => {
        $(impl_dupe_as_clone!($t => $($g),*);)*
    };
}

impl_dupe_as_clone! {
    // `Bytes` is a reference-counted type.
    bytes::Bytes => (),
    // `HeaderValue` is a wrapper around `Bytes`.
    http::header::HeaderValue => (),
    // `Authority` is a wrapper around `Bytes`.
    http::uri::Authority => (),
    // `Scheme` by default is a wrapper around `Bytes`.
    http::uri::Scheme => (),
    // `PathAndQuery` is a wrapper around `Bytes`.
    http::uri::PathAndQuery => (),
    // `Uri` is the combination of the above.
    http::Uri => (),
    // `Arc` is a reference-counted type.
    std::sync::Arc<T> => (T),
    // `Sender` is designed to be cheaply cloned.
    tokio::sync::mpsc::Sender<T> => (T),
    // `UnboundedSender` is designed to be cheaply cloned.
    tokio::sync::mpsc::UnboundedSender<T> => (T),
}
