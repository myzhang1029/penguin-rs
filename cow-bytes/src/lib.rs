//! A `Cow`-like type for bytes that uses `Bytes` as the owned variant.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

#![deny(rust_2018_idioms, missing_docs, missing_debug_implementations)]
#![deny(clippy::pedantic, clippy::cargo, clippy::nursery, clippy::unwrap_used)]
#![allow(clippy::multiple_crate_versions)]
#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

use alloc::borrow::Borrow;
use bytes::{Buf, Bytes};
use core::ops::Deref;

/// A special version of `std::borrow::Cow` whose owned variant is [`Bytes`].
#[derive(Clone, Debug, Eq, derive_more::From)]
pub enum CowBytes<'data> {
    /// A borrowed slice of bytes
    Borrowed(&'data [u8]),
    /// An owned `Bytes` instance
    Owned(Bytes),
}

impl PartialEq for CowBytes<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref() == other.as_ref()
    }
}

impl AsRef<[u8]> for CowBytes<'_> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Borrowed(data) => data,
            Self::Owned(bytes) => bytes.as_ref(),
        }
    }
}

impl Borrow<[u8]> for CowBytes<'_> {
    #[inline]
    fn borrow(&self) -> &[u8] {
        self.as_ref()
    }
}

impl Deref for CowBytes<'_> {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl Default for CowBytes<'_> {
    #[inline]
    fn default() -> Self {
        Self::Borrowed(&[])
    }
}

macro_rules! impl_fn_by_delegate {
    ($fn:ident, $self_ty:ty, $ret:ty, $field:ident$(,)? $($arg_name:ident: $arg_ty:ty),*) => {
        #[inline]
        fn $fn(
            self: $self_ty,
            $($arg_name: $arg_ty),*
        ) -> $ret {
            match self {
                Self::Borrowed(data) => data.$fn($($arg_name),*),
                Self::Owned(bytes) => bytes.$fn($($arg_name),*),
            }
        }
    };
}

impl Buf for CowBytes<'_> {
    impl_fn_by_delegate!(advance, &mut Self, (), self, cnt: usize);
    impl_fn_by_delegate!(remaining, &Self, usize, self);
    impl_fn_by_delegate!(chunk, &Self, &[u8], self);
}

impl CowBytes<'_> {
    /// Convert the `CowBytes` into an owned `Bytes` instance.
    #[inline]
    pub fn into_owned(self) -> Bytes {
        match self {
            Self::Borrowed(data) => Bytes::from(data.to_vec()),
            Self::Owned(bytes) => bytes,
        }
    }

    /// Get the length of the data in the `CowBytes`.
    #[inline]
    pub const fn len(&self) -> usize {
        match self {
            Self::Borrowed(data) => data.len(),
            Self::Owned(bytes) => bytes.len(),
        }
    }

    /// Splits the bytes into two at the given index.
    ///
    /// See [`Bytes::split_to`] for more details. This is an `O(1)` operation.
    #[inline]
    pub fn split_to(&mut self, at: usize) -> Self {
        match self {
            Self::Borrowed(data) => {
                let (left, right) = data.split_at(at);
                *self = Self::Borrowed(right);
                Self::Borrowed(left)
            }
            Self::Owned(bytes) => Self::Owned(bytes.split_to(at)),
        }
    }

    /// Splits the bytes into two at the given index.
    ///
    /// See [`Bytes::split_off`] for more details. This is an `O(1)` operation.
    #[inline]
    #[must_use = "consider CowBytes::advance if you don't need the other half"]
    pub fn split_off(&mut self, at: usize) -> Self {
        match self {
            Self::Borrowed(data) => {
                let (left, right) = data.split_at(at);
                *self = Self::Borrowed(left);
                Self::Borrowed(right)
            }
            Self::Owned(bytes) => Self::Owned(bytes.split_off(at)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cow_bytes_eq() {
        let cow1 = CowBytes::Borrowed(b"1234");
        let cow2 = CowBytes::Owned(Bytes::from_static(b"1234"));
        assert_eq!(cow1, cow2);
        let cow3 = CowBytes::Borrowed(b"12345");
        assert_ne!(cow1, cow3);
    }

    #[test]
    fn test_cow_bytes() {
        let cow1 = CowBytes::Borrowed(&[1, 2, 3]);
        let cow2 = cow1.clone();
        assert_eq!(cow1, cow2);
        assert_eq!(cow1.len(), 3);
        assert_eq!(cow2.len(), 3);
        let cow3 = cow1.into_owned();
        assert_eq!(cow3.as_ref(), cow2.as_ref());
        let bytes = Bytes::from(alloc::vec![4u8, 5, 6]);
        let cow4 = CowBytes::Owned(bytes.clone());
        assert_eq!(cow4.as_ref(), bytes.as_ref());
        assert_eq!(cow4.len(), 3);
    }

    #[test]
    fn test_default_is_empty() {
        let cow = CowBytes::default();
        assert_eq!(cow.as_ref(), b"");
        assert_eq!(cow.len(), 0);
        assert_eq!(cow.remaining(), 0);
        assert_eq!(cow.chunk(), b"");
    }

    #[test]
    fn test_deref_and_as_ref() {
        let cow = CowBytes::Borrowed(b"hello");
        assert_eq!(cow.as_ref(), &cow[..]);
        assert_eq!(&*cow, b"hello");
    }

    #[test]
    fn test_split_to_borrowed() {
        let mut cow = CowBytes::Borrowed(b"abcdef");
        let left = cow.split_to(2);
        assert_eq!(left.as_ref(), b"ab");
        assert_eq!(cow.as_ref(), b"cdef");
    }

    #[test]
    fn test_split_off_borrowed() {
        let mut cow = CowBytes::Borrowed(b"abcdef");
        let right = cow.split_off(4);
        assert_eq!(cow.as_ref(), b"abcd");
        assert_eq!(right.as_ref(), b"ef");
    }

    #[test]
    fn test_split_to_owned() {
        let mut cow = CowBytes::Owned(Bytes::from_static(b"abcdef"));
        let left = cow.split_to(3);
        assert_eq!(left.as_ref(), b"abc");
        assert_eq!(cow.as_ref(), b"def");
    }

    #[test]
    fn test_buf_methods() {
        let mut cow = CowBytes::Borrowed(b"1234");
        assert_eq!(cow.remaining(), 4);
        assert_eq!(cow.chunk(), b"1234");
        cow.advance(2);
        assert_eq!(cow.remaining(), 2);
        assert_eq!(cow.chunk(), b"34");
    }

    #[test]
    fn test_into_owned_from_borrowed() {
        let cow = CowBytes::Borrowed(b"data");
        let bytes = cow.into_owned();
        assert_eq!(bytes.as_ref(), b"data");
    }

    #[test]
    fn test_from_conversions() {
        let a: CowBytes<'static> = (&b"xyz"[..]).into();
        let b: CowBytes<'static> = Bytes::from_static(b"xyz").into();
        assert_eq!(a, b);
    }
}
