//! A `Cow`-like type for bytes that uses `Bytes` as the owned variant.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

#![deny(rust_2018_idioms, missing_docs, missing_debug_implementations)]
#![deny(clippy::pedantic, clippy::cargo, clippy::nursery, clippy::unwrap_used)]
#![allow(clippy::multiple_crate_versions)]
#![no_std]

extern crate alloc;

mod macros;

use alloc::borrow::Borrow;
use bytes::{Buf, Bytes};
use core::{fmt, ops::Deref};
use macros::{impl_by_as_ref, impl_by_delegate};

/// A special version of `std::borrow::Cow` whose owned variant is [`Bytes`].
///
/// The variants are named `Temporary` and `Static` since a `Bytes` instance
/// can also contain shared data.
///
/// Note that the `Temporary` may also contain a slice of lifetime `'static`.
#[derive(Clone, Debug, Eq, derive_more::From, derive_more::IsVariant)]
pub enum CowBytes<'data> {
    /// A borrowed slice of bytes
    Temporary(&'data [u8]),
    /// An owned `Bytes` instance
    Static(Bytes),
}

impl_by_as_ref! {
    impl PartialEq {
        #[inline] fn eq(&Self, [other]) -> bool
    }
    impl Borrow<[u8]> {
        #[inline] fn borrow(&Self) -> &[u8]
    }
    impl core::hash::Hash {
        #[inline] fn hash<H: core::hash::Hasher>(&Self, state: &mut H)
    }
}

impl_by_delegate! {
    impl PartialEq<Bytes> {
        #[inline] fn eq(&Self, other: &Bytes) -> bool
    }
    impl AsRef<[u8]> {
        #[inline] fn as_ref(&Self) -> &[u8]
    }
    impl Buf {
        #[inline] fn advance(&mut Self, cnt: usize)
        #[inline] fn remaining(&Self) -> usize
        #[inline] fn chunk(&Self) -> &[u8]
    }
}

impl Deref for CowBytes<'_> {
    type Target = [u8];

    impl_by_delegate! { #[inline] fn deref(&Self) -> &[u8] }
}

impl Default for CowBytes<'_> {
    #[inline]
    fn default() -> Self {
        Self::Static(Bytes::new())
    }
}

impl fmt::LowerHex for CowBytes<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.as_ref() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::UpperHex for CowBytes<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.as_ref() {
            write!(f, "{byte:02X}")?;
        }
        Ok(())
    }
}

impl CowBytes<'_> {
    /// Creates a new `CowBytes` instance from a static slice of bytes.
    ///
    /// The resulting `CowBytes` will be in the `Static` variant.
    /// This operation does not involve any heap allocation.
    #[inline]
    #[must_use]
    pub const fn from_static(data: &'static [u8]) -> Self {
        Self::Static(Bytes::from_static(data))
    }

    /// Convert the `CowBytes` into a `Bytes` instance.
    #[inline]
    pub fn into_static(self) -> Bytes {
        match self {
            Self::Temporary(data) => Bytes::from(data.to_vec()),
            Self::Static(bytes) => bytes,
        }
    }

    impl_by_delegate! {
        #[doc = "Get the length of the data in the `CowBytes`."]
        #[inline]
        pub [const] fn len(&Self) -> usize

        #[doc = "Check if the `CowBytes` is empty."]
        #[inline]
        pub [const] fn is_empty(&Self) -> bool
    }

    /// Splits the bytes into two at the given index.
    ///
    /// See [`Bytes::split_to`] for more details. This is an `O(1)` operation.
    #[inline]
    #[must_use = "consider CowBytes::advance if you don't need the other half"]
    pub fn split_to(&mut self, at: usize) -> Self {
        match self {
            Self::Temporary(data) => {
                let (left, right) = data.split_at(at);
                *self = Self::Temporary(right);
                Self::Temporary(left)
            }
            Self::Static(bytes) => Self::Static(bytes.split_to(at)),
        }
    }

    /// Splits the bytes into two at the given index.
    ///
    /// See [`Bytes::split_off`] for more details. This is an `O(1)` operation.
    #[inline]
    #[must_use = "consider CowBytes::truncate if you don't need the other half"]
    pub fn split_off(&mut self, at: usize) -> Self {
        match self {
            Self::Temporary(data) => {
                let (left, right) = data.split_at(at);
                *self = Self::Temporary(left);
                Self::Temporary(right)
            }
            Self::Static(bytes) => Self::Static(bytes.split_off(at)),
        }
    }

    /// Shortens the buffer, keeping the first `len` bytes and dropping the rest.
    #[inline]
    pub fn truncate(&mut self, len: usize) {
        match self {
            Self::Temporary(data) => *self = Self::Temporary(&data[..len]),
            Self::Static(bytes) => bytes.truncate(len),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cow_bytes_eq() {
        let cow1 = CowBytes::Temporary(b"1234");
        let cow2 = CowBytes::Static(Bytes::from_static(b"1234"));
        assert_eq!(cow1, cow2);
        let cow3 = CowBytes::Temporary(b"12345");
        assert_ne!(cow1, cow3);
    }

    #[test]
    fn test_cow_bytes() {
        let cow1 = CowBytes::Temporary(&[1, 2, 3]);
        assert!(cow1.is_temporary());
        let cow2 = cow1.clone();
        assert!(cow2.is_temporary());
        assert_eq!(cow1, cow2);
        assert_eq!(cow1.len(), 3);
        assert_eq!(cow2.len(), 3);
        let cow3 = cow1.into_static();
        assert_eq!(cow3.as_ref(), cow2.as_ref());
        let bytes = Bytes::from(alloc::vec![4u8, 5, 6]);
        let cow4 = CowBytes::Static(bytes.clone());
        assert!(cow4.is_static());
        assert_eq!(cow4.as_ref(), bytes.as_ref());
        assert_eq!(cow4.len(), 3);
    }

    #[test]
    fn test_default_is_empty() {
        let cow = CowBytes::default();
        assert_eq!(cow.as_ref(), b"");
        assert_eq!(cow.len(), 0);
        assert!(cow.is_empty());
        assert_eq!(cow.remaining(), 0);
        assert_eq!(cow.chunk(), b"");
    }

    #[test]
    fn test_len_and_is_empty() {
        let cow = CowBytes::Temporary(b"abc");
        assert_eq!(cow.len(), 3);
        assert!(!cow.is_empty());
        let cow = CowBytes::from_static(b"abcd");
        assert!(cow.is_static());
        assert_eq!(cow.len(), 4);
        assert!(!cow.is_empty());
    }

    #[test]
    fn test_deref_and_as_ref() {
        let cow = CowBytes::Temporary(b"hello");
        assert_eq!(cow.as_ref(), &cow[..]);
        assert_eq!(&*cow, b"hello");
    }

    #[test]
    fn test_split_to_off() {
        let mut cow = CowBytes::Temporary(b"abcdef");
        let left = cow.split_to(2);
        assert_eq!(left.as_ref(), b"ab");
        assert_eq!(cow.as_ref(), b"cdef");
        let right = cow.split_off(2);
        assert_eq!(cow.as_ref(), b"cd");
        assert_eq!(right.as_ref(), b"ef");

        let mut cow = CowBytes::Static(Bytes::from_static(b"abcdef"));
        let left = cow.split_to(3);
        assert_eq!(left.as_ref(), b"abc");
        assert_eq!(cow.as_ref(), b"def");
        let right = cow.split_off(1);
        assert_eq!(cow.as_ref(), b"d");
        assert_eq!(right.as_ref(), b"ef");
    }

    #[test]
    fn test_buf_methods() {
        let mut cow = CowBytes::Temporary(b"1234");
        assert_eq!(cow.remaining(), 4);
        assert_eq!(cow.chunk(), b"1234");
        cow.advance(2);
        assert_eq!(cow.remaining(), 2);
        assert_eq!(cow.chunk(), b"34");
    }

    #[test]
    fn test_into_static_from_temporary() {
        let cow = CowBytes::Temporary(b"data");
        let bytes = cow.into_static();
        assert_eq!(bytes.as_ref(), b"data");
    }

    #[test]
    fn test_from_conversions() {
        let a: CowBytes<'static> = (&b"xyz"[..]).into();
        let b: CowBytes<'static> = Bytes::from_static(b"xyz").into();
        assert_eq!(a, b);
    }
}
