use crate::CowBytes;
use alloc::vec::Vec;
use bytes::Buf;

/// A chain of [`CowBytes`] instances
///
/// This struct intentionally does not implement `Deref` to `[CowBytes]`
/// since that would expose `Vec`'s methods that operate on the number of
/// `CowBytes` instances instead of the number of bytes, which may lead
/// to confusion. To access the backing array, use [`AsRef`].
#[derive(Clone, Debug, Default)]
pub struct LongChain<'data> {
    data: Vec<CowBytes<'data>>,
    total_remaining_len: usize,
}

impl LongChain<'_> {
    /// Create a new empty [`LongChain`].
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            data: Vec::new(),
            total_remaining_len: 0,
        }
    }

    /// Create a new [`LongChain`] with the given number of [`CowBytes`] it can hold without reallocating.
    ///
    /// Note that this is the number of [`CowBytes`] instances instead of the number of bytes.
    #[inline]
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
            total_remaining_len: 0,
        }
    }

    /// Clear the [`LongChain`].
    #[inline]
    pub fn clear(&mut self) {
        #[cfg(debug_assertions)]
        self.verify_invariants();
        self.total_remaining_len = 0;
        self.data.clear();
    }

    /// Get the total length of all data in the [`LongChain`].
    #[inline]
    #[must_use]
    pub const fn len(&self) -> usize {
        #[cfg(debug_assertions)]
        self.verify_invariants();
        self.total_remaining_len
    }

    /// Check if the [`LongChain`] is empty.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        #[cfg(debug_assertions)]
        self.verify_invariants();
        self.total_remaining_len == 0
    }

    /// Internal method to verify data structure invariants
    const fn verify_invariants(&self) {
        let mut got_len = 0;
        let num_elems = self.data.len();
        let mut i = 0;
        // Written in this way to make this function const
        while i < num_elems {
            let this_len = self.data.as_slice()[i].len();
            assert!(this_len > 0);
            got_len += this_len;
            i += 1;
        }
        assert!(got_len == self.total_remaining_len);
    }
}

impl<'a> LongChain<'a> {
    /// Insert a [`CowBytes`] into the [`LongChain`] at the given index.
    ///
    /// Note that the index is in terms of the number of [`CowBytes`] instances instead of bytes.
    #[inline]
    pub fn insert(&mut self, index: usize, cow: CowBytes<'a>) {
        #[cfg(debug_assertions)]
        self.verify_invariants();
        self.total_remaining_len += cow.len();
        self.data.insert(index, cow);
    }

    /// Remove the last [`CowBytes`] from the [`LongChain`].
    #[inline]
    pub fn pop(&mut self) -> Option<CowBytes<'a>> {
        #[cfg(debug_assertions)]
        self.verify_invariants();
        let elem = self.data.pop();
        if let Some(elem) = &elem {
            self.total_remaining_len -= elem.len();
        }
        elem
    }

    /// Push a [`CowBytes`] onto the end of the [`LongChain`].
    #[inline]
    pub fn push(&mut self, cow: CowBytes<'a>) {
        #[cfg(debug_assertions)]
        self.verify_invariants();
        self.total_remaining_len += cow.len();
        self.data.push(cow);
    }

    /// Remove the [`CowBytes`] at the given index from the [`LongChain`].
    ///
    /// Note that the index is in terms of the number of [`CowBytes`] instances instead of bytes.
    #[inline]
    pub fn remove(&mut self, index: usize) -> CowBytes<'a> {
        #[cfg(debug_assertions)]
        self.verify_invariants();
        let elem = self.data.remove(index);
        self.total_remaining_len -= elem.len();
        elem
    }

    /// Split the instance into two at the given byte index.
    ///
    /// See [`bytes::Bytes::split_to`] for more details.
    #[must_use = "consider LongChain::truncate if you don't need the other half"]
    pub fn split_to(&mut self, at: usize) -> Self {
        let mut other = self.split_off(at);
        core::mem::swap(self, &mut other);
        other
    }

    /// Split the instance into two at the given byte index.
    ///
    /// See [`bytes::Bytes::split_off`] for more details.
    /// This methods allocates a new [`LongChain`] to hold the second half of the split,
    /// but does not involve copying any underlying data.
    /// In terms of time, this operation is `O(n)` where `n` is the number of [`CowBytes`]
    /// instances in the [`LongChain`].
    #[must_use = "consider LongChain::advance if you don't need the other half"]
    pub fn split_off(&mut self, at: usize) -> Self {
        #[cfg(debug_assertions)]
        self.verify_invariants();
        let mut remaining = at;
        let mut split_index = 0;
        while split_index < self.data.len() {
            let this_len = self.data[split_index].len();
            if remaining < this_len {
                break;
            }
            remaining -= this_len;
            split_index += 1;
        }
        let new_chain = if remaining == 0 {
            self.data.split_off(split_index)
        } else {
            let mut new_chain = Vec::with_capacity(1 + self.data.len() - split_index);
            let split_elem = self.data[split_index].split_off(remaining);
            new_chain.push(split_elem);
            new_chain.extend(self.data.split_off(split_index + 1));
            new_chain
        };
        let new_len = self.total_remaining_len - at;
        self.total_remaining_len = at;
        Self {
            data: new_chain,
            total_remaining_len: new_len,
        }
    }

    /// Keep the first `len` bytes and drop the rest.
    #[inline]
    pub fn truncate(&mut self, len: usize) {
        #[cfg(debug_assertions)]
        self.verify_invariants();
        let mut remaining = len;
        let mut truncate_index = 0;
        while truncate_index < self.data.len() {
            let this_len = self.data[truncate_index].len();
            if remaining == 0 {
                self.data.truncate(truncate_index);
                break;
            }
            if remaining < this_len {
                self.data[truncate_index].truncate(remaining);
                self.data.truncate(truncate_index + 1);
                break;
            }
            remaining -= this_len;
            truncate_index += 1;
        }
        self.total_remaining_len = len;
    }
}

impl<'a> AsRef<[CowBytes<'a>]> for LongChain<'a> {
    fn as_ref(&self) -> &[CowBytes<'a>] {
        &self.data
    }
}

impl Buf for LongChain<'_> {
    fn remaining(&self) -> usize {
        #[cfg(debug_assertions)]
        self.verify_invariants();
        self.total_remaining_len
    }

    fn chunk(&self) -> &[u8] {
        #[cfg(debug_assertions)]
        self.verify_invariants();
        self.data.first().map_or(&[], CowBytes::chunk)
    }

    fn advance(&mut self, mut cnt: usize) {
        #[cfg(debug_assertions)]
        self.verify_invariants();
        assert!(
            cnt <= self.total_remaining_len,
            "advance past end of buffer"
        );
        while cnt > 0 {
            let Some(next) = self.data.first_mut() else {
                unreachable!();
            };
            let advance_by = next.remaining().min(cnt);
            next.advance(advance_by);
            cnt -= advance_by;
            self.total_remaining_len -= advance_by;
            if next.remaining() == 0 {
                self.data.remove(0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_long_chain_basic() {
        let mut chain = LongChain::new();
        chain.push(CowBytes::from_static(b"hello"));
        chain.push(CowBytes::from_static(b"world"));
        chain.push(CowBytes::from_static(b"long chain"));
        assert_eq!(chain.len(), 20);
        assert_eq!(chain.chunk(), b"hello");
        chain.advance(2);
        assert_eq!(chain.len(), 18);
        assert_eq!(chain.chunk(), b"llo");
        chain.advance(3);
        assert_eq!(chain.len(), 15);
        assert_eq!(chain.chunk(), b"world");
        chain.advance(7);
        assert_eq!(chain.len(), 8);
        assert_eq!(chain.chunk(), b"ng chain");
        chain.advance(8);
        assert_eq!(chain.len(), 0);
        assert!(chain.is_empty());
    }

    #[test]
    fn test_long_chain_split_truncate() {
        let mut chain = LongChain::new();
        chain.push(CowBytes::from_static(b"hello"));
        chain.push(CowBytes::from_static(b"world"));
        let other = chain.split_off(10);
        assert_eq!(chain.len(), 10);
        assert_eq!(other.len(), 0);
        let mut other = chain.split_to(7);
        assert_eq!(chain.len(), 3);
        assert_eq!(other.len(), 7);
        assert_eq!(other.chunk(), b"hello");
        other.advance(5);
        assert_eq!(chain.chunk(), b"rld");
        assert_eq!(other.chunk(), b"wo");
        let other = chain.split_off(0);
        assert_eq!(chain.len(), 0);
        assert_eq!(other.len(), 3);

        let mut chain = LongChain::new();
        chain.push(CowBytes::from_static(b"hel"));
        chain.push(CowBytes::from_static(b"lo"));
        chain.push(CowBytes::from_static(b"world"));
        let other = chain.split_off(5);
        assert_eq!(chain.len(), 5);
        assert_eq!(other.len(), 5);
        assert_eq!(chain.chunk(), b"hel");
        chain.advance(3);
        assert_eq!(chain.chunk(), b"lo");
        assert_eq!(other.chunk(), b"world");

        let mut chain = LongChain::new();
        chain.push(CowBytes::from_static(b"hello"));
        chain.push(CowBytes::from_static(b"wor"));
        chain.push(CowBytes::from_static(b"ld"));
        chain.truncate(10);
        assert_eq!(chain.len(), 10);
        assert_eq!(chain.data.len(), 3);
        chain.truncate(7);
        assert_eq!(chain.len(), 7);
        assert_eq!(chain.data.len(), 2);
        assert_eq!(chain.data[0], b"hello");
        assert_eq!(chain.data[1], b"wo");
        chain.truncate(5);
        assert_eq!(chain.len(), 5);
        assert_eq!(chain.data.len(), 1);
        assert_eq!(chain.data[0], b"hello");
        chain.truncate(0);
        assert_eq!(chain.len(), 0);
        assert!(chain.is_empty());
    }
}
