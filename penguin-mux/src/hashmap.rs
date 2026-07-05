//! Utilities for generating integer keys for a `HashMap`
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use core::hash::{BuildHasher, Hash};
use rand::{
    Rng, RngExt,
    distr::{Distribution, StandardUniform},
};

/// A `HashMap`-like type whose keys can be randomly generated
pub trait HashMapLike {
    /// The type of the keys in the map
    type Key: Eq + Hash;

    /// Check if the map contains a key
    fn contains_key(&self, key: &Self::Key) -> bool;

    /// Generate a new key that is not in the map
    #[inline]
    #[must_use]
    fn next_available_key<R>(&self, rand: &mut R) -> Self::Key
    where
        StandardUniform: Distribution<Self::Key>,
        R: Rng,
    {
        loop {
            let key = rand.random::<Self::Key>();
            if !self.contains_key(&key) {
                break key;
            }
        }
    }
}

#[cfg(feature = "std")]
impl<K: Eq + Hash, V, S: BuildHasher> HashMapLike for std::collections::HashMap<K, V, S> {
    type Key = K;
    fn contains_key(&self, key: &Self::Key) -> bool {
        Self::contains_key(self, key)
    }
}

impl<K: Eq + Hash, V, S: BuildHasher> HashMapLike for hashbrown::HashMap<K, V, S> {
    type Key = K;
    fn contains_key(&self, key: &Self::Key) -> bool {
        Self::contains_key(self, key)
    }
}
