# cow-bytes

`bytes::Bytes` only works with buffers valid for `'static`. This crate provides a `CowBytes` type that can be used with buffers with their own lifetime, such as a slice to a stack-allocated array.

`CowBytes` implements many of traits and methods shared between `Bytes` and `&[u8]`. Notably, it implements `Deref<Target = [u8]>`.
