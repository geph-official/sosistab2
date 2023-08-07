pub mod crypt;

mod multiplex;
pub use multiplex::*;

mod pipe;
pub use pipe::*;

mod utilities;

// pub(crate) type SVec<T> = SmallVec<[T; 16]>;
