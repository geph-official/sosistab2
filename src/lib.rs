pub mod crypt;

mod frame;
mod multiplex;
pub use multiplex::*;

mod pipe;
pub use pipe::*;

mod utilities;

// pub(crate) type SVec<T> = SmallVec<[T; 16]>;
