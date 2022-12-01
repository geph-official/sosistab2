pub mod crypt;

mod multiplex;
pub use multiplex::*;
mod pacer;
mod pipe;
pub use pipe::*;
mod timer;

mod utilities;

// pub(crate) type SVec<T> = SmallVec<[T; 16]>;
