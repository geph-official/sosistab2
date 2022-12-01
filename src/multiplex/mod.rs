mod multiplex_actor;
mod stream;
mod structs;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
// pub use congestion::*;
pub use stream::MuxStream;
mod multiplex_struct;
pub use multiplex_struct::Multiplex;

/// A server public key for the end-to-end multiplex.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MuxPublic(pub(crate) x25519_dalek::PublicKey);

impl MuxPublic {
    /// Returns the bytes representation.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Convert from bytes.
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(x25519_dalek::PublicKey::from(b))
    }
}

/// A server secret key for the end-to-end multiplex.
#[derive(Clone, Serialize, Deserialize)]
pub struct MuxSecret(pub(crate) x25519_dalek::StaticSecret);

impl MuxSecret {
    /// Returns the bytes representation.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Convert from bytes.
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(x25519_dalek::StaticSecret::from(b))
    }

    /// Generate.
    pub fn generate() -> Self {
        Self(x25519_dalek::StaticSecret::new(OsRng {}))
    }

    /// Convert to a public key.
    pub fn to_public(&self) -> MuxPublic {
        MuxPublic((&self.0).into())
    }
}
