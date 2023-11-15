use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::MuxPublic;

/// A sequence number.
pub type Seqno = u64;

/// An outer message.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Frame {
    /// Frame sent from client to server when opening a connection. This is always globally encrypted.
    ClientHello {
        long_pk: MuxPublic,
        eph_pk: x25519_dalek::PublicKey,
        version: u64,
        /// seconds since the unix epoch
        timestamp: u64,
    },
    /// Frame sent from server to client to give a cookie for finally opening a connection.
    ServerHello {
        long_pk: MuxPublic,
        eph_pk: x25519_dalek::PublicKey,
    },

    /// Non-handshake messages; inner = serialized EncryptedFrame
    EncryptedMsg { inner: Bytes },
}
