use std::time::Duration;

use bytes::Bytes;
use rand::Rng;
use serde::{Deserialize, Serialize};

/// Encodes a buffer into multiple smaller "fragments". A fragment is prepended with two bytes: how many fragments in total, and which fragment this fragment is.
pub fn fragment(buff: Bytes, out: &mut Vec<Bytes>) {
    let limit = (buff.len() as f64 / (buff.len() as f64 / 1340.0).ceil()).ceil() as usize;
    // TODO: reuse the memory somehow?
    let chunk_count = buff.len() / limit + (buff.len() % limit).min(1);
    for (i, chunk) in buff.chunks(limit).enumerate() {
        let mut piece = Vec::with_capacity(chunk.len() + 2);
        piece.push(chunk_count as u8);
        piece.push(i as u8);
        piece.extend_from_slice(chunk);
        out.push(piece.into())
    }
}

/// Pipe-protocol frame, encrypted with a per-session key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PipeFrame {
    Data {
        /// Strictly incrementing counter of frames. Must never repeat.
        frame_no: u64,
        /// Body
        body: Bytes,
    },
    Parity {
        data_frame_first: u64,
        data_count: u8,
        parity_count: u8,
        parity_index: u8,
        pad_size: u16,
        body: Bytes,
    },
    Acks {
        first_ack: u64,
        last_ack: u64,
        ack_bitmap: Bytes,
        time_offset: Option<Duration>, // could be that we didn't receive *any* of the packets whose acks are requested
    },

    AckRequest {
        first_ack: u64,
        last_ack: u64,
    },
}

impl PipeFrame {
    /// Pads the frame to prepare for encryption.
    pub fn pad(&self) -> Bytes {
        stdcode::serialize(self).unwrap().into()
    }

    /// Depads a decrypted frame.
    pub fn depad(bts: &[u8]) -> Option<Self> {
        stdcode::deserialize(bts).ok()
    }
}

/// Frame sent as a session-negotiation message. This is always encrypted with the cookie.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum HandshakeFrame {
    /// Frame sent from client to server when opening a connection. This is always globally encrypted.
    ClientHello {
        long_pk: x25519_dalek::PublicKey,
        eph_pk: x25519_dalek::PublicKey,
        version: u64,
        /// seconds since the unix epoch, included to prevent replay attacks
        timestamp: u64,
    },
    /// Frame sent from server to client to give a cookie for finally opening a connection.
    ServerHello {
        long_pk: x25519_dalek::PublicKey,
        eph_pk: x25519_dalek::PublicKey,
        /// This value includes all the info required to reconstruct a session, encrypted under a secret key only the server knows.
        resume_token: Bytes,
    },

    /// Frame sent from client to server to either signal roaming, or complete an initial handshake. This is globally encrypted.
    /// Clients should send a ClientResume every time they suspect that their IP has changed.
    ClientResume { resume_token: Bytes },
}

impl HandshakeFrame {
    pub fn to_bytes(&self) -> Vec<u8> {
        stdcode::serialize(self).unwrap()
    }

    pub fn from_bytes(bts: &[u8]) -> anyhow::Result<Self> {
        Ok(stdcode::deserialize(bts)?)
    }
}
