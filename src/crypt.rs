use arrayref::array_ref;

use bytes::Bytes;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};

use chacha20poly1305::AeadInPlace;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use thiserror::Error;

/// Non-obfuscated AEAD, with a straightforward counting nonce.
#[derive(Clone)]
pub struct NonObfsAead {
    key: Arc<ChaCha20Poly1305>,
    nonce: Arc<AtomicU64>,
}

impl NonObfsAead {
    pub fn new(key: &[u8; 32]) -> Self {
        let aead_key = Key::from_slice(key);
        let aead = ChaCha20Poly1305::new(aead_key);
        Self {
            key: Arc::new(aead),
            nonce: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Returns the overhead.
    pub fn overhead() -> usize {
        12 + 16 // 12-byte nonce + 16-byte tag
    }

    /// Encrypts a message, returning the ciphertext .
    pub fn encrypt(&self, msg: &[u8]) -> Bytes {
        let nonce = self.nonce.fetch_add(1, Ordering::SeqCst);
        let mut bnonce = [0; 12];
        bnonce[..8].copy_from_slice(&nonce.to_le_bytes());
        let nonce = Nonce::from_slice(&bnonce);

        // make an output. it starts out containing the plaintext.
        let mut output = Vec::with_capacity(msg.len() + Self::overhead());
        output.extend_from_slice(msg);

        // now we overwrite it
        self.key.encrypt_in_place(nonce, b"", &mut output).unwrap();

        output.extend_from_slice(&bnonce);
        output.into()
    }

    /// Decrypts a message.
    pub fn decrypt(&self, ctext: &[u8]) -> Result<(u64, Bytes), AeadError> {
        if ctext.len() < Self::overhead() {
            return Err(AeadError::BadLength);
        }
        // nonce is last 12 bytes
        let (cytext, nonce) = ctext.split_at(ctext.len() - 12);
        // we now open
        let mut ctext = cytext.to_vec();
        self.key
            .decrypt_in_place(Nonce::from_slice(nonce), b"", &mut ctext)
            .ok()
            .ok_or(AeadError::DecryptionFailure)?;

        let nonce = u64::from_le_bytes(*array_ref![nonce, 0, 8]);
        Ok((nonce, ctext.into()))
    }
}

#[derive(Error, Debug)]
pub enum AeadError {
    #[error("bad ciphertext length")]
    BadLength,
    #[error("decryption failure")]
    DecryptionFailure,
}

/// A triple-ECDH handshake.
pub fn triple_ecdh(
    my_long_sk: &x25519_dalek::StaticSecret,
    my_eph_sk: &x25519_dalek::StaticSecret,
    their_long_pk: &x25519_dalek::PublicKey,
    their_eph_pk: &x25519_dalek::PublicKey,
) -> blake3::Hash {
    let g_e_a = my_eph_sk.diffie_hellman(their_long_pk);
    let g_a_e = my_long_sk.diffie_hellman(their_eph_pk);
    let g_e_e = my_eph_sk.diffie_hellman(their_eph_pk);
    let to_hash = {
        let mut to_hash = Vec::new();
        if g_e_a.as_bytes() < g_a_e.as_bytes() {
            to_hash.extend_from_slice(g_e_a.as_bytes());
            to_hash.extend_from_slice(g_a_e.as_bytes());
        } else {
            to_hash.extend_from_slice(g_a_e.as_bytes());
            to_hash.extend_from_slice(g_e_a.as_bytes());
        }
        to_hash.extend_from_slice(g_e_e.as_bytes());
        to_hash
    };
    blake3::hash(&to_hash)
}
