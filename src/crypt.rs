use arrayref::array_ref;

use bytes::Bytes;
use once_cell::sync::Lazy;

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use thiserror::Error;

/// Non-obfuscated AEAD, with a straightforward counting nonce.
#[derive(Debug, Clone)]
pub struct NonObfsAead {
    key: Arc<LessSafeKey>,
    nonce: Arc<AtomicU64>,
}

static SOSISTAB_NOCRYPT: Lazy<bool> = Lazy::new(|| std::env::var("SOSISTAB_NOCRYPT").is_ok());

impl NonObfsAead {
    pub fn new(key: &[u8]) -> Self {
        let ubk = UnboundKey::new(&CHACHA20_POLY1305, key).unwrap();
        Self {
            key: Arc::new(LessSafeKey::new(ubk)),
            nonce: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Returns the overhead.
    pub fn overhead() -> usize {
        12 + CHACHA20_POLY1305.tag_len()
    }

    /// Encrypts a message, returning the ciphertext .
    pub fn encrypt(&self, msg: &[u8]) -> Bytes {
        let nonce = self.nonce.fetch_add(1, Ordering::SeqCst);
        let mut bnonce = [0; 12];
        bnonce[..8].copy_from_slice(&nonce.to_le_bytes());

        // make an output. it starts out containing the plaintext.
        let mut output = Vec::with_capacity(msg.len() + 32);
        output.extend_from_slice(msg);

        // now we overwrite it
        if !*SOSISTAB_NOCRYPT {
            self.key
                .seal_in_place_append_tag(
                    Nonce::assume_unique_for_key(bnonce),
                    Aad::empty(),
                    &mut output,
                )
                .unwrap();
        }
        output.extend_from_slice(&bnonce);
        output.into()
    }

    /// Decrypts a message.
    pub fn decrypt(&self, ctext: &[u8]) -> Result<(u64, Bytes), AeadError> {
        if !*SOSISTAB_NOCRYPT && ctext.len() < 8 + CHACHA20_POLY1305.tag_len() {
            return Err(AeadError::BadLength);
        }
        // nonce is last 12 bytes
        let (cytext, nonce) = ctext.split_at(ctext.len() - 12);
        // we now open
        let mut ctext = cytext.to_vec();
        if !*SOSISTAB_NOCRYPT {
            self.key
                .open_in_place(
                    Nonce::try_assume_unique_for_key(nonce).unwrap(),
                    Aad::empty(),
                    &mut ctext,
                )
                .ok()
                .ok_or(AeadError::DecryptionFailure)?;
            let truncate_to = ctext.len() - CHACHA20_POLY1305.tag_len();
            ctext.truncate(truncate_to);
        }
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
