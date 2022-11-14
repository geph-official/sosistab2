use arrayref::array_ref;

use blake3::Hash;
use bytes::Bytes;
use once_cell::sync::Lazy;
use rand::prelude::*;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use thiserror::Error;

pub const CLIENT_UP_KEY: &[u8; 32] = b"upload--------------------------";
pub const CLIENT_DN_KEY: &[u8; 32] = b"download------------------------";

pub fn upify_shared_secret(shared_secret: &[u8]) -> Hash {
    blake3::keyed_hash(CLIENT_UP_KEY, shared_secret)
}
pub fn dnify_shared_secret(shared_secret: &[u8]) -> Hash {
    blake3::keyed_hash(CLIENT_DN_KEY, shared_secret)
}

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

    /// Encrypts a message, returning the ciphertext and integer nonce.
    pub fn encrypt(&self, msg: &[u8]) -> (u64, Bytes) {
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
        (nonce, output.into())
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

/// AEAD where the messages produced are "uniform" in appearance.
#[derive(Debug, Clone)]
pub struct ObfsAead {
    key: Arc<LessSafeKey>,
}

impl ObfsAead {
    pub fn new(key: &[u8]) -> Self {
        let ubk = UnboundKey::new(&CHACHA20_POLY1305, key).unwrap();
        Self {
            key: Arc::new(LessSafeKey::new(ubk)),
        }
    }

    /// Encrypts a message with a random nonce.
    pub fn encrypt(&self, msg: &[u8]) -> Bytes {
        let mut nonce = [0; 12];
        rand::thread_rng().fill_bytes(&mut nonce);

        // make an output. it starts out containing the padding.
        // we "round up" to ensure that long term averages cannot leak things either. regardless, this is very much "best effort"
        let padding_len = (16 - msg.len() % 16) + rand::random::<usize>() % 16;
        let mut padded_msg = Vec::with_capacity(1 + padding_len + msg.len() + 12);
        padded_msg.push(padding_len as u8);
        padded_msg.resize(padding_len + 1, 0xff);
        padded_msg.extend_from_slice(msg);

        // now we overwrite it
        self.key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::empty(),
                &mut padded_msg,
            )
            .unwrap();
        padded_msg.extend_from_slice(&nonce);
        padded_msg.into()
    }

    /// Decrypts a message.
    pub fn decrypt(&self, ctext: &[u8]) -> Result<Bytes, AeadError> {
        if ctext.len() < CHACHA20_POLY1305.nonce_len() + CHACHA20_POLY1305.tag_len() {
            return Err(AeadError::BadLength);
        }
        // nonce is last 12 bytes
        let (cytext, nonce) = ctext.split_at(ctext.len() - CHACHA20_POLY1305.nonce_len());
        // we now open
        let mut ctext = cytext.to_vec();
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
        let padding_len = ctext[0] as usize;
        if padding_len + 1 > ctext.len() {
            return Err(AeadError::BadLength);
        }
        Ok(Bytes::from(ctext).slice((padding_len + 1)..))
    }
}

#[derive(Error, Debug)]
pub enum AeadError {
    #[error("bad ciphertext length")]
    BadLength,
    #[error("decryption failure")]
    DecryptionFailure,
}

#[derive(Debug, Clone)]
/// Cookie is a generator of temporary symmetric keys.
pub struct Cookie(x25519_dalek::PublicKey);

impl Cookie {
    /// Create a new cookie based on a public key.
    pub fn new(pk: x25519_dalek::PublicKey) -> Cookie {
        Cookie(pk)
    }

    /// Generate a bunch of symmetric keys given the current time, for client to server.
    pub fn generate_c2s(&self) -> [u8; 32] {
        self.generate_temp_key("sosistab-1-c2s")
    }

    /// Generate a bunch of symmetric keys given the current time, for server to client.
    pub fn generate_s2c(&self) -> [u8; 32] {
        self.generate_temp_key("sosistab-1-s2c")
    }

    fn generate_temp_key(&self, ctx: &str) -> [u8; 32] {
        let mut key = [0u8; 32];
        blake3::derive_key(ctx, self.0.as_bytes(), &mut key);
        key
    }
}

// Two ways to get keys: triple ecdh &  server-pk-derived handshake key
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
