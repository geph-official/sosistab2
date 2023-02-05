use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use bytes::Bytes;
use parking_lot::Mutex;
use replay_filter::ReplayFilter;
use stdcode::StdcodeSerializeExt;

use crate::crypt::ObfsAead;

use super::frame::ObfsUdpFrame;

/// An encrypter of obfuscated packets.
#[derive(Clone)]
pub struct ObfsEncrypter {
    inner: ObfsAead,
    seqno: Arc<AtomicU64>,
}

impl ObfsEncrypter {
    pub fn new(inner: ObfsAead) -> Self {
        Self {
            inner,
            seqno: Default::default(),
        }
    }

    /// Encrypts a packet.
    pub fn encrypt(&self, pkt: &ObfsUdpFrame) -> Bytes {
        let seqno = self.seqno.fetch_add(1, Ordering::SeqCst);
        let ptext = (seqno, &pkt).stdcode();

        self.inner.encrypt(&ptext)
    }
}

/// A decrypter of obfuscated packets.
#[derive(Clone)]
pub struct ObfsDecrypter {
    inner: ObfsAead,
    dedupe: Arc<Mutex<ReplayFilter>>,
}

impl ObfsDecrypter {
    pub fn new(inner: ObfsAead) -> Self {
        Self {
            inner,
            dedupe: Mutex::new(ReplayFilter::default()).into(),
        }
    }

    /// Decrypts a packet.
    pub fn decrypt(&self, b: &[u8]) -> anyhow::Result<ObfsUdpFrame> {
        let ptext = self.inner.decrypt(b)?;
        let (outer_seqno, frame): (u64, ObfsUdpFrame) = stdcode::deserialize(&ptext)?;
        if !self.dedupe.lock().add(outer_seqno) {
            anyhow::bail!("rejecting duplicate outer_seqno {outer_seqno}")
        }
        Ok(frame)
    }
}
