use bytes::Bytes;
use parking_lot::Mutex;
use replay_filter::ReplayFilter;
use stdcode::StdcodeSerializeExt;

use crate::crypt::ObfsAead;

use super::frame::ObfsUdpFrame;

/// An encrypter of obfuscated packets.
pub struct ObfsEncrypter {
    inner: ObfsAead,
    seqno: u64,
}

impl ObfsEncrypter {
    pub fn new(inner: ObfsAead) -> Self {
        Self { inner, seqno: 0 }
    }

    /// Encrypts a packet.
    pub fn encrypt(&mut self, pkt: &ObfsUdpFrame) -> Bytes {
        let ptext = (self.seqno, &pkt).stdcode();
        self.seqno += 1;
        self.inner.encrypt(&ptext)
    }
}

/// A decrypter of obfuscated packets.
pub struct ObfsDecrypter {
    inner: ObfsAead,
    dedupe: Mutex<ReplayFilter>,
}

impl ObfsDecrypter {
    pub fn new(inner: ObfsAead) -> Self {
        Self {
            inner,
            dedupe: Mutex::new(ReplayFilter::default()),
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
