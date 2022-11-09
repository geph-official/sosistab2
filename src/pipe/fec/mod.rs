mod decoder;
mod encoder;
mod wrapped;

use bytes::Bytes;
pub use decoder::*;
pub use encoder::*;

fn pre_encode(pkt: &[u8], len: usize) -> Vec<u8> {
    assert!(pkt.len() <= 65535);
    assert!(pkt.len() + 2 <= len);
    // tracing::trace!("pre-encoding pkt with len {} => {}", pkt.len(), len);
    let mut hdr = (pkt.len() as u16).to_le_bytes().to_vec();
    let tail = vec![0u8; len - pkt.len() - 2];
    hdr.extend(pkt);
    hdr.extend(tail);
    hdr
}

fn post_decode(raw: Bytes) -> Option<Bytes> {
    if raw.len() < 2 {
        return None;
    }
    let body_len = u16::from_le_bytes([raw[0], raw[1]]) as usize;
    if raw.len() < 2 + body_len {
        return None;
    }
    Some(raw.slice(2..2 + body_len))
}
