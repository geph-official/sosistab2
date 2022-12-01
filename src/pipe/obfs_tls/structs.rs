use arrayref::array_ref;
use bytes::Bytes;
use futures_util::{AsyncRead, AsyncWrite, AsyncWriteExt};
use rand::Rng;
use serde::{Deserialize, Serialize};
use smol::io::AsyncReadExt;

#[derive(Clone, Debug)]
pub struct OuterMessage {
    pub version: u8,
    pub body: Bytes,
}

impl OuterMessage {
    /// Writes the message out
    pub async fn write(&self, mut out: impl AsyncWrite + Unpin) -> std::io::Result<()> {
        let unpadded_length = self.body.len() + 3; // version + 2 bytes length
        let padded_length =
            unpadded_length + (64 - (unpadded_length % 64)) + rand::thread_rng().gen_range(16, 33);
        let padding_length = (padded_length - unpadded_length - 2) as u16;
        let mut to_write = Vec::with_capacity(padded_length);
        to_write.extend_from_slice(&self.version.to_be_bytes());
        to_write.extend_from_slice(&(self.body.len() as u16).to_be_bytes());
        to_write.extend_from_slice(&self.body);
        to_write.extend_from_slice(&padding_length.to_be_bytes());
        to_write.extend_from_slice(&vec![0; padding_length as usize]);
        assert_eq!(to_write.len(), padded_length);
        out.write_all(&to_write).await
    }

    /// Reads a message.
    pub async fn read(mut rdr: impl AsyncRead + Unpin) -> std::io::Result<Self> {
        let mut first_header = [0u8; 3];
        rdr.read_exact(&mut first_header).await?;
        let version = first_header[0];
        let body_len = u16::from_be_bytes(*array_ref![first_header, 1, 2]);
        let mut body_buffer = vec![0u8; body_len as usize];
        rdr.read_exact(&mut body_buffer).await?;
        let mut padding_length = [0u8; 2];
        rdr.read_exact(&mut padding_length).await?;
        let padding_length = u16::from_be_bytes(padding_length) as usize;
        rdr.read_exact(&mut vec![0u8; padding_length]).await?;
        Ok(Self {
            version,
            body: body_buffer.into(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum InnerMessage {
    Normal(Bytes),
    Ping(u64),
    Pong(u64),
}
