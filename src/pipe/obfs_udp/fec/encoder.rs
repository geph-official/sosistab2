use std::time::Duration;

use bytes::Bytes;
use probability::distribution::Distribution;

use rustc_hash::FxHashMap;

use crate::{pipe::obfs_udp::frame::PipeFrame, utilities::batchtimer::BatchTimer};

use super::{pre_encode, wrapped::WrappedReedSolomon};

// forward error correction
pub struct FecEncoder {
    unfecked: Vec<(u64, Bytes)>,

    timer: BatchTimer,
}

impl FecEncoder {
    pub fn new(fec_timeout: Duration, burst_size: usize) -> Self {
        Self {
            unfecked: Vec::new(),

            timer: BatchTimer::new(fec_timeout, burst_size),
        }
    }

    pub fn add_unfecked(&mut self, seqno: u64, pkt: Bytes) {
        self.unfecked.push((seqno, pkt));
        self.timer.increment();
    }

    pub async fn wait_parity(&mut self, loss: f64) -> Vec<PipeFrame> {
        self.timer.wait().await;
        self.timer.reset();
        if loss == 0.0 {
            self.unfecked.clear();
            smol::future::pending().await
        }

        if self.unfecked.is_empty() {
            return vec![];
        }
        // encode
        let mut fec_encoder = FrameEncoder::new(1); // around 0.5 percent
        let first_frame_no = self.unfecked[0].0;
        let data_count = self.unfecked.len();
        let expanded = fec_encoder.encode(
            loss,
            &self
                .unfecked
                .iter()
                .map(|v| v.1.clone())
                .collect::<Vec<_>>(),
        );
        let pad_size = (self
            .unfecked
            .iter()
            .map(|v| v.1.len())
            .max()
            .unwrap_or_default()
            + 2) as u16;
        let parity = &expanded[self.unfecked.len()..];
        self.unfecked.clear();

        let parity_count = parity.len();
        // encode parity, taking along the first data frame no to identify the run
        let parity_frames = parity
            .iter()
            .enumerate()
            .map(|(index, parity)| PipeFrame::Parity {
                data_frame_first: first_frame_no,
                data_count: data_count as u8,
                parity_count: parity_count as u8,
                parity_index: index as u8,
                body: parity.clone(),
                pad_size,
            })
            .collect();
        parity_frames
    }
}

/// A forward error correction encoder. Retains internal state for memoization, memory pooling etc.
#[derive(Debug)]
pub struct FrameEncoder {
    // table mapping current loss in pct + run length => overhead
    rate_table: FxHashMap<(u8, usize), usize>,
    // target loss rate
    target_loss: u8,
}

impl FrameEncoder {
    /// Creates a new Encoder at the given loss level.
    pub fn new(target_loss: u8) -> Self {
        FrameEncoder {
            rate_table: FxHashMap::default(),
            target_loss,
        }
    }

    /// Encodes a slice of packets into more packets.
    pub fn encode(&mut self, measured_loss: f64, pkts: &[Bytes]) -> Vec<Bytes> {
        // max length
        let max_length = pkts.iter().map(|v| v.len()).max().unwrap();
        // first we precode the packets
        let mut padded_pkts: Vec<Vec<u8>> =
            pkts.iter().map(|p| pre_encode(p, max_length + 2)).collect();
        // then we get an encoder for this size
        let data_shards = pkts.len();
        let parity_shards = self.repair_len(measured_loss, pkts.len());
        // log::debug!("encoding {},{}", data_shards, parity_shards);

        // then we encode
        // prepare the space for in-place mutation
        let mut parity_shard_space = vec![vec![0u8; max_length + 2]; parity_shards];
        let mut padded_pkts: Vec<&mut [u8]> = padded_pkts.iter_mut().map(|v| v.as_mut()).collect();
        for r in parity_shard_space.iter_mut() {
            padded_pkts.push(r);
        }
        // log::debug!(
        //     "{:.1}% => {}/{}",
        //     100.0 * measured_loss as f64 / 256.0,
        //     data_shards,
        //     parity_shards
        // );
        if parity_shards > 0 {
            let encoder = WrappedReedSolomon::new_cached(data_shards, parity_shards);
            // do the encoding
            encoder
                .get_inner()
                .encode(&mut padded_pkts)
                .expect("can't encode");
        }
        // return
        let mut toret = Vec::with_capacity(data_shards + parity_shards);
        toret.extend(padded_pkts.iter().map(|vec| Bytes::copy_from_slice(vec)));
        toret
    }

    /// Calculates the number of repair blocks needed to properly reconstruct a run of packets.
    fn repair_len(&mut self, measured_loss: f64, run_len: usize) -> usize {
        log::trace!("repair_len({measured_loss}, {run_len})");
        let measured_loss = (measured_loss * 255.0) as u8;
        let target_loss = self.target_loss;
        let result = (*self
            .rate_table
            .entry((measured_loss, run_len))
            .or_insert_with(|| {
                for additional_len in 0.. {
                    let distro = probability::distribution::Binomial::with_failure(
                        run_len + additional_len,
                        (measured_loss as f64 / 255.0).max(1e-100).min(1.0 - 1e-100),
                    );
                    let result_loss = distro.distribution(run_len as f64);
                    if result_loss <= target_loss as f64 / 255.0 {
                        return additional_len.saturating_sub(1usize);
                    }
                }
                panic!()
            }))
        .min(255 - run_len)
        .min(run_len * 2);
        log::trace!("expand batch of {} with {} parities", run_len, result);
        result
    }
}
