use std::{convert::TryInto, sync::Arc};

use ahash::AHashMap;
use bytes::Bytes;

use lru::LruCache;

use super::{post_decode, pre_encode, wrapped::WrappedReedSolomon};

/// An out-of-band FEC reconstructor
pub struct FecDecoder {
    data_frames: LruCache<u64, Bytes>,
    parity_space: LruCache<ParitySpaceKey, AHashMap<u8, Bytes>>,
}

#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Debug)]
pub struct ParitySpaceKey {
    pub data_frame_first: u64, // seqno of first data frame in batch
    pub data_count: u8,        // how many data frames are in batch
    pub parity_count: u8,      // how many parity frames are in batch
    pub pad_size: u16,
}

impl FecDecoder {
    /// Create a new OOB decoder that has at most that many entries
    pub fn new(max_size: usize) -> Self {
        let data_frames = LruCache::new(max_size.try_into().unwrap());
        let parity_space = LruCache::new(max_size.try_into().unwrap());
        Self {
            data_frames,
            parity_space,
        }
    }

    /// Insert a new data frame.
    pub fn insert_data(&mut self, frame_no: u64, data: Bytes) {
        self.data_frames.put(frame_no, data);
    }

    /// Inserts a new parity frame, and attempt to reconstruct.
    pub fn insert_parity(
        &mut self,
        parity_info: ParitySpaceKey,
        parity_idx: u8,
        parity: Bytes,
    ) -> Vec<(u64, Bytes)> {
        // println!("hey parity packet!");
        let hash_ref = self
            .parity_space
            .get_or_insert_mut(parity_info, AHashMap::default);
        // if 255 is set, this means that the parity is done
        if hash_ref.get(&255).is_some() {
            return vec![];
        }
        hash_ref.insert(parity_idx, parity);

        // now we attempt reconstruction
        let actual_data = {
            let mut toret = Vec::new();
            for i in parity_info.data_frame_first
                ..parity_info.data_frame_first + (parity_info.data_count as u64)
            {
                if let Some(v) = self.data_frames.get(&i) {
                    toret.push((i, v.clone()))
                }
            }
            toret
        };
        if actual_data.len() + hash_ref.len() >= parity_info.data_count as _ {
            hash_ref.insert(255, Bytes::new());
            let mut decoder =
                FrameDecoder::new(parity_info.data_count as _, parity_info.parity_count as _);
            // we first insert the data shards.
            for (i, data) in actual_data.iter() {
                if data.len() + 2 > parity_info.pad_size as usize {
                    return vec![];
                }
                let data = pre_encode(data, parity_info.pad_size.into());
                decoder.decode(&data, (i - parity_info.data_frame_first) as _);
            }
            // make a list of MISSING data ids
            let mut missing_data_seqnos: Vec<_> = (parity_info.data_frame_first
                ..parity_info.data_frame_first + parity_info.data_count as u64)
                .collect();
            for (idx, _) in actual_data.iter() {
                missing_data_seqnos.retain(|v| v != idx);
            }
            // then the parity shards
            for (par_idx, data) in hash_ref {
                if let Some(res) = decoder.decode(
                    data,
                    (parity_info.data_count.saturating_add(*par_idx as u8)) as _,
                ) {
                    assert_eq!(res.len(), missing_data_seqnos.len());
                    return res
                        .into_iter()
                        .zip(missing_data_seqnos.into_iter())
                        .map(|(res, seqno)| (seqno, res))
                        .collect();
                }
            }
        }
        vec![]
    }
}

/// A single-use FEC decoder.
#[derive(Debug)]
pub struct FrameDecoder {
    data_shards: usize,
    parity_shards: usize,
    space: Vec<Vec<u8>>,
    present: Vec<bool>,
    present_count: usize,
    rs_decoder: Arc<WrappedReedSolomon>,
    done: bool,
}

impl FrameDecoder {
    pub fn new(data_shards: usize, parity_shards: usize) -> Self {
        FrameDecoder {
            data_shards,
            parity_shards,
            present_count: 0,
            space: vec![],
            present: vec![false; data_shards + parity_shards],
            rs_decoder: WrappedReedSolomon::new_cached(data_shards, parity_shards),
            done: false,
        }
    }

    pub fn decode(&mut self, pkt: &[u8], pkt_idx: usize) -> Option<Vec<Bytes>> {
        // if rand::random::<f64>() < 0.1 {
        //     log::debug!("decoding with {}/{}", self.data_shards, self.parity_shards);
        // }
        // if we don't have parity shards, don't touch anything
        if self.parity_shards == 0 {
            self.done = true;
            return Some(vec![post_decode(Bytes::copy_from_slice(pkt))?]);
        }
        if self.space.is_empty() {
            log::trace!("decode with pad len {}", pkt.len());
            self.space = vec![vec![0u8; pkt.len()]; self.data_shards + self.parity_shards]
        }
        if self.space.len() <= pkt_idx {
            return None;
        }
        if self.done
            || pkt_idx > self.space.len()
            || pkt_idx > self.present.len()
            || self.space[pkt_idx].len() != pkt.len()
        {
            return None;
        }
        // decompress without allocation
        self.space[pkt_idx].copy_from_slice(pkt);
        if !self.present[pkt_idx] {
            self.present_count += 1
        }
        self.present[pkt_idx] = true;
        // if I'm a data shard, just return it
        if pkt_idx < self.data_shards {
            return Some(vec![post_decode(Bytes::copy_from_slice(
                &self.space[pkt_idx],
            ))?]);
        }
        if self.present_count < self.data_shards {
            log::trace!("don't even attempt yet");
            return None;
        }
        let mut ref_vec: Vec<(&mut [u8], bool)> = self
            .space
            .iter_mut()
            .zip(self.present.iter())
            .map(|(v, pres)| (v.as_mut(), *pres))
            .collect();
        // otherwise, attempt to reconstruct
        log::trace!(
            "attempting to reconstruct (data={}, parity={})",
            self.data_shards,
            self.parity_shards
        );
        self.rs_decoder.get_inner().reconstruct(&mut ref_vec).ok()?;
        self.done = true;
        let res = self
            .space
            .drain(0..)
            .zip(self.present.iter().cloned())
            .take(self.data_shards)
            .filter_map(|(elem, present)| {
                if !present {
                    post_decode(Bytes::copy_from_slice(&elem))
                } else {
                    None
                }
            })
            .collect();
        Some(res)
    }
}
