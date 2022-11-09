use std::collections::HashMap;

use bytes::{Bytes};


/// A "defragmenter" that takes in fragmented packets and reassembles them.
#[derive(Default)]
pub struct Defragmenter {
    /// Maps the starting seqno of the fragments to a smallvec of fragments, as well as a count of how many fragments we already have. This is essentially allocation-free when amortized.
    batches: HashMap<u64, (usize, Vec<Bytes>)>,
}

impl Defragmenter {
    /// Inserts a new fragment into the batch. If this completes a packet, returns the reassembled packet.
    pub fn insert(&mut self, raw_seqno: u64, frag: Bytes) -> Option<Bytes> {
        if self.batches.len() > 50 {
            // "garbage collect" the system
            let max = self.batches.keys().copied().max().unwrap_or_default();
            self.batches.retain(|k, _| max <= k + 20);
        }
        if frag.len() < 2 {
            return None;
        }
        let total_count = frag[0];
        let curr_idx = frag[1];
        if curr_idx >= total_count || (curr_idx as u64) > raw_seqno || total_count == 0 {
            return None;
        }
        let key = raw_seqno - (curr_idx as u64);

        let mut buffer = self.batches.entry(key).or_default();
        buffer.0 += 1;
        buffer.1.resize_with(total_count as usize, Bytes::new);
        buffer.1[curr_idx as usize] = frag.slice(2..);
        let count = buffer.0;

        if count == total_count as usize {
            let (_, batch) = self.batches.remove(&key).unwrap();
            // TODO reuse the memory of the first frag
            let mut collect_into = Vec::with_capacity(batch.iter().map(|v| v.len()).sum());
            for b in batch {
                collect_into.extend_from_slice(&b);
            }
            Some(collect_into.into())
        } else {
            None
        }
    }
}
