use bitvec::prelude::*;
use itertools::Itertools;
use rustc_hash::FxHashMap;

use crate::utilities::batchtimer::BatchTimer;

use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use super::frame::PipeFrame;

pub struct AckResponder {
    received_map: FxHashMap<u64, Instant>,
    received_map_maxlen: usize,
    smallest_seqno: u64,
}

impl AckResponder {
    pub fn new(maxlen: usize) -> Self {
        Self {
            received_map: Default::default(),
            received_map_maxlen: maxlen,
            smallest_seqno: 0,
        }
    }

    pub fn add_ack(&mut self, seqno: u64) {
        while self.received_map.len() >= self.received_map_maxlen {
            self.received_map.remove(&self.smallest_seqno);
            self.smallest_seqno += 1;
        }
        self.received_map.insert(seqno, Instant::now());
    }

    pub fn construct_acks(&mut self, first: u64, last: u64) -> Vec<PipeFrame> {
        (first..=last)
            .chunks(5000)
            .into_iter()
            .map(|mut range| {
                let f = range.next().unwrap();
                let l = range.last().unwrap_or(first);
                // create a bitvec that internally uses a Vec<u8>, filled with 0s, with the smallest number of u8s necessary to contain l-f bits (i.e. ceiling((l-f) * 8))
                // Msb0 here means that the most significant bit of each u8 represents the "first" bit.
                let mut bitmap_underlying = vec![0u8; ((l - f + 8) / 8) as usize];
                let bitmap = BitSlice::<_, Msb0>::from_slice_mut(&mut bitmap_underlying);

                let mut time_offset = None;
                for i in f..=l {
                    let val = self.received_map.contains_key(&(i as u64));
                    if val && time_offset.is_none() {
                        let pkt_received_time = self.received_map.get(&(i as u64)).unwrap(); // unwrap will never fail because we only enter this block if map contains i as key
                        time_offset = Some(Instant::now().duration_since(*pkt_received_time));
                    }
                    bitmap.set((i - f) as usize, val);
                }

                PipeFrame::Acks {
                    first_ack: f,
                    last_ack: l,
                    ack_bitmap: bitmap_underlying.into(),
                    time_offset,
                }
            })
            .collect_vec()
    }
}

pub struct AckRequester {
    unacked: VecDeque<(u64, Instant)>,
    timer: BatchTimer,
    packet_live_time: Duration,
}

impl AckRequester {
    pub fn new(packet_live_time: Duration) -> Self {
        Self {
            unacked: VecDeque::new(), // queue of unacked seqnos, with oldest at the front
            timer: BatchTimer::new(Duration::from_millis(10), 1000),
            packet_live_time,
        }
    }

    pub fn add_unacked(&mut self, seqno: u64) {
        self.unacked.push_back((seqno, Instant::now()));

        self.timer.increment();
    }

    pub async fn wait_ack_request(&mut self) -> PipeFrame {
        // println!("at wait: {:p} UNACKED length: {}", self, self.unacked.len());
        self.timer.wait().await;
        log::trace!("wait_ack_request: {}", self.unacked.len());
        if let Some((first, _)) = self.unacked.pop_front() {
            let mut last = first;

            while let Some((seq, inst)) = self.unacked.pop_front() {
                if inst.elapsed() >= self.packet_live_time {
                    last = seq;
                } else {
                    self.unacked.push_front((seq, inst));
                    break;
                }
            }
            self.timer.reset();
            if first == last {
                self.timer.increment();
            }
            PipeFrame::AckRequest {
                first_ack: first,
                last_ack: last,
            }
        } else {
            smol::future::pending().await
        }
    }
}
