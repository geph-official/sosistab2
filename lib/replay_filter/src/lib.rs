use bitvec::prelude::BitArray;

/// A filter for replays. Records recently seen seqnos and rejects either repeats or really old seqnos.
#[derive(Debug, Default)]
pub struct ReplayFilter {
    bottom_seqno: u64,
    bitmap: BitArray<[usize; 1024]>,
}

impl ReplayFilter {
    /// Adds a new sequence number to the replay filter. Returns whether this is accepted.
    pub fn add(&mut self, seqno: u64) -> bool {
        loop {
            if seqno < self.bottom_seqno {
                // out of range. we can't know, so we just say no
                return false;
            }
            let position = (seqno - self.bottom_seqno) as usize;
            if let Some(mut posn) = self.bitmap.get_mut(position) {
                if posn.replace(true) {
                    return false;
                } else {
                    return true;
                }
            }
            // we are out of range in the "future" side. we thus frame-shift the whole thing.
            self.frame_shift((seqno + self.bottom_seqno) / 2);
        }
    }

    fn frame_shift(&mut self, new_starting: u64) {
        let shift_amount = (new_starting - self.bottom_seqno) as usize;
        log::debug!("frameshift {shift_amount}");
        let limit = self.bitmap.len() - 1;
        self.bitmap.shift_left(shift_amount.min(limit));
        self.bottom_seqno = new_starting;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replay_filter_failure() {
        let mut replay_filter = ReplayFilter::default();

        // Initial large sequence number leading to frameshift
        assert_eq!(replay_filter.add(8_192), true);

        // Adding sequence numbers after frameshift
        for i in 4_096..8_192 {
            assert_eq!(replay_filter.add(i), true);
        }

        // Repeating sequence numbers
        for i in 4_096..8_192 {
            // This assertion should hold
            // Repeated sequence numbers should be rejected,
            // but due to frameshift, they are not in the bitmap and get accepted.
            assert_eq!(replay_filter.add(i), false);
        }
    }
}
