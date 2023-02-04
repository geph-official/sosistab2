use std::collections::BTreeSet;

/// A filter for replays. Records recently seen seqnos and rejects either repeats or really old seqnos.
#[derive(Debug, Default)]
pub struct ReplayFilter {
    top_seqno: u64,
    bottom_seqno: u64,
    seen_seqno: BTreeSet<u64>,
}

impl ReplayFilter {
    pub fn add(&mut self, seqno: u64) -> bool {
        if seqno < self.bottom_seqno {
            // out of range. we can't know, so we just say no
            return false;
        }
        // check the seen
        if self.seen_seqno.contains(&seqno) {
            return false;
        }
        self.seen_seqno.insert(seqno);
        self.top_seqno = seqno.max(self.top_seqno);
        self.bottom_seqno = self.top_seqno.saturating_sub(10000);
        self.seen_seqno = self.seen_seqno.split_off(&self.bottom_seqno);
        // while self.top_seqno - self.bottom_seqno > 10000 {
        //     self.seen_seqno.remove(&self.bottom_seqno);
        //     self.bottom_seqno += 1;
        // }
        true
    }
}
