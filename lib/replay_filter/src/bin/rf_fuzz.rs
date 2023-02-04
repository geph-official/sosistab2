fn main() {
    #[cfg(fuzzing)]
    loop {
        use std::collections::HashSet;

        use replay_filter::ReplayFilter;
        honggfuzz::fuzz!(|data: &[u8]| {
            let values = data
                .chunks_exact(8)
                .map(|ch| u64::from_be_bytes(ch.try_into().unwrap()))
                .collect::<Vec<_>>();

            let mut ground_truth = HashSet::new();
            let mut filter = ReplayFilter::default();
            for value in values {
                eprintln!("hit {value}");
                let truth = ground_truth.insert(value);
                let approx = filter.add(value as u64);
                if !truth {
                    assert!(!approx)
                }
                if approx {
                    assert!(truth)
                }
            }
        });
    }
}
