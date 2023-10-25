use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sosistab2::crypt::NonObfsAead;

fn nonobfs_seal(b: &mut criterion::Bencher, n: usize) {
    let buff = vec![0u8; n];
    let ngaead = NonObfsAead::new(blake3::hash(b"hello world").as_bytes());
    b.iter(move || black_box(ngaead.encrypt(&buff)));
}

fn criterion_benchmark(c: &mut Criterion) {
    let _ = env_logger::try_init();

    c.bench_function("nonobfs_seal_1024", |b| nonobfs_seal(b, 1024));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
