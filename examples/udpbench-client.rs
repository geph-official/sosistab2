use std::{net::SocketAddr, time::Instant};

use itertools::Itertools;
use rand::SeedableRng;
use smol::io::AsyncReadExt;
use sosistab2::Multiplex;

fn main() {
    env_logger::init();
    let server_sk = x25519_dalek::StaticSecret::new(rand_chacha::ChaCha8Rng::seed_from_u64(0));

    let server_addr: SocketAddr = std::env::args().collect_vec()[1].parse().unwrap();
    smolscale::block_on(async move {
        let pipe = sosistab2::connect(server_addr, (&server_sk).into())
            .await
            .unwrap();
        let mux = Multiplex::new(x25519_dalek::StaticSecret::new(rand::thread_rng()));
        mux.add_pipe(pipe).await;
        let mut conn = mux.open_conn(None).await.unwrap();
        let start = Instant::now();
        for count in 0u64.. {
            conn.read_exact(&mut [0u8; 4096]).await.unwrap();
            if count % 100 == 0 {
                let total_bytes = count * 4096;
                let rate = total_bytes as f64 / start.elapsed().as_secs_f64();
                eprintln!(
                    "{:.2} MiB/s / {:.2} Mbps",
                    rate / 1024.0 / 1024.0,
                    rate / 1000.0 / 1000.0 * 8.0
                )
            }
        }
    })
}
