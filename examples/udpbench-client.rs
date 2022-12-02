use std::{net::SocketAddr, time::Instant};

use bytes::Bytes;
use futures_util::AsyncReadExt;
use itertools::Itertools;
use native_tls::TlsConnector;
use rand::SeedableRng;

use sosistab2::{
    Multiplex, MuxSecret, ObfsTlsPipe, {ObfsUdpPipe, ObfsUdpSecret},
};

fn main() {
    env_logger::init();
    let server_sk = ObfsUdpSecret::from_bytes(
        x25519_dalek::StaticSecret::new(rand_chacha::ChaCha8Rng::seed_from_u64(0)).to_bytes(),
    );

    let server_addr: SocketAddr = std::env::args().collect_vec()[1].parse().unwrap();
    smolscale::block_on(async move {
        let pipe1 = ObfsUdpPipe::connect(server_addr, server_sk.to_public(), "foo")
            .await
            .unwrap();
        let mut config = TlsConnector::builder();
        config
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true);
        let pipe2 =
            ObfsTlsPipe::connect(server_addr, "helloworld.com", config, Bytes::new(), "foo")
                .await
                .unwrap();
        let mux = Multiplex::new(MuxSecret::from_bytes(
            x25519_dalek::StaticSecret::new(rand::thread_rng()).to_bytes(),
        ));
        mux.add_pipe(pipe1).await;
        mux.add_pipe(pipe2).await;
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
