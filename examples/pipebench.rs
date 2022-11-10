use bytes::Bytes;
use smol::prelude::*;
use sosistab2::{Multiplex, Pipe};
use std::time::Instant;

fn main() {
    env_logger::init();
    smolscale::block_on(async move {
        let (alice_send_upcoded, bob_recv_downcoded) = smol::channel::bounded(1000);
        let (bob_send_upcoded, alice_recv_downcoded) = smol::channel::bounded(1000);
        let alice = Pipe::with_custom_transport(alice_recv_downcoded, alice_send_upcoded);
        let bob = Pipe::with_custom_transport(bob_recv_downcoded, bob_send_upcoded);

        let alice_mux = Multiplex::new(x25519_dalek::StaticSecret::new(rand::thread_rng()));
        alice_mux.add_pipe(alice).await;
        let bob_mux = Multiplex::new(x25519_dalek::StaticSecret::new(rand::thread_rng()));
        bob_mux.add_pipe(bob).await;

        smolscale::spawn(async move {
            let mut conn = bob_mux.accept_conn().await.unwrap();
            let mut buff = [0u8; 65536];
            loop {
                conn.recv_urel().await.unwrap();
            }
        })
        .detach();
        let size = 1024;
        let to_send = Bytes::from(vec![0u8; size]);
        let start = Instant::now();
        let mut conn = alice_mux.open_conn(None).await.unwrap();
        for count in 0.. {
            conn.send_urel(to_send.clone()).await.unwrap();
            if count % 100 == 0 {
                let rate = count as f64 / start.elapsed().as_secs_f64();
                eprintln!(
                    "{:.2} pps / {:.2} MiB/s / {:.2} Gbps",
                    rate,
                    rate * (size as f64) / 1024.0 / 1024.0,
                    rate * (size as f64) / 1000.0 / 1000.0 / 1000.0 * 8.0
                )
            }
        }
    })
}
