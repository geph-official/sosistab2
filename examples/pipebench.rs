use std::time::Instant;

use bytes::Bytes;
use sosistab2::Pipe;

fn main() {
    env_logger::init();
    smolscale::block_on(async move {
        let (alice_send_upcoded, bob_recv_downcoded) = smol::channel::bounded(1000);
        let (bob_send_upcoded, alice_recv_downcoded) = smol::channel::bounded(1000);
        let alice = Pipe::with_custom_transport(alice_recv_downcoded, alice_send_upcoded);
        let bob = Pipe::with_custom_transport(bob_recv_downcoded, bob_send_upcoded);
        smolscale::spawn(async move {
            loop {
                let _ = bob.recv().await;
            }
        })
        .detach();
        let size = 65535;
        let to_send = Bytes::from(vec![0u8; size]);
        let start = Instant::now();
        for count in 0.. {
            alice.send(to_send.clone()).await;
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
