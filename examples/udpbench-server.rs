use futures_util::AsyncWriteExt;
use rand::SeedableRng;
use sosistab2::{Listener, Multiplex};

fn main() {
    env_logger::init();
    let server_sk = x25519_dalek::StaticSecret::new(rand_chacha::ChaCha8Rng::seed_from_u64(0));
    let sk2 = server_sk.clone();
    smolscale::block_on(async move {
        let listener = Listener::new("0.0.0.0:10000".parse().unwrap(), sk2);
        loop {
            let pipe = listener.accept().await.unwrap();
            let mux = Multiplex::new(x25519_dalek::StaticSecret::new(rand::thread_rng()));
            mux.add_pipe(pipe).await;
            smolscale::spawn(async move {
                loop {
                    let mut conn = mux.accept_conn().await.unwrap();
                    smolscale::spawn(async move {
                        loop {
                            if conn.write_all(&[0u8; 65536]).await.is_err() {
                                return;
                            }
                        }
                    })
                    .detach()
                }
            })
            .detach();
        }
    })
}
