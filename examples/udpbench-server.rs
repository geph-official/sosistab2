use std::sync::Arc;

use bytes::Bytes;
use futures_util::AsyncWriteExt;
use rand::SeedableRng;
use sosistab2::{
    Multiplex, MuxSecret, ObfsTlsListener, PipeListener, {ObfsUdpListener, ObfsUdpSecret},
};

fn main() {
    env_logger::init();
    let mux = Arc::new(Multiplex::new(
        MuxSecret::from_bytes(x25519_dalek::StaticSecret::new(rand::thread_rng()).to_bytes()),
        None,
    ));
    {
        let mux = mux.clone();
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
    let server_sk = ObfsUdpSecret::from_bytes(
        x25519_dalek::StaticSecret::new(rand_chacha::ChaCha8Rng::seed_from_u64(0)).to_bytes(),
    );
    let sk2 = server_sk;
    {
        let mux = mux.clone();
        smolscale::spawn(async move {
            let cert =
                rcgen::generate_simple_self_signed(vec!["helloworld.com".to_string()]).unwrap();
            let cert_pem = cert.serialize_pem().unwrap();
            let cert_key = cert.serialize_private_key_pem();
            let identity =
                native_tls::Identity::from_pkcs8(cert_pem.as_bytes(), cert_key.as_bytes())
                    .expect("wtf cannot decode id???");
            let config = native_tls::TlsAcceptor::new(identity).unwrap();
            let listener =
                ObfsTlsListener::bind("0.0.0.0:10000".parse().unwrap(), config, Bytes::new())
                    .await
                    .unwrap();
            loop {
                let pipe = listener.accept_pipe().await.unwrap();
                mux.add_pipe(pipe);
            }
        })
        .detach();
    }

    smolscale::block_on(async move {
        let listener = ObfsUdpListener::new("0.0.0.0:10000".parse().unwrap(), sk2);
        loop {
            let pipe = listener.accept().await.unwrap();
            mux.add_pipe(pipe);
        }
    })
}
