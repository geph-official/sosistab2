use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use argh::FromArgs;
use bytes::Bytes;
use moka::sync::Cache;
use native_tls::TlsAcceptor;
use once_cell::sync::Lazy;
use rand::{rngs::OsRng, RngCore};
use smol::{future::FutureExt, net::TcpStream, Task};
use smol_str::SmolStr;
use sosistab2::{
    Multiplex, MuxSecret, ObfsTlsListener, ObfsUdpListener, ObfsUdpSecret, Pipe, PipeListener,
};

#[derive(FromArgs)]
/// Runs a simple proxy server using the sosistab2 protocol, over both TCP and UDP.
struct Args {
    /// address to listen to.
    #[argh(option)]
    listen: SocketAddr,

    /// path to store persistent keys. optional.
    #[argh(option)]
    key_path: Option<PathBuf>,
}

fn gen_mux_secret(mut key_path: PathBuf) -> anyhow::Result<MuxSecret> {
    key_path.push("mux.secret");
    if let Ok(existing) = std::fs::read(&key_path) {
        Ok(stdcode::deserialize(&existing)?)
    } else {
        let new = MuxSecret::generate();
        std::fs::write(&key_path, stdcode::serialize(&new)?)?;
        Ok(new)
    }
}

fn gen_obfsudp_secret(mut key_path: PathBuf) -> anyhow::Result<ObfsUdpSecret> {
    key_path.push("obfsudp.secret");
    if let Ok(existing) = std::fs::read(&key_path) {
        Ok(stdcode::deserialize(&existing)?)
    } else {
        let new = ObfsUdpSecret::generate();
        std::fs::write(&key_path, stdcode::serialize(&new)?)?;
        Ok(new)
    }
}

fn gen_obfstls_cookie(mut key_path: PathBuf) -> anyhow::Result<Bytes> {
    key_path.push("obfstls.cookie");
    if let Ok(existing) = std::fs::read(&key_path) {
        Ok(existing.into())
    } else {
        let mut buff = [0u8; 32];
        OsRng {}.fill_bytes(&mut buff);
        std::fs::write(&key_path, buff)?;
        Ok(buff.to_vec().into())
    }
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    smolscale::block_on(async {
        let args: Args = argh::from_env();
        let key_path = args.key_path.unwrap_or_else(|| {
            let mut d = dirs::config_dir().unwrap();
            d.push("sosis2socks");
            d
        });
        std::fs::create_dir_all(&key_path)?;
        let mux_secret = gen_mux_secret(key_path.clone())?;
        let obfstls_cookie = gen_obfstls_cookie(key_path.clone())?;
        let obfsudp_secret = gen_obfsudp_secret(key_path)?;
        eprintln!(
            "multiplex pubkey:\t{}",
            hex::encode(mux_secret.to_public().as_bytes())
        );
        eprintln!(
            "obfs-udp cookie:\t{}",
            hex::encode(obfsudp_secret.to_public().as_bytes())
        );
        eprintln!("obfs-tls cookie:\t{}", hex::encode(&obfstls_cookie));
        let udp_listener = ObfsUdpListener::new(args.listen, obfsudp_secret);
        let tls_listener = ObfsTlsListener::bind(args.listen, tls_config(), obfstls_cookie).await?;
        smolscale::spawn(accept_loop(mux_secret.clone(), udp_listener)).detach();
        smolscale::spawn(accept_loop(mux_secret, tls_listener)).detach();
        smol::future::pending().await
    })
}

fn tls_config() -> TlsAcceptor {
    let cert = rcgen::generate_simple_self_signed(vec!["helloworld.com".to_string()]).unwrap();
    let cert_pem = cert.serialize_pem().unwrap();
    let cert_key = cert.serialize_private_key_pem();
    let identity = native_tls::Identity::from_pkcs8(cert_pem.as_bytes(), cert_key.as_bytes())
        .expect("wtf cannot decode id???");
    native_tls::TlsAcceptor::new(identity).unwrap()
}

async fn accept_loop(longterm: MuxSecret, listener: impl PipeListener) {
    loop {
        let next = listener.accept_pipe().await.expect("cannot listen");
        eprintln!(
            "pipe from {} / {}; sessid {}",
            next.peer_addr(),
            next.protocol(),
            next.peer_metadata()
        );
        smolscale::spawn(process_pipe(longterm.clone(), next)).detach();
    }
}

async fn process_pipe(longterm: MuxSecret, pipe: Arc<dyn Pipe>) {
    static SESSION_MAP: Lazy<Cache<SmolStr, (Arc<Multiplex>, Arc<Task<anyhow::Result<()>>>)>> =
        Lazy::new(|| {
            Cache::builder()
                .time_to_idle(Duration::from_secs(3600))
                .build()
        });

    let (multiplex, _) = SESSION_MAP.get_with(pipe.peer_metadata().into(), || {
        let multiplex = Arc::new(Multiplex::new(longterm, None));
        let task = Arc::new(smolscale::spawn(process_mux(multiplex.clone())));
        (multiplex, task)
    });
    multiplex.add_pipe(pipe);
}

async fn process_mux(mux: Arc<Multiplex>) -> anyhow::Result<()> {
    loop {
        let next = mux.accept_conn().await?;
        smolscale::spawn(async move {
            let remote = next.additional_info();
            let start = Instant::now();
            eprintln!("opening connection to {}...", remote);
            let remconn = TcpStream::connect(remote).await?;
            eprintln!("opened connection to {} in {:?}", remote, start.elapsed());
            smol::io::copy(remconn.clone(), next.clone())
                .race(smol::io::copy(next, remconn))
                .await?;

            anyhow::Ok(())
        })
        .detach();
    }
}
