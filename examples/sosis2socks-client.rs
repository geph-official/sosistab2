use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::Arc,
    time::Duration,
};

use anyhow::Context;
use argh::FromArgs;
use native_tls::TlsConnector;
use rand::Rng;
use smol::net::TcpListener;
use smol_timeout::TimeoutExt;
use sosistab2::{Multiplex, MuxPublic, MuxSecret, ObfsTlsPipe, ObfsUdpPipe, ObfsUdpPublic};

#[derive(FromArgs)]
/// Connects to a sosis2socks server, exposing a socks5 on localhost.
struct Args {
    /// address to connect to.
    #[argh(option)]
    connect: SocketAddr,

    /// multiplex pubkey.
    #[argh(option)]
    mux_pk: String,

    /// cookie for obfuscated udp
    #[argh(option)]
    udp_cookie: String,

    /// cookie for obfuscated tls
    #[argh(option)]
    tls_cookie: String,
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    smolscale::block_on(async {
        let peer_metadata = format!("sess-{}", rand::thread_rng().gen::<u128>());
        let args: Args = argh::from_env();

        let mux = Arc::new(Multiplex::new(
            MuxSecret::generate(),
            Some(MuxPublic::from_bytes(
                hex::decode(&args.mux_pk)?
                    .try_into()
                    .ok()
                    .context("cannot fit")?,
            )),
        ));
        smolscale::spawn(socks_loop(mux.clone())).detach();
        loop {
            let fallible = async {
                if fastrand::bool() {
                    let mut config = TlsConnector::builder();
                    config
                        .danger_accept_invalid_certs(true)
                        .danger_accept_invalid_hostnames(true);
                    // connect to tls
                    let tls = ObfsTlsPipe::connect(
                        args.connect,
                        "helloworld",
                        config,
                        hex::decode(&args.tls_cookie)
                            .expect("cannot decode tls cookie")
                            .into(),
                        &peer_metadata,
                    )
                    .timeout(Duration::from_secs(10))
                    .await
                    .context("TLS timeout")??;
                    eprintln!("successfully made TLS to {}", args.connect);
                    mux.add_pipe(tls);
                    eprintln!("added!");
                } else {
                    let udp = ObfsUdpPipe::connect(
                        args.connect,
                        ObfsUdpPublic::from_bytes(
                            hex::decode(&args.udp_cookie)
                                .expect("cannot decode udp cookie")
                                .try_into()
                                .expect("udp cookie not right length"),
                        ),
                        &peer_metadata,
                    )
                    .timeout(Duration::from_secs(10))
                    .await
                    .context("UDP timeout")??;
                    eprintln!("successfully made UDP to {}", args.connect);
                    mux.add_pipe(udp);
                    eprintln!("added!");
                }

                anyhow::Ok(())
            };
            if let Err(err) = fallible.await {
                log::warn!("error connecting: {:?}", err);
            }
            smol::Timer::after(Duration::from_secs(15)).await;
        }
    })
}

async fn socks_loop(mux: Arc<Multiplex>) {
    let listener = TcpListener::bind("127.0.0.1:19909").await.unwrap();
    eprintln!("listening at {}", listener.local_addr().unwrap());
    loop {
        let (next, addr) = listener.accept().await.unwrap();
        eprintln!("got new socks5 conn from {addr}");
        smolscale::spawn(handle_socks5(mux.clone(), next)).detach();
    }
}

async fn handle_socks5(mux: Arc<Multiplex>, s5client: smol::net::TcpStream) -> anyhow::Result<()> {
    s5client.set_nodelay(true)?;
    use socksv5::v5::*;
    let _handshake = read_handshake(s5client.clone()).await?;
    write_auth_method(s5client.clone(), SocksV5AuthMethod::Noauth).await?;
    let request = read_request(s5client.clone()).await?;
    let port = request.port;
    let v4addr: Option<Ipv4Addr>;
    let addr: String = match &request.host {
        SocksV5Host::Domain(dom) => {
            v4addr = String::from_utf8_lossy(dom).parse().ok();
            format!("{}:{}", String::from_utf8_lossy(dom), request.port)
        }
        SocksV5Host::Ipv4(v4) => {
            let v4addr_inner = Ipv4Addr::new(v4[0], v4[1], v4[2], v4[3]);
            SocketAddr::V4(SocketAddrV4::new(
                {
                    v4addr = Some(v4addr_inner);
                    v4addr.unwrap()
                },
                request.port,
            ))
            .to_string()
        }
        _ => anyhow::bail!("not supported"),
    };
    let conn = mux
        .open_conn(Some(addr))
        .timeout(Duration::from_secs(10))
        .await
        .context("timeout")??;
    eprintln!("connected to the other side");
    write_request_status(
        s5client.clone(),
        SocksV5RequestStatus::Success,
        request.host,
        port,
    )
    .await?;
    smol::future::race(
        smol::io::copy(conn.clone(), s5client.clone()),
        smol::io::copy(s5client, conn),
    )
    .await?;
    Ok(())
}
