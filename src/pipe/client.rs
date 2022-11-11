// connect method that returns a pipe
// does handshake; creates pipe, creates background task, and returns the pipe

use std::{
    net::SocketAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use blake3::Hash;

use smol::{
    channel::{Receiver, Sender},
    future::FutureExt,
    net::UdpSocket,
};

use crate::{
    crypt::{triple_ecdh, Cookie, ObfsAead, CLIENT_DN_KEY, CLIENT_UP_KEY},
    pipe::Pipe,
    utilities::sockets::{new_udp_socket_bind, MyUdpSocket},
};

use super::frame::{HandshakeFrame, PipeFrame};

/// Establishes a pipe to the server_addr.
pub async fn connect(
    server_addr: SocketAddr,
    server_pk: x25519_dalek::PublicKey,
) -> anyhow::Result<Pipe> {
    let socket =
        new_udp_socket_bind("0.0.0.0:0".parse().unwrap()).context("could not bind udp socket")?;

    // do the handshake
    // generate pk-sk pairs for encryption after the session is established
    let my_long_sk = x25519_dalek::StaticSecret::new(rand::thread_rng());
    let my_eph_sk = x25519_dalek::StaticSecret::new(rand::thread_rng());
    let cookie = Cookie::new(server_pk);
    // construct the ClientHello message
    let client_hello = HandshakeFrame::ClientHello {
        long_pk: (&my_long_sk).into(),
        eph_pk: (&my_eph_sk).into(),
        version: 4,
        timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    }
    .to_bytes();
    // encrypt the ClientHello message
    let init_enc = ObfsAead::new(&cookie.generate_c2s());
    let client_hello = init_enc.encrypt(&client_hello);
    // send the ClientHello
    socket.send_to(&client_hello, server_addr).await?;

    // wait for the server's response
    let mut ctext_resp = [0u8; 2048];
    let (n, _) = socket
        .recv_from(&mut ctext_resp)
        .await
        .context("can't read response from server")?;
    let ctext_resp = &ctext_resp[..n];
    // decrypt the server's response
    let init_dec = ObfsAead::new(&cookie.generate_s2c());
    let ptext_resp = init_dec.decrypt(ctext_resp)?;
    let deser_resp = HandshakeFrame::from_bytes(&ptext_resp)?;
    if let HandshakeFrame::ServerHello {
        long_pk,
        eph_pk,
        resume_token,
    } = deser_resp
    {
        log::debug!("***** server hello received, calculating stuff ******");
        // finish off the handshake
        let client_resp =
            init_enc.encrypt(&HandshakeFrame::ClientResume { resume_token }.to_bytes());
        socket.send_to(&client_resp, server_addr).await?;

        // create a pipe
        let (send_upcoded, recv_upcoded) = smol::channel::unbounded();
        let (send_downcoded, recv_downcoded) = smol::channel::unbounded();
        let pipe = Pipe::with_custom_transport(recv_downcoded, send_upcoded);

        // start background encrypting/decrypting + forwarding task
        let shared_secret = triple_ecdh(&my_long_sk, &my_eph_sk, &long_pk, &eph_pk);
        log::debug!("CLIENT shared_secret: {:?}", shared_secret);
        smolscale::spawn(client_loop(
            recv_upcoded,
            send_downcoded,
            socket,
            server_addr,
            shared_secret,
        ))
        .detach();

        Ok(pipe)
    } else {
        anyhow::bail!("server sent unrecognizable message")
    }
}

async fn client_loop(
    recv_upcoded: Receiver<PipeFrame>,
    send_downcoded: Sender<PipeFrame>,
    socket: MyUdpSocket,
    server_addr: SocketAddr,
    shared_secret: Hash,
) {
    let up_key = blake3::keyed_hash(CLIENT_UP_KEY, shared_secret.as_bytes());
    let dn_key = blake3::keyed_hash(CLIENT_DN_KEY, shared_secret.as_bytes());
    let enc = ObfsAead::new(up_key.as_bytes());
    let dec = ObfsAead::new(dn_key.as_bytes());

    loop {
        let res: anyhow::Result<()> = async {
            let up_loop = async {
                loop {
                    let msg = recv_upcoded.recv().await?;
                    // log::debug!("serverbound: {:?}", msg);
                    let msg = stdcode::serialize(&msg)?;
                    let enc_msg = enc.encrypt(&msg);
                    socket.send_to(&enc_msg, server_addr).await?;
                }
            };

            up_loop
                .race(async {
                    let mut buf = [0u8; 65536];
                    loop {
                        let (n, _) = socket.recv_from(&mut buf).await?;
                        log::trace!("got {} bytes from server", n);
                        let dn_msg = &buf[..n];
                        let dec_msg = dec.decrypt(dn_msg)?;

                        let deser_msg = stdcode::deserialize(&dec_msg)?;
                        send_downcoded.send(deser_msg).await?;
                    }
                })
                .await
        }
        .await;
        if let Err(err) = res {
            log::error!("client loop error: {:?}", err);
        }
    }
}
