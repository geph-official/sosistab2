mod ack;
pub mod client;
mod defrag;
mod fec;
mod frame;
pub use listener_table::*;
pub mod listener;
pub use listener_table::*;
pub mod listener_table;
pub use listener_table::*;
pub mod stats;
pub use stats::*;
pub mod pipe_struct;
pub use pipe_struct::*;

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, str, time::Duration};

    use anyhow::Context;
    use bytes::Bytes;
    
    use smol_timeout::TimeoutExt;

    use crate::{
        connect,
        pipe::{frame::PipeFrame, Pipe},
        Listener,
    };

    #[test]
    fn pipe_test_1() {
        smolscale::block_on(async {
            let (alice_send_upcoded, bob_recv_downcoded) = smol::channel::unbounded();
            let (bob_send_upcoded, alice_recv_downcoded) = smol::channel::unbounded();
            let alice = Pipe::with_custom_transport(alice_recv_downcoded, alice_send_upcoded);
            let bob = Pipe::with_custom_transport(bob_recv_downcoded, bob_send_upcoded);
            println!("alice & bob are connected!");

            // send a bunch of numbers from a to b
            let mut alice_set = HashSet::new();
            for i in 0..10000 {
                let val = format!("{}", i);
                alice_set.insert(val.clone());
                alice.send(Bytes::from(val.clone())).await;
            }
            // put all packets received on bob's end into a hashmap
            let mut bob_set: HashSet<String> = HashSet::new();
            for _i in 0..10000 {
                let received = bob.recv().await;
                let val = str::from_utf8(&received).unwrap().to_owned();
                bob_set.insert(val);
            }
            assert!(bob_set == alice_set)
        })
    }

    #[test]
    fn pipe_test_2() {
        // send a bunch of packets
        // record each received pkt in a table
        // record each received ack request in a table
        // for each received ack request, delete included packets from table
        // at the end, assert table is empty.

        smolscale::block_on(async {
            let (send_upcoded, recv_upcoded) = smol::channel::unbounded();
            let (_send_downcoded, recv_downcoded) = smol::channel::unbounded();
            let pipe = Pipe::with_custom_transport(recv_downcoded, send_upcoded);

            for i in 0..10000 {
                let val = format!("{}", i);
                pipe.send(Bytes::from(val)).await;
            }

            let mut table = HashSet::new();
            for _i in 0..10000 {
                let frame = recv_upcoded.recv().await.unwrap();
                // println!("received frame: {:?}", frame);
                match frame {
                    PipeFrame::Data { frame_no, body: _ } => {
                        table.insert(frame_no);
                    }
                    PipeFrame::Parity {
                        data_frame_first: _,
                        data_count: _,
                        parity_count: _,
                        parity_index: _,
                        pad_size: _,
                        body: _,
                    } => {}
                    PipeFrame::Acks {
                        first_ack: _,
                        last_ack: _,
                        ack_bitmap: _,
                        time_offset: _,
                    } => {}
                    PipeFrame::AckRequest {
                        first_ack,
                        last_ack,
                    } => {
                        for i in first_ack..=last_ack {
                            table.remove(&i);
                        }
                    }
                }
            }
            assert!(table.is_empty());
        })
    }

    #[test]
    fn pipe_test_3() {
        smolscale::block_on(async {
            let (send_upcoded, recv_upcoded) = smol::channel::unbounded();
            let (_send_downcoded, recv_downcoded) = smol::channel::unbounded();
            let pipe = Pipe::with_custom_transport(recv_downcoded, send_upcoded);

            for i in 0..16000 {
                let val = format!("{}", i);
                pipe.send(Bytes::from(val)).await;
            }

            let mut parity_set = HashSet::new();
            for i in 0..16000 {
                let frame = recv_upcoded.recv().await.unwrap();
                match frame {
                    PipeFrame::Data {
                        frame_no: _,
                        body: _,
                    } => {}
                    PipeFrame::Parity {
                        data_frame_first: _,
                        data_count: _,
                        parity_count: _,
                        parity_index: _,
                        pad_size: _,
                        body: _,
                    } => {
                        parity_set.insert(i);
                    }
                    PipeFrame::Acks {
                        first_ack: _,
                        last_ack: _,
                        ack_bitmap: _,
                        time_offset: _,
                    } => {}
                    PipeFrame::AckRequest {
                        first_ack: _,
                        last_ack: _,
                    } => {}
                }
            }
            println!("NUMBER OF PARITY FRAMES SENT: {}", parity_set.len());
        })
    }

    #[test]
    fn pipe_test_4() {
        smolscale::block_on(async {
            let (alice_send_upcoded, alice_recv_upcoded) = smol::channel::unbounded();
            let (_alice_send_downcoded, alice_recv_downcoded) = smol::channel::unbounded();
            let alice = Pipe::with_custom_transport(alice_recv_downcoded, alice_send_upcoded);

            let (bob_send_upcoded, _bob_recv_upcoded) = smol::channel::unbounded();
            let (bob_send_downcoded, bob_recv_downcoded) = smol::channel::unbounded();
            let bob = Pipe::with_custom_transport(bob_recv_downcoded, bob_send_upcoded);

            // alice sends
            for i in 0..16000 {
                let val = format!("{}", i);
                alice.send(Bytes::from(val)).await;
            }

            // packet-dropping forwarding actor
            let mut packets_sent = 0;
            loop {
                let outcome = async {
                    if let Ok(msg) = alice_recv_upcoded.recv().await {
                        match &msg {
                            PipeFrame::Data { .. } => eprintln!("data"),
                            PipeFrame::Parity { .. } => eprintln!("parity"),
                            PipeFrame::Acks { .. } => eprintln!("acks"),
                            PipeFrame::AckRequest { .. } => eprintln!("ackrequest"),
                        }
                        let x = fastrand::u8(..);
                        packets_sent += 1;
                        if x < 200 {
                            let _ = bob_send_downcoded.send(msg).await;
                        }
                    }
                }
                .timeout(Duration::from_secs(1))
                .await;
                if outcome.is_none() {
                    break;
                }
            }

            // bob receives
            let mut received_set = HashSet::new();
            let mut i = 0;
            loop {
                let outcome = async {
                    let _p = bob.recv().await;
                    println!("received {i}th packet!");
                    received_set.insert(i);
                    i += 1;
                }
                .timeout(Duration::from_secs(1))
                .await;
                if outcome.is_none() {
                    break;
                }
            }

            println!("PACKETS SENT ON WIRE: {}", packets_sent);
            // println!("NUMBER OF PACKETS SENT: {}", sent_set.len());
            println!("NUMBER OF DATAGRAMS RECEIVED: {}", received_set.len());
        })
    }

    #[test]
    fn pipeback_test_1() {
        let _ = env_logger::try_init();
        smolscale::block_on(async {
            let res: anyhow::Result<()> = async {
                // spin up the server

                let server_sk = x25519_dalek::StaticSecret::new(rand::thread_rng());
                let server_pk: x25519_dalek::PublicKey = (&server_sk).into();
                let listener = Listener::new("127.0.0.1:33400".parse()?, server_sk);
                println!("created listener!");

                // connect
                let server_addr = "127.0.0.1:33400".parse()?;
                let client_pipe = connect(server_addr, server_pk)
                    .await
                    .context("could not create client_pipe")?;
                let server_pipe = listener
                    .accept()
                    .await
                    .context("could not create server_pipe")?;
                log::debug!("handshake succeeded!");

                // communicate
                let msg = "labooyah!";
                client_pipe.send(Bytes::from(msg)).await;
                println!("msg sent: {msg}");
                let msg = server_pipe.recv().await;
                let res = str::from_utf8(&msg)?;
                println!("msg received: {res}");
                assert!(res == "labooyah!");
                anyhow::Ok(())
            }
            .await;
            if res.is_err() {
                println!("ERR: {:?}", res);
            }
        })
    }
}
