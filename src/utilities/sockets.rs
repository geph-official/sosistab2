use std::net::SocketAddr;

use smol::net::UdpSocket;
use socket2::{Domain, Socket, Type};

pub type MyUdpSocket = UdpSocket;

/// Create a new UDP socket that has a largeish buffer and isn't bound to anything.
pub(crate) fn new_udp_socket_bind(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let socket = get_socket(addr)?;
    Ok(socket.into_udp_socket().try_into().unwrap())
}

// /// Create a new UDP socket that has a largeish buffer and isn't bound to anything.
// pub(crate) fn new_udp_socket_bind(addr: SocketAddr) -> std::io::Result<FastUdpSocket> {
//     let socket = get_socket(addr)?;
//     Ok(socket.into_udp_socket().try_into().unwrap())
// }

fn get_socket(addr: SocketAddr) -> std::io::Result<Socket> {
    let socket = Socket::new(
        match addr {
            SocketAddr::V4(_) => Domain::ipv4(),
            SocketAddr::V6(_) => Domain::ipv6(),
        },
        Type::dgram(),
        None,
    )
    .unwrap();
    drop(socket.set_only_v6(false));
    socket
        .set_recv_buffer_size(10 * 1024 * 1024)
        .unwrap_or_else(|e| log::warn!("cannot set receive buffer: {:?}", e));
    socket
        .set_send_buffer_size(10 * 1024 * 1024)
        .unwrap_or_else(|e| log::warn!("cannot set send buffer: {:?}", e));
    socket.bind(&addr.into())?;
    Ok(socket)
}
