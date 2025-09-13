use tls_tester::{TlsClientBuilder, TlsClientStream};

use std::{
    io::{Read, Write as _},
    net::{Ipv4Addr, SocketAddrV4, TcpStream},
};

fn main() {
    stderrlog::new()
        .verbosity(4)
        .timestamp(stderrlog::Timestamp::Microsecond)
        .init()
        .unwrap();

    const SERVER_NAME: &str = "one.one.one.one";
    const SERVER_IPV4: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);

    log::info!("Connecting to {SERVER_NAME} at {SERVER_IPV4}...");
    let addr: SocketAddrV4 = SocketAddrV4::new(SERVER_IPV4, 443);
    let tcp_stream: TcpStream = TcpStream::connect(addr).unwrap();

    log::info!("Handshaking");
    let mut tls_stream: TlsClientStream = TlsClientBuilder::new()
        .set_server_name(SERVER_NAME)
        .expect("Server name invalid")
        .load_ca_bundle()
        .expect("Failed to load system CA bundle")
        .handshake(tcp_stream)
        .expect("TLS handshake failed");

    let http_get: String = format!("GET / HTTP/1.1\r\nHost: {SERVER_NAME}\r\n\r\n");
    tls_stream.write_all(http_get.as_bytes()).unwrap();
    tls_stream.flush().unwrap();
    let mut ret: Vec<u8> = vec![0; 1024];
    let len: usize = tls_stream.read(&mut ret).unwrap();

    let ret_filled: &[u8] = &ret[..len];

    println!("{ret_filled:?}");
}
