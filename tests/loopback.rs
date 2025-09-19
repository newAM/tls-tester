use tls_tester::{
    NamedGroup, ServerCertificates, TlsClientBuilder, TlsClientStream, TlsServerBuilder,
    TlsServerStream,
};

use std::{
    io::{Read as _, Write as _},
    net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream},
};

fn loopback_with_named_groups(named_groups: Vec<NamedGroup>) {
    stderrlog::new()
        .verbosity(4)
        .timestamp(stderrlog::Timestamp::Microsecond)
        .init()
        .ok();

    // gen certs:
    // openssl req -x509 -newkey ec:<(openssl ecparam -name prime256v1) -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes -subj "/CN=localhost"
    let certs: ServerCertificates = ServerCertificates::from_secpr256r1_pem("cert.pem", "key.pem")
        .expect("Invalid certificates");

    let listener: TcpListener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port: u16 = listener
        .local_addr()
        .expect("Failed to get listener local address")
        .port();

    let server_thread = std::thread::Builder::new()
        .name("TLS server".to_string())
        .spawn(move || {
            log::info!("Accepting connections");
            let (client, addr) = listener.accept().expect("Unable to accept connections");
            log::info!("Accepted connection from {addr}");
            let mut tls_stream: TlsServerStream = TlsServerBuilder::new()
                .handshake(client, certs)
                .expect("TLS handshake failed");

            let mut data: [u8; 4] = [0; 4];
            tls_stream.read_exact(&mut data).unwrap();
            tls_stream.write_all(b"pong").unwrap();

            data
        })
        .expect("Failed to spawn TLS server thread");

    log::info!("Connecting");
    let addr: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port);
    let tcp_stream: TcpStream = TcpStream::connect(addr).unwrap();

    log::info!("Handshaking");
    let mut tls_stream: TlsClientStream = TlsClientBuilder::new()
        .ignore_unknown_ca(true)
        .set_supported_name_groups(named_groups)
        .handshake(tcp_stream)
        .expect("TLS handshake failed");

    tls_stream.write_all(b"ping").unwrap();
    let mut client_rx_data: [u8; 4] = [0; 4];
    tls_stream.read_exact(&mut client_rx_data).unwrap();

    let server_rx_data: [u8; 4] = server_thread.join().expect("Failed to join server thread");

    assert_eq!(&server_rx_data, b"ping");
    assert_eq!(&client_rx_data, b"pong");
}

#[test]
fn loopback_secp256r1() {
    loopback_with_named_groups(vec![NamedGroup::secp256r1]);
}

#[test]
fn loopback_x25519() {
    loopback_with_named_groups(vec![NamedGroup::x25519]);
}
