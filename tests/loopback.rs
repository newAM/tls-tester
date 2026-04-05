use tls_tester::{
    ECHConfig, ECHConfigList, NamedGroup, ServerCertificates, SignatureScheme, TlsClientBuilder,
    TlsClientStream, TlsServerBuilder, TlsServerStream,
};

use std::{
    io::{Read as _, Write as _},
    net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream},
};

// openssl req -x509 -newkey ec:<(openssl ecparam -name prime256v1) -keyout key_prime256v1.pem -out cert_prime256v1.pem -sha256 -days 3650 -nodes -subj "/CN=localhost"
fn certs_ecdsa_secp256r1_sha256() -> ServerCertificates {
    ServerCertificates::from_secpr256r1_pem("cert_prime256v1.pem", "key_prime256v1.pem")
        .expect("Invalid certificates")
}

// openssl req -x509 -newkey rsa:2048 -nodes -keyout key_rsa_pss_rsae_sha256.pem -out cert_rsa_pss_rsae_sha256.pem -sha256 -days 3650 -subj "/CN=localhost"
fn certs_rsa_pss_rsae_sha256() -> ServerCertificates {
    ServerCertificates::from_rsa_pss_rsae_sha256(
        "cert_rsa_pss_rsae_sha256.pem",
        "key_rsa_pss_rsae_sha256.pem",
    )
    .expect("Invalid certificates")
}

fn loopback_with(
    signature_algorithms: Vec<SignatureScheme>,
    named_groups: Vec<NamedGroup>,
    certs: ServerCertificates,
) {
    stderrlog::new()
        .verbosity(4)
        .timestamp(stderrlog::Timestamp::Microsecond)
        .init()
        .ok();

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
        .set_supported_named_groups(named_groups)
        .set_supported_signature_algorithms(signature_algorithms)
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
    loopback_with(
        vec![SignatureScheme::ecdsa_secp256r1_sha256],
        vec![NamedGroup::secp256r1],
        certs_ecdsa_secp256r1_sha256(),
    );
}

#[test]
fn loopback_x25519() {
    loopback_with(
        vec![SignatureScheme::ecdsa_secp256r1_sha256],
        vec![NamedGroup::x25519],
        certs_ecdsa_secp256r1_sha256(),
    );
}

#[test]
fn loopback_rsa_pss_rsae_sha256() {
    loopback_with(
        vec![SignatureScheme::rsa_pss_rsae_sha256],
        vec![NamedGroup::secp256r1, NamedGroup::x25519],
        certs_rsa_pss_rsae_sha256(),
    );
}

#[test]
fn loopback_psk() {
    stderrlog::new()
        .verbosity(4)
        .timestamp(stderrlog::Timestamp::Microsecond)
        .init()
        .ok();

    let certs: ServerCertificates = certs_ecdsa_secp256r1_sha256();

    let listener: TcpListener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port: u16 = listener
        .local_addr()
        .expect("Failed to get listener local address")
        .port();

    const PSK: [u8; 32] = [
        0x2f, 0x42, 0xac, 0xe2, 0xb6, 0xbe, 0x16, 0x81, 0xb3, 0xd2, 0xfc, 0xdd, 0x4b, 0xb5, 0x7b,
        0x4f, 0xfe, 0x34, 0x84, 0xee, 0x77, 0xfd, 0xaa, 0x8e, 0x21, 0x6e, 0x32, 0x72, 0xcd, 0x78,
        0x25, 0x9d,
    ];

    let server_thread = std::thread::Builder::new()
        .name("TLS server".to_string())
        .spawn(move || {
            log::info!("Accepting connections");
            let (client, addr) = listener.accept().expect("Unable to accept connections");
            log::info!("Accepted connection from {addr}");
            let mut tls_stream: TlsServerStream = TlsServerBuilder::new()
                .add_psk(b"not_used1", [0; 32])
                .add_psk(b"test", PSK)
                .add_psk(b"not_used2", [0; 32])
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
        .set_psk(b"test", PSK)
        .ignore_unknown_ca(true)
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
fn loopback_ech() {
    stderrlog::new()
        .verbosity(4)
        .timestamp(stderrlog::Timestamp::Microsecond)
        .init()
        .ok();

    let certs: ServerCertificates = certs_ecdsa_secp256r1_sha256();

    let listener: TcpListener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port: u16 = listener
        .local_addr()
        .expect("Failed to get listener local address")
        .port();

    let ech_server_secret: tls_tester::crypto::x25519::StaticSecret =
        tls_tester::crypto::x25519::StaticSecret::random();

    let ech_config: ECHConfigList =
        ECHConfig::from_x25519_secret(&ech_server_secret, "localhost").into();
    let ech_config_client: ECHConfigList = ech_config.clone();

    let server_thread = std::thread::Builder::new()
        .name("TLS server".to_string())
        .spawn(move || {
            log::info!("Accepting connections");
            let (client, addr) = listener.accept().expect("Unable to accept connections");
            log::info!("Accepted connection from {addr}");
            let mut tls_stream: TlsServerStream = TlsServerBuilder::new()
                .set_ech_config(ech_server_secret, ech_config)
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
        .set_ech_config(ech_config_client)
        .expect("Failed to set ECH configuration")
        .set_server_name("localhost")
        .expect("Failed to set server name")
        .ignore_unknown_ca(true)
        .handshake(tcp_stream)
        .expect("TLS handshake failed");

    tls_stream.write_all(b"ping").unwrap();
    let mut client_rx_data: [u8; 4] = [0; 4];
    tls_stream.read_exact(&mut client_rx_data).unwrap();

    let server_rx_data: [u8; 4] = server_thread.join().expect("Failed to join server thread");

    assert_eq!(&server_rx_data, b"ping");
    assert_eq!(&client_rx_data, b"pong");
}
