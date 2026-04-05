use tls_tester::{
    ECHConfig, ECHConfigList, NamedGroup, ServerCertificates, TlsServerBuilder, TlsServerStream,
};

use std::{
    io::{Read as _, Write as _},
    net::TcpListener,
    sync::Arc,
};

// openssl req -x509 -newkey ec:<(openssl ecparam -name prime256v1) -keyout key_prime256v1.pem -out cert_prime256v1.pem -sha256 -days 3650 -nodes -subj "/CN=localhost"
fn certs_ecdsa_secp256r1_sha256() -> ServerCertificates {
    ServerCertificates::from_secpr256r1_pem("cert_prime256v1.pem", "key_prime256v1.pem")
        .expect("Invalid certificates")
}

#[derive(Debug)]
pub struct AcceptAllVerifier {}

impl rustls::client::danger::ServerCertVerifier for AcceptAllVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // Accept any server certificate
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // deny TLS 1.2
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOfferedOrEnabled,
        ))
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // Accept any TLS 1.3 signature
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![rustls::SignatureScheme::ECDSA_NISTP256_SHA256]
    }
}

#[test]
fn rustls_ech() {
    stderrlog::new()
        .verbosity(3)
        .timestamp(stderrlog::Timestamp::Microsecond)
        .init()
        .ok();

    const HTTP_REQUEST: &[u8] = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    const HTTP_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";

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
    let ech_config_list_bytes: Vec<u8> = ech_config.ser();

    let verifier = AcceptAllVerifier {};

    let rustls_thread = std::thread::Builder::new()
        .name("rustls client".to_string())
        .spawn(move || {
            let mut client_config = rustls::ClientConfig::builder_with_provider(
                rustls::crypto::aws_lc_rs::default_provider().into(),
            )
            .with_ech(rustls::client::EchMode::Enable(
                rustls::client::EchConfig::new(
                    ech_config_list_bytes.into(),
                    rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES,
                )
                .expect("Failed to create rustls ECH configuration"),
            ))
            .expect("Failed to create rustls::ClientConfig")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();

            client_config.key_log = Arc::new(rustls::KeyLogFile::new());

            // The test certificate uses CN=localhost.
            let server_name =
                rustls::pki_types::ServerName::try_from("localhost").expect("Invalid server name");

            // Connect to the test server.
            let tcp_stream = std::net::TcpStream::connect(("127.0.0.1", port))
                .expect("Failed to connect to server");

            // Create the TLS client connection.
            let client_conn = rustls::client::ClientConnection::new(
                std::sync::Arc::new(client_config),
                server_name,
            )
            .expect("Failed to create client connection");

            // Wrap TLS connection with the TCP stream.
            let mut tls_stream = rustls::StreamOwned::new(client_conn, tcp_stream);

            // Send a minimal HTTP GET request.
            tls_stream
                .write_all(HTTP_REQUEST)
                .expect("Failed to write request");

            // Read the full response.
            let mut response: Vec<u8> = vec![0; HTTP_RESPONSE.len()];
            tls_stream
                .read_exact(&mut response)
                .expect("Failed to read response");

            let response_matches: bool = response == HTTP_RESPONSE;

            // Verify that the response contains "200 OK".
            let response_str: String = String::from_utf8_lossy(&response)
                .replace("\r", "\\r")
                .replace("\n", "\\n");
            log::info!("RESPONSE={}", response_str);

            response_matches
        })
        .expect("Failed to spawn thread for rustls client");

    log::info!("Accepting connections");
    let (client, addr) = listener.accept().expect("Unable to accept connections");
    log::info!("Accepted connection from {addr}");
    let mut tls_stream: TlsServerStream = TlsServerBuilder::new()
        .set_supported_named_groups(vec![NamedGroup::x25519])
        .set_ech_config(ech_server_secret, ech_config)
        .handshake(client, certs)
        .expect("Failed to create TLS stream");
    let mut http_buf: [u8; 4096] = [0; 4096];
    let read_len: usize = tls_stream
        .read(&mut http_buf)
        .expect("Failed to read from TLS stream");
    let request: &[u8] = &http_buf[..read_len];
    assert_eq!(
        request, HTTP_REQUEST,
        "HTTP request does not match expected"
    );
    log::info!(
        "REQUEST={}",
        String::from_utf8_lossy(request)
            .replace("\r", "\\r")
            .replace("\n", "\\n")
    );

    tls_stream
        .write_all(HTTP_RESPONSE)
        .expect("Failed to write HTTP response");

    let rustls_thread = rustls_thread.join().expect("Failed to join rustls thread");
    assert!(rustls_thread, "HTTP response does not match expected");
}
