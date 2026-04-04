use tls_tester::{NamedGroup, ServerCertificates, TlsServerBuilder, TlsServerStream};

use std::{
    io::{Read as _, Write as _},
    net::TcpListener,
    process::Command,
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

fn test_curl_with_args(
    args: &'static [&'static str],
    supported_named_groups: Vec<NamedGroup>,
    certs: ServerCertificates,
) -> TlsServerStream {
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

    let curl_thread = std::thread::spawn(move || {
        log::info!("sending http request with curl");
        let mut output: std::process::Child = Command::new("curl")
            .arg(format!("https://127.0.0.1:{port}"))
            .arg("--tlsv1.3")
            .args(args)
            .arg("--insecure")
            .arg("--connect-timeout")
            .arg("1")
            .arg("--max-time")
            .arg("5")
            .arg("-v")
            .arg("--http1.1")
            .spawn()
            .unwrap();

        output.wait().unwrap().success()
    });

    log::info!("Accepting connections");
    let (client, addr) = listener.accept().expect("Unable to accept connections");
    log::info!("Accepted connection from {addr}");
    let mut tls_stream: TlsServerStream = TlsServerBuilder::new()
        .set_supported_named_groups(supported_named_groups)
        .handshake(client, certs)
        .expect("Failed to create TLS stream");
    let mut http_buf: [u8; 4096] = [0; 4096];
    let read_len: usize = tls_stream
        .read(&mut http_buf)
        .expect("Failed to read from TLS stream");
    let request: &[u8] = &http_buf[..read_len];
    log::info!("REQUEST={}", String::from_utf8_lossy(request));

    let http_response: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    tls_stream
        .write_all(http_response)
        .expect("Failed to write HTTP response");

    let curl_status = curl_thread.join().expect("Failed to join curl thread");
    assert!(curl_status);

    tls_stream
}

#[test]
fn server_curl_secp256r1() {
    test_curl_with_args(
        &["--curves", "secp256r1"],
        vec![NamedGroup::secp256r1],
        certs_ecdsa_secp256r1_sha256(),
    );
}

#[test]
fn server_curl_x25519() {
    test_curl_with_args(
        &["--curves", "x25519"],
        vec![NamedGroup::x25519],
        certs_ecdsa_secp256r1_sha256(),
    );
}

#[test]
fn server_curl_hello_retry() {
    let server_stream = test_curl_with_args(
        &["--curves", "x25519:secp256r1"],
        vec![NamedGroup::secp256r1],
        certs_ecdsa_secp256r1_sha256(),
    );

    assert!(
        server_stream.hello_retry_request(),
        "Server did not send a hello retry"
    );
}

#[test]
fn server_curl_rsa_pss_rsae_sha256() {
    stderrlog::new()
        .verbosity(4)
        .timestamp(stderrlog::Timestamp::Microsecond)
        .init()
        .ok();
    test_curl_with_args(
        &["--curves", "x25519", "--sigalgs", "rsa_pss_rsae_sha256"],
        vec![NamedGroup::x25519],
        certs_rsa_pss_rsae_sha256(),
    );
}
