use tls_tester::{ServerCertificates, TlsStream, TlsStreamBuilder};

use std::{
    io::{Read as _, Write as _},
    net::TcpListener,
    process::{Command, Output},
};

fn test_curl_with_args(args: &'static [&'static str]) {
    stderrlog::new()
        .verbosity(3)
        .timestamp(stderrlog::Timestamp::Microsecond)
        .init()
        .ok();

    // gen certs:
    // openssl req -x509 -newkey ec:<(openssl ecparam -name secp256r1) -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes -subj "/CN=localhost"
    let certs: ServerCertificates = ServerCertificates::from_secpr256r1_pem("cert.pem", "key.pem")
        .expect("Invalid certificates");

    let listener: TcpListener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port: u16 = listener
        .local_addr()
        .expect("Failed to get listener local address")
        .port();

    let curl_thread = std::thread::spawn(move || {
        log::info!("sending http request with curl");
        let output: Output = Command::new("curl")
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
            .output()
            .unwrap();

        eprintln!("{}", String::from_utf8_lossy(&output.stderr));
        let stdout = String::from_utf8_lossy(&output.stdout);
        if !stdout.is_empty() {
            panic!("{}", String::from_utf8_lossy(&output.stdout));
        }

        output.status.success()
    });

    log::info!("Accepting connections");
    let (client, addr) = listener.accept().expect("Unable to accept connections");
    log::info!("Accepted connection from {addr}");
    let mut tls_stream: TlsStream = TlsStreamBuilder::new()
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
}

#[test]
fn test_curl() {
    test_curl_with_args(&["--curves", "secp256r1"])
}

#[test]
fn test_curl_hello_retry() {
    test_curl_with_args(&["--curves", "x25519:secp256r1"])
}
