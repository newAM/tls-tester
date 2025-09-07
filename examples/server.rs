use tls_tester::{ServerCertificates, TlsServerBuilder, TlsServerStream};

use std::{
    io::{Read as _, Write as _},
    net::TcpListener,
    process::{Command, Output},
};

fn main() {
    stderrlog::new()
        .verbosity(4)
        .timestamp(stderrlog::Timestamp::Microsecond)
        .init()
        .unwrap();

    let certs: ServerCertificates = ServerCertificates::from_secpr256r1_pem("cert.pem", "key.pem")
        .expect("Invalid certificates");

    let listener: TcpListener = TcpListener::bind("127.0.0.1:12345").unwrap();

    let curl_thread = std::thread::spawn(move || {
        log::info!("sending http request with curl");
        let output: Output = Command::new("curl")
            .arg("https://127.0.0.1:12345")
            .arg("--tlsv1.3")
            .arg("--curves")
            .arg("secp256r1")
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

    // openssl s_client -connect 127.0.0.1:12345 -tls1_3 -debug -curves secp256r1 -psk 2f42ace2b6be1681b3d2fcdd4bb57b4ffe3484ee77fdaa8e216e3272cd78259d
    // let output: Output = Command::new("openssl")
    //     .arg("s_client")
    //     .arg("-connect")
    //     .arg("127.0.0.1:12345")
    //     .arg("-tls1_3")
    //     .arg("-curves")
    //     .arg("secp256r1")
    //     .arg("-debug")
    //     .arg("-psk")
    //     .arg("2f42ace2b6be1681b3d2fcdd4bb57b4ffe3484ee77fdaa8e216e3272cd78259d")
    //     .output()
    //     .unwrap();

    log::info!("Accepting connections");
    let (client, addr) = listener.accept().expect("Unable to accept connections");
    log::info!("Accepted connection from {addr}");
    let mut tls_stream: TlsServerStream = TlsServerBuilder::new()
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
