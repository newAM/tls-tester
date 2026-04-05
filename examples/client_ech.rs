use tls_tester::{ECHConfigList, NamedGroup, TlsClientBuilder, TlsClientStream};

use std::{
    io::{Read, Write as _},
    net::{Ipv4Addr, SocketAddrV4, TcpStream, ToSocketAddrs as _},
};

/// Query the ECH configuration for a domain.
///
/// This performs a DNS query with DNS over HTTPs with curl.
/// The output of DNS over HTTPs is json, which is interpreted with jq.
///
/// This is naive and ignores multiple records and record priority.
///
/// jq and curl are used because I did not want to introduce serde_json and an
/// http request library for a single example.
fn query_ech_config_with_curl(domain: &str) -> ECHConfigList {
    // use DNS over HTTPS to curl one.one.one.one (cloudflare's DNS)
    // to resolve the https records
    let curl_url: String = format!(
        "https://one.one.one.one/dns-query?name={}&type=https",
        domain
    );
    let mut curl = std::process::Command::new("curl")
        .arg("-s")
        .arg("-H")
        .arg("accept: application/dns-json")
        .arg(&curl_url)
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn curl process");

    let jq = std::process::Command::new("jq")
        .arg("-r")
        .arg(".Answer[0].data")
        .stdin(curl.stdout.take().expect("Failed to capture curl stdout"))
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn jq process");

    let output = jq.wait_with_output().expect("failed to wait for jq output");

    let curl_status = curl.wait().expect("failed to wait for curl");
    if !curl_status.success() {
        panic!("curl exited with non-zero status: {:?}", curl_status.code());
    }

    if !output.status.success() {
        panic!(
            "jq exited with non-zero status: {}",
            String::from_utf8_lossy(&output.stderr)
        )
    }

    let jq_stdout: String = String::from_utf8(output.stdout).expect("jq output is not valid UTF-8");

    let mut parts = jq_stdout
        .trim()
        .strip_prefix(r"\#")
        .expect("data does not start with expected  \"\\#\" prefix")
        .split_whitespace();

    // length byte is in decimal, remainder is in hex
    let length: usize = parts
        .next()
        .expect("data is missing length after \\# prefix")
        .parse::<usize>()
        .expect("data contains invalid decimal length");

    let data: Vec<u8> = parts
        .map(|hex_byte| u8::from_str_radix(hex_byte, 16).expect("invalid hex byte in data"))
        .collect();

    if length != data.len() {
        panic!(
            "Length byte indicates {} bytes of data, actual length is {}",
            length,
            data.len() - 1
        );
    }

    let _priority: u16 = u16::from_be_bytes(
        data.get(..2)
            .expect("data is missing SvcPriority")
            .try_into()
            .unwrap(),
    );

    let target_name: u8 = *data.get(2).expect("data is missing TargetName");
    if target_name != 0 {
        panic!("TargetName value is not self (0), got {target_name}");
    }

    let param_key: u16 = u16::from_be_bytes(
        data.get(3..5)
            .expect("data is missing SvcParamKey")
            .try_into()
            .unwrap(),
    );
    if param_key != 5 {
        panic!("SvcParamKey value is not ECH (5), got {param_key}");
    }

    let param_len: u16 = u16::from_be_bytes(
        data.get(5..7)
            .expect("data is missing SvcParamLength")
            .try_into()
            .unwrap(),
    );
    if usize::from(param_len) != data.len() - 7 {
        panic!(
            "SvcParamLength indicates {} bytes of ECH configuration, actual length is {}",
            param_len,
            data.len() - 7
        );
    }
    let ech_bytes: &[u8] = &data[7..];

    ECHConfigList::deser(ech_bytes).expect("Failed to deserialize ECHConfigList")
}

fn main() {
    stderrlog::new()
        .verbosity(4)
        .timestamp(stderrlog::Timestamp::Microsecond)
        .init()
        .unwrap();

    const SERVER_NAME: &str = "tls-ech.dev";

    let server_ipv4: Ipv4Addr = format!("{SERVER_NAME}:443")
        .to_socket_addrs()
        .expect("DNS resolution failed")
        .filter_map(|addr| {
            if let std::net::SocketAddr::V4(v4) = addr {
                Some(*v4.ip())
            } else {
                None
            }
        })
        .next()
        .expect("No IPv4 address found for the host");

    let ech_config_list: ECHConfigList = query_ech_config_with_curl(SERVER_NAME);

    log::debug!("ech_config_list={ech_config_list:?}");

    log::info!("Connecting to {SERVER_NAME} at {server_ipv4}...");
    let addr: SocketAddrV4 = SocketAddrV4::new(server_ipv4, 443);
    let tcp_stream: TcpStream = TcpStream::connect(addr).unwrap();

    log::info!("Handshaking");
    let mut tls_stream: TlsClientStream = TlsClientBuilder::new()
        // TODO: make it work with hello retry, e.g. without supported named groups
        .set_supported_named_groups(vec![NamedGroup::x25519])
        .set_server_name(SERVER_NAME)
        .expect("Server name invalid")
        .load_ca_bundle()
        .expect("Failed to load system CA bundle")
        .set_ech_config(ech_config_list)
        .expect("Failed to set ECH configuration")
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
