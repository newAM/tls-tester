use rand::rngs::OsRng;
use std::{
    io::Read as _,
    net::TcpListener,
    str::from_utf8,
    thread::sleep,
    time::{Duration, Instant},
};
use tls_tester::{ServerCertificates, TlsServerBuilder, TlsServerStream};
use w5500_mqtt::{
    Event,
    hl::Hostname,
    ll::{
        Sn,
        net::{Ipv4Addr, SocketAddrV4},
    },
    tls::Client,
};
use w5500_regsim::W5500;

const HOSTNAME: Hostname = Hostname::new_unwrapped("localhost");
const HOST: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 12345);

const TLS_SN: Sn = Sn::Sn0;

fn monotonic_secs(start: Instant) -> u32 {
    Instant::now()
        .duration_since(start)
        .as_secs()
        .try_into()
        .unwrap()
}

#[test]
fn test_server_psk() {
    stderrlog::new()
        .verbosity(4)
        .timestamp(stderrlog::Timestamp::Nanosecond)
        .init()
        .unwrap();

    let start: Instant = Instant::now();

    let mut w5500: W5500 = W5500::default();
    w5500.set_socket_buffer_logging(false);

    const SPORT: u16 = 11234;

    let mut rxbuf: [u8; 1024] = [0; 1024];
    const PSK: [u8; 32] = [
        0x2f, 0x42, 0xac, 0xe2, 0xb6, 0xbe, 0x16, 0x81, 0xb3, 0xd2, 0xfc, 0xdd, 0x4b, 0xb5, 0x7b,
        0x4f, 0xfe, 0x34, 0x84, 0xee, 0x77, 0xfd, 0xaa, 0x8e, 0x21, 0x6e, 0x32, 0x72, 0xcd, 0x78,
        0x25, 0x9d,
    ];
    const PSK_ID: &[u8] = b"test";

    let certs: ServerCertificates = ServerCertificates::from_secpr256r1_pem("cert.pem", "key.pem")
        .expect("Invalid certificates");

    let listener: TcpListener = TcpListener::bind("127.0.0.1:12345").unwrap();

    std::thread::spawn(move || {
        let mut client: Client<1024> =
            Client::new(TLS_SN, SPORT, HOSTNAME, HOST, PSK_ID, &PSK, &mut rxbuf);

        loop {
            match client.process(&mut w5500, &mut OsRng, monotonic_secs(start)) {
                Ok(Event::CallAfter(_)) => (),
                Ok(Event::Publish(mut reader)) => {
                    let mut payload_buf: [u8; 128] = [0; 128];
                    let payload_len: u16 = reader
                        .read_payload(&mut payload_buf)
                        .expect("failed to read payload");
                    let mut topic_buf: [u8; 128] = [0; 128];
                    let topic_len: u16 = reader
                        .read_topic(&mut topic_buf)
                        .expect("failed to read payload");

                    match (
                        from_utf8(&topic_buf[..topic_len.into()]),
                        from_utf8(&payload_buf[..payload_len.into()]),
                    ) {
                        (Ok(topic), Ok(payload)) => log::info!("{topic} {payload}"),
                        _ => log::info!("payload and topic are not valid UTF-8"),
                    }

                    reader.done().unwrap();
                }
                // This does not handle failures
                Ok(Event::SubAck(ack)) => log::info!("{ack:?}"),
                // should never occur - we never unsubscribe
                Ok(Event::UnSubAck(ack)) => log::warn!("{ack:?}"),
                Ok(Event::ConnAck) => {
                    client
                        .subscribe(&mut w5500, "#")
                        .expect("failed to send SUBSCRIBE");
                }
                Ok(Event::None) => sleep(Duration::from_millis(10)),
                Err(e) => panic!("Error occured: {e:?}"),
            }
        }
    });

    log::info!("Accepting connections");
    let (client, addr) = listener.accept().expect("Unable to accept connections");
    log::info!("Accepted connection from {addr}");
    let mut tls_stream: TlsServerStream = TlsServerBuilder::new()
        .add_psk(PSK_ID, PSK)
        .handshake(client, certs)
        .expect("Failed to create TLS stream");
    let mut mqtt_buf: [u8; 4096] = [0; 4096];
    let read_len: usize = tls_stream
        .read(&mut mqtt_buf)
        .expect("Failed to read from TLS stream");
    let mqtt_pkt: &[u8] = &mqtt_buf[..read_len];
    log::info!("mqtt_pkt={}", String::from_utf8_lossy(mqtt_pkt));
}
