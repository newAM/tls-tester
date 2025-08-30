use std::{collections::VecDeque, io, net::TcpStream};

use crate::{
    AlertDescription, Psk,
    base::{TlsState, TlsStream},
    cipher_suite::CipherSuite,
    error::TlsError,
    handshake::{
        self, ClientHelloBuilder, HandshakeHeader, HandshakeType, NamedGroup, ServerHello,
        extension,
    },
    key_schedule::KeySchedule,
    parse,
    record::{self, ContentType},
    tls_version::TlsVersion,
};
use sha2::digest::crypto_common::{generic_array::GenericArray, typenum::U32};

#[derive(Debug, Clone)]
pub struct TlsClientBuilder {
    record_size_limit: u16,
    psks: Vec<Psk>,
}

impl Default for TlsClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsClientBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self {
            record_size_limit: extension::RecordSizeLimit::LIMIT_MAX,
            psks: Vec::new(),
        }
    }

    #[must_use]
    pub fn set_record_size_limit(mut self, record_size_limit: u16) -> Self {
        self.record_size_limit = record_size_limit;
        self
    }

    #[must_use]
    pub fn add_psk(mut self, identity: &[u8], key: [u8; 32]) -> Self {
        self.psks.push(Psk::new(identity.to_vec(), key));
        self
    }

    pub fn handshake(self, tcp_stream: TcpStream) -> Result<TlsClientStream, TlsError> {
        let base: TlsStream = TlsStream {
            stream: tcp_stream,
            key_schedule: KeySchedule::new_client(),
            state: TlsState::WaitServerHello,
            psks: self.psks,
            buf: VecDeque::new(),
            record_size_limit: self.record_size_limit,
        };

        let mut ret = TlsClientStream { base };

        ret.handshake()?;

        Ok(ret)
    }
}

pub struct TlsClientStream {
    base: TlsStream,
}

impl TlsClientStream {
    pub(crate) fn read_server_hello(&mut self) -> Result<ServerHello, TlsError> {
        let hs_hdr: HandshakeHeader = self.base.next_handshake_header()?;

        if hs_hdr.msg_type() != HandshakeType::ServerHello {
            log::error!(
                "Unexpected msg_type {:?} in state {:?}",
                hs_hdr.msg_type(),
                self.base.state
            );
            return Err(AlertDescription::UnexpectedMessage)?;
        }

        let data: Vec<u8> = self.base.next_handshake_data(hs_hdr)?;

        let server_hello: ServerHello = ServerHello::deser(&data)?;

        Ok(server_hello)
    }

    fn handle_server_hello(&mut self, server_hello: &ServerHello) -> Result<(), TlsError> {
        if server_hello.cipher_suite != CipherSuite::TLS_AES_128_GCM_SHA256 {
            log::error!(
                "ServerHello CipherSuite {:?} is not the expected CipherSuite TLS_AES_128_GCM_SHA256",
                server_hello.cipher_suite
            );
            return Err(AlertDescription::HandshakeFailure)?;
        }

        if server_hello.exts.supported_versions != u16::from(TlsVersion::V1_3) {
            log::error!(
                "ServerHello SupportedVersions 0x{:04X} is not TLS v1.3",
                server_hello.exts.supported_versions
            );
            return Err(AlertDescription::ProtocolVersion)?;
        }

        match server_hello.exts.key_share.group {
            Ok(NamedGroup::secp256r1) => {}
            Ok(ng) => {
                log::error!(
                    "ServerHello KeyShare named group {ng:?} is not the expected secp256r1"
                );
                return Err(AlertDescription::HandshakeFailure)?;
            }
            Err(v) => {
                log::error!(
                    "ServerHello KeyShare named group 0x{v:04X} is not the expected secp256r1"
                );
                return Err(AlertDescription::HandshakeFailure)?;
            }
        }

        let kex_len: usize = server_hello.exts.key_share.key_exchange.len();
        if kex_len != 65 {
            log::error!(
                "ServerHello KeyShare key_exchange length is {kex_len} expected 65 for secp256r1"
            );
            return Err(AlertDescription::DecodeError)?;
        }

        let key: p256::PublicKey = match p256::PublicKey::from_sec1_bytes(
            &server_hello.exts.key_share.key_exchange,
        ) {
            Ok(pk) => pk,
            Err(_) => {
                log::error!(
                    "ServerHello KeyShareEntry secp256r1 key_exchange data is not a valid SEC1 public key"
                );
                return Err(AlertDescription::DecodeError)?;
            }
        };

        self.base.key_schedule.set_public_key(key);
        self.base.key_schedule.initialize_handshake_secret();

        self.base.set_state(TlsState::WaitEncryptedExtensions);

        Ok(())
    }

    fn read_encrypted_extensions(&mut self) -> Result<(), TlsError> {
        let hs_hdr: HandshakeHeader = self.base.next_handshake_header()?;

        if hs_hdr.msg_type() != HandshakeType::EncryptedExtensions {
            log::error!(
                "Unexpected msg_type {:?} in state {:?}",
                hs_hdr.msg_type(),
                self.base.state
            );
            return Err(AlertDescription::UnexpectedMessage)?;
        }

        let data: Vec<u8> = self.base.next_handshake_data(hs_hdr)?;

        let (_, ee) = parse::vec16("EncryptedExtensions", &data, 0, 1)?;

        if !ee.is_empty() {
            log::error!("TODO: Client handling of server encrypted extensions unimplemented");
        }

        self.base.set_state(TlsState::WaitCertificate);

        Ok(())
    }

    fn read_certificate(&mut self) -> Result<(), TlsError> {
        let hs_hdr: HandshakeHeader = self.base.next_handshake_header()?;

        if hs_hdr.msg_type() != HandshakeType::Certificate {
            log::error!(
                "Unexpected msg_type {:?} in state {:?}",
                hs_hdr.msg_type(),
                self.base.state
            );
            return Err(AlertDescription::UnexpectedMessage)?;
        }

        let _data: Vec<u8> = self.base.next_handshake_data(hs_hdr)?;

        self.base.set_state(TlsState::WaitCertificateVerify);

        Ok(())
    }

    fn read_certificate_verify(&mut self) -> Result<(), TlsError> {
        let hs_hdr: HandshakeHeader = self.base.next_handshake_header()?;

        if hs_hdr.msg_type() != HandshakeType::CertificateVerify {
            log::error!(
                "Unexpected msg_type {:?} in state {:?}",
                hs_hdr.msg_type(),
                self.base.state
            );
            return Err(AlertDescription::UnexpectedMessage)?;
        }

        let _data: Vec<u8> = self.base.next_handshake_data(hs_hdr)?;

        self.base.set_state(TlsState::WaitServerFinished);

        Ok(())
    }

    // FIXME: this function name is misleading, it does more than just reading.
    fn read_server_finished(&mut self) -> Result<(), TlsError> {
        let transcript_hash = self.base.key_schedule.transcript_hash_bytes();

        let hs_hdr: HandshakeHeader = self.base.next_handshake_header()?;

        if hs_hdr.msg_type() != HandshakeType::Finished {
            log::error!(
                "Unexpected msg_type {:?} in state {:?}",
                hs_hdr.msg_type(),
                self.base.state
            );
            return Err(AlertDescription::UnexpectedMessage)?;
        }

        let data: Vec<u8> = self.base.next_handshake_data(hs_hdr)?;

        if !self.base.buf.is_empty() {
            log::error!("Server fragmented records across key changes");
            return Err(AlertDescription::DecodeError)?;
        }

        let data_len: usize = data.len();

        let data_finished: [u8; 32] = match data.try_into() {
            Ok(finished) => finished,
            Err(_) => {
                log::error!(
                    "Unexpected length for client finished, expected 32 B got {} B",
                    data_len
                );
                return Err(AlertDescription::DecodeError)?;
            }
        };

        if let Err(e) = self
            .base
            .key_schedule
            .verify_server_finished(&transcript_hash, &data_finished)
        {
            log::error!("server finished contents incorrect");
            Err(e)?
        } else {
            log::debug!("server finished contents correct");
            Ok(())
        }
    }

    fn send_client_finished(&mut self) -> Result<(), TlsError> {
        let verify_data: GenericArray<u8, U32> =
            self.base.key_schedule.client_finished_verify_data();
        let finished: Vec<u8> = handshake::finished_with_hs_hdr(&verify_data);

        self.base
            .write_encrypted_records(record::ContentType::Handshake, &finished)?;

        Ok(())
    }

    fn handshake(&mut self) -> Result<(), TlsError> {
        match self.handshake_alertable() {
            Err(TlsError::SendAlert(ad)) => self.base.send_fatal_alert(ad),
            x => x,
        }
    }

    fn handshake_alertable(&mut self) -> Result<(), TlsError> {
        let pub_key: [u8; 65] = self.base.key_schedule.new_secret_key();

        let ch_build: ClientHelloBuilder = ClientHelloBuilder::new();
        let data = ch_build.build(&pub_key);
        self.base
            .write_unencrypted_record(ContentType::Handshake, &data)?;

        if !self.base.buf.is_empty() {
            log::error!("Received fragmented records across key changes");
            return Err(AlertDescription::DecodeError)?;
        }

        self.base.key_schedule.random.replace(ch_build.random());
        self.base.key_schedule.initialize_early_secret();

        let server_hello: ServerHello = self.read_server_hello()?;
        self.handle_server_hello(&server_hello)?;

        if !self.base.buf.is_empty() {
            log::error!("Server fragmented record across key changes");
            return Err(AlertDescription::DecodeError)?;
        }

        self.read_encrypted_extensions()?;
        self.read_certificate()?;
        log::error!("TODO: Client handling of server certificate unimplemented");
        self.read_certificate_verify()?;
        log::error!("TODO: Client handling of server certificate verify unimplemented");

        self.read_server_finished()?;
        self.send_client_finished()?;

        self.base.key_schedule.initialize_master_secret();

        if !self.base.buf.is_empty() {
            log::error!("Server fragmented record across key changes");
            return Err(AlertDescription::DecodeError)?;
        }

        self.base.set_state(TlsState::Connected);

        Ok(())
    }
}

impl io::Write for TlsClientStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        assert_eq!(self.base.state, TlsState::Connected);

        self.base
            .write_encrypted_records(ContentType::ApplicationData, buf)
            .map_err(std::io::Error::other)?;

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.base.stream.flush()
    }
}

impl io::Read for TlsClientStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        assert_eq!(self.base.state, TlsState::Connected);

        while self.base.buf.is_empty() {
            self.base
                .read_next_record()
                .map_err(std::io::Error::other)?
        }

        let mut len: usize = 0;
        for byte in buf.iter_mut() {
            match self.base.buf.pop_front() {
                Some(b) => {
                    *byte = b;
                    len += 1;
                }
                None => return Ok(len),
            }
        }

        Ok(len)
    }
}
