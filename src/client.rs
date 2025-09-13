use std::{collections::VecDeque, io, net::TcpStream};

use crate::{
    AlertDescription, Psk,
    base::{TlsState, TlsStream},
    cipher_suite::CipherSuite,
    error::TlsError,
    handshake::{
        self, Certificate, CertificateEntry, CertificateVerify, ClientHelloBuilder,
        HandshakeHeader, HandshakeType, NamedGroup, ServerHello,
        extension::{self, ServerName, signature_scheme::SignatureScheme},
    },
    key_schedule::KeySchedule,
    parse,
    record::{self, ContentType},
    tls_version::TlsVersion,
};
use sha2::{
    Digest as _,
    digest::crypto_common::{generic_array::GenericArray, typenum::U32},
};

#[derive(Debug, Clone)]
pub struct TlsClientBuilder {
    record_size_limit: u16,
    psks: Vec<Psk>,
    server_name: Option<ServerName>,
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
            server_name: None,
        }
    }

    #[must_use]
    pub fn set_server_name(mut self, name: &str) -> Option<Self> {
        self.server_name = Some(ServerName::from_str(name)?);
        Some(self)
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

        let mut ret = TlsClientStream {
            base,
            server_name: self.server_name,
        };

        ret.handshake()?;

        Ok(ret)
    }
}

pub struct TlsClientStream {
    base: TlsStream,
    pub(crate) server_name: Option<ServerName>,
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

    fn read_certificate(&mut self) -> Result<Certificate, TlsError> {
        let hs_hdr: HandshakeHeader = self.base.next_handshake_header()?;

        if hs_hdr.msg_type() != HandshakeType::Certificate {
            log::error!(
                "Unexpected msg_type {:?} in state {:?}",
                hs_hdr.msg_type(),
                self.base.state
            );
            return Err(AlertDescription::UnexpectedMessage)?;
        }

        let data: Vec<u8> = self.base.next_handshake_data(hs_hdr)?;

        self.base.set_state(TlsState::WaitCertificateVerify);

        Ok(Certificate::deser(&data)?)
    }

    fn handle_certificate(&mut self, certificate: &Certificate) -> Result<(), TlsError> {
        log::error!("TODO: Client does not validate certificate chain against trust anchors");

        let mut prev_entry: Option<&CertificateEntry> = None;
        for (n, entry) in certificate.certificate_list.iter().enumerate() {
            if prev_entry.is_none() {
                if let Some(name) = &self.server_name {
                    entry.data.validate(Some(name.name.as_str()))?;
                } else {
                    log::warn!("Ignoring certificate name validation")
                }
            } else {
                entry.data.validate(None)?;
            }

            if let Some(prev_entry) = &prev_entry {
                log::debug!(
                    "Verifying entry {} Certificate.signature of Certificate.tbsCertificate with entry {} Certificate.tbsCertificate.subjectPublicKeyInfo",
                    n.checked_sub(1).unwrap(),
                    n
                );
                entry.data.verify_previous(
                    &prev_entry.tbs_certificate,
                    &prev_entry.data.signature_algorithm,
                    &prev_entry.data.signature_value.bitstring,
                )?;
            }

            prev_entry = Some(entry);

            if !entry.extensions.is_empty() {
                log::error!("TODO: Client handling of certificate entensions unimplemented");
            }
        }

        Ok(())
    }

    fn read_certificate_verify(&mut self) -> Result<CertificateVerify, TlsError> {
        let hs_hdr: HandshakeHeader = self.base.next_handshake_header()?;

        if hs_hdr.msg_type() != HandshakeType::CertificateVerify {
            log::error!(
                "Unexpected msg_type {:?} in state {:?}",
                hs_hdr.msg_type(),
                self.base.state
            );
            return Err(AlertDescription::UnexpectedMessage)?;
        }

        let data: Vec<u8> = self.base.next_handshake_data(hs_hdr)?;

        self.base.set_state(TlsState::WaitServerFinished);

        Ok(CertificateVerify::deser(&data)?)
    }

    fn handle_certificate_verify(
        &mut self,
        certificate: &Certificate,
        verify: &CertificateVerify,
        tsh: &[u8],
    ) -> Result<(), TlsError> {
        // The signature is represented as a DER-encoded X690 ECDSA-Sig-Value structure.
        //
        // The digital signature is then computed over the concatenation of:
        // -  A string that consists of octet 32 (0x20) repeated 64 times
        // -  The context string ("TLS 1.3, server CertificateVerify" or "TLS 1.3, client CertificateVerify")
        // -  A single 0 byte which serves as the separator
        // -  The content to be signed (transcript hash)
        let mut to_verify: Vec<u8> = vec![0x20; 64];
        to_verify.extend_from_slice(b"TLS 1.3, server CertificateVerify\x00");
        to_verify.extend_from_slice(tsh);

        // end entity certificate is always the first
        // https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.2
        let end_entity_certificate: &CertificateEntry = match certificate.certificate_list.first() {
            Some(end_entity_cert) => end_entity_cert,
            None => {
                log::error!("Certificate.certificate_list is empty");
                return Err(AlertDescription::DecodeError)?;
            }
        };

        if verify.algorithm != SignatureScheme::ecdsa_secp256r1_sha256 {
            // TODO: implement required signature algorithms
            log::error!(
                "Client does not implement server's signature scheme: {:?}",
                verify.algorithm
            );
            Err(AlertDescription::InternalError)?
        }

        end_entity_certificate
            .data
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .verify::<sha2::Sha256>(&to_verify, &verify.signature)?;

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

        let ch_build: ClientHelloBuilder =
            ClientHelloBuilder::new().set_server_name(self.server_name.clone());
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
        let certificate: Certificate = self.read_certificate()?;
        self.handle_certificate(&certificate)?;

        let tsh = self.base.key_schedule.transcript_hash().finalize();
        let certificate_verify: CertificateVerify = self.read_certificate_verify()?;
        self.handle_certificate_verify(&certificate, &certificate_verify, &tsh)?;

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
