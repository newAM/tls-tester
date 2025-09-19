use std::{collections::VecDeque, fs, io, net::TcpStream};

use crate::{
    AlertDescription, Psk,
    base::{TlsState, TlsStream},
    cipher_suite::CipherSuite,
    error::TlsError,
    handshake::{
        self, Certificate, CertificateEntry, CertificateVerify, ClientHelloBuilder,
        HandshakeHeader, HandshakeType, KeyShareEntry, NamedGroup, ServerHello,
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
    trusted_roots: Vec<crate::x509::Certificate>,
    ignore_unknown_ca: bool,
    supported_named_groups: Vec<NamedGroup>,
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
            trusted_roots: Vec::new(),
            ignore_unknown_ca: false,
            supported_named_groups: NamedGroup::default_groups(),
        }
    }

    #[must_use]
    pub fn set_supported_name_groups(mut self, named_groups: Vec<NamedGroup>) -> Self {
        assert!(
            !named_groups.is_empty(),
            "At least one group must be supported"
        );
        self.supported_named_groups = named_groups;
        self
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

    #[must_use]
    pub fn load_ca_bundle(mut self) -> Option<Self> {
        let ca_certificates: Vec<u8> = match fs::read("/etc/ssl/certs/ca-certificates.crt") {
            Ok(cac) => cac,
            Err(e) => {
                log::error!("Failed to read certificates from system: {e:?}");
                return None;
            }
        };

        let certs = match pem::parse_many(&ca_certificates) {
            Ok(c) => c,
            Err(e) => {
                log::error!("Failed to parse system certificates: {e:?}");
                return None;
            }
        };

        let mut n: usize = 0;

        for cert in certs {
            if cert.tag() != "CERTIFICATE" && cert.tag() != "TRUSTED CERTIFICATE" {
                log::error!(
                    "Invalid PEM tag, expected CERTIFICATE or TRUSTED CERTIFICATE got {}",
                    cert.tag()
                );
                return None;
            }

            n = n.saturating_add(1);

            let parsed_cert = match crate::x509::Certificate::deser(cert.contents(), true) {
                Some((_, c)) => c,
                None => {
                    log::error!("Failed to parse this shit");
                    continue;
                }
            };

            self.trusted_roots.push(parsed_cert);
        }

        Some(self)
    }

    #[must_use]
    pub fn ignore_unknown_ca(mut self, ignore_unknown_ca: bool) -> Self {
        self.ignore_unknown_ca = ignore_unknown_ca;
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
            supported_named_groups: self.supported_named_groups,
        };

        let mut ret = TlsClientStream {
            base,
            server_name: self.server_name,
            trusted_roots: self.trusted_roots,
            ignore_unknown_ca: self.ignore_unknown_ca,
        };

        ret.handshake()?;

        Ok(ret)
    }
}

pub struct TlsClientStream {
    base: TlsStream,
    pub(crate) server_name: Option<ServerName>,
    pub(crate) trusted_roots: Vec<crate::x509::Certificate>,
    ignore_unknown_ca: bool,
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

        match server_hello.exts.key_share.named_group() {
            Ok(NamedGroup::secp256r1) | Ok(NamedGroup::x25519) => {}
            Ok(ng) => {
                log::error!("ServerHello KeyShare named group {ng:?} is not supported");
                return Err(AlertDescription::HandshakeFailure)?;
            }
            Err(v) => {
                log::error!("ServerHello KeyShare named group 0x{v:04X} is unrecognized");
                return Err(AlertDescription::HandshakeFailure)?;
            }
        }

        self.base
            .key_schedule
            .set_public_key(server_hello.exts.key_share.clone());
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

        if let Some(prev_entry) = &prev_entry {
            log::debug!("Verifying last certificate entry with system trust anchors");

            let prev_entry_issuer: String =
                match prev_entry.data.tbs_certificate.issuer.common_name() {
                    Some(cn) => cn,
                    None => {
                        log::error!("Last certificate in chain does not have an issuer");
                        return Err(AlertDescription::BadCertificate)?;
                    }
                };

            let mut validated: bool = false;

            for root in &self.trusted_roots {
                if root.tbs_certificate.issuer.common_name() == Some(prev_entry_issuer.clone()) {
                    root.verify_previous(
                        &prev_entry.tbs_certificate,
                        &prev_entry.data.signature_algorithm,
                        &prev_entry.data.signature_value.bitstring,
                    )?;
                    validated = true;
                    break;
                }
            }

            if !validated && !self.ignore_unknown_ca {
                log::error!(
                    "Failed to find certificate for issuer {prev_entry_issuer} in system trust anchors"
                );
                return Err(AlertDescription::UnknownCa)?;
            }
        } else {
            log::error!("Server did not provide certificates in Certificate handshake message");
            return Err(AlertDescription::BadCertificate)?;
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
        let pub_key: KeyShareEntry = self
            .base
            .key_schedule
            .new_secret_key_client(*self.base.supported_named_groups.first().unwrap());

        let ch_build: ClientHelloBuilder =
            ClientHelloBuilder::new().set_server_name(self.server_name.clone());
        let data = ch_build.build(&self.base.supported_named_groups, pub_key);
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
