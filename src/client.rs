use std::{fs, io, net::TcpStream};

use crate::{
    AlertDescription, ECHConfigList, Psk,
    base::{self, TlsState, TlsStream},
    cipher_suite::CipherSuite,
    crypto::hpke::{AeadId, KdfId},
    decode::DecodeContext,
    error::TlsError,
    handshake::{
        self, Certificate, CertificateEntry, CertificateVerify, ClientHello, ClientHelloBuilder,
        HandshakeHeader, HandshakeType, KeyShareEntry, NamedGroup, ServerHello,
        ech::{ECHConfig, HpkeSymmetricCipherSuite},
        extension::{self, EncryptedExtensions, ServerName, signature_scheme::SignatureScheme},
    },
    key_schedule::KeySchedule,
    record::{self, ContentType},
    tls_version::TlsVersion,
};
use crypto_bigint::CtEq;
use sha2::{
    Digest as _,
    digest::{array::Array, typenum::U32},
};

#[derive(Debug, Clone)]
pub struct TlsClientBuilder {
    record_size_limit: u16,
    psk: Option<Psk>,
    server_name: Option<ServerName>,
    trusted_roots: Vec<crate::x509::Certificate>,
    ignore_unknown_ca: bool,
    supported_named_groups: Vec<NamedGroup>,
    supported_signature_algorithms: Vec<SignatureScheme>,
    ech: Option<ECHConfig>,
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
            psk: None,
            server_name: None,
            trusted_roots: Vec::new(),
            ignore_unknown_ca: false,
            supported_named_groups: NamedGroup::default_groups(),
            supported_signature_algorithms: SignatureScheme::default_signature_algorithms(),
            ech: None,
        }
    }

    #[must_use]
    pub fn set_supported_named_groups(mut self, named_groups: Vec<NamedGroup>) -> Self {
        assert!(
            !named_groups.is_empty(),
            "At least one group must be supported"
        );
        self.supported_named_groups = named_groups;
        self
    }

    #[must_use]
    pub fn set_ech_config(mut self, config: ECHConfigList) -> Option<Self> {
        const SUPPORTED_CIPHER_SUITE: HpkeSymmetricCipherSuite = HpkeSymmetricCipherSuite {
            kdf_id: KdfId::HkdfSha256,
            aead_id: AeadId::Aes128Gcm,
        };

        match config.list.iter().find(|p| {
            p.contents
                .key_config
                .cipher_suites
                .contains(&SUPPORTED_CIPHER_SUITE)
        }) {
            Some(config) => {
                self.ech = Some(config.clone());
                Some(self)
            }
            None => {
                log::error!(
                    "ECH configuration list does not contain a supported cipher suite, supported cipher suite: {SUPPORTED_CIPHER_SUITE:?}"
                );
                None
            }
        }
    }

    #[must_use]
    pub fn set_supported_signature_algorithms(
        mut self,
        signature_algorithms: Vec<SignatureScheme>,
    ) -> Self {
        assert!(
            !signature_algorithms.is_empty(),
            "At least one signature algorithm must be supported"
        );
        self.supported_signature_algorithms = signature_algorithms;
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

    // need to test multiple PSK handling if offering multiple
    #[must_use]
    pub fn set_psk(mut self, identity: &[u8], key: [u8; 32]) -> Self {
        self.psk.replace(Psk::new(identity.to_vec(), key));
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

            let mut ctx = DecodeContext::new("Certificate", cert.contents().to_vec());
            let parsed_cert = match crate::x509::Certificate::decode(&mut ctx, true) {
                Ok((_, c)) => c,
                Err(_) => {
                    log::error!("Failed to parse x509 certificate");
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
        let psks: Vec<Psk> = if let Some(psk) = self.psk {
            vec![psk]
        } else {
            Vec::new()
        };
        let base: TlsStream = TlsStream {
            stream: tcp_stream,
            key_schedule: KeySchedule::new_client(),
            state: TlsState::WaitServerHello,
            psks,
            buf: Vec::new(),
            buf_pos: 0,
            record_size_limit: self.record_size_limit,
            supported_named_groups: self.supported_named_groups,
            supported_signature_algorithms: self.supported_signature_algorithms,
        };

        let mut ret = TlsClientStream {
            base,
            server_name: self.server_name,
            trusted_roots: self.trusted_roots,
            ignore_unknown_ca: self.ignore_unknown_ca,
            ech: self.ech,
            inner_random: [0; 32],
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
    ech: Option<ECHConfig>,
    inner_random: [u8; 32],
}

impl TlsClientStream {
    pub(crate) fn read_server_hello(
        &mut self,
        mut transcript_hash_ech: sha2::Sha256,
    ) -> Result<(Vec<u8>, ServerHello, Vec<u8>), TlsError> {
        let mut ctx: DecodeContext = self.base.next_handshake("ServerHello")?;
        let hs_hdr: HandshakeHeader = HandshakeHeader::decode(&mut ctx)?;

        if hs_hdr.msg_type() != HandshakeType::ServerHello {
            log::error!(
                "Unexpected msg_type {:?} in state {:?}",
                hs_hdr.msg_type(),
                self.base.state
            );
            return Err(AlertDescription::UnexpectedMessage)?;
        }

        let server_hello: ServerHello = ServerHello::decode(&mut ctx)?;

        // handshake header: 4 bytes
        // tls version: 2 bytes
        // random: 32 bytes
        const RANDOM_LAST_8_BYTES_IDX: usize = 4 + 2 + 32 - 8;

        let mut data_transcript_hash_ech = ctx.original_buffer().to_vec();
        data_transcript_hash_ech[RANDOM_LAST_8_BYTES_IDX..RANDOM_LAST_8_BYTES_IDX + 8].fill(0);

        transcript_hash_ech.update(&data_transcript_hash_ech);
        let transcript_ech_conf: Vec<u8> = transcript_hash_ech.finalize().to_vec();

        Ok((
            ctx.original_buffer().to_vec(),
            server_hello,
            transcript_ech_conf,
        ))
    }

    fn handle_server_hello(
        &mut self,
        hash_client_hello1: &[u8],
        server_hello_data: &[u8],
        server_hello: &mut ServerHello,
        transcript_ech_conf: Option<&[u8]>,
    ) -> Result<Option<Psk>, TlsError> {
        // Check ECH acceptance if configured
        if let (Some(_ech), Some(transcript)) = (&self.ech, transcript_ech_conf) {
            let accept_confirmation: [u8; 8] =
                base::compute_accept_confirmation(&self.inner_random, transcript);

            let server_hello_random: [u8; 8] = server_hello.random[24..].try_into().unwrap();

            if server_hello_random.ct_eq(&accept_confirmation).to_u8() == 1 {
                log::info!("ECH accepted");
            } else {
                todo!(
                    "ECH was rejected expected {:02x?} got {:02x?}",
                    accept_confirmation,
                    server_hello_random
                );
            }
        }

        let key_share_entry: KeyShareEntry = match &server_hello.exts.key_share {
            extension::KeyShareServerHello::KeyShareServerHello(key_share_entry) => {
                key_share_entry.clone()
            }
            extension::KeyShareServerHello::KeyShareHelloRetryRequest(named_group) => {
                // When the server responds to a ClientHello with a HelloRetryRequest,
                // the value of ClientHello1 is replaced with a special synthetic handshake
                // message of handshake type "message_hash" containing Hash(ClientHello1).
                let mut new_transcript_hash: sha2::Sha256 = sha2::Sha256::new();
                new_transcript_hash.update(HandshakeHeader::prepend_header(
                    HandshakeType::MessageHash,
                    hash_client_hello1,
                ));
                new_transcript_hash.update(server_hello_data);
                self.base
                    .key_schedule
                    .set_transcript_hash(new_transcript_hash);

                let pub_key: KeyShareEntry =
                    self.base.key_schedule.new_secret_key_client(*named_group);

                let ch_build: ClientHelloBuilder = ClientHelloBuilder::new()
                    .set_psks(self.base.psks.clone())
                    .set_server_name(self.server_name.clone());
                let (data, _inner_data) = ch_build.build(
                    &self.base.supported_named_groups,
                    &self.base.supported_signature_algorithms,
                    pub_key,
                    &mut self.base.key_schedule,
                );
                self.base
                    .write_unencrypted_record(ContentType::Handshake, &data)?;

                let transcript_hash_ech = sha2::Sha256::new();
                let (_, server_hello, _) = self.read_server_hello(transcript_hash_ech)?;

                match &server_hello.exts.key_share {
                    extension::KeyShareServerHello::KeyShareServerHello(key_share_entry) => {
                        key_share_entry.clone()
                    }
                    extension::KeyShareServerHello::KeyShareHelloRetryRequest(ng) => {
                        log::error!(
                            "ServerHello is a second retry request with named group {ng:?}"
                        );
                        return Err(AlertDescription::HandshakeFailure)?;
                    }
                }
            }
        };

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

        match key_share_entry.named_group() {
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

        let psk: Option<Psk> = if let Some(selected_identity) =
            server_hello.exts.psk_selected_identity
        {
            if let Some(selected_psk) = self.base.psks.get(usize::from(selected_identity)) {
                log::debug!("Server selected {selected_psk:?}");
                Some(selected_psk.clone())
            } else {
                log::error!(
                    "ServerHello.extensions.pre_shared_key of 0x{selected_identity:04x} is not in range of offered keys"
                );
                return Err(AlertDescription::UnknownPskIdentity)?;
            }
        } else {
            None
        };

        self.base.key_schedule.set_public_key(key_share_entry);
        self.base.key_schedule.initialize_handshake_secret();

        self.base.set_state(TlsState::WaitEncryptedExtensions);

        Ok(psk)
    }

    fn read_encrypted_extensions(&mut self) -> Result<(), TlsError> {
        let mut ctx: DecodeContext = self.base.next_handshake("EncryptedExtensions")?;
        let hs_hdr: HandshakeHeader = HandshakeHeader::decode(&mut ctx)?;

        if hs_hdr.msg_type() != HandshakeType::EncryptedExtensions {
            log::error!(
                "Unexpected msg_type {:?} in state {:?}",
                hs_hdr.msg_type(),
                self.base.state
            );
            return Err(AlertDescription::UnexpectedMessage)?;
        }

        let encrypted_extensions: EncryptedExtensions = EncryptedExtensions::decode(&mut ctx)?;

        log::error!(
            "TODO: Client handling of server encrypted extensions unimplemented {encrypted_extensions:?}"
        );

        Ok(())
    }

    fn read_certificate(&mut self) -> Result<Certificate, TlsError> {
        let mut ctx: DecodeContext = self.base.next_handshake("EncryptedExtensions")?;
        let hs_hdr: HandshakeHeader = HandshakeHeader::decode(&mut ctx)?;

        if hs_hdr.msg_type() != HandshakeType::Certificate {
            log::error!(
                "Unexpected msg_type {:?} in state {:?}",
                hs_hdr.msg_type(),
                self.base.state
            );
            return Err(AlertDescription::UnexpectedMessage)?;
        }

        self.base.set_state(TlsState::WaitCertificateVerify);

        Ok(Certificate::decode(&mut ctx)?)
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
        let mut ctx: DecodeContext = self.base.next_handshake("CertificateVerify")?;
        let hs_hdr: HandshakeHeader = HandshakeHeader::decode(&mut ctx)?;

        if hs_hdr.msg_type() != HandshakeType::CertificateVerify {
            log::error!(
                "Unexpected msg_type {:?} in state {:?}",
                hs_hdr.msg_type(),
                self.base.state
            );
            return Err(AlertDescription::UnexpectedMessage)?;
        }

        self.base.set_state(TlsState::WaitServerFinished);

        Ok(CertificateVerify::decode(&mut ctx)?)
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

        if !self
            .base
            .supported_signature_algorithms
            .contains(&verify.algorithm)
        {
            log::error!(
                "Server sent a certificate verify algorithm {:?} which is unsupported by the client, client supports {:?}",
                verify.algorithm,
                self.base.supported_signature_algorithms,
            );
            Err(AlertDescription::InternalError)?
        }

        match verify.algorithm {
            SignatureScheme::ecdsa_secp256r1_sha256 | SignatureScheme::rsa_pss_rsae_sha256 => {
                end_entity_certificate
                    .data
                    .tbs_certificate
                    .subject_public_key_info
                    .subject_public_key
                    .verify::<sha2::Sha256>(&to_verify, &verify.signature)?;
            }
            _ => unimplemented!(),
        }

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

        if !self.base.buf_is_empty() {
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
        let verify_data: Array<u8, U32> = self.base.key_schedule.client_finished_verify_data();
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

        let ch_build: ClientHelloBuilder = ClientHelloBuilder::new()
            .set_psks(self.base.psks.clone())
            .set_ech_config(self.ech.clone())
            .set_server_name(self.server_name.clone());

        self.inner_random = ch_build.inner_random;

        let (ch_data, inner_data): (Vec<u8>, Vec<u8>) = ch_build.build(
            &self.base.supported_named_groups,
            &self.base.supported_signature_algorithms,
            pub_key,
            &mut self.base.key_schedule,
        );

        self.base
            .write_unencrypted_record(ContentType::Handshake, &ch_data)?;

        let hash_client_hello1 = self.base.key_schedule.transcript_hash_bytes();

        self.base.key_schedule.random.replace(ch_build.random());
        self.base.key_schedule.initialize_early_secret();

        // Handle ECH transcript if configured
        let mut transcript_hash_ech: sha2::Sha256 = sha2::Sha256::new();
        if !inner_data.is_empty() {
            // TODO: this is very hacky to decode the ClientHello I constructed
            let mut ctx_outer = DecodeContext::new("ClientHelloOuter", ch_data[4..].to_vec());
            let client_hello_outer: ClientHello =
                ClientHello::decode(&mut ctx_outer, None).expect("TODO");
            let mut ctx_inner = DecodeContext::new("ClientHelloInner", inner_data.clone());
            let client_hello_inner: ClientHello =
                ClientHello::decode(&mut ctx_inner, Some(&client_hello_outer)).expect("TODO");

            let transcript_hash_ech_data: Vec<u8> =
                client_hello_outer.ech_transcript_data(&client_hello_inner);
            transcript_hash_ech.update(&transcript_hash_ech_data);

            self.base
                .key_schedule
                .set_transcript_hash(transcript_hash_ech.clone());
        }

        let psk: Option<Psk> = {
            let (server_hello_data, mut server_hello, transcript_ech_conf): (
                Vec<u8>,
                ServerHello,
                Vec<u8>,
            ) = self.read_server_hello(transcript_hash_ech)?;
            self.handle_server_hello(
                &hash_client_hello1,
                &server_hello_data,
                &mut server_hello,
                if !inner_data.is_empty() {
                    Some(&transcript_ech_conf)
                } else {
                    None
                },
            )?
        };

        if !self.base.buf_is_empty() {
            log::error!("Server fragmented record across key changes");
            return Err(AlertDescription::DecodeError)?;
        }

        self.read_encrypted_extensions()?;

        if psk.is_some() {
            self.base.set_state(TlsState::WaitServerFinished)
        } else {
            self.base.set_state(TlsState::WaitCertificate);
            let certificate: Certificate = self.read_certificate()?;
            self.handle_certificate(&certificate)?;

            let tsh = self.base.key_schedule.transcript_hash().finalize();
            let certificate_verify: CertificateVerify = self.read_certificate_verify()?;
            self.handle_certificate_verify(&certificate, &certificate_verify, &tsh)?;
        }

        self.read_server_finished()?;
        self.send_client_finished()?;

        self.base.key_schedule.initialize_master_secret();

        if !self.base.buf_is_empty() {
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

        while self.base.buf_is_empty() {
            self.base
                .read_next_record()
                .map_err(std::io::Error::other)?
        }

        let mut len: usize = 0;
        for byte in buf.iter_mut() {
            match self.base.pop_front_byte() {
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
