use std::{
    collections::VecDeque,
    fs,
    io::{self},
    net::TcpStream,
    path::PathBuf,
};

use crate::{
    ECHConfigList, Psk,
    alert::AlertDescription,
    base::{TlsState, TlsStream},
    cipher_suite::CipherSuite,
    crypto::hpke::{self, Context, setup_base_r},
    error::TlsError,
    handshake::{
        self, CertificateVerify, ClientHello, HandshakeHeader, HandshakeType, KeyShareEntry,
        NamedGroup, ServerHelloBuilder,
        ech::ECHClientHello,
        extension::{self, EncryptedExtensions, signature_scheme::SignatureScheme},
    },
    key_schedule::KeySchedule,
    record::{self, ContentType},
};
use p256::pkcs8::DecodePrivateKey as _;
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use sha2::Digest as _;

fn pem_to_der(pem: &str) -> Option<Vec<u8>> {
    let parsed = match pem::parse(pem) {
        Ok(p) => p,
        Err(e) => {
            log::error!("Failed to parse public key: {e}");
            return None;
        }
    };

    if parsed.tag() != "CERTIFICATE" {
        log::error!("Invalid PEM tag, expected CERTIFICATE got {}", parsed.tag());
        return None;
    }

    Some(parsed.into_contents())
}

// Used for the CertificateVerify
#[derive(Debug, Clone)]
#[allow(non_camel_case_types)]
pub(crate) enum ServerCertificateSigningKey {
    rsa_pss_rsae_sha256(rsa::pss::BlindedSigningKey<sha2::Sha256>),
    ecdsa_secp256r1_sha256(p256::ecdsa::SigningKey),
}

#[derive(Debug, Clone)]
pub struct ServerCertificates {
    public_der: Vec<u8>,
    signing_key: ServerCertificateSigningKey,
}

impl ServerCertificates {
    pub fn from_secpr256r1_pem<P: Into<PathBuf>>(public: P, private: P) -> Option<Self> {
        let public: String = match fs::read_to_string(public.into()) {
            Ok(p) => p,
            Err(e) => {
                log::error!("Failed to read public key into string: {e}");
                return None;
            }
        };
        let private: String = match fs::read_to_string(private.into()) {
            Ok(p) => p,
            Err(e) => {
                log::error!("Failed to read private key into string: {e}");
                return None;
            }
        };

        let secret_key: p256::SecretKey = match p256::SecretKey::from_pkcs8_pem(&private) {
            Ok(key) => key,
            Err(_) => {
                log::error!("Private key is not a valid secpr256r1 in pkcs8 pem format");
                return None;
            }
        };
        let signing_key: p256::ecdsa::SigningKey = p256::ecdsa::SigningKey::from(secret_key);

        let public_der: Vec<u8> = pem_to_der(&public)?;

        // TODO: larger sizes are valid by TLS spec, u16 is an easier cutoff for now
        if u16::try_from(public_der.len()).is_err() {
            log::error!("Certificate length of {} is too long", public_der.len());
            return None;
        }

        Some(Self {
            public_der,
            signing_key: ServerCertificateSigningKey::ecdsa_secp256r1_sha256(signing_key),
        })
    }

    pub fn from_rsa_pss_rsae_sha256<P: Into<PathBuf>>(public: P, private: P) -> Option<Self> {
        let public: String = match fs::read_to_string(public.into()) {
            Ok(p) => p,
            Err(e) => {
                log::error!("Failed to read public key into string: {e}");
                return None;
            }
        };
        let private: String = match fs::read_to_string(private.into()) {
            Ok(p) => p,
            Err(e) => {
                log::error!("Failed to read private key into string: {e}");
                return None;
            }
        };

        let secret_key: rsa::pss::BlindedSigningKey<sha2::Sha256> =
            match rsa::pkcs8::DecodePrivateKey::from_pkcs8_pem(&private) {
                Ok(key) => key,
                Err(e) => {
                    log::error!("Private key is not a valid rsa in pkcs1 pem format: {e}");
                    return None;
                }
            };
        // let signing_key: rsa::pss::BlindedSigningKey<sha2::Sha256> =
        //     rsa::pss::BlindedSigningKey::<sha2::Sha256>::new(secret_key);

        let public_der: Vec<u8> = pem_to_der(&public)?;

        // TODO: larger sizes are valid by TLS spec, u16 is an easier cutoff for now
        if u16::try_from(public_der.len()).is_err() {
            log::error!("Certificate length of {} is too long", public_der.len());
            return None;
        }

        Some(Self {
            public_der,
            signing_key: ServerCertificateSigningKey::rsa_pss_rsae_sha256(secret_key),
        })
    }

    pub(crate) fn sign(&self, data: &[u8]) -> Vec<u8> {
        match &self.signing_key {
            ServerCertificateSigningKey::rsa_pss_rsae_sha256(signing_key) => signing_key
                .sign_with_rng(&mut rand::rngs::ThreadRng::default(), data)
                .to_vec(),
            ServerCertificateSigningKey::ecdsa_secp256r1_sha256(signing_key) => signing_key
                .sign_recoverable(data)
                .unwrap()
                .0
                .to_der()
                .to_vec(),
        }
    }
}

#[derive(Clone)]
pub struct TlsServerBuilder {
    record_size_limit: u16,
    psks: Vec<Psk>,
    supported_named_groups: Vec<NamedGroup>,
    ech: Option<(crate::crypto::x25519::StaticSecret, ECHConfigList)>,
    supported_signature_algorithms: Vec<SignatureScheme>,
}

impl Default for TlsServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsServerBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self {
            record_size_limit: extension::RecordSizeLimit::LIMIT_MAX,
            psks: Vec::new(),
            supported_named_groups: NamedGroup::default_groups(),
            ech: None,
            supported_signature_algorithms: SignatureScheme::default_signature_algorithms(),
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
    pub fn set_ech_config(
        mut self,
        ech_secret: crate::crypto::x25519::StaticSecret,
        config: ECHConfigList,
    ) -> Self {
        self.ech = Some((ech_secret, config));
        self
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
    pub fn set_record_size_limit(mut self, record_size_limit: u16) -> Self {
        self.record_size_limit = record_size_limit;
        self
    }

    #[must_use]
    pub fn add_psk(mut self, identity: &[u8], key: [u8; 32]) -> Self {
        self.psks.push(Psk::new(identity.to_vec(), key));
        self
    }

    pub fn handshake(
        self,
        tcp_stream: TcpStream,
        certs: ServerCertificates,
    ) -> Result<TlsServerStream, TlsError> {
        let base: TlsStream = TlsStream {
            stream: tcp_stream,
            key_schedule: KeySchedule::new_server(),
            state: TlsState::WaitClientHello,
            psks: self.psks,
            buf: VecDeque::new(),
            record_size_limit: self.record_size_limit,
            supported_named_groups: self.supported_named_groups,
            supported_signature_algorithms: self.supported_signature_algorithms,
        };
        let mut ret = TlsServerStream {
            base,
            certs,
            hello_retry_request: false,
            ech: self.ech,
        };

        ret.handshake()?;

        Ok(ret)
    }
}

pub struct TlsServerStream {
    base: TlsStream,
    certs: ServerCertificates,
    hello_retry_request: bool,
    ech: Option<(crate::crypto::x25519::StaticSecret, ECHConfigList)>,
}

impl TlsServerStream {
    /// Returns `true` if a hello retry request has been sent
    #[must_use]
    pub fn hello_retry_request(&self) -> bool {
        self.hello_retry_request
    }

    fn read_client_hello(&mut self) -> Result<ClientHello, TlsError> {
        let hs_hdr: HandshakeHeader = self.base.next_handshake_header()?;

        if hs_hdr.msg_type() != HandshakeType::ClientHello {
            log::error!(
                "Unexpected msg_type {:?} in state {:?}",
                hs_hdr.msg_type(),
                self.base.state
            );
            return Err(AlertDescription::UnexpectedMessage)?;
        }

        let data: Vec<u8> = self.base.next_handshake_data(hs_hdr)?;

        if !self.base.buf.is_empty() {
            log::error!("Received fragmented records across key changes");
            return Err(AlertDescription::DecodeError)?;
        }

        let client_hello: ClientHello = ClientHello::deser(&data, None)?;

        Ok(client_hello)
    }

    #[allow(clippy::type_complexity)]
    fn handle_client_hello(
        &mut self,
        client_hello: &mut ClientHello,
    ) -> Result<
        (
            Option<[u8; 32]>,
            Option<u16>,
            Option<[u8; 32]>,
            sha2::Sha256,
            Option<SignatureScheme>,
        ),
        TlsError,
    > {
        // only needed for NSS key logging
        // TODO: should this use inner with ECH?
        self.base.key_schedule.random.replace(client_hello.random);

        let mut transcript_hash_ech: sha2::Sha256 = self.base.key_schedule.transcript_hash();

        // TODO: below options need to happen after ECH resolution

        if !client_hello
            .cipher_suites
            .contains(&Ok(CipherSuite::TLS_AES_128_GCM_SHA256))
        {
            log::error!("ClientHello does not contain required CipherSuite TLS_AES_128_GCM_SHA256");
            return Err(AlertDescription::HandshakeFailure)?;
        }

        if !client_hello.exts.supported_versions.supports_tlsv1_3() {
            log::error!("ClientHello SupportedVersions does not contain TLS v1.3");
            return Err(AlertDescription::ProtocolVersion)?;
        }

        // https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8
        // Clients MAY send an empty client_shares vector in order to request
        // group selection from the server, at the cost of an additional round
        // trip.
        if client_hello.exts.supported_groups.is_empty() {
            log::info!("ClientHello has an empty client_shares vector");
            // this is a hack, removing the client shares will force a hello retry
            client_hello.exts.key_share.client_shares = vec![];
            return Ok((None, None, None, transcript_hash_ech, None));
        }

        let named_group: NamedGroup = match client_hello
            .exts
            .supported_groups
            .iter()
            .find(|&group| self.base.supported_named_groups.contains(group))
        {
            Some(ng) => *ng,
            None => {
                log::error!(
                    "ClientHello SupportedGroups {:?} does not contain any group supported by the server {:?}",
                    client_hello.exts.supported_groups,
                    self.base.supported_named_groups,
                );
                return Err(AlertDescription::HandshakeFailure)?;
            }
        };

        let mut client_hello_inner_random: Option<[u8; 32]> = None;

        if let Some((client_ech, _, _)) = &client_hello.exts.encrypted_client_hello {
            match client_ech {
                ECHClientHello::Inner => {
                    log::error!("ClientHello ECH extension is type inner for outer extension");
                    return Err(AlertDescription::IllegalParameter)?;
                }
                ECHClientHello::Outer(inner) => {
                    if inner.cipher_suite.kdf_id != hpke::KdfId::HkdfSha256 {
                        todo!("Handle unsupported KDF");
                    }
                    if inner.cipher_suite.aead_id != hpke::AeadId::Aes128Gcm {
                        todo!("Handle unsupported AEAD");
                    }
                    if let Some((skr, config)) = &self.ech {
                        let ech_config = config.find_id(inner.config_id).expect("TODO");

                        let enc: [u8; 32] = inner.enc.clone().try_into().expect("TODO");
                        let enc: crate::crypto::x25519::PublicKey =
                            crate::crypto::x25519::PublicKey::from(enc);

                        let mut info: Vec<u8> = Vec::new();
                        info.extend_from_slice(b"tls ech");
                        info.push(0);
                        info.extend_from_slice(&ech_config.ser());

                        let mut context: Context = setup_base_r(&enc, skr, &info);

                        let payload_decrypted: Vec<u8> = context
                            .open(client_hello.ech_aad(), &inner.payload)
                            .expect("TODO: handle tag mismatch");

                        log::info!("ECH tag ok");

                        let inner_client_hello: ClientHello =
                            ClientHello::deser(&payload_decrypted, Some(client_hello))?;

                        log::warn!("TODO: ignoring client hello inner: {inner_client_hello:02x?}");

                        client_hello_inner_random.replace(inner_client_hello.random);

                        // the transcript hash for ECH acceptance a munge of the inner and outer CH
                        // https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-25#section-5.1

                        let transcript_hash_ech_data =
                            client_hello.ech_transcript_data(&inner_client_hello);
                        transcript_hash_ech = sha2::Sha256::new();
                        transcript_hash_ech.update(&transcript_hash_ech_data);

                        // let mut transcript_hash: sha2::Sha256 = sha2::Sha256::new();
                        // transcript_hash.update(payload_decrypted);
                        // self.base.key_schedule.set_transcript_hash(transcript_hash);
                    } else {
                        todo!("Client requested ECH, but server has no ECH configuration");
                    }
                }
            }
        }

        log::debug!("Selected named group {named_group:?}");

        let mut selected_identity: Option<u16> = None;
        let mut binder_key: Option<[u8; 32]> = None;
        let mut signature_algorithm: Option<SignatureScheme> = None;

        if let Some(client_psks) = client_hello.exts.pre_shared_key.as_ref() {
            for (client_psk_idx, client_psk) in client_psks.identities.iter().enumerate() {
                if let Some(server_psk) = self
                    .base
                    .psks
                    .iter()
                    .find(|server_psk| server_psk.identity == client_psk.identity)
                {
                    binder_key.replace(server_psk.key);
                    selected_identity.replace(client_psk_idx.try_into().unwrap());
                }
            }

            if selected_identity.is_none() || binder_key.is_none() {
                log::error!("Received PSK with unknown identity");
                return Err(AlertDescription::UnknownPskIdentity)?;
            }
        } else {
            // validated to exist in ClientHelloExtensions::deser
            let signature_algorithms = client_hello.exts.signature_algorithms.as_ref().unwrap();

            // Find the first algorithm that the client lists that is also supported by the server
            if let Some(&chosen) = signature_algorithms.iter().find(|&&client_alg| {
                self.base
                    .supported_signature_algorithms
                    .contains(&client_alg)
            }) {
                signature_algorithm.replace(chosen);
                log::debug!("Selected signature algorithm {signature_algorithm:?}");
            } else {
                log::error!(
                    "Client does not have any signature algorithms that the server supports, client supports {:?}, server supports {:?}",
                    signature_algorithms,
                    self.base.supported_signature_algorithms
                );
                return Err(AlertDescription::HandshakeFailure)?;
            }
        }

        Ok((
            binder_key,
            selected_identity,
            client_hello_inner_random,
            transcript_hash_ech,
            signature_algorithm,
        ))
    }

    // FIXME: this function name is misleading, it does more than just reading.
    fn read_client_finished(&mut self) -> Result<(), TlsError> {
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
            log::error!("Received fragmented records across key changes");
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
            .verify_client_finished(&data_finished)
        {
            log::error!("client finished contents incorrect");
            Err(e)?
        } else {
            log::debug!("client finished contents correct");
            Ok(())
        }
    }

    fn handshake(&mut self) -> Result<(), TlsError> {
        match self.handshake_alertable() {
            Err(TlsError::SendAlert(ad)) => self.base.send_fatal_alert(ad),
            x => x,
        }
    }

    fn handshake_alertable(&mut self) -> Result<(), TlsError> {
        let mut client_hello: ClientHello = self.read_client_hello()?;

        #[allow(clippy::type_complexity)]
        let (
            mut binder_key,
            mut selected_identity,
            mut client_hello_inner_random,
            mut transcript_hash_ech,
            mut signature_scheme,
        ): (
            Option<[u8; 32]>,
            Option<u16>,
            Option<[u8; 32]>,
            sha2::Sha256,
            Option<SignatureScheme>,
        ) = self.handle_client_hello(&mut client_hello)?;

        self.base
            .key_schedule
            .set_transcript_hash(transcript_hash_ech.clone());

        let key_share: Option<KeyShareEntry> = client_hello
            .exts
            .key_share
            .client_shares
            .iter()
            .find(|&kse| {
                self.base
                    .supported_named_groups
                    .iter()
                    .any(|&ng| Ok(ng) == kse.named_group())
            })
            .cloned();

        if let Some(entry) = key_share {
            self.base.key_schedule.set_public_key(entry.clone());
        } else {
            // https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.1
            // If the server selects an (EC)DHE group and the client did not offer a
            // compatible "key_share" extension in the initial ClientHello, the
            // server MUST respond with a HelloRetryRequest (Section 4.1.4) message.

            self.hello_retry_request = true;

            // When the server responds to a ClientHello with a HelloRetryRequest,
            // the value of ClientHello1 is replaced with a special synthetic handshake
            // message of handshake type "message_hash" containing Hash(ClientHello1).
            let hash_client_hello1 = self.base.key_schedule.transcript_hash_bytes();
            let mut new_transcript_hash: sha2::Sha256 = sha2::Sha256::new();
            new_transcript_hash.update(HandshakeHeader::prepend_header(
                HandshakeType::MessageHash,
                &hash_client_hello1,
            ));
            self.base
                .key_schedule
                .set_transcript_hash(new_transcript_hash);

            log::error!("TODO: handle ECH transcript hash on retry");

            let hello_retry_req: Vec<u8> = HandshakeHeader::prepend_header(
                HandshakeType::ServerHello,
                &ServerHelloBuilder::new_retry(&client_hello.legacy_session_id, selected_identity)
                    .ser(&mut sha2::Sha256::new()),
            );
            self.base
                .write_unencrypted_record(record::ContentType::Handshake, &hello_retry_req)?;
            self.base.set_state(TlsState::WaitClientHelloRetry);

            client_hello = self.read_client_hello()?;
            (
                binder_key,
                selected_identity,
                client_hello_inner_random,
                transcript_hash_ech,
                signature_scheme,
            ) = self.handle_client_hello(&mut client_hello)?;

            let key_share: Option<KeyShareEntry> = client_hello
                .exts
                .key_share
                .client_shares
                .iter()
                .find(|&kse| {
                    self.base
                        .supported_named_groups
                        .iter()
                        .any(|&ng| Ok(ng) == kse.named_group())
                })
                .cloned();

            if let Some(kse) = key_share {
                self.base.key_schedule.set_public_key(kse);
            } else {
                log::error!("Client failed to negotiate key share with server");
                return Err(AlertDescription::InsufficientSecurity)?;
            }
        }

        self.base.key_schedule.binder_key(binder_key.as_ref());

        self.base.key_schedule.initialize_early_secret();

        if !self.base.buf.is_empty() {
            log::error!("Client fragmented record across key changes");
            return Err(AlertDescription::DecodeError)?;
        }

        let key: KeyShareEntry = self.base.key_schedule.new_secret_key_server();

        let mut server_hello_builder: ServerHelloBuilder =
            ServerHelloBuilder::new(&client_hello.legacy_session_id, key, selected_identity);

        if let Some(random) = client_hello_inner_random {
            server_hello_builder = server_hello_builder.accept_ech(&random);
        }

        let server_hello: Vec<u8> = HandshakeHeader::prepend_header(
            HandshakeType::ServerHello,
            &server_hello_builder.ser(&mut transcript_hash_ech),
        );

        self.base
            .write_unencrypted_record(record::ContentType::Handshake, &server_hello)?;

        self.base.key_schedule.initialize_handshake_secret();

        if !self.base.buf.is_empty() {
            log::error!("Client fragmented record across key changes");
            return Err(AlertDescription::DecodeError)?;
        }

        {
            let encrypted_extensions: Vec<u8> = HandshakeHeader::prepend_header(
                HandshakeType::EncryptedExtensions,
                &EncryptedExtensions::default().ser(),
            );

            self.base
                .write_encrypted_records(record::ContentType::Handshake, &encrypted_extensions)?;
        }

        if selected_identity.is_none() {
            let certificate: Vec<u8> = HandshakeHeader::prepend_header(
                HandshakeType::Certificate,
                &handshake::certificate_from_der(&self.certs.public_der)?,
            );

            self.base
                .write_encrypted_records(record::ContentType::Handshake, &certificate)?;

            let tsh = self.base.key_schedule.transcript_hash().finalize();

            // The signature is represented as a DER-encoded X690 ECDSA-Sig-Value structure.
            //
            // The digital signature is then computed over the concatenation of:
            // -  A string that consists of octet 32 (0x20) repeated 64 times
            // -  The context string ("TLS 1.3, server CertificateVerify" or "TLS 1.3, client CertificateVerify")
            // -  A single 0 byte which serves as the separator
            // -  The content to be signed (transcript hash)
            let mut to_sign: Vec<u8> = vec![0x20; 64];
            to_sign.extend_from_slice(b"TLS 1.3, server CertificateVerify\x00");
            to_sign.extend_from_slice(&tsh);

            let signature = self.certs.sign(&to_sign);

            let certificate_verify: Vec<u8> = HandshakeHeader::prepend_header(
                HandshakeType::CertificateVerify,
                &CertificateVerify::new(signature_scheme.unwrap(), &signature).ser(),
            );

            self.base
                .write_encrypted_records(record::ContentType::Handshake, &certificate_verify)?;
        }

        let verify_data = self.base.key_schedule.server_finished_verify_data();
        let finished: Vec<u8> = handshake::finished_with_hs_hdr(&verify_data);

        self.base
            .write_encrypted_records(record::ContentType::Handshake, &finished)?;

        self.base.set_state(TlsState::WaitClientFinished);

        self.read_client_finished()?;

        self.base.key_schedule.initialize_master_secret();

        if !self.base.buf.is_empty() {
            log::error!("Client fragmented record across key changes");
            return Err(AlertDescription::DecodeError)?;
        }

        self.base.set_state(TlsState::Connected);

        Ok(())
    }
}

impl std::io::Read for TlsServerStream {
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

impl std::io::Write for TlsServerStream {
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
