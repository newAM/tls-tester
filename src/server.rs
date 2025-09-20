use std::{
    collections::VecDeque,
    fs,
    io::{self},
    net::TcpStream,
    path::PathBuf,
};

use crate::{
    Psk,
    alert::AlertDescription,
    base::{TlsState, TlsStream},
    cipher_suite::CipherSuite,
    error::TlsError,
    handshake::{
        self, CertificateVerify, ClientHello, HandshakeHeader, HandshakeType, KeyShareEntry,
        NamedGroup, ServerHelloBuilder,
        extension::{self, EncryptedExtensions},
    },
    key_schedule::KeySchedule,
    record::{self, ContentType},
};
use p256::pkcs8::DecodePrivateKey as _;
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

#[derive(Debug, Clone)]
pub struct ServerCertificates {
    public_der: Vec<u8>,
    signing_key: p256::ecdsa::SigningKey,
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

        // larger sizes are valid by TLS spec, u16 is an easier cutoff for now
        if u16::try_from(public_der.len()).is_err() {
            log::error!("Certificate length of {} is too long", public_der.len());
            return None;
        }

        Some(Self {
            public_der,
            signing_key,
        })
    }

    pub(crate) fn sign(&self, data: &[u8]) -> p256::ecdsa::Signature {
        // as far as I know the unwrap will never occur
        self.signing_key.sign_recoverable(data).unwrap().0
    }
}

#[derive(Debug, Clone)]
pub struct TlsServerBuilder {
    record_size_limit: u16,
    psks: Vec<Psk>,
    supported_named_groups: Vec<NamedGroup>,
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
        };
        let mut ret = TlsServerStream {
            base,
            certs,
            hello_retry_request: false,
        };

        ret.handshake()?;

        Ok(ret)
    }
}

pub struct TlsServerStream {
    base: TlsStream,
    certs: ServerCertificates,
    hello_retry_request: bool,
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

        let client_hello: ClientHello = ClientHello::deser(&data)?;

        Ok(client_hello)
    }

    fn handle_client_hello(
        &mut self,
        client_hello: &mut ClientHello,
    ) -> Result<(Option<[u8; 32]>, Option<u16>), TlsError> {
        // only needed for NSS key logging
        self.base.key_schedule.random.replace(client_hello.random);

        if !client_hello
            .cipher_suites
            .contains(&CipherSuite::TLS_AES_128_GCM_SHA256)
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
            return Ok((None, None));
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

        log::debug!("Selected named group {named_group:?}");

        let mut selected_identity: Option<u16> = None;
        let mut binder_key: Option<[u8; 32]> = None;

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
        }

        Ok((binder_key, selected_identity))
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

        let (mut binder_key, mut selected_identity): (Option<[u8; 32]>, Option<u16>) =
            self.handle_client_hello(&mut client_hello)?;

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

            let hello_retry_req: Vec<u8> = HandshakeHeader::prepend_header(
                HandshakeType::ServerHello,
                &ServerHelloBuilder::new_retry(
                    &client_hello.legacy_session_id_echo,
                    selected_identity,
                )
                .ser(),
            );
            self.base
                .write_unencrypted_record(record::ContentType::Handshake, &hello_retry_req)?;
            self.base.set_state(TlsState::WaitClientHelloRetry);

            client_hello = self.read_client_hello()?;
            (binder_key, selected_identity) = self.handle_client_hello(&mut client_hello)?;

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

        let server_hello: Vec<u8> = HandshakeHeader::prepend_header(
            HandshakeType::ServerHello,
            &ServerHelloBuilder::new(&client_hello.legacy_session_id_echo, key, selected_identity)
                .ser(),
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
                &CertificateVerify::from_ecdsa_secp256r1_sha256(&signature.to_der().to_bytes())
                    .ser(),
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
