#![allow(dead_code)]

mod alert;
mod cipher_suite;
mod error;
mod handshake;
mod key_schedule;
pub(crate) mod parse;
mod record;
mod tls_version;

use std::{
    cmp::{max, min},
    collections::VecDeque,
    fs,
    io::{self, Read as _, Write},
    net::TcpStream,
    path::PathBuf,
};

use aes_gcm::aead::consts::{U12, U16};
use aes_gcm::{Aes128Gcm, KeyInit as _, aead::AeadMutInPlace};
pub use alert::{Alert, AlertDescription, AlertLevel};
use cipher_suite::CipherSuite;
pub use error::ServerError;
use handshake::{
    CertificateVerify, ClientHello, HandshakeHeader, HandshakeType, NamedGroup, ServerHello,
    extension::{self, EncryptedExtensions},
};
use key_schedule::KeySchedule;
use p256::pkcs8::DecodePrivateKey as _;
use record::{ContentType, RecordHeader};
use sha2::digest::crypto_common::{generic_array::GenericArray, typenum::U32};
use sha2::{Digest as _, Sha256};
pub use tls_version::TlsVersion;

const GCM_TAG_LEN: usize = 16;

/// Internal TLS server states.
// https://datatracker.ietf.org/doc/html/rfc8446#appendix-A.1
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ServerState {
    /// Wait for a ClientHello.
    WaitClientHello,
    /// Wait for a second ClientHello in response to HelloRetryRequest
    WaitClientHelloRetry,
    /// Wait for client Finished.
    WaitFinished,
    /// TLS handshake has completed.
    Connected,
    /// Fatal alert sent.
    SentAlert,
    /// Fatal alert received.
    RecvAlert,
}

fn pem_to_der(pem: &str) -> Option<Vec<u8>> {
    let parsed = match pem::parse(pem) {
        Ok(p) => p,
        Err(e) => {
            log::error!("Failed to parse public key: {e}");
            return None;
        }
    };

    if parsed.tag() != "CERTIFICATE" {
        log::error!("Invalid PEM tag, expected CERTIFICATE");
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
pub struct Psk {
    identity: Vec<u8>,
    key: [u8; 32],
}

impl Psk {
    pub fn new(identity: Vec<u8>, key: [u8; 32]) -> Self {
        Self { identity, key }
    }
}

#[derive(Debug, Clone)]
pub struct TlsStreamBuilder {
    record_size_limit: u16,
    psks: Vec<Psk>,
}

impl Default for TlsStreamBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsStreamBuilder {
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

    pub fn handshake(
        self,
        tcp_stream: TcpStream,
        certs: ServerCertificates,
    ) -> Result<TlsStream, ServerError> {
        let mut ret = TlsStream {
            client: tcp_stream,
            key_schedule: KeySchedule::default(),
            state: ServerState::WaitClientHello,
            certs,
            psks: self.psks,
            buf: VecDeque::new(),
            record_size_limit: self.record_size_limit,
        };

        ret.handshake()?;

        Ok(ret)
    }
}

pub struct TlsStream {
    client: std::net::TcpStream,
    key_schedule: KeySchedule,
    state: ServerState,
    certs: ServerCertificates,
    psks: Vec<Psk>,
    buf: VecDeque<u8>,
    record_size_limit: u16,
}

impl TlsStream {
    fn set_state(&mut self, state: ServerState) {
        log::debug!("{:?} -> {:?}", self.state, state);
        self.state = state;
    }

    fn next_record_header(&mut self) -> Result<RecordHeader, ServerError> {
        let mut hdr_buf: [u8; RecordHeader::LEN] = [0; RecordHeader::LEN];
        self.client.read_exact(&mut hdr_buf)?;
        let hdr: RecordHeader = RecordHeader::deser(hdr_buf)?;
        log::debug!("< {hdr:?}");
        Ok(hdr)
    }

    fn pop_front_fixed<const N: usize>(&mut self) -> Option<[u8; N]> {
        if self.buf.len() >= N {
            let mut buf: [u8; N] = [0; N];
            for byte in buf.iter_mut() {
                // unwrap will not occur, we checked length
                *byte = self.buf.pop_front().unwrap()
            }
            Some(buf)
        } else {
            None
        }
    }

    fn pop_front(&mut self, n: usize) -> Option<Vec<u8>> {
        if self.buf.len() >= n {
            let mut buf: Vec<u8> = Vec::with_capacity(n);
            for _ in 0..n {
                // unwrap will never occur due to initial length check
                buf.push(self.buf.pop_front().unwrap())
            }
            Some(buf)
        } else {
            None
        }
    }

    fn next_handshake_header(&mut self) -> Result<HandshakeHeader, ServerError> {
        loop {
            if let Some(buf) = self.pop_front_fixed() {
                let hs_hdr: HandshakeHeader = HandshakeHeader::deser(buf)?;
                log::debug!("< {hs_hdr:?}");
                return Ok(hs_hdr);
            };
            self.read_next_record()?;
        }
    }

    fn next_handshake_data(&mut self, header: HandshakeHeader) -> Result<Vec<u8>, ServerError> {
        let hdr_len: usize =
            usize::try_from(header.length()).expect("Unsupported target architecture");

        loop {
            if let Some(buf) = self.pop_front(hdr_len) {
                return Ok(buf);
            };
            self.read_next_record()?;
        }
    }

    fn read_next_record(&mut self) -> Result<(), ServerError> {
        let rec_hdr: RecordHeader = self.next_record_header()?;

        match rec_hdr.content_type() {
            ContentType::ChangeCipherSpec => {
                // not used in TLS 1.3

                if rec_hdr.length() != 1 {
                    log::error!(
                        "Record length of {} doesn't match expected of 1 for ChangeCipherSpec",
                        rec_hdr.length()
                    );
                    return Err(AlertDescription::DecodeError)?;
                }
                let mut change_cipher_spec: [u8; 1] = [0];
                self.client.read_exact(&mut change_cipher_spec)?;
            }
            ContentType::Alert => {
                // Alert messages MUST NOT be fragmented across records
                if rec_hdr.length() != 2 {
                    log::error!(
                        "Client sent alert record with size {} expected 2",
                        rec_hdr.length()
                    );
                    return Err(AlertDescription::DecodeError)?;
                }
                let mut alert_buf: [u8; 2] = [0; 2];
                self.client.read_exact(&mut alert_buf)?;

                let alert: Alert = Alert::from_be_bytes(alert_buf)?;

                log::error!("< {alert:?}");

                self.set_state(ServerState::RecvAlert);

                return Err(ServerError::RecvAlert(alert.description));
            }
            ContentType::Handshake => {
                if !matches!(
                    self.state,
                    ServerState::WaitClientHello | ServerState::WaitClientHelloRetry
                ) {
                    // https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2
                    // Because TLS 1.3 forbids renegotiation, if a server has negotiated
                    // TLS 1.3 and receives a ClientHello at any other time, it MUST
                    // terminate the connection with an "unexpected_message" alert.
                    log::error!("Unexpected unencrypted handshake in state {:?}", self.state);
                    return Err(AlertDescription::UnexpectedMessage)?;
                }

                if rec_hdr.length() == 0 {
                    log::error!("Client sent zero-length Handshake fragment");
                    return Err(AlertDescription::UnexpectedMessage)?;
                }

                let orig_len: usize = self.buf.len();
                self.buf.resize(orig_len + usize::from(rec_hdr.length()), 0);

                let read_buf: &mut [u8] = &mut self.buf.make_contiguous()[orig_len..];
                self.client.read_exact(read_buf)?;

                self.key_schedule.update_transcript_hash(read_buf);
                self.key_schedule.increment_read_record_sequence_number();
            }
            ContentType::ApplicationData => {
                // + 1 is for content type
                if usize::from(rec_hdr.length()) < GCM_TAG_LEN + 1 {
                    log::error!(
                        "Client sent encrypted record with length {} which is too short to contain an AES-GCM tag",
                        rec_hdr.length()
                    );
                    return Err(AlertDescription::UnexpectedMessage)?;
                }

                let mut buf: Vec<u8> = vec![0; rec_hdr.length().into()];
                self.client.read_exact(&mut buf)?;

                let (key, nonce): ([u8; 16], [u8; 12]) =
                    self.key_schedule.client_key_and_nonce().unwrap();
                let nonce: aes_gcm::Nonce<U12> = aes_gcm::Nonce::clone_from_slice(&nonce);
                let key: aes_gcm::Key<Aes128Gcm> =
                    aes_gcm::Key::<Aes128Gcm>::clone_from_slice(&key);

                // unwrap will not occur due to initial length checks
                let tag: Vec<u8> = buf.split_off(buf.len().checked_sub(GCM_TAG_LEN).unwrap());
                let tag: [u8; GCM_TAG_LEN] = tag.try_into().unwrap();
                let tag: aes_gcm::Tag<U16> = tag.into();

                let mut cipher = Aes128Gcm::new(&key);
                if cipher
                    .decrypt_in_place_detached(&nonce, rec_hdr.as_bytes(), &mut buf, &tag)
                    .is_err()
                {
                    log::error!("Tag mismatch during record decryption");
                    return Err(AlertDescription::BadRecordMac)?;
                }

                // unwrap will not occur due to initial length checks
                let content_type_byte: u8 = buf.pop().unwrap();
                let real_content_type: ContentType = match ContentType::try_from(content_type_byte)
                {
                    Ok(content_type) => content_type,
                    Err(val) => {
                        log::error!(
                            "Client sent invalid ContentType value 0x{val:02X} in encrypted record"
                        );
                        return Err(AlertDescription::DecodeError)?;
                    }
                };

                log::debug!("< {real_content_type:?}");

                match real_content_type {
                    ContentType::ChangeCipherSpec => {
                        log::error!("Client sent encrypted ChangeCipherSpec");
                        return Err(AlertDescription::UnexpectedMessage)?;
                    }
                    ContentType::Alert => {
                        // Alert messages MUST NOT be fragmented across records
                        let buf_len: usize = buf.len();
                        let buf_fixed: [u8; 2] = match buf.try_into() {
                            Ok(b) => b,
                            Err(_) => {
                                log::error!(
                                    "Client sent alert record with size {} expected 2",
                                    buf_len
                                );
                                return Err(AlertDescription::DecodeError)?;
                            }
                        };

                        let alert: Alert = Alert::from_be_bytes(buf_fixed)?;

                        log::error!("< {alert:?}");

                        self.set_state(ServerState::RecvAlert);

                        return Err(ServerError::RecvAlert(alert.description));
                    }
                    ContentType::Handshake => {
                        if self.state != ServerState::WaitFinished {
                            self.key_schedule.update_transcript_hash(&buf);
                        }
                        self.key_schedule.increment_read_record_sequence_number();
                        self.buf.extend(buf);
                    }
                    ContentType::ApplicationData => {
                        self.key_schedule.update_transcript_hash(&buf);
                        self.key_schedule.increment_read_record_sequence_number();
                        self.buf.extend(buf);
                    }
                }
            }
        };

        Ok(())
    }

    fn write_unencrypted_record(
        &mut self,
        content_type: ContentType,
        mut data: &[u8],
    ) -> Result<(), ServerError> {
        let record_size_limit: u16 = max(1, max(content_type.min_length(), self.record_size_limit));

        let num_records: usize = data.len().div_ceil(record_size_limit.into());

        for _ in 0..num_records {
            let record_data_len_no_overhead: u16 =
                min(record_size_limit, data.len().try_into().unwrap_or(u16::MAX));

            let (record_data, remain) = data.split_at(record_data_len_no_overhead.into());
            data = remain;

            let hdr: RecordHeader = RecordHeader::ser(content_type, record_data.len())?;

            log::debug!("> {hdr:?}");

            self.client.write_all(hdr.as_bytes())?;
            self.client.write_all(record_data)?;

            self.key_schedule.update_transcript_hash(record_data);
            self.key_schedule.increment_write_record_sequence_number();
        }

        Ok(())
    }

    fn write_encrypted_records(
        &mut self,
        content_type: ContentType,
        mut data: &[u8],
    ) -> Result<(), ServerError> {
        const CONTENT_TYPE_LEN: u16 = 1;

        let record_size_limit_no_overhead: u16 = max(
            1,
            max(
                content_type.min_length(),
                self.record_size_limit
                    .saturating_sub(GCM_TAG_LEN as u16)
                    .saturating_sub(CONTENT_TYPE_LEN),
            ),
        );

        let num_records: usize = data.len().div_ceil(record_size_limit_no_overhead.into());

        for _ in 0..num_records {
            let record_data_len_no_overhead: u16 = min(
                record_size_limit_no_overhead,
                data.len().try_into().unwrap_or(u16::MAX),
            );

            let (record_data, remain) = data.split_at(record_data_len_no_overhead.into());

            data = remain;

            let mut record_data: Vec<u8> = record_data.to_vec();

            let record_data_len: u16 =
                record_data_len_no_overhead + GCM_TAG_LEN as u16 + CONTENT_TYPE_LEN;

            let hdr: RecordHeader =
                RecordHeader::ser(ContentType::ApplicationData, record_data_len.into())?;

            let (key, nonce): ([u8; 16], [u8; 12]) =
                self.key_schedule.server_key_and_nonce().unwrap();
            let nonce: aes_gcm::Nonce<U12> = aes_gcm::Nonce::clone_from_slice(&nonce);
            let key: aes_gcm::Key<Aes128Gcm> = aes_gcm::Key::<Aes128Gcm>::clone_from_slice(&key);

            self.key_schedule.update_transcript_hash(&record_data);

            record_data.push(content_type as u8);

            let mut cipher = Aes128Gcm::new(&key);
            let tag: aes_gcm::Tag<U16> =
                match cipher.encrypt_in_place_detached(&nonce, hdr.as_bytes(), &mut record_data) {
                    Ok(tag) => tag,
                    Err(_) => {
                        log::error!("Failed to encrypt record");
                        return Err(AlertDescription::InternalError)?;
                    }
                };

            log::debug!("> {hdr:?}");

            self.client.write_all(hdr.as_bytes())?;
            self.client.write_all(&record_data)?;
            self.client.write_all(tag.as_slice())?;

            self.key_schedule.increment_write_record_sequence_number();
        }

        Ok(())
    }

    fn read_client_hello(&mut self) -> Result<ClientHello, ServerError> {
        let hs_hdr: HandshakeHeader = self.next_handshake_header()?;

        if hs_hdr.msg_type() != HandshakeType::ClientHello {
            log::error!(
                "Unexpected msg_type {:?} in state {:?}",
                hs_hdr.msg_type(),
                self.state
            );
            return Err(AlertDescription::UnexpectedMessage)?;
        }

        let data: Vec<u8> = self.next_handshake_data(hs_hdr)?;

        if !self.buf.is_empty() {
            log::error!("Client fragmented records across key changes");
            return Err(AlertDescription::DecodeError)?;
        }

        let client_hello: ClientHello = ClientHello::deser(&data)?;

        Ok(client_hello)
    }

    fn handle_client_hello(
        &mut self,
        client_hello: &mut ClientHello,
    ) -> Result<(Option<[u8; 32]>, Option<u16>), ServerError> {
        // only needed for NSS key logging
        self.key_schedule.client_random.replace(client_hello.random);

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
            // this is a hack, removing the secp256r1 key will force a hello retry
            client_hello.exts.key_share.secp256r1 = None;
            return Ok((None, None));
        }

        if !client_hello
            .exts
            .supported_groups
            .contains(&NamedGroup::secp256r1)
        {
            log::error!("ClientHello SupportedGroups does not contain secp256r1");
            return Err(AlertDescription::HandshakeFailure)?;
        }

        let mut selected_identity: Option<u16> = None;
        let mut binder_key: Option<[u8; 32]> = None;

        if let Some(client_psks) = client_hello.exts.pre_shared_key.as_ref() {
            for (client_psk_idx, client_psk) in client_psks.identities.iter().enumerate() {
                if let Some(server_psk) = self
                    .psks
                    .iter()
                    .find(|server_psk| server_psk.identity == client_psk.identity)
                {
                    binder_key.replace(server_psk.key);
                    selected_identity.replace(client_psk_idx.try_into().unwrap());
                }
            }

            if selected_identity.is_none() || binder_key.is_none() {
                log::error!("Client sent PSK with unknown identity");
                return Err(AlertDescription::UnknownPskIdentity)?;
            }
        }

        Ok((binder_key, selected_identity))
    }

    fn read_client_finished(&mut self) -> Result<(), ServerError> {
        let hs_hdr: HandshakeHeader = self.next_handshake_header()?;

        if hs_hdr.msg_type() != HandshakeType::Finished {
            log::error!(
                "Unexpected msg_type {:?} in state {:?}",
                hs_hdr.msg_type(),
                self.state
            );
            return Err(AlertDescription::UnexpectedMessage)?;
        }

        let data: Vec<u8> = self.next_handshake_data(hs_hdr)?;

        if !self.buf.is_empty() {
            log::error!("Client fragmented records across key changes");
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

        self.key_schedule.verify_client_finished(&data_finished)?;

        Ok(())
    }

    fn handshake(&mut self) -> Result<(), ServerError> {
        match self.handshake_alertable() {
            Err(ServerError::SendAlert(ad)) => {
                log::error!("> {ad:?}");
                if matches!(
                    self.state,
                    ServerState::WaitClientHello | ServerState::WaitClientHelloRetry
                ) {
                    if let Err(e) = self.write_unencrypted_record(
                        ContentType::Alert,
                        &Alert::new_fatal(ad).to_be_bytes(),
                    ) {
                        log::error!("Failed to send alert: {e}")
                    }
                } else if let Err(e) = self.write_encrypted_records(
                    ContentType::Alert,
                    &Alert::new_fatal(ad).to_be_bytes(),
                ) {
                    log::error!("Failed to send alert: {e}")
                }

                Err(ServerError::SendAlert(ad))
            }
            x => x,
        }
    }

    fn handshake_alertable(&mut self) -> Result<(), ServerError> {
        let mut client_hello: ClientHello = self.read_client_hello()?;

        let (mut binder_key, mut selected_identity): (Option<[u8; 32]>, Option<u16>) =
            self.handle_client_hello(&mut client_hello)?;

        if let Some(client_pub_secp256r1_key) = client_hello.exts.key_share.secp256r1 {
            self.key_schedule
                .set_client_public_key(client_pub_secp256r1_key);
        } else {
            // https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.1
            // If the server selects an (EC)DHE group and the client did not offer a
            // compatible "key_share" extension in the initial ClientHello, the
            // server MUST respond with a HelloRetryRequest (Section 4.1.4) message.

            // When the server responds to a ClientHello with a HelloRetryRequest,
            // the value of ClientHello1 is replaced with a special synthetic handshake
            // message of handshake type "message_hash" containing Hash(ClientHello1).
            let hash_client_hello1 = self.key_schedule.transcript_hash_bytes();
            let mut new_transcript_hash: Sha256 = Sha256::new();
            new_transcript_hash.update(HandshakeHeader::prepend_header(
                HandshakeType::MessageHash,
                &hash_client_hello1,
            ));
            self.key_schedule.set_transcript_hash(new_transcript_hash);

            let hello_retry_req: Vec<u8> = HandshakeHeader::prepend_header(
                HandshakeType::ServerHello,
                &ServerHello::new_retry(&client_hello.legacy_session_id_echo, selected_identity)
                    .ser(),
            );
            self.write_unencrypted_record(record::ContentType::Handshake, &hello_retry_req)?;
            self.set_state(ServerState::WaitClientHelloRetry);

            client_hello = self.read_client_hello()?;
            (binder_key, selected_identity) = self.handle_client_hello(&mut client_hello)?;

            if let Some(client_pub_secp256r1_key) = client_hello.exts.key_share.secp256r1 {
                self.key_schedule
                    .set_client_public_key(client_pub_secp256r1_key);
            } else {
                log::error!("Client failed to negotiate key share with server");
                return Err(AlertDescription::InsufficientSecurity)?;
            }
        }

        self.key_schedule.binder_key(binder_key.as_ref());

        self.key_schedule.initialize_early_secret();

        if !self.buf.is_empty() {
            log::error!("Client fragmented record across key changes");
            return Err(AlertDescription::DecodeError)?;
        }

        let key: [u8; 65] = self.key_schedule.new_server_secret();

        let server_hello: Vec<u8> = HandshakeHeader::prepend_header(
            HandshakeType::ServerHello,
            &ServerHello::new(
                &client_hello.legacy_session_id_echo,
                &key,
                selected_identity,
            )
            .ser(),
        );

        self.write_unencrypted_record(record::ContentType::Handshake, &server_hello)?;

        self.key_schedule.initialize_handshake_secret();

        if !self.buf.is_empty() {
            log::error!("Client fragmented record across key changes");
            return Err(AlertDescription::DecodeError)?;
        }

        {
            let encrypted_extensions: Vec<u8> = HandshakeHeader::prepend_header(
                HandshakeType::EncryptedExtensions,
                &EncryptedExtensions::default().ser(),
            );

            self.write_encrypted_records(record::ContentType::Handshake, &encrypted_extensions)?;
        }

        if selected_identity.is_none() {
            let certificate: Vec<u8> = HandshakeHeader::prepend_header(
                HandshakeType::Certificate,
                &handshake::certificate_from_der(&self.certs.public_der)?,
            );

            self.write_encrypted_records(record::ContentType::Handshake, &certificate)?;

            let tsh = self.key_schedule.transcript_hash().finalize();

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

            self.write_encrypted_records(record::ContentType::Handshake, &certificate_verify)?;
        }

        let verify_data: GenericArray<u8, U32> = self.key_schedule.server_finished_verify_data();
        let finished: Vec<u8> = handshake::finished_with_hs_hdr(&verify_data);

        self.write_encrypted_records(record::ContentType::Handshake, &finished)?;

        self.set_state(ServerState::WaitFinished);

        self.read_client_finished()?;

        self.key_schedule.initialize_master_secret();

        if !self.buf.is_empty() {
            log::error!("Client fragmented record across key changes");
            return Err(AlertDescription::DecodeError)?;
        }

        self.set_state(ServerState::Connected);

        Ok(())
    }
}

impl std::io::Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        debug_assert_eq!(self.state, ServerState::Connected);

        while self.buf.is_empty() {
            self.read_next_record().map_err(std::io::Error::other)?
        }

        let mut len: usize = 0;
        for byte in buf.iter_mut() {
            match self.buf.pop_front() {
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

impl std::io::Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        assert_eq!(self.state, ServerState::Connected);

        self.write_encrypted_records(ContentType::ApplicationData, buf)
            .map_err(std::io::Error::other)?;

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.client.flush()
    }
}
