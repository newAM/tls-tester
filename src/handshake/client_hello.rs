use rand::TryRng as _;
use sha2::{
    Digest,
    digest::{array::Array, typenum::U32},
};

use crate::{
    Psk, SignatureScheme,
    crypto::hpke::{self, AeadId, KdfId},
    handshake::{
        HandshakeHeader,
        ech::{ECHClientHello, ECHClientHelloOuter, ECHClientHelloType},
        extension::{
            ExtensionType, KeyShareClientHello, PskIdentity, PskKeyExchangeMode, ServerNameList,
        },
    },
    key_schedule::KeySchedule,
    parse,
    tls_version::TlsVersion,
};

use super::{
    HandshakeType, KeyShareEntry, NamedGroup,
    ech::{ECHConfig, HpkeSymmetricCipherSuite},
    extension::{
        ClientHelloExtensions, ServerName, SupportedVersionsClientHello,
        signature_scheme::ser_signature_scheme_list,
    },
    named_group::ser_named_group_list,
};
use crate::{alert::AlertDescription, cipher_suite::CipherSuite};

/// ClientHello handshake message.
///
/// # References
///
/// * [RFC 8446 Section 4.1.2](https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2)
///
/// ```text
/// uint8 CipherSuite[2];    /* Cryptographic suite selector */
///
/// struct {
///     ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
///     Random random;
///     opaque legacy_session_id<0..32>;
///     CipherSuite cipher_suites<2..2^16-2>;
///     opaque legacy_compression_methods<1..2^8-1>;
///     Extension extensions<8..2^16-1>;
/// } ClientHello;
/// ```
#[derive(Debug)]
pub struct ClientHello {
    legacy_version: u16,
    pub random: [u8; 32],
    pub legacy_session_id: Vec<u8>,
    pub cipher_suites: Vec<Result<CipherSuite, u16>>,
    legacy_compression_methods: Vec<u8>,
    pub exts: ClientHelloExtensions,
    ech_aad: Vec<u8>,
}

impl ClientHello {
    const LEGACY_SESSION_ID_LEN_IDX: usize = 34;

    pub fn deser(b: &[u8], outer: Option<&ClientHello>) -> Result<Self, AlertDescription> {
        let mut ech_aad: Vec<u8> = b.into();
        let initial_len: usize = b.len();

        let (b, legacy_version): (_, u16) = parse::u16("ClientHello.legacy_version", b)?;
        let (b, random): (_, [u8; 32]) = parse::fixed::<32>("ClientHello.random", b)?;

        let (b, legacy_session_id): (_, &[u8]) =
            parse::vec8("ClientHello.legacy_session_id", b, 0, 1)?;
        let legacy_session_id: Vec<u8> = legacy_session_id.into();

        let (b, cipher_suites_buf): (_, &[u8]) =
            parse::vec16("ClientHello.cipher_suites", b, 2, 2)?;

        let cipher_suites: Vec<Result<CipherSuite, u16>> = cipher_suites_buf
            .chunks_exact(2)
            .map(|chunk| {
                CipherSuite::try_from(u16::from_be_bytes(
                    TryInto::<[u8; 2]>::try_into(chunk).unwrap(),
                ))
            })
            .collect();

        for unknown in cipher_suites.iter().filter_map(|cs| cs.err()) {
            log::warn!("ClientHello.cipher_suites ignoring unknown value 0x{unknown:04X}");
        }

        let (b, legacy_compression_methods): (_, &[u8]) =
            parse::vec8("ClientHello.legacy_compression_methods", b, 1, 1)?;

        let (_, b): (_, &[u8]) = parse::vec16("ClientHello.extensions", b, 8, 1)?;

        let extensions_idx: usize = initial_len - b.len();
        let (remain, exts): (_, ClientHelloExtensions) = ClientHelloExtensions::deser(b, outer)?;

        if !remain.is_empty() {
            log::error!(
                "ClientHello.extensions contains {} bytes of extra data",
                remain.len()
            );
            return Err(AlertDescription::DecodeError)?;
        }

        if let Some((ech, start_ext_idx, end_ext_idx)) = &exts.encrypted_client_hello
            && let ECHClientHello::Outer(inner) = ech
        {
            let start_ech_payload: usize = extensions_idx + start_ext_idx + inner.payload_offset();
            let end_ech_payload: usize = extensions_idx + end_ext_idx;
            // https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-25#section-5.2
            ech_aad[start_ech_payload..end_ech_payload].fill(0);
        }

        Ok(Self {
            legacy_version,
            random,
            legacy_session_id,
            cipher_suites,
            legacy_compression_methods: legacy_compression_methods.to_vec(),
            exts,
            ech_aad,
        })
    }

    pub(crate) fn ech_aad(&self) -> &[u8] {
        &self.ech_aad
    }

    pub(crate) fn ech_transcript_data(&self, inner: &ClientHello) -> Vec<u8> {
        // TODO: cleanup to dedupe with builder
        let mut data: Vec<u8> = Vec::new();

        data.push(HandshakeType::ClientHello.into());
        data.extend_from_slice(&[0, 0, 0]); // length

        // legacy_version
        data.extend_from_slice(0x0303_u16.to_be_bytes().as_ref());

        // random
        data.extend_from_slice(&inner.random);

        // legacy_session_id
        let legacy_session_id_len: u8 = self
            .legacy_session_id
            .len()
            .try_into()
            .expect("Legacy session ID length exceeds maximum of 32");
        data.push(legacy_session_id_len);
        data.extend_from_slice(&self.legacy_session_id);

        // cipher_suites
        data.extend_from_slice(
            u16::try_from(inner.cipher_suites.len() * 2)
                .expect("TODO")
                .to_be_bytes()
                .as_ref(),
        );
        for cs in &inner.cipher_suites {
            match cs {
                Ok(cs) => data.extend_from_slice(&cs.to_be_bytes()),
                Err(unknown) => data.extend_from_slice(&unknown.to_be_bytes()),
            }
        }

        // legacy_compression_methods
        let legacy_compression_methods_len: u8 = inner
            .legacy_compression_methods
            .len()
            .try_into()
            .expect("Legacy compression methods ID length exceeds maximum of 255");
        data.push(legacy_compression_methods_len);
        data.extend_from_slice(&inner.legacy_compression_methods);

        // extensions length
        let extensions_length_idx: usize = data.len();
        data.extend_from_slice(&[0, 0]);

        for (extension_type, extension_data) in &inner.exts.extension_data {
            if *extension_type == Ok(ExtensionType::EchOuterExtensions) {
                for outer_ext in inner
                    .exts
                    .ech_outer_extensions
                    .clone()
                    .expect("TODO: bug here")
                    .types
                {
                    let (_, extension_data) = self.exts.extension_data.iter().find(|(ty, _)| *ty == outer_ext).expect("TODO: handle case where this isn't there, ECH RFC says illegal parameter alert");

                    let extension_type_u16: u16 = match outer_ext {
                        Ok(et) => et.into(),
                        Err(val) => val,
                    };

                    data.extend_from_slice(&extension_type_u16.to_be_bytes());
                    data.extend_from_slice(
                        &u16::try_from(extension_data.len())
                            .expect("TODO")
                            .to_be_bytes(),
                    );
                    data.extend_from_slice(extension_data);
                }
            } else {
                let extension_type_u16: u16 = match *extension_type {
                    Ok(et) => et.into(),
                    Err(val) => val,
                };

                data.extend_from_slice(&extension_type_u16.to_be_bytes());
                data.extend_from_slice(
                    &u16::try_from(extension_data.len())
                        .expect("TODO")
                        .to_be_bytes(),
                );
                data.extend_from_slice(extension_data);
            }
        }

        // set extensions length
        let extensions_len: u16 = u16::try_from(data.len() - extensions_length_idx - 2).unwrap();
        data[extensions_length_idx..extensions_length_idx + 2]
            .copy_from_slice(&extensions_len.to_be_bytes());

        // set handshake length
        let length: u32 = data.len().saturating_sub(4).try_into().unwrap();
        assert!(length <= HandshakeHeader::MAX_LENGTH);
        data[1..4].copy_from_slice(&length.to_be_bytes()[1..]);

        data
    }
}

pub(crate) struct ClientHelloBuilder {
    random: [u8; 32],
    pub(crate) inner_random: [u8; 32],
    legacy_session_id: Vec<u8>,
    server_name: Option<ServerName>,
    psks: Vec<Psk>,
    ech: Option<ECHConfig>,
}

impl ClientHelloBuilder {
    pub fn new() -> Self {
        let mut random: [u8; 32] = [0; 32];
        let mut inner_random: [u8; 32] = [0; 32];
        rand::rngs::ThreadRng::default()
            .try_fill_bytes(&mut random)
            .expect("OsRng failure");
        rand::rngs::ThreadRng::default()
            .try_fill_bytes(&mut inner_random)
            .expect("OsRng failure");
        Self {
            random,
            inner_random,
            legacy_session_id: Vec::new(),
            server_name: None,
            psks: Vec::new(),
            ech: None,
        }
    }

    #[must_use]
    pub fn set_server_name(mut self, server_name: Option<ServerName>) -> Self {
        self.server_name = server_name;
        self
    }

    #[must_use]
    pub fn set_psks(mut self, psks: Vec<Psk>) -> Self {
        self.psks = psks;
        self
    }

    #[must_use]
    pub fn set_ech_config(mut self, config: Option<ECHConfig>) -> Self {
        self.ech = config;
        self
    }

    #[must_use]
    pub fn set_legacy_session_id(mut self, legacy_session_id: Vec<u8>) -> Self {
        assert!(legacy_session_id.len() <= 32);
        self.legacy_session_id = legacy_session_id;
        self
    }

    #[must_use]
    pub fn set_random(mut self, random: [u8; 32]) -> Self {
        self.random = random;
        self
    }

    pub fn random(&self) -> [u8; 32] {
        self.random
    }

    pub fn inner_random(&self) -> [u8; 32] {
        self.inner_random
    }

    fn build_no_ext(&self, random: &[u8; 32]) -> Vec<u8> {
        let mut data: Vec<u8> = Vec::new();

        data.push(HandshakeType::ClientHello.into());
        data.extend_from_slice(&[0, 0, 0]); // length

        // legacy_version
        data.extend_from_slice(0x0303_u16.to_be_bytes().as_ref());

        // random
        data.extend_from_slice(random);

        // legacy_session_id
        let legacy_session_id_len: u8 = self
            .legacy_session_id
            .len()
            .try_into()
            .expect("Legacy session ID length exceeds maximum of 32");
        data.push(legacy_session_id_len);
        data.extend_from_slice(&self.legacy_session_id);

        // cipher_suites
        data.extend_from_slice(2_u16.to_be_bytes().as_ref());
        data.extend_from_slice(
            u16::from(CipherSuite::TLS_AES_128_GCM_SHA256)
                .to_be_bytes()
                .as_ref(),
        );

        // legacy_compression_methods
        data.push(1);
        data.push(0);

        // extensions length
        data.extend_from_slice(&[0, 0]);

        data
    }

    pub fn build(
        &self,
        named_groups: &[NamedGroup],
        signature_algorithms: &[SignatureScheme],
        pub_key: KeyShareEntry,
        key_schedule: &mut KeySchedule,
    ) -> (Vec<u8>, Vec<u8>) {
        let mut data: Vec<u8> = self.build_no_ext(&self.random);
        let mut inner: Vec<u8> = Vec::new();

        let extensions_length_idx: usize = data.len() - 2;

        let supported_versions: Vec<u8> = SupportedVersionsClientHello::ser(&[TlsVersion::V1_3]);
        data.extend_from_slice(ExtensionType::SupportedVersions.to_be_bytes().as_ref());
        data.extend_from_slice(
            u16::try_from(supported_versions.len())
                .unwrap()
                .to_be_bytes()
                .as_ref(),
        );
        data.extend_from_slice(&supported_versions);

        let key_share: Vec<u8> = KeyShareClientHello::ser(vec![pub_key.clone()]);
        data.extend_from_slice(ExtensionType::KeyShare.to_be_bytes().as_ref());
        data.extend_from_slice(
            u16::try_from(key_share.len())
                .unwrap()
                .to_be_bytes()
                .as_ref(),
        );
        data.extend_from_slice(&key_share);

        let supported_groups: Vec<u8> = ser_named_group_list(named_groups);
        data.extend_from_slice(ExtensionType::SupportedGroups.to_be_bytes().as_ref());
        data.extend_from_slice(
            u16::try_from(supported_groups.len())
                .unwrap()
                .to_be_bytes()
                .as_ref(),
        );
        data.extend_from_slice(&supported_groups);

        let signature_algorithms_data: Vec<u8> = ser_signature_scheme_list(signature_algorithms);
        data.extend_from_slice(ExtensionType::SignatureAlgorithms.to_be_bytes().as_ref());
        data.extend_from_slice(
            u16::try_from(signature_algorithms_data.len())
                .unwrap()
                .to_be_bytes()
                .as_ref(),
        );
        data.extend_from_slice(&signature_algorithms_data);

        if let Some(server_name) = &self.server_name {
            if let Some(ech_config) = &self.ech {
                if !self.psks.is_empty() {
                    unimplemented!("TODO: support ECH with PSK")
                }

                // use ECH public name for outer hello
                data.extend_from_slice(ExtensionType::ServerName.to_be_bytes().as_ref());
                let server_name_data: Vec<u8> = ServerNameList {
                    server_name_list: vec![
                        ServerName::from_str(&ech_config.contents.public_name).expect("TODO"),
                    ],
                }
                .ser();
                data.extend_from_slice(
                    u16::try_from(server_name_data.len())
                        .unwrap()
                        .to_be_bytes()
                        .as_ref(),
                );
                data.extend_from_slice(&server_name_data);

                // draft-ietf-tls-esni-25 section 5.1 "Encoding the ClientHelloInner":
                // "This does not include Handshake structure's four-byte header in TLS"
                inner = self.build_no_ext(&self.inner_random).split_off(4);

                let inner_extensions_length_idx: usize = inner.len() - 2;

                let supported_versions: Vec<u8> =
                    SupportedVersionsClientHello::ser(&[TlsVersion::V1_3]);
                inner.extend_from_slice(ExtensionType::SupportedVersions.to_be_bytes().as_ref());
                inner.extend_from_slice(
                    u16::try_from(supported_versions.len())
                        .unwrap()
                        .to_be_bytes()
                        .as_ref(),
                );
                inner.extend_from_slice(&supported_versions);

                let key_share: Vec<u8> = KeyShareClientHello::ser(vec![pub_key]);
                inner.extend_from_slice(ExtensionType::KeyShare.to_be_bytes().as_ref());
                inner.extend_from_slice(
                    u16::try_from(key_share.len())
                        .unwrap()
                        .to_be_bytes()
                        .as_ref(),
                );
                inner.extend_from_slice(&key_share);

                let supported_groups: Vec<u8> = ser_named_group_list(named_groups);
                inner.extend_from_slice(ExtensionType::SupportedGroups.to_be_bytes().as_ref());
                inner.extend_from_slice(
                    u16::try_from(supported_groups.len())
                        .unwrap()
                        .to_be_bytes()
                        .as_ref(),
                );
                inner.extend_from_slice(&supported_groups);

                let signature_algorithms_data: Vec<u8> =
                    ser_signature_scheme_list(signature_algorithms);
                inner.extend_from_slice(ExtensionType::SignatureAlgorithms.to_be_bytes().as_ref());
                inner.extend_from_slice(
                    u16::try_from(signature_algorithms_data.len())
                        .unwrap()
                        .to_be_bytes()
                        .as_ref(),
                );
                inner.extend_from_slice(&signature_algorithms_data);

                inner.extend_from_slice(ExtensionType::ServerName.to_be_bytes().as_ref());
                let server_name_data: Vec<u8> = ServerNameList {
                    server_name_list: vec![server_name.clone()],
                }
                .ser();
                inner.extend_from_slice(
                    u16::try_from(server_name_data.len())
                        .unwrap()
                        .to_be_bytes()
                        .as_ref(),
                );
                inner.extend_from_slice(&server_name_data);

                // To offer ECH, the client sends an "encrypted_client_hello" extension in the ClientHelloOuter.
                // When it does, it MUST also send the extension in ClientHelloInner.
                inner.extend_from_slice(ExtensionType::EncryptedClientHello.to_be_bytes().as_ref());
                inner.extend_from_slice(&1_u16.to_be_bytes());
                inner.push(ECHClientHelloType::Inner.into());

                // set inner extensions length
                let inner_extensions_len: u16 =
                    u16::try_from(inner.len() - inner_extensions_length_idx - 2).unwrap();
                inner[inner_extensions_length_idx..inner_extensions_length_idx + 2]
                    .copy_from_slice(&inner_extensions_len.to_be_bytes());

                // TODO: padding

                // The client then constructs EncodedClientHelloInner as described in Section 5.1.
                // It also computes an HPKE encryption context and enc value as:
                // pkR = DeserializePublicKey(ECHConfig.contents.public_key)
                // enc, context = SetupBaseS(pkR, "tls ech" || 0x00 || ECHConfig)
                let mut hpke_data: Vec<u8> = Vec::new();
                hpke_data.extend_from_slice(b"tls ech\0");
                hpke_data.extend_from_slice(&ech_config.ser());

                // TODO: only x25519 is supported
                let server_public: crate::crypto::x25519::PublicKey =
                    crate::crypto::x25519::PublicKey::from(
                        <Vec<u8> as TryInto<[u8; 32]>>::try_into(
                            ech_config.contents.key_config.public_key.clone(),
                        )
                        .expect("TODO: move this validation into ech.rs"),
                    );

                let (enc, mut context) = hpke::setup_base_s(&server_public, &hpke_data);

                let ech_outer: ECHClientHelloOuter = ECHClientHelloOuter {
                    // TODO: ech_config previously validated to contain this cipher suite
                    cipher_suite: HpkeSymmetricCipherSuite {
                        kdf_id: KdfId::HkdfSha256,
                        aead_id: AeadId::Aes128Gcm,
                    },
                    config_id: ech_config.contents.key_config.config_id,
                    enc: enc.as_bytes().to_vec(),
                    payload: inner.clone(),
                };

                let (ech_zero_payload_zero_tag, ech_payload): (Vec<u8>, Vec<u8>) = ech_outer.ser();

                data.extend_from_slice(ExtensionType::EncryptedClientHello.to_be_bytes().as_ref());
                data.extend_from_slice(
                    u16::try_from(ech_zero_payload_zero_tag.len())
                        .expect("ECHClientHello length exceeds u16::MAX")
                        .to_be_bytes()
                        .as_ref(),
                );
                data.extend_from_slice(&ech_zero_payload_zero_tag);

                // set extensions length prior to AAD
                let extensions_len: u16 =
                    u16::try_from(data.len() - extensions_length_idx - 2).unwrap();
                data[extensions_length_idx..extensions_length_idx + 2]
                    .copy_from_slice(&extensions_len.to_be_bytes());

                // https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-25#section-5.2
                let aad: &[u8] = &data[HandshakeHeader::LEN..];
                let payload_and_tag: Vec<u8> = context.seal(aad, &ech_payload);
                let data_len: usize = data.len();
                data[data_len - payload_and_tag.len()..].copy_from_slice(&payload_and_tag);
            } else {
                data.extend_from_slice(ExtensionType::ServerName.to_be_bytes().as_ref());
                let server_name_data: Vec<u8> = ServerNameList {
                    server_name_list: vec![server_name.clone()],
                }
                .ser();
                data.extend_from_slice(
                    u16::try_from(server_name_data.len())
                        .unwrap()
                        .to_be_bytes()
                        .as_ref(),
                );
                data.extend_from_slice(&server_name_data);
            }
        } else if self.ech.is_some() {
            log::warn!("ECH configuration is unused without a server name");
        }

        const EXTENSION_TYPE_LEN: usize = 2;
        const EXTENSION_LEN_LEN: usize = 2;
        const IDENTITIES_LEN_LEN: usize = 2;

        const PSK_KEM_DHE_KE: [u8; 6] = [
            ExtensionType::PskKeyExchangeModes.to_be_bytes()[0],
            ExtensionType::PskKeyExchangeModes.to_be_bytes()[1],
            0, // length
            2, // length
            1, // inner length
            PskKeyExchangeMode::psk_dhe_ke as u8,
        ];

        let binders_len: usize = self.psks.len() * (<sha2::Sha256 as Digest>::output_size() + 1);

        let psks_extra_len: usize = if self.psks.is_empty() {
            0
        } else {
            let identities_len: usize = self.psks.iter().fold(0, |acc, psk| {
                acc.checked_add(6)
                    .unwrap()
                    .checked_add(psk.identity.len())
                    .unwrap()
            });

            const BINDERS_LEN_LEN: usize = 2;

            PSK_KEM_DHE_KE.len()
                + EXTENSION_TYPE_LEN
                + EXTENSION_LEN_LEN
                + IDENTITIES_LEN_LEN
                + identities_len
                + BINDERS_LEN_LEN
                + binders_len
        };

        // set extensions length
        let extensions_len: u16 =
            u16::try_from(data.len() + psks_extra_len - extensions_length_idx - 2).unwrap();
        data[extensions_length_idx..extensions_length_idx + 2]
            .copy_from_slice(&extensions_len.to_be_bytes());

        // set handshake length
        let length: u32 = data
            .len()
            .saturating_sub(4)
            .checked_add(psks_extra_len)
            .unwrap()
            .try_into()
            .unwrap();
        assert!(length <= HandshakeHeader::MAX_LENGTH);
        data[1..4].copy_from_slice(&length.to_be_bytes()[1..]);

        // https://datatracker.ietf.org/doc/html/rfc8446#section-4.2
        // When multiple extensions of different types are present, the
        // extensions MAY appear in any order, with the exception of
        // "pre_shared_key" (Section 4.2.11) which MUST be the last extension in
        // the ClientHello.
        if !self.psks.is_empty() {
            data.extend_from_slice(&PSK_KEM_DHE_KE);

            data.extend_from_slice(ExtensionType::PreSharedKey.to_be_bytes().as_ref());
            data.extend_from_slice(
                u16::try_from(
                    psks_extra_len - EXTENSION_TYPE_LEN - EXTENSION_LEN_LEN - PSK_KEM_DHE_KE.len(),
                )
                .unwrap()
                .to_be_bytes()
                .as_ref(),
            );

            let identities: Vec<Vec<u8>> = self
                .psks
                .iter()
                .map(|psk| PskIdentity {
                    identity: psk.identity.clone(),
                    obfuscated_ticket_age: 0,
                })
                .map(|psk_id| psk_id.ser())
                .collect();

            let identities_len: usize = identities
                .iter()
                .fold(0, |acc, id| acc.checked_add(id.len()).unwrap());

            data.extend_from_slice(
                u16::try_from(identities_len)
                    .unwrap()
                    .to_be_bytes()
                    .as_ref(),
            );
            identities.iter().for_each(|id| data.extend_from_slice(id));

            let truncated_transcript_hash: Array<u8, U32> = sha2::Sha256::digest(&data);

            data.extend_from_slice(u16::try_from(binders_len).unwrap().to_be_bytes().as_ref());

            for psk in &self.psks {
                let binder: Array<u8, U32> =
                    key_schedule.binder(Some(&psk.key), &truncated_transcript_hash);
                data.push(u8::try_from(binder.len()).unwrap());
                data.extend_from_slice(&binder);
            }
        }

        (data, inner)
    }
}
