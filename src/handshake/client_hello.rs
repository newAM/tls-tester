use rand::{TryRngCore as _, rngs::OsRng};
use sha2::{
    Digest,
    digest::{array::Array, typenum::U32},
};

use crate::{
    Psk,
    handshake::{
        HandshakeHeader,
        extension::{ExtensionType, KeyShareClientHello, PskIdentity, PskKeyExchangeMode},
    },
    key_schedule::KeySchedule,
    parse,
    tls_version::TlsVersion,
};

use super::{
    HandshakeType, KeyShareEntry, NamedGroup,
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
    // includes length byte for echo into ServerHello
    pub legacy_session_id_echo: Vec<u8>,
    pub cipher_suites: Vec<CipherSuite>,
    legacy_compression_methods: Vec<u8>,
    pub exts: ClientHelloExtensions,
}

impl ClientHello {
    const LEGACY_SESSION_ID_LEN_IDX: usize = 34;

    pub fn deser(b: &[u8]) -> Result<Self, AlertDescription> {
        let (b, legacy_version): (_, u16) = parse::u16("ClientHello.legacy_version", b)?;
        let (b, random): (_, [u8; 32]) = parse::fixed::<32>("ClientHello.random", b)?;

        let (b, legacy_session_id): (_, &[u8]) =
            parse::vec8("ClientHello.legacy_session_id", b, 0, 1)?;

        let mut legacy_session_id_echo: Vec<u8> = Vec::new();
        legacy_session_id_echo.push(legacy_session_id.len().try_into().unwrap());
        legacy_session_id_echo.extend_from_slice(legacy_session_id);

        let (b, cipher_suites_buf): (_, &[u8]) =
            parse::vec16("ClientHello.cipher_suites", b, 2, 2)?;

        let mut cipher_suites: Vec<CipherSuite> = Vec::new();
        for chunk in cipher_suites_buf.chunks_exact(2) {
            match CipherSuite::try_from(u16::from_be_bytes(
                TryInto::<[u8; 2]>::try_into(chunk).unwrap(),
            )) {
                Ok(cs) => cipher_suites.push(cs),
                Err(e) => {
                    log::info!("ClientHello.cipher_suites ignoring unknown value: 0x{e:04X?}");
                }
            }
        }

        let (b, legacy_compression_methods): (_, &[u8]) =
            parse::vec8("ClientHello.legacy_compression_methods", b, 1, 1)?;

        let (_, b): (_, &[u8]) = parse::vec16("ClientHello.extensions", b, 8, 1)?;

        let (remain, exts): (_, ClientHelloExtensions) = ClientHelloExtensions::deser(b)?;

        if !remain.is_empty() {
            log::error!(
                "ClientHello.extensions contains {} bytes of extra data",
                remain.len()
            );
            return Err(AlertDescription::DecodeError)?;
        }

        Ok(Self {
            legacy_version,
            random,
            legacy_session_id_echo,
            cipher_suites,
            legacy_compression_methods: legacy_compression_methods.to_vec(),
            exts,
        })
    }
}

pub(crate) struct ClientHelloBuilder {
    random: [u8; 32],
    server_name: Option<ServerName>,
    psks: Vec<Psk>,
}

impl ClientHelloBuilder {
    pub fn new() -> Self {
        let mut random: [u8; 32] = [0; 32];
        OsRng.try_fill_bytes(&mut random).expect("OsRng failure");
        Self {
            random,
            server_name: None,
            psks: Vec::new(),
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

    pub fn random(&self) -> [u8; 32] {
        self.random
    }

    pub fn build(
        &self,
        named_groups: &[NamedGroup],
        pub_key: KeyShareEntry,
        key_schedule: &mut KeySchedule,
    ) -> Vec<u8> {
        let mut data: Vec<u8> = Vec::new();

        data.push(HandshakeType::ClientHello.into());
        data.extend_from_slice(&[0, 0, 0]); // length

        // legacy_version
        data.extend_from_slice(0x0303_u16.to_be_bytes().as_ref());

        // random
        data.extend_from_slice(&self.random);

        // legacy_session_id
        // this is just the length byte
        data.push(0);

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

        let extensions_length_idx: usize = data.len();

        // extensions length
        data.extend_from_slice(&[0, 0]);

        let supported_versions: Vec<u8> = SupportedVersionsClientHello::ser(&[TlsVersion::V1_3]);
        data.extend_from_slice(ExtensionType::SupportedVersions.to_be_bytes().as_ref());
        data.extend_from_slice(
            u16::try_from(supported_versions.len())
                .unwrap()
                .to_be_bytes()
                .as_ref(),
        );
        data.extend_from_slice(&supported_versions);

        let key_share: Vec<u8> = KeyShareClientHello::ser(vec![pub_key]);
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

        let signature_algorithms: Vec<u8> = ser_signature_scheme_list();
        data.extend_from_slice(ExtensionType::SignatureAlgorithms.to_be_bytes().as_ref());
        data.extend_from_slice(
            u16::try_from(signature_algorithms.len())
                .unwrap()
                .to_be_bytes()
                .as_ref(),
        );
        data.extend_from_slice(&signature_algorithms);

        if let Some(server_name) = &self.server_name {
            data.extend_from_slice(ExtensionType::ServerName.to_be_bytes().as_ref());
            let server_name_data: Vec<u8> = server_name.ser();
            data.extend_from_slice(
                u16::try_from(server_name_data.len())
                    .unwrap()
                    .to_be_bytes()
                    .as_ref(),
            );
            data.extend_from_slice(&server_name_data);
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

        data
    }
}
