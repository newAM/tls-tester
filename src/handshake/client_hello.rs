use rand::{RngCore as _, rngs::OsRng};

use crate::{
    handshake::extension::{ExtensionType, KeyShareClientHello},
    parse,
    tls_version::TlsVersion,
};

use super::{
    HandshakeHeader, HandshakeType, KeyShareEntry, NamedGroup,
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
        let (b, legacy_version): (_, u16) = parse::u16("ClientHello legacy_version", b)?;
        let (b, random): (_, [u8; 32]) = parse::fixed::<32>("ClientHello random", b)?;

        let (b, legacy_session_id): (_, &[u8]) =
            parse::vec8("ClientHello legacy_session_id", b, 0, 1)?;

        let mut legacy_session_id_echo: Vec<u8> = Vec::new();
        legacy_session_id_echo.push(legacy_session_id.len().try_into().unwrap());
        legacy_session_id_echo.extend_from_slice(legacy_session_id);

        let (b, cipher_suites_buf): (_, &[u8]) =
            parse::vec16("ClientHello cipher_suites", b, 2, 2)?;

        let mut cipher_suites: Vec<CipherSuite> = Vec::new();
        for chunk in cipher_suites_buf.chunks_exact(2) {
            match CipherSuite::try_from(u16::from_be_bytes(
                TryInto::<[u8; 2]>::try_into(chunk).unwrap(),
            )) {
                Ok(cs) => cipher_suites.push(cs),
                Err(e) => {
                    log::info!("ClientHello ignoring unknown cipher suite value: 0x{e:04X?}");
                }
            }
        }

        let (b, legacy_compression_methods): (_, &[u8]) =
            parse::vec8("ClientHello legacy_compression_methods", b, 1, 1)?;

        let (_, b): (_, &[u8]) = parse::vec16("ClientHello extensions", b, 8, 1)?;

        let (remain, exts): (_, ClientHelloExtensions) = ClientHelloExtensions::deser(b)?;

        if !remain.is_empty() {
            log::error!(
                "ClientHello contains {} bytes of data after extensions",
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
}

impl ClientHelloBuilder {
    pub fn new() -> Self {
        let mut random: [u8; 32] = [0; 32];
        OsRng.fill_bytes(&mut random);
        Self {
            random,
            server_name: None,
        }
    }

    #[must_use]
    pub fn set_server_name(mut self, server_name: Option<ServerName>) -> Self {
        self.server_name = server_name;
        self
    }

    pub fn random(&self) -> [u8; 32] {
        self.random
    }

    pub fn build(&self, named_groups: &[NamedGroup], pub_key: KeyShareEntry) -> Vec<u8> {
        let mut data: Vec<u8> = Vec::new();

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

        let mut extensions: Vec<u8> = Vec::new();

        let supported_versions: Vec<u8> = SupportedVersionsClientHello::ser(&[TlsVersion::V1_3]);
        extensions.extend_from_slice(ExtensionType::SupportedVersions.to_be_bytes().as_ref());
        extensions.extend_from_slice(
            u16::try_from(supported_versions.len())
                .unwrap()
                .to_be_bytes()
                .as_ref(),
        );
        extensions.extend_from_slice(&supported_versions);

        let key_share: Vec<u8> = KeyShareClientHello::ser(vec![pub_key]);
        extensions.extend_from_slice(ExtensionType::KeyShare.to_be_bytes().as_ref());
        extensions.extend_from_slice(
            u16::try_from(key_share.len())
                .unwrap()
                .to_be_bytes()
                .as_ref(),
        );
        extensions.extend_from_slice(&key_share);

        let supported_groups: Vec<u8> = ser_named_group_list(named_groups);
        extensions.extend_from_slice(ExtensionType::SupportedGroups.to_be_bytes().as_ref());
        extensions.extend_from_slice(
            u16::try_from(supported_groups.len())
                .unwrap()
                .to_be_bytes()
                .as_ref(),
        );
        extensions.extend_from_slice(&supported_groups);

        let signature_algorithms: Vec<u8> = ser_signature_scheme_list();
        extensions.extend_from_slice(ExtensionType::SignatureAlgorithms.to_be_bytes().as_ref());
        extensions.extend_from_slice(
            u16::try_from(signature_algorithms.len())
                .unwrap()
                .to_be_bytes()
                .as_ref(),
        );
        extensions.extend_from_slice(&signature_algorithms);

        if let Some(server_name) = &self.server_name {
            extensions.extend_from_slice(ExtensionType::ServerName.to_be_bytes().as_ref());
            let server_name_data: Vec<u8> = server_name.ser();
            extensions.extend_from_slice(
                u16::try_from(server_name_data.len())
                    .unwrap()
                    .to_be_bytes()
                    .as_ref(),
            );
            extensions.extend_from_slice(&server_name_data);
        }

        // extensions
        let extensions_len: u16 = extensions.len().try_into().unwrap();
        data.extend_from_slice(extensions_len.to_be_bytes().as_ref());
        data.extend_from_slice(extensions.as_ref());

        // pub key_share: KeyShareClientHello,
        // pub server_name_list: Option<ServerNameList>,
        // pub supported_groups: Vec<NamedGroup>,
        // pub signature_algorithms: Option<Vec<SignatureScheme>>,
        // pub pre_shared_key: Option<OfferedPsks>,
        // pub psk_key_exchange_modes: Option<PskKeyExchangeModes>,
        // pub record_size_limit: Option<RecordSizeLimit>,

        HandshakeHeader::prepend_header(HandshakeType::ClientHello, &data)
    }
}
