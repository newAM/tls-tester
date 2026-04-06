pub(crate) mod ech;
mod key_share;
mod psk;
mod record_size_limit;
mod server_name;
pub(crate) mod signature_scheme;
mod supported_versions;

use std::collections::HashSet;

pub(crate) use key_share::KeyShareServerHello;
pub(crate) use key_share::{KeyShareClientHello, KeyShareEntry};
pub(crate) use psk::{
    OfferedPsks, PskIdentity, PskKeyExchangeMode, PskKeyExchangeModes, PskServerHello,
};
pub use record_size_limit::RecordSizeLimit;
pub(crate) use server_name::ServerName;
pub use server_name::ServerNameList;
pub use signature_scheme::SignatureScheme;
use signature_scheme::decode_signature_scheme_list;
pub use supported_versions::SupportedVersionsClientHello;

use crate::{
    alert::AlertDescription,
    decode::DecodeContext,
    handshake::{
        ClientHello,
        ech::{ECHClientHello, OuterExtensions},
    },
    tls_version::TlsVersion,
};

use super::named_group::{NamedGroup, decode_named_group_list};

/// Extension type.
///
/// # References
///
/// * [RFC 8446 Section 4.2](https://datatracker.ietf.org/doc/html/rfc8446#section-4.2)
/// * [RFC 8449](https://datatracker.ietf.org/doc/html/rfc8449)
#[repr(u16)]
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExtensionType {
    ServerName = 0,                           // RFC 6066
    MaxFragmentLength = 1,                    // RFC 6066
    StatusRequest = 5,                        // RFC 6066
    SupportedGroups = 10,                     // RFC 8422, 7919
    SignatureAlgorithms = 13,                 // RFC 8446
    UseSrtp = 14,                             // RFC 5764
    Heartbeat = 15,                           // RFC 6520
    ApplicationLayerProtocolNegotiation = 16, // RFC 7301
    SignedCertificateTimestamp = 18,          // RFC 6962
    ClientCertificateType = 19,               // RFC 7250
    ServerCertificateType = 20,               // RFC 7250
    Padding = 21,                             // RFC 7685
    RecordSizeLimit = 28,                     // RFC 8449
    PreSharedKey = 41,                        // RFC 8446
    EarlyData = 42,                           // RFC 8446
    SupportedVersions = 43,                   // RFC 8446
    Cookie = 44,                              // RFC 8446
    PskKeyExchangeModes = 45,                 // RFC 8446
    CertificateAuthorities = 47,              // RFC 8446
    OidFilters = 48,                          // RFC 8446
    PostHandshakeAuth = 49,                   // RFC 8446
    SignatureAlgorithmsCert = 50,             // RFC 8446
    KeyShare = 51,                            // RFC 8446
    EncryptedClientHello = 0xfe0d,            // draft-ietf-tls-esni-25
    EchOuterExtensions = 0xfd00,              // draft-ietf-tls-esni-25
}

impl ExtensionType {
    pub const fn msb(self) -> u8 {
        ((self as u16) >> 8) as u8
    }

    pub const fn lsb(self) -> u8 {
        self as u8
    }

    pub const fn to_be_bytes(self) -> [u8; 2] {
        (self as u16).to_be_bytes()
    }

    pub fn may_appear_in_ee(&self) -> bool {
        // https://datatracker.ietf.org/doc/html/rfc8446#section-4.2
        matches!(
            self,
            Self::ServerName
                | Self::MaxFragmentLength
                | Self::SupportedGroups
                | Self::UseSrtp
                | Self::Heartbeat
                | Self::ApplicationLayerProtocolNegotiation
                | Self::ClientCertificateType
                | Self::ServerCertificateType
                | Self::EarlyData
        )
    }
}

impl From<ExtensionType> for u16 {
    #[inline]
    fn from(extension_type: ExtensionType) -> Self {
        extension_type as u16
    }
}

impl TryFrom<u16> for ExtensionType {
    type Error = u16;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            x if x == (Self::ServerName as u16) => Ok(Self::ServerName),
            x if x == (Self::MaxFragmentLength as u16) => Ok(Self::MaxFragmentLength),
            x if x == (Self::StatusRequest as u16) => Ok(Self::StatusRequest),
            x if x == (Self::SupportedGroups as u16) => Ok(Self::SupportedGroups),
            x if x == (Self::SignatureAlgorithms as u16) => Ok(Self::SignatureAlgorithms),
            x if x == (Self::UseSrtp as u16) => Ok(Self::UseSrtp),
            x if x == (Self::Heartbeat as u16) => Ok(Self::Heartbeat),
            x if x == (Self::ApplicationLayerProtocolNegotiation as u16) => {
                Ok(Self::ApplicationLayerProtocolNegotiation)
            }
            x if x == (Self::SignedCertificateTimestamp as u16) => {
                Ok(Self::SignedCertificateTimestamp)
            }
            x if x == (Self::ClientCertificateType as u16) => Ok(Self::ClientCertificateType),
            x if x == (Self::ServerCertificateType as u16) => Ok(Self::ServerCertificateType),
            x if x == (Self::Padding as u16) => Ok(Self::Padding),
            x if x == (Self::RecordSizeLimit as u16) => Ok(Self::RecordSizeLimit),
            x if x == (Self::PreSharedKey as u16) => Ok(Self::PreSharedKey),
            x if x == (Self::EarlyData as u16) => Ok(Self::EarlyData),
            x if x == (Self::SupportedVersions as u16) => Ok(Self::SupportedVersions),
            x if x == (Self::Cookie as u16) => Ok(Self::Cookie),
            x if x == (Self::PskKeyExchangeModes as u16) => Ok(Self::PskKeyExchangeModes),
            x if x == (Self::CertificateAuthorities as u16) => Ok(Self::CertificateAuthorities),
            x if x == (Self::OidFilters as u16) => Ok(Self::OidFilters),
            x if x == (Self::PostHandshakeAuth as u16) => Ok(Self::PostHandshakeAuth),
            x if x == (Self::SignatureAlgorithmsCert as u16) => Ok(Self::SignatureAlgorithmsCert),
            x if x == (Self::KeyShare as u16) => Ok(Self::KeyShare),
            x if x == (Self::EncryptedClientHello as u16) => Ok(Self::EncryptedClientHello),
            x if x == (Self::EchOuterExtensions as u16) => Ok(Self::EchOuterExtensions),
            _ => Err(value),
        }
    }
}

/// ClientHello extensions.
///
/// Extensions may not be repeated, easier to represent as a struct.
///
/// # References
///
/// * [RFC 8446 Section 4.2](https://datatracker.ietf.org/doc/html/rfc8446#section-4.2)
/// * [RFC 8449](https://datatracker.ietf.org/doc/html/rfc8449)
/// * [RFC 8446 Section 9.2](https://datatracker.ietf.org/doc/html/rfc8446#section-9.2)
///
/// ```text
/// struct {
///     ExtensionType extension_type;
///     opaque extension_data<0..2^16-1>;
/// } Extension;
/// ```
#[derive(Debug)]
pub(crate) struct ClientHelloExtensions {
    pub extension_data: Vec<(Result<ExtensionType, u16>, Vec<u8>)>,
    pub supported_versions: SupportedVersionsClientHello,
    // optional with psk_ke, but we only implement psk_dhe_ke
    pub key_share: KeyShareClientHello,
    pub server_name_list: Option<ServerNameList>,
    pub supported_groups: Vec<NamedGroup>,
    pub signature_algorithms: Option<Vec<SignatureScheme>>,
    pub signature_algorithms_cert: Option<Vec<SignatureScheme>>,
    pub pre_shared_key: Option<OfferedPsks>,
    pub psk_key_exchange_modes: Option<PskKeyExchangeModes>,
    pub record_size_limit: Option<RecordSizeLimit>,
    pub encrypted_client_hello: Option<(ECHClientHello, usize, usize)>,
    pub ech_outer_extensions: Option<OuterExtensions>,
}

impl ClientHelloExtensions {
    // Assumes the caller has already called begin_vec16 for the extensions block
    pub fn decode(
        ctx: &mut DecodeContext,
        outer: Option<&ClientHello>,
    ) -> Result<Self, AlertDescription> {
        let mut extension_data: Vec<(Result<ExtensionType, u16>, Vec<u8>)> = Vec::new();
        let mut extenstion_types: HashSet<Result<ExtensionType, u16>> = HashSet::new();

        let mut supported_versions: Option<SupportedVersionsClientHello> = None;
        let mut key_share: Option<KeyShareClientHello> = None;
        let mut server_name_list: Option<ServerNameList> = None;
        let mut supported_groups: Option<Vec<NamedGroup>> = None;
        let mut signature_algorithms: Option<Vec<SignatureScheme>> = None;
        let mut pre_shared_key: Option<OfferedPsks> = None;
        let mut psk_key_exchange_modes: Option<PskKeyExchangeModes> = None;
        let mut record_size_limit: Option<RecordSizeLimit> = None;
        let mut encrypted_client_hello: Option<(ECHClientHello, usize, usize)> = None;
        let mut signature_algorithms_cert: Option<Vec<SignatureScheme>> = None;
        let mut ech_outer_extensions: Option<OuterExtensions> = None;

        let mut index = 0;
        while ctx.remaining() > 0 {
            ctx.begin_element("extension", "Extension", index);

            let extension_type = ctx.u16("extension_type", "ExtensionType")?;
            let extension_type_result = ExtensionType::try_from(extension_type);

            let extension_pretty: String = match extension_type_result {
                Ok(et) => format!("{et:?}"),
                Err(val) => format!("0x{val:04x}"),
            };

            // https://datatracker.ietf.org/doc/html/rfc8446#section-4.2
            // There MUST NOT be more than one extension of the same type in a
            // given extension block.
            let duplicate: bool = !extenstion_types.insert(extension_type_result);
            if duplicate {
                log::error!("ClientHello extension appeared more than once: {extension_pretty}");
                return Err(AlertDescription::DecodeError);
            }

            // Parse extension_data as a vec16 - this creates a nested vector context
            ctx.begin_vec16("extension_data", "opaque<0..2^16-1>", 0, 1)?;

            // Track the start and end positions for ECH
            let extension_data_start = ctx.current_position();

            match extension_type_result {
                Ok(ExtensionType::ServerName) => {
                    let snl = ServerNameList::decode(ctx)?;
                    log::debug!("< {} {:?}", ctx.prev_path(), snl);
                    server_name_list.replace(snl);
                }
                Ok(ExtensionType::MaxFragmentLength) => {
                    log::warn!("Ignoring ClientHello extension MaxFragmentLength");
                    ctx.skip_remaining();
                }
                Ok(ExtensionType::StatusRequest) => {
                    log::warn!("Ignoring ClientHello extension StatusRequest");
                    ctx.skip_remaining();
                }
                Ok(ExtensionType::SupportedGroups) => {
                    let groups = decode_named_group_list(ctx)?;
                    log::debug!("< {} {:?}", ctx.prev_path(), groups);
                    supported_groups.replace(groups);
                }
                Ok(ExtensionType::SignatureAlgorithms) => {
                    let sig_algs = decode_signature_scheme_list(ctx)?;
                    log::debug!("< {} {:?}", ctx.prev_path(), sig_algs);
                    signature_algorithms.replace(sig_algs);
                }
                Ok(ExtensionType::UseSrtp) => {
                    log::warn!("Ignoring ClientHello extension UseSrtp");
                    ctx.skip_remaining();
                }
                Ok(ExtensionType::Heartbeat) => {
                    log::warn!("Ignoring ClientHello extension Heartbeat");
                    ctx.skip_remaining();
                }
                Ok(ExtensionType::ApplicationLayerProtocolNegotiation) => {
                    log::warn!(
                        "Ignoring ClientHello extension ApplicationLayerProtocolNegotiation"
                    );
                    ctx.skip_remaining();
                }
                Ok(ExtensionType::SignedCertificateTimestamp) => {
                    log::warn!("Ignoring ClientHello extension SignedCertificateTimestamp");
                    ctx.skip_remaining();
                }
                Ok(ExtensionType::ClientCertificateType) => {
                    log::warn!("Ignoring ClientHello extension ClientCertificateType");
                    ctx.skip_remaining();
                }
                Ok(ExtensionType::ServerCertificateType) => {
                    log::warn!("Ignoring ClientHello extension ServerCertificateType");
                    ctx.skip_remaining();
                }
                Ok(ExtensionType::Padding) => {
                    // Read the padding data to check it's all zeros
                    let padding_len = ctx.remaining();
                    log::debug!("< {} padding length {}", ctx.current_path(), padding_len);

                    // We need to verify all bytes are zero
                    let current_pos = ctx.current_position();
                    let padding_data =
                        &ctx.original_buffer()[current_pos..current_pos + padding_len];
                    let all_zero: bool = padding_data.iter().all(|&x| x == 0);
                    if !all_zero {
                        log::error!("ClientHello Padding extension is non-zero");
                        return Err(AlertDescription::IllegalParameter);
                    }
                    // Consume the padding bytes
                    for _ in 0..padding_len {
                        ctx.u8("padding", "uint8")?;
                    }
                }
                Ok(ExtensionType::RecordSizeLimit) => {
                    let rsl = RecordSizeLimit::decode(ctx)?;
                    log::debug!("< {} {:?}", ctx.prev_path(), rsl);
                    record_size_limit.replace(rsl);
                }
                Ok(ExtensionType::PreSharedKey) => {
                    // https://datatracker.ietf.org/doc/html/rfc8446#section-4.2
                    // When multiple extensions of different types are present, the
                    // extensions MAY appear in any order, with the exception of
                    // "pre_shared_key" (Section 4.2.11) which MUST be the last extension in
                    // the ClientHello (but can appear anywhere in the ServerHello
                    // extensions block).
                    // We'll check this after consuming the extension data

                    let offered_psks = OfferedPsks::decode(ctx)?;
                    log::debug!("< {} {:02X?}", ctx.prev_path(), offered_psks);
                    pre_shared_key.replace(offered_psks);
                }
                Ok(ExtensionType::EarlyData) => {
                    log::warn!("Ignoring ClientHello extension EarlyData");
                    ctx.skip_remaining();
                }
                Ok(ExtensionType::SupportedVersions) => {
                    let sv = SupportedVersionsClientHello::decode(ctx)?;
                    log::debug!("< {} {:04x?}", ctx.prev_path(), sv);
                    supported_versions.replace(sv);
                }
                Ok(ExtensionType::Cookie) => {
                    log::error!(
                        "ClientHello contains cookie extension, but the server did not request this"
                    );
                    return Err(AlertDescription::UnsupportedExtension);
                }
                Ok(ExtensionType::PskKeyExchangeModes) => {
                    let modes = PskKeyExchangeModes::decode(ctx)?;
                    log::debug!("< {} {:?}", ctx.prev_path(), modes);
                    psk_key_exchange_modes.replace(modes);
                }
                Ok(ExtensionType::CertificateAuthorities) => {
                    log::warn!("Ignoring ClientHello extension CertificateAuthorities");
                    ctx.skip_remaining();
                }
                Ok(ExtensionType::OidFilters) => {
                    log::warn!("Ignoring ClientHello extension OidFilters");
                    ctx.skip_remaining();
                }
                Ok(ExtensionType::PostHandshakeAuth) => {
                    log::warn!("Ignoring ClientHello extension PostHandshakeAuth");
                    ctx.skip_remaining();
                }
                Ok(ExtensionType::SignatureAlgorithmsCert) => {
                    let sig_algs = decode_signature_scheme_list(ctx)?;
                    log::debug!("< {} {:?}", ctx.prev_path(), sig_algs);
                    signature_algorithms_cert.replace(sig_algs);
                }
                Ok(ExtensionType::KeyShare) => {
                    let ks = KeyShareClientHello::decode(ctx)?;
                    log::debug!("< {} {:?}", ctx.prev_path(), ks);
                    key_share.replace(ks);
                }
                Ok(ExtensionType::EncryptedClientHello) => {
                    let ech_client_hello = ECHClientHello::decode(ctx)?;
                    let ech_end_idx = ctx.current_position();
                    log::debug!("< {} {:02x?}", ctx.prev_path(), ech_client_hello);
                    encrypted_client_hello.replace((
                        ech_client_hello,
                        extension_data_start,
                        ech_end_idx,
                    ));
                }
                Ok(ExtensionType::EchOuterExtensions) => {
                    let outer_ext = OuterExtensions::decode(ctx)?;
                    log::debug!("< {} {:02x?}", ctx.prev_path(), outer_ext);
                    ech_outer_extensions.replace(outer_ext);
                }
                Err(val) => {
                    // https://datatracker.ietf.org/doc/html/rfc8446#section-9.3
                    // A server receiving a ClientHello MUST correctly ignore all
                    // unrecognized cipher suites, extensions, and other parameters.
                    // Otherwise, it may fail to interoperate with newer clients.  In
                    // TLS 1.3, a client receiving a CertificateRequest or
                    // NewSessionTicket MUST also ignore all unrecognized extensions.
                    log::warn!("Ignoring unknown ClientHello extension 0x{val:04X}");
                    ctx.skip_remaining();
                }
            }

            // Store the extension data (raw bytes) for later use
            let extension_data_end = ctx.current_position();
            let data = ctx.original_buffer()[extension_data_start..extension_data_end].to_vec();
            extension_data.push((extension_type_result, data));

            // Check if PreSharedKey is the last extension
            if extension_type_result == Ok(ExtensionType::PreSharedKey) && ctx.remaining() > 0 {
                log::error!("ClientHello PreSharedKey is not the last extension");
                return Err(AlertDescription::UnexpectedMessage);
            }

            // Verify extension_data was fully consumed
            ctx.end_vec()?;
            ctx.end_element();
            index += 1;
        }

        if let Some(outer) = outer
            && let Some(outer_extensions) = &ech_outer_extensions
        {
            // TODO: all other extenions
            // TODO: validate ordering (maybe replace my hashset dupe checker with a vec)
            if outer_extensions
                .types
                .contains(&Ok(ExtensionType::SupportedVersions))
                && supported_versions
                    .replace(outer.exts.supported_versions.clone())
                    .is_some()
            {
                todo!("handle duplicate supported versions")
            }

            if outer_extensions
                .types
                .contains(&Ok(ExtensionType::SignatureAlgorithms))
            {
                if signature_algorithms.is_some() {
                    todo!("handle dupe sig algs")
                }
                signature_algorithms = outer.exts.signature_algorithms.clone();
            }

            if outer_extensions
                .types
                .contains(&Ok(ExtensionType::SupportedGroups))
                && supported_groups
                    .replace(outer.exts.supported_groups.clone())
                    .is_some()
            {
                todo!("handle duplicate supported groups extension")
            }

            if outer_extensions
                .types
                .contains(&Ok(ExtensionType::KeyShare))
                && key_share.replace(outer.exts.key_share.clone()).is_some()
            {
                todo!("handle duplicate key share extension")
            }
        }

        if signature_algorithms_cert.is_none() {
            // https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.3
            // If no "signature_algorithms_cert" extension is
            // present, then the "signature_algorithms" extension also applies to
            // signatures appearing in certificates.
            signature_algorithms_cert = signature_algorithms.clone();
        }

        let supported_versions: SupportedVersionsClientHello = match supported_versions {
            Some(sv) => sv,
            None => {
                log::error!("ClientHello missing required supported_versions extension");
                return Err(AlertDescription::MissingExtension);
            }
        };

        // https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.9
        // A client MUST provide a "psk_key_exchange_modes" extension if it
        // offers a "pre_shared_key" extension.  If clients offer
        // "pre_shared_key" without a "psk_key_exchange_modes" extension,
        // servers MUST abort the handshake.
        if pre_shared_key.is_some() {
            if let Some(psk_kems) = psk_key_exchange_modes.as_ref() {
                if !psk_kems.contains_psk_dhe_ke() {
                    log::warn!(
                        "ClientHello does not support psk_dhe_ke in psk_key_exchange_modes, server only implements psk_dhe_ke"
                    );
                    return Err(AlertDescription::HandshakeFailure);
                }
            } else {
                log::error!(
                    "ClientHello contains pre_shared_key extension without a psk_key_exchange_modes extension"
                );
                return Err(AlertDescription::MissingExtension);
            }
        }

        if let Some(signature_algorithms) = &signature_algorithms {
            if !signature_algorithms.contains(&SignatureScheme::rsa_pss_rsae_sha256) {
                log::warn!(
                    "ClientHello signature_algorithms does not support required SignatureScheme rsa_pss_rsae_sha256"
                );
            }
            if !signature_algorithms.contains(&SignatureScheme::ecdsa_secp256r1_sha256) {
                log::warn!(
                    "ClientHello signature_algorithms does not support required SignatureScheme ecdsa_secp256r1_sha256"
                );
            }
        }

        if let Some(signature_algorithms_cert) = &signature_algorithms_cert {
            if !signature_algorithms_cert.contains(&SignatureScheme::rsa_pkcs1_sha256) {
                log::warn!(
                    "ClientHello signature_algorithms_cert does not support required SignatureScheme rsa_pkcs1_sha256"
                );
            }
            if !signature_algorithms_cert.contains(&SignatureScheme::rsa_pss_rsae_sha256) {
                log::warn!(
                    "ClientHello signature_algorithms_cert does not support required SignatureScheme rsa_pss_rsae_sha256"
                );
            }
            if !signature_algorithms_cert.contains(&SignatureScheme::ecdsa_secp256r1_sha256) {
                log::warn!(
                    "ClientHello signature_algorithms_cert does not support required SignatureScheme ecdsa_secp256r1_sha256"
                );
            }
        } else if pre_shared_key.is_none() {
            // https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.3
            // If a server is authenticating via a certificate and the client has not
            // sent a "signature_algorithms" extension, then the server MUST abort
            // the handshake with a "missing_extension" alert
            log::error!("ClientHello is missing the signature_algorithms extension");
            return Err(AlertDescription::MissingExtension);
        }

        let key_share: KeyShareClientHello = match key_share {
            Some(ks) => ks,
            None => {
                log::error!("ClientHello missing required key_share extension");
                return Err(AlertDescription::MissingExtension);
            }
        };

        // https://datatracker.ietf.org/doc/html/rfc8446#section-9.2
        // A ClientHello message MUST meet the following requirements:
        // If containing a "supported_groups" extension, it MUST also contain
        // a "key_share" extension, and vice versa.
        let supported_groups: Vec<NamedGroup> = match supported_groups {
            Some(g) => g,
            None => {
                log::error!(
                    "ClientHello missing required supported_groups extension, this must be present when key_share is present"
                );
                return Err(AlertDescription::MissingExtension);
            }
        };

        // https://datatracker.ietf.org/doc/html/rfc8446#section-9.2
        // A ClientHello message MUST meet the following requirements:
        // If not containing a "pre_shared_key" extension, it MUST contain
        // both a "signature_algorithms" extension and a "supported_groups"
        // extension.
        if pre_shared_key.is_none() && signature_algorithms.is_none() {
            log::error!(
                r#"ClientHello MUST contain a "signature_algorithms" extension \
                if not containing a "pre_shared_key" extension"#,
            );
            return Err(AlertDescription::MissingExtension);
        }

        // TODO: if outer exists then check ECH extension exists and is value inner

        Ok(Self {
            extension_data,
            supported_versions,
            key_share,
            server_name_list,
            supported_groups,
            signature_algorithms,
            signature_algorithms_cert,
            pre_shared_key,
            psk_key_exchange_modes,
            record_size_limit,
            encrypted_client_hello,
            ech_outer_extensions,
        })
    }
}

/// ServerHello extension.
///
/// # References
///
/// * [RFC 8446 Section 4.2](https://datatracker.ietf.org/doc/html/rfc8446#section-4.2)
/// * [RFC 8449](https://datatracker.ietf.org/doc/html/rfc8449)
///
/// ```text
/// struct {
///     ExtensionType extension_type;
///     opaque extension_data<0..2^16-1>;
/// } Extension;
/// ```
#[derive(Debug)]
pub enum ServerHelloExtension {
    PreSharedKey(PskServerHello),          // RFC 8446
    SupportedVersions(TlsVersion),         // RFC 8446
    KeyShareServerHello(KeyShareEntry),    // RFC 8446
    KeyShareHelloRetryRequest(NamedGroup), // RFC 8446
}

impl ServerHelloExtension {
    pub fn ser(&self) -> Vec<u8> {
        let mut ret: Vec<u8> = Vec::new();

        let extension_type: ExtensionType = match self {
            Self::PreSharedKey(_) => ExtensionType::PreSharedKey,
            Self::SupportedVersions(_) => ExtensionType::SupportedVersions,
            Self::KeyShareServerHello(_) | Self::KeyShareHelloRetryRequest(_) => {
                ExtensionType::KeyShare
            }
        };

        ret.extend_from_slice(&extension_type.to_be_bytes());

        let ext_data: &[u8] = match self {
            Self::PreSharedKey(psk) => &psk.ser(),
            Self::SupportedVersions(supported_versions) => &supported_versions.to_be_bytes(),
            Self::KeyShareServerHello(key_share) => &key_share.ser(),
            Self::KeyShareHelloRetryRequest(named_group) => &named_group.to_be_bytes(),
        };

        ret.extend_from_slice(
            u16::try_from(ext_data.len())
                // server controls the extension data length, should never exceed u16
                .unwrap()
                .to_be_bytes()
                .as_ref(),
        );

        ret.extend_from_slice(ext_data);

        ret
    }
}

/// ServerHello extensions.
///
/// # References
///
/// * [RFC 8446 Section 4.2](https://datatracker.ietf.org/doc/html/rfc8446#section-4.2)
/// * [RFC 8449](https://datatracker.ietf.org/doc/html/rfc8449)
///
/// ```text
/// struct {
///     ExtensionType extension_type;
///     opaque extension_data<0..2^16-1>;
/// } Extension;
/// ```
#[derive(Debug)]
pub struct ServerHelloExtensions {
    pub psk_selected_identity: Option<u16>, // RFC 8446
    pub supported_versions: u16,            // RFC 8446
    pub key_share: KeyShareServerHello,     // RFC 8446
}

impl ServerHelloExtensions {
    // Assumes the caller has already called begin_vec16 for the extensions block
    pub fn decode(ctx: &mut DecodeContext, retry_request: bool) -> Result<Self, AlertDescription> {
        let mut extenstion_types: HashSet<Result<ExtensionType, u16>> = HashSet::new();

        let mut supported_versions: Option<u16> = None;
        let mut key_share: Option<KeyShareServerHello> = None;
        let mut psk_selected_identity: Option<u16> = None;

        let mut index = 0;
        while ctx.remaining() > 0 {
            ctx.begin_element("extension", "Extension", index);

            let extension_type = ctx.u16("extension_type", "ExtensionType")?;
            let extension_type_result = ExtensionType::try_from(extension_type);

            let extension_pretty: String = match extension_type_result {
                Ok(et) => format!("{et:?}"),
                Err(val) => format!("{val}"),
            };

            // https://datatracker.ietf.org/doc/html/rfc8446#section-4.2
            // There MUST NOT be more than one extension of the same type in a
            // given extension block.
            let duplicate: bool = !extenstion_types.insert(extension_type_result);
            if duplicate {
                log::error!("ServerHello extension appeared more than once: {extension_pretty}");
                return Err(AlertDescription::DecodeError);
            }

            // Parse extension_data as a vec16 - this creates a nested vector context
            ctx.begin_vec16("extension_data", "opaque<0..2^16-1>", 0, 1)?;

            match extension_type_result {
                Ok(
                    ExtensionType::ServerName
                    | ExtensionType::MaxFragmentLength
                    | ExtensionType::StatusRequest
                    | ExtensionType::SupportedGroups
                    | ExtensionType::SignatureAlgorithms
                    | ExtensionType::UseSrtp
                    | ExtensionType::Heartbeat
                    | ExtensionType::ApplicationLayerProtocolNegotiation
                    | ExtensionType::SignedCertificateTimestamp
                    | ExtensionType::ClientCertificateType
                    | ExtensionType::ServerCertificateType
                    | ExtensionType::Padding
                    | ExtensionType::EarlyData
                    | ExtensionType::Cookie
                    | ExtensionType::PskKeyExchangeModes
                    | ExtensionType::CertificateAuthorities
                    | ExtensionType::OidFilters
                    | ExtensionType::PostHandshakeAuth
                    | ExtensionType::SignatureAlgorithmsCert
                    | ExtensionType::RecordSizeLimit
                    | ExtensionType::EncryptedClientHello
                    | ExtensionType::EchOuterExtensions,
                ) => {
                    // https://datatracker.ietf.org/doc/html/rfc8446#section-4.2
                    // If an implementation receives an extension
                    // which it recognizes and which is not specified for the message in
                    // which it appears, it MUST abort the handshake with an
                    // "illegal_parameter" alert.
                    log::error!(
                        "{} extension is not specified for ServerHello",
                        ctx.current_path()
                    );
                    return Err(AlertDescription::IllegalParameter);
                }
                Ok(ExtensionType::PreSharedKey) => {
                    let selected_identity = ctx.u16("selected_identity", "u16")?;

                    log::debug!("< {} 0x{:04x?}", ctx.prev_path(), selected_identity);

                    psk_selected_identity.replace(selected_identity);
                }
                Ok(ExtensionType::SupportedVersions) => {
                    let data: u16 = ctx.u16("selected_version", "ProtocolVersion")?;

                    log::debug!("< {} 0x{:04X}", ctx.prev_path(), data);

                    supported_versions.replace(data);
                }
                Ok(ExtensionType::KeyShare) => {
                    let key_share_sh = KeyShareServerHello::decode(ctx, retry_request)?;
                    log::debug!("< {} {:?}", ctx.prev_path(), key_share_sh);
                    key_share.replace(key_share_sh);
                }
                Err(val) => {
                    log::warn!("Ignoring unknown ServerHello extension 0x{:04X}", val);
                }
            }

            // Verify extension_data was fully consumed
            ctx.end_vec()?;
            ctx.end_element();
            index += 1;
        }

        let supported_versions: u16 = match supported_versions {
            Some(sv) => sv,
            None => {
                log::error!("ServerHello missing required supported_versions extension");
                return Err(AlertDescription::MissingExtension);
            }
        };

        let key_share: KeyShareServerHello = match key_share {
            Some(ks) => ks,
            None => {
                log::error!("ServerHello missing required key_share extension");
                return Err(AlertDescription::MissingExtension);
            }
        };

        Ok(Self {
            psk_selected_identity,
            supported_versions,
            key_share,
        })
    }
}

/// Encrypted extensions.
///
/// # References
///
/// - [RFC 8446 Section 4.3.1](https://datatracker.ietf.org/doc/html/rfc8446#section-4.3.1)
///
/// ```text
/// struct {
///     Extension extensions<0..2^16-1>;
/// } EncryptedExtensions;
/// ```
#[derive(Default, Debug)]
pub(crate) struct EncryptedExtensions {
    pub server_name_list: Option<ServerNameList>,
    pub supported_groups: Option<Vec<NamedGroup>>,
}

impl EncryptedExtensions {
    pub fn decode(ctx: &mut DecodeContext) -> Result<Self, AlertDescription> {
        ctx.begin_vec16("extensions", "Extension<0..2^16-1>", 0, 1)?;

        let mut extenstion_types: HashSet<Result<ExtensionType, u16>> = HashSet::new();

        let mut server_name_list: Option<ServerNameList> = None;
        let mut supported_groups: Option<Vec<NamedGroup>> = None;

        let mut index = 0;
        while ctx.remaining() > 0 {
            ctx.begin_element("extension", "Extension", index);

            let extension_type = ctx.u16("extension_type", "ExtensionType")?;
            let extension_type_result = ExtensionType::try_from(extension_type);

            let extension_pretty: String = match extension_type_result {
                Ok(et) => format!("{et:?}"),
                Err(val) => format!("0x{val:04x}"),
            };

            // https://datatracker.ietf.org/doc/html/rfc8446#section-4.2
            // There MUST NOT be more than one extension of the same type in a
            // given extension block.
            let duplicate: bool = !extenstion_types.insert(extension_type_result);
            if duplicate {
                log::error!(
                    "< EncryptedExtensions extension appeared more than once: {extension_pretty}"
                );
                return Err(AlertDescription::DecodeError);
            }

            if let Ok(et) = extension_type_result
                && !et.may_appear_in_ee()
            {
                log::error!(
                    "< EncryptedExtensions extension type {extension_pretty} is not allowed in EncryptedExtensions"
                );
                return Err(AlertDescription::IllegalParameter)?;
            }

            ctx.begin_vec16("extension_data", "opaque<0..2^16-1>", 0, 1)?;

            match extension_type_result {
                Ok(ExtensionType::ServerName) => {
                    if ctx.remaining() > 0 {
                        let snl = ServerNameList::decode(ctx)?;
                        log::debug!("< {} {:?}", ctx.prev_path(), snl);
                        server_name_list.replace(snl);
                    }
                }
                Ok(ExtensionType::MaxFragmentLength) => {
                    log::warn!("Ignoring EncryptedExtensions extension MaxFragmentLength");
                    ctx.skip_remaining();
                }
                Ok(ExtensionType::StatusRequest) => unreachable!(),
                Ok(ExtensionType::SupportedGroups) => {
                    let groups = decode_named_group_list(ctx)?;
                    log::debug!("< {} {:?}", ctx.prev_path(), groups);
                    supported_groups.replace(groups);
                }
                Ok(ExtensionType::SignatureAlgorithms) => unreachable!(),
                Ok(ExtensionType::UseSrtp) => {
                    log::warn!("Ignoring EncryptedExtensions extension UseSrtp");
                    ctx.skip_remaining();
                }
                Ok(ExtensionType::Heartbeat) => {
                    log::warn!("Ignoring EncryptedExtensions extension Heartbeat");
                    ctx.skip_remaining();
                }
                Ok(ExtensionType::ApplicationLayerProtocolNegotiation) => {
                    log::warn!(
                        "Ignoring EncryptedExtensions extension ApplicationLayerProtocolNegotiation"
                    );
                    ctx.skip_remaining();
                }
                Ok(ExtensionType::SignedCertificateTimestamp) => {
                    log::warn!("Ignoring EncryptedExtensions extension SignedCertificateTimestamp");
                    ctx.skip_remaining();
                }
                Ok(ExtensionType::ClientCertificateType) => {
                    log::warn!("Ignoring EncryptedExtensions extension ClientCertificateType");
                    ctx.skip_remaining();
                }
                Ok(ExtensionType::ServerCertificateType) => {
                    log::warn!("Ignoring EncryptedExtensions extension ServerCertificateType");
                    ctx.skip_remaining();
                }
                Ok(ExtensionType::Padding) => unreachable!(),
                Ok(ExtensionType::RecordSizeLimit) => unreachable!(),
                Ok(ExtensionType::PreSharedKey) => unreachable!(),
                Ok(ExtensionType::EarlyData) => {
                    log::warn!("Ignoring EncryptedExtensions extension EarlyData");
                    ctx.skip_remaining();
                }
                Ok(ExtensionType::SupportedVersions) => unreachable!(),
                Ok(ExtensionType::Cookie) => unreachable!(),
                Ok(ExtensionType::PskKeyExchangeModes) => unreachable!(),
                Ok(ExtensionType::CertificateAuthorities) => unreachable!(),
                Ok(ExtensionType::OidFilters) => unreachable!(),
                Ok(ExtensionType::PostHandshakeAuth) => unreachable!(),
                Ok(ExtensionType::SignatureAlgorithmsCert) => unreachable!(),
                Ok(ExtensionType::KeyShare) => unreachable!(),
                Ok(ExtensionType::EncryptedClientHello) => unreachable!(),
                Ok(ExtensionType::EchOuterExtensions) => unreachable!(),
                Err(val) => {
                    log::warn!("Ignoring unknown EncryptedExtension extension 0x{val:04X}");
                    ctx.skip_remaining();
                }
            }

            ctx.end_vec()?;
            ctx.end_element();
            index += 1;
        }

        ctx.end_vec()?;

        let exts: EncryptedExtensions = EncryptedExtensions {
            server_name_list,
            supported_groups,
        };

        Ok(exts)
    }

    pub fn ser(&self) -> Vec<u8> {
        let mut ret: Vec<u8> = vec![0; 2];

        if let Some(server_name_list) = &self.server_name_list {
            ret.extend_from_slice(&server_name_list.ser());
        }

        if self.supported_groups.is_some() {
            todo!("Handle supported groups serialization");
        }

        let len: u16 = ret.len().strict_sub(2).try_into().expect("TODO");

        ret[0..2].copy_from_slice(&len.to_be_bytes());

        ret
    }
}

/// Encrypted extension.
///
/// # References
///
/// * [RFC 8446 Section 4.2](https://datatracker.ietf.org/doc/html/rfc8446#section-4.2)
/// * [RFC 8449](https://datatracker.ietf.org/doc/html/rfc8449)
///
/// ```text
/// struct {
///     ExtensionType extension_type;
///     opaque extension_data<0..2^16-1>;
/// } Extension;
/// ```
#[derive(Debug)]
pub enum EncryptedExtension {
    ServerName(ServerNameList),       // RFC 6066
    SupportedGroups(Vec<u8>),         // RFC 8422, 7919
    SignatureAlgorithms(Vec<u8>),     // RFC 8446
    RecordSizeLimit(RecordSizeLimit), // RFC 8449
}

impl EncryptedExtension {
    pub fn ser(&self) -> Vec<u8> {
        let mut ret: Vec<u8> = Vec::new();

        let extension_type: ExtensionType = match self {
            Self::ServerName(_) => ExtensionType::ServerName,
            Self::SupportedGroups(_) => ExtensionType::SupportedGroups,
            Self::SignatureAlgorithms(_) => ExtensionType::SignatureAlgorithms,
            Self::RecordSizeLimit(_) => ExtensionType::RecordSizeLimit,
        };

        ret.extend_from_slice(&extension_type.to_be_bytes());

        let ext_data: &[u8] = match self {
            Self::ServerName(server_name) => &server_name.ser(),
            Self::SupportedGroups(items) => items,
            Self::SignatureAlgorithms(items) => items,
            Self::RecordSizeLimit(limit) => &limit.ser(),
        };

        ret.extend_from_slice(
            u16::try_from(ext_data.len())
                // server controls the extension data length, should never exceed u16
                .unwrap()
                .to_be_bytes()
                .as_ref(),
        );

        ret.extend_from_slice(ext_data);

        ret
    }
}

/// Create an `Extension` at compile time.
///
/// # References
///
/// * [RFC 8446 Section 4.2](https://datatracker.ietf.org/doc/html/rfc8446#section-4.2)
///
/// ```text
/// struct {
///     ExtensionType extension_type;
///     opaque extension_data<0..2^16-1>;
/// } Extension;
/// ```
// N = DATA_LEN + size_of::<u16>() + size_of::<u16>()
const fn extension<const DATA_LEN: usize, const N: usize>(
    extension: ExtensionType,
    data: [u8; DATA_LEN],
) -> [u8; N] {
    let mut ret: [u8; N] = [0; N];
    ret[0] = (extension as u16).to_be_bytes()[0];
    ret[1] = (extension as u16).to_be_bytes()[1];
    ret[2] = (data.len() as u16).to_be_bytes()[0];
    ret[3] = (data.len() as u16).to_be_bytes()[1];

    let mut data_idx: usize = 0;
    while data_idx < DATA_LEN {
        ret[data_idx + 4] = data[data_idx];
        data_idx += 1;
    }
    ret
}
