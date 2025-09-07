mod encrypted;
mod key_share;
mod psk;
mod record_size_limit;
mod server_name;
pub(crate) mod signature_scheme;
mod supported_versions;

use std::collections::HashSet;

pub use encrypted::EncryptedExtensions;
pub use key_share::{KeyShareClientHello, KeyShareServerHello};
use psk::PskKeyExchangeModes;
pub use psk::{OfferedPsks, PskServerHello};
pub use record_size_limit::RecordSizeLimit;
pub(crate) use server_name::ServerName;
pub use server_name::ServerNameList;
use signature_scheme::{SignatureScheme, deser_signature_scheme_list};
pub use supported_versions::SupportedVersionsClientHello;

use crate::{alert::AlertDescription, parse, tls_version::TlsVersion};

use super::named_group::{NamedGroup, deser_named_group_list};

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
    pub supported_versions: SupportedVersionsClientHello,
    // optional with psk_ke, but we only implement psk_dhe_ke
    pub key_share: KeyShareClientHello,
    pub server_name_list: Option<ServerNameList>,
    pub supported_groups: Vec<NamedGroup>,
    pub signature_algorithms: Option<Vec<SignatureScheme>>,
    pub pre_shared_key: Option<OfferedPsks>,
    pub psk_key_exchange_modes: Option<PskKeyExchangeModes>,
    pub record_size_limit: Option<RecordSizeLimit>,
}

impl ClientHelloExtensions {
    pub fn deser(mut b: &[u8]) -> Result<(&[u8], Self), AlertDescription> {
        let mut extenstion_types: HashSet<Result<ExtensionType, u16>> = HashSet::new();

        let mut supported_versions: Option<SupportedVersionsClientHello> = None;
        let mut key_share: Option<KeyShareClientHello> = None;
        let mut server_name_list: Option<ServerNameList> = None;
        let mut supported_groups: Option<Vec<NamedGroup>> = None;
        let mut signature_algorithms: Option<Vec<SignatureScheme>> = None;
        let mut pre_shared_key: Option<OfferedPsks> = None;
        let mut psk_key_exchange_modes: Option<PskKeyExchangeModes> = None;
        let mut record_size_limit: Option<RecordSizeLimit> = None;
        let mut signature_algorithms_cert: Option<Vec<SignatureScheme>> = None;

        while !b.is_empty() {
            let (new_b, extension_type): (_, u16) =
                parse::u16("ClientHello extensions extension_type", b)?;
            b = new_b;
            let (new_b, data): (_, &[u8]) =
                parse::vec16("ClientHello extensions extension_data", b, 0, 1)?;
            b = new_b;

            let extension_type = ExtensionType::try_from(extension_type);

            let extension_pretty: String = match extension_type {
                Ok(et) => format!("{et:?}"),
                Err(val) => format!("{val}"),
            };

            // https://datatracker.ietf.org/doc/html/rfc8446#section-4.2
            // There MUST NOT be more than one extension of the same type in a
            // given extension block.
            let duplicate: bool = !extenstion_types.insert(extension_type);
            if duplicate {
                log::error!("ClientHello Extension appeared more than once: {extension_pretty}");
                return Err(AlertDescription::DecodeError)?;
            }

            match extension_type {
                Ok(ExtensionType::ServerName) => {
                    let server_name_list_deser = ServerNameList::deser(data)?;
                    log::debug!("ClientHello ServerName {:?}", server_name_list_deser);
                    server_name_list.replace(server_name_list_deser);
                }
                Ok(ExtensionType::MaxFragmentLength) => {
                    log::warn!("Ignoring ClientHello extension MaxFragmentLength");
                }
                Ok(ExtensionType::StatusRequest) => {
                    log::warn!("Ignoring ClientHello extension StatusRequest");
                }
                Ok(ExtensionType::SupportedGroups) => {
                    let supported_groups_deser = deser_named_group_list(data)?;
                    log::debug!("ClientHello SupportedGroups {supported_groups_deser:?}");
                    supported_groups.replace(supported_groups_deser);
                }
                Ok(ExtensionType::SignatureAlgorithms) => {
                    let signature_scheme_list: Vec<SignatureScheme> =
                        deser_signature_scheme_list(data)?;
                    log::debug!("ClientHello SignatureAlgorithms {signature_scheme_list:?}");

                    signature_algorithms.replace(signature_scheme_list);
                }
                Ok(ExtensionType::UseSrtp) => {
                    log::warn!("Ignoring ClientHello extension UseSrtp");
                }
                Ok(ExtensionType::Heartbeat) => {
                    log::warn!("Ignoring ClientHello extension Heartbeat");
                }
                Ok(ExtensionType::ApplicationLayerProtocolNegotiation) => {
                    log::warn!(
                        "Ignoring ClientHello extension ApplicationLayerProtocolNegotiation"
                    );
                }
                Ok(ExtensionType::SignedCertificateTimestamp) => {
                    log::warn!("Ignoring ClientHello extension SignedCertificateTimestamp");
                }
                Ok(ExtensionType::ClientCertificateType) => {
                    log::warn!("Ignoring ClientHello extension ClientCertificateType");
                }
                Ok(ExtensionType::ServerCertificateType) => {
                    log::warn!("Ignoring ClientHello extension ServerCertificateType");
                }
                Ok(ExtensionType::Padding) => {
                    log::debug!("ClientHello padding length {}", data.len());
                    let all_zero: bool = data.iter().all(|&x| x == 0);
                    if !all_zero {
                        log::error!("ClientHello Padding extension is non-zero");
                        return Err(AlertDescription::IllegalParameter);
                    }
                }
                Ok(ExtensionType::RecordSizeLimit) => {
                    let rsl: RecordSizeLimit = RecordSizeLimit::deser(data)?;
                    log::debug!("ClientHello RecordSizeLimit {rsl:?}");
                    record_size_limit.replace(rsl);
                }
                Ok(ExtensionType::PreSharedKey) => {
                    // https://datatracker.ietf.org/doc/html/rfc8446#section-4.2
                    // When multiple extensions of different types are present, the
                    // extensions MAY appear in any order, with the exception of
                    // "pre_shared_key" (Section 4.2.11) which MUST be the last extension in
                    // the ClientHello (but can appear anywhere in the ServerHello
                    // extensions block).
                    if !b.is_empty() {
                        log::error!("ClientHello PreSharedKey is not the last extension");
                        return Err(AlertDescription::UnexpectedMessage);
                    }

                    let offered_psks = OfferedPsks::deser(data)?;

                    log::debug!("ClientHello PreSharedKey {offered_psks:?}");

                    pre_shared_key.replace(offered_psks);
                }
                Ok(ExtensionType::EarlyData) => {
                    log::warn!("Ignoring ClientHello extension EarlyData");
                }
                Ok(ExtensionType::SupportedVersions) => {
                    let supported_versions_deser = SupportedVersionsClientHello::deser(data)?;
                    log::debug!("ClientHello supported_versions {supported_versions_deser:04x?}");
                    supported_versions.replace(supported_versions_deser);
                }
                Ok(ExtensionType::Cookie) => {
                    log::error!(
                        "ClientHello contains cookie extension, but the server did not request this"
                    );
                    return Err(AlertDescription::UnsupportedExtension);
                }
                Ok(ExtensionType::PskKeyExchangeModes) => {
                    let psk_key_exchange_modes_deser = PskKeyExchangeModes::deser(data)?;
                    log::debug!("ClientHello PskKeyExchangeModes {psk_key_exchange_modes_deser:?}");
                    psk_key_exchange_modes.replace(psk_key_exchange_modes_deser);
                }
                Ok(ExtensionType::CertificateAuthorities) => {
                    log::warn!("Ignoring ClientHello extension CertificateAuthorities");
                }
                Ok(ExtensionType::OidFilters) => {
                    log::warn!("Ignoring ClientHello extension OidFilters");
                }
                Ok(ExtensionType::PostHandshakeAuth) => {
                    log::warn!("Ignoring ClientHello extension PostHandshakeAuth");
                }
                Ok(ExtensionType::SignatureAlgorithmsCert) => {
                    let signature_scheme_list: Vec<SignatureScheme> =
                        deser_signature_scheme_list(data)?;
                    log::debug!("ClientHello SignatureAlgorithmsCert {signature_scheme_list:?}");
                    signature_algorithms_cert.replace(signature_scheme_list);
                }
                Ok(ExtensionType::KeyShare) => {
                    let key_share_ch = KeyShareClientHello::deser_secp256r1(data)?;
                    log::debug!("ClientHello KeyShare {key_share_ch:?}");
                    key_share.replace(key_share_ch);
                }
                Err(val) => {
                    // https://datatracker.ietf.org/doc/html/rfc8446#section-9.3
                    // A server receiving a ClientHello MUST correctly ignore all
                    // unrecognized cipher suites, extensions, and other parameters.
                    // Otherwise, it may fail to interoperate with newer clients.  In
                    // TLS 1.3, a client receiving a CertificateRequest or
                    // NewSessionTicket MUST also ignore all unrecognized extensions.
                    log::warn!("Ignoring unknown ClientHello extension 0x{val:04X}");
                }
            }
        }

        if signature_algorithms_cert.is_none() {
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

        if let Some(cert_signature_algorithms) = signature_algorithms_cert {
            if !cert_signature_algorithms.contains(&SignatureScheme::ecdsa_secp256r1_sha256) {
                log::error!(
                    "Client does not supoort required ecdsa_secp256r1_sha256 signature algorithm"
                );
                return Err(AlertDescription::HandshakeFailure);
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

        let exts: ClientHelloExtensions = ClientHelloExtensions {
            supported_versions,
            key_share,
            server_name_list,
            supported_groups,
            signature_algorithms,
            pre_shared_key,
            psk_key_exchange_modes,
            record_size_limit,
        };

        Ok((b, exts))
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
    PreSharedKey(PskServerHello),             // RFC 8446
    SupportedVersions(TlsVersion),            // RFC 8446
    KeyShareServerHello(KeyShareServerHello), // RFC 8446
    KeyShareHelloRetryRequest(NamedGroup),    // RFC 8446
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
    // pre_shared_key: PskServerHello,                   // RFC 8446
    pub supported_versions: u16, // RFC 8446
    pub key_share: KeyShareServerHello, // RFC 8446
                                 // key_share_hello_retry: NamedGroup,                // RFC 8446
}

impl ServerHelloExtensions {
    pub fn deser(mut b: &[u8]) -> Result<(&[u8], Self), AlertDescription> {
        let mut extenstion_types: HashSet<Result<ExtensionType, u16>> = HashSet::new();

        let mut supported_versions: Option<u16> = None;
        let mut key_share: Option<KeyShareServerHello> = None;

        while !b.is_empty() {
            let (new_b, extension_type): (_, u16) =
                parse::u16("ServerHello extensions extension_type", b)?;
            b = new_b;
            let (new_b, data): (_, &[u8]) =
                parse::vec16("ServerHello extensions extension_data", b, 0, 1)?;
            b = new_b;

            let extension_type = ExtensionType::try_from(extension_type);

            let extension_pretty: String = match extension_type {
                Ok(et) => format!("{et:?}"),
                Err(val) => format!("{val}"),
            };

            // https://datatracker.ietf.org/doc/html/rfc8446#section-4.2
            // There MUST NOT be more than one extension of the same type in a
            // given extension block.
            let duplicate: bool = !extenstion_types.insert(extension_type);
            if duplicate {
                log::error!("ServerHello Extension appeared more than once: {extension_pretty}");
                return Err(AlertDescription::DecodeError)?;
            }

            match extension_type {
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
                    | ExtensionType::RecordSizeLimit,
                ) => {
                    // https://datatracker.ietf.org/doc/html/rfc8446#section-4.2
                    // If an implementation receives an extension
                    // which it recognizes and which is not specified for the message in
                    // which it appears, it MUST abort the handshake with an
                    // "illegal_parameter" alert.
                    log::error!("ServerHello extension {extension_pretty} is not specified");
                    return Err(AlertDescription::IllegalParameter);
                }
                Ok(ExtensionType::PreSharedKey) => {
                    // https://datatracker.ietf.org/doc/html/rfc8446#section-4.2
                    // When multiple extensions of different types are present, the
                    // extensions MAY appear in any order, with the exception of
                    // "pre_shared_key" (Section 4.2.11) which MUST be the last extension in
                    // the ClientHello (but can appear anywhere in the ServerHello
                    // extensions block).
                    if !b.is_empty() {
                        log::error!("ServerHello PreSharedKey is not the last extension");
                        return Err(AlertDescription::UnexpectedMessage);
                    }

                    todo!("implement ServerHello ExtensionType::PreSharedKey");

                    // let offered_psks = OfferedPsks::deser(data)?;

                    // log::debug!("< ServerHello PreSharedKey {offered_psks:?}");

                    // pre_shared_key.replace(offered_psks);
                }
                Ok(ExtensionType::SupportedVersions) => {
                    let data_sized: [u8; 2] = match data.try_into() {
                        Ok(ds) => ds,
                        Err(_) => {
                            log::error!(
                                "ServerHello extension SupportedVersions length is {} expected 2",
                                data.len()
                            );
                            return Err(AlertDescription::DecodeError);
                        }
                    };

                    let data_u16: u16 = u16::from_be_bytes(data_sized);

                    log::debug!("< ServerHello supported_versions 0x{data_u16:04X}");

                    supported_versions.replace(data_u16);
                }
                Ok(ExtensionType::KeyShare) => {
                    let (_, key_share_sh) = KeyShareServerHello::deser(data)?;
                    log::debug!("< ServerHello KeyShare {key_share_sh:?}");
                    key_share.replace(key_share_sh);
                }
                Err(val) => {
                    log::warn!("Ignoring unknown ServerHello extension 0x{val:04X}");
                }
            }
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

        let exts: Self = Self {
            supported_versions,
            key_share,
        };

        Ok((b, exts))
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
