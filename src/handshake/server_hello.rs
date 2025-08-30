use super::{
    NamedGroup,
    extension::{KeyShareServerHello, PskServerHello, ServerHelloExtension, ServerHelloExtensions},
};
use rand::{RngCore, rngs::OsRng};

use crate::{AlertDescription, cipher_suite::CipherSuite, parse, tls_version::TlsVersion};

// https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.3
// For reasons of backward compatibility with middleboxes (see
// Appendix D.4), the HelloRetryRequest message uses the same structure
// as the ServerHello, but with Random set to the special value of the
// SHA-256 of "HelloRetryRequest"
const SERVER_HELLO_RETRY_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

/// Server Hello key exchange message.
///
/// # References
///
/// * [RFC 8446 Appendix B.3.1](https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.3.1)
///
/// ```text
/// struct {
///     ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
///     Random random;
///     opaque legacy_session_id_echo<0..32>;
///     CipherSuite cipher_suite;
///     uint8 legacy_compression_method = 0;
///     Extension extensions<6..2^16-1>;
/// } ServerHello;
/// ```
#[derive(Debug)]
pub struct ServerHelloBuilder {
    random: [u8; 32],
    legacy_session_id_echo: Vec<u8>,
    extensions: Vec<ServerHelloExtension>,
}

impl ServerHelloBuilder {
    pub fn new(
        legacy_session_id_echo: &[u8],
        key: &[u8; 65],
        selected_identity: Option<u16>,
    ) -> Self {
        let mut random: [u8; 32] = [0; 32];
        OsRng.fill_bytes(&mut random);

        let mut extensions: Vec<ServerHelloExtension> = Vec::with_capacity(3);

        extensions.push(ServerHelloExtension::SupportedVersions(TlsVersion::V1_3));

        if let Some(selected_identity_idx) = selected_identity {
            extensions.push(ServerHelloExtension::PreSharedKey(PskServerHello::new(
                selected_identity_idx,
            )));
        }

        extensions.push(ServerHelloExtension::KeyShareServerHello(
            KeyShareServerHello::new_secp256r1(key),
        ));

        Self {
            random,
            legacy_session_id_echo: legacy_session_id_echo.to_vec(),
            extensions,
        }
    }

    pub fn new_retry(legacy_session_id_echo: &[u8], selected_identity: Option<u16>) -> Self {
        let mut extensions: Vec<ServerHelloExtension> = Vec::with_capacity(3);

        extensions.push(ServerHelloExtension::SupportedVersions(TlsVersion::V1_3));

        if let Some(selected_identity_idx) = selected_identity {
            extensions.push(ServerHelloExtension::PreSharedKey(PskServerHello::new(
                selected_identity_idx,
            )));
        }

        extensions.push(ServerHelloExtension::KeyShareHelloRetryRequest(
            NamedGroup::secp256r1,
        ));

        Self {
            random: SERVER_HELLO_RETRY_RANDOM,
            legacy_session_id_echo: legacy_session_id_echo.to_vec(),
            extensions,
        }
    }

    pub fn ser(self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();

        // legacy_version
        buf.extend_from_slice(&[0x03, 0x03]);

        // random
        buf.extend_from_slice(&self.random);

        // legacy_session_id_echo
        buf.extend_from_slice(&self.legacy_session_id_echo);

        // cipher_suite
        buf.extend_from_slice(&u16::from(CipherSuite::TLS_AES_128_GCM_SHA256).to_be_bytes());

        // legacy_compression_method
        buf.push(0);

        let extensions_len_idx: usize = buf.len();

        // extensions length
        buf.extend_from_slice(&0_u16.to_be_bytes());

        // All TLS 1.3
        // ServerHello messages MUST contain the "supported_versions"
        // extension.  Current ServerHello messages additionally contain
        // either the "pre_shared_key" extension or the "key_share"
        // extension, or both (when using a PSK with (EC)DHE key
        // establishment).

        let mut extensions_len: u16 = 0;

        for extension in &self.extensions {
            let data: Vec<u8> = extension.ser();
            let data_len: u16 = data.len().try_into().unwrap();
            extensions_len = extensions_len.checked_add(data_len).unwrap();
            buf.extend_from_slice(&extension.ser());
        }

        buf[extensions_len_idx..extensions_len_idx + 2]
            .copy_from_slice(&extensions_len.to_be_bytes());

        buf
    }
}

/// Server Hello key exchange message.
///
/// # References
///
/// * [RFC 8446 Appendix B.3.1](https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.3.1)
///
/// ```text
/// struct {
///     ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
///     Random random;
///     opaque legacy_session_id_echo<0..32>;
///     CipherSuite cipher_suite;
///     uint8 legacy_compression_method = 0;
///     Extension extensions<6..2^16-1>;
/// } ServerHello;
/// ```
#[derive(Debug)]
pub struct ServerHello {
    pub random: [u8; 32],
    pub legacy_session_id_echo: Vec<u8>,
    pub cipher_suite: CipherSuite,
    pub exts: ServerHelloExtensions,
}

impl ServerHello {
    pub fn deser(b: &[u8]) -> Result<Self, AlertDescription> {
        let (b, legacy_version) = parse::u16("ServerHello legacy_version", b)?;

        if legacy_version != 0x0303 {
            log::error!(
                "ServerHello legacy_version 0x{legacy_version:04X} is not the required value of 0x0303"
            );
            return Err(AlertDescription::IllegalParameter);
        }

        let (b, random): (&[u8], [u8; 32]) = parse::fixed("ServerHello random", b)?;

        let (b, legacy_session_id_echo) =
            parse::vec8("ServerHello legacy_session_id_echo", b, 0, 1)?;

        let legacy_session_id_echo: Vec<u8> = legacy_session_id_echo.to_vec();

        if legacy_session_id_echo.len() > 32 {
            log::error!("ServerHello legacy_session_id_echo length is greater than maximum of 32");
            return Err(AlertDescription::DecodeError);
        }

        let (b, cipher_suite) = parse::u16("ServerHello cipher_suite", b)?;

        let cipher_suite: CipherSuite = match CipherSuite::try_from(cipher_suite) {
            Ok(cs) => cs,
            Err(v) => {
                log::error!("ServerHello cipher_suite contains unknown value 0x{v:04X}");
                return Err(AlertDescription::IllegalParameter);
            }
        };

        let (b, legacy_compression_method) = parse::u8("ServerHello legacy_compression_method", b)?;

        if legacy_compression_method != 0 {
            log::error!(
                "ServerHello legacy_compression_method 0x{legacy_compression_method:02X} is not the required value of 0"
            );
            return Err(AlertDescription::IllegalParameter);
        }

        let (_, exts) = parse::vec16("ServerHello extensions", b, 6, 1)?;

        let (_, exts) = ServerHelloExtensions::deser(exts)?;

        Ok(Self {
            random,
            legacy_session_id_echo,
            cipher_suite,
            exts,
        })
    }
}
