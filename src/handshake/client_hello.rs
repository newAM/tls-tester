use crate::parse;

use super::extension::ClientHelloExtensions;
use crate::{AlertDescription, CipherSuite};

/// Create a list of cipher suites.
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
            log::error!("ClientHello contains data after extensions");
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
