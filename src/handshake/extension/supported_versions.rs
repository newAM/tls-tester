use crate::{AlertDescription, TlsVersion, parse};

/// # References
///
/// * [RFC 8446 Appendix B.3.1.1](https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.3.1.1)
///
/// ```text
/// struct {
///     select (Handshake.msg_type) {
///         case client_hello:
///              ProtocolVersion versions<2..254>;
///
///         case server_hello: /* and HelloRetryRequest */
///              ProtocolVersion selected_version;
///     };
/// } SupportedVersions;
/// ```
#[derive(Debug)]
pub struct SupportedVersionsClientHello {
    versions: Vec<u16>,
}

pub type SupportedVersionsServerHello = TlsVersion;

impl SupportedVersionsClientHello {
    pub fn deser(b: &[u8]) -> Result<Self, AlertDescription> {
        let (_, versions_b) = parse::vec8("SupportedVersions versions", b, 2, 2)?;

        let mut versions: Vec<u16> = Vec::with_capacity(versions_b.len() / 2);
        for chunk in versions_b.chunks_exact(2) {
            // unwrap will never panic, data has been validated as a multiple of 2
            let version: u16 = u16::from_be_bytes(chunk.try_into().unwrap());
            versions.push(version);
        }

        Ok(Self { versions })
    }

    pub fn supports_tlsv1_3(&self) -> bool {
        self.versions.contains(&TlsVersion::V1_3.into())
    }
}
