use crate::{alert::AlertDescription, parse, tls_version::TlsVersion};

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

    pub fn ser(versions: &[TlsVersion]) -> Vec<u8> {
        assert!(
            !versions.is_empty(),
            "At least one version must be supported"
        );

        let versions_len: u8 = u8::try_from(versions.len())
            .unwrap()
            .checked_mul(2)
            .unwrap();

        let mut data: Vec<u8> = Vec::new();
        data.push(versions_len);
        versions
            .iter()
            .for_each(|v| data.extend_from_slice(v.to_be_bytes().as_ref()));

        data
    }

    pub fn supports_tlsv1_3(&self) -> bool {
        self.versions.contains(&TlsVersion::V1_3.into())
    }
}
