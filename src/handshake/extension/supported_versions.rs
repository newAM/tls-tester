use crate::{alert::AlertDescription, decode::DecodeContext, tls_version::TlsVersion};

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
#[derive(Debug, Clone)]
pub struct SupportedVersionsClientHello {
    versions: Vec<u16>,
}

impl SupportedVersionsClientHello {
    pub fn decode(ctx: &mut DecodeContext) -> Result<Self, AlertDescription> {
        ctx.begin_vec8("versions", "ProtocolVersion<2..254>", 2, 2)?;

        let mut versions: Vec<u16> = Vec::new();
        while ctx.remaining() > 0 {
            let version = ctx.u16("version", "ProtocolVersion")?;
            versions.push(version);
        }

        ctx.end_vec()?;

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
