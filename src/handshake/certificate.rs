use crate::{alert::AlertDescription, decode::DecodeContext, x509};

use super::extension::signature_scheme::SignatureScheme;

/// # References
///
/// - [RFC 8446 Appendix B.3.3](https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.3.3)
///
/// ```text
/// enum {
///     X509(0),
///     OpenPGP_RESERVED(1),
///     RawPublicKey(2),
///     (255)
/// } CertificateType;
/// ```
#[repr(u8)]
#[derive(Debug)]
#[allow(non_camel_case_types)]
pub enum CertificateType {
    X509 = 0,
    OpenPGP_RESERVED = 1,
    RawPublicKey = 2,
}

/// # References
///
/// - [RFC 8446 Appendix B.3.3](https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.3.3)
///
/// ```text
/// struct {
///     select (certificate_type) {
///         case RawPublicKey:
///           /* From RFC 7250 ASN.1_subjectPublicKeyInfo */
///           opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;
///
///         case X509:
///           opaque cert_data<1..2^24-1>;
///     };
///     Extension extensions<0..2^16-1>;
/// } CertificateEntry;
/// ```
#[derive(Debug)]
pub(crate) struct CertificateEntry {
    pub(crate) data: x509::Certificate,
    pub(crate) tbs_certificate: Vec<u8>,
    pub(crate) extensions: Vec<u8>,
}

impl CertificateEntry {
    pub fn decode(ctx: &mut DecodeContext) -> Result<Self, AlertDescription> {
        ctx.begin_vec24("cert_data", "opaque<1..2^24-1>", 1, 1)?;

        let (tbs_certificate_bytes, data) = x509::Certificate::decode(ctx, false)?;
        ctx.end_vec()?;

        let extensions: Vec<u8> = ctx.vec16("extensions", "Extension<0..2^16-1>", 0, 1)?;

        Ok(Self {
            data,
            tbs_certificate: tbs_certificate_bytes,
            extensions,
        })
    }
}

/// # References
///
/// - [RFC 8446 Appendix B.3.3](https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.3.3)
///
/// ```text
/// struct {
///     opaque certificate_request_context<0..2^8-1>;
///     CertificateEntry certificate_list<0..2^24-1>;
/// } Certificate;
/// ```
pub(crate) struct Certificate {
    pub(crate) request_context: Vec<u8>,
    pub(crate) certificate_list: Vec<CertificateEntry>,
}

impl Certificate {
    pub fn decode(ctx: &mut DecodeContext) -> Result<Self, AlertDescription> {
        let request_context: Vec<u8> =
            ctx.vec8("certificate_request_context", "opaque<0..2^8-1>", 0, 1)?;

        ctx.begin_vec24("certificate_list", "CertificateEntry<0..2^24-1>", 0, 1)?;

        let mut certificate_list: Vec<CertificateEntry> = Vec::new();

        while ctx.remaining() > 0 {
            let entry = CertificateEntry::decode(ctx)?;
            certificate_list.push(entry);
        }

        ctx.end_vec()?;
        ctx.ensure_fully_consumed()?;

        Ok(Self {
            request_context,
            certificate_list,
        })
    }
}

pub fn certificate_from_der(public_der: &[u8]) -> Result<Vec<u8>, AlertDescription> {
    // validated in ServerCertificates constructor
    assert_ne!(public_der.len(), 0);
    // validated in ServerCertificates constructor
    assert!(public_der.len() < (1 << 24) - 1);

    // unwrap should never occur, value range has been validated
    let data_len: u32 = public_der.len().try_into().unwrap();
    let certificates_len: u32 = data_len + 5;

    let mut ret: Vec<u8> = Vec::with_capacity(public_der.len().saturating_add(15));

    ret.push(0); // certificate request context length
    ret.extend_from_slice(&certificates_len.to_be_bytes()[1..]);
    ret.extend_from_slice(&data_len.to_be_bytes()[1..]);
    ret.extend_from_slice(public_der);
    ret.extend_from_slice(&0_u16.to_be_bytes()); // extensions length

    Ok(ret)
}

/// # References
///
/// - [RFC 8446 Section 4.4.3](https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.3)
/// - [RFC 8446 Appendix B.3.3](https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.3.3)
///
/// ```text
/// struct {
///     SignatureScheme algorithm;
///     opaque signature<0..2^16-1>;
/// } CertificateVerify;
/// ```
#[derive(Debug)]
pub(crate) struct CertificateVerify {
    pub(crate) algorithm: SignatureScheme,
    pub(crate) signature: Vec<u8>,
}

impl CertificateVerify {
    pub fn new(algorithm: SignatureScheme, signature: &[u8]) -> Self {
        Self {
            algorithm,
            signature: signature.to_vec(),
        }
    }

    pub fn ser(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();

        buf.extend_from_slice(&self.algorithm.to_be_bytes());

        // unwrap should never occur, length is validated in constructors
        let signature_len: u16 = self.signature.len().try_into().unwrap();
        buf.extend_from_slice(&signature_len.to_be_bytes());

        buf.extend_from_slice(&self.signature);

        buf
    }

    pub fn decode(ctx: &mut DecodeContext) -> Result<Self, AlertDescription> {
        let algorithm: u16 = ctx.u16("algorithm", "SignatureScheme")?;
        let signature: Vec<u8> = ctx.vec16("signature", "opaque<0..2^16-1>", 0, 1)?;

        let algorithm: SignatureScheme = match SignatureScheme::try_from(algorithm) {
            Ok(algorithm) => algorithm,
            Err(e) => {
                log::error!("CertificateVerify.algorithm value of {e:#04X} is invalid");
                return Err(AlertDescription::IllegalParameter)?;
            }
        };

        ctx.ensure_fully_consumed()?;

        Ok(Self {
            algorithm,
            signature,
        })
    }
}
