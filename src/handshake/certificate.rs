use crate::{AlertDescription, handshake::ServerHelloExtension};

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
pub struct CertificateEntry {
    data: Vec<u8>,
    extensions: Vec<ServerHelloExtension>,
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
///
/// struct {
///     opaque certificate_request_context<0..2^8-1>;
///     CertificateEntry certificate_list<0..2^24-1>;
/// } Certificate;
/// ```
pub struct Certificate {
    data: Vec<u8>,
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
    ret.extend_from_slice(&[0, 0]); // extensions length

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
pub struct CertificateVerify {
    algorithm: SignatureScheme,
    signature: Vec<u8>,
}

impl CertificateVerify {
    pub fn from_ecdsa_secp256r1_sha256(signature: &[u8]) -> Self {
        Self {
            algorithm: SignatureScheme::ecdsa_secp256r1_sha256,
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
}
