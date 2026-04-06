use crate::{alert::AlertDescription, decode::DecodeContext};

/// # References
///
/// - [RFC 8446 Section 4.2.3](https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.3)
///
/// ```text
/// enum {
///     /* RSASSA-PKCS1-v1_5 algorithms */
///     rsa_pkcs1_sha256(0x0401),
///     rsa_pkcs1_sha384(0x0501),
///     rsa_pkcs1_sha512(0x0601),
///
///     /* ECDSA algorithms */
///     ecdsa_secp256r1_sha256(0x0403),
///     ecdsa_secp384r1_sha384(0x0503),
///     ecdsa_secp521r1_sha512(0x0603),
///
///     /* RSASSA-PSS algorithms with public key OID rsaEncryption */
///     rsa_pss_rsae_sha256(0x0804),
///     rsa_pss_rsae_sha384(0x0805),
///     rsa_pss_rsae_sha512(0x0806),
///
///     /* EdDSA algorithms */
///     ed25519(0x0807),
///     ed448(0x0808),
///
///     /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
///     rsa_pss_pss_sha256(0x0809),
///     rsa_pss_pss_sha384(0x080a),
///     rsa_pss_pss_sha512(0x080b),
///
///     /* Legacy algorithms */
///     rsa_pkcs1_sha1(0x0201),
///     ecdsa_sha1(0x0203),
///
///     /* Reserved Code Points */
///     private_use(0xFE00..0xFFFF),
///     (0xFFFF)
/// } SignatureScheme;
/// ```
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum SignatureScheme {
    // RSASSA-PKCS1-v1_5 algorithms
    rsa_pkcs1_sha256 = 0x0401,
    rsa_pkcs1_sha384 = 0x0501,
    rsa_pkcs1_sha512 = 0x0601,
    // ECDSA algorithms
    ecdsa_secp256r1_sha256 = 0x0403,
    ecdsa_secp384r1_sha384 = 0x0503,
    ecdsa_secp521r1_sha512 = 0x0603,
    // RSASSA-PSS algorithms with public key OID rsaEncryption
    rsa_pss_rsae_sha256 = 0x0804,
    rsa_pss_rsae_sha384 = 0x0805,
    rsa_pss_rsae_sha512 = 0x0806,
    // EdDSA algorithms
    ed25519 = 0x0807,
    ed448 = 0x0808,
    // RSASSA-PSS algorithms with public key OID RSASSA-PSS
    rsa_pss_pss_sha256 = 0x0809,
    rsa_pss_pss_sha384 = 0x080a,
    rsa_pss_pss_sha512 = 0x080b,
    // Legacy algorithms
    // rsa_pkcs1_sha1 = 0x0201,
    // ecdsa_sha1 = 0x0203,
}

impl SignatureScheme {
    pub(crate) fn to_be_bytes(self) -> [u8; 2] {
        u16::from(self).to_be_bytes()
    }

    pub(crate) fn default_signature_algorithms() -> Vec<Self> {
        vec![Self::ecdsa_secp256r1_sha256, Self::rsa_pss_rsae_sha256]
    }
}

impl From<SignatureScheme> for u16 {
    fn from(value: SignatureScheme) -> Self {
        value as u16
    }
}

impl TryFrom<u16> for SignatureScheme {
    type Error = u16;

    fn try_from(val: u16) -> Result<Self, Self::Error> {
        match val {
            x if x == (Self::rsa_pkcs1_sha256 as u16) => Ok(Self::rsa_pkcs1_sha256),
            x if x == (Self::rsa_pkcs1_sha384 as u16) => Ok(Self::rsa_pkcs1_sha384),
            x if x == (Self::rsa_pkcs1_sha512 as u16) => Ok(Self::rsa_pkcs1_sha512),
            x if x == (Self::ecdsa_secp256r1_sha256 as u16) => Ok(Self::ecdsa_secp256r1_sha256),
            x if x == (Self::ecdsa_secp384r1_sha384 as u16) => Ok(Self::ecdsa_secp384r1_sha384),
            x if x == (Self::ecdsa_secp521r1_sha512 as u16) => Ok(Self::ecdsa_secp521r1_sha512),
            x if x == (Self::rsa_pss_rsae_sha256 as u16) => Ok(Self::rsa_pss_rsae_sha256),
            x if x == (Self::rsa_pss_rsae_sha384 as u16) => Ok(Self::rsa_pss_rsae_sha384),
            x if x == (Self::rsa_pss_rsae_sha512 as u16) => Ok(Self::rsa_pss_rsae_sha512),
            x if x == (Self::ed25519 as u16) => Ok(Self::ed25519),
            x if x == (Self::ed448 as u16) => Ok(Self::ed448),
            x if x == (Self::rsa_pss_pss_sha256 as u16) => Ok(Self::rsa_pss_pss_sha256),
            x if x == (Self::rsa_pss_pss_sha384 as u16) => Ok(Self::rsa_pss_pss_sha384),
            x if x == (Self::rsa_pss_pss_sha512 as u16) => Ok(Self::rsa_pss_pss_sha512),
            _ => Err(val),
        }
    }
}

/// # References
///
/// - [RFC 8446 Appendix B.3.1.3](https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.3.1.3)
///
/// ```text
/// struct {
///     SignatureScheme supported_signature_algorithms<2..2^16-2>;
/// } SignatureSchemeList;
/// ```
pub(crate) fn decode_signature_scheme_list(
    ctx: &mut DecodeContext,
) -> Result<Vec<SignatureScheme>, AlertDescription> {
    ctx.begin_vec16(
        "supported_signature_algorithms",
        "SignatureScheme<2..2^16-2>",
        2,
        2,
    )?;

    let mut ret: Vec<SignatureScheme> = Vec::new();
    while ctx.remaining() > 0 {
        let signature_scheme: u16 = ctx.u16("signature_scheme", "SignatureScheme")?;

        match SignatureScheme::try_from(signature_scheme) {
            Ok(signature_scheme) => ret.push(signature_scheme),
            Err(val) => {
                log::info!("Ignoring unknown SignatureScheme 0x{val:04x}");
            }
        }
    }

    ctx.end_vec()?;

    Ok(ret)
}

pub(crate) fn ser_signature_scheme_list(schemes: &[SignatureScheme]) -> Vec<u8> {
    let scheme_len: u16 = schemes
        .len()
        .checked_mul(2)
        .expect("Too many signature schemes")
        .try_into()
        .expect("Too many signature schemes");

    let mut ret: Vec<u8> = Vec::new();
    ret.extend_from_slice(scheme_len.to_be_bytes().as_ref());
    schemes
        .iter()
        .for_each(|ss| ret.extend_from_slice(ss.to_be_bytes().as_ref()));

    ret
}
