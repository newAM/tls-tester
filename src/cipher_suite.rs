/// Cipher Suites.
///
/// # References
///
/// * [RFC 8446 Appendix B.4](https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.4)
/// * [RFC 8446 Section 9.1](https://datatracker.ietf.org/doc/html/rfc8446#section-9.1)
///
/// +------------------------------+----------------+
/// | Description                  | Value          |
/// +------------------------------+----------------+
/// | TLS_AES_128_GCM_SHA256       | `[0x13, 0x01]` |
/// | TLS_AES_256_GCM_SHA384       | `[0x13, 0x02]` |
/// | TLS_CHACHA20_POLY1305_SHA256 | `[0x13, 0x03]` |
/// | TLS_AES_128_CCM_SHA256       | `[0x13, 0x04]` |
/// | TLS_AES_128_CCM_8_SHA256     | `[0x13, 0x05]` |
/// +------------------------------+----------------+
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
#[non_exhaustive]
#[allow(non_camel_case_types)]
pub enum CipherSuite {
    TLS_AES_128_GCM_SHA256 = 0x1301, // required
    TLS_AES_256_GCM_SHA384 = 0x1302,
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303,
    TLS_AES_128_CCM_SHA256 = 0x1304,
    TLS_AES_128_CCM_8_SHA256 = 0x1305,
}

impl From<CipherSuite> for u16 {
    #[inline]
    fn from(cipher_suite: CipherSuite) -> Self {
        cipher_suite as u16
    }
}

impl TryFrom<u16> for CipherSuite {
    type Error = u16;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            x if x == (Self::TLS_AES_128_GCM_SHA256 as u16) => Ok(Self::TLS_AES_128_GCM_SHA256),
            x if x == (Self::TLS_AES_256_GCM_SHA384 as u16) => Ok(Self::TLS_AES_256_GCM_SHA384),
            x if x == (Self::TLS_CHACHA20_POLY1305_SHA256 as u16) => {
                Ok(Self::TLS_CHACHA20_POLY1305_SHA256)
            }
            x if x == (Self::TLS_AES_128_CCM_SHA256 as u16) => Ok(Self::TLS_AES_128_CCM_SHA256),
            x if x == (Self::TLS_AES_128_CCM_8_SHA256 as u16) => Ok(Self::TLS_AES_128_CCM_8_SHA256),
            _ => Err(value),
        }
    }
}
