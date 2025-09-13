use crate::{alert::AlertDescription, parse};

/// # References
///
/// - [RFC 8446 Section 4.2.7](https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.7)
/// - [RFC 8446 Section 9.1](https://datatracker.ietf.org/doc/html/rfc8446#section-9.1)
/// - [draft-ietf-tls-ecdhe-mlkem-00](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/)
#[repr(u16)]
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types, dead_code)]
pub(crate) enum NamedGroup {
    // Elliptic Curve Groups (ECDHE)
    secp256r1 = 0x0017, // required
    secp384r1 = 0x0018,
    secp521r1 = 0x0019,
    x25519 = 0x001D,
    x448 = 0x001E,
    // Finite Field Groups (DHE)
    ffdhe2048 = 0x0100,
    ffdhe3072 = 0x0101,
    ffdhe4096 = 0x0102,
    ffdhe6144 = 0x0103,
    ffdhe8192 = 0x0104,
    // Post-quantum hybrid
    SecP256r1MLKEM768 = 0x11EB,
    X25519MLKEM768 = 0x11EC,
    SecP384r1MLKEM1024 = 0x11ED,
    // Reserved Code Points
    // ffdhe_private_use(0x01FC..0x01FF),
    // ecdhe_private_use(0xFE00..0xFEFF),
}

impl NamedGroup {
    pub const fn msb(self) -> u8 {
        ((self as u16) >> 8) as u8
    }

    pub const fn lsb(self) -> u8 {
        self as u8
    }

    pub const fn to_be_bytes(self) -> [u8; 2] {
        (self as u16).to_be_bytes()
    }

    pub fn from_be_bytes(bytes: [u8; 2]) -> Result<Self, u16> {
        Self::try_from(u16::from_be_bytes(bytes))
    }
}

impl TryFrom<u16> for NamedGroup {
    type Error = u16;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            x if x == (Self::secp256r1 as u16) => Ok(Self::secp256r1),
            x if x == (Self::secp384r1 as u16) => Ok(Self::secp384r1),
            x if x == (Self::secp521r1 as u16) => Ok(Self::secp521r1),
            x if x == (Self::x25519 as u16) => Ok(Self::x25519),
            x if x == (Self::x448 as u16) => Ok(Self::x448),
            x if x == (Self::ffdhe2048 as u16) => Ok(Self::ffdhe2048),
            x if x == (Self::ffdhe3072 as u16) => Ok(Self::ffdhe3072),
            x if x == (Self::ffdhe4096 as u16) => Ok(Self::ffdhe4096),
            x if x == (Self::ffdhe6144 as u16) => Ok(Self::ffdhe6144),
            x if x == (Self::ffdhe8192 as u16) => Ok(Self::ffdhe8192),
            x if x == (Self::SecP256r1MLKEM768 as u16) => Ok(Self::SecP256r1MLKEM768),
            x if x == (Self::X25519MLKEM768 as u16) => Ok(Self::X25519MLKEM768),
            x if x == (Self::SecP384r1MLKEM1024 as u16) => Ok(Self::SecP384r1MLKEM1024),
            x => Err(x),
        }
    }
}

/// # References
///
/// - [RFC 8446 Appendix B.3.1.4](https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.3.1.4)
///
/// ```text
/// struct {
///     NamedGroup named_group_list<2..2^16-1>;
/// } NamedGroupList;
/// ```
pub(crate) fn deser_named_group_list(b: &[u8]) -> Result<Vec<NamedGroup>, AlertDescription> {
    let (_, named_group_list): (_, &[u8]) =
        parse::vec16("NamedGroupList named_group_list", b, 2, 2)?;

    let mut ret: Vec<NamedGroup> = Vec::with_capacity(named_group_list.len() / 2);
    for chunk in named_group_list.chunks_exact(2) {
        let group: u16 = u16::from_be_bytes(chunk.try_into().unwrap());

        match NamedGroup::try_from(group) {
            Ok(n) => ret.push(n),
            Err(e) => {
                // https://datatracker.ietf.org/doc/html/rfc8446#section-9.3
                // A server receiving a ClientHello MUST correctly ignore all
                // unrecognized cipher suites, extensions, and other parameters.
                // Otherwise, it may fail to interoperate with newer clients.
                log::warn!("Unknown NamedGroup value 0x{e:04x}");
            }
        }
    }

    Ok(ret)
}

pub(crate) fn ser_named_group_list() -> Vec<u8> {
    let mut ret: Vec<u8> = Vec::new();

    ret.extend_from_slice(2_u16.to_be_bytes().as_ref());
    ret.extend_from_slice(NamedGroup::secp256r1.to_be_bytes().as_ref());

    ret
}
