use crate::{AlertDescription, parse};

/// # References
///
/// * [RFC 8446 Section 4.2.7](https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.7)
/// * [RFC 8446 Section 9.1](https://datatracker.ietf.org/doc/html/rfc8446#section-9.1)
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
            x => Err(x),
        }
    }
}

pub fn deser_named_group_list(b: &[u8]) -> Result<Vec<NamedGroup>, AlertDescription> {
    let (_, named_group_list): (_, &[u8]) =
        parse::vec16("NamedGroupList named_group_list", b, 2, 2)?;

    let mut ret: Vec<NamedGroup> = Vec::with_capacity(named_group_list.len() / 2);
    for chunk in named_group_list.chunks_exact(2) {
        let group: u16 = u16::from_be_bytes(chunk.try_into().unwrap());

        match NamedGroup::try_from(group) {
            Ok(n) => ret.push(n),
            Err(e) => {
                log::error!("Unknown NamedGroup value 0x{e:04x}");
                return Err(AlertDescription::IllegalParameter);
            }
        }
    }

    Ok(ret)
}
