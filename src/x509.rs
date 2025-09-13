//! # References
//!
//! - [A Warm Welcome to ASN.1 and DER](https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/)
//! - [A Layman's Guide to a Subset of ASN.1, BER, and DER](https://luca.ntop.org/Teaching/Appunti/asn1.html)

// hex string for example
// https://lapo.it/asn1js/#MIIBfTCCASOgAwIBAgIUC8omRPq3ArTh5TMajfWXhSgn8jEwCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI1MDgzMDIxMjExM1oXDTM1MDgyODIxMjExM1owFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzfoCZVZzX15nttNicIoP6Z5XqCbw_0YW-jrV0ubU9KW6Ul7ttvx5yy0hw9_ykzZHPfAbP5vSbzgXQ1C3Ni-NBaNTMFEwHQYDVR0OBBYEFNx6TDo0jekr5UpvOZweKNCN0fjjMB8GA1UdIwQYMBaAFNx6TDo0jekr5UpvOZweKNCN0fjjMA8GA1UdEwEB_wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhAIXRACeQSoJxDWt1aMX2ngI35Lk_E1L6fddABTGNrHouAiBZEjwxUu9D15OOHzpGeXxXtngSG1cFLXg1CDZsAHsXog
// 3082017d30820123a00302010202140bca2644fab702b4e1e5331a8df597852827f231300a06082a8648ce3d04030230143112301006035504030c096c6f63616c686f7374301e170d3235303833303231323131335a170d3335303832383231323131335a30143112301006035504030c096c6f63616c686f73743059301306072a8648ce3d020106082a8648ce3d03010703420004cdfa026556735f5e67b6d362708a0fe99e57a826f0ff4616fa3ad5d2e6d4f4a5ba525eedb6fc79cb2d21c3dff29336473df01b3f9bd26f38174350b7362f8d05a3533051301d0603551d0e04160414dc7a4c3a348de92be54a6f399c1e28d08dd1f8e3301f0603551d23041830168014dc7a4c3a348de92be54a6f399c1e28d08dd1f8e3300f0603551d130101ff040530030101ff300a06082a8648ce3d040302034800304502210085d10027904a82710d6b7568c5f69e0237e4b93f1352fa7dd74005318dac7a2e022059123c3152ef43d7938e1f3a46797c57b678121b57052d783508366c007b17a2

use p256::ecdsa::signature::Verifier as _;
use rsa::{pkcs1::DecodeRsaPublicKey as _, pkcs8::AssociatedOid};
use sha2::Digest;
use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::Add,
};

use jiff::{Zoned, civil::DateTime, tz::TimeZone};

use crate::{AlertDescription, parse};

/// Identifier octet
///
/// # References
///
/// - X.690 Section 8.1.2.2
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Class {
    Universal = 0b00,
    Application = 0b01,
    ContextSpecific = 0b10,
    Private = 0b11,
}

/// Primitive or constructed bit.
///
/// # References
///
/// - X.690 Section 8.1.2.5
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Pc {
    /// Atomic type that cannot be broken down into smaller components.
    Primitive = 0b0,
    /// Composite type that consists of other types.
    Constructed = 0b1,
}

impl Pc {
    /// Returns `true` if the pc is [`Primitive`].
    ///
    /// [`Primitive`]: Pc::Primitive
    #[must_use]
    pub(crate) fn is_primitive(&self) -> bool {
        matches!(self, Self::Primitive)
    }

    /// Returns `true` if the pc is [`Constructed`].
    ///
    /// [`Constructed`]: Pc::Constructed
    #[must_use]
    pub(crate) fn is_constructed(&self) -> bool {
        matches!(self, Self::Constructed)
    }
}

/// X.609 identifier
///
/// # References
///
/// - X.690 Section 8.1.2 Identifier octets
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Tag {
    /// `BOOLEAN` tag: `1`.
    Boolean,
    /// `INTEGER` tag: `2`.
    Integer,
    /// `BIT STRING` tag: `3`.
    BitString,
    /// `OCTET STRING` tag: `4`.
    OctetString,
    /// `NULL` tag: `5`.
    Null,
    /// `OBJECT IDENTIFIER` tag: `6`.
    ObjectIdentifier,
    /// `REAL` tag: `9`.
    Real,
    /// `ENUMERATED` tag: `10`.
    Enumerated,
    /// `UTF8String` tag: `12`.
    Utf8String,
    /// `RELATIVE OID` tag: `13`.
    RelativeOid,
    /// `SEQUENCE` tag: `16`.
    Sequence,
    /// `SET` and `SET OF` tag: `17`.
    Set,
    /// `NumericString` tag: `18`.
    NumericString,
    /// `PrintableString` tag: `19`.
    PrintableString,
    /// `TeletexString` tag: `20`.
    TeletexString,
    /// `VideotexString` tag: `21`.
    VideotexString,
    /// `IA5String` tag: `22`.
    Ia5String,
    /// `UTCTime` tag: `23`.
    UtcTime,
    /// `GeneralizedTime` tag: `24`.
    GeneralizedTime,
    /// `VisibleString` tag: `26`.
    VisibleString,
    /// `GeneralString` tag: `27`.
    GeneralString,
    /// `BMPString` tag: `28`.
    UniversalString,
    /// `BMPString` tag: `30`.
    BmpString,
    /// Everything else.
    Unknown(u8),
}

impl From<Tag> for u8 {
    fn from(value: Tag) -> Self {
        match value {
            Tag::Boolean => 1,
            Tag::Integer => 2,
            Tag::BitString => 3,
            Tag::OctetString => 4,
            Tag::Null => 5,
            Tag::ObjectIdentifier => 6,
            Tag::Real => 9,
            Tag::Enumerated => 10,
            Tag::Utf8String => 12,
            Tag::RelativeOid => 13,
            Tag::Sequence => 16,
            Tag::Set => 17,
            Tag::NumericString => 18,
            Tag::PrintableString => 19,
            Tag::TeletexString => 20,
            Tag::VideotexString => 21,
            Tag::Ia5String => 22,
            Tag::UtcTime => 23,
            Tag::GeneralizedTime => 24,
            Tag::VisibleString => 26,
            Tag::GeneralString => 27,
            Tag::UniversalString => 28,
            Tag::BmpString => 30,
            Tag::Unknown(other) => other,
        }
    }
}

/// Identifier octet
///
/// # References
///
/// - X.690 Section 8.1.2 Identifier octets
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Identifier {
    class: Class,
    pc: Pc,
    tag: Tag,
}

impl Identifier {
    pub const SEQUENCE: Self = Self {
        class: Class::Universal,
        pc: Pc::Constructed,
        tag: Tag::Sequence,
    };

    pub const SET: Self = Self {
        class: Class::Universal,
        pc: Pc::Constructed,
        tag: Tag::Set,
    };

    pub const BITSTRING: Self = Self {
        class: Class::Universal,
        pc: Pc::Primitive,
        tag: Tag::BitString,
    };

    pub const UTCTIME: Self = Self {
        class: Class::Universal,
        pc: Pc::Primitive,
        tag: Tag::UtcTime,
    };

    pub const GENERALIZEDTIME: Self = Self {
        class: Class::Universal,
        pc: Pc::Primitive,
        tag: Tag::GeneralizedTime,
    };

    pub const UTF8STRING: Self = Self {
        class: Class::Universal,
        pc: Pc::Primitive,
        tag: Tag::Utf8String,
    };

    pub const PRINTABLESTRING: Self = Self {
        class: Class::Universal,
        pc: Pc::Primitive,
        tag: Tag::PrintableString,
    };

    pub const OBJECTIDENTIFIER: Self = Self {
        class: Class::Universal,
        pc: Pc::Primitive,
        tag: Tag::ObjectIdentifier,
    };

    pub const INTEGER: Self = Self {
        class: Class::Universal,
        pc: Pc::Primitive,
        tag: Tag::Integer,
    };

    pub const NULL: Self = Self {
        class: Class::Universal,
        pc: Pc::Primitive,
        tag: Tag::Null,
    };

    pub const OCTETSTRING: Self = Self {
        class: Class::Universal,
        pc: Pc::Primitive,
        tag: Tag::OctetString,
    };

    pub const BOOLEAN: Self = Self {
        class: Class::Universal,
        pc: Pc::Primitive,
        tag: Tag::Boolean,
    };
}

impl From<u8> for Identifier {
    fn from(val: u8) -> Self {
        let tag_raw: u8 = val & 0x1F;
        let pc_raw: u8 = (val >> 5) & 0x1;
        let class_raw: u8 = (val >> 7) & 0x3;

        let class: Class = match class_raw {
            0b00 => Class::Universal,
            0b01 => Class::Application,
            0b10 => Class::ContextSpecific,
            0b11 => Class::Private,
            _ => unreachable!(),
        };

        let pc: Pc = match pc_raw {
            0b0 => Pc::Primitive,
            0b1 => Pc::Constructed,
            _ => unreachable!(),
        };

        let tag: Tag = match tag_raw {
            1 => Tag::Boolean,
            2 => Tag::Integer,
            3 => Tag::BitString,
            4 => Tag::OctetString,
            5 => Tag::Null,
            6 => Tag::ObjectIdentifier,
            9 => Tag::Real,
            10 => Tag::Enumerated,
            12 => Tag::Utf8String,
            13 => Tag::RelativeOid,
            16 => Tag::Sequence,
            17 => Tag::Set,
            18 => Tag::NumericString,
            19 => Tag::PrintableString,
            20 => Tag::TeletexString,
            21 => Tag::VideotexString,
            22 => Tag::Ia5String,
            23 => Tag::UtcTime,
            24 => Tag::GeneralizedTime,
            26 => Tag::VisibleString,
            27 => Tag::GeneralString,
            28 => Tag::UniversalString,
            30 => Tag::BmpString,
            other => Tag::Unknown(other),
        };

        Self { class, pc, tag }
    }
}

/// DER encoding
///
/// # References
///
/// - X.690 Section 8.1.1 Structure of an encoding
#[derive(Debug, Clone)]
pub(crate) struct Encoding {
    identifier: Identifier,
    content: Vec<u8>,
}

impl Encoding {
    pub fn deser<'a>(name: &str, b: &'a [u8]) -> Option<(&'a [u8], Self)> {
        let (b, id) = parse::u8(name, b).ok()?;
        let identifier: Identifier = Identifier::from(id);

        let length_debug: String = format!("{name} with {identifier:?}");

        let (b, len_octet) = parse::u8(&length_debug, b).ok()?;

        // Reference section 8.1.3, Length octets
        // - indefinite form is forbidden by DER
        //
        // definite short form and long form:
        // - short: bit 8 is zero, 7-1 to encode number of bytes in contents
        // - long: bit 8 is one, 7-1 to encode number of bytes in length

        if len_octet == 0xFF {
            // 8.1.3.5 "the value 11111111 2 shall not be used"
            log::error!("{length_debug} uses a forbidden value of 0xFF");
            return None;
        }

        let long_form: bool = len_octet & 0x80 == 0x80;
        let encoding_len_or_len_len: u8 = len_octet & 0x7F;

        let (b, len): (_, u32) = if long_form {
            let len_len: u8 = encoding_len_or_len_len;

            let (b, len_buf) = parse::n(&length_debug, b, len_len.into()).ok()?;

            // TLS limits certificates to 2**24, ensure all bytes preceding the
            // last three are zero
            if let Some(high_bytes) = len_buf.get(3..)
                && high_bytes.iter().any(|&x| x != 0)
            {
                log::error!("{length_debug} exceeds maximum of 2**24");
                return None;
            }

            let mut len: u32 = 0;
            for (i, &byte) in len_buf.iter().rev().enumerate() {
                len |= u32::from(byte) << i.saturating_mul(8);
            }

            (b, len)
        } else {
            (b, encoding_len_or_len_len.into())
        };

        let content_debug: String = format!("{name} with {identifier:?} of length {len}");

        let (remain, content) = parse::n(
            &content_debug,
            b,
            len.try_into().expect("unsupported architecture"),
        )
        .ok()?;

        Some((
            remain,
            Self {
                identifier,
                content: content.into(),
            },
        ))
    }

    pub fn deser_bool<'a>(name: &str, b: &'a [u8]) -> Option<(&'a [u8], bool)> {
        let (b, encoding) = Self::deser_expected(Identifier::BOOLEAN, name, b)?;

        let val: bool = Self::deser_bool_from_encoding(encoding, name)?;

        Some((b, val))
    }

    pub fn deser_bool_from_encoding(encoding: Encoding, name: &str) -> Option<bool> {
        match encoding.content.first() {
            Some(0x00) => Some(false),
            Some(0xFF) => Some(true),
            Some(val) => {
                log::error!("{name} boolean value invalid, expected 0x00 or 0xFF, got 0x{val:02x}");
                None
            }
            None => {
                log::error!("{name} boolean is missing a value byte");
                None
            }
        }
    }

    pub fn deser_expected<'a>(
        identifier: Identifier,
        name: &str,
        b: &'a [u8],
    ) -> Option<(&'a [u8], Self)> {
        let (b, encoding) = Encoding::deser(name, b)?;

        if encoding.identifier != identifier {
            log::error!(
                "{name} expected identifier octet {:?} got {:?} of length {}",
                identifier,
                encoding.identifier,
                encoding.content.len(),
            );
            return None;
        }

        Some((b, encoding))
    }

    pub fn deser_expected2<'a>(
        identifier1: Identifier,
        identifier2: Identifier,
        name: &str,
        b: &'a [u8],
    ) -> Option<(&'a [u8], Self)> {
        let (b, encoding) = Encoding::deser(name, b)?;

        if encoding.identifier != identifier1 && encoding.identifier != identifier2 {
            log::error!(
                "{name} expected identifier octet {:?} or {:?} got {:?} of length {}",
                identifier1,
                identifier2,
                encoding.identifier,
                encoding.content.len(),
            );
            return None;
        }

        Some((b, encoding))
    }

    pub fn deser_set<'a>(
        inner_identifier: Identifier,
        name: &str,
        b: &'a [u8],
    ) -> Option<(&'a [u8], Vec<Self>)> {
        let (remain, encoding) = Encoding::deser_expected(Identifier::SET, name, b)?;

        let mut encoding_data: &[u8] = &encoding.content;
        let mut encodings: Vec<Encoding> = Vec::new();
        let mut i: usize = 0;

        while !encoding_data.is_empty() {
            let loop_name: String = format!("{name}[{i}]");
            let (loop_b, encoding) =
                Self::deser_expected(inner_identifier, &loop_name, encoding_data)?;
            encodings.push(encoding);
            encoding_data = loop_b;
            i += 1;
        }

        Some((remain, encodings))
    }

    // printable string or utf-8 string
    pub fn deser_string<'a>(name: &str, b: &'a [u8]) -> Option<(&'a [u8], String)> {
        let (b, encoding) = Encoding::deser_expected2(
            Identifier::UTF8STRING,
            Identifier::PRINTABLESTRING,
            name,
            b,
        )?;

        if encoding.identifier == Identifier::UTF8STRING {
            match String::from_utf8(encoding.content) {
                Ok(s) => Some((b, s)),
                Err(e) => {
                    log::error!("{name} is not a valid UTF-8 string: {e:?}");
                    None
                }
            }
        } else {
            Some((b, String::from_utf8_lossy(&encoding.content).to_string()))
        }
    }

    pub fn deser_utf8_string<'a>(name: &str, b: &'a [u8]) -> Option<(&'a [u8], String)> {
        let (b, encoding) = Encoding::deser_expected(Identifier::UTF8STRING, name, b)?;

        match String::from_utf8(encoding.content) {
            Ok(s) => Some((b, s)),
            Err(e) => {
                log::error!("{name} is not a valid UTF-8 string: {e:?}");
                None
            }
        }
    }

    /// # References
    ///
    /// - [RFC 5280 Section 4.1](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1)
    ///
    /// ```text
    /// Time ::= CHOICE {
    ///      utcTime        UTCTime,
    ///      generalTime    GeneralizedTime }
    /// ```
    pub fn deser_time<'a>(name: &str, b: &'a [u8]) -> Option<(&'a [u8], Zoned)> {
        let (b, encoding) =
            Encoding::deser_expected2(Identifier::GENERALIZEDTIME, Identifier::UTCTIME, name, b)?;

        let timefmt: &str = match encoding.identifier {
            Identifier::GENERALIZEDTIME => "%Y%m%d%H%M%SZ",
            Identifier::UTCTIME => "%y%m%d%H%M%SZ",
            _ => unreachable!(),
        };

        let content: String = String::from_utf8_lossy(&encoding.content).to_string();

        let datetime = match DateTime::strptime(timefmt, &content) {
            Ok(datetime) => datetime,
            Err(e) => {
                log::error!("{name} with content '{content}' is not a valid UTC time: {e:?}");
                return None;
            }
        };

        let timestamp = datetime.to_zoned(TimeZone::UTC).unwrap();

        Some((b, timestamp))
    }
}

// 2.5.4.10 is organizationName (printable string)
// 2.5.4.6 countryName (printable string)
// 2.5.4.3 commonName (printable string)
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct ObjectIdentifier {
    oid: Vec<u8>,
    repr: String,
}

impl fmt::Display for ObjectIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", &self.repr)
    }
}

impl ObjectIdentifier {
    // https://learn.microsoft.com/en-gb/windows/win32/seccertenroll/about-object-identifier
    fn decode(name: &str, content: Vec<u8>) -> Option<Self> {
        let mut repr: String = String::new();

        if let Some(byte0) = content.first() {
            let node1: u8 = byte0 % 0x28;
            let node0: u8 = (byte0 - node1) / 0x28;
            repr.push_str(&format!("{node0}.{node1}"));
        } else {
            log::error!("{name} must not be empty");
            return None;
        }

        let mut acc: Option<u32> = None;

        for byte in content.iter().skip(1) {
            let is_long: bool = byte & 0x80 == 0x80;
            if let Some(mut val) = acc.take() {
                val <<= 7;
                val |= u32::from(byte & 0x7F);
                if is_long {
                    acc = Some(val);
                } else {
                    repr.push_str(&format!(".{val}"));
                }
            } else if is_long {
                acc = Some(u32::from(byte & 0x7F));
            } else {
                repr.push_str(&format!(".{}", *byte));
            }
        }

        if acc.is_some() {
            log::error!("{name} has an unterminated multi-byte encoding");
            return None;
        }

        Some(Self { oid: content, repr })
    }

    pub fn deser<'a>(name: &str, b: &'a [u8]) -> Option<(&'a [u8], Self)> {
        let (b, encoding) = Encoding::deser_expected(Identifier::OBJECTIDENTIFIER, name, b)?;

        Some((b, Self::decode(name, encoding.content)?))
    }

    pub fn deser_or_null<'a>(name: &str, b: &'a [u8]) -> Option<(&'a [u8], Option<Self>)> {
        let (b, encoding) =
            Encoding::deser_expected2(Identifier::OBJECTIDENTIFIER, Identifier::NULL, name, b)?;

        if encoding.identifier == Identifier::NULL {
            if !encoding.content.is_empty() {
                log::error!(
                    "{name} with a null identifer has a content length of {}",
                    encoding.content.len()
                );
                return None;
            }
            Some((b, None))
        } else {
            Some((b, Some(Self::decode(name, encoding.content)?)))
        }
    }
}

#[cfg(test)]
mod object_identifier_tests {
    use super::ObjectIdentifier;

    #[test]
    fn object_identifier() {
        let content: Vec<u8> = vec![0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
        let oid: ObjectIdentifier = ObjectIdentifier::decode("test", content).unwrap();
        assert_eq!(oid.repr, "1.2.840.10045.2.1");

        let content: Vec<u8> = vec![0x2B, 0x81, 0x04, 0x00, 0x22];
        let oid: ObjectIdentifier = ObjectIdentifier::decode("test", content).unwrap();
        assert_eq!(oid.repr, "1.3.132.0.34");

        let content: Vec<u8> = vec![0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
        let oid: ObjectIdentifier = ObjectIdentifier::decode("test", content).unwrap();
        assert_eq!(oid.repr, "1.2.840.113549.1.1.1");
    }
}

/// # References
///
/// - [RFC 5280 Section 4.1.2.4](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4)
///
/// ```text
/// AttributeTypeAndValue ::= SEQUENCE {
///   type     AttributeType,
///   value    AttributeValue }
///
/// AttributeType ::= OBJECT IDENTIFIER
///
/// AttributeValue ::= ANY -- DEFINED BY AttributeType
///
/// DirectoryString ::= CHOICE {
///       teletexString           TeletexString (SIZE (1..MAX)),
///       printableString         PrintableString (SIZE (1..MAX)),
///       universalString         UniversalString (SIZE (1..MAX)),
///       utf8String              UTF8String (SIZE (1..MAX)),
///       bmpString               BMPString (SIZE (1..MAX)) }
/// ```
#[derive(Debug, Clone)]
pub(crate) struct AttributeTypeAndValue {
    oid: ObjectIdentifier,
    value: String,
}

impl AttributeTypeAndValue {
    pub fn deser<'a>(name: &str, b: &'a [u8]) -> Option<(&'a [u8], Self)> {
        let (b, oid) = ObjectIdentifier::deser(&format!("{name}.type"), b)?;
        let value_name: String = format!("{name}.value");

        let (b, encoding) = Encoding::deser(&value_name, b)?;

        if encoding.identifier.class != Class::Universal {
            log::error!(
                "{name} expected identifier class {:?} got {:?}",
                Class::Universal,
                encoding.identifier.class
            );
            return None;
        }

        if encoding.identifier.pc != Pc::Primitive {
            log::error!(
                "{name} expected identifier pc {:?} got {:?}",
                Pc::Primitive,
                encoding.identifier.pc
            );
            return None;
        }

        let value: String = match encoding.identifier.tag {
            Tag::Utf8String => match String::from_utf8(encoding.content) {
                Ok(s) => s,
                Err(e) => {
                    log::error!("{name} is not a valid UTF-8 string: {e:?}");
                    return None;
                }
            },
            Tag::PrintableString | Tag::TeletexString => {
                String::from_utf8_lossy(&encoding.content).to_string()
            }
            Tag::UniversalString => todo!(),
            Tag::BmpString => todo!(),
            // not in the spec but some CA's use it for DirectoryString anyway
            Tag::Ia5String => {
                log::warn!("{name} uses an unsupported tag Ia5String for DirectoryString");
                String::from_utf8_lossy(&encoding.content).to_string()
            }
            tag => {
                log::error!("{name} unsupported tag for DirectoryString: {tag:?}");
                return None;
            }
        };

        Some((b, Self { oid, value }))
    }
}

/// # References
///
/// - [RFC 5280 Section 4.1.2.4](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4)
///
/// ```text
/// Name ::= CHOICE { -- only one possibility for now --
///   rdnSequence  RDNSequence }
///
/// RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
///
/// RelativeDistinguishedName ::=
///   SET SIZE (1..MAX) OF AttributeTypeAndValue
/// ```
#[derive(Debug, Clone)]
pub(crate) struct Name {
    rdn_sequence: Vec<AttributeTypeAndValue>,
}

impl Name {
    pub fn deser<'a>(name: &str, b: &'a [u8]) -> Option<(&'a [u8], Self)> {
        let (remain, encoding) = Encoding::deser_expected(Identifier::SEQUENCE, name, b)?;

        let rdn_name: String = format!("{name}.rdnSequence");

        let mut rdn_sequence: Vec<AttributeTypeAndValue> = Vec::new();

        let mut content: &[u8] = encoding.content.as_ref();
        let mut x: usize = 0;

        while !content.is_empty() {
            let (local_b, set) = Encoding::deser_set(Identifier::SEQUENCE, &rdn_name, content)?;
            content = local_b;

            for (y, rdn) in set.iter().enumerate() {
                let loop_name: String = format!("{name}[{x}][{y}]");
                let (_, atav) = AttributeTypeAndValue::deser(&loop_name, &rdn.content)?;
                rdn_sequence.push(atav);
            }

            x += 1;
        }

        Some((remain, Self { rdn_sequence }))
    }

    /// Returns the commonName if present in the sequence
    pub fn common_name(&self) -> Option<String> {
        Some(
            self.rdn_sequence
                .iter()
                .find(|atav| atav.oid.repr.as_str() == "2.5.4.3")?
                .value
                .clone(),
        )
    }
}

/// # References
///
/// - [RFC 5280 Section 4.1](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1)
///
/// ```text
/// Validity ::= SEQUENCE {
///      notBefore      Time,
///      notAfter       Time }
/// ```
#[derive(Debug, Clone)]
pub(crate) struct Validity {
    not_before: Zoned,
    not_after: Zoned,
}

impl Validity {
    pub fn deser(b: &[u8]) -> Option<(&[u8], Self)> {
        let (remain, validity) = Encoding::deser_expected(
            Identifier::SEQUENCE,
            "Certificate.tbsCertificate.validity",
            b,
        )?;

        let (b, not_before) = Encoding::deser_time(
            "Certificate.tbsCertificate.validity.notBefore",
            &validity.content,
        )?;

        let (b, not_after) =
            Encoding::deser_time("Certificate.tbsCertificate.validity.notAfter", b)?;

        if !b.is_empty() {
            log::error!(
                "Certificate.tbsCertificate.validity contains {} bytes of extra data",
                b.len()
            );
            return None;
        }

        Some((
            remain,
            Self {
                not_before,
                not_after,
            },
        ))
    }
}

#[derive(Debug, Clone)]
pub enum PublicKey {
    Prime256v1(p256::ecdsa::VerifyingKey),
    Secp384r1(p384::ecdsa::VerifyingKey),
    Rsa(rsa::RsaPublicKey),
}

impl PublicKey {
    pub(crate) fn verify<D>(
        &self,
        to_verify: &[u8],
        signature: &[u8],
    ) -> Result<(), AlertDescription>
    where
        D: Digest + AssociatedOid,
    {
        let is_ok: bool = match self {
            PublicKey::Prime256v1(verifying_key) => {
                let signature: p256::ecdsa::Signature =
                    match p256::ecdsa::Signature::from_der(signature) {
                        Ok(signature) => signature,
                        Err(e) => {
                            log::error!(
                                "Certificate signature format does not match prime256v1: {e:?}"
                            );
                            return Err(AlertDescription::BadCertificate)?;
                        }
                    };

                let result = verifying_key.verify(to_verify, &signature);

                if let Err(e) = result {
                    log::error!("Verification of certificate prime256v1 signature failed: {e:?}");
                    false
                } else {
                    true
                }
            }
            PublicKey::Secp384r1(verifying_key) => {
                let signature: p384::ecdsa::Signature =
                    match p384::ecdsa::Signature::from_der(signature) {
                        Ok(signature) => signature,
                        Err(e) => {
                            log::error!(
                                "Certificate signature format does not match secp384r1: {e:?}"
                            );
                            return Err(AlertDescription::BadCertificate)?;
                        }
                    };

                let result = verifying_key.verify(to_verify, &signature);

                if let Err(e) = result {
                    log::error!("Verification of certificate secp384r1 signature failed: {e:?}");
                    false
                } else {
                    true
                }
            }
            PublicKey::Rsa(public_key) => {
                let signature: rsa::pkcs1v15::Signature = match rsa::pkcs1v15::Signature::try_from(
                    signature,
                ) {
                    Ok(signature) => signature,
                    Err(e) => {
                        log::error!(
                            "Certificate signature format does not match RSA PKCS #1 v1.5: {e:?}"
                        );
                        return Err(AlertDescription::BadCertificate)?;
                    }
                };

                let verifying_key: rsa::pkcs1v15::VerifyingKey<D> =
                    rsa::pkcs1v15::VerifyingKey::new(public_key.clone());

                let result = verifying_key.verify(to_verify, &signature);

                if let Err(e) = result {
                    log::error!("Verification of certificate RSA signature failed: {e:?}");
                    false
                } else {
                    true
                }
            }
        };

        if is_ok {
            Ok(())
        } else {
            // RFC 8446 4.4.3 If the verification fails, the receiver MUST
            // terminate the handshake with a "decrypt_error" alert.
            Err(AlertDescription::DecryptError)
        }
    }
}

/// # References
///
/// - [RFC 5280 Section 4.1](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1)
///
/// ```text
/// SubjectPublicKeyInfo  ::=  SEQUENCE  {
///      algorithm            AlgorithmIdentifier,
///      subjectPublicKey     BIT STRING  }
/// ```
#[derive(Debug, Clone)]
pub(crate) struct SubjectPublicKeyInfo {
    pub(crate) algorithm: AlgorithmIdentifier,
    pub(crate) subject_public_key: PublicKey,
}

impl SubjectPublicKeyInfo {
    pub fn deser(b: &[u8]) -> Option<(&[u8], Self)> {
        let (remain, subject_public_key_info) = Encoding::deser_expected(
            Identifier::SEQUENCE,
            "Certificate.tbsCertificate.subjectPublicKeyInfo",
            b,
        )?;

        let (b, algorithm) = AlgorithmIdentifier::deser(
            "Certificate.tbsCertificate.subjectPublicKeyInfo.algorithm",
            &subject_public_key_info.content,
        )?;
        let (b, subject_public_key) = Encoding::deser_expected(
            Identifier::BITSTRING,
            "Certificate.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey",
            b,
        )?;

        let pub_key_bytes = match subject_public_key.content.get(1..) {
            Some(bytes) => bytes,
            _ => {
                log::error!(
                    "Certificate.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey contains no data"
                );
                return None;
            }
        };

        let subject_public_key: PublicKey = match algorithm.algorithm.repr.as_str() {
            // ecPublicKey (ANSI X9.62 public key type)
            "1.2.840.10045.2.1" => {
                if let Some(params) = &algorithm.parameters {
                    match params.repr.as_str() {
                        // prime256v1 (ANSI X9.62 named elliptic curve)
                        "1.2.840.10045.3.1.7" => {
                            match p256::ecdsa::VerifyingKey::from_sec1_bytes(pub_key_bytes) {
                                Ok(key) => PublicKey::Prime256v1(key),
                                Err(e) => {
                                    log::error!(
                                        "Certificate.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey is not a valid prime256v1 key in sec1 bytes: {e:?}"
                                    );
                                    return None;
                                }
                            }
                        }
                        // secp384r1 (SECG (Certicom) named elliptic curve)
                        "1.3.132.0.34" => {
                            match p384::ecdsa::VerifyingKey::from_sec1_bytes(pub_key_bytes) {
                                Ok(key) => PublicKey::Secp384r1(key),
                                Err(e) => {
                                    log::error!(
                                        "Certificate.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey is not a valid secp384r1 key in sec1 bytes: {e:?}"
                                    );
                                    return None;
                                }
                            }
                        }
                        oid => {
                            log::error!(
                                "Certificate.tbsCertificate.subjectPublicKeyInfo.algorithm.parameters contains an unrecognized object identifier: {oid}"
                            );
                            return None;
                        }
                    }
                } else {
                    log::error!(
                        "Certificate.tbsCertificate.subjectPublicKeyInfo.algorithm.parameters is missing, required with ecPublicKey algorithm"
                    );
                    return None;
                }
            }
            // rsaEncryption (PKCS #1)
            "1.2.840.113549.1.1.1" => {
                if algorithm.parameters.is_some() {
                    log::error!(
                        "Certificate.tbsCertificate.subjectPublicKeyInfo.algorithm.parameters is present, unexpected for RSA encryption"
                    );
                    return None;
                }

                match rsa::RsaPublicKey::from_pkcs1_der(pub_key_bytes) {
                    Ok(pk) => PublicKey::Rsa(pk),
                    Err(e) => {
                        log::error!(
                            "Certificate.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey is not a valid RSA public key: {e:?}"
                        );
                        return None;
                    }
                }
            }
            oid => {
                log::error!(
                    "Certificate.tbsCertificate.SubjectPublicKeyInfo.algorithm.algorithm contains an unrecognized object identifier: {oid}"
                );
                return None;
            }
        };

        if !b.is_empty() {
            log::error!(
                "Certificate.tbsCertificate.subjectPublicKeyInfo contains {} bytes of extra data",
                b.len()
            );
            return None;
        }

        Some((
            remain,
            Self {
                algorithm,
                subject_public_key,
            },
        ))
    }
}

/// # References
///
/// - [RFC 5280 Section 4.1](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1)
///
/// ```text
/// Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Version {
    V1,
    V2,
    V3,
}

impl Version {
    pub fn deser(b: &[u8]) -> Option<(&[u8], Self)> {
        let (remain, encoding) = Encoding::deser_expected(
            Identifier {
                class: Class::Application,
                pc: Pc::Constructed,
                tag: Tag::Unknown(0),
            },
            "Certificate.tbsCertificate.version",
            b,
        )?;

        let (b, version_encoding) = Encoding::deser_expected(
            Identifier::INTEGER,
            "Certificate.tbsCertificate.version",
            &encoding.content,
        )?;

        if version_encoding.content.len() != 1 {
            log::error!(
                "Certificate.tbsCertificate.version must contain exactly 1 byte, got {}",
                version_encoding.content.len()
            );
            return None;
        }

        let version: Version = match version_encoding.content[0] {
            0 => Version::V1,
            1 => Version::V2,
            2 => Version::V3,
            x => {
                log::error!("Certificate.tbsCertificate.version invalid value {x}");
                return None;
            }
        };

        if !b.is_empty() {
            log::error!(
                "Certificate.tbsCertificate.version contains {} bytes of extra data",
                b.len()
            );
            return None;
        }

        Some((remain, version))
    }
}

/// # References
///
/// - [RFC 5280 Section 4.2.1.6](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6)
///
/// ```text
/// GeneralName ::= CHOICE {
///     otherName                       [0]     OtherName,
///     rfc822Name                      [1]     IA5String,
///     dNSName                         [2]     IA5String,
///     x400Address                     [3]     ORAddress,
///     directoryName                   [4]     Name,
///     ediPartyName                    [5]     EDIPartyName,
///     uniformResourceIdentifier       [6]     IA5String,
///     iPAddress                       [7]     OCTET STRING,
///     registeredID                    [8]     OBJECT IDENTIFIER }
///
/// OtherName ::= SEQUENCE {
///     type-id    OBJECT IDENTIFIER,
///     value      [0] EXPLICIT ANY DEFINED BY type-id }
///
/// EDIPartyName ::= SEQUENCE {
///     nameAssigner            [0]     DirectoryString OPTIONAL,
///     partyName               [1]     DirectoryString }
/// ```
#[derive(Debug, Clone)]
pub enum GeneralName {
    Rfc822Name(String),
    DnsName(String),
    IpAddr(IpAddr),
    UniformResourceIdentifier(String),
    Unimplemented(Vec<u8>),
    Unrecognized(Vec<u8>),
}

impl GeneralName {
    pub fn deser<'a>(name: &str, b: &'a [u8]) -> Option<(&'a [u8], Self)> {
        let (b, encoding) = Encoding::deser(name, b)?;

        if encoding.identifier.class != Class::Application {
            log::error!(
                "{name} expected identifier class {:?} got {:?}",
                Class::Application,
                encoding.identifier.class
            );
            return None;
        }
        if encoding.identifier.pc != Pc::Primitive {
            // warning instead of an error because a CA in my system trust store
            // had it incorrectly set to constructed
            log::warn!(
                "{name} expected identifier PC {:?} got {:?}",
                Pc::Primitive,
                encoding.identifier.pc
            );
        }

        let tag_val: u8 = u8::from(encoding.identifier.tag);

        let ret: Self = match tag_val {
            0 => {
                // TODO: implement AnotherName type
                log::warn!("{name} ignoring unimplemented GeneralName type AnotherName");
                Self::Unimplemented(encoding.content)
            }
            1 => {
                let val = String::from_utf8_lossy(&encoding.content);
                if !val.is_ascii() {
                    log::error!("{name} rfc822Name is not a valid IA5String (ASCII)");
                    return None;
                }
                Self::Rfc822Name(val.into())
            }
            2 => {
                let val = String::from_utf8_lossy(&encoding.content);
                if !val.is_ascii() {
                    log::error!("{name} dNSName is not a valid IA5String (ASCII)");
                    return None;
                }
                Self::DnsName(val.into())
            }
            3 => {
                // TODO: implement ORAddress type
                log::warn!("{name} ignoring unimplemented GeneralName type ORAddress");
                Self::Unimplemented(encoding.content)
            }
            4 => {
                // TODO: implement Name type
                log::warn!("{name} ignoring unimplemented GeneralName type Name");
                Self::Unimplemented(encoding.content)
            }
            5 => {
                // TODO: implement EDIPartyName type
                log::warn!("{name} ignoring unimplemented GeneralName type EDIPartyName");
                Self::Unimplemented(encoding.content)
            }
            6 => {
                let val = String::from_utf8_lossy(&encoding.content);
                if !val.is_ascii() {
                    log::error!(
                        "{name} uniformResourceIdentifier is not a valid IA5String (ASCII)"
                    );
                    return None;
                }
                Self::UniformResourceIdentifier(val.into())
            }
            7 => {
                if encoding.content.len() == 4 {
                    Self::IpAddr(IpAddr::V4(Ipv4Addr::from_bits(u32::from_be_bytes(
                        encoding.content.try_into().unwrap(),
                    ))))
                } else if encoding.content.len() == 16 {
                    Self::IpAddr(IpAddr::V6(Ipv6Addr::from_bits(u128::from_be_bytes(
                        encoding.content.try_into().unwrap(),
                    ))))
                } else {
                    log::error!(
                        "{name} contains an unrecoginzed IP address length {} expected 4 for IPv4 or 16 for IPv6",
                        encoding.content.len()
                    );
                    return None;
                }
            }
            8 => {
                // TODO: implement EDIPartyName type
                log::warn!("{name} ignoring unimplemented GeneralName type registeredID");
                Self::Unimplemented(encoding.content)
            }
            unrecognized => {
                log::warn!("{name} ignoring unrecognized GeneralName type 0x{unrecognized:02x}");
                Self::Unrecognized(encoding.content)
            }
        };

        Some((b, ret))
    }

    /// Returns `true` if the general name is [`DnsName`].
    ///
    /// [`DnsName`]: GeneralName::DnsName
    #[must_use]
    pub fn is_dns_name(&self) -> bool {
        matches!(self, Self::DnsName(..))
    }
}

/// # References
///
/// - [RFC 5280 Section 4.2.1.6](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6)
///
/// ```text
/// id-ce-subjectAltName OBJECT IDENTIFIER ::=  { id-ce 17 }
///
/// SubjectAltName ::= GeneralNames
///
/// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
/// ```
#[derive(Debug, Clone)]
pub struct SubjectAltName {
    names: Vec<GeneralName>,
}

impl SubjectAltName {
    pub fn deser(n: usize, b: &[u8]) -> Option<Self> {
        let name = format!("Certificate.tbsCertificate.extensions[{n}].extnValue");

        let (b, seq) =
            Encoding::deser_expected(Identifier::SEQUENCE, &format!("{name}.GeneralNames"), b)?;

        let mut seq_b: &[u8] = seq.content.as_ref();

        let mut names: Vec<GeneralName> = Vec::new();

        while !seq_b.is_empty() {
            let name_name = format!("{name}.GeneralNames[{}]", names.len());
            let (local_b, general_name) = GeneralName::deser(&name_name, seq_b)?;
            seq_b = local_b;

            names.push(general_name);
        }

        if !b.is_empty() {
            log::error!("{name} contains {} bytes of extra data", b.len());
            return None;
        }

        Some(Self { names })
    }

    pub fn dns_names(&self) -> Vec<String> {
        self.names
            .iter()
            .filter_map(|general_name| match general_name {
                GeneralName::DnsName(dns_name) => Some(dns_name.clone()),
                _ => None,
            })
            .collect()
    }
}

/// # References
///
/// - [RFC 5280 Section 4.2.1.2](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2)
///
/// ```text
/// id-ce-subjectKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 14 }
///
/// SubjectKeyIdentifier ::= KeyIdentifier
///
/// KeyIdentifier ::= OCTET STRING
/// ```
#[derive(Debug, Clone)]
pub struct SubjectKeyIdentifier {
    key_id: Vec<u8>,
}

impl SubjectKeyIdentifier {
    pub fn deser(n: usize, b: &[u8]) -> Option<Self> {
        let name = format!("Certificate.tbsCertificate.extensions[{n}].extnValue");

        let (b, os) =
            Encoding::deser_expected(Identifier::OCTETSTRING, &format!("{name}.KeyIdentifier"), b)?;

        if !b.is_empty() {
            log::error!("{name} contains {} bytes of extra data", b.len());
            return None;
        }

        Some(Self { key_id: os.content })
    }
}

/// # References
///
/// - [RFC 5280 Section 4.2.1.9](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.9)
///
/// ```text
/// id-ce-basicConstraints OBJECT IDENTIFIER ::=  { id-ce 19 }
///
/// BasicConstraints ::= SEQUENCE {
///     cA                      BOOLEAN DEFAULT FALSE,
///     pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
/// ```
#[derive(Debug, Clone)]
pub struct BasicConstraints {
    ca: bool,
    path_len_constraint: Option<Vec<u8>>,
}

impl BasicConstraints {
    pub fn deser(n: usize, b: &[u8]) -> Option<Self> {
        let name = format!("Certificate.tbsCertificate.extensions[{n}].extnValue");

        let (b, encoding) =
            Encoding::deser_expected(Identifier::SEQUENCE, &format!("{name}.BasicConstraints"), b)?;

        if !b.is_empty() {
            log::error!("{name} contains {} bytes of extra data", b.len());
            return None;
        }

        if encoding.content.is_empty() {
            Some(Self {
                ca: false,
                path_len_constraint: None,
            })
        } else {
            let (seq_b, ca) =
                Encoding::deser_bool(&format!("{name}.BasicConstraints.cA"), &encoding.content)?;

            let path_len_constraint = if !seq_b.is_empty() {
                let (b, path_len_constraint) = Encoding::deser_expected(
                    Identifier::INTEGER,
                    &format!("{name}.BasicConstraints.pathLenConstraint"),
                    seq_b,
                )?;

                if !b.is_empty() {
                    log::error!(
                        "{name}.BasicConstraints contains {} bytes of extra data",
                        b.len()
                    );
                    return None;
                }

                Some(path_len_constraint.content)
            } else {
                None
            };

            Some(Self {
                ca,
                path_len_constraint,
            })
        }
    }
}

/// # References
///
/// - [RFC 5280 Section 4.2.1.3](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3)
///
/// ```text
/// id-ce-keyUsage OBJECT IDENTIFIER ::=  { id-ce 15 }
///
/// KeyUsage ::= BIT STRING {
///      digitalSignature        (0),
///      nonRepudiation          (1), -- recent editions of X.509 have
///                           -- renamed this bit to contentCommitment
///      keyEncipherment         (2),
///      dataEncipherment        (3),
///      keyAgreement            (4),
///      keyCertSign             (5),
///      cRLSign                 (6),
///      encipherOnly            (7),
///      decipherOnly            (8) }
/// ```
#[derive(Debug, Clone)]
pub struct KeyUsage {
    usage: Vec<u8>,
}

impl KeyUsage {
    pub fn deser(n: usize, b: &[u8]) -> Option<Self> {
        let name = format!("Certificate.tbsCertificate.extensions[{n}].extnValue");

        let (b, encoding) =
            Encoding::deser_expected(Identifier::BITSTRING, &format!("{name}.KeyUsage"), b)?;

        if !b.is_empty() {
            log::error!("{name} contains {} bytes of extra data", b.len());
            return None;
        }

        Some(Self {
            usage: encoding.content,
        })
    }
}

/// # References
///
/// - [RFC 5280 Section 4.2](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2)
#[derive(Debug, Clone)]
pub(crate) struct Extensions {
    pub(crate) subject_key_identifier: Option<SubjectKeyIdentifier>,
    pub(crate) subject_alt_name: Option<SubjectAltName>,
    pub(crate) key_usage: Option<KeyUsage>,
    pub(crate) basic_constraints: Option<BasicConstraints>,

    unrecognized: Vec<Encoding>,
}

impl Extensions {
    pub fn deser(b: &[u8]) -> Option<Self> {
        let (remain, encoding) = Encoding::deser_expected(
            Identifier::SEQUENCE,
            "Certificate.tbsCertificate.extensions",
            b,
        )?;

        if !remain.is_empty() {
            log::error!(
                "Certificate.tbsCertificate.extensions contains {} bytes of extra data",
                remain.len()
            );
            return None;
        }

        let mut b: &[u8] = &encoding.content;

        let mut subject_key_identifier: Option<SubjectKeyIdentifier> = None;
        let mut key_usage: Option<KeyUsage> = None;
        let mut subject_alt_name: Option<SubjectAltName> = None;
        let mut basic_constraints: Option<BasicConstraints> = None;
        let mut unrecognized: Vec<Encoding> = Vec::new();

        let mut n: usize = 0;

        while !b.is_empty() {
            let (local_b, encoding) = Encoding::deser_expected(
                Identifier::SEQUENCE,
                format!("Certificate.tbsCertificate.extensions[{n}]").as_str(),
                b,
            )?;
            b = local_b;

            let (ext_remain, ext_obj_id) = ObjectIdentifier::deser(
                format!("Certificate.tbsCertificate.extensions[{n}].extnID").as_str(),
                &encoding.content,
            )?;

            let (ext_remain, maybe_bool) = Encoding::deser_expected2(
                Identifier::BOOLEAN,
                Identifier::OCTETSTRING,
                format!("Certificate.tbsCertificate.extensions[{n}].critical_or_extnValue")
                    .as_str(),
                ext_remain,
            )?;

            let (critical, octetstring): (bool, Vec<u8>) = if maybe_bool.identifier
                == Identifier::BOOLEAN
            {
                let (remain, octetstring_encoding) = Encoding::deser_expected(
                    Identifier::OCTETSTRING,
                    format!("Certificate.tbsCertificate.extensions[{n}].extnValue").as_str(),
                    ext_remain,
                )?;

                if !remain.is_empty() {
                    log::error!(
                        "Certificate.tbsCertificate.extensions[{n}] contains {} bytes of extra data",
                        remain.len()
                    );
                    return None;
                }

                let critical: bool = Encoding::deser_bool_from_encoding(
                    maybe_bool,
                    &format!("Certificate.tbsCertificate.extensions[{n}].critical"),
                )?;

                (critical, octetstring_encoding.content)
            } else {
                (false, maybe_bool.content)
            };

            match ext_obj_id.repr.as_str() {
                // SubjectKeyIdentifier
                "2.5.29.14" => {
                    if subject_key_identifier
                        .replace(SubjectKeyIdentifier::deser(n, &octetstring)?)
                        .is_some()
                    {
                        log::error!(
                            "Certificate.tbsCertificate.extensions[{n}] is a duplicate SubjectKeyIdentifier extension"
                        );
                        return None;
                    }
                }
                // keyUsage
                "2.5.29.15" => {
                    if key_usage
                        .replace(KeyUsage::deser(n, &octetstring)?)
                        .is_some()
                    {
                        log::error!(
                            "Certificate.tbsCertificate.extensions[{n}] is a duplicate KeyUsage extension"
                        );
                        return None;
                    }
                }
                // subjectAltName
                "2.5.29.17" => {
                    if subject_alt_name
                        .replace(SubjectAltName::deser(n, &octetstring)?)
                        .is_some()
                    {
                        log::error!(
                            "Certificate.tbsCertificate.extensions[{n}] is a duplicate SubjectAltName extension"
                        );
                        return None;
                    }
                }
                // basicConstraints
                "2.5.29.19" => {
                    if basic_constraints
                        .replace(BasicConstraints::deser(n, &octetstring)?)
                        .is_some()
                    {
                        log::error!(
                            "Certificate.tbsCertificate.extensions[{n}] is a duplicate BasicConstraints extension"
                        );
                        return None;
                    }
                }
                unrecognized_oid => {
                    if critical {
                        log::error!(
                            "Certificate.tbsCertificate.extensions[{n}] unrecognized OID {unrecognized_oid} with critical bit set ignored",
                        );
                        // TODO: bail here
                    } else {
                        log::warn!(
                            "Certificate.tbsCertificate.extensions[{n}] unrecognized OID {unrecognized_oid} ignored",
                        );
                    }

                    unrecognized.push(encoding);
                }
            }

            n = n.saturating_add(1);
        }

        Some(Self {
            subject_key_identifier,
            subject_alt_name,
            key_usage,
            basic_constraints,
            unrecognized,
        })
    }
}

/// # References
///
/// - [RFC 5280 Section 4.1](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1)
///
/// ```text
/// TBSCertificate  ::=  SEQUENCE  {
///      version         [0]  EXPLICIT Version DEFAULT v1,
///      serialNumber         CertificateSerialNumber,
///      signature            AlgorithmIdentifier,
///      issuer               Name,
///      validity             Validity,
///      subject              Name,
///      subjectPublicKeyInfo SubjectPublicKeyInfo,
///      issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
///                           -- If present, version MUST be v2 or v3
///      subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
///                           -- If present, version MUST be v2 or v3
///      extensions      [3]  EXPLICIT Extensions OPTIONAL
///                           -- If present, version MUST be v3
///      }
/// ```
#[derive(Clone)]
pub(crate) struct TbsCertificate {
    pub(crate) version: Version,
    pub(crate) serial_number: Vec<u8>,
    pub(crate) signature: AlgorithmIdentifier,
    pub(crate) issuer: Name,
    pub(crate) validity: Validity,
    pub(crate) subject: Name,
    pub(crate) subject_public_key_info: SubjectPublicKeyInfo,
    pub(crate) issuer_unique_id: Option<Vec<u8>>,
    pub(crate) subject_unique_id: Option<Vec<u8>>,
    pub(crate) extensions: Option<Extensions>,
}

impl fmt::Debug for TbsCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut serial_number: String = String::with_capacity(40);

        for byte in self.serial_number.iter() {
            serial_number.push_str(&format!("{byte:02x}"));
        }

        f.debug_struct("TbsCertificate")
            .field("version", &self.version)
            .field("serial_number", &serial_number)
            .field("signature", &self.signature)
            .field("issuer", &self.issuer)
            .field("validity", &self.validity)
            .field("subject", &self.subject)
            .field("subject_public_key_info", &self.subject_public_key_info)
            .field("issuer_unique_id", &self.issuer_unique_id)
            .field("subject_unique_id", &self.subject_unique_id)
            .field("extensions", &self.extensions)
            .finish()
    }
}

impl TbsCertificate {
    pub fn deser(encoding: Encoding) -> Option<Self> {
        let (b, version) = Version::deser(&encoding.content)?;
        let (b, serial_number) = Encoding::deser("Certificate.tbsCertificate.serialNumber", b)?;
        let (b, signature) = AlgorithmIdentifier::deser("Certificate.tbsCertificate.signature", b)?;
        let (b, issuer) = Name::deser("Certificate.tbsCertificate.issuer", b)?;
        let (b, validity) = Validity::deser(b)?;
        let (b, subject) = Name::deser("Certificate.tbsCertificate.subject", b)?;
        let (mut b, subject_public_key_info) = SubjectPublicKeyInfo::deser(b)?;

        let mut issuer_unique_id: Option<Vec<u8>> = None;
        let mut subject_unique_id: Option<Vec<u8>> = None;
        let mut extensions = None;

        let mut prev_tag: u8 = 0;

        while !b.is_empty() {
            let (local_b, encoding) = Encoding::deser("Certificate.tbsCertificate optional", b)?;
            b = local_b;

            if encoding.identifier.class != Class::Application {
                log::error!(
                    "Unexpected idenitifer class after Certificate.tbsCertificate.subjectPublicKeyInfo, expected {:?}, got {:?}",
                    Class::Application,
                    encoding.identifier.class
                );
                return None;
            }

            let tag: u8 = encoding.identifier.tag.into();
            if prev_tag >= tag {
                log::error!(
                    "Certificate.tbsCertificate optional fields out-of-order previous tag {}, current tag {}",
                    prev_tag,
                    tag
                );
                return None;
            }
            prev_tag = tag;

            match tag {
                1 => issuer_unique_id = Some(encoding.content),
                2 => subject_unique_id = Some(encoding.content),
                3 => extensions = Some(Extensions::deser(&encoding.content)?),
                _ => {
                    log::error!(
                        "Certificate.tbsCertificate contains unexpected tag value for {tag}"
                    );
                    return None;
                }
            }
        }

        Some(Self {
            version,
            serial_number: serial_number.content,
            signature,
            issuer,
            validity,
            subject,
            subject_public_key_info,
            issuer_unique_id,
            subject_unique_id,
            extensions,
        })
    }
}

/// # References
///
/// - [RFC 5280 Section 4.1.1.2](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.1.2)
///
/// ```text
/// AlgorithmIdentifier  ::=  SEQUENCE  {
///     algorithm               OBJECT IDENTIFIER,
///     parameters              ANY DEFINED BY algorithm OPTIONAL  }
/// ```
#[derive(Debug, Clone)]
pub(crate) struct AlgorithmIdentifier {
    algorithm: ObjectIdentifier,
    parameters: Option<ObjectIdentifier>,
}

impl AlgorithmIdentifier {
    pub fn deser<'a>(name: &str, b: &'a [u8]) -> Option<(&'a [u8], Self)> {
        let (remain, signature_algorithm) =
            Encoding::deser_expected(Identifier::SEQUENCE, name, b)?;

        let (b, algorithm) =
            ObjectIdentifier::deser(&format!("{name}.algorithm"), &signature_algorithm.content)?;

        let parameters = if b.is_empty() {
            None
        } else {
            let (b, parameters) =
                ObjectIdentifier::deser_or_null(&format!("{name}.parameters"), b)?;

            if !b.is_empty() {
                log::error!("{name} contains {} bytes of extra data", b.len());
                return None;
            }

            parameters
        };

        Some((
            remain,
            Self {
                algorithm,
                parameters,
            },
        ))
    }
}

/// # References
///
/// - [RFC 5280 Section 4.1.1.3](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.1.3)
#[derive(Debug, Clone)]
pub(crate) struct SignatureValue {
    pub(crate) bitstring: Vec<u8>,
}

impl SignatureValue {
    pub fn deser(b: &[u8]) -> Option<(&[u8], Self)> {
        let (b, signature_value) =
            Encoding::deser_expected(Identifier::BITSTRING, "Certificate.signatureValue", b)?;

        Some((
            b,
            Self {
                bitstring: signature_value.content,
            },
        ))
    }
}

/// # References
///
/// - [RFC 5280 Section 4.1](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1)
///
/// ```text
/// Certificate  ::=  SEQUENCE  {
///     tbsCertificate       TBSCertificate,
///     signatureAlgorithm   AlgorithmIdentifier,
///     signatureValue       BIT STRING  }
/// ```
#[derive(Debug, Clone)]
pub(crate) struct Certificate {
    pub(crate) tbs_certificate: TbsCertificate,
    pub(crate) signature_algorithm: AlgorithmIdentifier,
    pub(crate) signature_value: SignatureValue,
}

impl Certificate {
    pub fn deser(buf: &[u8], ignore_extra: bool) -> Option<(&[u8], Self)> {
        let init_len: usize = buf.len();

        let (b, certificate) = Encoding::deser_expected(Identifier::SEQUENCE, "Certificate", buf)?;

        if !b.is_empty() && !ignore_extra {
            log::error!(
                "Certificate contains {} bytes of data after sequence encoding",
                b.len()
            );
            return None;
        }

        let tbs_certificate_start = init_len.saturating_sub(certificate.content.len());

        let (b, encoding) = Encoding::deser_expected(
            Identifier::SEQUENCE,
            "Certificate.tbsCertificate",
            &certificate.content,
        )?;

        let tbs_certificate_end: usize = tbs_certificate_start
            .add(certificate.content.len())
            .saturating_sub(b.len());

        let tbs_certificate: TbsCertificate = TbsCertificate::deser(encoding)?;

        let (b, signature_algorithm) =
            AlgorithmIdentifier::deser("Certificate.signatureAlgorithm", b)?;

        let (b, signature_value) = SignatureValue::deser(b)?;

        if !b.is_empty() {
            log::error!(
                "CertificateEntry cert_data contains {} extra bytes of data",
                b.len()
            );
            return None;
        }

        Some((
            &buf[tbs_certificate_start..tbs_certificate_end],
            Self {
                tbs_certificate,
                signature_algorithm,
                signature_value,
            },
        ))
    }

    pub fn validate(&self, server_name: Option<&str>) -> Result<(), AlertDescription> {
        let now: Zoned = Zoned::now();
        if self.tbs_certificate.validity.not_before > now {
            log::error!(
                "Certificate expired validity.notBefore={} now={now}",
                self.tbs_certificate.validity.not_before
            );
            return Err(AlertDescription::CertificateExpired);
        }
        if self.tbs_certificate.validity.not_after < now {
            log::error!(
                "Certificate expired validity.notAfter={} now={now}",
                self.tbs_certificate.validity.not_after
            );
            return Err(AlertDescription::CertificateExpired);
        }

        if self.tbs_certificate.issuer_unique_id.is_some()
            && self.tbs_certificate.version == Version::V1
        {
            log::error!(
                "Certificate.tbsCertificate.issuerUniqueID is not allowed with {:?}",
                self.tbs_certificate.version
            );
            return Err(AlertDescription::BadCertificate);
        }

        if self.tbs_certificate.subject_unique_id.is_some()
            && self.tbs_certificate.version == Version::V1
        {
            log::error!(
                "Certificate.tbsCertificate.subjectUniqueID is not allowed with {:?}",
                self.tbs_certificate.version
            );
            return Err(AlertDescription::BadCertificate);
        }

        if self.tbs_certificate.extensions.is_some() && self.tbs_certificate.version != Version::V3
        {
            log::error!(
                "Certificate.tbsCertificate.extensions is not allowed with {:?}",
                self.tbs_certificate.version
            );
            return Err(AlertDescription::BadCertificate);
        }

        // RFC 5280 4.1.2.2
        const SERIAL_NUMBER_MAX: usize = 20;
        if self.tbs_certificate.serial_number.len() > SERIAL_NUMBER_MAX {
            log::error!(
                "Certificate.tbsCertificate.serialNumber is of length {}, conforming CAs MUST NOT use serialNumber values longer than {} octets",
                self.tbs_certificate.serial_number.len(),
                SERIAL_NUMBER_MAX
            );
            return Err(AlertDescription::BadCertificate);
        }

        // RFC 5280 4.1.1.2 signatureAlgorithm:
        // This field MUST contain the same algorithm identifier as the signature field in the sequence tbsCertificate
        if self.signature_algorithm.algorithm != self.tbs_certificate.signature.algorithm {
            log::error!(
                "Certificate.signatureAlgorithm.algorithm={:?} MUST contain the same algorithm idenitifier as Certificate.tbsCertificate.signature.algorithm={:?}",
                self.signature_algorithm.algorithm,
                self.tbs_certificate.signature.algorithm
            );
            return Err(AlertDescription::BadCertificate);
        }

        if let Some(name) = server_name {
            let mut certificate_names: Vec<String> = self
                .tbs_certificate
                .subject
                .rdn_sequence
                .iter()
                .map(|atav| atav.value.clone())
                .collect();

            if let Some(extensions) = &self.tbs_certificate.extensions
                && let Some(subject_alt_name) = &extensions.subject_alt_name
            {
                certificate_names.extend_from_slice(&subject_alt_name.dns_names());
            }

            // TODO: does not handle wildcards
            // TODO: does not handle IPv4/IPv6
            if !certificate_names.iter().any(|n| n == name) {
                log::error!(
                    "Certificate.tbsCertificate.subject does not contain {}, valid for {:?}",
                    name,
                    certificate_names
                );
                return Err(AlertDescription::BadCertificate);
            }
        }

        if let Some(extensions) = &self.tbs_certificate.extensions {
            if let Some(key_usage) = &extensions.key_usage {
                // TODO: this extension is marked as critical
                log::error!(
                    "Certificate.tbsCertificate.extensions contains unimplemented KeyUsage extension {key_usage:?}"
                );
            }

            if let Some(basic_constraints) = &extensions.basic_constraints {
                // TODO: this extension is marked as critical
                log::error!(
                    "Certificate.tbsCertificate.extensions contains unimplemented BasicConstraints extension {basic_constraints:?}"
                );
            }

            if let Some(subject_key_identifier) = &extensions.subject_key_identifier {
                log::warn!(
                    "Certificate.tbsCertificate.extensions contains unimplemented SubjectKeyIdentifier extension {subject_key_identifier:02x?}"
                );
            }
        }

        // TODO: check other fields

        Ok(())
    }

    pub fn verify_previous(
        &self,
        tbs_certificate_bytes: &[u8],
        signature_algorithm: &AlgorithmIdentifier,
        signature: &[u8],
    ) -> Result<(), AlertDescription> {
        let signature_bytes = match signature.get(1..) {
            Some(s) => s,
            None => {
                log::error!("Certificate signature contains only a single byte");
                return Err(AlertDescription::BadCertificate);
            }
        };

        let pk: &PublicKey = &self
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key;

        match signature_algorithm.algorithm.repr.as_str() {
            // ecdsaWithSHA256 (ANSI X9.62 ECDSA algorithm with SHA256)
            "1.2.840.10045.4.3.2" => {
                pk.verify::<sha2::Sha256>(tbs_certificate_bytes, signature_bytes)
            }
            // ecdsaWithSHA384 (ANSI X9.62 ECDSA algorithm with SHA384)
            "1.2.840.10045.4.3.3" => {
                pk.verify::<sha2::Sha384>(tbs_certificate_bytes, signature_bytes)
            }
            // sha256WithRSAEncryption (PKCS #1)
            "1.2.840.113549.1.1.11" => {
                pk.verify::<sha2::Sha256>(tbs_certificate_bytes, signature_bytes)
            }
            // sha384WithRSAEncryption (PKCS #1)
            "1.2.840.113549.1.1.12" => {
                pk.verify::<sha2::Sha384>(tbs_certificate_bytes, signature_bytes)
            }
            // sha512WithRSAEncryption (PKCS #1)
            "1.2.840.113549.1.1.13" => {
                pk.verify::<sha2::Sha512>(tbs_certificate_bytes, signature_bytes)
            }
            oid => {
                log::error!(
                    "Certificate.signatureAlgorithm.algorithm contains an unrecognized object identifier: {oid}"
                );
                Err(AlertDescription::BadCertificate)
            }
        }
    }
}
