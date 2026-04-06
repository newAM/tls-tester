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
};

use jiff::Zoned;

use crate::{AlertDescription, decode};

/// Identifier octet
///
/// # References
///
/// - X.690 Section 8.1.2.2
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
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
pub enum Pc {
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
pub enum Tag {
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
pub struct Identifier {
    pub(crate) class: Class,
    pub(crate) pc: Pc,
    pub(crate) tag: Tag,
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
        // Bits 7:6 are the class (X.690 §8.1.2.2)
        let class_raw: u8 = (val >> 6) & 0x3;

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

/// DER encoding — a parsed TLV (Tag-Length-Value) structure.
///
/// This type is retained as an internal representation for places in the
/// DER parser that need to inspect the identifier and content together
/// (e.g., iterating over a SET OF, or reading an arbitrary TLV whose
/// tag determines subsequent parsing branches).
///
/// In the new `DecodeContext`-based API the `Encoding` struct is populated
/// from the context cursor rather than being deserialized from raw `&[u8]`.
///
/// # References
///
/// - X.690 Section 8.1.1 Structure of an encoding
#[derive(Debug, Clone)]
pub(crate) struct Encoding {
    pub(crate) identifier: Identifier,
    pub(crate) content: Vec<u8>,
}

impl Encoding {
    /// Read one DER TLV from `ctx`, returning the `Encoding` and leaving the
    /// cursor positioned after the TLV's content.
    pub(crate) fn read(name: &str, ctx: &mut decode::DecodeContext) -> Option<Self> {
        let id = ctx.begin_tlv(name, "TLV")?;
        let start = ctx.current_position();
        let end = start + ctx.der_remaining();
        let content = ctx
            .original_buffer()
            .get(start..end)
            .unwrap_or(&[])
            .to_vec();
        // advance cursor to end of content, then close field
        ctx.advance(end - start);
        ctx.end_tlv()?;
        Some(Self {
            identifier: id,
            content,
        })
    }

    /// Read one DER TLV from `ctx` and assert the identifier matches `expected`.
    pub(crate) fn read_expected(
        expected: Identifier,
        name: &str,
        ctx: &mut decode::DecodeContext,
    ) -> Option<Self> {
        let id = ctx.tlv_expected(name, "TLV", expected)?;
        let start = ctx.current_position();
        let end = start + ctx.der_remaining();
        let content = ctx
            .original_buffer()
            .get(start..end)
            .unwrap_or(&[])
            .to_vec();
        ctx.advance(end - start);
        ctx.end_tlv()?;
        Some(Self {
            identifier: id,
            content,
        })
    }

    /// Read one DER TLV from `ctx` and assert the identifier matches `id1` or `id2`.
    pub(crate) fn read_expected2(
        id1: Identifier,
        id2: Identifier,
        name: &str,
        ctx: &mut decode::DecodeContext,
    ) -> Option<Self> {
        let id = ctx.tlv_expected2(name, "TLV", id1, id2)?;
        let start = ctx.current_position();
        let end = start + ctx.der_remaining();
        let content = ctx
            .original_buffer()
            .get(start..end)
            .unwrap_or(&[])
            .to_vec();
        ctx.advance(end - start);
        ctx.end_tlv()?;
        Some(Self {
            identifier: id,
            content,
        })
    }

    /// Interpret an already-read `Encoding` as a DER BOOLEAN.
    pub(crate) fn bool_from_content(content: &[u8], name: &str) -> Option<bool> {
        match content.first() {
            Some(0x00) => Some(false),
            Some(0xFF) => Some(true),
            Some(val) => {
                log::error!(
                    "{name} DER BOOLEAN has invalid value 0x{val:02x}, expected 0x00 or 0xFF"
                );
                None
            }
            None => {
                log::error!("{name} DER BOOLEAN is missing value byte");
                None
            }
        }
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
    fn from_content(name: &str, content: Vec<u8>) -> Option<Self> {
        let mut repr: String = String::new();

        if let Some(byte0) = content.first() {
            let node1: u8 = byte0 % 0x28;
            let node0: u8 = (byte0 - node1) / 0x28;
            repr.push_str(&format!("{node0}.{node1}"));
        } else {
            log::error!("{name} OID must not be empty");
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
            log::error!("{name} OID has an unterminated multi-byte encoding");
            return None;
        }

        Some(Self { oid: content, repr })
    }

    /// Read a DER OBJECT IDENTIFIER TLV from `ctx`.
    pub fn deser(name: &str, ctx: &mut decode::DecodeContext) -> Option<Self> {
        let raw = ctx.der_oid_raw(name)?;
        Self::from_content(name, raw)
    }

    /// Read a DER OBJECT IDENTIFIER or NULL TLV from `ctx`.
    /// Returns `Some(oid)` for an OID, `None` for a well-formed NULL.
    pub fn deser_or_null(name: &str, ctx: &mut decode::DecodeContext) -> Option<Option<Self>> {
        match ctx.der_oid_or_null(name)? {
            Some(raw) => Some(Some(Self::from_content(name, raw)?)),
            None => Some(None),
        }
    }
}

#[cfg(test)]
mod object_identifier_tests {
    use super::ObjectIdentifier;

    #[test]
    fn object_identifier() {
        let content: Vec<u8> = vec![0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
        let oid: ObjectIdentifier = ObjectIdentifier::from_content("test", content).unwrap();
        assert_eq!(oid.repr, "1.2.840.10045.2.1");

        let content: Vec<u8> = vec![0x2B, 0x81, 0x04, 0x00, 0x22];
        let oid: ObjectIdentifier = ObjectIdentifier::from_content("test", content).unwrap();
        assert_eq!(oid.repr, "1.3.132.0.34");

        let content: Vec<u8> = vec![0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
        let oid: ObjectIdentifier = ObjectIdentifier::from_content("test", content).unwrap();
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
    pub fn deser(name: &str, ctx: &mut decode::DecodeContext) -> Option<Self> {
        let oid = ObjectIdentifier::deser(&format!("{name}.type"), ctx)?;
        let value_name: String = format!("{name}.value");

        // Read the DirectoryString — an arbitrary string tag
        let encoding = Encoding::read(&value_name, ctx)?;

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

        Some(Self { oid, value })
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
    pub fn deser(name: &str, ctx: &mut decode::DecodeContext) -> Option<Self> {
        // Outer SEQUENCE (the RDNSequence)
        ctx.tlv_expected(name, "SEQUENCE", Identifier::SEQUENCE)?;

        let rdn_name: String = format!("{name}.rdnSequence");
        let mut rdn_sequence: Vec<AttributeTypeAndValue> = Vec::new();
        let mut x: usize = 0;

        while ctx.der_remaining() > 0 {
            // Each RDN is a SET
            let set_name = format!("{rdn_name}[{x}]");
            ctx.tlv_expected(&set_name, "SET", Identifier::SET)?;
            let mut y: usize = 0;
            while ctx.der_remaining() > 0 {
                // Each element of the SET is a SEQUENCE (AttributeTypeAndValue)
                let atav_name = format!("{name}[{x}][{y}]");
                ctx.tlv_expected(&atav_name, "SEQUENCE", Identifier::SEQUENCE)?;
                let atav = AttributeTypeAndValue::deser(&atav_name, ctx)?;
                ctx.end_tlv()?; // end AttributeTypeAndValue SEQUENCE
                rdn_sequence.push(atav);
                y += 1;
            }
            ctx.end_tlv()?; // end SET
            x += 1;
        }

        ctx.end_tlv()?; // end outer SEQUENCE
        Some(Self { rdn_sequence })
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
    pub fn deser(ctx: &mut decode::DecodeContext) -> Option<Self> {
        ctx.tlv_expected(
            "Certificate.tbsCertificate.validity",
            "SEQUENCE",
            Identifier::SEQUENCE,
        )?;

        let not_before = ctx.der_time("Certificate.tbsCertificate.validity.notBefore")?;
        let not_after = ctx.der_time("Certificate.tbsCertificate.validity.notAfter")?;

        if ctx.der_remaining() > 0 {
            log::error!(
                "Certificate.tbsCertificate.validity contains {} bytes of extra data",
                ctx.der_remaining()
            );
            return None;
        }

        ctx.end_tlv()?; // end SEQUENCE
        Some(Self {
            not_before,
            not_after,
        })
    }
}

#[derive(Debug, Clone)]
pub enum PublicKey {
    Prime256v1(p256::ecdsa::VerifyingKey),
    Secp384r1(p384::ecdsa::VerifyingKey),
    Ansip521r1(p521::ecdsa::VerifyingKey),
    Rsa(rsa::RsaPublicKey),
}

impl PublicKey {
    pub(crate) fn verify<D>(
        &self,
        to_verify: &[u8],
        signature: &[u8],
    ) -> Result<(), AlertDescription>
    where
        D: Digest + AssociatedOid + sha2::digest::FixedOutputReset,
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
            PublicKey::Ansip521r1(verifying_key) => {
                let signature: p521::ecdsa::Signature =
                    match p521::ecdsa::Signature::from_der(signature) {
                        Ok(signature) => signature,
                        Err(e) => {
                            log::error!(
                                "Certificate signature format does not match ansip521r1: {e:?}"
                            );
                            return Err(AlertDescription::BadCertificate)?;
                        }
                    };

                let result = verifying_key.verify(to_verify, &signature);

                if let Err(e) = result {
                    log::error!("Verification of certificate ansip521r1 signature failed: {e:?}");
                    false
                } else {
                    true
                }
            }
            PublicKey::Rsa(public_key) => {
                let signature: rsa::pss::Signature = match rsa::pss::Signature::try_from(signature)
                {
                    Ok(signature) => signature,
                    Err(e) => {
                        log::error!(
                            "Certificate signature format does not match RSA PKCS #8: {e:?}"
                        );
                        return Err(AlertDescription::BadCertificate)?;
                    }
                };

                let verifying_key: rsa::pss::VerifyingKey<D> =
                    rsa::pss::VerifyingKey::new(public_key.clone());

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

    pub(crate) fn verify_rsa_pkcs1v15<D>(
        &self,
        to_verify: &[u8],
        signature: &[u8],
    ) -> Result<(), AlertDescription>
    where
        D: Digest + AssociatedOid + sha2::digest::FixedOutputReset,
    {
        let is_ok: bool = match self {
            PublicKey::Prime256v1(_) | PublicKey::Secp384r1(_) | PublicKey::Ansip521r1(_) => {
                panic!("verify_rsa_pkcs1v15 called with EC key");
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
    pub fn deser(ctx: &mut decode::DecodeContext) -> Option<Self> {
        ctx.tlv_expected(
            "Certificate.tbsCertificate.subjectPublicKeyInfo",
            "SEQUENCE",
            Identifier::SEQUENCE,
        )?;

        let algorithm = AlgorithmIdentifier::deser(
            "Certificate.tbsCertificate.subjectPublicKeyInfo.algorithm",
            ctx,
        )?;

        // BIT STRING: first content byte is the unused-bits count
        let bit_string =
            ctx.der_bit_string("Certificate.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey")?;
        let pub_key_bytes = match bit_string.get(1..) {
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
                        // ansip521r1
                        "1.3.132.0.35" => {
                            match p521::ecdsa::VerifyingKey::from_sec1_bytes(pub_key_bytes) {
                                Ok(key) => PublicKey::Ansip521r1(key),
                                Err(e) => {
                                    log::error!(
                                        "Certificate.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey is not a valid ansip521r1 key in sec1 bytes: {e:?}"
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

        if ctx.der_remaining() > 0 {
            log::error!(
                "Certificate.tbsCertificate.subjectPublicKeyInfo contains {} bytes of extra data",
                ctx.der_remaining()
            );
            return None;
        }

        ctx.end_tlv()?; // end SEQUENCE
        Some(Self {
            algorithm,
            subject_public_key,
        })
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
    pub fn deser(ctx: &mut decode::DecodeContext) -> Option<Self> {
        // The [0] EXPLICIT wrapper: tag byte 0xA0 = ContextSpecific | Constructed | tag 0
        let wrapper_id = Identifier {
            class: Class::ContextSpecific,
            pc: Pc::Constructed,
            tag: Tag::Unknown(0),
        };
        ctx.tlv_expected(
            "Certificate.tbsCertificate.version",
            "[0] EXPLICIT",
            wrapper_id,
        )?;

        let version_bytes = ctx.der_integer("Certificate.tbsCertificate.version")?;

        if version_bytes.len() != 1 {
            log::error!(
                "Certificate.tbsCertificate.version must contain exactly 1 byte, got {}",
                version_bytes.len()
            );
            return None;
        }

        let version: Version = match version_bytes[0] {
            0 => Version::V1,
            1 => Version::V2,
            2 => Version::V3,
            x => {
                log::error!("Certificate.tbsCertificate.version invalid value {x}");
                return None;
            }
        };

        if ctx.der_remaining() > 0 {
            log::error!(
                "Certificate.tbsCertificate.version contains {} bytes of extra data",
                ctx.der_remaining()
            );
            return None;
        }

        ctx.end_tlv()?; // end [0] EXPLICIT
        Some(version)
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
    pub fn deser(name: &str, ctx: &mut decode::DecodeContext) -> Option<Self> {
        // GeneralName uses context-specific IMPLICIT tags (class = ContextSpecific)
        let encoding = Encoding::read(name, ctx)?;

        if encoding.identifier.class != Class::ContextSpecific {
            log::error!(
                "{name} expected identifier class {:?} got {:?}",
                Class::ContextSpecific,
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
                // TODO: implement registeredID type
                log::warn!("{name} ignoring unimplemented GeneralName type registeredID");
                Self::Unimplemented(encoding.content)
            }
            unrecognized => {
                log::warn!("{name} ignoring unrecognized GeneralName type 0x{unrecognized:02x}");
                Self::Unrecognized(encoding.content)
            }
        };

        Some(ret)
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
    /// Parse SubjectAltName from `ctx` positioned at the start of the
    /// extension's `extnValue` content (inside the OCTET STRING wrapper).
    /// `n` is the extension index for diagnostic messages.
    pub fn deser(n: usize, ctx: &mut decode::DecodeContext) -> Option<Self> {
        let name = format!("Certificate.tbsCertificate.extensions[{n}].extnValue");

        // GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
        ctx.tlv_expected(
            &format!("{name}.GeneralNames"),
            "SEQUENCE",
            Identifier::SEQUENCE,
        )?;

        let mut names: Vec<GeneralName> = Vec::new();

        while ctx.der_remaining() > 0 {
            let name_name = format!("{name}.GeneralNames[{}]", names.len());
            let general_name = GeneralName::deser(&name_name, ctx)?;
            names.push(general_name);
        }

        ctx.end_tlv()?; // end GeneralNames SEQUENCE

        if ctx.der_remaining() > 0 {
            log::error!(
                "{name} contains {} bytes of extra data",
                ctx.der_remaining()
            );
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
    /// Parse SubjectKeyIdentifier from `ctx` positioned at the start of the
    /// extension's `extnValue` content (inside the OCTET STRING wrapper).
    pub fn deser(n: usize, ctx: &mut decode::DecodeContext) -> Option<Self> {
        let name = format!("Certificate.tbsCertificate.extensions[{n}].extnValue");

        let key_id = ctx.der_octet_string(&format!("{name}.KeyIdentifier"))?;

        if ctx.der_remaining() > 0 {
            log::error!(
                "{name} contains {} bytes of extra data",
                ctx.der_remaining()
            );
            return None;
        }

        Some(Self { key_id })
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
    /// Parse BasicConstraints from `ctx` positioned at the start of the
    /// extension's `extnValue` content (inside the OCTET STRING wrapper).
    pub fn deser(n: usize, ctx: &mut decode::DecodeContext) -> Option<Self> {
        let name = format!("Certificate.tbsCertificate.extensions[{n}].extnValue");

        ctx.tlv_expected(
            &format!("{name}.BasicConstraints"),
            "SEQUENCE",
            Identifier::SEQUENCE,
        )?;

        let result = if ctx.der_remaining() == 0 {
            Self {
                ca: false,
                path_len_constraint: None,
            }
        } else {
            let ca = ctx.der_bool(&format!("{name}.BasicConstraints.cA"))?;

            let path_len_constraint = if ctx.der_remaining() > 0 {
                let plen =
                    ctx.der_integer(&format!("{name}.BasicConstraints.pathLenConstraint"))?;

                if ctx.der_remaining() > 0 {
                    log::error!(
                        "{name}.BasicConstraints contains {} bytes of extra data",
                        ctx.der_remaining()
                    );
                    return None;
                }

                Some(plen)
            } else {
                None
            };

            Self {
                ca,
                path_len_constraint,
            }
        };

        ctx.end_tlv()?; // end SEQUENCE

        if ctx.der_remaining() > 0 {
            log::error!(
                "{name} contains {} bytes of extra data",
                ctx.der_remaining()
            );
            return None;
        }

        Some(result)
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
    /// Parse KeyUsage from `ctx` positioned at the start of the extension's
    /// `extnValue` content (inside the OCTET STRING wrapper).
    pub fn deser(n: usize, ctx: &mut decode::DecodeContext) -> Option<Self> {
        let name = format!("Certificate.tbsCertificate.extensions[{n}].extnValue");

        let usage = ctx.der_bit_string(&format!("{name}.KeyUsage"))?;

        if ctx.der_remaining() > 0 {
            log::error!(
                "{name} contains {} bytes of extra data",
                ctx.der_remaining()
            );
            return None;
        }

        Some(Self { usage })
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

    /// Raw DER bytes of unrecognized extensions (preserved for diagnostics)
    unrecognized: Vec<Vec<u8>>,
}

impl Extensions {
    /// Parse the Extensions SEQUENCE from `ctx`.
    /// `ctx` must be positioned at the outer SEQUENCE TLV.
    pub fn deser(ctx: &mut decode::DecodeContext) -> Option<Self> {
        // Outer SEQUENCE wrapping all extensions
        ctx.tlv_expected(
            "Certificate.tbsCertificate.extensions",
            "SEQUENCE",
            Identifier::SEQUENCE,
        )?;

        let mut subject_key_identifier: Option<SubjectKeyIdentifier> = None;
        let mut key_usage: Option<KeyUsage> = None;
        let mut subject_alt_name: Option<SubjectAltName> = None;
        let mut basic_constraints: Option<BasicConstraints> = None;
        let mut unrecognized: Vec<Vec<u8>> = Vec::new();

        let mut n: usize = 0;

        while ctx.der_remaining() > 0 {
            // Each extension is a SEQUENCE { extnID OID, critical BOOLEAN OPTIONAL, extnValue OCTET STRING }
            ctx.tlv_expected(
                format!("Certificate.tbsCertificate.extensions[{n}]").as_str(),
                "SEQUENCE",
                Identifier::SEQUENCE,
            )?;

            let ext_obj_id = ObjectIdentifier::deser(
                format!("Certificate.tbsCertificate.extensions[{n}].extnID").as_str(),
                ctx,
            )?;

            // Next field is either BOOLEAN (critical) or OCTET STRING (extnValue)
            let maybe_bool_or_os = Encoding::read_expected2(
                Identifier::BOOLEAN,
                Identifier::OCTETSTRING,
                format!("Certificate.tbsCertificate.extensions[{n}].critical_or_extnValue")
                    .as_str(),
                ctx,
            )?;

            let (critical, octetstring_content): (bool, Vec<u8>) = if maybe_bool_or_os.identifier
                == Identifier::BOOLEAN
            {
                let critical = Encoding::bool_from_content(
                    &maybe_bool_or_os.content,
                    &format!("Certificate.tbsCertificate.extensions[{n}].critical"),
                )?;

                // Now read the OCTET STRING
                let os = Encoding::read_expected(
                    Identifier::OCTETSTRING,
                    format!("Certificate.tbsCertificate.extensions[{n}].extnValue").as_str(),
                    ctx,
                )?;

                if ctx.der_remaining() > 0 {
                    log::error!(
                        "Certificate.tbsCertificate.extensions[{n}] contains {} bytes of extra data",
                        ctx.der_remaining()
                    );
                    return None;
                }

                (critical, os.content)
            } else {
                // The encoding we read was already the OCTET STRING
                if ctx.der_remaining() > 0 {
                    log::error!(
                        "Certificate.tbsCertificate.extensions[{n}] contains {} bytes of extra data after extnValue",
                        ctx.der_remaining()
                    );
                    return None;
                }
                (false, maybe_bool_or_os.content)
            };

            // The octetstring_content IS the raw DER of the extension value.
            // We need to parse it through a sub-context that points into the
            // main buffer.  Since the content is already materialized as
            // Vec<u8>, we create a temporary DecodeContext over it.
            let mut ext_ctx = decode::DecodeContext::new(
                &format!("Certificate.tbsCertificate.extensions[{n}].extnValue"),
                octetstring_content.clone(),
            );

            match ext_obj_id.repr.as_str() {
                // SubjectKeyIdentifier
                "2.5.29.14" => {
                    if subject_key_identifier
                        .replace(SubjectKeyIdentifier::deser(n, &mut ext_ctx)?)
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
                        .replace(KeyUsage::deser(n, &mut ext_ctx)?)
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
                        .replace(SubjectAltName::deser(n, &mut ext_ctx)?)
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
                        .replace(BasicConstraints::deser(n, &mut ext_ctx)?)
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

                    unrecognized.push(octetstring_content);
                }
            }

            ctx.end_tlv()?; // end extension SEQUENCE
            n = n.saturating_add(1);
        }

        ctx.end_tlv()?; // end outer extensions SEQUENCE

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
    /// Parse TBSCertificate fields from `ctx`.
    /// `ctx` must be positioned at the start of the TBSCertificate SEQUENCE TLV.
    pub fn deser(ctx: &mut decode::DecodeContext) -> Option<Self> {
        // Open the TBSCertificate SEQUENCE
        ctx.tlv_expected(
            "Certificate.tbsCertificate",
            "SEQUENCE",
            Identifier::SEQUENCE,
        )?;

        let version = Version::deser(ctx)?;
        let serial_number = ctx.der_integer("Certificate.tbsCertificate.serialNumber")?;
        let signature = AlgorithmIdentifier::deser("Certificate.tbsCertificate.signature", ctx)?;
        let issuer = Name::deser("Certificate.tbsCertificate.issuer", ctx)?;
        let validity = Validity::deser(ctx)?;
        let subject = Name::deser("Certificate.tbsCertificate.subject", ctx)?;
        let subject_public_key_info = SubjectPublicKeyInfo::deser(ctx)?;

        let mut issuer_unique_id: Option<Vec<u8>> = None;
        let mut subject_unique_id: Option<Vec<u8>> = None;
        let mut extensions: Option<Extensions> = None;

        let mut prev_tag: u8 = 0;

        while ctx.der_remaining() > 0 {
            // Optional context-specific fields: [1] issuerUniqueID, [2] subjectUniqueID, [3] extensions
            let encoding = Encoding::read("Certificate.tbsCertificate optional", ctx)?;

            if encoding.identifier.class != Class::ContextSpecific {
                log::error!(
                    "Unexpected identifier class after Certificate.tbsCertificate.subjectPublicKeyInfo, expected {:?}, got {:?}",
                    Class::ContextSpecific,
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
                3 => {
                    // [3] EXPLICIT Extensions — the content IS the Extensions SEQUENCE
                    let mut ext_ctx = decode::DecodeContext::new(
                        "Certificate.tbsCertificate.extensions",
                        encoding.content,
                    );
                    extensions = Some(Extensions::deser(&mut ext_ctx)?);
                }
                _ => {
                    log::error!(
                        "Certificate.tbsCertificate contains unexpected context-specific tag {tag}"
                    );
                    return None;
                }
            }
        }

        ctx.end_tlv()?; // end TBSCertificate SEQUENCE

        Some(Self {
            version,
            serial_number,
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
    pub fn deser(name: &str, ctx: &mut decode::DecodeContext) -> Option<Self> {
        ctx.tlv_expected(name, "SEQUENCE", Identifier::SEQUENCE)?;

        let algorithm = ObjectIdentifier::deser(&format!("{name}.algorithm"), ctx)?;

        let parameters = if ctx.der_remaining() == 0 {
            None
        } else {
            let parameters = ObjectIdentifier::deser_or_null(&format!("{name}.parameters"), ctx)?;

            if ctx.der_remaining() > 0 {
                log::error!(
                    "{name} contains {} bytes of extra data",
                    ctx.der_remaining()
                );
                return None;
            }

            parameters
        };

        ctx.end_tlv()?; // end SEQUENCE
        Some(Self {
            algorithm,
            parameters,
        })
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
    pub fn deser(ctx: &mut decode::DecodeContext) -> Option<Self> {
        let bitstring = ctx.der_bit_string("Certificate.signatureValue")?;
        Some(Self { bitstring })
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
    /// Decode a DER-encoded X.509 certificate from the TLS `DecodeContext`.
    ///
    /// `ctx` must be positioned at the start of the certificate DER data
    /// (i.e. at the outer `SEQUENCE` TLV).  After a successful call the
    /// cursor is advanced to just after the certificate bytes.
    ///
    /// Returns `(tbs_bytes, certificate)` where `tbs_bytes` is the raw
    /// DER-encoded TBSCertificate (used for signature verification).
    pub fn decode(
        ctx: &mut decode::DecodeContext,
        ignore_extra: bool,
    ) -> Result<(Vec<u8>, Self), AlertDescription> {
        // Record where we are in the TLS buffer before we start
        let cert_start = ctx.current_position();

        // Open the outer Certificate SEQUENCE
        ctx.tlv_expected("Certificate", "SEQUENCE", Identifier::SEQUENCE)
            .ok_or(AlertDescription::BadCertificate)?;

        // Record the position of the TBSCertificate SEQUENCE (for byte extraction)
        let tbs_start = ctx.current_position();

        // Parse TBSCertificate — this opens + closes the inner SEQUENCE
        let tbs_certificate = TbsCertificate::deser(ctx).ok_or(AlertDescription::BadCertificate)?;

        let tbs_end = ctx.current_position();

        // Parse signatureAlgorithm
        let signature_algorithm = AlgorithmIdentifier::deser("Certificate.signatureAlgorithm", ctx)
            .ok_or(AlertDescription::BadCertificate)?;

        // Parse signatureValue
        let signature_value = SignatureValue::deser(ctx).ok_or(AlertDescription::BadCertificate)?;

        if ctx.der_remaining() > 0 {
            log::error!(
                "CertificateEntry cert_data contains {} extra bytes of data",
                ctx.der_remaining()
            );
            return Err(AlertDescription::BadCertificate);
        }

        // Close the outer Certificate SEQUENCE
        ctx.end_tlv().ok_or(AlertDescription::BadCertificate)?;

        let cert_end = ctx.current_position();

        // If there are bytes after the Certificate SEQUENCE and !ignore_extra, error
        if !ignore_extra {
            // We already closed the TLV and verified der_remaining() == 0 inside it,
            // but there may still be trailing bytes in the TLS vec context
            let _ = cert_end; // cert_end == tls cursor position now
        }

        // Extract the raw TBSCertificate bytes for signature verification
        let tbs_bytes = ctx
            .original_buffer()
            .get(tbs_start..tbs_end)
            .ok_or_else(|| {
                log::error!("Failed to extract TBSCertificate bytes");
                AlertDescription::BadCertificate
            })?
            .to_vec();

        let _ = cert_start; // suppress unused warning

        Ok((
            tbs_bytes,
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
                pk.verify_rsa_pkcs1v15::<sha2::Sha256>(tbs_certificate_bytes, signature_bytes)
            }
            // sha384WithRSAEncryption (PKCS #1)
            "1.2.840.113549.1.1.12" => {
                pk.verify_rsa_pkcs1v15::<sha2::Sha384>(tbs_certificate_bytes, signature_bytes)
            }
            // sha512WithRSAEncryption (PKCS #1)
            "1.2.840.113549.1.1.13" => {
                pk.verify_rsa_pkcs1v15::<sha2::Sha512>(tbs_certificate_bytes, signature_bytes)
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
