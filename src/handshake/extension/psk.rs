use crate::{alert::AlertDescription, parse};

/// # References
///
/// * [RFC 8446 Section 4.2.11](https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.11)
///
/// ```text
/// struct {
///     opaque identity<1..2^16-1>;
///     uint32 obfuscated_ticket_age;
/// } PskIdentity;
/// ```
#[derive(Debug)]
pub struct PskIdentity {
    pub(crate) identity: Vec<u8>,
    obfuscated_ticket_age: u32,
}

impl PskIdentity {
    pub fn deser(b: &[u8]) -> Result<(&[u8], Self), AlertDescription> {
        let (b, identity): (_, &[u8]) = parse::vec16("PskIdentity identity", b, 1, 1)?;

        let (b, obfuscated_ticket_age): (_, u32) =
            parse::u32("PskIdentity obfuscated_ticket_age", b)?;

        Ok((
            b,
            Self {
                identity: identity.to_vec(),
                obfuscated_ticket_age,
            },
        ))
    }
}

/// # References
///
/// * [RFC 8446 Section 4.2.11](https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.11)
///
/// ```text
/// opaque PskBinderEntry<32..255>;
/// ```
#[derive(Debug)]
pub struct PskBinderEntry {
    data: Vec<u8>,
}

impl PskBinderEntry {
    pub fn deser(b: &[u8]) -> Result<(&[u8], Self), AlertDescription> {
        let (b, binder_entry) = parse::vec8("PskBinderEntry", b, 32, 1)?;
        Ok((
            b,
            Self {
                data: binder_entry.to_vec(),
            },
        ))
    }
}

/// # References
///
/// * [RFC 8446 Section 4.2.11](https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.11)
///
/// ```text
/// struct {
///     opaque identity<1..2^16-1>;
///     uint32 obfuscated_ticket_age;
/// } PskIdentity;
///
/// opaque PskBinderEntry<32..255>;
///
/// struct {
///     PskIdentity identities<7..2^16-1>;
///     PskBinderEntry binders<33..2^16-1>;
/// } OfferedPsks;
///
/// struct {
///     select (Handshake.msg_type) {
///         case client_hello: OfferedPsks;
///         case server_hello: uint16 selected_identity;
///     };
/// } PreSharedKeyExtension;
/// ```
#[derive(Debug)]
pub struct OfferedPsks {
    pub(crate) identities: Vec<PskIdentity>,
    binders: Vec<PskBinderEntry>,
}

impl OfferedPsks {
    pub fn deser(b: &[u8]) -> Result<Self, AlertDescription> {
        let (b, mut identities_b): (_, &[u8]) = parse::vec16("OfferedPsks identities", b, 7, 1)?;

        let mut identities: Vec<PskIdentity> = Vec::new();
        while !identities_b.is_empty() {
            let (new_identities, identity) = PskIdentity::deser(identities_b)?;
            identities_b = new_identities;
            identities.push(identity);
        }

        let (_, mut binders_b): (_, &[u8]) = parse::vec16("OfferedPsks binders", b, 33, 1)?;

        let mut binders: Vec<PskBinderEntry> = Default::default();
        while !binders_b.is_empty() {
            let (new_binders, binder) = PskBinderEntry::deser(binders_b)?;
            binders_b = new_binders;
            binders.push(binder);
        }

        Ok(Self {
            identities,
            binders,
        })
    }
}

/// # References
///
/// * [RFC 8446 Section 4.2.11](https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.11)
///
/// ```text
/// struct {
///     opaque identity<1..2^16-1>;
///     uint32 obfuscated_ticket_age;
/// } PskIdentity;
///
/// opaque PskBinderEntry<32..255>;
///
/// struct {
///     PskIdentity identities<7..2^16-1>;
///     PskBinderEntry binders<33..2^16-1>;
/// } OfferedPsks;
///
/// struct {
///     select (Handshake.msg_type) {
///         case client_hello: OfferedPsks;
///         case server_hello: uint16 selected_identity;
///     };
/// } PreSharedKeyExtension;
/// ```
#[derive(Debug)]
pub struct PskServerHello {
    selected_identity: u16,
}

impl PskServerHello {
    pub fn new(selected_identity: u16) -> Self {
        Self { selected_identity }
    }

    pub fn ser(&self) -> Vec<u8> {
        self.selected_identity.to_be_bytes().to_vec()
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum PskKeyExchangeMode {
    /// PSK-only key establishment.  In this mode, the server
    /// MUST NOT supply a "key_share" value.
    psk_ke = 0,
    /// PSK with (EC)DHE key establishment.  In this mode, the
    /// client and server MUST supply "key_share" values as described in
    /// Section 4.2.8.
    psk_dhe_ke = 1,
}

impl TryFrom<u8> for PskKeyExchangeMode {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::psk_ke),
            1 => Ok(Self::psk_dhe_ke),
            _ => Err(value),
        }
    }
}

/// # References
///
/// * [RFC 8446 Section 4.2.9](https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.9)
///
/// ```text
/// enum { psk_ke(0), psk_dhe_ke(1), (255) } PskKeyExchangeMode;
///
/// struct {
///     PskKeyExchangeMode ke_modes<1..255>;
/// } PskKeyExchangeModes;
/// ```
#[derive(Debug)]
pub struct PskKeyExchangeModes {
    ke_modes: Vec<Result<PskKeyExchangeMode, u8>>,
}

impl PskKeyExchangeModes {
    pub fn deser(b: &[u8]) -> Result<Self, AlertDescription> {
        let (_, b): (_, &[u8]) = parse::vec8("PskKeyExchangeModes ke_modes", b, 1, 1)?;

        let mut ke_modes: Vec<Result<PskKeyExchangeMode, u8>> = Vec::with_capacity(b.len());

        for ke_mode in b {
            ke_modes.push((*ke_mode).try_into())
        }

        Ok(Self { ke_modes })
    }

    pub fn contains_psk_dhe_ke(&self) -> bool {
        self.ke_modes.contains(&Ok(PskKeyExchangeMode::psk_dhe_ke))
    }
}
