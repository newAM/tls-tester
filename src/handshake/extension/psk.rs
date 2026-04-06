use crate::{alert::AlertDescription, decode::DecodeContext};

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
pub(crate) struct PskIdentity {
    pub(crate) identity: Vec<u8>,
    pub(crate) obfuscated_ticket_age: u32,
}

impl PskIdentity {
    pub fn decode(ctx: &mut DecodeContext) -> Result<Self, AlertDescription> {
        let identity = ctx.vec16("identity", "opaque<1..2^16-1>", 1, 1)?;
        let obfuscated_ticket_age = ctx.u32("obfuscated_ticket_age", "uint32")?;

        Ok(Self {
            identity,
            obfuscated_ticket_age,
        })
    }

    pub fn ser(&self) -> Vec<u8> {
        let mut ret: Vec<u8> = Vec::new();
        // length validated in constructors
        ret.extend_from_slice(
            u16::try_from(self.identity.len())
                .unwrap()
                .to_be_bytes()
                .as_ref(),
        );
        ret.extend_from_slice(self.identity.as_slice());
        ret.extend_from_slice(self.obfuscated_ticket_age.to_be_bytes().as_ref());
        ret
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
pub(crate) struct PskBinderEntry {
    pub(crate) data: Vec<u8>,
}

impl PskBinderEntry {
    pub fn decode(ctx: &mut DecodeContext) -> Result<Self, AlertDescription> {
        let data = ctx.vec8("binder_entry", "opaque<32..255>", 32, 1)?;

        Ok(Self { data })
    }

    pub fn ser(&self) -> Vec<u8> {
        let mut ret: Vec<u8> = Vec::new();
        // length validated in constructors
        ret.push(u8::try_from(self.data.len()).unwrap());
        ret.extend_from_slice(&self.data);
        ret
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
    pub fn decode(ctx: &mut DecodeContext) -> Result<Self, AlertDescription> {
        ctx.begin_vec16("identities", "PskIdentity<7..2^16-1>", 7, 1)?;

        let mut identities: Vec<PskIdentity> = Vec::new();
        let mut index = 0;
        while ctx.remaining() > 0 {
            ctx.begin_element("identity", "PskIdentity", index);
            let identity = PskIdentity::decode(ctx)?;
            identities.push(identity);
            ctx.end_element();
            index += 1;
        }

        ctx.end_vec()?;

        ctx.begin_vec16("binders", "PskBinderEntry<33..2^16-1>", 33, 1)?;

        let mut binders: Vec<PskBinderEntry> = Vec::new();
        index = 0;
        while ctx.remaining() > 0 {
            ctx.begin_element("binder", "PskBinderEntry", index);
            let binder = PskBinderEntry::decode(ctx)?;
            binders.push(binder);
            ctx.end_element();
            index += 1;
        }

        ctx.end_vec()?;

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
pub(crate) enum PskKeyExchangeMode {
    /// PSK-only key establishment.  In this mode, the server
    /// MUST NOT supply a "key_share" value.
    psk_ke = 0,
    /// PSK with (EC)DHE key establishment.  In this mode, the
    /// client and server MUST supply "key_share" values as described in
    /// Section 4.2.8.
    psk_dhe_ke = 1,
}

impl From<PskKeyExchangeMode> for u8 {
    fn from(value: PskKeyExchangeMode) -> Self {
        value as u8
    }
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
pub(crate) struct PskKeyExchangeModes {
    ke_modes: Vec<Result<PskKeyExchangeMode, u8>>,
}

impl PskKeyExchangeModes {
    pub fn decode(ctx: &mut DecodeContext) -> Result<Self, AlertDescription> {
        ctx.begin_vec8("ke_modes", "PskKeyExchangeMode<1..255>", 1, 1)?;

        let mut ke_modes: Vec<Result<PskKeyExchangeMode, u8>> = Vec::new();
        while ctx.remaining() > 0 {
            let ke_mode = ctx.u8("ke_mode", "PskKeyExchangeMode")?;
            ke_modes.push(ke_mode.try_into());
        }

        ctx.end_vec()?;

        Ok(Self { ke_modes })
    }

    pub fn contains_psk_dhe_ke(&self) -> bool {
        self.ke_modes.contains(&Ok(PskKeyExchangeMode::psk_dhe_ke))
    }
}
