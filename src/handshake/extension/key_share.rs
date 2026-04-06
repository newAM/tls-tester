use crate::{alert::AlertDescription, decode::DecodeContext, handshake::named_group::NamedGroup};

/// Unrecognized KeyShare entry.
#[derive(Debug, Clone)]
pub(crate) struct UnrecognizedKeyShareEntry {
    pub group: Result<NamedGroup, u16>,
    pub key_exchange: Vec<u8>,
}

/// KeyShare entry.
///
/// # References
///
/// * [RFC 8446 Section 4.2.8](https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8)
///
/// ```text
/// struct {
///     NamedGroup group;
///     opaque key_exchange<1..2^16-1>;
/// } KeyShareEntry;
/// ```
#[derive(Debug, Clone)]
pub(crate) enum KeyShareEntry {
    Secp256r1(p256::PublicKey),
    X25519(crate::crypto::x25519::PublicKey),
    Unrecognized(UnrecognizedKeyShareEntry),
}

impl KeyShareEntry {
    pub fn named_group(&self) -> Result<NamedGroup, u16> {
        match self {
            KeyShareEntry::Secp256r1(_) => Ok(NamedGroup::secp256r1),
            KeyShareEntry::X25519(_) => Ok(NamedGroup::x25519),
            KeyShareEntry::Unrecognized(ur) => ur.group,
        }
    }

    pub fn ser(&self) -> Vec<u8> {
        let named_group: [u8; 2] = match self {
            KeyShareEntry::Secp256r1(_) => NamedGroup::secp256r1.to_be_bytes(),
            KeyShareEntry::X25519(_) => NamedGroup::x25519.to_be_bytes(),
            KeyShareEntry::Unrecognized(unrecognized_key_share_entry) => {
                match unrecognized_key_share_entry.group {
                    Ok(ng) => ng.to_be_bytes(),
                    Err(val) => val.to_be_bytes(),
                }
            }
        };

        let key_exchange: &[u8] = match self {
            KeyShareEntry::Secp256r1(public_key) => &public_key.to_sec1_bytes(),
            KeyShareEntry::X25519(public_key) => public_key.as_bytes(),
            KeyShareEntry::Unrecognized(unrecognized) => &unrecognized.key_exchange,
        };

        let mut buf: Vec<u8> = Vec::with_capacity(key_exchange.len().saturating_add(4));
        buf.extend_from_slice(&named_group);
        buf.extend_from_slice(
            &u16::try_from(key_exchange.len())
                // unwrap will not occur, length validated in constructor
                .unwrap()
                .to_be_bytes(),
        );
        buf.extend_from_slice(key_exchange);

        buf
    }

    pub fn decode(ctx: &mut DecodeContext) -> Result<Self, AlertDescription> {
        let group: u16 = ctx.u16("group", "NamedGroup")?;

        let named_group = NamedGroup::try_from(group);

        let key_exchange: Vec<u8> = ctx.vec16("key_exchange", "opaque<1..2^16-1>", 1, 1)?;

        match named_group {
            Ok(NamedGroup::secp256r1) => {
                const P256_CLIENT_SHARE_LEN_EXPECTED: usize = 65;

                if key_exchange.len() != P256_CLIENT_SHARE_LEN_EXPECTED {
                    log::error!(
                        "{:?} secp256r1 has key_exchange length {} expected {}",
                        ctx,
                        key_exchange.len(),
                        P256_CLIENT_SHARE_LEN_EXPECTED
                    );
                    return Err(AlertDescription::DecodeError)?;
                }

                match p256::PublicKey::from_sec1_bytes(&key_exchange) {
                    Ok(pk) => Ok(Self::Secp256r1(pk)),
                    Err(_) => {
                        log::error!(
                            "{:?} secp256r1 key_exchange data is not a valid SEC1 public key",
                            ctx
                        );
                        Err(AlertDescription::DecodeError)
                    }
                }
            }
            Ok(NamedGroup::x25519) => {
                let key_exact: [u8; 32] = match key_exchange.clone().try_into() {
                    Ok(key) => key,
                    Err(_) => {
                        log::error!(
                            "{:?} x25519 has key_exchange length {} expected 32",
                            ctx,
                            key_exchange.len(),
                        );
                        return Err(AlertDescription::DecodeError)?;
                    }
                };
                Ok(Self::X25519(crate::crypto::x25519::PublicKey::from(
                    key_exact,
                )))
            }
            Err(_) | Ok(_) => Ok(Self::Unrecognized(UnrecognizedKeyShareEntry {
                group: named_group,
                key_exchange: key_exchange.to_vec(),
            })),
        }
    }
}

/// KeyShare extension for the ClientHello.
///
/// # References
///
/// * [RFC 8446 Section 4.2.8](https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8)
///
/// ```text
/// struct {
///     KeyShareEntry client_shares<0..2^16-1>;
/// } KeyShareClientHello;
/// ```
#[derive(Debug, Clone)]
pub(crate) struct KeyShareClientHello {
    pub(crate) client_shares: Vec<KeyShareEntry>,
}

impl KeyShareClientHello {
    pub fn decode(ctx: &mut DecodeContext) -> Result<Self, AlertDescription> {
        ctx.begin_vec16("client_shares", "KeyShareEntry<0..2^16-1>", 0, 1)?;

        let mut client_shares: Vec<KeyShareEntry> = Vec::new();
        let mut index = 0;
        while ctx.remaining() > 0 {
            ctx.begin_element("client_share", "KeyShareEntry", index);
            let client_share = KeyShareEntry::decode(ctx)?;
            client_shares.push(client_share);
            ctx.end_element();
            index += 1;
        }

        ctx.end_vec()?;

        Ok(Self { client_shares })
    }

    pub fn is_empty(&self) -> bool {
        self.client_shares.is_empty()
    }

    pub fn ser(client_shares: Vec<KeyShareEntry>) -> Vec<u8> {
        let mut ret: Vec<u8> = Vec::new();

        let entries: Vec<Vec<u8>> = client_shares.iter().map(|kse| kse.ser()).collect();
        let entries_len: usize = entries
            .iter()
            .fold(0, |acc, kse| acc.checked_add(kse.len()).unwrap());

        ret.extend_from_slice(u16::try_from(entries_len).unwrap().to_be_bytes().as_ref());

        entries.iter().for_each(|kse| ret.extend_from_slice(kse));

        ret
    }
}

/// KeyShare extension for the ServerHello.
///
/// # References
///
/// * [RFC 8446 Section 4.2.8](https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8)
///
/// ```text
/// struct {
///     NamedGroup selected_group;
/// } KeyShareHelloRetryRequest;
///
/// struct {
///     KeyShareEntry server_share;
/// } KeyShareServerHello;
/// ```
#[derive(Debug)]
pub(crate) enum KeyShareServerHello {
    KeyShareServerHello(KeyShareEntry),
    KeyShareHelloRetryRequest(NamedGroup),
}

impl KeyShareServerHello {
    pub fn decode(ctx: &mut DecodeContext, retry_request: bool) -> Result<Self, AlertDescription> {
        if retry_request {
            let selected_group = ctx.u16("selected_group", "NamedGroup")?;

            let named_group: NamedGroup = match NamedGroup::try_from(selected_group) {
                Ok(ng) => ng,
                Err(val) => {
                    // Upon receipt of this extension in a HelloRetryRequest, the client
                    // MUST verify that (1) the selected_group field corresponds to a group
                    // which was provided in the "supported_groups" extension in the
                    // original ClientHello and (2) the selected_group field does not
                    // correspond to a group which was provided in the "key_share" extension
                    // in the original ClientHello.  If either of these checks fails, then
                    // the client MUST abort the handshake with an "illegal_parameter"
                    // alert.
                    log::error!("{:?} selected an unknown named group 0x{val:04x}", ctx);
                    return Err(AlertDescription::IllegalParameter);
                }
            };
            Ok(Self::KeyShareHelloRetryRequest(named_group))
        } else {
            let kse = KeyShareEntry::decode(ctx)?;
            Ok(Self::KeyShareServerHello(kse))
        }
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//
//     #[test]
//     fn key_share_server_hello_decode() {
//         todo!()
//     }
// }
