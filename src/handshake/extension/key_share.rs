use crate::{AlertDescription, handshake::named_group::NamedGroup, parse};

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
#[derive(Debug)]
pub(crate) struct KeyShareEntry {
    group: Result<NamedGroup, u16>,
    key_exchange: Vec<u8>,
}

impl KeyShareEntry {
    pub fn new_secp256r1(data: &[u8; 65]) -> Self {
        Self {
            group: Ok(NamedGroup::secp256r1),
            key_exchange: data.to_vec(),
        }
    }

    pub fn ser(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::with_capacity(self.key_exchange.len().saturating_add(4));

        match self.group {
            Ok(o) => buf.extend_from_slice(&o.to_be_bytes()),
            Err(e) => buf.extend_from_slice(&e.to_be_bytes()),
        };

        buf.extend_from_slice(
            &u16::try_from(self.key_exchange.len())
                // unwrap will not occur, length validated in constructor
                .unwrap()
                .to_be_bytes(),
        );

        buf.extend_from_slice(&self.key_exchange);

        buf
    }

    pub fn deser(b: &[u8]) -> Result<(&[u8], Self), AlertDescription> {
        let (b, group) = parse::u16("KeyShareEntry group", b)?;
        let (b, key_exchange) = parse::vec16("KeyShareEntry key_exchange", b, 1, 1)?;

        Ok((
            b,
            Self {
                group: NamedGroup::try_from(group),
                key_exchange: key_exchange.to_vec(),
            },
        ))
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
#[derive(Debug)]
pub struct KeyShareClientHello {
    pub secp256r1: Option<p256::PublicKey>,
    empty: bool,
}

impl KeyShareClientHello {
    pub fn deser_secp256r1(b: &[u8]) -> Result<Self, AlertDescription> {
        let (_, mut b) = parse::vec16("KeyShareClientHello client_shares", b, 0, 1)?;

        let empty: bool = b.is_empty();

        let mut secp256r1: Option<p256::PublicKey> = None;

        while !b.is_empty() {
            let (new_b, client_share) = KeyShareEntry::deser(b)?;
            b = new_b;

            if client_share.group == Ok(NamedGroup::secp256r1) {
                const CLIENT_SHARE_LEN_EXPECTED: usize = 65;
                let client_share_len: usize = client_share.key_exchange.len();
                if client_share_len != CLIENT_SHARE_LEN_EXPECTED {
                    log::error!(
                        "KeyShareEntry secp256r1 has key_exchange length {} expected {}",
                        client_share_len,
                        CLIENT_SHARE_LEN_EXPECTED
                    );
                    return Err(AlertDescription::DecodeError)?;
                }

                secp256r1 = match p256::PublicKey::from_sec1_bytes(&client_share.key_exchange) {
                    Ok(pk) => Some(pk),
                    Err(_) => {
                        log::error!(
                            "KeyShareEntry secp256r1 key_exchange data is not a valid SEC1 public key"
                        );
                        return Err(AlertDescription::DecodeError)?;
                    }
                };
            } else {
                log::warn!("Unused group type {:?}", client_share.group);
            }
        }

        Ok(Self { secp256r1, empty })
    }

    pub fn is_empty(&self) -> bool {
        self.empty
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
///     KeyShareEntry server_share;
/// } KeyShareServerHello;
/// ```
pub type KeyShareServerHello = KeyShareEntry;
