//! Encrypted Client Hello

use crate::crypto::hpke::{AeadId, KdfId, KemId};
use crate::handshake::extension::ExtensionType;
use crate::{AlertDescription, decode::DecodeContext};

/// # References
///
/// - [draft-ietf-tls-esni-25 Section 5](https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-25#section-5)
///
/// ```text
/// enum { outer(0), inner(1) } ECHClientHelloType;
/// ```
#[repr(u8)]
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ECHClientHelloType {
    Outer = 0,
    Inner = 1,
}

impl From<ECHClientHelloType> for u8 {
    fn from(value: ECHClientHelloType) -> Self {
        value as u8
    }
}

impl ECHClientHelloType {
    pub(crate) fn decode(ctx: &mut DecodeContext) -> Result<Self, AlertDescription> {
        let ech_type = ctx.u8("type", "ECHClientHelloType")?;

        match ech_type {
            0 => Ok(ECHClientHelloType::Outer),
            1 => Ok(ECHClientHelloType::Inner),
            x => {
                log::error!("{} invalid value: 0x{x:02x}", ctx.current_path());
                Err(AlertDescription::DecodeError)
            }
        }
    }
}

/// # References
///
/// - [draft-ietf-tls-esni-25 Section 4](https://datatracker.ietf.org/doc/draft-ietf-tls-esni/25/)
///
/// ```text
/// struct {
///     HpkeKdfId kdf_id;
///     HpkeAeadId aead_id;
/// } HpkeSymmetricCipherSuite;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HpkeSymmetricCipherSuite {
    pub(crate) kdf_id: KdfId,
    pub(crate) aead_id: AeadId,
}

impl HpkeSymmetricCipherSuite {
    pub(crate) fn decode(ctx: &mut DecodeContext) -> Result<Self, AlertDescription> {
        let kdf_id = ctx.u16("kdf_id", "HpkeKdfId")?;
        let aead_id = ctx.u16("aead_id", "HpkeAeadId")?;

        let kdf_id: KdfId = match KdfId::try_from(kdf_id) {
            Ok(kdf_id) => kdf_id,
            Err(e) => {
                log::warn!("{} unknown kdf_id value 0x{e:04X}", ctx.current_path());
                return Err(AlertDescription::IllegalParameter);
            }
        };

        let aead_id: AeadId = match AeadId::try_from(aead_id) {
            Ok(aead_id) => aead_id,
            Err(e) => {
                log::error!("{} unknown aead_id value 0x{e:04X}", ctx.current_path());
                return Err(AlertDescription::IllegalParameter);
            }
        };

        Ok(Self { kdf_id, aead_id })
    }

    pub fn ser(&self) -> [u8; 4] {
        [
            self.kdf_id.to_be_bytes()[0],
            self.kdf_id.to_be_bytes()[1],
            self.aead_id.to_be_bytes()[0],
            self.aead_id.to_be_bytes()[1],
        ]
    }
}

/// # References
///
/// - [draft-ietf-tls-esni-25 Section 4](https://datatracker.ietf.org/doc/draft-ietf-tls-esni/25/)
///
/// ```text
/// opaque HpkePublicKey<1..2^16-1>;
///
/// struct {
///     uint8 config_id;
///     HpkeKemId kem_id;
///     HpkePublicKey public_key;
///     HpkeSymmetricCipherSuite cipher_suites<4..2^16-4>;
/// } HpkeKeyConfig;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HpkeKeyConfig {
    pub(crate) config_id: u8,
    pub(crate) kem_id: KemId,
    pub(crate) public_key: Vec<u8>,
    pub(crate) cipher_suites: Vec<HpkeSymmetricCipherSuite>,
}

impl HpkeKeyConfig {
    pub(crate) fn decode(ctx: &mut DecodeContext) -> Result<Self, AlertDescription> {
        let config_id = ctx.u8("config_id", "uint8")?;
        let kem_id = ctx.u16("kem_id", "HpkeKemId")?;

        let kem_id: KemId = match KemId::try_from(kem_id) {
            Ok(kem_id) => kem_id,
            Err(e) => {
                log::warn!("{} ignoring unknown value 0x{e:04X}", ctx.current_path());
                return Err(AlertDescription::IllegalParameter);
            }
        };

        let public_key = ctx.vec16("public_key", "opaque<1..2^16-1>", 1, 1)?;

        ctx.begin_vec16("cipher_suites", "HpkeSymmetricCipherSuite<4..2^16-4>", 4, 4)?;

        let mut cipher_suites: Vec<HpkeSymmetricCipherSuite> = Vec::new();
        let mut n: usize = 0;

        while ctx.remaining() > 0 {
            ctx.begin_element("cipher_suite", "HpkeSymmetricCipherSuite", n);
            let cipher_suite = HpkeSymmetricCipherSuite::decode(ctx)?;
            ctx.end_element();
            cipher_suites.push(cipher_suite);
            n = n.saturating_add(1);
        }

        ctx.end_vec()?;

        Ok(Self {
            config_id,
            kem_id,
            public_key,
            cipher_suites,
        })
    }

    pub(crate) fn ser(&self) -> Vec<u8> {
        let mut ret: Vec<u8> = Vec::new();
        ret.push(self.config_id);
        ret.extend_from_slice(self.kem_id.to_be_bytes().as_ref());
        ret.extend_from_slice(
            u16::try_from(self.public_key.len())
                .expect("HpkeKeyConfig.public_key length exceeds u16::MAX")
                .to_be_bytes()
                .as_ref(),
        );
        ret.extend_from_slice(&self.public_key);
        let cipher_suites_bytes: usize = self.cipher_suites.len() * 4;
        ret.extend_from_slice(
            u16::try_from(cipher_suites_bytes)
                .expect("HpkeKeyConfig.cipher_suites length exceeds u16::MAX")
                .to_be_bytes()
                .as_ref(),
        );
        self.cipher_suites
            .iter()
            .for_each(|cs| ret.extend_from_slice(&cs.ser()));

        ret
    }
}

/// # References
///
/// - [draft-ietf-tls-esni-25 Section 4](https://datatracker.ietf.org/doc/draft-ietf-tls-esni/25/)
///
/// ```text
/// uint16 ECHConfigExtensionType; // Defined in Section 11.3
///
/// struct {
///     ECHConfigExtensionType type;
///     opaque data<0..2^16-1>;
/// } ECHConfigExtension;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ECHConfigExtension {
    pub(crate) _type: u16,
    pub(crate) data: Vec<u8>,
}

impl ECHConfigExtension {
    pub(crate) fn decode(ctx: &mut DecodeContext) -> Result<Self, AlertDescription> {
        let _type = ctx.u16("type", "ECHConfigExtensionType")?;
        let data = ctx.vec8("data", "opaque<0..2^8-1>", 0, 1)?;

        Ok(Self { _type, data })
    }

    pub(crate) fn ser(&self) -> Vec<u8> {
        let mut ret: Vec<u8> = Vec::new();
        ret.extend_from_slice(self._type.to_be_bytes().as_ref());
        ret.extend_from_slice(
            u16::try_from(self.data.len())
                .expect("ECHConfigExtension.data length exceeds u16::MAX")
                .to_be_bytes()
                .as_ref(),
        );
        ret.extend_from_slice(&self.data);
        ret
    }
}

/// # References
///
/// - [draft-ietf-tls-esni-25 Section 4](https://datatracker.ietf.org/doc/draft-ietf-tls-esni/25/)
///
/// ```text
/// uint16 ECHConfigExtensionType; // Defined in Section 11.3
///
/// struct {
///     HpkeKeyConfig key_config;
///     uint8 maximum_name_length;
///     opaque public_name<1..255>;
///     ECHConfigExtension extensions<0..2^16-1>;
/// } ECHConfigContents;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ECHConfigContents {
    pub(crate) key_config: HpkeKeyConfig,
    pub(crate) maximum_name_length: u8,
    pub(crate) public_name: String,
    pub(crate) extensions: Vec<ECHConfigExtension>,
}

impl ECHConfigContents {
    pub(crate) fn decode(ctx: &mut DecodeContext) -> Result<Self, AlertDescription> {
        let key_config = HpkeKeyConfig::decode(ctx)?;
        let maximum_name_length = ctx.u8("maximum_name_length", "uint8")?;
        let public_name_bytes = ctx.vec8("public_name", "opaque<1..255>", 1, 1)?;
        let public_name: String = String::from_utf8_lossy(&public_name_bytes).to_string();

        ctx.begin_vec16("extensions", "ECHConfigExtension<0..2^16-1>", 0, 1)?;

        let mut extensions: Vec<ECHConfigExtension> = Vec::new();
        let mut n: usize = 0;

        while ctx.remaining() > 0 {
            ctx.begin_element("extension", "ECHConfigExtension", n);
            let extension = ECHConfigExtension::decode(ctx)?;
            ctx.end_element();
            extensions.push(extension);
            n = n.saturating_add(1);
        }

        ctx.end_vec()?;

        Ok(Self {
            key_config,
            maximum_name_length,
            public_name,
            extensions,
        })
    }

    pub(crate) fn ser(&self) -> Vec<u8> {
        let mut ret: Vec<u8> = Vec::new();
        ret.extend_from_slice(&self.key_config.ser());
        ret.push(self.maximum_name_length);
        ret.push(
            self.public_name
                .len()
                .try_into()
                .expect("ECHConfigContents.public_name length exceeds u8::MAX"),
        );
        ret.extend_from_slice(self.public_name.as_bytes());
        let extension_len_start: usize = ret.len();
        ret.extend_from_slice(&[0, 0]); // extensions length
        self.extensions
            .iter()
            .for_each(|ext| ret.extend_from_slice(&ext.ser()));

        let extension_len: u16 = ret
            .len()
            .checked_sub(extension_len_start)
            .unwrap()
            .checked_sub(size_of::<u16>())
            .unwrap()
            .try_into()
            .expect("ECHConfigContents.extensions lengths exceeds u16::MAX");

        ret[extension_len_start..extension_len_start + 2]
            .copy_from_slice(extension_len.to_be_bytes().as_ref());

        ret
    }
}

/// # References
///
/// - [draft-ietf-tls-esni-25 Section 4](https://datatracker.ietf.org/doc/draft-ietf-tls-esni/25/)
///
/// ```text
/// struct {
///     uint16 version;
///     uint16 length;
///     select (ECHConfig.version) {
///       case 0xfe0d: ECHConfigContents contents;
///     }
/// } ECHConfig;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ECHConfig {
    pub(crate) version: u16,
    pub(crate) length: u16,
    pub(crate) contents: ECHConfigContents,
}

impl ECHConfig {
    const VERSION_EXPECTED: u16 = 0xfe0d;

    pub(crate) fn decode(ctx: &mut DecodeContext) -> Result<Option<Self>, AlertDescription> {
        let version = ctx.u16("version", "uint16")?;
        let length = ctx.u16("length", "uint16")?;

        if version != Self::VERSION_EXPECTED {
            log::warn!(
                "Unrecognized value for ECHConfig.version got 0x{:04x} expected 0x{:04x}",
                version,
                Self::VERSION_EXPECTED
            );
        }

        // Save the current position to check length later
        let start_offset = ctx.current_position();

        match ECHConfigContents::decode(ctx) {
            Ok(contents) => {
                // Verify the length matches
                let bytes_consumed = ctx.current_position() - start_offset;
                if bytes_consumed != usize::from(length) {
                    log::warn!(
                        "ECHConfig length mismatch: declared {} bytes but consumed {}",
                        length,
                        bytes_consumed
                    );
                }

                Ok(Some(Self {
                    version,
                    length,
                    contents,
                }))
            }
            Err(e) => {
                log::warn!("Skipping unrecognized ECHConfigContents: {:?}", e);
                // Skip the declared length of bytes
                let bytes_to_skip = usize::from(length);
                let current_pos = ctx.current_position();
                let target_pos = current_pos + bytes_to_skip;

                if target_pos <= ctx.original_buffer().len() {
                    // Create a new context to skip the bytes
                    ctx.advance(bytes_to_skip);
                    Ok(None)
                } else {
                    Err(e)
                }
            }
        }
    }

    pub(crate) fn ser(&self) -> Vec<u8> {
        let mut ret: Vec<u8> = Vec::new();
        ret.extend_from_slice(self.version.to_be_bytes().as_ref());
        ret.extend_from_slice(self.length.to_be_bytes().as_ref());
        let contents: Vec<u8> = self.contents.ser();
        assert_eq!(usize::from(self.length), contents.len());
        ret.extend_from_slice(&contents);
        ret
    }

    pub fn from_x25519_secret(secret: &crate::crypto::x25519::StaticSecret, name: &str) -> Self {
        assert!(name.len() <= 255);
        let public_key: crate::crypto::x25519::PublicKey = secret.into();
        let contents: ECHConfigContents = ECHConfigContents {
            key_config: HpkeKeyConfig {
                config_id: 4,
                kem_id: KemId::DhkemX25519HkdfSha256,
                public_key: public_key.as_bytes().into(),
                cipher_suites: vec![HpkeSymmetricCipherSuite {
                    kdf_id: KdfId::HkdfSha256,
                    aead_id: AeadId::Aes128Gcm,
                }],
            },
            maximum_name_length: name.len().next_power_of_two().try_into().unwrap_or(u8::MAX),
            public_name: name.to_string(),
            extensions: vec![],
        };
        ECHConfig {
            version: Self::VERSION_EXPECTED,
            length: contents
                .ser()
                .len()
                .try_into()
                .expect("ECHConfigContents should never exceed u16::MAX"),
            contents,
        }
    }
}

impl From<ECHConfig> for ECHConfigList {
    fn from(value: ECHConfig) -> Self {
        Self { list: vec![value] }
    }
}

/// Encrypted Client Hello configuration list.
///
/// # References
///
/// - [draft-ietf-tls-esni-25 Section 4](https://datatracker.ietf.org/doc/draft-ietf-tls-esni/25/)
///
/// ```text
/// ECHConfig ECHConfigList<4..2^16-1>;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ECHConfigList {
    pub(crate) list: Vec<ECHConfig>,
}

impl ECHConfigList {
    pub fn from_bytes(buf: &[u8]) -> Result<Self, AlertDescription> {
        let mut ctx = DecodeContext::new("ECHConfigList", buf.to_vec());
        Self::decode(&mut ctx)
    }

    pub(crate) fn decode(ctx: &mut DecodeContext) -> Result<Self, AlertDescription> {
        ctx.begin_vec16("ech_config_list", "ECHConfig<4..2^16-1>", 4, 1)?;

        let mut list: Vec<ECHConfig> = Vec::new();
        let mut n: usize = 0;

        while ctx.remaining() > 0 {
            ctx.begin_element("ech_config", "ECHConfig", n);
            match ECHConfig::decode(ctx) {
                Ok(Some(config)) => {
                    list.push(config);
                }
                Ok(None) => {
                    // Config was skipped due to parse error
                }
                Err(e) => {
                    ctx.end_element();
                    return Err(e);
                }
            }
            ctx.end_element();
            n = n.saturating_add(1);
        }

        ctx.end_vec()?;

        Ok(Self { list })
    }

    /// Serialize into bytes.
    pub fn ser(&self) -> Vec<u8> {
        let mut ret: Vec<u8> = Vec::new();
        // length placeholder
        ret.extend_from_slice(&[0, 0]);

        self.list
            .iter()
            .for_each(|ech_config| ret.extend_from_slice(&ech_config.ser()));

        let len: u16 = ret
            .len()
            .checked_sub(2)
            .unwrap()
            .try_into()
            .expect("ECHConfigList length exceeds u16::MAX");

        ret[..2].copy_from_slice(len.to_be_bytes().as_ref());

        ret
    }

    pub fn find_id(&self, id: u8) -> Option<&ECHConfig> {
        self.list
            .iter()
            .find(|config| config.contents.key_config.config_id == id)
    }
}

/// Encrypted Client Hello configuration list.
///
/// # References
///
/// - [draft-ietf-tls-esni-25 Section 5](https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-25#section-5)
///
/// ```text
/// struct {
///    ECHClientHelloType type;
///    select (ECHClientHello.type) {
///        case outer:
///            HpkeSymmetricCipherSuite cipher_suite;
///            uint8 config_id;
///            opaque enc<0..2^16-1>;
///            opaque payload<1..2^16-1>;
///        case inner:
///            Empty;
///    };
/// } ECHClientHello;
/// ```
#[derive(Debug)]
pub(crate) enum ECHClientHello {
    Inner,
    Outer(ECHClientHelloOuter),
}

impl ECHClientHello {
    pub(crate) fn decode(ctx: &mut DecodeContext) -> Result<Self, AlertDescription> {
        let ech_type = ECHClientHelloType::decode(ctx)?;

        match ech_type {
            ECHClientHelloType::Outer => Ok(Self::Outer(ECHClientHelloOuter::decode(ctx)?)),
            ECHClientHelloType::Inner => {
                if ctx.remaining() > 0 {
                    log::error!(
                        "{} with {ech_type:?} contains {} bytes of data, expected zero",
                        ctx.current_path(),
                        ctx.remaining()
                    );
                    Err(AlertDescription::DecodeError)
                } else {
                    Ok(Self::Inner)
                }
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct ECHClientHelloOuter {
    /// The cipher suite used to encrypt ClientHelloInner.
    /// This MUST match a value provided in the corresponding
    /// ECHConfigContents.cipher_suites list.
    pub(crate) cipher_suite: HpkeSymmetricCipherSuite,
    /// The ECHConfigContents.key_config.config_id for the chosen ECHConfig.
    pub(crate) config_id: u8,
    /// The HPKE encapsulated key, used by servers to decrypt the
    /// corresponding payload field.  This field is empty in a
    /// ClientHelloOuter sent in response to HelloRetryRequest.
    pub(crate) enc: Vec<u8>,
    /// The serialized and encrypted EncodedClientHelloInner structure,
    /// encrypted using HPKE.
    pub(crate) payload: Vec<u8>,
}

impl ECHClientHelloOuter {
    pub(crate) fn decode(ctx: &mut DecodeContext) -> Result<Self, AlertDescription> {
        let cipher_suite = HpkeSymmetricCipherSuite::decode(ctx)?;
        let config_id = ctx.u8("config_id", "uint8")?;
        let enc = ctx.vec16("enc", "opaque<0..2^16-1>", 0, 1)?;
        let payload = ctx.vec16("payload", "opaque<1..2^16-1>", 1, 1)?;

        if ctx.remaining() > 0 {
            log::error!(
                "{} contains {} bytes of trailing data",
                ctx.current_path(),
                ctx.remaining()
            );
            Err(AlertDescription::DecodeError)
        } else {
            Ok(Self {
                cipher_suite,
                config_id,
                enc,
                payload,
            })
        }
    }

    pub(crate) fn ser(&self) -> (Vec<u8>, Vec<u8>) {
        let mut ret: Vec<u8> = Vec::new();
        ret.push(ECHClientHelloType::Outer.into());
        ret.extend_from_slice(&self.cipher_suite.ser());
        ret.push(self.config_id);
        let enc_len: [u8; 2] = u16::try_from(self.enc.len()).expect("TODO").to_be_bytes();
        ret.extend_from_slice(&enc_len);
        ret.extend_from_slice(&self.enc);
        const AES_GCM_TAG_LEN: usize = 16;
        let payload_with_tag_len: usize = self.payload.len() + AES_GCM_TAG_LEN;
        let payload_len_bytes: [u8; 2] = u16::try_from(payload_with_tag_len)
            .expect("TODO")
            .to_be_bytes();
        ret.extend_from_slice(&payload_len_bytes);
        ret.resize(ret.len() + payload_with_tag_len, 0);

        (ret, self.payload.clone())
    }

    pub(crate) fn payload_offset(&self) -> usize {
        const TYPE_LEN: usize = 1;
        const CIPHER_SUITE_LEN: usize = 4;
        const CONFIG_ID_LEN: usize = 1;
        const ENC_LEN_LEN: usize = size_of::<u16>();
        let enc_len: usize = self.enc.len();
        const PAYLOAD_LEN_LEN: usize = size_of::<u16>();

        TYPE_LEN + CIPHER_SUITE_LEN + CONFIG_ID_LEN + ENC_LEN_LEN + enc_len + PAYLOAD_LEN_LEN
    }
}

/// Encrypted Client Hello outer extensions extension.
///
/// # References
///
/// - [draft-ietf-tls-esni-25 Section 5](https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-25#section-5)
///
/// ```text
/// ExtensionType OuterExtensions<2..254>;
/// ```
#[derive(Debug, Clone)]
pub(crate) struct OuterExtensions {
    pub(crate) types: Vec<Result<ExtensionType, u16>>,
}

impl OuterExtensions {
    pub(crate) fn decode(ctx: &mut DecodeContext) -> Result<Self, AlertDescription> {
        ctx.begin_vec8("outer_extensions", "ExtensionType<2..254>", 2, 2)?;

        let mut types: Vec<Result<ExtensionType, u16>> = Vec::new();
        while ctx.remaining() > 0 {
            let ext_type = ctx.u16("extension_type", "ExtensionType")?;
            types.push(ExtensionType::try_from(ext_type));
        }

        ctx.end_vec()?;

        Ok(Self { types })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AeadId, DecodeContext, ECHConfig, ECHConfigContents, ECHConfigList, HpkeKeyConfig,
        HpkeSymmetricCipherSuite, KdfId, KemId,
    };

    // record from tls-ech.dev
    const TLS_ECH_DEV_CONFIG_LIST: &[u8] = &[
        0x00, 0x49, 0xfe, 0x0d, 0x00, 0x45, 0x2b, 0x00, 0x20, 0x00, 0x20, 0x01, 0x58, 0x81, 0xd4,
        0x1a, 0x3e, 0x2e, 0xf8, 0xf2, 0x20, 0x81, 0x85, 0xdc, 0x47, 0x92, 0x45, 0xd2, 0x06, 0x24,
        0xdd, 0xd0, 0x91, 0x8a, 0x80, 0x56, 0xf2, 0xe2, 0x6a, 0xf4, 0x7e, 0x26, 0x28, 0x00, 0x08,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x03, 0x40, 0x12, 0x70, 0x75, 0x62, 0x6c, 0x69,
        0x63, 0x2e, 0x74, 0x6c, 0x73, 0x2d, 0x65, 0x63, 0x68, 0x2e, 0x64, 0x65, 0x76, 0x00, 0x00,
    ];

    // record from defo.ie
    const DEFO_IE_CONFIG_LIST: &[u8] = &[
        0x00, 0xc0, 0xfe, 0x0d, 0x00, 0x3c, 0x1d, 0x00, 0x20, 0x00, 0x20, 0x1c, 0xdc, 0xc4, 0xe5,
        0xc3, 0x89, 0xf6, 0xd6, 0x88, 0x31, 0x5a, 0x7c, 0x9f, 0xf8, 0xad, 0xe3, 0x44, 0x5e, 0x9c,
        0x18, 0x66, 0x83, 0x9a, 0x45, 0x89, 0x56, 0x42, 0x07, 0x2b, 0x06, 0xe5, 0x62, 0x00, 0x04,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x0d, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x2e, 0x64, 0x65, 0x66,
        0x6f, 0x2e, 0x69, 0x65, 0x00, 0x00, 0xfe, 0x0d, 0x00, 0x3c, 0x5c, 0x00, 0x20, 0x00, 0x20,
        0x5c, 0x8b, 0x7f, 0xdd, 0xd6, 0xdc, 0x3e, 0xa7, 0xe5, 0xf6, 0x92, 0x2f, 0x31, 0x6c, 0xf6,
        0xc6, 0x1b, 0xad, 0x62, 0xd8, 0x7e, 0x3b, 0x44, 0xba, 0xda, 0x09, 0x6f, 0x24, 0xdc, 0xa7,
        0xa2, 0x0e, 0x00, 0x04, 0x00, 0x01, 0x00, 0x01, 0x00, 0x0d, 0x63, 0x6f, 0x76, 0x65, 0x72,
        0x2e, 0x64, 0x65, 0x66, 0x6f, 0x2e, 0x69, 0x65, 0x00, 0x00, 0xfe, 0x0d, 0x00, 0x3c, 0x3a,
        0x00, 0x20, 0x00, 0x20, 0xcc, 0x3f, 0x7f, 0x29, 0x9a, 0xab, 0x1d, 0x0c, 0xc2, 0x81, 0xc5,
        0x34, 0x27, 0x4f, 0xa6, 0xb8, 0x2d, 0x2c, 0xc2, 0x00, 0xfb, 0xe1, 0xc8, 0xa4, 0xf7, 0x4b,
        0xd3, 0x88, 0xf8, 0xec, 0xd4, 0x45, 0x00, 0x04, 0x00, 0x01, 0x00, 0x01, 0x00, 0x0d, 0x63,
        0x6f, 0x76, 0x65, 0x72, 0x2e, 0x64, 0x65, 0x66, 0x6f, 0x2e, 0x69, 0x65, 0x00, 0x00,
    ];

    fn tls_ech_dev_config_list() -> ECHConfigList {
        ECHConfigList {
            list: vec![ECHConfig {
                version: 0xfe0d,
                length: 69,
                contents: ECHConfigContents {
                    key_config: HpkeKeyConfig {
                        config_id: 43,
                        kem_id: KemId::DhkemX25519HkdfSha256,
                        public_key: vec![
                            0x01, 0x58, 0x81, 0xd4, 0x1a, 0x3e, 0x2e, 0xf8, 0xf2, 0x20, 0x81, 0x85,
                            0xdc, 0x47, 0x92, 0x45, 0xd2, 0x06, 0x24, 0xdd, 0xd0, 0x91, 0x8a, 0x80,
                            0x56, 0xf2, 0xe2, 0x6a, 0xf4, 0x7e, 0x26, 0x28,
                        ],
                        cipher_suites: vec![
                            HpkeSymmetricCipherSuite {
                                kdf_id: KdfId::HkdfSha256,
                                aead_id: AeadId::Aes128Gcm,
                            },
                            HpkeSymmetricCipherSuite {
                                kdf_id: KdfId::HkdfSha256,
                                aead_id: AeadId::ChaCha20Poly1305,
                            },
                        ],
                    },
                    maximum_name_length: 64,
                    public_name: "public.tls-ech.dev".to_string(),
                    extensions: vec![],
                },
            }],
        }
    }

    fn defo_io_config_list() -> ECHConfigList {
        ECHConfigList {
            list: vec![
                ECHConfig {
                    version: 0xfe0d,
                    length: 60,
                    contents: ECHConfigContents {
                        key_config: HpkeKeyConfig {
                            config_id: 29,
                            kem_id: KemId::DhkemX25519HkdfSha256,
                            public_key: vec![
                                28, 220, 196, 229, 195, 137, 246, 214, 136, 49, 90, 124, 159, 248,
                                173, 227, 68, 94, 156, 24, 102, 131, 154, 69, 137, 86, 66, 7, 43,
                                6, 229, 98,
                            ],
                            cipher_suites: vec![HpkeSymmetricCipherSuite {
                                kdf_id: KdfId::HkdfSha256,
                                aead_id: AeadId::Aes128Gcm,
                            }],
                        },
                        maximum_name_length: 0,
                        public_name: "cover.defo.ie".to_string(),
                        extensions: vec![],
                    },
                },
                ECHConfig {
                    version: 0xfe0d,
                    length: 60,
                    contents: ECHConfigContents {
                        key_config: HpkeKeyConfig {
                            config_id: 92,
                            kem_id: KemId::DhkemX25519HkdfSha256,
                            public_key: vec![
                                92, 139, 127, 221, 214, 220, 62, 167, 229, 246, 146, 47, 49, 108,
                                246, 198, 27, 173, 98, 216, 126, 59, 68, 186, 218, 9, 111, 36, 220,
                                167, 162, 14,
                            ],
                            cipher_suites: vec![HpkeSymmetricCipherSuite {
                                kdf_id: KdfId::HkdfSha256,
                                aead_id: AeadId::Aes128Gcm,
                            }],
                        },
                        maximum_name_length: 0,
                        public_name: "cover.defo.ie".to_string(),
                        extensions: vec![],
                    },
                },
                ECHConfig {
                    version: 0xfe0d,
                    length: 60,
                    contents: ECHConfigContents {
                        key_config: HpkeKeyConfig {
                            config_id: 58,
                            kem_id: KemId::DhkemX25519HkdfSha256,
                            public_key: vec![
                                204, 63, 127, 41, 154, 171, 29, 12, 194, 129, 197, 52, 39, 79, 166,
                                184, 45, 44, 194, 0, 251, 225, 200, 164, 247, 75, 211, 136, 248,
                                236, 212, 69,
                            ],
                            cipher_suites: vec![HpkeSymmetricCipherSuite {
                                kdf_id: KdfId::HkdfSha256,
                                aead_id: AeadId::Aes128Gcm,
                            }],
                        },
                        maximum_name_length: 0,
                        public_name: "cover.defo.ie".to_string(),
                        extensions: vec![],
                    },
                },
            ],
        }
    }

    #[test]
    fn ech_config_list_decode() {
        let mut ctx = DecodeContext::new("ECHConfigList", TLS_ECH_DEV_CONFIG_LIST.to_vec());
        let tls_ech_dev: ECHConfigList = ECHConfigList::decode(&mut ctx).unwrap();
        assert_eq!(tls_ech_dev, tls_ech_dev_config_list());

        let mut ctx = DecodeContext::new("ECHConfigList", DEFO_IE_CONFIG_LIST.to_vec());
        let defo_ie: ECHConfigList = ECHConfigList::decode(&mut ctx).unwrap();
        assert_eq!(defo_ie, defo_io_config_list());
    }

    #[test]
    fn ech_config_list_ser() {
        let tls_ech_dev: Vec<u8> = tls_ech_dev_config_list().ser();
        assert_eq!(tls_ech_dev, TLS_ECH_DEV_CONFIG_LIST);

        let defo_ie: Vec<u8> = defo_io_config_list().ser();
        assert_eq!(defo_ie, DEFO_IE_CONFIG_LIST);
    }
}
