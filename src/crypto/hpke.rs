//! # References
//!
//! - [RFC 9180](https://datatracker.ietf.org/doc/html/rfc9180)
//!
//! # Notation
//!
//! - (skX, pkX): A key encapsulation mechanism (KEM) key pair used in role X
//!     - skX is the private key
//!     - pkX is the public key
//! - Roles:
//!     - Sender (S): Role of entity that sends an encrypted message.
//!     - Recipient (R): Role of entity that receives an encrypted message.
//!     - Ephemeral (E): Role of a fresh random value meant for one-time use.

use aes_gcm::{Aes128Gcm, KeyInit, aead::AeadInOut as _};
use crypto_bigint::{
    consts::{U12, U16},
    hybrid_array::Array,
};

/// Key Encapsulation Mechanisms (KEMs)
///
/// # References
///
/// - [RFC 9180 Section 7.1](https://datatracker.ietf.org/doc/html/rfc9180#section-7.1)
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u16)]
pub enum KemId {
    DhkemP256HkdfSha256 = 0x0010,
    DhkemP384HkdfSha384 = 0x0011,
    DhkemP512HkdfSha512 = 0x0012,
    DhkemX25519HkdfSha256 = 0x0020,
    DhkemX448HkdfSha512 = 0x0021,
}

impl KemId {
    pub const fn to_be_bytes(self) -> [u8; 2] {
        (self as u16).to_be_bytes()
    }
}

impl From<KemId> for u16 {
    fn from(value: KemId) -> Self {
        value as u16
    }
}

impl TryFrom<u16> for KemId {
    type Error = u16;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            x if x == (Self::DhkemP256HkdfSha256 as u16) => Ok(Self::DhkemP256HkdfSha256),
            x if x == (Self::DhkemP384HkdfSha384 as u16) => Ok(Self::DhkemP384HkdfSha384),
            x if x == (Self::DhkemP512HkdfSha512 as u16) => Ok(Self::DhkemP512HkdfSha512),
            x if x == (Self::DhkemX25519HkdfSha256 as u16) => Ok(Self::DhkemX25519HkdfSha256),
            x if x == (Self::DhkemX448HkdfSha512 as u16) => Ok(Self::DhkemX448HkdfSha512),
            x => Err(x),
        }
    }
}

/// Key Derivation Functions (KDFs)
///
/// # References
///
/// - [RFC 9180 Section 7.2](https://datatracker.ietf.org/doc/html/rfc9180#name-key-derivation-functions-kd)
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u16)]
pub enum KdfId {
    HkdfSha256 = 0x0001,
    HkdfSha384 = 0x0002,
    HkdfSha512 = 0x0003,
}

impl KdfId {
    pub const fn to_be_bytes(self) -> [u8; 2] {
        (self as u16).to_be_bytes()
    }
}

impl From<KdfId> for u16 {
    fn from(value: KdfId) -> Self {
        value as u16
    }
}

impl TryFrom<u16> for KdfId {
    type Error = u16;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            x if x == (Self::HkdfSha256 as u16) => Ok(Self::HkdfSha256),
            x if x == (Self::HkdfSha384 as u16) => Ok(Self::HkdfSha384),
            x if x == (Self::HkdfSha512 as u16) => Ok(Self::HkdfSha512),
            x => Err(x),
        }
    }
}

/// Authenticated Encryption with Associated Data (AEAD) Functions
///
/// # References
///
/// - [RFC 9180 Section 7.3](https://datatracker.ietf.org/doc/html/rfc9180#section-7.3)
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u16)]
pub enum AeadId {
    Aes128Gcm = 0x0001,
    Aes256Gcm = 0x0002,
    ChaCha20Poly1305 = 0x0003,
}

impl AeadId {
    pub const fn to_be_bytes(self) -> [u8; 2] {
        (self as u16).to_be_bytes()
    }
}

impl From<AeadId> for u16 {
    fn from(value: AeadId) -> Self {
        value as u16
    }
}

impl TryFrom<u16> for AeadId {
    type Error = u16;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            x if x == (Self::Aes128Gcm as u16) => Ok(Self::Aes128Gcm),
            x if x == (Self::Aes256Gcm as u16) => Ok(Self::Aes256Gcm),
            x if x == (Self::ChaCha20Poly1305 as u16) => Ok(Self::ChaCha20Poly1305),
            x => Err(x),
        }
    }
}

// single suite for now
const SUITE_ID_DHKEM: [u8; 5] = [
    b'K',
    b'E',
    b'M',
    KemId::DhkemX25519HkdfSha256.to_be_bytes()[0],
    KemId::DhkemX25519HkdfSha256.to_be_bytes()[1],
];
const SUITE_ID_EC: [u8; 10] = [
    b'H',
    b'P',
    b'K',
    b'E',
    KemId::DhkemX25519HkdfSha256.to_be_bytes()[0],
    KemId::DhkemX25519HkdfSha256.to_be_bytes()[1],
    KdfId::HkdfSha256.to_be_bytes()[0],
    KdfId::HkdfSha256.to_be_bytes()[1],
    AeadId::Aes128Gcm.to_be_bytes()[0],
    AeadId::Aes128Gcm.to_be_bytes()[1],
];
const EXTRACT_EXPAND_PREFIX: &[u8] = b"HPKE-v1";

/// # References
///
/// - [RFC 9180 Section 5](https://datatracker.ietf.org/doc/html/rfc9180#section-5)
#[repr(u8)]
enum Mode {
    Base = 0x00,
    Psk = 0x01,
    Auth = 0x02,
    AuthPsk = 0x03,
}

impl From<Mode> for u8 {
    fn from(value: Mode) -> Self {
        value as Self
    }
}

const DEFAULT_PSK: &[u8] = b"";
const DEFAULT_PSK_ID: &[u8] = b"";

/// # References
///
/// - [RFC 9180 Section 4](https://datatracker.ietf.org/doc/html/rfc9180#section-4)
///
/// ```text
/// def LabeledExtract(salt, label, ikm):
///   labeled_ikm = concat("HPKE-v1", suite_id, label, ikm)
///   return Extract(salt, labeled_ikm)
/// ```
fn labeled_extract(suite_id: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> Vec<u8> {
    // labeled_ikm = concat("HPKE-v1", suite_id, label, ikm)
    let mut labeled_ikm: Vec<u8> =
        Vec::with_capacity(EXTRACT_EXPAND_PREFIX.len() + suite_id.len() + label.len() + ikm.len());
    labeled_ikm.extend_from_slice(EXTRACT_EXPAND_PREFIX);
    labeled_ikm.extend_from_slice(suite_id);
    labeled_ikm.extend_from_slice(label);
    labeled_ikm.extend_from_slice(ikm);

    // return Extract(salt, labeled_ikm)
    let (prk, _hkdf): (_, hkdf::Hkdf<sha2::Sha256>) = hkdf::Hkdf::extract(Some(salt), &labeled_ikm);
    prk.into()
}

/// # References
///
/// - [RFC 9180 Section 4](https://datatracker.ietf.org/doc/html/rfc9180#section-4)
///
/// ```text
/// def LabeledExpand(prk, label, info, L):
///   labeled_info = concat(I2OSP(L, 2), "HPKE-v1", suite_id,
///                         label, info)
///   return Expand(prk, labeled_info, L)
/// ```
fn labeled_expand<const L: usize>(
    suite_id: &[u8],
    prk: &[u8],
    label: &[u8],
    info: &[u8],
) -> [u8; L] {
    let l_bytes: [u8; 2] = (L as u16).to_be_bytes();

    // labeled_info = concat(I2OSP(L, 2), "HPKE-v1", suite_id, label, info)
    let labeled_info: &[&[u8]] = &[&l_bytes, EXTRACT_EXPAND_PREFIX, suite_id, label, info];

    // return Expand(prk, labeled_info, L)
    let mut okm: [u8; L] = [0; L];
    hkdf::Hkdf::<sha2::Sha256>::from_prk(prk)
        .expect("invalid PRK length")
        .expand_multi_info(labeled_info, &mut okm)
        .expect("invalid OKM length");
    okm
}

/// # References
///
/// - [RFC 9180 Section 4.1](https://datatracker.ietf.org/doc/html/rfc9180#section-4.1
///
/// ```text
/// def ExtractAndExpand(dh, kem_context):
///   eae_prk = LabeledExtract("", "eae_prk", dh)
///   shared_secret = LabeledExpand(eae_prk, "shared_secret",
///                                 kem_context, Nsecret)
///   return shared_secret
/// ```
fn extract_and_expand(
    suite_id: &[u8],
    dh: &crate::crypto::x25519::SharedSecret,
    kem_context: &[u8],
) -> crate::crypto::x25519::SharedSecret {
    // eae_prk = LabeledExtract("", "eae_prk", dh)
    let eae_prk: Vec<u8> = labeled_extract(suite_id, b"", b"eae_prk", dh.as_bytes());
    // Nsecret is the length in bytes of the HPKE shared secret that the KEM algorithm produces.
    // 32 for x25519
    const NSECRET: usize = 32;
    // shared_secret = LabeledExpand(eae_prk, "shared_secret", kem_context, Nsecret)
    // return shared_secret
    crate::crypto::x25519::SharedSecret(curve25519_dalek::MontgomeryPoint(
        labeled_expand::<NSECRET>(suite_id, &eae_prk, b"shared_secret", kem_context),
    ))
}

/// # References
///
/// - [RFC 9180 Section 4](https://datatracker.ietf.org/doc/html/rfc9180#section-4)
///
/// ```text
/// def Encap(pkR):
///   skE, pkE = GenerateKeyPair()
///   dh = DH(skE, pkR)
///   enc = SerializePublicKey(pkE)
///
///   pkRm = SerializePublicKey(pkR)
///   kem_context = concat(enc, pkRm)
///
///   shared_secret = ExtractAndExpand(dh, kem_context)
///   return shared_secret, enc
/// ```
///
/// Randomized algorithm to generate an ephemeral, fixed-length symmetric key
/// (the KEM shared secret) and a fixed-length encapsulation of that key that
/// can be decapsulated by the holder of the private key corresponding to pkR.
/// This function can raise an EncapError on encapsulation failure.
fn encap(
    pkr: &crate::crypto::x25519::PublicKey,
) -> (
    crate::crypto::x25519::SharedSecret,
    crate::crypto::x25519::PublicKey,
) {
    // skE, pkE = GenerateKeyPair()
    let ske: crate::crypto::x25519::StaticSecret = crate::crypto::x25519::StaticSecret::random();
    encap_inner(pkr, &ske)
}

fn encap_inner(
    pkr: &crate::crypto::x25519::PublicKey,
    ske: &crate::crypto::x25519::StaticSecret,
) -> (
    crate::crypto::x25519::SharedSecret,
    crate::crypto::x25519::PublicKey,
) {
    let pke: crate::crypto::x25519::PublicKey = crate::crypto::x25519::PublicKey::from(ske);

    // dh = DH(skE, pkR)
    let dh: crate::crypto::x25519::SharedSecret = ske.diffie_hellman(pkr);

    // enc = SerializePublicKey(pkE)
    let enc: Vec<u8> = pke.as_bytes().to_vec();

    // pkRm = SerializePublicKey(pkR)
    // kem_context = concat(enc, pkRm)
    let mut kem_context: Vec<u8> = Vec::with_capacity(64);
    kem_context.extend_from_slice(&enc);
    kem_context.extend_from_slice(pkr.as_bytes());

    // shared_secret = ExtractAndExpand(dh, kem_context)
    let shared_secret: crate::crypto::x25519::SharedSecret =
        extract_and_expand(&SUITE_ID_DHKEM, &dh, &kem_context);

    // return shared_secret, enc
    (shared_secret, pke)
}

/// # References
///
/// - [RFC 9180 Section 4](https://datatracker.ietf.org/doc/html/rfc9180#section-4)
///
/// ```text
/// def Decap(enc, skR):
///   pkE = DeserializePublicKey(enc)
///   dh = DH(skR, pkE)
///
///   pkRm = SerializePublicKey(pk(skR))
///   kem_context = concat(enc, pkRm)
///
///   shared_secret = ExtractAndExpand(dh, kem_context)
///   return shared_secret
/// ```
///
/// Deterministic algorithm using the private key skR to recover the ephemeral
/// symmetric key (the KEM shared secret) from its encapsulated representation
/// enc.
fn decap(
    enc: &crate::crypto::x25519::PublicKey,
    skr: &crate::crypto::x25519::StaticSecret,
) -> crate::crypto::x25519::SharedSecret {
    // pkE = DeserializePublicKey(enc)
    let pke: &crate::crypto::x25519::PublicKey = enc;
    // dh = DH(skR, pkE)
    let dh: crate::crypto::x25519::SharedSecret = skr.diffie_hellman(pke);

    // pkRm = SerializePublicKey(pk(skR))
    let pkrm: crate::crypto::x25519::PublicKey = crate::crypto::x25519::PublicKey::from(skr);

    // kem_context = concat(enc, pkRm)
    let mut kem_context: Vec<u8> = Vec::with_capacity(64);
    kem_context.extend_from_slice(enc.as_bytes());
    kem_context.extend_from_slice(pkrm.as_bytes());

    // shared_secret = ExtractAndExpand(dh, kem_context)
    let shared_secret: crate::crypto::x25519::SharedSecret =
        extract_and_expand(&SUITE_ID_DHKEM, &dh, &kem_context);

    // return shared_secret
    shared_secret
}

/// # References
///
/// - [RFC 9180 Section 5.1](https://datatracker.ietf.org/doc/html/rfc9180#section-5.1)
///
/// ```text
/// struct {
///     uint8 mode;
///     opaque psk_id_hash[Nh];
///     opaque info_hash[Nh];
/// } KeyScheduleContext;
/// ```
struct KeyScheduleContext {
    mode: u8,
    psk_id_hash: [u8; 32],
    info_hash: [u8; 32],
}

pub(crate) struct Context {
    key: Array<u8, U16>,
    base_nonce: Array<u8, U12>,
    seq: u64,
    cipher: Aes128Gcm,
    exporter_secret: [u8; 32],
}

impl Context {
    fn increment_seq(&mut self) {
        // Implementations MAY use a sequence number that is shorter than the
        // nonce length (padding on the left with zero), but MUST raise an error
        // if the sequence number overflows.
        self.seq = self
            .seq
            .checked_add(1)
            .expect("sequence number wrapping should never occur");
    }

    fn compute_nonce(&self) -> [u8; 12] {
        // All these parameters except the AEAD sequence number are constant.
        // The sequence number provides nonce uniqueness:
        // The nonce used for each encryption or decryption operation is the
        // result of XORing base_nonce with the current sequence number, encoded
        // as a big-endian integer of the same length as base_nonce.

        let seq_be: [u8; 8] = self.seq.to_be_bytes();

        let mut seq_padded: [u8; 12] = [0u8; 12];
        seq_padded[4..].copy_from_slice(&seq_be);

        std::array::from_fn(|i| self.base_nonce[i] ^ seq_padded[i])
    }

    fn set_seq(&mut self, seq: u64) {
        self.seq = seq;
    }

    /// # References
    ///
    /// - [RFC 9180 Section 5.2](https://datatracker.ietf.org/doc/html/rfc9180#section-5.2)
    ///
    /// ```text
    /// def Context.Seal(aad, pt):
    ///   ct = Seal(self.key, self.ComputeNonce(self.seq), aad, pt)
    ///   self.IncrementSeq()
    ///   return ct
    /// ```
    pub fn seal(&mut self, aad: &[u8], pt: &[u8]) -> Vec<u8> {
        let mut buf: Vec<u8> = pt.into();
        let nonce: Array<u8, U12> = Array(self.compute_nonce());
        self.cipher
            .encrypt_in_place(&nonce, aad, &mut buf)
            .expect("buf has insufficient capabity");
        self.increment_seq();
        buf
    }

    /// # References
    ///
    /// - [RFC 9180 Section 5.2](https://datatracker.ietf.org/doc/html/rfc9180#section-5.2)
    ///
    /// ```text
    /// def ContextR.Open(aad, ct):
    ///   pt = Open(self.key, self.ComputeNonce(self.seq), aad, ct)
    ///   if pt == OpenError:
    ///     raise OpenError
    ///   self.IncrementSeq()
    ///   return pt
    /// ```
    pub fn open(&mut self, aad: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
        let mut buf: Vec<u8> = ct.into();
        let nonce: Array<u8, U12> = Array(self.compute_nonce());
        self.cipher.decrypt_in_place(&nonce, aad, &mut buf).ok()?;
        self.increment_seq();
        Some(buf)
    }
}

/// # References
///
/// - [RFC 9180 Section 5.1](https://datatracker.ietf.org/doc/html/rfc9180#section-5.1)
///
/// ```text
/// def KeySchedule<ROLE>(mode, shared_secret, info, psk, psk_id):
///   VerifyPSKInputs(mode, psk, psk_id)
///
///   psk_id_hash = LabeledExtract("", "psk_id_hash", psk_id)
///   info_hash = LabeledExtract("", "info_hash", info)
///   key_schedule_context = concat(mode, psk_id_hash, info_hash)
///
///   secret = LabeledExtract(shared_secret, "secret", psk)
///
///   key = LabeledExpand(secret, "key", key_schedule_context, Nk)
///   base_nonce = LabeledExpand(secret, "base_nonce",
///                              key_schedule_context, Nn)
///   exporter_secret = LabeledExpand(secret, "exp",
///                                   key_schedule_context, Nh)
///
///   return Context<ROLE>(key, base_nonce, 0, exporter_secret)
/// ```
fn key_schedule(
    mode: Mode,
    shared_secret: &crate::crypto::x25519::SharedSecret,
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
) -> Context {
    // psk_id_hash = LabeledExtract("", "psk_id_hash", psk_id)
    let psk_id_hash: Vec<u8> = labeled_extract(&SUITE_ID_EC, b"", b"psk_id_hash", psk_id);
    // info_hash = LabeledExtract("", "info_hash", info)
    let info_hash: Vec<u8> = labeled_extract(&SUITE_ID_EC, b"", b"info_hash", info);
    // key_schedule_context = concat(mode, psk_id_hash, info_hash)
    let mut key_schedule_context: Vec<u8> = Vec::new();
    key_schedule_context.push(mode as u8);
    key_schedule_context.extend_from_slice(&psk_id_hash);
    key_schedule_context.extend_from_slice(&info_hash);

    // secret = LabeledExtract(shared_secret, "secret", psk)
    let secret: Vec<u8> = labeled_extract(&SUITE_ID_EC, shared_secret.as_bytes(), b"secret", psk);

    // key = LabeledExpand(secret, "key", key_schedule_context, Nk)
    const NK: usize = 16;
    let key: [u8; NK] = labeled_expand(&SUITE_ID_EC, &secret, b"key", &key_schedule_context);
    // base_nonce = LabeledExpand(secret, "base_nonce", key_schedule_context, Nn)
    const NN: usize = 12;
    let base_nonce: [u8; NN] =
        labeled_expand(&SUITE_ID_EC, &secret, b"base_nonce", &key_schedule_context);
    // exporter_secret = LabeledExpand(secret, "exp", key_schedule_context, Nh)
    const NH: usize = 32;
    let exporter_secret: [u8; NH] =
        labeled_expand(&SUITE_ID_EC, &secret, b"exp", &key_schedule_context);

    let key: Array<u8, U16> = Array(key);

    let cipher: Aes128Gcm = Aes128Gcm::new(&key);

    // return Context<ROLE>(key, base_nonce, 0, exporter_secret)
    Context {
        key,
        cipher,
        base_nonce: Array(base_nonce),
        seq: 0,
        exporter_secret,
    }
}

/// # References
///
/// - [RFC 9180 Section 5.1.1](https://datatracker.ietf.org/doc/html/rfc9180#section-5.1.1)
///
/// ```text
/// def SetupBaseS(pkR, info):
///   shared_secret, enc = Encap(pkR)
///   return enc, KeyScheduleS(mode_base, shared_secret, info,
///                            default_psk, default_psk_id)
/// ```
pub(crate) fn setup_base_s(
    pkr: &crate::crypto::x25519::PublicKey,
    info: &[u8],
) -> (crate::crypto::x25519::PublicKey, Context) {
    let (shared_secret, enc): (
        crate::crypto::x25519::SharedSecret,
        crate::crypto::x25519::PublicKey,
    ) = encap(pkr);

    (
        enc,
        key_schedule(
            Mode::Base,
            &shared_secret,
            info,
            DEFAULT_PSK,
            DEFAULT_PSK_ID,
        ),
    )
}

/// # References
///
/// - [RFC 9180 Section 5.1.1](https://datatracker.ietf.org/doc/html/rfc9180#section-5.1.1)
///
/// ```text
/// def SetupBaseR(enc, skR, info):
///   shared_secret = Decap(enc, skR)
///   return KeyScheduleR(mode_base, shared_secret, info,
///                       default_psk, default_psk_id)
///
/// ```
pub(crate) fn setup_base_r(
    enc: &crate::crypto::x25519::PublicKey,
    skr: &crate::crypto::x25519::StaticSecret,
    info: &[u8],
) -> Context {
    let shared_secret: crate::crypto::x25519::SharedSecret = decap(enc, skr);

    key_schedule(
        Mode::Base,
        &shared_secret,
        info,
        DEFAULT_PSK,
        DEFAULT_PSK_ID,
    )
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_PSK, DEFAULT_PSK_ID, Mode, decap, encap_inner, key_schedule, setup_base_r,
    };

    const fn hex_val(n: u8) -> u8 {
        match n {
            b'0'..=b'9' => n - b'0',
            b'a'..=b'f' => n - b'a' + 10,
            b'A'..=b'F' => n - b'A' + 10,
            _ => panic!("invalid hex digit"),
        }
    }

    /// # Examples
    ///
    /// ```
    /// const BYTES: [u8; 4] = hex_to_array::<4>("deadbeef");
    /// assert_eq!(BYTES, [0xDE, 0xAD, 0xBE, 0xEF]);
    /// ```
    pub const fn hex_to_array<const N: usize>(hex: &str) -> [u8; N] {
        let src: &[u8] = hex.as_bytes();

        assert!(
            src.len() == N * 2,
            "hex string length must be twice the array length"
        );

        let mut out: [u8; N] = [0u8; N];

        let mut i: usize = 0;
        while i < N {
            let hi: u8 = hex_val(src[2 * i]);
            let lo: u8 = hex_val(src[2 * i + 1]);
            out[i] = (hi << 4) | lo;
            i += 1;
        }

        out
    }

    /// Test vectors
    ///
    /// # References
    ///
    /// - [RFC 9180 Appendix A.1](https://datatracker.ietf.org/doc/html/rfc9180#appendix-A.1)
    mod a1 {
        use super::hex_to_array;

        pub const INFO: [u8; 20] = hex_to_array("4f6465206f6e2061204772656369616e2055726e");
        pub const IKME: [u8; 32] =
            hex_to_array("938d3daa5a8904540bc24f48ae90eed3f4f7f11839560597b55e7c9598c996c0");
        pub const PKEM: [u8; 32] =
            hex_to_array("f7674cc8cd7baa5872d1f33dbaffe3314239f6197ddf5ded1746760bfc847e0e");
        pub const SKEM: [u8; 32] =
            hex_to_array("52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736");
        pub const IKMR: [u8; 32] =
            hex_to_array("64835d5ee64aa7aad57c6f2e4f758f7696617f8829e70bc9ac7a5ef95d1c756c");
        pub const PKRM: [u8; 32] =
            hex_to_array("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d");
        pub const SKRM: [u8; 32] =
            hex_to_array("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8");
        pub const SHARED_SECRET: [u8; 32] =
            hex_to_array("fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc");
        pub const ENC: [u8; 32] =
            hex_to_array("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431");
        pub const KEY: [u8; 16] = hex_to_array("4531685d41d65f03dc48f6b8302c05b0");

        pub struct Encryption<const AAD_LEN: usize> {
            pub sequence_number: u32,
            pub pt: [u8; 29],
            pub aad: [u8; AAD_LEN],
            pub nonce: [u8; 12],
            pub ct: [u8; 45], // concat of ciphertext and tag
        }

        pub const ENCRYPTION_0: Encryption<7> = Encryption {
            sequence_number: 0,
            pt: hex_to_array("4265617574792069732074727574682c20747275746820626561757479"),
            aad: hex_to_array("436f756e742d30"),
            nonce: hex_to_array("56d890e5accaaf011cff4b7d"),
            ct: hex_to_array(
                "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a",
            ),
        };
        pub const ENCRYPTION_1: Encryption<7> = Encryption {
            sequence_number: 1,
            pt: hex_to_array("4265617574792069732074727574682c20747275746820626561757479"),
            aad: hex_to_array("436f756e742d31"),
            nonce: hex_to_array("56d890e5accaaf011cff4b7c"),
            ct: hex_to_array(
                "af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84",
            ),
        };
        pub const ENCRYPTION_2: Encryption<7> = Encryption {
            sequence_number: 2,
            pt: hex_to_array("4265617574792069732074727574682c20747275746820626561757479"),
            aad: hex_to_array("436f756e742d32"),
            nonce: hex_to_array("56d890e5accaaf011cff4b7f"),
            ct: hex_to_array(
                "498dfcabd92e8acedc281e85af1cb4e3e31c7dc394a1ca20e173cb72516491588d96a19ad4a683518973dcc180",
            ),
        };
        pub const ENCRYPTION_4: Encryption<7> = Encryption {
            sequence_number: 4,
            pt: hex_to_array("4265617574792069732074727574682c20747275746820626561757479"),
            aad: hex_to_array("436f756e742d34"),
            nonce: hex_to_array("56d890e5accaaf011cff4b79"),
            ct: hex_to_array(
                "583bd32bc67a5994bb8ceaca813d369bca7b2a42408cddef5e22f880b631215a09fc0012bc69fccaa251c0246d",
            ),
        };
        pub const ENCRYPTION_255: Encryption<9> = Encryption {
            sequence_number: 255,
            pt: hex_to_array("4265617574792069732074727574682c20747275746820626561757479"),
            aad: hex_to_array("436f756e742d323535"),
            nonce: hex_to_array("56d890e5accaaf011cff4b82"),
            ct: hex_to_array(
                "7175db9717964058640a3a11fb9007941a5d1757fda1a6935c805c21af32505bf106deefec4a49ac38d71c9e0a",
            ),
        };
        pub const ENCRYPTION_256: Encryption<9> = Encryption {
            sequence_number: 256,
            pt: hex_to_array("4265617574792069732074727574682c20747275746820626561757479"),
            aad: hex_to_array("436f756e742d323536"),
            nonce: hex_to_array("56d890e5accaaf011cff4a7d"),
            ct: hex_to_array(
                "957f9800542b0b8891badb026d79cc54597cb2d225b54c00c5238c25d05c30e3fbeda97d2e0e1aba483a2df9f2",
            ),
        };
    }

    #[test]
    fn encap_inner_shared_secret() {
        let pkr: crate::crypto::x25519::PublicKey =
            crate::crypto::x25519::PublicKey::from(a1::PKRM);
        let ske: crate::crypto::x25519::StaticSecret =
            crate::crypto::x25519::StaticSecret::from(a1::SKEM);

        let (shared_secret, enc): (
            crate::crypto::x25519::SharedSecret,
            crate::crypto::x25519::PublicKey,
        ) = encap_inner(&pkr, &ske);

        assert_eq!(enc.to_bytes(), a1::ENC);
        assert_eq!(shared_secret.to_bytes(), a1::SHARED_SECRET);
    }

    #[test]
    fn key_schedule_seal() {
        let shared_secret: crate::crypto::x25519::SharedSecret =
            crate::crypto::x25519::SharedSecret(curve25519_dalek::MontgomeryPoint(
                a1::SHARED_SECRET,
            ));

        let mut key_schedule = key_schedule(
            Mode::Base,
            &shared_secret,
            &a1::INFO,
            DEFAULT_PSK,
            DEFAULT_PSK_ID,
        );

        assert_eq!(key_schedule.key, a1::KEY);
        assert_eq!(key_schedule.base_nonce, a1::ENCRYPTION_0.nonce);

        let ct: Vec<u8> = key_schedule.seal(&a1::ENCRYPTION_0.aad, &a1::ENCRYPTION_0.pt);
        assert_eq!(ct, &a1::ENCRYPTION_0.ct);

        let ct: Vec<u8> = key_schedule.seal(&a1::ENCRYPTION_1.aad, &a1::ENCRYPTION_1.pt);
        assert_eq!(ct, &a1::ENCRYPTION_1.ct);

        let ct: Vec<u8> = key_schedule.seal(&a1::ENCRYPTION_2.aad, &a1::ENCRYPTION_2.pt);
        assert_eq!(ct, &a1::ENCRYPTION_2.ct);

        key_schedule.set_seq(4);
        let ct: Vec<u8> = key_schedule.seal(&a1::ENCRYPTION_4.aad, &a1::ENCRYPTION_4.pt);
        assert_eq!(ct, &a1::ENCRYPTION_4.ct);

        key_schedule.set_seq(255);
        let ct: Vec<u8> = key_schedule.seal(&a1::ENCRYPTION_255.aad, &a1::ENCRYPTION_255.pt);
        assert_eq!(ct, &a1::ENCRYPTION_255.ct);

        let ct: Vec<u8> = key_schedule.seal(&a1::ENCRYPTION_256.aad, &a1::ENCRYPTION_256.pt);
        assert_eq!(ct, &a1::ENCRYPTION_256.ct);
    }

    #[test]
    fn decap_shared_secret() {
        let skr: crate::crypto::x25519::StaticSecret =
            crate::crypto::x25519::StaticSecret::from(a1::SKRM);
        let enc: crate::crypto::x25519::PublicKey = crate::crypto::x25519::PublicKey::from(a1::ENC);
        let shared_secret: crate::crypto::x25519::SharedSecret = decap(&enc, &skr);
        assert_eq!(shared_secret.to_bytes(), a1::SHARED_SECRET);
    }

    #[test]
    fn setup_base_r_open() {
        let skr: crate::crypto::x25519::StaticSecret =
            crate::crypto::x25519::StaticSecret::from(a1::SKRM);
        let enc: crate::crypto::x25519::PublicKey = crate::crypto::x25519::PublicKey::from(a1::ENC);

        let mut context = setup_base_r(&enc, &skr, &a1::INFO);

        let pt: Vec<u8> = context
            .open(&a1::ENCRYPTION_0.aad, &a1::ENCRYPTION_0.ct)
            .expect("Tag mismatch");
        assert_eq!(pt, &a1::ENCRYPTION_0.pt);

        let pt: Vec<u8> = context
            .open(&a1::ENCRYPTION_1.aad, &a1::ENCRYPTION_1.ct)
            .expect("Tag mismatch");
        assert_eq!(pt, &a1::ENCRYPTION_1.pt);

        let pt: Vec<u8> = context
            .open(&a1::ENCRYPTION_2.aad, &a1::ENCRYPTION_2.ct)
            .expect("Tag mismatch");
        assert_eq!(pt, &a1::ENCRYPTION_2.pt);

        context.set_seq(4);
        let pt: Vec<u8> = context
            .open(&a1::ENCRYPTION_4.aad, &a1::ENCRYPTION_4.ct)
            .expect("Tag mismatch");
        assert_eq!(pt, &a1::ENCRYPTION_4.pt);

        context.set_seq(255);
        let pt: Vec<u8> = context
            .open(&a1::ENCRYPTION_255.aad, &a1::ENCRYPTION_255.ct)
            .expect("Tag mismatch");
        assert_eq!(pt, &a1::ENCRYPTION_255.pt);

        let pt: Vec<u8> = context
            .open(&a1::ENCRYPTION_256.aad, &a1::ENCRYPTION_256.ct)
            .expect("Tag mismatch");
        assert_eq!(pt, &a1::ENCRYPTION_256.pt);
    }
}
