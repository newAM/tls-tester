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

// A.1. DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM
// A.1.1. Base Setup Information
//
// mode: 0
// kem_id: 32
// kdf_id: 1
// aead_id: 1
// info: 4f6465206f6e2061204772656369616e2055726e
// ikmE:
// 7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234
// pkEm:
// 37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431
// skEm:
// 52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736
// ikmR:
// 6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037
// pkRm:
// 3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d
// skRm:
// 4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8
// enc:
// 37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431
// shared_secret:
// fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc
// key_schedule_context: 00725611c9d98c07c03f60095cd32d400d8347d45ed670
// 97bbad50fc56da742d07cb6cffde367bb0565ba28bb02c90744a20f5ef37f3052352
// 6106f637abb05449
// secret:
// 12fff91991e93b48de37e7daddb52981084bd8aa64289c3788471d9a9712f397
// key: 4531685d41d65f03dc48f6b8302c05b0
// base_nonce: 56d890e5accaaf011cff4b7d
// exporter_secret:
// 45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8
//
// A.1.1.1. Encryptions
//
// sequence number: 0
// pt: 4265617574792069732074727574682c20747275746820626561757479
// aad: 436f756e742d30
// nonce: 56d890e5accaaf011cff4b7d
// ct: f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a9
// 6d8770ac83d07bea87e13c512a

use crypto_bigint::hybrid_array::Array;
use p256::{U32, elliptic_curve::sec1::ToEncodedPoint};

/// # References
///
/// - [RFC 9180 Section 7.1](https://datatracker.ietf.org/doc/html/rfc9180#section-7.1)
///
/// ```text
/// suite_id = concat("KEM", I2OSP(kem_id, 2))
/// ```
pub(super) mod kems {
    pub const DHKEM_P256_HKDF_SHA256: [u8; 2] = 0x0010_u16.to_be_bytes();
    pub const DHKEM_P384_HKDF_SHA384: [u8; 2] = 0x0011_u16.to_be_bytes();
    pub const DHKEM_P521_HKDF_SHA512: [u8; 2] = 0x0012_u16.to_be_bytes();
    pub const DHKEM_X25519_HKDF_SHA256: [u8; 2] = 0x0020_u16.to_be_bytes();
    pub const DHKEM_X448_HKDF_SHA512: [u8; 2] = 0x0021_u16.to_be_bytes();
}

// single suite for now
const SUITE_ID: &[u8] = &kems::DHKEM_P256_HKDF_SHA256;
const EXTRACT_EXPAND_PREFIX: &[u8] = b"HPKE-v1KEM";

/// # References
///
/// - [RFC 9180 Section 4](https://datatracker.ietf.org/doc/html/rfc9180#section-4)
///
/// ```text
/// def LabeledExtract(salt, label, ikm):
///   labeled_ikm = concat("HPKE-v1", suite_id, label, ikm)
///   return Extract(salt, labeled_ikm)
/// ```
fn labeled_extract(salt: &[u8], label: &[u8], ikm: &[u8]) -> hkdf::Hkdf<sha2::Sha256> {
    // labeled_ikm = concat("HPKE-v1", suite_id, label, ikm)
    let mut labeled_ikm: Vec<u8> =
        Vec::with_capacity(EXTRACT_EXPAND_PREFIX.len() + SUITE_ID.len() + label.len() + ikm.len());
    labeled_ikm.extend_from_slice(EXTRACT_EXPAND_PREFIX);
    labeled_ikm.extend_from_slice(SUITE_ID);
    labeled_ikm.extend_from_slice(label);
    labeled_ikm.extend_from_slice(ikm);

    // return Extract(salt, labeled_ikm)
    hkdf::Hkdf::new(Some(salt), &labeled_ikm)
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
fn labeled_expand(
    eae_prk: hkdf::Hkdf<sha2::Sha256>,
    label: &[u8],
    info: &[u8],
    l: u16,
) -> p256::ecdh::SharedSecret {
    let l_bytes: [u8; 2] = l.to_be_bytes();

    // labeled_info = concat(I2OSP(L, 2), "HPKE-v1", suite_id, label, info)
    let mut labeled_info: Vec<u8> = Vec::with_capacity(
        l_bytes.len() + EXTRACT_EXPAND_PREFIX.len() + SUITE_ID.len() + label.len() + info.len(),
    );
    labeled_info.extend_from_slice(&l_bytes);
    labeled_info.extend_from_slice(EXTRACT_EXPAND_PREFIX);
    labeled_info.extend_from_slice(SUITE_ID);
    labeled_info.extend_from_slice(label);
    labeled_info.extend_from_slice(info);

    // return Expand(prk, labeled_info, L)
    let mut okm: Array<u8, U32> = Array::default();
    eae_prk
        .expand(&labeled_info, &mut okm)
        .expect("HKDF expand will not fail with a valid length");

    p256::ecdh::SharedSecret::from(okm)
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
    dh: &p256::ecdh::SharedSecret,
    kem_context: &[u8],
) -> p256::ecdh::SharedSecret {
    // eae_prk = LabeledExtract("", "eae_prk", dh)
    let eae_prk: hkdf::Hkdf<sha2::Sha256> = labeled_extract(b"", b"eae_prk", dh.raw_secret_bytes());
    // Nsecret is the length in bytes of the HPKE shared secret that the KEM algorithm produces.
    // 32 for x25519
    const NSECRET: u16 = 32;
    // shared_secret = LabeledExpand(eae_prk, "shared_secret", kem_context, Nsecret)
    // return shared_secret
    labeled_expand(eae_prk, b"shared_secret", kem_context, NSECRET)
}

fn serialize_public_key(pk: &p256::PublicKey) -> Vec<u8> {
    // `to_encoded_point(false)` gives the *uncompressed* form 0x04 || X || Y.
    // Dropping the first byte yields the raw representation required by the spec.
    let encoded = pk.to_encoded_point(false);
    let bytes = encoded.as_bytes();
    debug_assert_eq!(bytes[0], 0x04);
    let ret: Vec<u8> = bytes[1..].to_vec();
    debug_assert_eq!(ret.len(), 64);
    ret
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
pub(crate) fn encap(pkr: &p256::PublicKey) -> (p256::ecdh::SharedSecret, p256::PublicKey) {
    // skE, pkE = GenerateKeyPair()
    let ske: p256::SecretKey =
        p256::SecretKey::try_from_rng(&mut rand::rngs::OsRng).expect("OsRng failed");
    let pke: p256::PublicKey = ske.public_key();

    // dh = DH(skE, pkR)
    let dh: p256::ecdh::SharedSecret =
        p256::ecdh::diffie_hellman(ske.to_nonzero_scalar(), pke.as_affine());

    // enc = SerializePublicKey(pkE)
    let enc: Vec<u8> = serialize_public_key(&pke);

    // pkRm = SerializePublicKey(pkR)
    let pkrm: Vec<u8> = serialize_public_key(pkr);

    // kem_context = concat(enc, pkRm)
    let mut kem_context: Vec<u8> = Vec::with_capacity(64);
    kem_context.extend_from_slice(&enc);
    kem_context.extend_from_slice(&pkrm);

    // shared_secret = ExtractAndExpand(dh, kem_context)
    let shared_secret: p256::ecdh::SharedSecret = extract_and_expand(&dh, &enc);

    // return shared_secret, enc
    (shared_secret, pke)
}
