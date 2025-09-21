//! TLS key schedule.
//!
//! # References
//!
//! * [RFC 5869] HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
//! * [RFC 8446 Section 7.1](https://datatracker.ietf.org/doc/html/rfc8446#section-7.1)
//!
//! [RFC 5869]: https://datatracker.ietf.org/doc/html/rfc5869

use crate::{NamedGroup, alert::AlertDescription, handshake::KeyShareEntry};
use hkdf::{
    Hkdf,
    hmac::{
        Hmac, KeyInit as _, Mac,
        digest::{
            array::{Array, ArraySize},
            consts::U16,
        },
    },
};
use rand::rngs::OsRng;
use sha2::{
    Digest, Sha256,
    digest::{
        OutputSizeUser,
        typenum::{U12, U32, Unsigned},
    },
};

pub type SharedSecret = [u8; 32];

// pre-computed SHA256 digest with no data
const SHA256_EMPTY_DIGEST: [u8; 32] = [
    0xE3, 0xB0, 0xC4, 0x42, 0x98, 0xFC, 0x1C, 0x14, 0x9A, 0xFB, 0xF4, 0xC8, 0x99, 0x6F, 0xB9, 0x24,
    0x27, 0xAE, 0x41, 0xE4, 0x64, 0x9B, 0x93, 0x4C, 0xA4, 0x95, 0x99, 0x1B, 0x78, 0x52, 0xB8, 0x55,
];

const SHA256_DIGEST_LEN: usize = 256 / 8;
const ZEROS_OF_SHA256_DIGEST_LEN: [u8; SHA256_DIGEST_LEN] = [0; SHA256_DIGEST_LEN];

/// Create a TLS HKDF label.
///
/// # References
///
/// * [RFC 8446 Section 7.1](https://datatracker.ietf.org/doc/html/rfc8446#section-7.1)
///
/// ```text
/// struct {
///     uint16 length = Length;
///     opaque label<7..255> = "tls13 " + Label;
///     opaque context<0..255> = Context;
/// } HkdfLabel;
/// ```
fn hkdf_label(len: u16, label: &[u8], context: &[u8]) -> Vec<u8> {
    let mut hkdf_label: Vec<u8> = Vec::new();
    hkdf_label.extend(&len.to_be_bytes());

    const LABEL_PREFIX: &[u8] = b"tls13 ";
    let label_len: u8 = u8::try_from(label.len() + LABEL_PREFIX.len()).unwrap();

    hkdf_label.push(label_len);
    hkdf_label.extend(LABEL_PREFIX);
    hkdf_label.extend(label);

    let context_len: u8 = u8::try_from(context.len()).unwrap();
    hkdf_label.push(context_len);
    hkdf_label.extend(context);

    hkdf_label
}

/// TLS `HKDF-Expand-Label` function.
///
/// # References
///
/// * [RFC 8446 Section 7.1](https://datatracker.ietf.org/doc/html/rfc8446#section-7.1)
///
/// ```text
/// HKDF-Expand-Label(Secret, Label, Context, Length) =
///     HKDF-Expand(Secret, HkdfLabel, Length)
/// ```
pub(crate) fn hkdf_expand_label<N: ArraySize>(
    secret: &Hkdf<Sha256>,
    label: &[u8],
    context: &[u8],
) -> Array<u8, N> {
    let label: Vec<u8> = hkdf_label(N::to_u16(), label, context);
    let mut okm: Array<u8, N> = Default::default();
    secret.expand(&label, &mut okm).unwrap();
    okm
}

/// TLS `Derive-Secret` function.
///
/// # References
///
/// * [RFC 8446 Section 7.1](https://datatracker.ietf.org/doc/html/rfc8446#section-7.1)
///
/// ```text
/// Derive-Secret(Secret, Label, Messages) =
///     HKDF-Expand-Label(Secret, Label,
///                       Transcript-Hash(Messages), Hash.length)
/// ```
pub(crate) fn derive_secret(
    secret: &Hkdf<Sha256>,
    label: &[u8],
    context: &[u8],
) -> Array<u8, <Sha256 as OutputSizeUser>::OutputSize> {
    let label: Vec<u8> = hkdf_label(
        <Sha256 as OutputSizeUser>::OutputSize::to_u16(),
        label,
        context,
    );

    let mut okm: Array<u8, _> = Default::default();
    secret.expand(&label, &mut okm).unwrap();
    okm
}

// https://firefox-source-docs.mozilla.org/security/nss/legacy/key_log_format/index.html
fn print_nss_key_log(label: &str, client_random: &[u8; 32], secret: &[u8]) {
    print!("{label} ");
    client_random.iter().for_each(|b| print!("{b:02x}"));
    print!(" ");
    secret.iter().for_each(|b| print!("{b:02x}"));
    println!();
}

pub enum KeyScheduleMain {
    Server,
    Client,
}

pub enum SecretKey {
    Secp256r1(p256::ecdh::EphemeralSecret),
    X25519(x25519_dalek::ReusableSecret),
}

pub struct KeySchedule {
    secret_key: Option<SecretKey>,
    public_key: Option<KeyShareEntry>,

    main: KeyScheduleMain,

    // https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.1
    // Many of the cryptographic computations in TLS make use of a
    // transcript hash.  This value is computed by hashing the concatenation
    // of each included handshake message, including the handshake message
    // header carrying the handshake message type and length fields, but not
    // including record layer headers.
    transcript_hash: Sha256,

    // https://datatracker.ietf.org/doc/html/rfc8446#section-5.3
    // A 64-bit sequence number is maintained separately for reading and
    // writing records.  The appropriate sequence number is incremented by
    // one after reading or writing each record.  Each sequence number is
    // set to zero at the beginning of a connection and whenever the key is
    // changed; the first record transmitted under a particular traffic key
    // MUST use sequence number 0.
    read_record_sequence_number: u64,
    write_record_sequence_number: u64,

    hkdf: Hkdf<Sha256>,
    secret: Array<u8, U32>,

    client_traffic_secret: Option<Hkdf<Sha256>>,
    server_traffic_secret: Option<Hkdf<Sha256>>,

    // only for NSS key logging
    pub random: Option<[u8; 32]>,
    traffic_secret_count: u64,
}

impl KeySchedule {
    fn new_main(main: KeyScheduleMain) -> Self {
        let (_, hkdf): (Array<u8, _>, Hkdf<Sha256>) = Hkdf::<Sha256>::extract(
            Some(&ZEROS_OF_SHA256_DIGEST_LEN),
            &ZEROS_OF_SHA256_DIGEST_LEN,
        );
        let secret = derive_secret(&hkdf, b"derived", &SHA256_EMPTY_DIGEST);

        Self {
            secret_key: None,
            public_key: None,
            main,
            transcript_hash: sha2::Sha256::new(),
            read_record_sequence_number: 0,
            write_record_sequence_number: 0,
            hkdf,
            secret,
            client_traffic_secret: None,
            server_traffic_secret: None,
            random: None,
            traffic_secret_count: 0,
        }
    }

    pub fn new_server() -> Self {
        Self::new_main(KeyScheduleMain::Server)
    }

    pub fn new_client() -> Self {
        Self::new_main(KeyScheduleMain::Client)
    }

    pub fn increment_read_record_sequence_number(&mut self) {
        self.read_record_sequence_number = self.read_record_sequence_number.checked_add(1).unwrap();
        log::debug!(
            "read_record_sequence_number={}",
            self.read_record_sequence_number
        )
    }
    pub fn increment_write_record_sequence_number(&mut self) {
        self.write_record_sequence_number =
            self.write_record_sequence_number.checked_add(1).unwrap();
        log::debug!(
            "write_record_sequence_number={}",
            self.write_record_sequence_number
        )
    }

    pub fn reset(&mut self) {
        *self = match self.main {
            KeyScheduleMain::Server => Self::new_server(),
            KeyScheduleMain::Client => Self::new_client(),
        }
    }

    /// Create a new ephemeral secret, and return the public key.
    pub fn new_secret_key_client(&mut self, named_group: NamedGroup) -> KeyShareEntry {
        match named_group {
            NamedGroup::x25519 => {
                let (private, public) = {
                    let private_key = x25519_dalek::ReusableSecret::random();
                    let public: x25519_dalek::PublicKey = (&private_key).into();

                    (private_key, public)
                };
                self.secret_key.replace(SecretKey::X25519(private));
                KeyShareEntry::X25519(public)
            }
            NamedGroup::secp256r1 => {
                let (private, public) = {
                    let private_key = p256::ecdh::EphemeralSecret::try_from_rng(&mut OsRng)
                        .expect("OsRng failure");
                    let public_key = private_key.public_key();

                    (private_key, public_key)
                };
                self.secret_key.replace(SecretKey::Secp256r1(private));
                KeyShareEntry::Secp256r1(public)
            }
            _ => unreachable!(),
        }
    }

    /// Create a new ephemeral secret, and return the public key.
    pub fn new_secret_key_server(&mut self) -> KeyShareEntry {
        match self
            .public_key
            .as_ref()
            .expect("self.publick_key is uninitialized")
            .named_group()
        {
            Ok(NamedGroup::x25519) => self.new_secret_key_client(NamedGroup::x25519),
            Ok(NamedGroup::secp256r1) => self.new_secret_key_client(NamedGroup::secp256r1),
            _ => unreachable!(),
        }
    }

    pub fn update_transcript_hash(&mut self, data: &[u8]) {
        self.transcript_hash.update(data)
    }

    pub fn transcript_hash_bytes(&self) -> Array<u8, U32> {
        self.transcript_hash.clone().finalize()
    }

    pub fn set_transcript_hash(&mut self, hash: Sha256) {
        self.transcript_hash = hash
    }

    pub fn transcript_hash(&self) -> Sha256 {
        self.transcript_hash.clone()
    }

    pub fn set_public_key(&mut self, key: KeyShareEntry) {
        self.public_key.replace(key);
    }

    fn shared_secret(&self) -> SharedSecret {
        match self
            .secret_key
            .as_ref()
            .expect("KeySchedule.secret_key has not been initialized")
        {
            SecretKey::Secp256r1(ephemeral_secret) => {
                let public_key: &p256::PublicKey = match self
                    .public_key
                    .as_ref()
                    .expect("KeySchedule.public_key has not been initialized")
                {
                    KeyShareEntry::Secp256r1(public_key) => public_key,
                    other => {
                        unreachable!(
                            "Public key {other:?} does not match private key type secp256r1"
                        );
                    }
                };
                ephemeral_secret
                    .diffie_hellman(public_key)
                    .raw_secret_bytes()
                    .as_slice()
                    .try_into()
                    .unwrap()
            }
            SecretKey::X25519(ephemeral_secret) => {
                let public_key: &x25519_dalek::PublicKey = match self
                    .public_key
                    .as_ref()
                    .expect("KeySchedule.public_key has not been initialized")
                {
                    KeyShareEntry::X25519(public_key) => public_key,
                    other => {
                        unreachable!("Public key {other:?} does not match private key type X25519");
                    }
                };
                ephemeral_secret
                    .clone()
                    .diffie_hellman(public_key)
                    .as_bytes()
                    .as_slice()
                    .try_into()
                    .unwrap()
            }
        }
    }

    pub fn binder_key(&mut self, psk: Option<&[u8; 32]>) -> Hkdf<Sha256> {
        let ikm = psk.unwrap_or(&[0; 32]);
        (self.secret, self.hkdf) = Hkdf::<Sha256>::extract(Some(&ZEROS_OF_SHA256_DIGEST_LEN), ikm);
        let binder_key = derive_secret(&self.hkdf, b"ext binder", &SHA256_EMPTY_DIGEST);
        Hkdf::<Sha256>::from_prk(&binder_key).unwrap()
    }

    pub fn binder(
        &mut self,
        psk: Option<&[u8; 32]>,
        truncated_transcript_hash: &[u8],
    ) -> Array<u8, U32> {
        let binder_key: Hkdf<Sha256> = self.binder_key(psk);

        // The PskBinderEntry is computed in the same way as the Finished
        // message (Section 4.4.4) but with the BaseKey being the binder_key
        // derived via the key schedule from the corresponding PSK which is
        // being offered (see Section 7.1).
        //
        // finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
        let key: Array<u8, U32> = hkdf_expand_label(&binder_key, b"finished", &[]);

        let mut hmac = Hmac::<Sha256>::new_from_slice(&key).unwrap();
        hmac.update(truncated_transcript_hash);
        hmac.finalize().into_bytes()
    }

    pub fn initialize_early_secret(&mut self) {
        let transcript_hash_bytes = self.transcript_hash_bytes();
        let client_secret = derive_secret(&self.hkdf, b"c e traffic", &transcript_hash_bytes);
        self.client_traffic_secret
            .replace(Hkdf::<Sha256>::from_prk(&client_secret).unwrap());

        // there is also a early_exporter_master_secret here

        self.secret = derive_secret(&self.hkdf, b"derived", &SHA256_EMPTY_DIGEST);

        self.read_record_sequence_number = 0;
        self.write_record_sequence_number = 0;

        print_nss_key_log(
            "CLIENT_EARLY_TRAFFIC_SECRET",
            self.random.as_ref().unwrap(),
            &client_secret,
        );
    }

    pub fn initialize_handshake_secret(&mut self) {
        let shared_secret = self.shared_secret();
        (self.secret, self.hkdf) = Hkdf::<Sha256>::extract(Some(&self.secret), &shared_secret);

        let transcript_hash_bytes = self.transcript_hash_bytes();
        let client_secret = derive_secret(&self.hkdf, b"c hs traffic", &transcript_hash_bytes);
        self.client_traffic_secret
            .replace(Hkdf::<Sha256>::from_prk(&client_secret).unwrap());

        let server_secret = derive_secret(&self.hkdf, b"s hs traffic", &transcript_hash_bytes);
        self.server_traffic_secret
            .replace(Hkdf::<Sha256>::from_prk(&server_secret).unwrap());

        self.secret = derive_secret(&self.hkdf, b"derived", &SHA256_EMPTY_DIGEST);

        self.read_record_sequence_number = 0;
        self.write_record_sequence_number = 0;

        {
            print_nss_key_log(
                "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
                self.random.as_ref().unwrap(),
                &client_secret,
            );
            print_nss_key_log(
                "SERVER_HANDSHAKE_TRAFFIC_SECRET",
                self.random.as_ref().unwrap(),
                &server_secret,
            );
        }
    }

    pub fn initialize_master_secret(&mut self) {
        (self.secret, self.hkdf) =
            Hkdf::<Sha256>::extract(Some(&self.secret), &ZEROS_OF_SHA256_DIGEST_LEN);

        let transcript_hash_bytes = self.transcript_hash_bytes();
        let client_secret = derive_secret(&self.hkdf, b"c ap traffic", &transcript_hash_bytes);
        self.client_traffic_secret
            .replace(Hkdf::<Sha256>::from_prk(&client_secret).unwrap());

        let server_secret = derive_secret(&self.hkdf, b"s ap traffic", &transcript_hash_bytes);
        self.server_traffic_secret
            .replace(Hkdf::<Sha256>::from_prk(&server_secret).unwrap());

        self.secret = derive_secret(&self.hkdf, b"derived", &SHA256_EMPTY_DIGEST);

        self.read_record_sequence_number = 0;
        self.write_record_sequence_number = 0;

        {
            print_nss_key_log(
                &format!("CLIENT_TRAFFIC_SECRET_{}", self.traffic_secret_count),
                self.random.as_ref().unwrap(),
                &client_secret,
            );
            print_nss_key_log(
                &format!("SERVER_TRAFFIC_SECRET_{}", self.traffic_secret_count),
                self.random.as_ref().unwrap(),
                &server_secret,
            );
            self.traffic_secret_count += 1;
        }
    }

    /// Update traffic secrets.
    ///
    /// # References
    ///
    /// * [RFC 8446 Section 7.2](https://datatracker.ietf.org/doc/html/rfc8446#section-7.2)
    ///
    /// ```text
    /// application_traffic_secret_N+1 =
    ///     HKDF-Expand-Label(application_traffic_secret_N,
    ///                       "traffic upd", "", Hash.length)
    /// ```
    pub fn update_traffic_secret(&mut self) {
        (self.secret, self.hkdf) =
            Hkdf::<Sha256>::extract(Some(&self.secret), &ZEROS_OF_SHA256_DIGEST_LEN);

        let transcript_hash_bytes = self.transcript_hash_bytes();
        let client_secret = derive_secret(&self.hkdf, b"traffic upd", &transcript_hash_bytes);
        self.client_traffic_secret
            .replace(Hkdf::<Sha256>::from_prk(&client_secret).unwrap());

        let server_secret = derive_secret(&self.hkdf, b"traffic upd", &transcript_hash_bytes);
        self.server_traffic_secret
            .replace(Hkdf::<Sha256>::from_prk(&server_secret).unwrap());

        self.secret = derive_secret(&self.hkdf, b"derived", &SHA256_EMPTY_DIGEST);

        self.read_record_sequence_number = 0;
        self.write_record_sequence_number = 0;

        {
            print_nss_key_log(
                &format!("CLIENT_TRAFFIC_SECRET_{}", self.traffic_secret_count),
                self.random.as_ref().unwrap(),
                &client_secret,
            );
            print_nss_key_log(
                &format!("SERVER_TRAFFIC_SECRET_{}", self.traffic_secret_count),
                self.random.as_ref().unwrap(),
                &server_secret,
            );
            self.traffic_secret_count += 1;
        }
    }

    pub fn server_traffic_secret_exists(&self) -> bool {
        self.server_traffic_secret.is_some()
    }

    pub fn write_key_and_nonce(&self) -> Option<([u8; 16], [u8; 12])> {
        match self.main {
            KeyScheduleMain::Server => self.key_and_nonce(
                self.server_traffic_secret.as_ref()?,
                self.write_record_sequence_number,
            ),
            KeyScheduleMain::Client => self.key_and_nonce(
                self.client_traffic_secret.as_ref()?,
                self.write_record_sequence_number,
            ),
        }
    }

    pub fn read_key_and_nonce(&self) -> Option<([u8; 16], [u8; 12])> {
        match self.main {
            KeyScheduleMain::Server => self.key_and_nonce(
                self.client_traffic_secret.as_ref()?,
                self.read_record_sequence_number,
            ),
            KeyScheduleMain::Client => self.key_and_nonce(
                self.server_traffic_secret.as_ref()?,
                self.read_record_sequence_number,
            ),
        }
    }

    /// Get the key and nonce.
    ///
    /// # References
    ///
    /// * [RFC 8446 Section 7.3](https://datatracker.ietf.org/doc/html/rfc8446#ref-sender)
    ///
    /// ```text
    /// [sender]_write_key = HKDF-Expand-Label(Secret, "key", "", key_length)
    /// ```
    fn key_and_nonce(
        &self,
        traffic_secret: &Hkdf<Sha256>,
        sequence_number: u64,
    ) -> Option<([u8; 16], [u8; 12])> {
        let key: Array<u8, U16> = hkdf_expand_label(traffic_secret, b"key", &[]);
        let mut iv: Array<u8, U12> = hkdf_expand_label(traffic_secret, b"iv", &[]);

        sequence_number
            .to_be_bytes()
            .iter()
            .enumerate()
            .for_each(|(idx, byte)| iv[idx + 4] ^= byte);
        Some((key.into(), iv.into()))
    }

    /// # References
    ///
    /// * [RFC 8446 Section 4.4.4](https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.4)
    ///
    /// ```text
    /// finished_key =
    ///     HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
    ///
    /// struct {
    ///     opaque verify_data[Hash.length];
    /// } Finished;
    ///
    /// verify_data =
    ///     HMAC(finished_key,
    ///          Transcript-Hash(Handshake Context,
    ///                          Certificate*, CertificateVerify*))
    /// ```
    pub fn verify_server_finished(
        &self,
        transcript_hash: &Array<u8, U32>,
        finished: &[u8; 32],
    ) -> Result<(), AlertDescription> {
        let key: Array<u8, U32> = hkdf_expand_label(
            self.server_traffic_secret.as_ref().unwrap(),
            b"finished",
            &[],
        );

        let mut hmac = Hmac::<Sha256>::new_from_slice(&key).unwrap();
        hmac.update(transcript_hash);

        // Recipients of Finished messages MUST verify that the contents are
        // correct and if incorrect MUST terminate the connection with a
        // "decrypt_error" alert.
        hmac.verify_slice(finished)
            .map_err(|_| AlertDescription::DecryptError)
    }

    pub fn verify_client_finished(&self, finished: &[u8; 32]) -> Result<(), AlertDescription> {
        let key: Array<u8, U32> = hkdf_expand_label(
            self.client_traffic_secret.as_ref().unwrap(),
            b"finished",
            &[],
        );

        let mut hmac = Hmac::<Sha256>::new_from_slice(&key).unwrap();
        hmac.update(&self.transcript_hash_bytes());

        // Recipients of Finished messages MUST verify that the contents are
        // correct and if incorrect MUST terminate the connection with a
        // "decrypt_error" alert.
        hmac.verify_slice(finished)
            .map_err(|_| AlertDescription::DecryptError)
    }

    pub fn client_finished_verify_data(&self) -> Array<u8, U32> {
        let key: Array<u8, U32> = hkdf_expand_label(
            self.client_traffic_secret.as_ref().unwrap(),
            b"finished",
            &[],
        );

        let mut hmac = Hmac::<Sha256>::new_from_slice(&key).unwrap();
        hmac.update(&self.transcript_hash_bytes());
        hmac.finalize().into_bytes()
    }

    pub fn server_finished_verify_data(&self) -> Array<u8, U32> {
        let key: Array<u8, U32> = hkdf_expand_label(
            self.server_traffic_secret.as_ref().unwrap(),
            b"finished",
            &[],
        );

        let mut hmac = Hmac::<Sha256>::new_from_slice(&key).unwrap();
        hmac.update(&self.transcript_hash_bytes());
        hmac.finalize().into_bytes()
    }
}

impl ::core::fmt::Debug for KeySchedule {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> Result<(), ::core::fmt::Error> {
        write!(f, "KeySchedule {{ ... }}")
    }
}
