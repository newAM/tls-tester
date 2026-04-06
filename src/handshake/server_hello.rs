use super::{
    KeyShareEntry, NamedGroup,
    extension::{PskServerHello, ServerHelloExtension, ServerHelloExtensions},
};
use crypto_bigint::{consts::U32, hybrid_array::Array};
use rand::TryRng as _;
use sha2::Digest;

use crate::{
    AlertDescription, base, cipher_suite::CipherSuite, decode::DecodeContext,
    tls_version::TlsVersion,
};

// https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.3
// For reasons of backward compatibility with middleboxes (see
// Appendix D.4), the HelloRetryRequest message uses the same structure
// as the ServerHello, but with Random set to the special value of the
// SHA-256 of "HelloRetryRequest"
const SERVER_HELLO_RETRY_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

/// Server Hello key exchange message.
///
/// # References
///
/// * [RFC 8446 Appendix B.3.1](https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.3.1)
///
/// ```text
/// struct {
///     ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
///     Random random;
///     opaque legacy_session_id<0..32>;
///     CipherSuite cipher_suite;
///     uint8 legacy_compression_method = 0;
///     Extension extensions<6..2^16-1>;
/// } ServerHello;
/// ```
#[derive(Debug)]
pub struct ServerHelloBuilder {
    random: [u8; 32],
    legacy_session_id: Vec<u8>,
    client_hello_inner_random: Option<[u8; 32]>,
    extensions: Vec<ServerHelloExtension>,
}

impl ServerHelloBuilder {
    pub fn new(
        legacy_session_id: &[u8],
        key: KeyShareEntry,
        selected_identity: Option<u16>,
    ) -> Self {
        let mut random: [u8; 32] = [0; 32];
        rand::rngs::ThreadRng::default()
            .try_fill_bytes(&mut random)
            .expect("ThreadRng failure");

        let mut extensions: Vec<ServerHelloExtension> = Vec::with_capacity(3);

        extensions.push(ServerHelloExtension::SupportedVersions(TlsVersion::V1_3));

        if let Some(selected_identity_idx) = selected_identity {
            extensions.push(ServerHelloExtension::PreSharedKey(PskServerHello::new(
                selected_identity_idx,
            )));
        }

        extensions.push(ServerHelloExtension::KeyShareServerHello(key));

        Self {
            random,
            legacy_session_id: legacy_session_id.to_vec(),
            client_hello_inner_random: None,
            extensions,
        }
    }

    #[must_use]
    pub fn accept_ech(mut self, client_hello_inner_random: &[u8; 32]) -> Self {
        self.client_hello_inner_random = Some(*client_hello_inner_random);
        self
    }

    pub fn new_retry(legacy_session_id: &[u8], selected_identity: Option<u16>) -> Self {
        let mut extensions: Vec<ServerHelloExtension> = Vec::with_capacity(3);

        extensions.push(ServerHelloExtension::SupportedVersions(TlsVersion::V1_3));

        if let Some(selected_identity_idx) = selected_identity {
            extensions.push(ServerHelloExtension::PreSharedKey(PskServerHello::new(
                selected_identity_idx,
            )));
        }

        extensions.push(ServerHelloExtension::KeyShareHelloRetryRequest(
            NamedGroup::secp256r1,
        ));

        Self {
            random: SERVER_HELLO_RETRY_RANDOM,
            legacy_session_id: legacy_session_id.to_vec(),
            client_hello_inner_random: None,
            extensions,
        }
    }

    pub fn ser(self, transcript_hash_ech: &mut sha2::Sha256) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();

        // legacy_version
        buf.extend_from_slice(&[0x03, 0x03]);

        // random
        let random_last_8_bytes: usize = buf.len() + 24;
        buf.extend_from_slice(&self.random);

        // legacy_session_id
        buf.push(
            self.legacy_session_id
                .len()
                .try_into()
                .expect("ServerHello.legacy_session_id length exceeds maximum of 32"),
        );
        buf.extend_from_slice(&self.legacy_session_id);

        // cipher_suite
        buf.extend_from_slice(&u16::from(CipherSuite::TLS_AES_128_GCM_SHA256).to_be_bytes());

        // legacy_compression_method
        buf.push(0);

        let extensions_len_idx: usize = buf.len();

        // extensions length
        buf.extend_from_slice(&0_u16.to_be_bytes());

        // All TLS 1.3
        // ServerHello messages MUST contain the "supported_versions"
        // extension.  Current ServerHello messages additionally contain
        // either the "pre_shared_key" extension or the "key_share"
        // extension, or both (when using a PSK with (EC)DHE key
        // establishment).

        let mut extensions_len: u16 = 0;

        for extension in &self.extensions {
            let data: Vec<u8> = extension.ser();
            let data_len: u16 = data.len().try_into().unwrap();
            extensions_len = extensions_len.checked_add(data_len).unwrap();
            buf.extend_from_slice(&extension.ser());
        }

        buf[extensions_len_idx..extensions_len_idx + 2]
            .copy_from_slice(&extensions_len.to_be_bytes());

        if let Some(client_hello_inner_random) = self.client_hello_inner_random {
            // "the last 8 bytes of ServerHello.random are set to zero"
            buf[random_last_8_bytes..random_last_8_bytes + 8].fill(0);

            // compute the transcript hash for ClientHelloInner up to and
            // including the modified ServerHello
            let server_hello_with_zeros: Vec<u8> =
                crate::handshake::HandshakeHeader::prepend_header(
                    crate::handshake::HandshakeType::ServerHello,
                    &buf,
                );
            transcript_hash_ech.update(&server_hello_with_zeros);

            let transcript_ech_conf: Array<u8, U32> = transcript_hash_ech.clone().finalize();

            let accept_confirmation: [u8; 8] =
                base::compute_accept_confirmation(&client_hello_inner_random, &transcript_ech_conf);

            buf[random_last_8_bytes..random_last_8_bytes + 8].copy_from_slice(&accept_confirmation);
        }
        buf
    }
}

/// Server Hello key exchange message.
///
/// # References
///
/// * [RFC 8446 Appendix B.3.1](https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.3.1)
///
/// ```text
/// struct {
///     ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
///     Random random;
///     opaque legacy_session_id<0..32>;
///     CipherSuite cipher_suite;
///     uint8 legacy_compression_method = 0;
///     Extension extensions<6..2^16-1>;
/// } ServerHello;
/// ```
#[derive(Debug)]
pub struct ServerHello {
    pub random: [u8; 32],
    pub legacy_session_id: Vec<u8>,
    pub cipher_suite: CipherSuite,
    pub exts: ServerHelloExtensions,
}

impl ServerHello {
    pub fn decode(ctx: &mut DecodeContext) -> Result<Self, AlertDescription> {
        let legacy_version = ctx.u16("legacy_version", "ProtocolVersion")?;

        if legacy_version != 0x0303 {
            log::error!(
                "{} 0x{legacy_version:04X} is not the required value of 0x0303",
                ctx.prev_path()
            );
            return Err(AlertDescription::IllegalParameter);
        }

        let random: [u8; 32] = ctx.fixed("random", "Random")?;

        let retry_request: bool = random == SERVER_HELLO_RETRY_RANDOM;
        if retry_request {
            log::debug!("< {} is a retry request", ctx.prev_path());
        }

        let legacy_session_id: Vec<u8> = ctx.vec8("legacy_session_id", "opaque<0..32>", 0, 1)?;

        if legacy_session_id.len() > 32 {
            log::error!("{} length is greater than maximum of 32", ctx.prev_path());
            return Err(AlertDescription::DecodeError);
        }

        let cipher_suite = ctx.u16("cipher_suite", "CipherSuite")?;

        let cipher_suite: CipherSuite = match CipherSuite::try_from(cipher_suite) {
            Ok(cs) => cs,
            Err(v) => {
                log::error!("{} contains unknown value 0x{v:04X}", ctx.prev_path());
                return Err(AlertDescription::IllegalParameter);
            }
        };

        let legacy_compression_method = ctx.u8("legacy_compression_method", "uint8")?;

        if legacy_compression_method != 0 {
            log::error!(
                "{} 0x{legacy_compression_method:02X} is not the required value of 0",
                ctx.prev_path()
            );
            return Err(AlertDescription::IllegalParameter);
        }

        ctx.begin_vec16("extensions", "Extension<6..2^16-1>", 6, 1)?;
        let exts = ServerHelloExtensions::decode(ctx, retry_request)?;
        ctx.end_vec()?;

        Ok(Self {
            random,
            legacy_session_id,
            cipher_suite,
            exts,
        })
    }
}
