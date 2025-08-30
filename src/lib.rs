#![allow(dead_code)]

mod alert;
mod base;
mod cipher_suite;
mod client;
mod error;
mod handshake;
mod key_schedule;
pub(crate) mod parse;
mod record;
mod server;
mod tls_version;

pub use alert::{Alert, AlertDescription, AlertLevel};
pub use client::{TlsClientBuilder, TlsClientStream};
pub use error::TlsError;
pub use server::{ServerCertificates, TlsServerBuilder, TlsServerStream};

pub(crate) const GCM_TAG_LEN: usize = 16;

/// Pre-shared key.
#[derive(Debug, Clone)]
pub struct Psk {
    identity: Vec<u8>,
    key: [u8; 32],
}

impl Psk {
    /// Create a new pre-shared key from an identity and a key.
    ///
    /// # Examples
    ///
    /// ```
    /// # const PRIVATE_PRE_SHARED_KEY: [u8; 32] = [0; 32];
    /// use tls_tester::Psk;
    ///
    /// let psk: Psk = Psk::new(b"devicename".to_vec(), PRIVATE_PRE_SHARED_KEY);
    /// ```
    pub fn new(identity: Vec<u8>, key: [u8; 32]) -> Self {
        Self { identity, key }
    }
}
