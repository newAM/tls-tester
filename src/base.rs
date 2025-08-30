use std::{
    cmp::{max, min},
    io::{Read as _, Write as _},
    net::TcpStream,
};

use aes_gcm::{Aes128Gcm, KeyInit as _, aead::AeadMutInPlace as _};
use hmac::digest::consts::{U12, U16};

use crate::{
    Alert, AlertDescription, GCM_TAG_LEN, Psk, TlsError,
    handshake::HandshakeHeader,
    key_schedule::KeySchedule,
    record::{ContentType, RecordHeader},
};

/// Internal TLS states.
// https://datatracker.ietf.org/doc/html/rfc8446#appendix-A.1
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum TlsState {
    /// Wait for a ClientHello.
    ///
    /// Client Only.
    WaitServerHello,
    /// Wait for encrypted extensions.
    ///
    /// Client only.
    WaitEncryptedExtensions,
    /// Wait for certificate.
    ///
    /// Client only.
    WaitCertificate,
    /// Wait for certificate verify.
    ///
    /// Client only.
    WaitCertificateVerify,
    /// Wait for a ClientHello.
    ///
    /// Server only.
    WaitClientHello,
    /// Wait for a second ClientHello in response to HelloRetryRequest.
    ///
    /// Server only.
    WaitClientHelloRetry,
    /// Wait for Finished.
    ///
    /// Server only.
    WaitClientFinished,
    /// Wait for Finished.
    ///
    /// Client only.
    WaitServerFinished,
    /// TLS handshake has completed.
    Connected,
    /// Fatal alert sent.
    SentAlert,
    /// Fatal alert received.
    RecvAlert,
}

pub(crate) struct TlsStream {
    pub(crate) stream: TcpStream,
    pub(crate) state: TlsState,
    pub(crate) key_schedule: KeySchedule,
    pub(crate) psks: Vec<Psk>,
    pub(crate) buf: std::collections::VecDeque<u8>,
    pub(crate) record_size_limit: u16,
}

impl TlsStream {
    pub(crate) fn set_state(&mut self, state: TlsState) {
        debug_assert_ne!(self.state, state);
        log::debug!("{:?} -> {:?}", self.state, state);
        self.state = state;
    }

    fn next_record_header(&mut self) -> Result<RecordHeader, TlsError> {
        let mut hdr_buf: [u8; RecordHeader::LEN] = [0; RecordHeader::LEN];
        self.stream.read_exact(&mut hdr_buf)?;
        let hdr: RecordHeader = RecordHeader::deser(hdr_buf)?;
        log::debug!("< {hdr:?}");
        Ok(hdr)
    }

    fn pop_front_fixed<const N: usize>(&mut self) -> Option<[u8; N]> {
        if self.buf.len() >= N {
            let mut buf: [u8; N] = [0; N];
            for byte in buf.iter_mut() {
                // unwrap will not occur, we checked length
                *byte = self.buf.pop_front().unwrap()
            }
            Some(buf)
        } else {
            None
        }
    }

    fn pop_front(&mut self, n: usize) -> Option<Vec<u8>> {
        if self.buf.len() >= n {
            let mut buf: Vec<u8> = Vec::with_capacity(n);
            for _ in 0..n {
                // unwrap will never occur due to initial length check
                buf.push(self.buf.pop_front().unwrap())
            }
            Some(buf)
        } else {
            None
        }
    }

    pub(crate) fn next_handshake_header(&mut self) -> Result<HandshakeHeader, TlsError> {
        loop {
            if let Some(buf) = self.pop_front_fixed() {
                let hs_hdr: HandshakeHeader = HandshakeHeader::deser(buf)?;
                log::debug!("< {hs_hdr:?}");
                return Ok(hs_hdr);
            };
            self.read_next_record()?;
        }
    }

    pub(crate) fn next_handshake_data(
        &mut self,
        header: HandshakeHeader,
    ) -> Result<Vec<u8>, TlsError> {
        let hdr_len: usize =
            usize::try_from(header.length()).expect("Unsupported target architecture");

        loop {
            if let Some(buf) = self.pop_front(hdr_len) {
                return Ok(buf);
            };
            self.read_next_record()?;
        }
    }

    pub(crate) fn read_next_record(&mut self) -> Result<(), TlsError> {
        let rec_hdr: RecordHeader = self.next_record_header()?;

        match rec_hdr.content_type() {
            ContentType::ChangeCipherSpec => {
                // not used in TLS 1.3

                if rec_hdr.length() != 1 {
                    log::error!(
                        "Record length of {} doesn't match expected of 1 for ChangeCipherSpec",
                        rec_hdr.length()
                    );
                    return Err(AlertDescription::DecodeError)?;
                }
                let mut change_cipher_spec: [u8; 1] = [0];
                self.stream.read_exact(&mut change_cipher_spec)?;
            }
            ContentType::Alert => {
                // Alert messages MUST NOT be fragmented across records
                if rec_hdr.length() != 2 {
                    log::error!(
                        "Received alert record with size {} expected 2",
                        rec_hdr.length()
                    );
                    return Err(AlertDescription::DecodeError)?;
                }
                let mut alert_buf: [u8; 2] = [0; 2];
                self.stream.read_exact(&mut alert_buf)?;

                let alert: Alert = Alert::from_be_bytes(alert_buf)?;

                log::error!("< {alert:?}");

                self.set_state(TlsState::RecvAlert);

                return Err(TlsError::RecvAlert(alert.description));
            }
            ContentType::Handshake => {
                if !matches!(
                    self.state,
                    TlsState::WaitServerHello
                        | TlsState::WaitClientHello
                        | TlsState::WaitClientHelloRetry
                ) {
                    // https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2
                    // Because TLS 1.3 forbids renegotiation, if a server has negotiated
                    // TLS 1.3 and receives a ClientHello at any other time, it MUST
                    // terminate the connection with an "unexpected_message" alert.
                    log::error!("Unexpected unencrypted handshake in state {:?}", self.state);
                    return Err(AlertDescription::UnexpectedMessage)?;
                }

                if rec_hdr.length() == 0 {
                    log::error!("Received zero-length Handshake fragment");
                    return Err(AlertDescription::UnexpectedMessage)?;
                }

                let orig_len: usize = self.buf.len();
                self.buf.resize(orig_len + usize::from(rec_hdr.length()), 0);

                let read_buf: &mut [u8] = &mut self.buf.make_contiguous()[orig_len..];
                self.stream.read_exact(read_buf)?;

                self.key_schedule.update_transcript_hash(read_buf);
                self.key_schedule.increment_read_record_sequence_number();
            }
            ContentType::ApplicationData => {
                // + 1 is for content type
                if usize::from(rec_hdr.length()) < GCM_TAG_LEN + 1 {
                    log::error!(
                        "Received encrypted record with length {} which is too short to contain an AES-GCM tag",
                        rec_hdr.length()
                    );
                    return Err(AlertDescription::UnexpectedMessage)?;
                }

                let mut buf: Vec<u8> = vec![0; rec_hdr.length().into()];
                self.stream.read_exact(&mut buf)?;

                let (key, nonce): ([u8; 16], [u8; 12]) =
                    self.key_schedule.read_key_and_nonce().unwrap();
                let nonce: aes_gcm::Nonce<U12> = aes_gcm::Nonce::clone_from_slice(&nonce);
                let key: aes_gcm::Key<Aes128Gcm> =
                    aes_gcm::Key::<Aes128Gcm>::clone_from_slice(&key);

                // unwrap will not occur due to initial length checks
                let tag: Vec<u8> = buf.split_off(buf.len().checked_sub(GCM_TAG_LEN).unwrap());
                let tag: [u8; GCM_TAG_LEN] = tag.try_into().unwrap();
                let tag: aes_gcm::Tag<U16> = tag.into();

                let mut cipher = Aes128Gcm::new(&key);
                if cipher
                    .decrypt_in_place_detached(&nonce, rec_hdr.as_bytes(), &mut buf, &tag)
                    .is_err()
                {
                    log::error!("Tag mismatch during record decryption");
                    return Err(AlertDescription::BadRecordMac)?;
                }

                // unwrap will not occur due to initial length checks
                let content_type_byte: u8 = buf.pop().unwrap();
                let real_content_type: ContentType = match ContentType::try_from(content_type_byte)
                {
                    Ok(content_type) => content_type,
                    Err(val) => {
                        log::error!(
                            "Received invalid ContentType value 0x{val:02X} in encrypted record"
                        );
                        return Err(AlertDescription::DecodeError)?;
                    }
                };

                log::debug!("< {real_content_type:?}");

                match real_content_type {
                    ContentType::ChangeCipherSpec => {
                        log::error!("Received encrypted ChangeCipherSpec");
                        return Err(AlertDescription::UnexpectedMessage)?;
                    }
                    ContentType::Alert => {
                        // Alert messages MUST NOT be fragmented across records
                        let buf_len: usize = buf.len();
                        let buf_fixed: [u8; 2] = match buf.try_into() {
                            Ok(b) => b,
                            Err(_) => {
                                log::error!(
                                    "Received alert record with size {} expected 2",
                                    buf_len
                                );
                                return Err(AlertDescription::DecodeError)?;
                            }
                        };

                        let alert: Alert = Alert::from_be_bytes(buf_fixed)?;

                        log::error!("< {alert:?}");

                        self.set_state(TlsState::RecvAlert);

                        return Err(TlsError::RecvAlert(alert.description));
                    }
                    ContentType::Handshake => {
                        // master secret transcript hash spans ClientHello...server Finished
                        if self.state != TlsState::WaitClientFinished {
                            self.key_schedule.update_transcript_hash(&buf);
                        }
                        self.key_schedule.increment_read_record_sequence_number();
                        self.buf.extend(buf);
                    }
                    ContentType::ApplicationData => {
                        self.key_schedule.update_transcript_hash(&buf);
                        self.key_schedule.increment_read_record_sequence_number();
                        self.buf.extend(buf);
                    }
                }
            }
        };

        Ok(())
    }

    pub(crate) fn write_unencrypted_record(
        &mut self,
        content_type: ContentType,
        mut data: &[u8],
    ) -> Result<(), TlsError> {
        let record_size_limit: u16 = max(1, max(content_type.min_length(), self.record_size_limit));

        let num_records: usize = data.len().div_ceil(record_size_limit.into());

        for _ in 0..num_records {
            let record_data_len_no_overhead: u16 =
                min(record_size_limit, data.len().try_into().unwrap_or(u16::MAX));

            let (record_data, remain) = data.split_at(record_data_len_no_overhead.into());
            data = remain;

            let hdr: RecordHeader = RecordHeader::ser(content_type, record_data.len())?;

            log::debug!("> {hdr:?}");

            self.stream.write_all(hdr.as_bytes())?;
            self.stream.write_all(record_data)?;

            self.key_schedule.update_transcript_hash(record_data);
            self.key_schedule.increment_write_record_sequence_number();
        }

        Ok(())
    }

    pub(crate) fn write_encrypted_records(
        &mut self,
        content_type: ContentType,
        mut data: &[u8],
    ) -> Result<(), TlsError> {
        const CONTENT_TYPE_LEN: u16 = 1;

        let record_size_limit_no_overhead: u16 = max(
            1,
            max(
                content_type.min_length(),
                self.record_size_limit
                    .saturating_sub(GCM_TAG_LEN as u16)
                    .saturating_sub(CONTENT_TYPE_LEN),
            ),
        );

        let num_records: usize = data.len().div_ceil(record_size_limit_no_overhead.into());

        for _ in 0..num_records {
            let record_data_len_no_overhead: u16 = min(
                record_size_limit_no_overhead,
                data.len().try_into().unwrap_or(u16::MAX),
            );

            let (record_data, remain) = data.split_at(record_data_len_no_overhead.into());

            data = remain;

            let mut record_data: Vec<u8> = record_data.to_vec();

            let record_data_len: u16 =
                record_data_len_no_overhead + GCM_TAG_LEN as u16 + CONTENT_TYPE_LEN;

            let hdr: RecordHeader =
                RecordHeader::ser(ContentType::ApplicationData, record_data_len.into())?;

            let (key, nonce): ([u8; 16], [u8; 12]) =
                self.key_schedule.write_key_and_nonce().unwrap();
            let nonce: aes_gcm::Nonce<U12> = aes_gcm::Nonce::clone_from_slice(&nonce);
            let key: aes_gcm::Key<Aes128Gcm> = aes_gcm::Key::<Aes128Gcm>::clone_from_slice(&key);

            // master secret transcript hash spans ClientHello...server Finished
            if self.state != TlsState::WaitServerFinished {
                self.key_schedule.update_transcript_hash(&record_data);
            }

            record_data.push(content_type as u8);

            let mut cipher = Aes128Gcm::new(&key);
            let tag: aes_gcm::Tag<U16> =
                match cipher.encrypt_in_place_detached(&nonce, hdr.as_bytes(), &mut record_data) {
                    Ok(tag) => tag,
                    Err(_) => {
                        log::error!("Failed to encrypt record");
                        return Err(AlertDescription::InternalError)?;
                    }
                };

            log::debug!("> {hdr:?}");

            self.stream.write_all(hdr.as_bytes())?;
            self.stream.write_all(&record_data)?;
            self.stream.write_all(tag.as_slice())?;

            self.key_schedule.increment_write_record_sequence_number();
        }

        Ok(())
    }

    pub(crate) fn send_fatal_alert(
        &mut self,
        description: AlertDescription,
    ) -> Result<(), TlsError> {
        log::error!("> {description:?}");
        if !matches!(
            self.state,
            TlsState::WaitServerHello | TlsState::WaitClientHello | TlsState::WaitClientHelloRetry
        ) {
            if let Err(e) = self.write_unencrypted_record(
                ContentType::Alert,
                &Alert::new_fatal(description).to_be_bytes(),
            ) {
                log::error!("Failed to send unencrypted alert: {e}")
            }
        } else if let Err(e) = self.write_encrypted_records(
            ContentType::Alert,
            &Alert::new_fatal(description).to_be_bytes(),
        ) {
            log::error!("Failed to send encrypted alert: {e}")
        }

        Err(TlsError::SendAlert(description))
    }
}
