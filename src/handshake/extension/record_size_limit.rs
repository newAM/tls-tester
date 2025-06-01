use crate::AlertDescription;

/// # Reference
///
/// - [RFC 8449 Section 4](https://datatracker.ietf.org/doc/html/rfc8449#section-4)
///
/// ```text
/// uint16 RecordSizeLimit;
/// ```
#[derive(Debug, Clone, Copy)]
pub struct RecordSizeLimit(u16);

impl RecordSizeLimit {
    // TLS 1.3 uses a limit of 2^14+1 octets
    pub const LIMIT_MAX: u16 = (1 << 14) + 1;

    pub fn deser(data: &[u8]) -> Result<Self, AlertDescription> {
        let data_sized: [u8; 2] = match data.try_into() {
            Ok(d) => d,
            Err(_) => {
                log::error!(
                    "RecordSizeLimit size {} does not match expected of 2",
                    data.len()
                );
                return Err(AlertDescription::DecodeError);
            }
        };

        let limit: u16 = u16::from_be_bytes(data_sized);

        if limit > Self::LIMIT_MAX {
            log::error!(
                "RecordSizeLimit of {limit} is greater than TLS v1.3 maximum of {}",
                Self::LIMIT_MAX
            );
            return Err(AlertDescription::IllegalParameter);
        }

        // Endpoints MUST NOT send a "record_size_limit" extension with a value
        // smaller than 64.  An endpoint MUST treat receipt of a smaller value
        // as a fatal error and generate an "illegal_parameter" alert.
        const LIMIT_MIN: u16 = 64;
        if limit < LIMIT_MIN {
            log::error!("RecordSizeLimit of {limit} is less than minimum of {LIMIT_MIN}");
            return Err(AlertDescription::IllegalParameter);
        }

        Ok(RecordSizeLimit(limit))
    }

    pub fn ser(&self) -> Vec<u8> {
        self.0.to_be_bytes().to_vec()
    }
}

impl std::fmt::Display for RecordSizeLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<RecordSizeLimit> for u16 {
    fn from(value: RecordSizeLimit) -> Self {
        value.0
    }
}
