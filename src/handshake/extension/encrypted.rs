use super::EncryptedExtension;

/// Encrypted extensions message.
///
/// # References
///
/// * [RFC 8446 Section 4.3.1](https://datatracker.ietf.org/doc/html/rfc8446#section-4.3.1)
///
/// ```text
/// struct {
///     Extension extensions<0..2^16-1>;
/// } EncryptedExtensions;
/// ```
#[derive(Default)]
pub struct EncryptedExtensions {
    pub extensions: Vec<EncryptedExtension>,
}

impl EncryptedExtensions {
    pub fn ser(&self) -> Vec<u8> {
        let mut ret: Vec<u8> = vec![0; 2];

        let mut len: u16 = 0;

        for extension in &self.extensions {
            let data: Vec<u8> = match extension {
                EncryptedExtension::ServerName(server_name) => server_name.ser(),
                e => unimplemented!("Extension is unimplemented: {e:?}"),
            };

            ret.extend_from_slice(&data);

            len = len.checked_add(data.len().try_into().unwrap()).unwrap();
        }

        ret[0..2].copy_from_slice(&len.to_be_bytes());

        ret
    }
}
