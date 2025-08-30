use crate::{alert::AlertDescription, parse};

/// ServerName extension.
///
/// # References
///
/// * [RFC 8446 Appendix B.3.1](https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.3.1)
///
/// ```text
/// struct {
///     NameType name_type;
///     select (name_type) {
///         case host_name: HostName;
///     } name;
/// } ServerName;
///
/// enum {
///     host_name(0), (255)
/// } NameType;
///
/// opaque HostName<1..2^16-1>;
///
/// struct {
///     ServerName server_name_list<1..2^16-1>
/// } ServerNameList;
/// ```
#[derive(Debug)]
pub struct ServerNameList {
    server_name_list: Vec<ServerName>,
}

impl ServerNameList {
    pub fn deser(b: &[u8]) -> Result<Self, AlertDescription> {
        let (_, mut b) = parse::vec16("ServerNameList", b, 1, 1)?;

        let mut ret: Vec<ServerName> = Vec::new();

        while !b.is_empty() {
            let (b_new, name): (_, ServerName) = ServerName::deser(b)?;
            b = b_new;
            ret.push(name);
        }

        Ok(ServerNameList {
            server_name_list: ret,
        })
    }

    pub fn ser(&self) -> Vec<u8> {
        let mut len: u16 = 0;

        let mut ret: Vec<u8> = vec![0; 2];
        for name in &self.server_name_list {
            let name_data: Vec<u8> = name.ser();
            len = len.saturating_add(name_data.len().try_into().unwrap());
            ret.extend_from_slice(&name_data);
        }

        ret
    }
}

#[derive(Debug)]
pub struct ServerName {
    pub name: String,
}

impl ServerName {
    // maximum length for a valid DNS name
    const DNS_MAX_LEN: usize = 253;

    pub fn from_str(name: &str) -> Option<Self> {
        if name.is_empty() || name.len() > Self::DNS_MAX_LEN {
            None
        } else {
            Some(Self {
                name: name.to_string(),
            })
        }
    }

    fn deser(b: &[u8]) -> Result<(&[u8], Self), AlertDescription> {
        let (b, name_type): (_, u8) = parse::u8("ServerName name_type", b)?;

        if name_type != 0 {
            log::error!("ServerName name_type is not host_name");
            return Err(AlertDescription::IllegalParameter)?;
        }

        let (remain, b): (_, &[u8]) = parse::vec16("ServerName host_name", b, 1, 1)?;

        let name: String = match String::from_utf8(b.to_vec()) {
            Ok(name) => name,
            Err(e) => {
                // spec does not require host_name is UTF-8
                log::error!("ServerName host_name is not UTF-8: {e}");
                return Err(AlertDescription::DecodeError)?;
            }
        };

        if name.len() > Self::DNS_MAX_LEN {
            log::warn!(
                "ServerName host_name is {} bytes, which is larger than {} bytes, the maximum for a valid DNS record",
                name.len(),
                Self::DNS_MAX_LEN
            );
        }

        Ok((remain, Self { name }))
    }

    pub fn ser(&self) -> Vec<u8> {
        let mut ret: Vec<u8> = Vec::with_capacity(3 + self.name.len());

        // unwrap will never panic, length is validated in constructors
        let len: [u8; 2] = u16::try_from(self.name.len()).unwrap().to_be_bytes();

        ret.push(0); // name_type host_name
        ret.extend_from_slice(&len);
        ret.extend(self.name.as_bytes());

        ret
    }
}
