use crate::{alert::AlertDescription, decode::DecodeContext};

/// ServerName extension.
///
/// # References
///
/// - [RFC 6066 Section 3](https://datatracker.ietf.org/doc/html/rfc6066#section-3)
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
#[derive(Debug, PartialEq)]
pub struct ServerNameList {
    pub server_name_list: Vec<ServerName>,
}

impl ServerNameList {
    pub fn decode(ctx: &mut DecodeContext) -> Result<Self, AlertDescription> {
        ctx.begin_vec16("server_name_list", "ServerName<1..2^16-1>", 1, 1)?;

        let mut server_name_list: Vec<ServerName> = Vec::new();
        let mut index = 0;
        while ctx.remaining() > 0 {
            ctx.begin_element("server_name", "ServerName", index);
            let name = ServerName::decode(ctx)?;
            server_name_list.push(name);
            ctx.end_element();
            index += 1;
        }

        ctx.end_vec()?;

        Ok(Self { server_name_list })
    }

    pub fn ser(&self) -> Vec<u8> {
        let mut len: u16 = 0;

        let mut ret: Vec<u8> = vec![0; 2];
        for name in &self.server_name_list {
            let name_data: Vec<u8> = name.ser();
            let name_len: u16 = name_data
                .len()
                .try_into()
                .expect("ServerName length exceeds u16::MAX");
            len = len
                .checked_add(name_len)
                .expect("ServerNameList total length exceeds u16::MAX");
            ret.extend_from_slice(&name_data);
        }

        ret[..2].copy_from_slice(&len.to_be_bytes());

        ret
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ServerName {
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

    fn decode(ctx: &mut DecodeContext) -> Result<Self, AlertDescription> {
        let name_type = ctx.u8("name_type", "NameType")?;

        if name_type != 0 {
            log::error!("{} name_type is not host_name", ctx.current_path());
            return Err(AlertDescription::IllegalParameter);
        }

        let host_name_bytes = ctx.vec16("host_name", "HostName<1..2^16-1>", 1, 1)?;

        let name: String = match String::from_utf8(host_name_bytes) {
            Ok(name) => name,
            Err(e) => {
                // spec does not require host_name is UTF-8
                log::error!("{} host_name is not UTF-8: {e}", ctx.current_path());
                return Err(AlertDescription::DecodeError);
            }
        };

        if name.len() > Self::DNS_MAX_LEN {
            log::warn!(
                "{} host_name is {} bytes, which is larger than {} bytes, the maximum for a valid DNS record",
                ctx.current_path(),
                name.len(),
                Self::DNS_MAX_LEN
            );
        }

        Ok(Self { name })
    }

    pub fn ser(&self) -> Vec<u8> {
        let mut ret: Vec<u8> = Vec::with_capacity(self.name.len().saturating_add(3));

        let name_len: [u8; 2] = u16::try_from(self.name.len()).unwrap().to_be_bytes();

        ret.push(0); // name_type host_name
        ret.extend_from_slice(&name_len);
        ret.extend(self.name.as_bytes());

        ret
    }
}

#[cfg(test)]
mod tests {
    use super::{DecodeContext, ServerName, ServerNameList};

    const NAME: &str = "subdomain.example.com";

    #[test]
    fn server_name() {
        let server_name: ServerName = ServerName::from_str(NAME).unwrap();

        let server_name_bytes: Vec<u8> = server_name.ser();
        let mut ctx = DecodeContext::new("ServerName", server_name_bytes);
        let result = ServerName::decode(&mut ctx).unwrap();

        assert!(ctx.remaining() == 0);
        assert_eq!(result, server_name);
    }

    #[test]
    fn server_name_list() {
        let server_name: ServerName = ServerName::from_str(NAME).unwrap();
        let server_name_list: ServerNameList = ServerNameList {
            server_name_list: vec![server_name],
        };

        let server_name_list_bytes: Vec<u8> = server_name_list.ser();
        let mut ctx = DecodeContext::new("ServerNameList", server_name_list_bytes);
        let result = ServerNameList::decode(&mut ctx).unwrap();

        assert_eq!(result, server_name_list);
    }
}
