#[repr(u16)]
#[derive(Debug, Clone, Copy)]
pub enum TlsVersion {
    V1_2 = 0x0303,
    V1_3 = 0x0304,
}

impl From<TlsVersion> for u16 {
    #[inline]
    fn from(tls_version: TlsVersion) -> Self {
        tls_version as u16
    }
}

impl TlsVersion {
    pub const fn msb(self) -> u8 {
        ((self as u16) >> 8) as u8
    }

    pub const fn lsb(self) -> u8 {
        self as u8
    }

    pub const fn to_be_bytes(self) -> [u8; 2] {
        (self as u16).to_be_bytes()
    }
}
