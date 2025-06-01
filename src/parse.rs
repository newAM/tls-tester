// vec8, pop u8 len from buf, pop &[u8] from buf, return remaining data
// maybe accept a multiple argument for len validation, also a min then?
// vec16

use crate::AlertDescription;

pub fn u8<'a>(name: &str, buf: &'a [u8]) -> Result<(&'a [u8], u8), AlertDescription> {
    match buf.split_at_checked(1) {
        Some((val, remain)) => Ok((remain, val[0])),
        None => {
            log::error!("{name} is missing");
            Err(AlertDescription::DecodeError)
        }
    }
}

pub fn u16<'a>(name: &str, buf: &'a [u8]) -> Result<(&'a [u8], u16), AlertDescription> {
    match buf.split_at_checked(2) {
        Some((val, remain)) => Ok((remain, u16::from_be_bytes(val.try_into().unwrap()))),
        None => {
            log::error!("{name} is missing");
            Err(AlertDescription::DecodeError)
        }
    }
}

pub fn u32<'a>(name: &str, buf: &'a [u8]) -> Result<(&'a [u8], u32), AlertDescription> {
    match buf.split_at_checked(4) {
        Some((val, remain)) => Ok((remain, u32::from_be_bytes(val.try_into().unwrap()))),
        None => {
            log::error!("{name} is missing");
            Err(AlertDescription::DecodeError)
        }
    }
}

pub fn vec8<'a>(
    name: &str,
    buf: &'a [u8],
    min: u8,
    multiple: u8,
) -> Result<(&'a [u8], &'a [u8]), AlertDescription> {
    let len: u8 = match buf.first() {
        Some(l) => *l,
        None => {
            log::error!("{name} length is missing");
            return Err(AlertDescription::DecodeError);
        }
    };

    if len < min {
        log::error!("{name} length is less than minimum of {min}");
        return Err(AlertDescription::DecodeError);
    }

    if len % multiple != 0 {
        log::error!("{name} length is not a multiple of {multiple}");
        return Err(AlertDescription::DecodeError);
    }

    const DATA_START: usize = 1;
    let data_end: usize = usize::from(len) + DATA_START;

    let data = match buf.get(DATA_START..data_end) {
        Some(data) => data,
        None => {
            log::error!("{name} does not have enough data for length {len}");
            return Err(AlertDescription::DecodeError);
        }
    };

    let remain = &buf[data_end..];

    Ok((remain, data))
}

pub fn vec16<'a>(
    name: &str,
    buf: &'a [u8],
    min: u16,
    multiple: u16,
) -> Result<(&'a [u8], &'a [u8]), AlertDescription> {
    let len: u16 = match buf.get(..2) {
        Some(l) => u16::from_be_bytes(l.try_into().unwrap()),
        None => {
            log::error!("{name} length is missing");
            return Err(AlertDescription::DecodeError);
        }
    };

    if len < min {
        log::error!("{name} length is less than minimum of {min}");
        return Err(AlertDescription::DecodeError);
    }

    if len % multiple != 0 {
        log::error!("{name} length is not a multiple of {multiple}");
        return Err(AlertDescription::DecodeError);
    }

    const DATA_START: usize = 2;
    let data_end: usize = usize::from(len) + DATA_START;

    let data = match buf.get(DATA_START..data_end) {
        Some(data) => data,
        None => {
            log::error!("{name} does not have enough data for length {len}");
            return Err(AlertDescription::DecodeError);
        }
    };

    let remain = &buf[data_end..];

    Ok((remain, data))
}

pub fn fixed<'a, const N: usize>(
    name: &str,
    buf: &'a [u8],
) -> Result<(&'a [u8], [u8; N]), AlertDescription> {
    match buf.split_at_checked(N) {
        Some((val, remain)) => Ok((remain, val.try_into().unwrap())),
        None => {
            log::error!("{name} is missing");
            Err(AlertDescription::DecodeError)
        }
    }
}
