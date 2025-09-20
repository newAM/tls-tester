use super::{HandshakeHeader, HandshakeType};

/// # References
///
/// * [RFC 8446 Appendix B.3.3](https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.3.3)
///
/// ```text
/// struct {
///     opaque verify_data[Hash.length];
/// } Finished;
/// ```
pub fn finished_with_hs_hdr(verify_data: &[u8]) -> Vec<u8> {
    HandshakeHeader::prepend_header(HandshakeType::Finished, verify_data)
}
