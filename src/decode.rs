use crate::alert::AlertDescription;
use crate::x509::Identifier;

/// Represents a single field in the decoded buffer
#[derive(Debug, Clone)]
pub(crate) struct FieldNode {
    /// Human-readable top level name (e.g., "legacy_version")
    pub(crate) name: String,
    /// Type name of the field (e.g., "u8", "u16", "vec16")
    pub(crate) type_name: String,
    /// Start index in the original buffer (absolute position)
    pub(crate) start: usize,
    /// End index in the original buffer (absolute position)
    pub(crate) end: usize,
    /// Child fields (for nested structures like extensions, vectors, etc.)
    pub(crate) children: Vec<FieldNode>,
    /// Optional array index for vector elements (e.g., Some(0) for extensions[0])
    pub(crate) index: Option<usize>,
}

impl FieldNode {
    pub(crate) fn new(name: String, type_name: String, start: usize, end: usize) -> Self {
        Self {
            name,
            type_name,
            start,
            end,
            children: Vec::new(),
            index: None,
        }
    }

    pub(crate) fn with_index(
        name: String,
        type_name: String,
        start: usize,
        end: usize,
        index: usize,
    ) -> Self {
        Self {
            name,
            type_name,
            start,
            end,
            children: Vec::new(),
            index: Some(index),
        }
    }

    pub(crate) fn add_child(&mut self, child: FieldNode) {
        self.children.push(child);
    }
}

/// Context for tracking decoding positions and building the parse tree
#[derive(Debug)]
pub(crate) struct DecodeContext {
    /// Top level name of the data structure being decoded.
    name: String,
    /// The original buffer being decoded
    original_buffer: Vec<u8>,
    /// Current offset from the start of original_buffer
    current_offset: usize,
    /// Stack of (node, start_offset) for building the tree structure
    node_stack: Vec<(FieldNode, usize)>,
    /// The completed root node (once parsing is done)
    root: Option<FieldNode>,
    /// Optional parent path for sub-contexts (used for debug logging)
    parent_path: Option<String>,
    /// Path to the previously completed field node
    prev_completed_path: Option<String>,
    /// Stack of expected end positions for nested vectors
    /// Each entry is the absolute end position of a vector's data (after length prefix)
    vec_end_stack: Vec<usize>,
    /// Stack of expected end positions for nested DER TLV structures (separate from TLS vec_end_stack)
    /// Each entry is the absolute end position of a DER TLV's content
    der_end_stack: Vec<usize>,
}

impl DecodeContext {
    pub fn new(name: &str, buffer: Vec<u8>) -> Self {
        Self {
            name: name.to_string(),
            original_buffer: buffer,
            current_offset: 0,
            node_stack: Vec::new(),
            root: None,
            parent_path: None,
            prev_completed_path: None,
            vec_end_stack: Vec::new(),
            der_end_stack: Vec::new(),
        }
    }

    pub fn original_buffer(&self) -> &[u8] {
        &self.original_buffer
    }

    pub fn current_position(&self) -> usize {
        self.current_offset
    }

    /// Get the number of remaining bytes to be consumed
    /// Respects vector boundaries if inside a begin_vec/end_vec block
    pub fn remaining(&self) -> usize {
        let end = self
            .vec_end_stack
            .last()
            .copied()
            .unwrap_or(self.original_buffer.len());
        end.saturating_sub(self.current_offset)
    }

    /// Check if all data has been consumed, return error if there's trailing data
    pub fn ensure_fully_consumed(&self) -> Result<(), AlertDescription> {
        let remaining = self.remaining();
        if remaining > 0 {
            log::error!(
                "{} has {} bytes of trailing data",
                self.current_path(),
                remaining
            );
            return Err(AlertDescription::DecodeError);
        }
        Ok(())
    }

    /// Build the current path string for debug logging (e.g., "ServerHello.extensions[0].extension_type")
    pub fn current_path(&self) -> String {
        let mut parts: Vec<String> = vec![self.name.clone()];

        // Add parent path if this is a sub-context
        if let Some(ref parent) = self.parent_path {
            parts.push(parent.clone());
        }

        // Walk the stack to build the path
        for (node, _) in &self.node_stack {
            let part = if let Some(idx) = node.index {
                format!("{}[{}]", node.name, idx)
            } else {
                node.name.clone()
            };
            parts.push(part);
        }

        parts.join(".")
    }

    /// Build the previous path string
    pub fn prev_path(&self) -> String {
        // Return the path of the previously completed field node
        if let Some(ref prev_path) = self.prev_completed_path {
            prev_path.clone()
        } else {
            // If no field has been completed yet, return empty string
            String::new()
        }
    }

    pub fn advance(&mut self, n: usize) {
        self.current_offset += n;
    }

    pub(crate) fn begin_field(&mut self, name: &str, type_name: &str) {
        let node = FieldNode::new(
            name.to_string(),
            type_name.to_string(),
            self.current_offset,
            0,
        );
        self.node_stack.push((node, self.current_offset));
    }

    pub(crate) fn end_field(&mut self) {
        // Capture the path before popping
        let completed_path = self.current_path();

        if let Some((mut node, _start_offset)) = self.node_stack.pop() {
            node.end = self.current_offset;

            // Store the path of this completed node
            self.prev_completed_path = Some(completed_path);

            // Add to parent or set as root
            if let Some((parent, _)) = self.node_stack.last_mut() {
                parent.add_child(node);
            } else {
                // No parent, this is the root
                self.root = Some(node);
            }
        }
    }

    pub fn begin_element(&mut self, name: &str, type_name: &str, index: usize) {
        let node = FieldNode::with_index(
            name.to_string(),
            type_name.to_string(),
            self.current_offset,
            0,
            index,
        );
        self.node_stack.push((node, self.current_offset));
    }

    /// End parsing of a vector element
    pub fn end_element(&mut self) {
        self.end_field();
    }

    pub fn u8(&mut self, name: &str, type_name: &str) -> Result<u8, AlertDescription> {
        self.begin_field(name, type_name);

        let val = self
            .original_buffer
            .get(self.current_offset..)
            .and_then(|s| s.first())
            .copied()
            .ok_or_else(|| {
                log::error!("{} is missing", self.current_path());
                AlertDescription::DecodeError
            })?;

        self.advance(size_of::<u8>());
        self.end_field();
        Ok(val)
    }

    pub fn u16(&mut self, name: &str, type_name: &str) -> Result<u16, AlertDescription> {
        self.begin_field(name, type_name);

        let val = self
            .original_buffer
            .get(self.current_offset..self.current_offset + 2)
            .ok_or_else(|| {
                log::error!("{} is missing", self.current_path());
                AlertDescription::DecodeError
            })?
            .try_into()
            .map(u16::from_be_bytes)
            .unwrap();

        self.advance(size_of::<u16>());
        self.end_field();
        Ok(val)
    }

    pub fn u32(&mut self, name: &str, type_name: &str) -> Result<u32, AlertDescription> {
        self.begin_field(name, type_name);

        let val = self
            .original_buffer
            .get(self.current_offset..self.current_offset + 4)
            .ok_or_else(|| {
                log::error!("{} is missing", self.current_path());
                AlertDescription::DecodeError
            })?
            .try_into()
            .map(u32::from_be_bytes)
            .unwrap();

        self.advance(size_of::<u32>());
        self.end_field();
        Ok(val)
    }

    /// Begin parsing a vec8 field - pushes vector boundary to tracking stack
    /// Caller is responsible for parsing the contents and calling end_vec()
    /// The remaining() method will return bytes left in this vector
    pub fn begin_vec8(
        &mut self,
        name: &str,
        type_name: &str,
        min: u8,
        multiple: u8,
    ) -> Result<(), AlertDescription> {
        self.begin_field(name, type_name);

        let len: u8 = self
            .original_buffer
            .get(self.current_offset)
            .copied()
            .ok_or_else(|| {
                log::error!("{} length byte is missing", self.current_path());
                AlertDescription::DecodeError
            })?;

        if len < min {
            log::error!(
                "{} length is less than minimum of {min}",
                self.current_path()
            );
            self.end_field();
            return Err(AlertDescription::DecodeError);
        }

        if !len.is_multiple_of(multiple) {
            log::error!(
                "{} length is not a multiple of {multiple}",
                self.current_path()
            );
            self.end_field();
            return Err(AlertDescription::DecodeError);
        }

        const DATA_START: usize = 1;
        let data_start = self.current_offset + DATA_START;
        let data_end = data_start + usize::from(len);

        // Verify we have enough data
        if data_end > self.original_buffer.len() {
            log::error!(
                "{} does not have enough data for length {len}",
                self.current_path()
            );
            self.end_field();
            return Err(AlertDescription::DecodeError);
        }

        // Push the expected end position to the stack
        self.vec_end_stack.push(data_end);

        // Advance past the length byte to the start of data
        self.current_offset = data_start;

        Ok(())
    }

    pub fn end_vec(&mut self) -> Result<(), AlertDescription> {
        let expected_end = self
            .vec_end_stack
            .pop()
            .expect("end_vec called without matching begin_vec");

        if self.current_offset != expected_end {
            let trailing = expected_end.saturating_sub(self.current_offset);
            log::error!(
                "{} has {} bytes of trailing data",
                self.current_path(),
                trailing
            );
            self.end_field();
            return Err(AlertDescription::DecodeError);
        }

        self.end_field();
        Ok(())
    }

    /// Skip remaining bytes in the current vec context
    /// Useful when ignoring an extension but still needing to consume its bytes
    pub fn skip_remaining(&mut self) {
        if let Some(&end) = self.vec_end_stack.last() {
            self.current_offset = end;
        }
    }

    pub fn vec8(
        &mut self,
        name: &str,
        type_name: &str,
        min: u8,
        multiple: u8,
    ) -> Result<Vec<u8>, AlertDescription> {
        self.begin_vec8(name, type_name, min, multiple)?;

        // Copy the remaining data in this vector
        let start = self.current_offset;
        let end = self
            .vec_end_stack
            .last()
            .copied()
            .unwrap_or(self.original_buffer.len());
        let data = self.original_buffer.get(start..end).unwrap_or(&[]).to_vec();

        // Advance to the end of the vector
        self.current_offset = end;
        self.end_vec()?;

        Ok(data)
    }

    pub fn begin_vec16(
        &mut self,
        name: &str,
        type_name: &str,
        min: u16,
        multiple: u16,
    ) -> Result<(), AlertDescription> {
        self.begin_field(name, type_name);

        let len: u16 = self
            .original_buffer
            .get(self.current_offset..self.current_offset + 2)
            .and_then(|s| s.try_into().ok())
            .map(u16::from_be_bytes)
            .ok_or_else(|| {
                log::error!("{} length bytes are missing", self.current_path());
                AlertDescription::DecodeError
            })?;

        if len < min {
            log::error!(
                "{} length of {len} is less than minimum of {min}",
                self.current_path()
            );
            self.end_field();
            return Err(AlertDescription::DecodeError);
        }

        if !len.is_multiple_of(multiple) {
            log::error!(
                "{} length of {len} is not a multiple of {multiple}",
                self.current_path()
            );
            self.end_field();
            return Err(AlertDescription::DecodeError);
        }

        const DATA_START: usize = 2;
        let data_start = self.current_offset + DATA_START;
        let data_end = data_start + usize::from(len);

        // Verify we have enough data
        if data_end > self.original_buffer.len() {
            log::error!(
                "{} does not have enough data for length {len}",
                self.current_path()
            );
            self.end_field();
            return Err(AlertDescription::DecodeError);
        }

        // Push the expected end position to the stack
        self.vec_end_stack.push(data_end);

        // Advance past the length bytes to the start of data
        self.current_offset = data_start;

        Ok(())
    }

    pub fn vec16(
        &mut self,
        name: &str,
        type_name: &str,
        min: u16,
        multiple: u16,
    ) -> Result<Vec<u8>, AlertDescription> {
        self.begin_vec16(name, type_name, min, multiple)?;

        // Copy the remaining data in this vector
        let start = self.current_offset;
        let end = self
            .vec_end_stack
            .last()
            .copied()
            .unwrap_or(self.original_buffer.len());
        let data = self.original_buffer.get(start..end).unwrap_or(&[]).to_vec();

        // Advance to the end of the vector
        self.current_offset = end;
        self.end_vec()?;

        Ok(data)
    }

    pub fn begin_vec24(
        &mut self,
        name: &str,
        type_name: &str,
        min: u32,
        multiple: u32,
    ) -> Result<(), AlertDescription> {
        self.begin_field(name, type_name);

        let len: u32 = self
            .original_buffer
            .get(self.current_offset..self.current_offset + 3)
            .map(|s| {
                let be_bytes: [u8; 4] = [0, s[0], s[1], s[2]];
                u32::from_be_bytes(be_bytes)
            })
            .ok_or_else(|| {
                log::error!("{} length bytes are missing", self.current_path());
                AlertDescription::DecodeError
            })?;

        if len < min {
            log::error!(
                "{} length of {len} is less than minimum of {min}",
                self.current_path()
            );
            self.end_field();
            return Err(AlertDescription::DecodeError);
        }

        if !len.is_multiple_of(multiple) {
            log::error!(
                "{} length of {len} is not a multiple of {multiple}",
                self.current_path()
            );
            self.end_field();
            return Err(AlertDescription::DecodeError);
        }

        const DATA_START: usize = 3;
        let data_start = self.current_offset + DATA_START;
        let data_end = data_start + usize::try_from(len).expect("unsupported architecture");

        // Verify we have enough data
        if data_end > self.original_buffer.len() {
            log::error!(
                "{} does not have enough data for length {len}",
                self.current_path()
            );
            self.end_field();
            return Err(AlertDescription::DecodeError);
        }

        // Push the expected end position to the stack
        self.vec_end_stack.push(data_end);

        // Advance past the length bytes to the start of data
        self.current_offset = data_start;

        Ok(())
    }

    pub fn fixed<const N: usize>(
        &mut self,
        name: &str,
        type_name: &str,
    ) -> Result<[u8; N], AlertDescription> {
        self.begin_field(name, type_name);

        let val = self
            .original_buffer
            .get(self.current_offset..self.current_offset + N)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| {
                log::error!("{} is missing", self.current_path());
                AlertDescription::DecodeError
            })?;

        self.advance(N);
        self.end_field();
        Ok(val)
    }
}

impl DecodeContext {
    /// Number of bytes remaining in the current DER TLV content.
    /// When outside any `begin_tlv`/`end_tlv` pair, returns distance to the
    /// end of the underlying buffer.
    pub fn der_remaining(&self) -> usize {
        let end = self
            .der_end_stack
            .last()
            .copied()
            .unwrap_or(self.original_buffer.len());
        end.saturating_sub(self.current_offset)
    }

    /// Read the identifier octet at the current cursor position, advance by 1.
    /// Does **not** push onto the node stack.
    fn der_read_identifier(&mut self, name: &str) -> Option<Identifier> {
        let byte = self
            .original_buffer
            .get(self.current_offset)
            .copied()
            .or_else(|| {
                log::error!("{name} identifier byte is missing");
                None
            })?;
        self.current_offset += 1;
        Some(Identifier::from(byte))
    }

    /// Read DER length octets (short-form or long-form) at the current cursor,
    /// advance past them.  Returns the content length as `usize`.
    fn der_read_length(&mut self, name: &str) -> Option<usize> {
        let len_octet = self
            .original_buffer
            .get(self.current_offset)
            .copied()
            .or_else(|| {
                log::error!("{name} length octet is missing");
                None
            })?;
        self.current_offset += 1;

        if len_octet == 0xFF {
            // X.690 §8.1.3.5: "the value 11111111₂ shall not be used"
            log::error!("{name} uses forbidden DER length 0xFF");
            return None;
        }

        let long_form = len_octet & 0x80 == 0x80;
        let encoding_len_or_len_len = len_octet & 0x7F;

        if long_form {
            let len_len = usize::from(encoding_len_or_len_len);

            // Validate we have enough bytes for the length field itself
            let len_bytes = self
                .original_buffer
                .get(self.current_offset..self.current_offset + len_len)
                .or_else(|| {
                    log::error!("{name} long-form length bytes are missing");
                    None
                })?;

            // TLS limits certificates to 2²⁴ bytes; ensure high bytes are zero
            if let Some(high) = len_bytes.get(..len_bytes.len().saturating_sub(3))
                && high.iter().any(|&x| x != 0)
            {
                log::error!("{name} DER length exceeds maximum of 2²⁴");
                return None;
            }

            let mut len: u32 = 0;
            for (i, &byte) in len_bytes.iter().rev().enumerate() {
                len |= u32::from(byte) << i.saturating_mul(8);
            }
            self.current_offset += len_len;

            usize::try_from(len).ok().or_else(|| {
                log::error!("{name} DER length overflows usize");
                None
            })
        } else {
            Some(usize::from(encoding_len_or_len_len))
        }
    }

    /// Begin parsing a DER TLV structure.
    ///
    /// Reads the identifier byte and length octets, advances the cursor past
    /// them, and pushes the content-end position onto `der_end_stack`.  Also
    /// pushes a `FieldNode` onto the parse-tree stack (via `begin_field`).
    ///
    /// Returns the `Identifier` so the caller can inspect class / tag.
    /// Returns `None` and logs an error on any parse failure.
    pub fn begin_tlv(&mut self, name: &str, type_name: &str) -> Option<Identifier> {
        self.begin_field(name, type_name);

        let identifier = self.der_read_identifier(name)?;
        let content_len = self.der_read_length(name)?;

        let content_end = self.current_offset + content_len;
        if content_end > self.original_buffer.len() {
            log::error!("{name} DER TLV content length {content_len} exceeds buffer");
            self.end_field();
            return None;
        }

        self.der_end_stack.push(content_end);
        Some(identifier)
    }

    /// End parsing of the current DER TLV structure.
    ///
    /// Pops `der_end_stack`, verifies the cursor is exactly at the expected
    /// content-end (no unconsumed bytes), and calls `end_field()`.
    /// Returns `None` and logs an error on trailing data.
    pub fn end_tlv(&mut self) -> Option<()> {
        let expected_end = self
            .der_end_stack
            .pop()
            .expect("end_tlv called without matching begin_tlv");

        if self.current_offset != expected_end {
            let trailing = expected_end.saturating_sub(self.current_offset);
            log::error!(
                "{} DER TLV has {trailing} bytes of trailing data",
                self.current_path()
            );
            self.end_field();
            return None;
        }

        self.end_field();
        Some(())
    }

    /// Open a DER TLV and assert the identifier matches `expected`.
    /// Logs an error and returns `None` on mismatch.
    pub fn tlv_expected(
        &mut self,
        name: &str,
        type_name: &str,
        expected: Identifier,
    ) -> Option<Identifier> {
        let id = self.begin_tlv(name, type_name)?;
        if id != expected {
            log::error!("{name} expected DER identifier {expected:?} got {id:?}");
            // Pop the boundary we just pushed, close the field, return None
            self.der_end_stack.pop();
            self.end_field();
            return None;
        }
        Some(id)
    }

    /// Open a DER TLV and assert the identifier matches `id1` or `id2`.
    /// Logs an error and returns `None` on mismatch.
    pub fn tlv_expected2(
        &mut self,
        name: &str,
        type_name: &str,
        id1: Identifier,
        id2: Identifier,
    ) -> Option<Identifier> {
        let id = self.begin_tlv(name, type_name)?;
        if id != id1 && id != id2 {
            log::error!("{name} expected DER identifier {id1:?} or {id2:?} got {id:?}");
            self.der_end_stack.pop();
            self.end_field();
            return None;
        }
        Some(id)
    }

    /// Read a complete DER TLV and return its raw content bytes.
    /// The identifier is asserted to match `expected`.
    fn der_read_content(
        &mut self,
        name: &str,
        type_name: &str,
        expected: Identifier,
    ) -> Option<Vec<u8>> {
        self.tlv_expected(name, type_name, expected)?;
        let start = self.current_offset;
        let end = *self.der_end_stack.last().unwrap();
        let content = self.original_buffer.get(start..end).unwrap_or(&[]).to_vec();
        self.current_offset = end;
        self.end_tlv()?;
        Some(content)
    }

    /// Read a DER BOOLEAN TLV.  Returns the decoded `bool`.
    ///
    /// DER encoding: `0x00` = false, `0xFF` = true (any other value is an error).
    pub fn der_bool(&mut self, name: &str) -> Option<bool> {
        let content = self.der_read_content(name, "BOOLEAN", Identifier::BOOLEAN)?;
        match content.first() {
            Some(0x00) => Some(false),
            Some(0xFF) => Some(true),
            Some(val) => {
                log::error!(
                    "{name} DER BOOLEAN has invalid value 0x{val:02x}, expected 0x00 or 0xFF"
                );
                None
            }
            None => {
                log::error!("{name} DER BOOLEAN is missing value byte");
                None
            }
        }
    }

    /// Read a DER INTEGER TLV.  Returns raw content bytes (big-endian, with
    /// leading zeros/sign byte per DER rules).
    pub fn der_integer(&mut self, name: &str) -> Option<Vec<u8>> {
        self.der_read_content(name, "INTEGER", Identifier::INTEGER)
    }

    /// Read a DER OCTET STRING TLV.  Returns content bytes.
    pub fn der_octet_string(&mut self, name: &str) -> Option<Vec<u8>> {
        self.der_read_content(name, "OCTET STRING", Identifier::OCTETSTRING)
    }

    /// Read a DER BIT STRING TLV.  Returns all content bytes including the
    /// leading unused-bits byte.
    pub fn der_bit_string(&mut self, name: &str) -> Option<Vec<u8>> {
        self.der_read_content(name, "BIT STRING", Identifier::BITSTRING)
    }

    /// Read a DER OBJECT IDENTIFIER TLV.  Returns raw OID content bytes
    /// (before the first-byte `div/mod 40` decoding step).
    pub fn der_oid_raw(&mut self, name: &str) -> Option<Vec<u8>> {
        self.der_read_content(name, "OBJECT IDENTIFIER", Identifier::OBJECTIDENTIFIER)
    }

    /// Read a DER OBJECT IDENTIFIER **or** NULL TLV.
    ///
    /// Returns `Some(bytes)` for OID content, `None` for a well-formed NULL.
    /// Propagates parse errors as `None` from the returned `Option<Option<Vec<u8>>>`.
    pub fn der_oid_or_null(&mut self, name: &str) -> Option<Option<Vec<u8>>> {
        let id = self.tlv_expected2(
            name,
            "OID or NULL",
            Identifier::OBJECTIDENTIFIER,
            Identifier::NULL,
        )?;

        let start = self.current_offset;
        let end = *self.der_end_stack.last().unwrap();
        let content = self.original_buffer.get(start..end).unwrap_or(&[]).to_vec();
        self.current_offset = end;
        self.end_tlv()?;

        if id == Identifier::NULL {
            if !content.is_empty() {
                log::error!(
                    "{name} DER NULL has non-zero content length {}",
                    content.len()
                );
                return None;
            }
            Some(None)
        } else {
            Some(Some(content))
        }
    }

    /// Read a DER time TLV (UTCTime or GeneralizedTime).
    /// Returns a `jiff::Zoned` in UTC.
    pub fn der_time(&mut self, name: &str) -> Option<jiff::Zoned> {
        use jiff::{civil::DateTime, tz::TimeZone};

        let id = self.tlv_expected2(
            name,
            "UTCTime or GeneralizedTime",
            Identifier::GENERALIZEDTIME,
            Identifier::UTCTIME,
        )?;

        let start = self.current_offset;
        let end = *self.der_end_stack.last().unwrap();
        let content = self.original_buffer.get(start..end).unwrap_or(&[]).to_vec();
        self.current_offset = end;
        self.end_tlv()?;

        let timefmt: &str = if id == Identifier::GENERALIZEDTIME {
            "%Y%m%d%H%M%SZ"
        } else {
            "%y%m%d%H%M%SZ"
        };

        let content_str = String::from_utf8_lossy(&content);

        match DateTime::strptime(timefmt, &*content_str) {
            Ok(dt) => Some(dt.to_zoned(TimeZone::UTC).unwrap()),
            Err(e) => {
                log::error!(
                    "{name} DER time '{content_str}' is not valid (format {timefmt:?}): {e:?}"
                );
                None
            }
        }
    }
}
