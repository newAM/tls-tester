# TLS tester

A tool for testing [TLS 1.3] implementation compliance.

> [!WARNING]  
> This is in a pre-alpha state, the crate is missing:
>
> - Documentation
> - Unit tests

## Goals

- Hackability
- Debugability
- Testing TLS implementation compliance

## Non-goals

- Performance
- Security
- Versions of TLS older than [TLS 1.3]
- `#![no_std]` support
- Strict TLS compliance
  - TLS tester needs to create non-compliant behaviour to test compliance, for all other purposes TLS tester should be compliant unless otherwise noted

## Limitations

- [Compliance](https://datatracker.ietf.org/doc/html/rfc8446#section-9) limitations
  - Does not implement all required digital signature algorithms, missing:
    - `rsa_pkcs1_sha256`
    - `rsa_pss_rsae_sha256`
  - Does not implement all recommended cipher suites, missing:
    - `TLS_AES_256_GCM_SHA384`
    - `TLS_CHACHA20_POLY1305_SHA256`
  - Does not implement all recommended key exchange algorithms, missing:
    - `X25519`
  - Client does not validate server certificates against a trust anchor
- PSK does not support `psk_ke`, only `psk_dhe_ke` is supported

## Available tests

- Server record fragmentation

### Planned tests

- Forced HelloRetry
- Invalid GCM tag
- Missing handshake messages, such as CertificateVerify
- Packing server Encrypted Extensions, Certificate, CertificateVerify, and Finished into a single record
- Non-zero padding extension
- Record fragmentation across key changes
- Record overflow
- Sending application data before handshake is done
- Sending duplicate handshake message types
- Sending handshake messages out of order
- Zero length alert/handshake/applicationdata
- Zero padding appended to records
- Certificates with GeneralizedTime and UTCTime types for notBefore and notAfter
  - UTCTime before 2050
  - GeneralizedTime after 2050
- Sending unrecognized values for:
  - cipher suites
  - hello extensions
  - named groups
  - key shared
  - supported versions
  - signature algorithms

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

[TLS 1.3]: https://datatracker.ietf.org/doc/html/rfc8446
