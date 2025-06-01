# TLS tester

A rust crate for testing [TLS 1.3] client implementations.

> [!WARNING]  
> This is in a pre-alpha state, the crate is missing:
> - Documentation
> - Unit tests

## Goals

- Hackability
- Debugability
- Testing TLS client implementation compliance

## Non-goals

- Performance
- Security
- Versions of TLS older than [TLS 1.3]
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
- PSK does not support `psk_ke`, only `psk_dhe_ke` is supported

## Available tests

- Server record fragmentation

### Planned tests

- Forced HelloRetry
- Invalid GCM tag
- Missing handshake messages, such as CertificateVerify
- Non-zero padding extension
- Record fragmentation across key changes
- Record overflow
- Sending application data before handshake is done
- Sending duplicate handshake message types
- Sending handshake messages out of order
- Zero length alert/handshake/applicationdata

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

[TLS 1.3]: https://datatracker.ietf.org/doc/html/rfc8446
