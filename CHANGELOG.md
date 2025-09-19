# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added a client implementation.
- Added all recommended key exchange algorithms: `X25519`.

### Changed

- Renamed `TlsStreamBuilder` to `TlsServerBuilder`.
- Renamed `TlsStream` to `TlsServerStream`.
- Renamed `ServerError` to `TlsError`.
- Changed many types to private.

## [0.1.0] - 2025-06-01

- Initial release.

[Unreleased]: https://github.com/newAM/tls-tester/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/newAM/tls-tester/releases/tag/v0.1.0
