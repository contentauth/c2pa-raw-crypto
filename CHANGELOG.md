# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.2](https://github.com/contentauth/c2pa-raw-crypto/compare/v0.2.1...v0.2.2)
_25 October 2026_

### Added

* Add fuzz targets for public APIs ([#46](https://github.com/contentauth/c2pa-raw-crypto/pull/46))
* Make `serde` optional ([#43](https://github.com/contentauth/c2pa-raw-crypto/pull/43))

### Fixed

* Explicitly reject OpenSSL on wasm32 targets ([#57](https://github.com/contentauth/c2pa-raw-crypto/pull/57))

## [0.2.1](https://github.com/contentauth/c2pa-raw-crypto/compare/v0.2.0...v0.2.1)
_24 October 2026_

### Other

* Update rasn requirement from 0.28.2 to 0.29.0 ([#39](https://github.com/contentauth/c2pa-raw-crypto/pull/39))
* Update ed25519-dalek requirement from 2.1.1 to 3.0.0 ([#29](https://github.com/contentauth/c2pa-raw-crypto/pull/29))

## [0.2.0](https://github.com/contentauth/c2pa-raw-crypto/compare/v0.1.2...v0.2.0)
_24 October 2026_

### Added

* Migrate RustCrypto ECDSA dependencies ([#38](https://github.com/contentauth/c2pa-raw-crypto/pull/38))
* Raise MSRV to Rust 1.96.0 and modernize CI ([#35](https://github.com/contentauth/c2pa-raw-crypto/pull/35))

## [0.1.2](https://github.com/contentauth/c2pa-raw-crypto/compare/v0.1.1...v0.1.2)
_20 June 2026_

### Added

* Update sha2 dependency to 0.11.0 ([#23](https://github.com/contentauth/c2pa-raw-crypto/pull/23))

## [0.1.1](https://github.com/contentauth/c2pa-raw-crypto/compare/v0.1.0...v0.1.1)
_08 June 2026_

### Added

* Implement `ZeroizeOnDrop` for private key data ([#16](https://github.com/contentauth/c2pa-raw-crypto/pull/16))

### Fixed

* Drop direct `const-oid` dependency to avoid version conflict ([#17](https://github.com/contentauth/c2pa-raw-crypto/pull/17))

## [0.1.0](https://github.com/contentauth/c2pa-raw-crypto/releases/tag/v0.1.0)
_04 June 2026_

### New

* Split this crate out from c2pa-rs
* Verify all c2pa-rs support-tier platforms ([#14](https://github.com/contentauth/c2pa-raw-crypto/pull/14))
