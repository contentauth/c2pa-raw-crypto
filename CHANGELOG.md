# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Changed

* Update ECDSA coherently to `ecdsa` 0.17 and the three NIST curve crates 0.14,
  superseding the incompatible standalone bump in [#26](https://github.com/contentauth/c2pa-raw-crypto/pull/26).
  Preserve Rust 1.96.0 and supported targets, including browser Wasm and WASI.
* Use direct PKCS#8/SPKI decoding and zeroize-on-drop keys for P-521.
  P-521 signing now uses upstream RFC6979, like P-256 and P-384.

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
