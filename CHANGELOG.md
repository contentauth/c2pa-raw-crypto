# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0](https://github.com/contentauth/c2pa-raw-crypto/releases/tag/v0.1.0)
_04 June 2026_

### Fixed

* Improve code coverage ([#11](https://github.com/contentauth/c2pa-raw-crypto/pull/11))
* Remove `RawSignerError::IoError` (not actually used)

### Other

* Verify all c2pa-rs support-tier platforms ([#14](https://github.com/contentauth/c2pa-raw-crypto/pull/14))
* Improve code coverage for signers, validators, and error paths ([#12](https://github.com/contentauth/c2pa-raw-crypto/pull/12))
* Use repo-specific token for release-lz
* Split this crate out from c2pa-rs
