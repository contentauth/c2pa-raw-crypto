# c2pa_raw_crypto

[![CI](https://github.com/contentauth/c2pa-raw-crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/contentauth/c2pa-raw-crypto/actions/workflows/ci.yml) [![Latest Version](https://img.shields.io/crates/v/c2pa-raw-crypto.svg)](https://crates.io/crates/c2pa-raw-crypto) [![docs.rs](https://img.shields.io/docsrs/c2pa_raw_crypto)](https://docs.rs/c2pa_raw_crypto/) [![codecov](https://codecov.io/gh/contentauth/c2pa-raw-crypto/branch/main/graph/badge.svg?token=z1yA0Y6HZK)](https://codecov.io/gh/contentauth/c2pa-raw-crypto)

Raw cryptographic signing and validation primitives for [C2PA](https://c2pa.org).

**IMPORTANT:** This crate is an implemementation detail for the [`c2pa`](https://crates.io/crates/c2pa) crate and not generally designed for independent use.

This crate provides the `RawSigner` and `RawSignatureValidator` traits together with built-in implementations of the digital signature algorithms required by the C2PA specification.
It deliberately stays narrow: it knows nothing about COSE framing, RFC 3161 time stamping, or OCSP — those concerns are handled by the calling code (today, the `c2pa` crate).

## Cryptography backend / Crate features

Crate capabilities are available via Cargo feature flags:

- **`rust_native_crypto`** (enabled by default) — pure-Rust crates.
- **`openssl`** — a vendored OpenSSL implementation. **Unsupported on all `wasm32` targets**, including browser Wasm and WASI; enabling it there is a compile-time error.
- **`serde`** (enabled by default) — `Serialize` and `Deserialize` support for `SigningAlg`.

Disable default features and enable only what you need to omit serde, for
example `--no-default-features --features rust_native_crypto`.

**On non-`wasm32` targets, `rust_native_crypto` takes precedence.** If both features end up enabled (which can happen through Cargo feature unification in a workspace), the rust-native backend is selected at runtime and the OpenSSL backend, while compiled, is not used.
This is not considered an error.

**On `wasm32`, `openssl` is prohibited even when `rust_native_crypto` is also enabled.**
OpenSSL relies on C-language facilities unavailable on these targets. It is not
silently ignored: `--all-features` is therefore also unsupported on `wasm32`.
Use default features or `--no-default-features --features rust_native_crypto`,
and ensure no dependency enables this crate's `openssl` feature through Cargo
feature unification.

| Feature selection | Non-`wasm32` platforms | Browser Wasm / WASI |
| --- | --- | --- |
| Default features | Rust-native backend | Rust-native backend |
| `--no-default-features` | No built-in backend | No built-in backend |
| `--no-default-features --features rust_native_crypto` | Rust-native backend | Rust-native backend |
| `--no-default-features --features openssl` | OpenSSL backend | Compile-time error |
| `--all-features` | Rust-native backend (OpenSSL also compiled) | Compile-time error |

Enabling neither is allowed (e.g. when only the type definitions are needed, or when signing is delegated to a remote service and no validation is performed); in that case the built-in signer/validator constructors report an error / return `None` at runtime.

### RustCrypto dependency compatibility

ECDSA uses the stable `ecdsa` 0.17 / `p256`, `p384`, and `p521` 0.14
family together: `signature` 3, `elliptic-curve` 0.14, `digest` / `sha2`
0.11, and PKCS#8 0.11 / SPKI 0.8. Import key-decoding and signature traits
from that family, not from the older RSA dependencies. This replaces the
standalone `ecdsa` update proposed in [#26](https://github.com/contentauth/c2pa-raw-crypto/pull/26):
`ecdsa` 0.17 traits and signature types cannot be used with the 0.13 curves.
Dependabot groups ECDSA and the three curves so updates can be reviewed together.

Ed25519 uses `ed25519-dalek` 3 with `signature` 3, `digest` / `sha2` 0.11,
and PKCS#8 0.11 / SPKI 0.8, matching the newer ECDSA dependency family.

RSA remains on stable `rsa` 0.9, `pkcs1` 0.7, and `rand` 0.8; RSA 0.10 is
still prerelease. RSA uses `signature` 2, `digest` / `sha2` 0.10, and
PKCS#8 0.10 / SPKI 0.7. The shared byte-oriented
key parsers also retain PKCS#8 0.10 / SPKI 0.7. These generations coexist
intentionally, with bounded duplicate exceptions in `deny.toml`; no
prereleases or unrelated dependency majors are needed for the ECDSA migration.

The public APIs and key/signature formats are unchanged: PEM PKCS#8 private
keys, DER SPKI public keys, fixed-width P1363 signing output (64, 96, and 132
bytes), and DER or P1363 verification input. Both low-S and high-S NIST
signatures remain accepted. P-521 now uses the same zeroize-on-drop signing
key and direct key decoding as the other curves, without an intermediate
private-key byte copy. Its upstream implementation now uses deterministic
RFC6979 signing, as P-256 and P-384 already did; callers must not rely on
fresh randomness making repeated ECDSA signatures distinct.

The ECDSA/curve releases and PKCS#8 0.11 / SPKI 0.8 / `getrandom` 0.4
declare Rust 1.85. The resolved `crypto-bigint` 0.7.6 and `sha2` 0.11.1
require Rust 1.87 and 1.88 respectively, also below this crate's unchanged
Rust 1.96.0 requirement.
Browser Wasm enables `getrandom` 0.4's `wasm_js` feature alongside
`getrandom` 0.2's `js` feature for RSA; this needs no custom `RUSTFLAGS`.
These JavaScript features are scoped to `wasm32-unknown-unknown`, not WASI.
WASI continues to use system randomness, and the supported targets and
backend precedence are unchanged.

Upstream migration references:
[ECDSA 0.17 changelog](https://github.com/RustCrypto/signatures/blob/ecdsa/v0.17.0/ecdsa/CHANGELOG.md),
[P-521 0.14 changelog](https://github.com/RustCrypto/elliptic-curves/blob/p521/v0.14.0/p521/CHANGELOG.md),
and [getrandom 0.4 target support](https://github.com/rust-random/getrandom/blob/v0.4.3/README.md).

## Contributions and feedback

We welcome contributions to this project. For information on contributing, providing feedback, and about ongoing work, see [Contributing](./CONTRIBUTING.md).

## Requirements

The toolkit requires **Rust version 1.96.0** or newer. When a newer version of Rust becomes required, a new minor version of this crate will be released.

### Supported platforms

This crate's [CI workflow](./.github/workflows/ci.yml) builds and tests against the platforms that the [`c2pa-rs` support tiers](https://github.com/contentauth/c2pa-rs/blob/main/docs/support-tiers.md) cover (Tiers 1A, 1B, and 2). Unlike `c2pa-rs`, this crate does not split those platforms across separate tier workflows — because it evolves more slowly, every platform below is exercised on every commit.

The crate is built and tested on the following platforms:

* Windows (`x86_64-pc-windows-msvc` and `aarch64-pc-windows-msvc`)
  * Only the MSVC build chain is supported on Windows. As discussed in [#155](https://github.com/adobe/xmp-toolkit-rs/issues/155), we would welcome a PR to enable GNU build chain support on Windows.

* macOS on Apple silicon (`aarch64-apple-darwin`)

* Linux on x86 (`x86_64-unknown-linux-gnu`) and ARM v8 (`aarch64-unknown-linux-gnu`)

* Wasm in the browser (`wasm32-unknown-unknown`)

* WASI (`wasm32-wasip2`)

The crate is also verified on the following platforms. CI runs the full test suite on the iOS simulator and confirms that the remaining targets build, but does not run tests on physical devices:

* iOS (tested on the `aarch64-apple-ios-sim` simulator; `aarch64-apple-ios` and `x86_64-apple-ios` are build-verified)

* Android (`aarch64-linux-android`, `armv7-linux-androideabi`, `i686-linux-android`, and `x86_64-linux-android` are build-verified)

## License

The `c2pa_raw_crypto` crate is distributed under the terms of both the MIT license and the Apache License (Version 2.0).

See [LICENSE-APACHE](./LICENSE-APACHE) and [LICENSE-MIT](./LICENSE-MIT).

Note that some components and dependent crates are licensed under different terms; please check the license terms for each crate and component for details.
