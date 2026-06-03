# c2pa_raw_crypto

Raw cryptographic signing and validation primitives for [C2PA](https://c2pa.org).

**IMPORTANT:** This crate is an implemementation detail for the [`c2pa`](https://crates.io/crates/c2pa) crate and not generally designed for independent use.

This crate provides the `RawSigner` and `RawSignatureValidator` traits together with built-in implementations of the digital signature algorithms required by the C2PA specification.
It deliberately stays narrow: it knows nothing about COSE framing, RFC 3161 time stamping, or OCSP — those concerns are handled by the calling code (today, the `c2pa` crate).

## Cryptography backend / Crate features

Two cryptography backends are available via Cargo feature flags:

- **`rust_native_crypto`** (enabled by default) — pure-Rust crates.
- **`openssl`** — a vendored OpenSSL implementation.

**`rust_native_crypto` takes precedence.** If both features end up enabled (which can happen through Cargo feature unification in a workspace), the rust-native backend is selected at runtime and the OpenSSL backend, while compiled, is not used.
This is not considered an error.

Enabling neither is allowed (e.g. when only the type definitions are needed, or when signing is delegated to a remote service and no validation is performed); in that case the built-in signer/validator constructors report an error / return `None` at runtime.

## Contributions and feedback

We welcome contributions to this project. For information on contributing, providing feedback, and about ongoing work, see [Contributing](./CONTRIBUTING.md).

## Requirements

The toolkit requires **Rust version 1.88.0** or newer. When a newer version of Rust becomes required, a new minor (1.x.0) version of this crate will be released.

### Supported platforms

The toolkit has been tested on the following operating systems:

* Windows
  * Only the MSVC build chain is supported on Windows. As discussed in [#155](https://github.com/adobe/xmp-toolkit-rs/issues/155), we would welcome a PR to enable GNU build chain support on Windows.

* MacOS (Intel and Apple silicon)

* Ubuntu Linux on x86 and ARM v8 (aarch64)

* iOS

## License

The `c2pa_raw_crypto` crate is distributed under the terms of both the MIT license and the Apache License (Version 2.0).

See [LICENSE-APACHE](./LICENSE-APACHE) and [LICENSE-MIT](./LICENSE-MIT).

Note that some components and dependent crates are licensed under different terms; please check the license terms for each crate and component for details.
