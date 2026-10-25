# Fuzzing

The fuzz package is intentionally separate from the library's normal build.
Install [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz), then run a
target from the repository root:

```sh
cargo +nightly fuzz run ec_der
cargo +nightly fuzz run private_key
cargo +nightly fuzz run signature_validation
```

`ec_der` exercises the public ECDSA DER and EC key-inspection APIs.
`private_key` exercises private-key parsing through the public signer
constructor with each supported signing algorithm. `signature_validation` accepts inputs encoded as an algorithm byte, little-endian
`u16` signature and content lengths, one-byte signature-OID and hash-OID
lengths, then both OIDs, the signature, content, and remaining public-key bytes.
The `corpus/` directories contain sample inputs from the repository's signature
fixtures.

GitHub Actions runs 100-iteration smoke tests for every target and both backends
on pull requests. A weekly campaign runs each target/backend combination for
five minutes and uploads crash artifacts for 14 days. The same campaign can be
started manually from the Actions tab.

The default fuzz build selects the Rust-native backend. To fuzz OpenSSL
instead, disable the default feature and select the OpenSSL backend:

```sh
cargo +nightly fuzz run signature_validation --no-default-features --features openssl
```

Do not enable both backends for an OpenSSL run: the crate selects the
Rust-native backend when both are enabled.
