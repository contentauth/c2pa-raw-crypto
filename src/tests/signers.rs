// Copyright 2024 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

#[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
use wasm_bindgen_test::wasm_bindgen_test;

use crate::{
    RawSigner, RawSignerError, SigningAlg, signer_from_private_key, validator_for_signing_alg,
};

/// Unwraps the signer when a crypto backend is compiled in.
///
/// When neither the `rust_native_crypto` nor the `openssl` feature is enabled,
/// no backend is available: asserts that the expected `NoCryptoBackend` error
/// was returned and yields `None` so the test can stop early.
fn check_signer(
    result: Result<Box<dyn RawSigner + Send + Sync>, RawSignerError>,
) -> Option<Box<dyn RawSigner + Send + Sync>> {
    #[cfg(any(feature = "rust_native_crypto", feature = "openssl"))]
    {
        Some(result.unwrap())
    }

    #[cfg(not(any(feature = "rust_native_crypto", feature = "openssl")))]
    {
        assert!(matches!(result, Err(RawSignerError::NoCryptoBackend)));
        None
    }
}

#[test]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
fn es256() {
    let private_key = include_bytes!("../../tests/fixtures/raw_signature/es256.priv");

    let Some(signer) = check_signer(signer_from_private_key(private_key, SigningAlg::Es256)) else {
        return;
    };

    assert_eq!(signer.alg(), SigningAlg::Es256);

    let data = b"some sample content to sign";
    let signature = signer.sign(data).unwrap();

    println!("signature len = {}", signature.len());
    assert_eq!(signature.len(), 64);
    assert_eq!(signer.max_signature_size(), 64);

    let pub_key = include_bytes!("../../tests/fixtures/raw_signature/es256.pub_key");

    let validator = validator_for_signing_alg(SigningAlg::Es256).unwrap();
    validator.validate(&signature, data, pub_key).unwrap();
}

#[test]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
fn es384() {
    let private_key = include_bytes!("../../tests/fixtures/raw_signature/es384.priv");

    let Some(signer) = check_signer(signer_from_private_key(private_key, SigningAlg::Es384)) else {
        return;
    };

    assert_eq!(signer.alg(), SigningAlg::Es384);

    let data = b"some sample content to sign";
    let signature = signer.sign(data).unwrap();

    println!("signature len = {}", signature.len());
    assert_eq!(signature.len(), 96);
    assert_eq!(signer.max_signature_size(), 96);

    let pub_key = include_bytes!("../../tests/fixtures/raw_signature/es384.pub_key");

    let validator = validator_for_signing_alg(SigningAlg::Es384).unwrap();
    validator.validate(&signature, data, pub_key).unwrap();
}

#[test]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
fn es512() {
    let private_key = include_bytes!("../../tests/fixtures/raw_signature/es512.priv");

    let Some(signer) = check_signer(signer_from_private_key(private_key, SigningAlg::Es512)) else {
        return;
    };

    assert_eq!(signer.alg(), SigningAlg::Es512);

    let data = b"some sample content to sign";
    let signature = signer.sign(data).unwrap();

    println!("signature len = {}", signature.len());
    assert_eq!(signature.len(), 132);
    assert_eq!(signer.max_signature_size(), 132);

    let pub_key = include_bytes!("../../tests/fixtures/raw_signature/es512.pub_key");

    let validator = validator_for_signing_alg(SigningAlg::Es512).unwrap();
    validator.validate(&signature, data, pub_key).unwrap();
}

#[test]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
fn ed25519() {
    let private_key = include_bytes!("../../tests/fixtures/raw_signature/ed25519.priv");

    let Some(signer) = check_signer(signer_from_private_key(private_key, SigningAlg::Ed25519))
    else {
        return;
    };

    assert_eq!(signer.alg(), SigningAlg::Ed25519);

    let data = b"some sample content to sign";
    let signature = signer.sign(data).unwrap();

    println!("signature len = {}", signature.len());
    assert!(signature.len() <= signer.max_signature_size());

    let pub_key = include_bytes!("../../tests/fixtures/raw_signature/ed25519.pub_key");

    let validator = validator_for_signing_alg(SigningAlg::Ed25519).unwrap();
    validator.validate(&signature, data, pub_key).unwrap();
}

#[test]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
fn ps256() {
    let private_key = include_bytes!("../../tests/fixtures/raw_signature/ps256.priv");

    let Some(signer) = check_signer(signer_from_private_key(private_key, SigningAlg::Ps256)) else {
        return;
    };

    assert_eq!(signer.alg(), SigningAlg::Ps256);

    let data = b"some sample content to sign";
    let signature = signer.sign(data).unwrap();

    println!("signature len = {}", signature.len());
    assert!(signature.len() <= signer.max_signature_size());

    let pub_key = include_bytes!("../../tests/fixtures/raw_signature/ps256.pub_key");

    let validator = validator_for_signing_alg(SigningAlg::Ps256).unwrap();
    validator.validate(&signature, data, pub_key).unwrap();
}

#[test]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
fn ps384() {
    let private_key = include_bytes!("../../tests/fixtures/raw_signature/ps384.priv");

    let Some(signer) = check_signer(signer_from_private_key(private_key, SigningAlg::Ps384)) else {
        return;
    };

    assert_eq!(signer.alg(), SigningAlg::Ps384);

    let data = b"some sample content to sign";
    let signature = signer.sign(data).unwrap();

    println!("signature len = {}", signature.len());
    assert!(signature.len() <= signer.max_signature_size());

    let pub_key = include_bytes!("../../tests/fixtures/raw_signature/ps384.pub_key");

    let validator = validator_for_signing_alg(SigningAlg::Ps384).unwrap();
    validator.validate(&signature, data, pub_key).unwrap();
}

#[test]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
fn ps512() {
    let private_key = include_bytes!("../../tests/fixtures/raw_signature/ps512.priv");

    let Some(signer) = check_signer(signer_from_private_key(private_key, SigningAlg::Ps512)) else {
        return;
    };

    assert_eq!(signer.alg(), SigningAlg::Ps512);

    let data = b"some sample content to sign";
    let signature = signer.sign(data).unwrap();

    println!("signature len = {}", signature.len());
    assert!(signature.len() <= signer.max_signature_size());

    let pub_key = include_bytes!("../../tests/fixtures/raw_signature/ps512.pub_key");

    let validator = validator_for_signing_alg(SigningAlg::Ps512).unwrap();
    validator.validate(&signature, data, pub_key).unwrap();
}

#[cfg(feature = "rust_native_crypto")]
const ECDSA_CASES: [(SigningAlg, &[u8], &[u8], usize); 3] = [
    (
        SigningAlg::Es256,
        include_bytes!("../../tests/fixtures/raw_signature/es256.priv"),
        include_bytes!("../../tests/fixtures/raw_signature/es256.pub_key"),
        64,
    ),
    (
        SigningAlg::Es384,
        include_bytes!("../../tests/fixtures/raw_signature/es384.priv"),
        include_bytes!("../../tests/fixtures/raw_signature/es384.pub_key"),
        96,
    ),
    (
        SigningAlg::Es512,
        include_bytes!("../../tests/fixtures/raw_signature/es512.priv"),
        include_bytes!("../../tests/fixtures/raw_signature/es512.pub_key"),
        132,
    ),
];

#[cfg(feature = "rust_native_crypto")]
fn ecdsa_der(alg: SigningAlg, signature: &[u8]) -> Vec<u8> {
    match alg {
        SigningAlg::Es256 => p256::ecdsa::Signature::from_slice(signature)
            .unwrap()
            .to_der()
            .as_bytes()
            .to_vec(),
        SigningAlg::Es384 => p384::ecdsa::Signature::from_slice(signature)
            .unwrap()
            .to_der()
            .as_bytes()
            .to_vec(),
        SigningAlg::Es512 => p521::ecdsa::Signature::from_slice(signature)
            .unwrap()
            .to_der()
            .as_bytes()
            .to_vec(),
        _ => unreachable!(),
    }
}

#[cfg(feature = "rust_native_crypto")]
fn ecdsa_opposite_s(alg: SigningAlg, signature: &[u8]) -> Vec<u8> {
    macro_rules! opposite_s {
        ($signature:ty) => {{
            let signature = <$signature>::from_slice(signature).unwrap();
            let (r, s) = signature.split_scalars();
            <$signature>::from_scalars(r.to_bytes(), (-s).to_bytes())
                .unwrap()
                .to_vec()
        }};
    }
    match alg {
        SigningAlg::Es256 => opposite_s!(p256::ecdsa::Signature),
        SigningAlg::Es384 => opposite_s!(p384::ecdsa::Signature),
        SigningAlg::Es512 => opposite_s!(p521::ecdsa::Signature),
        _ => unreachable!(),
    }
}

#[test]
#[cfg(feature = "rust_native_crypto")]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
fn ecdsa_formats_and_errors() {
    use crate::{RawSignatureValidationError, ec_utils::der_to_p1363};

    for (alg, private_key, public_key, size) in ECDSA_CASES {
        let signer = signer_from_private_key(private_key, alg).unwrap();
        let validator = validator_for_signing_alg(alg).unwrap();
        for data in [b"".as_slice(), b"sample", b"some sample content to sign"] {
            let signature = signer.sign(data).unwrap();
            assert_eq!(signature.len(), size);
            assert_eq!(signer.max_signature_size(), size);
            validator.validate(&signature, data, public_key).unwrap();

            let der = ecdsa_der(alg, &signature);
            assert_eq!(der_to_p1363(&der, size).unwrap(), signature);
            validator.validate(&der, data, public_key).unwrap();
            // C2PA NIST signatures accept both low-S and high-S encodings.
            let opposite_s = ecdsa_opposite_s(alg, &signature);
            assert_ne!(opposite_s, signature);
            validator.validate(&opposite_s, data, public_key).unwrap();
            validator
                .validate(&ecdsa_der(alg, &opposite_s), data, public_key)
                .unwrap();
            assert_eq!(
                validator.validate(&der, b"wrong message", public_key),
                Err(RawSignatureValidationError::SignatureMismatch)
            );

            let mut oversized = signature.clone();
            oversized.push(0);
            for malformed in [
                &signature[..size - 1],
                oversized.as_slice(),
                vec![0; size].as_slice(),
                &[0x30, 0x03, 0x02, 0x01, 0x01],
            ] {
                assert_eq!(
                    validator.validate(malformed, data, public_key),
                    Err(RawSignatureValidationError::InvalidSignature)
                );
            }
            assert_eq!(
                validator.validate(&signature, data, b"not a public key"),
                Err(RawSignatureValidationError::InvalidPublicKey)
            );
        }

        for (other_alg, other_private_key, _, _) in ECDSA_CASES {
            if other_alg != alg {
                assert!(matches!(
                    signer_from_private_key(other_private_key, alg),
                    Err(RawSignerError::InvalidSigningCredentials(_))
                ));
            }
        }
    }
}

#[test]
#[cfg(all(
    feature = "rust_native_crypto",
    feature = "openssl",
    not(target_arch = "wasm32")
))]
fn ecdsa_cross_backend_and_native_precedence() {
    use crate::{RawSignatureValidationError, openssl, rust_native};

    let data = b"cross-backend ECDSA interoperability";
    for (alg, private_key, public_key, size) in ECDSA_CASES {
        let native_signer =
            rust_native::signers::signer_from_private_key(private_key, alg).unwrap();
        let openssl_signer = openssl::signers::signer_from_private_key(private_key, alg).unwrap();
        let native_validator = rust_native::validators::validator_for_signing_alg(alg).unwrap();
        let openssl_validator = openssl::validators::validator_for_signing_alg(alg).unwrap();

        for signer in [&native_signer, &openssl_signer] {
            let signature = signer.sign(data).unwrap();
            assert_eq!(signature.len(), size);
            let der = ecdsa_der(alg, &signature);
            for validator in [&native_validator, &openssl_validator] {
                validator.validate(&signature, data, public_key).unwrap();
                validator.validate(&der, data, public_key).unwrap();
                assert_eq!(
                    validator.validate(&signature, b"wrong message", public_key),
                    Err(RawSignatureValidationError::SignatureMismatch)
                );
            }
        }

        // Rust-native signing is deterministic; OpenSSL signing is randomized.
        let selected = signer_from_private_key(private_key, alg).unwrap();
        assert_eq!(
            selected.sign(data).unwrap(),
            native_signer.sign(data).unwrap()
        );
        let selected_validator = validator_for_signing_alg(alg).unwrap();
        assert_eq!(
            selected_validator.validate(&[], data, public_key),
            Err(RawSignatureValidationError::InvalidSignature)
        );
    }
}
