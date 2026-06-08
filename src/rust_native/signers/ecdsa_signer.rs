// Copyright 2025 Adobe. All rights reserved.
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

use ecdsa::signature::Signer;
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use p384::ecdsa::{Signature as P384Signature, SigningKey as P384SigningKey};
use p521::ecdsa::{Signature as P512Signature, SigningKey as P512SigningKey};
use pkcs8::DecodePrivateKey;
use zeroize::ZeroizeOnDrop;

use crate::{RawSigner, RawSignerError, SigningAlg};

enum EcdsaSigningAlg {
    Es256,
    Es384,
    Es512,
}

/// Holds the ECDSA private key. Each variant wraps a curve-specific
/// `SigningKey`, all of which are zeroized when this value is dropped.
#[derive(ZeroizeOnDrop)]
pub(crate) enum EcdsaSigningKey {
    Es256(P256SigningKey),
    Es384(P384SigningKey),
    // The `p521` crate wraps the inner `ecdsa` signing key in a newtype that
    // does not re-expose `ZeroizeOnDrop`, so it must be skipped here. The
    // secret is still scrubbed: the inner `ecdsa::SigningKey` zeroizes its
    // secret scalar in its own `Drop` impl when this value is dropped.
    Es512(#[zeroize(skip)] P512SigningKey),
}

/// Implements [`RawSigner`] trait using the `p256`/`p384`/`p521` crates'
/// implementations of ECDSA.
///
/// The private key material is held in an [`EcdsaSigningKey`], which is
/// zeroized when this signer is dropped.
#[derive(ZeroizeOnDrop)]
pub(crate) struct EcdsaSigner {
    // `alg` carries no secret material, so it is skipped when zeroizing.
    #[zeroize(skip)]
    alg: EcdsaSigningAlg,
    signing_key: EcdsaSigningKey,
}

impl EcdsaSigner {
    pub(crate) fn from_private_key(
        private_key: &[u8],
        algorithm: SigningAlg,
    ) -> Result<Self, RawSignerError> {
        let private_key_pem = std::str::from_utf8(private_key).map_err(|e| {
            RawSignerError::InvalidSigningCredentials(format!("invalid private key: {e}"))
        })?;

        let (signing_key, alg) = match algorithm {
            SigningAlg::Es256 => {
                let key = P256SigningKey::from_pkcs8_pem(private_key_pem).map_err(|e| {
                    RawSignerError::InvalidSigningCredentials(format!(
                        "invalid ES256 private key: {e}"
                    ))
                })?;
                (EcdsaSigningKey::Es256(key), EcdsaSigningAlg::Es256)
            }

            SigningAlg::Es384 => {
                let key = P384SigningKey::from_pkcs8_pem(private_key_pem).map_err(|e| {
                    RawSignerError::InvalidSigningCredentials(format!(
                        "invalid ES384 private key: {e}"
                    ))
                })?;
                (EcdsaSigningKey::Es384(key), EcdsaSigningAlg::Es384)
            }

            SigningAlg::Es512 => {
                let secret = p521::SecretKey::from_pkcs8_pem(private_key_pem).map_err(|e| {
                    RawSignerError::InvalidSigningCredentials(format!(
                        "invalid ES512 private key: {e}"
                    ))
                })?;
                let key = P512SigningKey::from_slice(&secret.to_bytes()).map_err(|e| {
                    RawSignerError::InvalidSigningCredentials(format!(
                        "invalid ES512 private key: {e}"
                    ))
                })?;
                (EcdsaSigningKey::Es512(key), EcdsaSigningAlg::Es512)
            }

            _ => {
                return Err(RawSignerError::InvalidSigningCredentials(
                    "Unsupported algorithm".to_string(),
                ));
            }
        };

        Ok(EcdsaSigner { alg, signing_key })
    }
}

impl RawSigner for EcdsaSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, RawSignerError> {
        match self.signing_key {
            EcdsaSigningKey::Es256(ref key) => {
                let signature: P256Signature = key.sign(data);
                Ok(signature.to_vec())
            }

            EcdsaSigningKey::Es384(ref key) => {
                let signature: P384Signature = key.sign(data);
                Ok(signature.to_vec())
            }

            EcdsaSigningKey::Es512(ref key) => {
                let signature: P512Signature = key.sign(data);
                Ok(signature.to_vec())
            }
        }
    }

    fn alg(&self) -> SigningAlg {
        match self.alg {
            EcdsaSigningAlg::Es256 => SigningAlg::Es256,
            EcdsaSigningAlg::Es384 => SigningAlg::Es384,
            EcdsaSigningAlg::Es512 => SigningAlg::Es512,
        }
    }

    fn max_signature_size(&self) -> usize {
        // An ECDSA signature in IEEE P1363 (r‖s) form is twice the curve's field
        // size: 64 bytes for ES256, 96 for ES384, 132 for ES512.
        match self.alg {
            EcdsaSigningAlg::Es256 => 64,
            EcdsaSigningAlg::Es384 => 96,
            EcdsaSigningAlg::Es512 => 132,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::SigningAlg;

    #[test]
    fn test_es512_supported() {
        let private_key = include_bytes!("../../../tests/fixtures/raw_signature/es512.priv");
        let algorithm = SigningAlg::Es512;

        let result = EcdsaSigner::from_private_key(private_key, algorithm);

        assert!(result.is_ok());
        if let Ok(ecdsa_signer) = result {
            assert_eq!(ecdsa_signer.alg(), SigningAlg::Es512);
        } else {
            unreachable!("Expected InvalidSigningCredentials error");
        }
    }

    #[test]
    fn test_other_not_supported() {
        let private_key = include_bytes!("../../../tests/fixtures/raw_signature/ps256.priv");
        let algorithm = SigningAlg::Ps256;

        let result = EcdsaSigner::from_private_key(private_key, algorithm);

        assert!(result.is_err());
        if let Err(RawSignerError::InvalidSigningCredentials(err_msg)) = result {
            assert_eq!(err_msg, "Unsupported algorithm");
        } else {
            unreachable!("Expected InvalidSigningCredentials error");
        }
    }

    // A syntactically valid PEM that is not a usable key (base64 "MA==" decodes
    // to a single 0x30 byte). Drives each per-algorithm `from_pkcs8_pem` /
    // `from_slice` failure branch.
    const BAD_PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMA==\n-----END PRIVATE KEY-----\n";

    #[test]
    fn rejects_invalid_utf8() {
        let Err(err) = EcdsaSigner::from_private_key(&[0xff, 0xfe, 0xfd], SigningAlg::Es256) else {
            panic!("expected error");
        };

        assert!(matches!(err, RawSignerError::InvalidSigningCredentials(_)));
    }

    #[test]
    fn rejects_invalid_es256_key() {
        let Err(err) = EcdsaSigner::from_private_key(BAD_PEM, SigningAlg::Es256) else {
            panic!("expected error");
        };

        assert!(matches!(err, RawSignerError::InvalidSigningCredentials(_)));
    }

    #[test]
    fn rejects_invalid_es384_key() {
        let Err(err) = EcdsaSigner::from_private_key(BAD_PEM, SigningAlg::Es384) else {
            panic!("expected error");
        };

        assert!(matches!(err, RawSignerError::InvalidSigningCredentials(_)));
    }

    #[test]
    fn rejects_invalid_es512_key() {
        let Err(err) = EcdsaSigner::from_private_key(BAD_PEM, SigningAlg::Es512) else {
            panic!("expected error");
        };

        assert!(matches!(err, RawSignerError::InvalidSigningCredentials(_)));
    }

    #[test]
    fn es512_sign_round_trip() {
        // The integration ES512 sign test is gated to the OpenSSL backend, so
        // this exercises the rust-native ES512 `sign` arm and its 132-byte
        // `max_signature_size`.
        let private_key = include_bytes!("../../../tests/fixtures/raw_signature/es512.priv");
        let Ok(signer) = EcdsaSigner::from_private_key(private_key, SigningAlg::Es512) else {
            panic!("expected a signer");
        };

        assert_eq!(signer.max_signature_size(), 132);

        let data = b"some sample content to sign";
        let signature = signer.sign(data).unwrap();
        assert!(!signature.is_empty());
        assert!(signature.len() <= signer.max_signature_size());

        let pub_key = include_bytes!("../../../tests/fixtures/raw_signature/es512.pub_key");

        let validator =
            crate::rust_native::validators::validator_for_signing_alg(SigningAlg::Es512).unwrap();
        validator.validate(&signature, data, pub_key).unwrap();
    }
}
