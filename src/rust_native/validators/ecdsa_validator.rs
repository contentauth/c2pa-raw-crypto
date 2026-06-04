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

use ecdsa::{Signature as EcdsaSignature, signature::hazmat::PrehashVerifier};
use p256::ecdsa::VerifyingKey as P256VerifyingKey;
use p384::ecdsa::VerifyingKey as P384VerifyingKey;
use p521::{PublicKey as P521PublicKey, ecdsa::VerifyingKey as P521VerifyingKey};
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::{
    RawSignatureValidationError, RawSignatureValidator,
    ec_utils::{EcdsaCurve, der_to_p1363, ec_curve_from_public_key_der},
};

/// Validate raw signatures with one of the ECDSA signature algorithms.
pub(crate) enum EcdsaValidator {
    /// ECDSA with SHA-256
    Es256,

    /// ECDSA with SHA-384
    Es384,

    /// ECDSA with SHA-512
    Es512,
}

impl RawSignatureValidator for EcdsaValidator {
    fn validate(
        &self,
        sig: &[u8],
        data: &[u8],
        public_key: &[u8],
    ) -> Result<(), RawSignatureValidationError> {
        let digest = match self {
            EcdsaValidator::Es256 => {
                let mut hasher = Sha256::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }

            EcdsaValidator::Es384 => {
                let mut hasher = Sha384::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }

            EcdsaValidator::Es512 => {
                let mut hasher = Sha512::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
        };

        // Determine curve from public key.
        let curve = ec_curve_from_public_key_der(public_key)
            .ok_or(RawSignatureValidationError::InvalidPublicKey)?;

        // Requires fixed-size P1363 signature.
        let adjusted_sig = match der_to_p1363(sig, curve.p1363_sig_len()) {
            Ok(p1363) => p1363,
            Err(_) => sig.to_vec(),
        };

        let result = match curve {
            EcdsaCurve::P256 => {
                use p256::pkcs8::DecodePublicKey;
                let signature = EcdsaSignature::from_slice(&adjusted_sig)
                    .map_err(|_| RawSignatureValidationError::InvalidSignature)?;

                let vk = P256VerifyingKey::from_public_key_der(public_key)
                    .map_err(|_| RawSignatureValidationError::InvalidPublicKey)?;

                vk.verify_prehash(&digest, &signature)
            }

            EcdsaCurve::P384 => {
                use p384::pkcs8::DecodePublicKey;
                let signature = EcdsaSignature::from_slice(&adjusted_sig)
                    .map_err(|_| RawSignatureValidationError::InvalidSignature)?;

                let vk = P384VerifyingKey::from_public_key_der(public_key)
                    .map_err(|_| RawSignatureValidationError::InvalidPublicKey)?;

                vk.verify_prehash(&digest, &signature)
            }

            EcdsaCurve::P521 => {
                use p521::pkcs8::DecodePublicKey;
                let signature = EcdsaSignature::from_slice(&adjusted_sig)
                    .map_err(|_| RawSignatureValidationError::InvalidSignature)?;

                // P521VerifyingKey does't have an implementation of `from_public_key` so we
                // load it manually.
                let pk = P521PublicKey::from_public_key_der(public_key)
                    .map_err(|_| RawSignatureValidationError::InvalidPublicKey)?;

                let pk_bytes = pk.to_sec1_bytes();

                let vk = P521VerifyingKey::from_sec1_bytes(&pk_bytes)
                    .map_err(|_| RawSignatureValidationError::InvalidPublicKey)?;

                vk.verify_prehash(&digest, &signature)
            }
        };

        match result {
            Ok(_) => Ok(()),
            Err(_err) => Err(RawSignatureValidationError::SignatureMismatch),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    const SAMPLE_DATA: &[u8] = b"some sample content to sign";

    #[test]
    fn invalid_public_key_rejected() {
        // Bytes that are not a parseable EC SubjectPublicKeyInfo: the curve
        // cannot be determined.
        let sig = include_bytes!("../../../tests/fixtures/raw_signature/es256.raw_sig");

        assert_eq!(
            EcdsaValidator::Es256
                .validate(sig, SAMPLE_DATA, &[0x00, 0x01, 0x02])
                .unwrap_err(),
            RawSignatureValidationError::InvalidPublicKey
        );
    }

    #[test]
    fn invalid_signature_rejected() {
        // Valid P-256 public key, but a signature too short to be a valid
        // fixed-size ECDSA signature.
        let pub_key = include_bytes!("../../../tests/fixtures/raw_signature/es256.pub_key");

        assert_eq!(
            EcdsaValidator::Es256
                .validate(&[0u8; 8], SAMPLE_DATA, pub_key)
                .unwrap_err(),
            RawSignatureValidationError::InvalidSignature
        );
    }
}
