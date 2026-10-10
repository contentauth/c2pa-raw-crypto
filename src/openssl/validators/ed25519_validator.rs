// Copyright 2022 Adobe. All rights reserved.
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

use curve25519_dalek::edwards::CompressedEdwardsY;
use openssl::{pkey::PKey, sign::Verifier};
use spki::SubjectPublicKeyInfoRef;

use crate::{RawSignatureValidationError, RawSignatureValidator, openssl::OpenSslMutex};

/// Validates raw signatures with the Ed25519 signature algorithm.
pub(crate) struct Ed25519Validator {}

impl RawSignatureValidator for Ed25519Validator {
    fn validate(
        &self,
        sig: &[u8],
        data: &[u8],
        public_key: &[u8],
    ) -> Result<(), RawSignatureValidationError> {
        let _openssl = OpenSslMutex::acquire()?;

        // OpenSSL's Ed25519 verification has no equivalent of a "strict" mode:
        // it never rejects small-order ("weak") public keys. Such a key makes
        // the verification equation independent of the message, so a single
        // fabricated signature would otherwise validate against any content
        // for that key. Reject weak keys ourselves before asking OpenSSL to
        // verify anything.
        let spki = SubjectPublicKeyInfoRef::try_from(public_key)
            .map_err(|_| RawSignatureValidationError::InvalidPublicKey)?;

        let raw_public_key = spki.subject_public_key.raw_bytes();
        let key_bytes: [u8; 32] = raw_public_key
            .try_into()
            .map_err(|_| RawSignatureValidationError::InvalidPublicKey)?;

        let point = CompressedEdwardsY(key_bytes)
            .decompress()
            .ok_or(RawSignatureValidationError::InvalidPublicKey)?;

        if point.is_small_order() {
            return Err(RawSignatureValidationError::InvalidPublicKey);
        }

        let public_key = PKey::public_key_from_der(public_key)?;

        if Verifier::new_without_digest(&public_key)?.verify_oneshot(sig, data)? {
            Ok(())
        } else {
            Err(RawSignatureValidationError::SignatureMismatch)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    const SAMPLE_DATA: &[u8] = b"some sample content to sign";

    #[test]
    fn unparseable_public_key_rejected() {
        // Malformed SPKI is now caught by our own parsing (needed for the
        // weak-key check below) before OpenSSL ever sees it.
        let sig = include_bytes!("../../../tests/fixtures/raw_signature/ed25519.raw_sig");

        let err = Ed25519Validator {}
            .validate(sig, SAMPLE_DATA, &[0x00, 0x01, 0x02])
            .unwrap_err();

        assert_eq!(err, RawSignatureValidationError::InvalidPublicKey);
    }

    #[test]
    fn weak_public_key_rejected() {
        // A well-formed SPKI carrying the Ed25519 OID, but whose public key
        // is the curve's identity point (order 1). This point is small-order:
        // the verification equation becomes independent of the message, so
        // an all-zero "signature" would otherwise validate against any data.
        let spki = [
            0x30, 0x2a, // SEQUENCE, 42 bytes
            0x30, 0x05, // algorithm SEQUENCE, 5 bytes
            0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
            0x03, 0x21, 0x00, // BIT STRING, 33 bytes: 0 unused bits + 32 key bytes
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

        let forged_sig = [0u8; 64];

        let err = Ed25519Validator {}
            .validate(&forged_sig, SAMPLE_DATA, &spki)
            .unwrap_err();

        assert_eq!(err, RawSignatureValidationError::InvalidPublicKey);
    }
}
