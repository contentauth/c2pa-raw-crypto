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

use ed25519_dalek::{PUBLIC_KEY_LENGTH, Signature, Verifier, VerifyingKey};
use spki::SubjectPublicKeyInfoRef;

use crate::{RawSignatureValidationError, RawSignatureValidator, oids::ED25519_OID};

/// Validates raw signatures with the Ed25519 signature algorithm.
pub(crate) struct Ed25519Validator {}

impl RawSignatureValidator for Ed25519Validator {
    fn validate(
        &self,
        sig: &[u8],
        data: &[u8],
        public_key: &[u8],
    ) -> Result<(), RawSignatureValidationError> {
        let spki = SubjectPublicKeyInfoRef::try_from(public_key)
            .map_err(|_| RawSignatureValidationError::InvalidPublicKey)?;

        if spki.algorithm.oid.as_bytes() != ED25519_OID.as_bytes() {
            return Err(RawSignatureValidationError::InvalidPublicKey);
        }

        let public_key = spki.subject_public_key.raw_bytes();
        if public_key.len() != PUBLIC_KEY_LENGTH {
            return Err(RawSignatureValidationError::InvalidPublicKey);
        }

        let mut public_key_slice: [u8; PUBLIC_KEY_LENGTH] = Default::default();
        public_key_slice.copy_from_slice(public_key);

        let vk = VerifyingKey::from_bytes(&public_key_slice)
            .map_err(|_| RawSignatureValidationError::InvalidPublicKey)?;

        let ed_sig = Signature::from_slice(sig)
            .map_err(|_| RawSignatureValidationError::InvalidSignature)?;

        match vk.verify(data, &ed_sig) {
            Ok(_) => Ok(()),
            Err(_) => Err(RawSignatureValidationError::SignatureMismatch),
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
        let sig = include_bytes!("../../../tests/fixtures/raw_signature/ed25519.raw_sig");

        assert_eq!(
            Ed25519Validator {}
                .validate(sig, SAMPLE_DATA, &[0x00, 0x01, 0x02])
                .unwrap_err(),
            RawSignatureValidationError::InvalidPublicKey
        );
    }

    #[test]
    fn wrong_algorithm_public_key_rejected() {
        // A well-formed SPKI, but for an EC key rather than Ed25519: the OID
        // guard rejects it.
        let sig = include_bytes!("../../../tests/fixtures/raw_signature/ed25519.raw_sig");

        let ec_pub_key = include_bytes!("../../../tests/fixtures/raw_signature/es256.pub_key");
        assert_eq!(
            Ed25519Validator {}
                .validate(sig, SAMPLE_DATA, ec_pub_key)
                .unwrap_err(),
            RawSignatureValidationError::InvalidPublicKey
        );
    }

    #[test]
    fn wrong_length_public_key_rejected() {
        // A well-formed SPKI carrying the Ed25519 OID, but whose BIT STRING
        // public key is not the required 32 bytes: the length guard rejects it.
        //
        // SubjectPublicKeyInfo ::= SEQUENCE {
        //   algorithm   AlgorithmIdentifier { 1.3.101.112 },
        //   subjectPublicKey BIT STRING (here only 1 byte of key data) }
        let spki = [
            0x30, 0x0b, // SEQUENCE, 11 bytes
            0x30, 0x05, // algorithm SEQUENCE, 5 bytes
            0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
            0x03, 0x02, 0x00, 0x00, // BIT STRING, 2 bytes: 0 unused bits + 1 key byte
        ];
        let sig = include_bytes!("../../../tests/fixtures/raw_signature/ed25519.raw_sig");

        assert_eq!(
            Ed25519Validator {}
                .validate(sig, SAMPLE_DATA, &spki)
                .unwrap_err(),
            RawSignatureValidationError::InvalidPublicKey
        );
    }

    #[test]
    fn invalid_signature_rejected() {
        // Valid Ed25519 public key, but a signature that is not 64 bytes.
        let pub_key = include_bytes!("../../../tests/fixtures/raw_signature/ed25519.pub_key");

        assert_eq!(
            Ed25519Validator {}
                .validate(&[0u8; 8], SAMPLE_DATA, pub_key)
                .unwrap_err(),
            RawSignatureValidationError::InvalidSignature
        );
    }
}
