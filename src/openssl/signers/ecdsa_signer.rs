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

use openssl::{
    ec::EcKey,
    hash::MessageDigest,
    pkey::{PKey, Private},
    sign::Signer,
};

use crate::{
    RawSigner, RawSignerError, SigningAlg,
    ec_utils::{der_to_p1363, ec_curve_from_private_key_der},
    openssl::OpenSslMutex,
};

enum EcdsaSigningAlg {
    Es256,
    Es384,
    Es512,
}

/// Implements [`RawSigner`] trait using OpenSSL's implementation of
/// ECDSA encryption.
pub(crate) struct EcdsaSigner {
    alg: EcdsaSigningAlg,
    private_key: EcKey<Private>,
}

impl EcdsaSigner {
    pub(crate) fn from_private_key(
        private_key: &[u8],
        alg: SigningAlg,
    ) -> Result<Self, RawSignerError> {
        let alg = match alg {
            SigningAlg::Es256 => EcdsaSigningAlg::Es256,
            SigningAlg::Es384 => EcdsaSigningAlg::Es384,
            SigningAlg::Es512 => EcdsaSigningAlg::Es512,
            _ => {
                return Err(RawSignerError::InternalError(
                    "EcdsaSigner should be used only for SigningAlg::Es***".to_string(),
                ));
            }
        };

        let _openssl = OpenSslMutex::acquire()?;
        let private_key = EcKey::private_key_from_pem(private_key)?;
        Ok(EcdsaSigner { alg, private_key })
    }
}

impl RawSigner for EcdsaSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, RawSignerError> {
        let _openssl = OpenSslMutex::acquire()?;

        let private_key = PKey::from_ec_key(self.private_key.clone())?;

        let pkcs8_private_key = private_key.private_key_to_pkcs8().map_err(|_| {
            RawSignerError::InvalidSigningCredentials("unsupported EC curve".to_string())
        })?;

        let curve = ec_curve_from_private_key_der(&pkcs8_private_key).ok_or(
            RawSignerError::InvalidSigningCredentials("unsupported EC curve".to_string()),
        )?;

        let sig_len = curve.p1363_sig_len();

        let mut signer = match self.alg {
            EcdsaSigningAlg::Es256 => Signer::new(MessageDigest::sha256(), &private_key)?,
            EcdsaSigningAlg::Es384 => Signer::new(MessageDigest::sha384(), &private_key)?,
            EcdsaSigningAlg::Es512 => Signer::new(MessageDigest::sha512(), &private_key)?,
        };

        signer.update(data)?;

        let der_sig = signer.sign_to_vec()?;
        der_to_p1363(&der_sig, sig_len)
    }

    fn alg(&self) -> SigningAlg {
        match self.alg {
            EcdsaSigningAlg::Es256 => SigningAlg::Es256,
            EcdsaSigningAlg::Es384 => SigningAlg::Es384,
            EcdsaSigningAlg::Es512 => SigningAlg::Es512,
        }
    }

    /// An ECDSA signature in IEEE P1363 (r‖s) form is twice the curve's field
    /// size: 64 bytes for ES256, 96 for ES384, 132 for ES512.
    fn max_signature_size(&self) -> usize {
        match self.alg {
            EcdsaSigningAlg::Es256 => 64,
            EcdsaSigningAlg::Es384 => 96,
            EcdsaSigningAlg::Es512 => 132,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]

    use super::*;

    #[test]
    fn rejects_non_ecdsa_alg() {
        // The algorithm is checked before the key is parsed, so any key works.
        let key = include_bytes!("../../../tests/fixtures/raw_signature/es256.priv");

        let Err(err) = EcdsaSigner::from_private_key(key, SigningAlg::Ps256) else {
            panic!("expected error");
        };
        assert!(matches!(err, RawSignerError::InternalError(_)));
    }

    #[test]
    fn sign_rejects_unsupported_curve() {
        // OpenSSL happily loads a secp256k1 key, but `sign` rejects it because
        // it is not one of the curves this crate supports, exercising the
        // unsupported-curve error path in `sign`.
        let key = include_bytes!("../../../tests/fixtures/raw_signature/secp256k1.priv");

        let Ok(signer) = EcdsaSigner::from_private_key(key, SigningAlg::Es256) else {
            panic!("expected the key to load");
        };

        let Err(err) = signer.sign(b"some sample content to sign") else {
            panic!("expected a signing error");
        };

        assert!(matches!(err, RawSignerError::InvalidSigningCredentials(_)));
    }

    #[test]
    fn rejects_bad_pem() {
        let Err(err) = EcdsaSigner::from_private_key(b"not a PEM key", SigningAlg::Es256) else {
            panic!("expected error");
        };

        // OpenSSL surfaces a parse failure as a crypto-library error.
        assert!(matches!(err, RawSignerError::CryptoLibraryError(_)));
    }
}
