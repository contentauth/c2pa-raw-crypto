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

use const_oid::ObjectIdentifier;
use pkcs8::der::{SecretDocument, pem::PemLabel};
use rsa::{
    BigUint, RsaPrivateKey,
    pkcs8::PrivateKeyInfo,
    pss::SigningKey,
    sha2::{Sha256, Sha384, Sha512},
    signature::{RandomizedSigner, SignatureEncoding},
    traits::PublicKeyParts,
};
use zeroize::ZeroizeOnDrop;

use crate::{RawSigner, RawSignerError, SigningAlg};

enum RsaSigningAlg {
    Ps256,
    Ps384,
    Ps512,
}

/// Implements [`RawSigner`] trait using `rsa` crate's implementation of SHA256
/// + RSA encryption.
///
/// The private key material is held in an `rsa::RsaPrivateKey`, which is
/// zeroized when this signer is dropped.
#[derive(ZeroizeOnDrop)]
pub(crate) struct RsaSigner {
    // `alg` carries no secret material, so it is skipped when zeroizing.
    #[zeroize(skip)]
    alg: RsaSigningAlg,
    private_key: RsaPrivateKey,
}

// Can't use the OIDs defined at certificate_profile.rs because they're
// different underlying types. (Sigh.)
const RSA_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const RSA_PSS_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");

impl RsaSigner {
    pub(crate) fn from_private_key(
        private_key: &[u8],
        alg: SigningAlg,
    ) -> Result<Self, RawSignerError> {
        let pem_str = std::str::from_utf8(private_key)
            .map_err(|e| RawSignerError::InvalidSigningCredentials(e.to_string()))?;

        let (label, private_key_der) = SecretDocument::from_pem(pem_str)
            .map_err(|e| RawSignerError::InvalidSigningCredentials(e.to_string()))?;

        PrivateKeyInfo::validate_pem_label(label)
            .map_err(|e| RawSignerError::InvalidSigningCredentials(e.to_string()))?;

        let pki = PrivateKeyInfo::try_from(private_key_der.as_bytes())
            .map_err(|e| RawSignerError::InvalidSigningCredentials(e.to_string()))?;

        let oid = &pki.algorithm.oid;
        if !(oid == &RSA_OID || oid == &RSA_PSS_OID) {
            return Err(RawSignerError::InvalidSigningCredentials(format!(
                "unsupported private key algorithm ({oid})"
            )));
        }

        let pkcs1_key = pkcs1::RsaPrivateKey::try_from(pki.private_key)
            .map_err(|e| RawSignerError::InvalidSigningCredentials(e.to_string()))?;

        if pkcs1_key.version() != pkcs1::Version::TwoPrime {
            return Err(RawSignerError::InvalidSigningCredentials(
                "multi-prime RSA keys not supported".to_string(),
            ));
        }

        let n = BigUint::from_bytes_be(pkcs1_key.modulus.as_bytes());
        let e = BigUint::from_bytes_be(pkcs1_key.public_exponent.as_bytes());
        let d = BigUint::from_bytes_be(pkcs1_key.private_exponent.as_bytes());
        let prime1 = BigUint::from_bytes_be(pkcs1_key.prime1.as_bytes());
        let prime2 = BigUint::from_bytes_be(pkcs1_key.prime2.as_bytes());
        let primes = vec![prime1, prime2];

        let private_key = RsaPrivateKey::from_components(n, e, d, primes)
            .map_err(|e| RawSignerError::InvalidSigningCredentials(e.to_string()))?;

        let alg: RsaSigningAlg = match alg {
            SigningAlg::Ps256 => RsaSigningAlg::Ps256,
            SigningAlg::Ps384 => RsaSigningAlg::Ps384,
            SigningAlg::Ps512 => RsaSigningAlg::Ps512,
            _ => {
                return Err(RawSignerError::InternalError(
                    "RsaSigner should be used only for SigningAlg::Ps***".to_string(),
                ));
            }
        };

        Ok(RsaSigner { alg, private_key })
    }
}

impl RawSigner for RsaSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, RawSignerError> {
        let mut rng = rand::thread_rng();

        match self.alg {
            RsaSigningAlg::Ps256 => {
                let s = SigningKey::<Sha256>::new(self.private_key.clone());
                let sig = s.sign_with_rng(&mut rng, data);
                Ok(sig.to_bytes().to_vec())
            }

            RsaSigningAlg::Ps384 => {
                let s = SigningKey::<Sha384>::new(self.private_key.clone());
                let sig = s.sign_with_rng(&mut rng, data);
                Ok(sig.to_bytes().to_vec())
            }

            RsaSigningAlg::Ps512 => {
                let s = SigningKey::<Sha512>::new(self.private_key.clone());
                let sig = s.sign_with_rng(&mut rng, data);
                Ok(sig.to_bytes().to_vec())
            }
        }
    }

    /// An RSASSA-PSS signature is the size of the RSA modulus.
    fn max_signature_size(&self) -> usize {
        self.private_key.size()
    }

    fn alg(&self) -> SigningAlg {
        match self.alg {
            RsaSigningAlg::Ps256 => SigningAlg::Ps256,
            RsaSigningAlg::Ps384 => SigningAlg::Ps384,
            RsaSigningAlg::Ps512 => SigningAlg::Ps512,
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

    // `RsaSigner` intentionally does not implement `Debug`, so we match the
    // `Err` arm directly rather than using `unwrap_err`.

    #[test]
    fn rejects_invalid_utf8() {
        let Err(err) = RsaSigner::from_private_key(&[0xff, 0xfe, 0xfd], SigningAlg::Ps256) else {
            panic!("expected error");
        };

        assert!(matches!(err, RawSignerError::InvalidSigningCredentials(_)));
    }

    #[test]
    fn rejects_non_pem() {
        let Err(err) = RsaSigner::from_private_key(b"this is not a PEM file", SigningAlg::Ps256)
        else {
            panic!("expected error");
        };

        assert!(matches!(err, RawSignerError::InvalidSigningCredentials(_)));
    }

    #[test]
    fn rejects_non_rsa_key_oid() {
        // A syntactically valid PKCS#8 PEM, but an EC key rather than RSA.
        let ec_key = include_bytes!("../../../tests/fixtures/raw_signature/es256.priv");

        let Err(err) = RsaSigner::from_private_key(ec_key, SigningAlg::Ps256) else {
            panic!("expected error");
        };

        match err {
            RawSignerError::InvalidSigningCredentials(m) => {
                assert!(m.contains("unsupported private key algorithm"), "got: {m}");
            }
            other => panic!("expected InvalidSigningCredentials, got {other:?}"),
        }
    }

    #[test]
    fn rejects_multi_prime_key() {
        // A 3-prime RSA key parses as a valid PKCS#1 key but is rejected because
        // the `rsa` crate only supports two-prime keys.
        let key = include_bytes!("../../../tests/fixtures/raw_signature/multiprime_rsa.priv");
        let Err(err) = RsaSigner::from_private_key(key, SigningAlg::Ps256) else {
            panic!("expected error");
        };

        match err {
            RawSignerError::InvalidSigningCredentials(m) => {
                assert!(m.contains("multi-prime RSA keys not supported"), "got: {m}");
            }
            other => panic!("expected InvalidSigningCredentials, got {other:?}"),
        }
    }

    #[test]
    fn rejects_non_rsa_signing_alg() {
        // A valid RSA key, but asked to sign with a non-RSA algorithm: the
        // `_` arm of the alg match returns an internal error.
        let rsa_key = include_bytes!("../../../tests/fixtures/raw_signature/ps256.priv");
        let Err(err) = RsaSigner::from_private_key(rsa_key, SigningAlg::Es256) else {
            panic!("expected error");
        };

        match err {
            RawSignerError::InternalError(m) => {
                assert!(m.contains("RsaSigner should be used only"), "got: {m}");
            }
            other => panic!("expected InternalError, got {other:?}"),
        }
    }
}
