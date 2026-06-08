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
    pkey::{PKey, Private},
    sign::Signer,
};

use crate::{RawSigner, RawSignerError, SigningAlg, openssl::OpenSslMutex};

/// Implements [`RawSigner`] trait using OpenSSL's implementation of
/// Edwards Curve encryption.
///
/// The private key is held in an OpenSSL `PKey<Private>`. OpenSSL owns this key
/// material and clears it when the key is freed (`EVP_PKEY_free`), so the
/// `zeroize` crate cannot (and need not) be applied to the handle itself.
pub(crate) struct Ed25519Signer {
    private_key: PKey<Private>,
}

impl Ed25519Signer {
    pub(crate) fn from_private_key(private_key: &[u8]) -> Result<Self, RawSignerError> {
        let _openssl = OpenSslMutex::acquire()?;
        let private_key = PKey::private_key_from_pem(private_key)?;
        Ok(Ed25519Signer { private_key })
    }
}

impl RawSigner for Ed25519Signer {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, RawSignerError> {
        let _openssl = OpenSslMutex::acquire()?;
        let mut signer = Signer::new_without_digest(&self.private_key)?;
        Ok(signer.sign_oneshot_to_vec(data)?)
    }

    fn alg(&self) -> SigningAlg {
        SigningAlg::Ed25519
    }

    fn max_signature_size(&self) -> usize {
        64
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]

    use super::*;

    #[test]
    fn rejects_bad_pem() {
        let Err(err) = Ed25519Signer::from_private_key(b"not a PEM key") else {
            panic!("expected error");
        };

        assert!(matches!(err, RawSignerError::CryptoLibraryError(_)));
    }
}
