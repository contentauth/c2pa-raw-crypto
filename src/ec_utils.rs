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

//! Utilities for working with the EC signatures used by C2PA in ECDSA
//! signatures.

use pkcs8::PrivateKeyInfo;
use spki::{SubjectPublicKeyInfoRef, der::Tagged};

use crate::{
    RawSignerError,
    oids::{EC_PUBLICKEY_OID, PRIME256V1_OID, SECP384R1_OID, SECP521R1_OID},
};

/// NIST curves supported by `EcdsaValidator`.
pub enum EcdsaCurve {
    /// NIST curve P-256
    P256,

    /// NIST curve P-384
    P384,

    /// NIST curve P-521
    P521,
}

impl EcdsaCurve {
    /// Return the IEEE P1363 `r‖s` signature size (in bytes) for this curve.
    pub fn p1363_sig_len(&self) -> usize {
        match self {
            EcdsaCurve::P256 => 64,
            EcdsaCurve::P384 => 96,
            EcdsaCurve::P521 => 132,
        }
    }
}

/// Parses an ASN.1 DER-encoded ECDSA signature (`SEQUENCE { r INTEGER, s
/// INTEGER }`) into its `r` and `s` integer components.
///
/// Returns `None` if `data` is not a syntactically valid DER ECDSA signature.
pub fn parse_ec_der_sig(data: &[u8]) -> Option<EcSigComps<'_>> {
    const SEQUENCE_TAG: u8 = 0x30;
    const INTEGER_TAG: u8 = 0x02;

    let (seq_content, _rest) = read_der_tlv(data, SEQUENCE_TAG)?;
    let (r, rest) = read_der_tlv(seq_content, INTEGER_TAG)?;
    let (s, _) = read_der_tlv(rest, INTEGER_TAG)?;

    Some(EcSigComps { r, s })
}

/// The `r` and `s` integer components of an ECDSA signature.
pub struct EcSigComps<'a> {
    /// The `r` component, as big-endian bytes.
    pub r: &'a [u8],

    /// The `s` component, as big-endian bytes.
    pub s: &'a [u8],
}

/// Reads a single DER TLV (tag-length-value) with the expected `tag`.
///
/// Returns the content slice and the trailing bytes after the TLV.
fn read_der_tlv(input: &[u8], expected_tag: u8) -> Option<(&[u8], &[u8])> {
    if *input.first()? != expected_tag {
        return None;
    }

    let (content_len, length_octets) = read_der_length(input.get(1..)?)?;
    let header_len = 1 + length_octets;
    let total = header_len.checked_add(content_len)?;
    if input.len() < total {
        return None;
    }

    Some((&input[header_len..total], &input[total..]))
}

/// Reads DER length octets.
///
/// Returns `(content_length, length_octet_count)`.
fn read_der_length(input: &[u8]) -> Option<(usize, usize)> {
    let first = *input.first()?;
    if first & 0x80 == 0 {
        // Short form: length fits in 7 bits.
        return Some((first as usize, 1));
    }

    // Long form: low 7 bits give the number of subsequent length octets.
    let n = (first & 0x7f) as usize;
    if n == 0 || n > core::mem::size_of::<usize>() {
        // Indefinite length (n == 0) is not valid in DER; values wider than
        // `usize` cannot be represented on this platform.
        return None;
    }
    let bytes = input.get(1..1 + n)?;
    let mut len: usize = 0;
    for &b in bytes {
        len = (len << 8) | b as usize;
    }
    Some((len, 1 + n))
}

/// Converts an ASN.1 DER-encoded ECDSA signature to fixed-size IEEE P1363
/// (`r‖s`) form of length `sig_len` bytes.
pub fn der_to_p1363(data: &[u8], sig_len: usize) -> Result<Vec<u8>, RawSignerError> {
    // P1363 format: r | s

    let p = parse_ec_der_sig(data)
        .ok_or_else(|| RawSignerError::InternalError("invalid DER signature".to_string()))?;

    let mut r = const_hex::encode(p.r);
    let mut s = const_hex::encode(p.s);

    // Check against the supported signature sizes.
    if ![64usize, 96, 132].contains(&sig_len) {
        return Err(RawSignerError::InternalError(
            "unsupported algorithm for der_to_p1363".to_string(),
        ));
    }

    // Pad or truncate as needed.
    let rp = if r.len() > sig_len {
        let offset = r.len() - sig_len;
        &r[offset..r.len()]
    } else {
        while r.len() != sig_len {
            r.insert(0, '0');
        }
        r.as_ref()
    };

    let sp = if s.len() > sig_len {
        let offset = s.len() - sig_len;
        &s[offset..s.len()]
    } else {
        while s.len() != sig_len {
            s.insert(0, '0');
        }
        s.as_ref()
    };

    if rp.len() != sig_len || rp.len() != sp.len() {
        return Err(RawSignerError::InternalError(
            "invalid signature components".to_string(),
        ));
    }

    // Merge r and s strings.
    let new_sig = format!("{rp}{sp}");

    // Convert back from hex string to byte array.
    const_hex::decode(&new_sig)
        .map_err(|e| RawSignerError::InternalError(format!("invalid signature components {e}")))
}

/// Returns the [`EcdsaCurve`] for a DER-encoded SubjectPublicKeyInfo
/// or `None` if the key is not on a supported curve.
pub fn ec_curve_from_public_key_der(public_key: &[u8]) -> Option<EcdsaCurve> {
    let spki = SubjectPublicKeyInfoRef::try_from(public_key).ok()?;

    if spki.algorithm.oid.as_bytes() != EC_PUBLICKEY_OID.as_bytes() {
        return None;
    }

    // The `parameters` field of an `id-ecPublicKey` algorithm identifier is a
    // named-curve OID. Extract its DER content octets and compare.
    let params = spki.algorithm.parameters.as_ref()?;
    if params.tag() != spki::der::Tag::ObjectIdentifier {
        return None;
    }
    let curve_oid = params.value();

    if curve_oid == PRIME256V1_OID.as_bytes() {
        Some(EcdsaCurve::P256)
    } else if curve_oid == SECP384R1_OID.as_bytes() {
        Some(EcdsaCurve::P384)
    } else if curve_oid == SECP521R1_OID.as_bytes() {
        Some(EcdsaCurve::P521)
    } else {
        None
    }
}

/// Returns the [`EcdsaCurve`] for a DER-encoded PKCS#8 private key
/// or `None` if the key is not on a supported curve.
pub fn ec_curve_from_private_key_der(private_key: &[u8]) -> Option<EcdsaCurve> {
    use pkcs8::der::Decode;
    let ec_key = PrivateKeyInfo::from_der(private_key).ok()?;

    let p256_oid = pkcs8::ObjectIdentifier::from_bytes(PRIME256V1_OID.as_bytes()).ok()?;
    let p384_oid = pkcs8::ObjectIdentifier::from_bytes(SECP384R1_OID.as_bytes()).ok()?;
    let p521_oid = pkcs8::ObjectIdentifier::from_bytes(SECP521R1_OID.as_bytes()).ok()?;

    if ec_key.algorithm.assert_parameters_oid(p256_oid).is_ok() {
        return Some(EcdsaCurve::P256);
    } else if ec_key.algorithm.assert_parameters_oid(p384_oid).is_ok() {
        return Some(EcdsaCurve::P384);
    } else if ec_key.algorithm.assert_parameters_oid(p521_oid).is_ok() {
        return Some(EcdsaCurve::P521);
    }

    None
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::RawSignerError;

    /// Builds a DER `SEQUENCE { r INTEGER, s INTEGER }` from raw `r`/`s` content
    /// octets. Lengths are kept short-form (< 128 bytes) for test simplicity.
    fn der_sig(r: &[u8], s: &[u8]) -> Vec<u8> {
        let int = |v: &[u8]| {
            let mut out = vec![0x02u8, v.len() as u8];
            out.extend_from_slice(v);
            out
        };

        let body: Vec<u8> = int(r).into_iter().chain(int(s)).collect();

        let mut out = vec![0x30u8, body.len() as u8];
        out.extend_from_slice(&body);
        out
    }

    #[test]
    fn p1363_sig_len_per_curve() {
        assert_eq!(EcdsaCurve::P256.p1363_sig_len(), 64);
        assert_eq!(EcdsaCurve::P384.p1363_sig_len(), 96);
        assert_eq!(EcdsaCurve::P521.p1363_sig_len(), 132);
    }

    #[test]
    fn parse_ec_der_sig_round_trip() {
        let sig = der_sig(&[0x01, 0x02], &[0x03]);
        let comps = parse_ec_der_sig(&sig).expect("valid DER");
        assert_eq!(comps.r, &[0x01, 0x02]);
        assert_eq!(comps.s, &[0x03]);
    }

    #[test]
    fn parse_ec_der_sig_rejects_non_sequence() {
        // Leading tag is INTEGER, not SEQUENCE.
        assert!(parse_ec_der_sig(&[0x02, 0x01, 0x00]).is_none());
    }

    #[test]
    fn parse_ec_der_sig_rejects_truncated() {
        // SEQUENCE claims 4 content bytes but only 1 is present.
        assert!(parse_ec_der_sig(&[0x30, 0x04, 0x02]).is_none());
    }

    #[test]
    fn read_der_length_short_and_long_form() {
        // Short form: high bit clear, value is the length itself.
        assert_eq!(read_der_length(&[0x7f]), Some((0x7f, 1)));

        // Long form: 0x82 => two subsequent length octets => 0x0100 = 256.
        assert_eq!(read_der_length(&[0x82, 0x01, 0x00]), Some((256, 3)));
    }

    #[test]
    fn read_der_length_rejects_indefinite_and_oversize() {
        // Indefinite length (0x80) is invalid in DER.
        assert!(read_der_length(&[0x80]).is_none());

        // More length octets than a usize can hold.
        let oversize = 0x80u8 | ((core::mem::size_of::<usize>() + 1) as u8);
        assert!(read_der_length(&[oversize, 0, 0, 0, 0, 0, 0, 0, 0, 0]).is_none());

        // Empty input.
        assert!(read_der_length(&[]).is_none());
    }

    #[test]
    fn der_to_p1363_rejects_invalid_der() {
        let err = der_to_p1363(&[0x00], 64).unwrap_err();
        assert!(matches!(err, RawSignerError::InternalError(m) if m == "invalid DER signature"));
    }

    #[test]
    fn der_to_p1363_rejects_unsupported_sig_len() {
        let sig = der_sig(&[0x01], &[0x02]);
        let err = der_to_p1363(&sig, 65).unwrap_err();

        assert!(
            matches!(err, RawSignerError::InternalError(m) if m == "unsupported algorithm for der_to_p1363")
        );
    }

    #[test]
    fn der_to_p1363_left_pads_short_components() {
        // r and s are far shorter than the field size, so both are left-padded
        // with zeros out to 32 bytes each (64 bytes total for P-256).
        let sig = der_sig(&[0x01, 0x02], &[0x03]);
        let p1363 = der_to_p1363(&sig, 64).unwrap();

        assert_eq!(p1363.len(), 64);

        // r occupies the first 32 bytes, right-aligned.
        assert_eq!(p1363[30], 0x01);
        assert_eq!(p1363[31], 0x02);
        assert_eq!(p1363[..30], [0u8; 30]);

        // s occupies the second 32 bytes, right-aligned.
        assert_eq!(p1363[63], 0x03);
        assert_eq!(p1363[32..63], [0u8; 31]);
    }

    #[test]
    fn der_to_p1363_truncates_long_components() {
        // A 33-byte r (DER's leading 0x00 sign byte on a high-bit-set value) is
        // one byte too long for P-256 and must have its leading byte dropped.
        let mut r = vec![0x00u8];
        r.extend(std::iter::repeat_n(0xab, 32));
        let sig = der_sig(&r, &[0x05]);

        let p1363 = der_to_p1363(&sig, 64).unwrap();
        assert_eq!(p1363.len(), 64);

        // The leading 0x00 is gone; the 32 0xab bytes remain as r.
        assert_eq!(p1363[..32], [0xabu8; 32]);
    }

    #[test]
    fn ec_curve_from_public_key_der_recognizes_supported_curves() {
        let p256 = include_bytes!("../tests/fixtures/raw_signature/es256.pub_key");
        let p384 = include_bytes!("../tests/fixtures/raw_signature/es384.pub_key");
        let p521 = include_bytes!("../tests/fixtures/raw_signature/es512.pub_key");

        assert!(matches!(
            ec_curve_from_public_key_der(p256),
            Some(EcdsaCurve::P256)
        ));

        assert!(matches!(
            ec_curve_from_public_key_der(p384),
            Some(EcdsaCurve::P384)
        ));

        assert!(matches!(
            ec_curve_from_public_key_der(p521),
            Some(EcdsaCurve::P521)
        ));
    }

    #[test]
    fn ec_curve_from_public_key_der_rejects_non_ec_and_garbage() {
        // A valid SPKI, but an RSA key rather than an EC key.
        let rsa = include_bytes!("../tests/fixtures/raw_signature/ps256.pub_key");
        assert!(ec_curve_from_public_key_der(rsa).is_none());

        // Not parseable as SPKI at all.
        assert!(ec_curve_from_public_key_der(&[0x00, 0x01, 0x02]).is_none());
    }

    #[test]
    fn ec_curve_from_public_key_der_rejects_unsupported_curve() {
        // A valid EC SPKI, but on secp256k1 — not one of the supported NIST
        // curves, so the named-curve OID matches none of them.
        let k1 = include_bytes!("../tests/fixtures/raw_signature/secp256k1.pub_key");
        assert!(ec_curve_from_public_key_der(k1).is_none());
    }

    // Decoding the PEM fixtures to DER needs `SecretDocument::from_pem`, which
    // requires the `pem` feature that the rust-native crypto deps enable.
    #[test]
    #[cfg(feature = "rust_native_crypto")]
    fn ec_curve_from_private_key_der_recognizes_supported_curves() {
        for (pem, expect_256) in [
            (
                include_bytes!("../tests/fixtures/raw_signature/es256.priv").as_slice(),
                EcdsaCurve::P256,
            ),
            (
                include_bytes!("../tests/fixtures/raw_signature/es384.priv").as_slice(),
                EcdsaCurve::P384,
            ),
            (
                include_bytes!("../tests/fixtures/raw_signature/es512.priv").as_slice(),
                EcdsaCurve::P521,
            ),
        ] {
            let pem_str = std::str::from_utf8(pem).unwrap();
            let (_label, der) = pkcs8::der::SecretDocument::from_pem(pem_str).unwrap();
            let curve = ec_curve_from_private_key_der(der.as_bytes()).expect("supported curve");
            assert_eq!(curve.p1363_sig_len(), expect_256.p1363_sig_len());
        }
    }

    #[test]
    fn ec_curve_from_private_key_der_rejects_garbage() {
        assert!(ec_curve_from_private_key_der(&[0x00, 0x01, 0x02]).is_none());
    }

    // PEM decoding needs the `pem` feature enabled by the rust-native deps.
    #[test]
    #[cfg(feature = "rust_native_crypto")]
    fn ec_curve_from_private_key_der_rejects_unsupported_curve() {
        // A valid PKCS#8 EC key on secp256k1: parses fine, but its curve OID
        // matches none of the supported NIST curves.
        let pem = include_bytes!("../tests/fixtures/raw_signature/secp256k1.priv");
        let pem_str = std::str::from_utf8(pem).unwrap();
        let (_label, der) = pkcs8::der::SecretDocument::from_pem(pem_str).unwrap();
        assert!(ec_curve_from_private_key_der(der.as_bytes()).is_none());
    }
}
