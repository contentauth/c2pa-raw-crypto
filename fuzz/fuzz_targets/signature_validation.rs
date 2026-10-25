#![no_main]

use c2pa_raw_crypto::{
    Oid, SigningAlg, validator_for_sig_and_hash_algs, validator_for_signing_alg,
};
use libfuzzer_sys::fuzz_target;

const ALGORITHMS: [SigningAlg; 7] = [
    SigningAlg::Es256,
    SigningAlg::Es384,
    SigningAlg::Es512,
    SigningAlg::Ps256,
    SigningAlg::Ps384,
    SigningAlg::Ps512,
    SigningAlg::Ed25519,
];

fuzz_target!(|data: &[u8]| {
    if data.len() < 7 {
        return;
    }

    let alg = ALGORITHMS[data[0] as usize % ALGORITHMS.len()];
    let signature_len = u16::from_le_bytes([data[1], data[2]]) as usize;
    let content_len = u16::from_le_bytes([data[3], data[4]]) as usize;
    let signature_oid_len = data[5] as usize;
    let hash_oid_len = data[6] as usize;
    let Some(signature_oid_end) = 7usize.checked_add(signature_oid_len) else {
        return;
    };
    let Some(hash_oid_end) = signature_oid_end.checked_add(hash_oid_len) else {
        return;
    };
    let Some(signature_oid_bytes) = data.get(7..signature_oid_end) else {
        return;
    };
    let Some(hash_oid_bytes) = data.get(signature_oid_end..hash_oid_end) else {
        return;
    };
    let fields = &data[hash_oid_end..];
    let Some(signature) = fields.get(..signature_len) else {
        return;
    };
    let remaining = &fields[signature_len..];
    let Some(content) = remaining.get(..content_len) else {
        return;
    };
    let public_key = &remaining[content_len..];

    if let Some(validator) = validator_for_signing_alg(alg) {
        let _ = validator.validate(signature, content, public_key);
    }

    let sig_oid = Oid::new(signature_oid_bytes);
    let hash_oid = Oid::new(hash_oid_bytes);
    if let Some(validator) = validator_for_sig_and_hash_algs(&sig_oid, &hash_oid) {
        let _ = validator.validate(signature, content, public_key);
    }
});
