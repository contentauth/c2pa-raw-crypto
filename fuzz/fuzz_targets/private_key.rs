#![no_main]

use c2pa_raw_crypto::{SigningAlg, signer_from_private_key};
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
    let Some((&algorithm, private_key)) = data.split_first() else {
        return;
    };

    let _ = signer_from_private_key(
        private_key,
        ALGORITHMS[algorithm as usize % ALGORITHMS.len()],
    );
});
