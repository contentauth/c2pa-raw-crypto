#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = c2pa_raw_crypto::ec_utils::parse_ec_der_sig(data);

    for sig_len in [64, 96, 132, 0, usize::MAX] {
        let _ = c2pa_raw_crypto::ec_utils::der_to_p1363(data, sig_len);
    }

    let _ = c2pa_raw_crypto::ec_utils::ec_curve_from_public_key_der(data);
    let _ = c2pa_raw_crypto::ec_utils::ec_curve_from_private_key_der(data);
});
