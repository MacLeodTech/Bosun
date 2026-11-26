//! Client certificate files are uploaded by a user but come from elsewhere: PEM and PKCS#12 parsing must never
//! panic, whatever the bytes and password.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let (pw, file) = match data.split_first() {
        Some((n, rest)) => rest.split_at((*n as usize).min(rest.len())),
        None => return,
    };
    let _ = bosun_proxy::clientcert::parse_identity(file, &String::from_utf8_lossy(pw));
});
