fn client() -> reqwest::Client {
    // ruleid: traust-rust-cryptography-tls-verify-off
    let builder = reqwest::Client::builder().danger_accept_invalid_certs(true);
    builder.build().unwrap()
}

fn strict() -> reqwest::Client {
    // ok: traust-rust-cryptography-tls-verify-off
    let builder = reqwest::Client::builder().danger_accept_invalid_certs(false);
    builder.build().unwrap()
}

fn digest(password: &str, blob: &[u8]) {
    // ruleid: traust-rust-cryptography-weak-hash
    let stored = md5::compute(password.as_bytes());
    // ok: traust-rust-cryptography-weak-hash
    let strong = Sha256::digest(blob);
}
