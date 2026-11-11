use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

fn verify(token: &str, key: &DecodingKey) -> Result<Claims> {
    let mut validation = Validation::new(Algorithm::RS256);
    // ruleid: traust-rust-authentication-jwt-validation-disabled
    validation.insecure_disable_signature_validation();
    // ruleid: traust-rust-authentication-jwt-validation-disabled
    validation.validate_exp = false;
    // ok: traust-rust-authentication-jwt-validation-disabled
    validation.validate_aud = true;
    Ok(decode::<Claims>(token, key, &validation)?.claims)
}

fn peek(token: &str) -> Claims {
    // ruleid: traust-rust-authentication-jwt-validation-disabled
    jsonwebtoken::dangerous_insecure_decode::<Claims>(token).unwrap().claims
}

fn strict(token: &str, key: &DecodingKey) -> Result<Claims> {
    // ok: traust-rust-authentication-jwt-validation-disabled
    let validation = Validation::new(Algorithm::ES256);
    Ok(decode::<Claims>(token, key, &validation)?.claims)
}
