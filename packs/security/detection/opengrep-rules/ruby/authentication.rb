class TokenAuth
  def claims(token)
    # ruleid: traust-ruby-authentication-jwt-verification-off
    payload, _ = JWT.decode(token, nil, false)
    # ruleid: traust-ruby-authentication-jwt-verification-off
    stale, _ = JWT.decode(token, KEY, true, algorithm: "HS256", verify_expiration: false)
    # ok: traust-ruby-authentication-jwt-verification-off
    good, _ = JWT.decode(token, KEY, true, algorithm: "RS256")
    # Verification is only useful with a trusted key and an expected algorithm.
    # ok: traust-ruby-authentication-jwt-verification-off
    checked, _ = JWT.decode(token, KEY, true, algorithm: "RS256", verify_expiration: true)
    good
  end
end
