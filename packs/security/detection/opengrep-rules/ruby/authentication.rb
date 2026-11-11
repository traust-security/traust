class TokenAuth
  def claims(token)
    # ruleid: traust-ruby-authentication-jwt-verification-off
    payload, _ = JWT.decode(token, nil, false)
    # ruleid: traust-ruby-authentication-jwt-verification-off
    stale, _ = JWT.decode(token, KEY, true, algorithm: "HS256", verify_expiration: false)
    # ok: traust-ruby-authentication-jwt-verification-off
    good, _ = JWT.decode(token, KEY, true, algorithm: "RS256")
    good
  end
end
