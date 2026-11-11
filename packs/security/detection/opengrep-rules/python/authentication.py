import jwt


def decode_inline(token):
    # ruleid: traust-python-authentication-jwt-signature-unverified
    return jwt.decode(token, options={"verify_signature": False})


def decode_behind_flag(token, settings, key):
    options = {"verify_aud": True}
    if settings.get("TEST_MODE", False):
        # ruleid: traust-python-authentication-jwt-signature-unverified
        options["verify_signature"] = False
    return jwt.decode(token, key, algorithms=["RS256"], options=options)


def decode_kwargs(token):
    # ruleid: traust-python-authentication-jwt-signature-unverified
    opts = dict(verify_signature=False)
    return jwt.decode(token, options=opts)


def decode_legacy(token, key):
    # ruleid: traust-python-authentication-jwt-signature-unverified
    return jwt.decode(token, key, verify=False)


def decode_none_alg(token, key):
    # ruleid: traust-python-authentication-jwt-signature-unverified
    return jwt.decode(token, key, algorithms=["HS256", "none"])


def decode_verified(token, key):
    # ok: traust-python-authentication-jwt-signature-unverified
    return jwt.decode(token, key, algorithms=["RS256"], audience="api")


def decode_verified_options(token, key):
    # ok: traust-python-authentication-jwt-signature-unverified
    return jwt.decode(token, key, algorithms=["ES256"], options={"verify_signature": True})


def decode_skip_nbf(token, key):
    # ok: traust-python-authentication-jwt-signature-unverified
    return jwt.decode(token, key, algorithms=["RS256"], options={"verify_nbf": False})
