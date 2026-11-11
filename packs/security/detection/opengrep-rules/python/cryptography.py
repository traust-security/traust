import requests


def fetch(url, session):
    # ruleid: traust-python-cryptography-requests-verify-false
    requests.get(url, verify=False)

    # ruleid: traust-python-cryptography-requests-verify-false
    session.verify = False

    # ok: traust-python-cryptography-requests-verify-false
    requests.get(url, timeout=30)

    # ok: traust-python-cryptography-requests-verify-false
    requests.get(url, verify="/etc/pki/ca-trust/custom.pem")


def irc_factory(sock, host):
    import ssl
    import functools
    # ruleid: traust-python-cryptography-ssl-wrap-socket
    wrapper = ssl.wrap_socket

    # ruleid: traust-python-cryptography-ssl-wrap-socket
    ssl.wrap_socket(sock)

    # ok: traust-python-cryptography-ssl-wrap-socket
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # ok: traust-python-cryptography-ssl-wrap-socket
    wrapper = functools.partial(ctx.wrap_socket, server_hostname=host)
    return wrapper


def build_dsn(user, host):
    # ruleid: traust-python-cryptography-insecure-dsn-transport
    dsn = f"postgresql://{user}@{host}:5432/app?sslmode=disable"

    # ruleid: traust-python-cryptography-insecure-dsn-transport
    mysql_dsn = "mysql+pymysql://app@db/app?ssl-mode=DISABLED"

    # ok: traust-python-cryptography-insecure-dsn-transport
    safe = f"postgresql://{user}@{host}:5432/app?sslmode=verify-full"
    return dsn, mysql_dsn, safe


def check_credentials(record, supplied_token, supplied_password, expected_mac, request):
    import hmac
    import secrets

    # ruleid: traust-python-cryptography-secret-compare-not-constant-time
    if supplied_token == record.api_token:
        return True

    # ruleid: traust-python-cryptography-secret-compare-not-constant-time
    if record.password_hash != supplied_password:
        return False

    # ruleid: traust-python-cryptography-secret-compare-not-constant-time
    if request.headers.get("X-Signature") == expected_mac:
        return True

    # ok: traust-python-cryptography-secret-compare-not-constant-time
    if hmac.compare_digest(supplied_token, record.api_token):
        return True

    # ok: traust-python-cryptography-secret-compare-not-constant-time
    if secrets.compare_digest(expected_mac, supplied_password):
        return True

    # ok: traust-python-cryptography-secret-compare-not-constant-time
    if record.token_type == "bearer":
        return True

    # ok: traust-python-cryptography-secret-compare-not-constant-time
    if supplied_token is None or supplied_token == "":
        return False

    # ok: traust-python-cryptography-secret-compare-not-constant-time
    if record.token_type != supplied_token_type:
        return False

    # ok: traust-python-cryptography-secret-compare-not-constant-time
    if len(supplied_token) != 32:
        return False

    # ok: traust-python-cryptography-secret-compare-not-constant-time
    if record.machine == supplied_machine:
        return False

    # ok: traust-python-cryptography-secret-compare-not-constant-time
    if settings.AUTH_MODE == AUTH_MODES.TOKEN:
        return False

    # ok: traust-python-cryptography-secret-compare-not-constant-time
    if order_token == parser.ASC_OPERATOR or completion_tokens == limit:
        return False

    # ok: traust-python-cryptography-secret-compare-not-constant-time
    if dataset.digest == metric.dataset_digest:
        return False

    # ok: traust-python-cryptography-secret-compare-not-constant-time
    if record.signature_kind == SignatureKind.DETACHED:
        return False
    return None


def test_round_trip(loaded, expected_signature):
    # ok: traust-python-cryptography-secret-compare-not-constant-time
    assert loaded.signature == expected_signature


def make_reset():
    # ruleid: traust-python-cryptography-weak-random-secret
    reset_token = "".join(random.choices(ALPHABET, k=32))
    # ruleid: traust-python-cryptography-weak-random-secret
    otp = random.randint(100000, 999999)
    # ok: traust-python-cryptography-weak-random-secret
    reset_token = secrets.token_urlsafe(32)
    # ok: traust-python-cryptography-weak-random-secret
    jitter = random.random()
    return reset_token


def digest(blob, password):
    # ruleid: traust-python-cryptography-weak-hash
    stored = hashlib.md5(password.encode()).hexdigest()
    # ok: traust-python-cryptography-weak-hash
    etag = hashlib.md5(blob, usedforsecurity=False).hexdigest()
    # ok: traust-python-cryptography-weak-hash
    strong = hashlib.sha256(blob).hexdigest()
    return stored, etag, strong
