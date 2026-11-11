import logging

logger = logging.getLogger(__name__)
log = logger


def startup(password, sasl_password, token_url, replica_count, headers):
    # ruleid: traust-python-data-exposure-secret-in-log
    logger.info("connecting with %s", password)

    # ruleid: traust-python-data-exposure-secret-in-log
    logging.debug("sasl config: %s", sasl_password)

    # ruleid: traust-python-data-exposure-secret-in-log
    print("pw:", password)

    # ruleid: traust-python-data-exposure-secret-in-log
    logger.error(f"auth failed for token {api_token}")

    # ruleid: traust-python-data-exposure-secret-in-log
    log.warning("db config %s", config["password"])

    # %-formatted operand naming a credential
    # ruleid: traust-python-data-exposure-secret-in-log
    log.info("access %s secret %s" % (access_key, secret_key))

    # ok: traust-python-data-exposure-secret-in-log
    logger.info("requesting token from %s", token_url)

    # ok: traust-python-data-exposure-secret-in-log
    logger.info("scaled to %d replicas", replica_count)

    # ok: traust-python-data-exposure-secret-in-log
    logger.error(f"request failed with headers count {len(headers)}")

    # ok: traust-python-data-exposure-secret-in-log
    logger.info("masked credential %s", mask(password))

    # ok: traust-python-data-exposure-secret-in-log
    logger.info("mounted secret %s", secret_name)


def credential_metadata(access_token_obj, masked_secret, token_length):
    # credential-adjacent metadata / pre-masked values (2026-07-29
    # dismissal classes) — identity and lifecycle facts, not the value
    # ok: traust-python-data-exposure-secret-in-log
    logger.debug("token length: %d", token_length)

    # ok: traust-python-data-exposure-secret-in-log
    logger.debug("token scopes: %s", access_token_obj.scopes)

    # ok: traust-python-data-exposure-secret-in-log
    logger.debug("token expiry: %s", access_token_obj.expires_at)

    # ok: traust-python-data-exposure-secret-in-log
    logger.debug("credentials: %s", masked_secret)
