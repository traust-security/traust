import os
import urllib.request
from urllib.parse import urlparse

import requests
from django.conf import settings
from flask import request


def proxy():
    target = request.args.get("url")
    # ruleid: traust-python-ssrf-request-taint
    requests.get(target)

    # ruleid: traust-python-ssrf-request-taint
    requests.post("https://" + request.form.get("backend") + "/api")

    # ok: traust-python-ssrf-request-taint
    requests.get("https://api.openshift.com/healthz")


def proxy_json():
    body = request.get_json(force=True)
    # ruleid: traust-python-ssrf-request-taint
    requests.get(body["url"], timeout=5)


def import_feed(db):
    row = db.execute("SELECT url FROM feeds WHERE workspace = ?", ("w",)).fetchone()
    # ruleid: traust-python-ssrf-stored-url
    requests.get(row["url"], timeout=10)


def import_feed_from_handler(db):
    options = request.get_json(force=True)
    row = db.execute("SELECT url FROM feeds WHERE id = ?", (options["id"],)).fetchone()
    # ruleid: traust-python-ssrf-stored-url
    requests.get(row["url"], timeout=10)


def deliver_webhook(hook):
    # ruleid: traust-python-ssrf-stored-url
    requests.post(hook.callback_url, json={}, timeout=5)


def health(app_config, row):
    # ok: traust-python-ssrf-stored-url
    requests.get(app_config["HEALTH_URL"], timeout=5)
    # ok: traust-python-ssrf-stored-url
    requests.get(settings.STATUS_URL, timeout=5)
    # ok: traust-python-ssrf-stored-url
    requests.get(os.environ["UPSTREAM_URL"], timeout=5)
    # ok: traust-python-ssrf-stored-url
    requests.get(row["name"], timeout=5)


def follow(url, req):
    # ok: traust-python-ssrf-stored-url
    requests.get(urlparse(url).geturl(), timeout=5)
    # ok: traust-python-ssrf-stored-url
    requests.get(req.links["next"]["url"], timeout=5)


def notify(subscription):
    # ruleid: traust-python-ssrf-stored-url
    requests.post(subscription.webhookUrl, json={}, timeout=5)


def fetch_avatar(profile):
    # ruleid: traust-python-ssrf-stored-url
    return urllib.request.urlopen(profile.avatar_url, timeout=5).read()
