import aiohttp_cors
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from flask import Flask
from flask_cors import CORS, cross_origin

api = FastAPI()
# ruleid: traust-python-cors-any-origin-with-credentials
api.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"])
# ruleid: traust-python-cors-any-origin-with-credentials
api.add_middleware(CORSMiddleware, allow_credentials=True, allow_origin_regex=".*")
# ok: traust-python-cors-any-origin-with-credentials
api.add_middleware(CORSMiddleware, allow_origins=["https://app.example.org"], allow_credentials=True)
# ok: traust-python-cors-any-origin-with-credentials
api.add_middleware(CORSMiddleware, allow_origins=["*"])

site = Flask(__name__)
# ruleid: traust-python-cors-any-origin-with-credentials
CORS(site, supports_credentials=True)
# ok: traust-python-cors-any-origin-with-credentials
CORS(site, origins=["https://app.example.org"], supports_credentials=True)


# ruleid: traust-python-cors-any-origin-with-credentials
@cross_origin(supports_credentials=True)
def balance():
    return {}


def setup(app):
    # ruleid: traust-python-cors-any-origin-with-credentials
    aiohttp_cors.setup(app, defaults={"*": aiohttp_cors.ResourceOptions(allow_credentials=True, expose_headers="*")})
