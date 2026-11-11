from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from flask import Flask
from flask_wtf.csrf import CSRFProtect


# ruleid: traust-python-csrf-protection-disabled
@csrf_exempt
def transfer(request):
    return None


# ruleid: traust-python-csrf-protection-disabled
@method_decorator(csrf_exempt, name="dispatch")
class SettingsView(View):
    pass


def make_app():
    app = Flask(__name__)
    # ruleid: traust-python-csrf-protection-disabled
    app.config["WTF_CSRF_ENABLED"] = False
    protect = CSRFProtect(app)

    # ruleid: traust-python-csrf-protection-disabled
    @protect.exempt
    def rename():
        return ""

    return app


class ProductionConfig:
    # ruleid: traust-python-csrf-protection-disabled
    WTF_CSRF_ENABLED = False


class TestingConfig:
    # ok: traust-python-csrf-protection-disabled
    WTF_CSRF_ENABLED = False


def test_client():
    app = Flask(__name__)
    # ok: traust-python-csrf-protection-disabled
    app.config["WTF_CSRF_ENABLED"] = False


# ok: traust-python-csrf-protection-disabled
def summary(request):
    return None
