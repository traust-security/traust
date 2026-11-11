import yaml


def parse(doc):
    # ruleid: traust-python-input-validation-yaml-unsafe-load
    yaml.load(doc)

    # ruleid: traust-python-input-validation-yaml-unsafe-load
    yaml.load(doc, Loader=yaml.UnsafeLoader)

    # ruleid: traust-python-input-validation-yaml-unsafe-load
    yaml.unsafe_load(doc)

    # ok: traust-python-input-validation-yaml-unsafe-load
    yaml.safe_load(doc)

    # ok: traust-python-input-validation-yaml-unsafe-load
    yaml.load(doc, Loader=yaml.SafeLoader)

    # ok: traust-python-input-validation-yaml-unsafe-load
    yaml.load(open("config/defaults.yaml"))

    # ok: traust-python-input-validation-yaml-unsafe-load
    yaml.load(open("settings.yml", "r"), Loader=yaml.FullLoader)


def ruamel_roundtrip(doc):
    from ruamel.yaml import YAML
    yaml = YAML(typ="rt")

    # ok: traust-python-input-validation-yaml-unsafe-load
    yaml.load(doc)


def restore_state(request):
    import pickle
    import base64
    raw = request.body
    # ruleid: traust-python-input-validation-pickle-loads-taint
    return pickle.loads(raw)


def restore_state_encoded(request):
    import pickle
    import base64
    blob = request.form.get("state")
    # ruleid: traust-python-input-validation-pickle-loads-taint
    return pickle.loads(base64.b64decode(blob))


def load_trusted_cache(path):
    import pickle
    # ok: traust-python-input-validation-pickle-loads-taint
    with open(path, "rb") as f:
        return pickle.load(f)


def restore_with_unpickler(request):
    import io
    import pickle

    raw = request.get_data()
    # ruleid: traust-python-input-validation-pickle-loads-taint
    return pickle.Unpickler(io.BytesIO(raw)).load()


def restore_third_party(request):
    import dill
    import jsonpickle

    blob = request.form.get("state")
    # ruleid: traust-python-input-validation-pickle-loads-taint
    first = dill.loads(blob)
    # ruleid: traust-python-input-validation-pickle-loads-taint
    second = jsonpickle.decode(blob)
    return first, second


def open_shelf(request):
    import shelve

    name = request.form.get("shelf")
    # ruleid: traust-python-input-validation-pickle-loads-taint
    return shelve.open(name)


import io
import pickle


class AllowListUnpickler(pickle.Unpickler):
    # ruleid: traust-python-input-validation-restricted-unpickler-inventory
    def find_class(self, module, name):
        if (module, name) == ("collections", "OrderedDict"):
            return super().find_class(module, name)
        raise pickle.UnpicklingError(name)


def restore_subclass(request):
    raw = request.body
    # ruleid: traust-python-input-validation-pickle-loads-taint
    return AllowListUnpickler(io.BytesIO(raw)).load()


def restore_subclass_trusted(path):
    with open(path, "rb") as f:
        # ok: traust-python-input-validation-pickle-loads-taint
        return AllowListUnpickler(f).load()


class PlainLoader:
    # ok: traust-python-input-validation-restricted-unpickler-inventory
    def find_class(self, module, name):
        return None


def parse_upload(data):
    # ruleid: traust-python-input-validation-xxe-parser
    parser = etree.XMLParser(resolve_entities=True)
    # ruleid: traust-python-input-validation-xxe-parser
    remote = etree.XMLParser(no_network=False, recover=True)
    sax = xml.sax.make_parser()
    # ruleid: traust-python-input-validation-xxe-parser
    sax.setFeature(feature_external_ges, True)
    # ok: traust-python-input-validation-xxe-parser
    safe = etree.XMLParser(resolve_entities=False, no_network=True)
    # ok: traust-python-input-validation-xxe-parser
    sax.setFeature(feature_external_ges, False)
    return etree.fromstring(data, parser)
