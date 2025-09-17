# app/extensions.py
from pyhanko.keys.pemder import load_cert_from_pemder
from pyhanko_certvalidator import ValidationContext

VC = None
ROOT_CERT = None

def init_extensions(app):
    global VC, ROOT_CERT
    root_path = app.config.get("ROOT_CERT_PATH")
    if root_path:
        ROOT_CERT = load_cert_from_pemder(root_path)
        VC = ValidationContext(trust_roots=[ROOT_CERT], allow_fetching=True)
    else:
        VC = ValidationContext(trust_roots=[], allow_fetching=True)
