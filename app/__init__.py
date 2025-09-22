# app/__init__.py
from flask import Flask
from .signatures import signatures_bp
from .validation import validation_bp
from .health import health_bp
from .config import Config
import logging

def _silence_pyhanko():
    logging.basicConfig()
    for mod in ('pyhanko', 'pyhanko.sign', 'pyhanko.sign.validation',
                'pyhanko.sign.validation.generic_cms', 'pyhanko_certvalidator'):
        lg = logging.getLogger(mod)
        lg.setLevel(logging.CRITICAL)
        lg.propagate = False

def create_app(config_object: str | None = None):
    app = Flask(__name__, instance_relative_config=False)
    app.config.from_object(Config if config_object is None else config_object)
    _silence_pyhanko()

    app.register_blueprint(signatures_bp)
    app.register_blueprint(validation_bp)
    app.register_blueprint(health_bp)

    return app
