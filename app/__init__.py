# app/__init__.py
from flask import Flask
from .extensions import init_extensions
from .signatures import signatures_bp
from .validation import validation_bp
from .config import Config

def create_app(config_object: str | None = None):
    app = Flask(__name__, instance_relative_config=False)
    app.config.from_object(Config if config_object is None else config_object)

    # inicializa extensões/objetos globais (VC, logging, etc)
    init_extensions(app)

    # registrando blueprints (não use prefix para manter rotas iguais)
    app.register_blueprint(signatures_bp)
    app.register_blueprint(validation_bp)

    return app
