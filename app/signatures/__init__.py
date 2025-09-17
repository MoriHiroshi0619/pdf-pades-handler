# app/signatures/__init__.py
from flask import Blueprint

signatures_bp = Blueprint("signatures", __name__)

# importa as rotas para registrar no blueprint
from . import routes  # noqa: F401
