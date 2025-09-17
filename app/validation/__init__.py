# app/validation/__init__.py
from flask import Blueprint

validation_bp = Blueprint("validation", __name__)

from . import routes  # noqa: F401
