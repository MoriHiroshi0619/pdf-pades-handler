from . import health_bp

@health_bp.route("/health", methods=["GET"])
def health():
    return {"status": "ok"}, 200
