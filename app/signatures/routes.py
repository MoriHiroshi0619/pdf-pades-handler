# app/signatures/routes.py
import base64
import traceback
from flask import request, jsonify, current_app
import logging
from . import signatures_bp
from .service import preparar_pdf_logic, finalizar_assinatura_logic
from ..config import Config

@signatures_bp.route("/preparar-pdf", methods=["POST"])
def preparar_pdf():
    try:
        body = request.get_json(force=True)
        pdf_b64 = body.get("pdf")
        if not pdf_b64:
            return jsonify({"message": "campo 'pdf' (base64) é obrigatório"}), 400

        field_name = body.get("field_name", current_app.config.get("DEFAULT_FIELD_NAME", Config.DEFAULT_FIELD_NAME))
        bytes_reserved = int(body.get("bytes_reserved", current_app.config.get("DEFAULT_BYTES_RESERVED", Config.DEFAULT_BYTES_RESERVED)))

        prepared_pdf_bytes, digest_bytes, pickled, field_name, bytes_reserved = preparar_pdf_logic(
            pdf_b64, field_name, bytes_reserved,
            current_app.config.get("MD_ALGO", Config.MD_ALGO),
            current_app.config.get("SUBFILTER", Config.SUBFILTER)
        )

        prepared_digest_b64 = base64.b64encode(pickled).decode()

        return jsonify({
            "prepared_pdf_b64": base64.b64encode(prepared_pdf_bytes).decode(),
            "digest_b64": base64.b64encode(digest_bytes).decode(),
            "prepared_digest_b64": prepared_digest_b64,
            "field_name": field_name,
            "bytes_reserved": bytes_reserved,
            "md_algorithm": current_app.config.get("MD_ALGO", Config.MD_ALGO)
        }), 200

    except Exception as e:
        tb = traceback.format_exc()
        logging.error(tb)
        return jsonify({"message": str(e), "traceback": tb}), 500


@signatures_bp.route("/finalizar-assinatura", methods=["POST"])
def finalizar_assinatura():
    try:
        body = request.get_json(force=True)
        prepared_pdf_b64 = body.get("prepared_pdf_b64")
        prepared_digest_b64 = body.get("prepared_digest_b64")
        p7s_b64 = body.get("p7s_b64")

        if not (prepared_pdf_b64 and prepared_digest_b64 and p7s_b64):
            return jsonify({"message": "prepared_pdf_b64, prepared_digest_b64 e p7s_b64 são obrigatórios"}), 400

        final_pdf_bytes = finalizar_assinatura_logic(prepared_pdf_b64, prepared_digest_b64, p7s_b64)

        return jsonify({
            "pades_pdf_b64": base64.b64encode(final_pdf_bytes).decode()
        }), 200

    except Exception as e:
        tb = traceback.format_exc()
        logging.error(tb)
        return jsonify({"message": str(e), "traceback": tb}), 500
