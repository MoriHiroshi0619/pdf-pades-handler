import io
import base64
import pickle
import asyncio
import traceback
import time

from flask import Flask, request, jsonify

from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import signers, fields
from pyhanko.sign.signers.pdf_signer import PdfTBSDocument

app = Flask(__name__)

DEFAULT_FIELD_NAME = f"Signature - {int(time.time())}"
DEFAULT_BYTES_RESERVED = 15302
MD_ALGO = "sha256"
SUBFILTER = fields.SigSeedSubFilter.PADES


def run_sync(maybe_awaitable):
    if asyncio.iscoroutine(maybe_awaitable):
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(maybe_awaitable)
        finally:
            loop.close()
    return maybe_awaitable


@app.route("/preparar-pdf", methods=["POST"])
def preparar_pdf():
    """
    Entrada JSON:
      { "pdf": "<base64>", "field_name": "<opcional>", "bytes_reserved": <opcional int> }

    Retorno JSON:
      {
        "prepared_pdf_b64": "...",
        "digest_b64": "...",                    # base64(raw document_digest)
        "prepared_digest_b64": "..."            # base64(pickle(prepared_digest + post_sign_instr))
      }
    """
    try:
        body = request.get_json(force=True)
        pdf_b64 = body.get("pdf")
        if not pdf_b64:
            return jsonify({"message": "campo 'pdf' (base64) é obrigatório"}), 400

        field_name = body.get("field_name", DEFAULT_FIELD_NAME)
        bytes_reserved = int(body.get("bytes_reserved", DEFAULT_BYTES_RESERVED))

        pdf_bytes = base64.b64decode(pdf_b64)

        # writer em memória
        buf_in = io.BytesIO(pdf_bytes)
        writer = IncrementalPdfFileWriter(buf_in)

        # garante campo de assinatura (invisível)
        fields.append_signature_field(
            writer,
            sig_field_spec=fields.SigFieldSpec(sig_field_name=field_name)
        )

        meta = signers.PdfSignatureMetadata(
            field_name=field_name,
            md_algorithm=MD_ALGO,
            subfilter=SUBFILTER
        )

        ext_signer = signers.ExternalSigner(
            signing_cert=None,
            cert_registry=None,
            signature_value=bytes(bytes_reserved)
        )
        pdf_signer = signers.PdfSigner(meta, signer=ext_signer)

        # digest_doc_for_signing -> (prepared_digest, tbs_document, output_io)
        result = run_sync(pdf_signer.digest_doc_for_signing(
            pdf_out=writer,
            bytes_reserved=bytes_reserved,
            in_place=False
        ))
        prepared_digest, tbs_document, output = result

        # obter bytes do pdf preparado
        output.seek(0)
        prepared_pdf_bytes = output.read()

        # serializar prepared_digest + post_sign_instructions para retornar ao cliente (Laravel)
        payload = {
            "prepared_digest": prepared_digest,
            "post_sign_instr": getattr(tbs_document, "post_sign_instructions", None)
        }
        pickled = pickle.dumps(payload, protocol=pickle.HIGHEST_PROTOCOL)
        prepared_digest_b64 = base64.b64encode(pickled).decode()

        return jsonify({
            "prepared_pdf_b64": base64.b64encode(prepared_pdf_bytes).decode(),
            "digest_b64": base64.b64encode(prepared_digest.document_digest).decode(),
            "prepared_digest_b64": prepared_digest_b64,
            "field_name": field_name,
            "bytes_reserved": bytes_reserved,
            "md_algorithm": MD_ALGO
        }), 200

    except Exception as e:
        tb = traceback.format_exc()
        return jsonify({"message": str(e), "traceback": tb}), 500


@app.route("/finalizar-assinatura", methods=["POST"])
def finalizar_assinatura():
    """
    Entrada JSON:
      {
        "prepared_pdf_b64": "...",            # retornado por /preparar-pdf (obrigatório)
        "prepared_digest_b64": "...",         # retornado por /preparar-pdf (obrigatório)
        "p7s_b64": "..."                      # .p7s retornado pela ICP (obrigatório)
      }

    Retorno JSON:
      { "pades_pdf_b64": "..." }
    """
    try:
        body = request.get_json(force=True)
        prepared_pdf_b64 = body.get("prepared_pdf_b64")
        prepared_digest_b64 = body.get("prepared_digest_b64")
        p7s_b64 = body.get("p7s_b64")

        if not (prepared_pdf_b64 and prepared_digest_b64 and p7s_b64):
            return jsonify({"message": "prepared_pdf_b64, prepared_digest_b64 e p7s_b64 são obrigatórios"}), 400

        prepared_pdf_bytes = base64.b64decode(prepared_pdf_b64)
        pickled = base64.b64decode(prepared_digest_b64)
        stored = pickle.loads(pickled)

        prepared_digest = stored.get("prepared_digest")
        post_sign_instr = stored.get("post_sign_instr")

        signature_bytes = base64.b64decode(p7s_b64)

        # em memória: inserir assinatura e obter PDF final
        buf = io.BytesIO(prepared_pdf_bytes)
        PdfTBSDocument.finish_signing(
            buf,
            prepared_digest=prepared_digest,
            signature_cms=signature_bytes,
            post_sign_instr=post_sign_instr
        )
        buf.seek(0)
        final_pdf_bytes = buf.read()

        return jsonify({
            "pades_pdf_b64": base64.b64encode(final_pdf_bytes).decode()
        }), 200

    except Exception as e:
        tb = traceback.format_exc()
        return jsonify({"message": str(e), "traceback": tb}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
