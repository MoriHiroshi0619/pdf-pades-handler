import os
import io
import uuid
import base64
import pickle
import tempfile
import asyncio
from flask import Flask, request, jsonify
from pathlib import Path

from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import signers, fields
from pyhanko.sign.signers.pdf_signer import PdfTBSDocument

TASK_DIR = Path(tempfile.gettempdir()) / "pades_tasks"
TASK_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)

# util para lidar com coroutines (algumas versões do pyhanko expõem APIs async)
def run_sync(maybe_awaitable):
    if asyncio.iscoroutine(maybe_awaitable):
        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
            return loop.run_until_complete(maybe_awaitable)
        finally:
            loop.close()
    return maybe_awaitable

@app.route('/preparar-pdf', methods=['POST'])
def preparar_pdf():
    """
    Recebe JSON:
    {
      "pdf_b64": "...",
      "field_name": "Signature1",          # opcional
      "bytes_reserved": 8192                # opcional
    }
    Retorna JSON com task_id, digest_b64 e prepared_pdf_b64.
    """
    print("\n\nRecebido endpoint /preparar-pdf")
    body = request.get_json(force=True)
    pdf_b64 = body['pdf']
    field_name = body.get('field_name', 'Signature1')
    bytes_reserved = int(body.get('bytes_reserved', 15302))

    pdf_bytes = base64.b64decode(pdf_b64)

    # writer em memória
    buf_in = io.BytesIO(pdf_bytes)
    writer = IncrementalPdfFileWriter(buf_in)

    # garante que existe um campo de assinatura visível/invisível
    fields.append_signature_field(
        writer,
        sig_field_spec=fields.SigFieldSpec(sig_field_name=field_name)
    )

    # metadata para PAdES (use PADES para subfilter ETSI.CAdES.detached)
    meta = signers.PdfSignatureMetadata(
        field_name=field_name,
        md_algorithm='sha256',
        subfilter=fields.SigSeedSubFilter.ADOBE_PKCS7_DETACHED
    )

    # ExternalSigner com placeholder do tamanho estimado
    ext_signer = signers.ExternalSigner(
        signing_cert=None,
        cert_registry=None,
        signature_value=bytes(bytes_reserved)
    )
    pdf_signer = signers.PdfSigner(meta, signer=ext_signer)

    try:
        # digest_doc_for_signing pode ser sync ou async dependendo da versão
        result = run_sync(pdf_signer.digest_doc_for_signing(
            pdf_out=writer,
            bytes_reserved=bytes_reserved,
            in_place=False
        ))

        prepared_digest, tbs_document, output = result
        # output é um io.BytesIO com o PDF preparado
        output.seek(0)
        prepared_pdf_bytes = output.read()

        # persistir estado para finalizar depois
        task_id = str(uuid.uuid4())
        with open(TASK_DIR / f"{task_id}.prepared.pdf", "wb") as f:
            f.write(prepared_pdf_bytes)
        # grave o prepared_digest + post_sign_instructions (pickle)
        stored = {
            "prepared_digest": prepared_digest,
            "post_sign_instr": getattr(tbs_document, "post_sign_instructions", None)
        }
        with open(TASK_DIR / f"{task_id}.state.pkl", "wb") as f:
            pickle.dump(stored, f, protocol=pickle.HIGHEST_PROTOCOL)

        return jsonify({
            "task_id": task_id,
            "prepared_pdf_b64": base64.b64encode(prepared_pdf_bytes).decode(),
            "digest_b64": base64.b64encode(prepared_digest.document_digest).decode()
        }), 200

    except Exception as e:
        return jsonify({"error": repr(e)}), 500


@app.route('/finalizar-assinatura', methods=['POST'])
def finalizar_assinatura():
    """
    Recebe JSON:
    {
      "task_id": "...",           # id retornado em preparar-pdf
      "p7s_b64": "..."            # o conteúdo .p7s retornado pelo integra ICP (base64)
      # opcional: "prepared_pdf_b64": "..." (se quiser enviar o pdf preparado de novo)
    }
    Retorna final PDF (PAdES) em base64.
    """
    print("\n\nRecebido endpoint /finalizar-assinatura")
    body = request.get_json(force=True)
    task_id = body['task_id']
    p7s_b64 = body['p7s_b64']
    prepared_pdf_b64 = body.get('prepared_pdf_b64')

    state_path = TASK_DIR / f"{task_id}.state.pkl"
    prepared_pdf_path = TASK_DIR / f"{task_id}.prepared.pdf"

    if prepared_pdf_b64:
        prepared_pdf_bytes = base64.b64decode(prepared_pdf_b64)
    else:
        if not prepared_pdf_path.exists() or not state_path.exists():
            return jsonify({"error": "task_id não encontrado ou estado expirado"}), 404
        prepared_pdf_bytes = prepared_pdf_path.read_bytes()

    with open(state_path, "rb") as f:
        stored = pickle.load(f)

    prepared_digest = stored["prepared_digest"]
    post_sign_instr = stored.get("post_sign_instr")

    signature_bytes = base64.b64decode(p7s_b64)

    try:
        buf = io.BytesIO(prepared_pdf_bytes)
        # finish_signing insere a CMS no local reservado e retorna o pdf final no buffer
        PdfTBSDocument.finish_signing(
            buf,
            prepared_digest=prepared_digest,
            signature_cms=signature_bytes,
            post_sign_instr=post_sign_instr
        )
        buf.seek(0)
        final_pdf = buf.read()

        # opcional: limpar arquivos temporários
        try:
            prepared_pdf_path.unlink(missing_ok=True)
            state_path.unlink(missing_ok=True)
        except Exception:
            pass

        return jsonify({
            "pades_pdf_b64": base64.b64encode(final_pdf).decode()
        }), 200

    except Exception as e:
        return jsonify({"error": repr(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
