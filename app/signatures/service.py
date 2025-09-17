# app/signatures/service.py
import io
import base64
import pickle
import time
import traceback

from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import signers, fields
from pyhanko.sign.signers.pdf_signer import PdfTBSDocument

from ..utils import run_sync

def preparar_pdf_logic(pdf_b64: str, field_name: str, bytes_reserved: int, md_algo: str, subfilter):
    """
    Lógica extraída do endpoint /preparar-pdf.
    Retorna (prepared_pdf_bytes, digest_bytes, pickled_payload, field_name, bytes_reserved)
    """
    pdf_bytes = base64.b64decode(pdf_b64)

    buf_in = io.BytesIO(pdf_bytes)
    writer = IncrementalPdfFileWriter(buf_in)

    # garante campo de assinatura (invisível)
    fields.append_signature_field(
        writer,
        sig_field_spec=fields.SigFieldSpec(sig_field_name=field_name)
    )

    meta = signers.PdfSignatureMetadata(
        field_name=field_name,
        md_algorithm=md_algo,
        subfilter=subfilter
    )

    ext_signer = signers.ExternalSigner(
        signing_cert=None,
        cert_registry=None,
        signature_value=bytes(bytes_reserved)
    )
    pdf_signer = signers.PdfSigner(meta, signer=ext_signer)

    result = run_sync(pdf_signer.digest_doc_for_signing(
        pdf_out=writer,
        bytes_reserved=bytes_reserved,
        in_place=False
    ))
    prepared_digest, tbs_document, output = result

    output.seek(0)
    prepared_pdf_bytes = output.read()

    payload = {
        "prepared_digest": prepared_digest,
        "post_sign_instr": getattr(tbs_document, "post_sign_instructions", None)
    }
    # ATENÇÃO: estamos usando pickle por decisão do usuário (consumo interno)
    pickled = pickle.dumps(payload, protocol=pickle.HIGHEST_PROTOCOL)

    return prepared_pdf_bytes, prepared_digest.document_digest, pickled, field_name, bytes_reserved


def finalizar_assinatura_logic(prepared_pdf_b64: str, prepared_digest_pickled_b64: str, p7s_b64: str):
    """
    Lógica do endpoint /finalizar-assinatura
    Retorna final_pdf_bytes
    """
    prepared_pdf_bytes = base64.b64decode(prepared_pdf_b64)
    pickled = base64.b64decode(prepared_digest_pickled_b64)
    stored = pickle.loads(pickled)

    prepared_digest = stored.get("prepared_digest")
    post_sign_instr = stored.get("post_sign_instr")

    signature_bytes = base64.b64decode(p7s_b64)

    buf = io.BytesIO(prepared_pdf_bytes)
    PdfTBSDocument.finish_signing(
        buf,
        prepared_digest=prepared_digest,
        signature_cms=signature_bytes,
        post_sign_instr=post_sign_instr
    )
    buf.seek(0)
    final_pdf_bytes = buf.read()
    return final_pdf_bytes
