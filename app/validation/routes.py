# app/validation/routes.py
import io
import base64
import traceback
from flask import request, jsonify
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import validation

from ..extensions import VC
from . import validation_bp

@validation_bp.route('/validar-pades', methods=['POST'])
def validar_pades():
    json_data = request.get_json(silent=True)
    if not json_data or 'pdf_base64' not in json_data:
        return jsonify({'status': 'erro', 'message': 'A chave "pdf_base64" é obrigatória.'}), 400

    pdf_bytes = base64.b64decode(json_data['pdf_base64'])

    try:
        reader = PdfFileReader(io.BytesIO(pdf_bytes))

        # Verifica se há assinaturas no PDF
        if not reader.embedded_signatures:
            return jsonify({'status': 'sucesso', 'assinado': False,
                            'message': 'O documento PDF não contém nenhuma assinatura.'}), 200

        validation_results = []
        # Itera sobre todas as assinaturas encontradas
        for sig in reader.embedded_signatures:
            # valida a assinatura usando o ValidationContext inicializado em extensions
            status = validation.validate_pdf_signature(sig, signer_validation_context=VC)

            validation_results.append({
                'nome_assinante': getattr(sig.signer_cert, 'subject', None) and sig.signer_cert.subject.human_friendly,
                'formato_pades': sig.sig_object.get('/SubFilter') == '/ETSI.CAdES.detached',
                'timestamp': getattr(status, 'signer_reported_dt', None),
                'valido': bool(getattr(status, 'bottom_line', False)),
                'intacto': bool(getattr(status, 'intact', None)),
                'confiavel': getattr(status, 'trusted', None),
                'resumo_validacao': status.summary() if hasattr(status, 'summary') else None,
                'erros': [str(e) for e in getattr(status, 'errors', [])] if getattr(status, 'errors', None) else [],
                'avisos': [str(w) for w in getattr(status, 'warnings', [])] if getattr(status, 'warnings', None) else [],
            })

        return jsonify({'status': 'sucesso', 'assinado': True, 'validacoes': validation_results}), 200

    except Exception as e:
        tb = traceback.format_exc()
        return jsonify({'status': 'erro', 'message': f'Ocorreu um erro ao processar o PDF: {e}', 'traceback': tb}), 500
