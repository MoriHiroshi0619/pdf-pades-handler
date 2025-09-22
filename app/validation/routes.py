# app/validation/routes.py
import io
import base64
import traceback
from flask import request, jsonify
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import validation
import logging
from ..config import Config
from .service import _signed_content_from_byte_range, _extract_byte_range, _canonical_sha256, _digest_with_algo
from . import validation_bp

@validation_bp.route('/validar-pades', methods=['POST'])
def validar_pades():
    json_data = request.get_json(silent=True)
    if not json_data or 'pdf_base64' not in json_data:
        return jsonify({'status': 'erro', 'message': 'A chave "pdf_base64" é obrigatória.'}), 400

    try:
        pdf_bytes = base64.b64decode(json_data['pdf_base64'])

        reader = PdfFileReader(io.BytesIO(pdf_bytes))

        # Verifica se há assinaturas no PDF
        if not reader.embedded_signatures:
            return jsonify({'assinado': False,
                            'message': 'O documento PDF não contém nenhuma assinatura.'}), 200

        validation_results = []
        for sig in reader.embedded_signatures:
            status = validation.validate_pdf_signature(sig, signer_validation_context=Config.VC, skip_diff=True)

            validation_results.append({
                'nome_assinante': getattr(sig.signer_cert, 'subject', None) and sig.signer_cert.subject.native.get("common_name"),
                'timestamp': getattr(status, 'signer_reported_dt', None),
                'valido': bool(getattr(status, 'valid', False)),
                'intacto': bool(getattr(status, 'intact', None)),
                'pkcs7_signature_mechanism': getattr(status, 'pkcs7_signature_mechanism', None),
                'md_algorithm': getattr(status, 'md_algorithm', None),
                'resumo_validacao': status.summary() if hasattr(status, 'summary') else None,
                'erros': [str(e) for e in getattr(status, 'errors', [])] if getattr(status, 'errors', None) else [],
                'avisos': [str(w) for w in getattr(status, 'warnings', [])] if getattr(status, 'warnings', None) else [],
            })

        return jsonify({'assinado': True, 'validacoes': validation_results}), 200

    except Exception as e:
        tb = traceback.format_exc()
        logging.error(tb)
        return jsonify({'status': 'erro', 'message': f'Ocorreu um erro ao processar o PDF: {e}', 'traceback': tb}), 500

@validation_bp.route('/comparar-assinatura', methods=['POST'])
def comparar_assinatura():
    json_data = request.get_json(silent=True)
    if not json_data or 'pdf_original_b64' not in json_data or 'pdf_validar_b64' not in json_data:
        return jsonify({
            'status': 'erro',
            'message': 'As chaves "pdf_original_b64" e "pdf_validar_b64" (base64) são obrigatórias.'
        }), 400

    try:
        pdf_original_b64 = json_data['pdf_original_b64']
        pdf_para_validar_b64 = json_data['pdf_validar_b64']

        original_bytes = base64.b64decode(pdf_original_b64)
        validar_bytes = base64.b64decode(pdf_para_validar_b64)

        # readers
        reader_orig = PdfFileReader(io.BytesIO(original_bytes))
        reader_val = PdfFileReader(io.BytesIO(validar_bytes))

        if not reader_orig.embedded_signatures:
            return jsonify({'status': 'erro', 'message': 'O pdf original não contém assinatura.'}), 400

        original_signatures = list(reader_orig.embedded_signatures)
        original_multi = len(original_signatures) > 1
        ref_sig = original_signatures[0]

        orig_status = validation.validate_pdf_signature(ref_sig, signer_validation_context=Config.VC, skip_diff=True)

        # extrair conteúdo assinado do original
        orig_br = _extract_byte_range(ref_sig)
        orig_signed_content = _signed_content_from_byte_range(original_bytes, orig_br) if orig_br else None
        orig_canonical = _canonical_sha256(orig_signed_content) if orig_signed_content is not None else None

        # também tenta calcular o digest com o algoritmo da assinatura (se disponível)
        orig_md_algo = getattr(orig_status, 'md_algorithm', None) if orig_status is not None else None
        orig_algo_digest = _digest_with_algo(orig_signed_content, orig_md_algo)

        # preparar resposta do original
        original_info = {
            'assinado': True,
            'assinaturas_totais': len(original_signatures),
            'original_multi': original_multi,
            'nome_assinante': getattr(ref_sig.signer_cert, 'subject', None) and ref_sig.signer_cert.subject.native.get("common_name"),
            'valido': bool(getattr(orig_status, 'valid', False)) if orig_status is not None else None,
            'intacto': bool(getattr(orig_status, 'intact', False)) if orig_status is not None else None,
            'md_algorithm': orig_md_algo,
            'digest_algo_hexdigest': orig_algo_digest,
            'canonical_sha256': orig_canonical,
            'byte_range': orig_br,
        }

        # processar assinaturas do pdfParaValidar
        validar_signatures = list(reader_val.embedded_signatures) if reader_val.embedded_signatures else []
        if not validar_signatures:
            return jsonify({
                'status': 'erro',
                'message': 'pdf enviado para validar não contém assinaturas.',
            }), 200

        results = []
        any_match = False
        for idx, sig in enumerate(validar_signatures):
            try:
                st = validation.validate_pdf_signature(sig, signer_validation_context=Config.VC, skip_diff=True)
            except Exception:
                st = None

            br = _extract_byte_range(sig)
            signed_content = _signed_content_from_byte_range(validar_bytes, br) if br else None
            canonical = _canonical_sha256(signed_content) if signed_content is not None else None

            md_algo = getattr(st, 'md_algorithm', None) if st is not None else None
            algo_digest = _digest_with_algo(signed_content, md_algo)

            matches_original = False
            # se temos canonical para ambos, comparar by canonical (SHA-256)
            if orig_canonical is not None and canonical is not None:
                matches_original = (orig_canonical == canonical)
            else:
                # fallback: se ambos têm digest pelo algoritmo declarado e os algoritmos coincidem, comparar esses digests
                if orig_algo_digest and algo_digest and (orig_md_algo and md_algo) and (orig_md_algo == md_algo):
                    matches_original = (orig_algo_digest == algo_digest)
                else:
                    matches_original = False

            if matches_original:
                any_match = True

            results.append({
                'nome_assinante': getattr(sig.signer_cert, 'subject', None) and sig.signer_cert.subject.native.get("common_name"),
                'valido': bool(getattr(st, 'valid', False)) if st is not None else None,
                'intacto': bool(getattr(st, 'intact', False)) if st is not None else None,
                'md_algorithm': md_algo,
                'digest_algo_hexdigest': algo_digest,
                'canonical_sha256': canonical,
                'byte_range': br,
                'matches_original': matches_original,
                'resumo_validacao': st.summary() if (st is not None and hasattr(st, 'summary')) else None,
                'erros': [str(e) for e in getattr(st, 'errors', [])] if (st is not None and getattr(st, 'errors', None)) else [],
                'avisos': [str(w) for w in getattr(st, 'warnings', [])] if (st is not None and getattr(st, 'warnings', None)) else [],
            })

        return jsonify({
            'status': 'sucesso',
            'match': any_match,
            'original': original_info,
            'para_validar': {
                'assinado': True,
                'signatures': results,
            }
        }), 200

    except Exception as e:
        tb = traceback.format_exc()
        logging.error(tb)
        return jsonify({'status': 'erro', 'message': f'Ocorreu um erro ao comparar assinaturas: {e}', 'traceback': tb}), 500
