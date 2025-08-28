# converter_corrigido.py
from io import BytesIO
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign.signers.cms_embedder import (
    PdfCMSEmbedder,
    SigObjSetup,
    SigIOSetup,
)
from pyhanko.sign.signers.pdf_byterange import SignatureObject
from pyhanko.sign import fields

ARQUIVO_PDF_ORIGINAL = 'documento.pdf'
ARQUIVO_P7S = 'assinatura.p7s'
ARQUIVO_PDF_SAIDA = 'documento_assinado_pades.pdf'

print(">>> Iniciando conversão .p7s -> PAdES (embed CMS usando PdfCMSEmbedder)")

try:
    with open(ARQUIVO_P7S, 'rb') as f:
        p7s_content: bytes = f.read()
    print(f"lido {len(p7s_content)} bytes do {ARQUIVO_P7S}")

    # abrir PDF de entrada
    with open(ARQUIVO_PDF_ORIGINAL, 'rb') as inf:
        w = IncrementalPdfFileWriter(inf)

        # cria o embedder
        embedder = PdfCMSEmbedder()

        # iniciar o gerador. se você quiser preencher um campo existente, passe field_name='NomeDoCampo'
        gen = embedder.write_cms(field_name="Assinatura1", writer=w, existing_fields_only=False)

        # 1) o gerador devolve uma referência ao campo (ou similar) — ignoramos o valor, apenas avançamos
        field_ref = next(gen)

        # 2) enviar SigObjSetup com um placeholder (assinalamos bytes_reserved suficiente)
        #    como o /Contents é escrito em hex, reserve pelo menos 2x o tamanho DER do CMS.
        reserve = max(len(p7s_content) * 2, 16 * 1024)  # 16 KiB mínimo
        sig_placeholder = SignatureObject(
            bytes_reserved=reserve,
            subfilter=fields.SigSeedSubFilter.ETSI_CADES
        )
        sig_obj_setup = SigObjSetup(sig_placeholder=sig_placeholder)
        sig_dict_ref = gen.send(sig_obj_setup)

        # 3) enviar SigIOSetup: gerador escreverá o PDF com placeholder e retornará digest preparado + stream de saída
        #    Ajuste md_algorithm para o algoritmo usado no seu .p7s (sha256 é o caso mais comum).
        #    Aqui escrevemos direto para o arquivo de saída.
        with open(ARQUIVO_PDF_SAIDA, 'wb') as outf:
            io_setup = SigIOSetup(md_algorithm='sha256', in_place=False, output=outf)
            prepared_digest, output_stream = gen.send(io_setup)

            # prepared_digest contém o hash que foi calculado sobre o PDF (PreparedByteRangeDigest).
            # Se você tivesse que gerar um CMS a partir desse digest (remote signer), usaria-o.
            print("prepared digest length:", len(prepared_digest.document_digest))

            # 4) enviar os bytes do CMS (.p7s). O gerador coloca esses bytes no /Contents e conclui.
            contents_hex = gen.send(p7s_content)

            # contents_hex é a string hex que foi escrita no /Contents (útil para debug)
            print("conteúdo do /Contents escrito (hex) com tamanho:", len(contents_hex))

    print(">>> Concluído. PDF de saída:", ARQUIVO_PDF_SAIDA)

except FileNotFoundError as e:
    print("Arquivo não encontrado:", e.filename)
except Exception as e:
    import traceback
    print("Erro inesperado:", repr(e))
    traceback.print_exc()
