# app/config.py
import time
from pyhanko.sign import fields

class Config:
    # constantes originais
    DEFAULT_FIELD_NAME = f"Signature - {int(time.time())}"
    DEFAULT_BYTES_RESERVED = 15302
    MD_ALGO = "sha256"
    SUBFILTER = fields.SigSeedSubFilter.PADES

    # path do root cert (ajuste conforme ambiente)
    ROOT_CERT_PATH = "/home/hiroshi/Downloads/ICP-Brasilv5.crt"

    # segurança / limites
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10 MB, ajuste se preciso
