# app/config.py
import time
from pyhanko.sign import fields

class Config:
    # constantes originais
    DEFAULT_FIELD_NAME = f"Signature - {int(time.time())}"
    DEFAULT_BYTES_RESERVED = 15302
    MD_ALGO = "sha256"
    SUBFILTER = fields.SigSeedSubFilter.PADES
