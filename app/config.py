# app/config.py
import time
from pyhanko.sign import fields
from pyhanko_certvalidator import ValidationContext

class Config:
    DEFAULT_FIELD_NAME = f"Signature - {int(time.time())}"
    DEFAULT_BYTES_RESERVED = 15302
    MD_ALGO = "sha256"
    SUBFILTER = fields.SigSeedSubFilter.PADES
    VC = ValidationContext(trust_roots=[], allow_fetching=False)
    ERROR_BYTES_INSUFFICIENT = "Final ByteRange payload larger than expected"