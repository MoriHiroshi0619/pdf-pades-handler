import hashlib

def _extract_byte_range(sig):
    br_obj = sig.sig_object.get('/ByteRange')
    if br_obj is None:
        br_obj = sig.sig_object.get('ByteRange')
    if not br_obj:
        return None
    # converter elementos para int
    return [int(x) for x in br_obj]


def _signed_content_from_byte_range(pdf_bytes: bytes, byte_range: list[int]) -> bytes | None:
    if not byte_range or len(byte_range) % 2 != 0:
        return None
    parts = []
    try:
        for i in range(0, len(byte_range), 2):
            off = int(byte_range[i])
            ln = int(byte_range[i + 1])
            if off < 0 or ln < 0 or off + ln > len(pdf_bytes):
                return None
            parts.append(pdf_bytes[off: off + ln])
        return b"".join(parts)
    except Exception:
        return None


def _canonical_sha256(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


def _digest_with_algo(data: bytes, algo_name: str) -> str | None:
    if data is None or algo_name is None:
        return None
    try:
        h = hashlib.new(algo_name)
        h.update(data)
        return h.hexdigest()
    except Exception:
        return None