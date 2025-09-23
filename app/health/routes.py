from . import health_bp

from flask import Flask, Blueprint, jsonify
import time

@health_bp.route("/health", methods=["GET"])
def health():
    return {"status": "ok"}, 200

def sum_primes_upto(n: int) -> int:
    sieve = bytearray(b"\x01") * (n + 1)
    sieve[0:2] = b"\x00\x00"
    s = int(n**0.5) + 1
    for p in range(2, s):
        if sieve[p]:
            step = p
            start = p*p
            sieve[start:n+1:step] = b"\x00" * ((n - start)//step + 1)
    total = 0
    for i, isprime in enumerate(sieve):
        if isprime:
            total += i
    return total

@health_bp.route("/heavy", methods=["GET"])
def heavy():
    n = 200_000
    t0 = time.perf_counter()
    total = sum_primes_upto(n)
    elapsed = time.perf_counter() - t0
    return jsonify({
        "status": "ok",
        "primes_sum_upto": n,
        "primes_sum_value": total,
        "elapsed_seconds": elapsed
    }), 200