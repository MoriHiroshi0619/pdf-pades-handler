import requests
import time
from multiprocessing import Pool
import argparse

def do_request(args):
    idx, url, timeout = args
    try:
        t0 = time.perf_counter()
        with requests.Session() as s:
            r = s.get(url, timeout=timeout)
            elapsed = time.perf_counter() - t0
            return idx, r.status_code, elapsed, None
    except Exception as e:
        elapsed = None
        return idx, None, elapsed, str(e)

def run_load_test(base_url, endpoint="/heavy", num_requests=100, concurrency=3, timeout=30):
    url = base_url.rstrip("/") + endpoint
    print(f"Testing {num_requests} requests to: {url} with concurrency={concurrency}")
    args_list = [(i, url, timeout) for i in range(num_requests)]

    t_start = time.perf_counter()
    results = []
    with Pool(processes=concurrency) as pool:
        results = pool.map(do_request, args_list)
    t_end = time.perf_counter()
    total_elapsed = t_end - t_start

    successes = [r for r in results if r[1] == 200]
    failures = [r for r in results if r[1] != 200]
    per_req_times = [r[2] for r in results if r[2] is not None]

    print("=== RESULTS ===")
    print(f"Requests attempted: {len(results)}")
    print(f"Successful (HTTP 200): {len(successes)}")
    print(f"Failures or non-200: {len(failures)}")
    print(f"Total wall-clock time for all requests to complete: {total_elapsed:.3f} s")
    if per_req_times:
        print(f"Min per-request: {min(per_req_times):.3f} s")
        print(f"Max per-request: {max(per_req_times):.3f} s")
        print(f"Avg per-request: {sum(per_req_times)/len(per_req_times):.3f} s")
    else:
        print("No per-request timing available (all failed).")

    if failures:
        print("\nFalhas (algumas):")
        for f in failures[:10]:
            print(f" idx={f[0]} status={f[1]} err={f[3]}")

    return {
        "total_elapsed": total_elapsed,
        "results": results
    }

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple load test script (multiprocessing Pool)")
    parser.add_argument("--host", default="http://127.0.0.1:5000", help="Base host ex(http://127.0.0.1:5000)")
    parser.add_argument("--endpoint", default="/heavy", help="Endpoint path to hit")
    parser.add_argument("--n", type=int, default=100, help="Number of requests")
    parser.add_argument("--c", type=int, default=3, help="Concurrency (processes)")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout (seconds)")
    args = parser.parse_args()

    run_load_test(args.host, endpoint=args.endpoint, num_requests=args.n, concurrency=args.c, timeout=args.timeout)
