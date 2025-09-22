import multiprocessing
import os

CPU_COUNT = multiprocessing.cpu_count()

workers = int(os.getenv("GUNICORN_WORKERS", max(1, CPU_COUNT)))

threads = int(os.getenv("GUNICORN_THREADS", 2))

bind = os.getenv("GUNICORN_BIND", "0.0.0.0:8005")

timeout = int(os.getenv("GUNICORN_TIMEOUT", 30))
keepalive = int(os.getenv("GUNICORN_KEEPALIVE", 2))

accesslog = "-"   # stdout
errorlog = "-"    # stderr
loglevel = os.getenv("GUNICORN_LOGLEVEL", "info")
