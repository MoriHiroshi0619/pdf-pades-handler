# app/utils.py
import asyncio

def run_sync(maybe_awaitable):
    """
    Helper para rodar coroutines de forma síncrona (igual ao seu run_sync anterior).
    """
    if asyncio.iscoroutine(maybe_awaitable):
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(maybe_awaitable)
        finally:
            loop.close()
    return maybe_awaitable
