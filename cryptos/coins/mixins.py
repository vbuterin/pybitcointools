import asyncio
from concurrent.futures import Future
import threading
import janus
from cryptos.coins_async.base import BaseCoin
from typing import Optional, Tuple, Any


class SyncCoinMixin(BaseCoin):
    is_closing: bool = False
    _thread: threading.Thread = None

    def __init__(self, testnet: bool = False, use_ssl: bool = None, **kwargs):
        super().__init__(testnet=testnet, use_ssl=use_ssl, **kwargs)
        self._request_queue: Optional[janus.Queue[Tuple[Future, str, tuple, dict[str, Any]]]] = None
        self._loop_is_started = threading.Event()

    def start(self, *args, **kwargs):
        if not self._thread or not self._thread.is_alive():
            self._thread = threading.Thread(target=self.start_event_loop, daemon=True)
            self._thread.start()
        self._loop_is_started.wait(timeout=10)

    def start_event_loop(self):
        asyncio.run(self.run())

    async def run(self):
        self._request_queue = janus.Queue()
        fut: Future
        method: str
        args: tuple
        kwargs: dict
        if not self.is_closing:
            try:
                asyncio.get_running_loop().call_soon(self._loop_is_started.set)
                while True:
                    val = await self._request_queue.async_q.get()
                    fut, method, args, kwargs = val
                    if method == "close":
                        break
                    try:
                        result = await getattr(super(), method)(*args, **kwargs)
                        fut.set_result(result)
                    except Exception as e:
                        fut.set_exception(e)
            finally:
                await super().close()
            self._loop_is_started.clear()

    def _run_async(self, method: str, *args, **kwargs):
        self.start()
        fut = Future()
        self._request_queue.sync_q.put((fut, method, args, kwargs))
        return fut.result()

    def __del__(self):
        self.close()

    def close(self):
        self.is_closing = True
        if self._loop_is_started.is_set():
            fut = Future()
            self._request_queue.sync_q.put((fut, "close", (), {}))
            fut.result(timeout=10)
