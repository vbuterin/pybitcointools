import asyncio
import janus
import threading
from concurrent.futures import Future
from typing import Any, Optional, Tuple, Type
from ..coins_async import BaseCoin as BaseAsyncCoin


class BaseCoin:
    async_class: Type[BaseAsyncCoin]
    is_closing: bool = False
    _thread: threading.Thread = None

    def __init__(self, *args, **kwargs):
        self._client_args = args
        self._client_kwargs = kwargs
        self._request_queue: Optional[janus.Queue[Tuple[Future, str, tuple, dict[str, Any]]]] = None
        self._async: Optional[BaseAsyncCoin] = None
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
        self._async = self.async_class(*self._client_args, **self._client_kwargs)
        try:
            fut: Future
            method: str
            args: tuple
            kwargs: dict
            if not self.is_closing:
                asyncio.get_running_loop().call_soon(self._loop_is_started.set)
                while True:
                    val = await self._request_queue.async_q.get()
                    fut, method, args, kwargs = val
                    if method == "_close":
                        break
                    try:
                        result = await getattr(self._async, method)(*args, **kwargs)
                        fut.set_result(result)
                    except Exception as e:
                        fut.set_exception(e)
        finally:
            await self._async.close()
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
            self._request_queue.sync_q.put((fut, "_close", (), {}))
            fut.result(timeout=10)
