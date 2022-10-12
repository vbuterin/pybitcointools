import asyncio
import janus
import threading
from concurrent.futures import Future
from typing import Any, Optional, Tuple, Type
from ..coins_async import BaseCoin as BaseAsyncCoin


class BaseCoin:
    async_class: Type[BaseAsyncCoin]
    _thread: threading.Thread = None

    def __init__(self, *args, **kwargs):
        self._client_args = args
        self._client_kwargs = kwargs
        self.is_closing = threading.Event()
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
        fut: Future
        method: str
        args: tuple
        kwargs: dict
        self._loop_is_started.set()
        while not self.is_closing.is_set():
            val = await self._request_queue.async_q.get()
            fut, method, args, kwargs = val
            callback = kwargs.get('callback')
            try:
                if "subscribe" in method:
                    if callback:
                        result = await self._client.subscribe(callback, method, *args)
                    else:
                        result = await self._client.unsubscribe(method)
                else:
                    result = await self._client.send_request(method, *args, **kwargs)
                fut.set_result(result)
            except Exception as e:
                fut.set_exception(e)

    def send_request(self, method: str, *args, timeout: int = 30, **kwargs):
        self.start()
        fut = Future()
        kwargs['timeout'] = timeout
        self._request_queue.sync_q.put((fut, method, args, kwargs))
        return fut.result()

    def subscribe(self, callback: Callable, method: str,  *args):
        self.start()
        fut = Future()
        kwargs = {'callback': callback}
        self._request_queue.sync_q.put((fut, method, args, kwargs))
        return fut.result()

    def unsubscribe(self, method: str):
        self.start()
        fut = Future()
        self._request_queue.sync_q.put((fut, method, (), {}))
        return fut.result()

    def close(self):
        self.is_closing.set()
