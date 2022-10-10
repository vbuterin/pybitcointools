import asyncio
import os.path

import threading
import janus
from typing import Tuple
from pathlib import Path
from concurrent.futures import Future

import certifi
import ssl
import itertools
import aiorpcx
from .. import constants
from .. import utils
from ipaddress import ip_address, IPv6Address
from aiorpcx import RPCSession, Notification, NewlineFramer
from aiorpcx.curio import TaskTimeout
from aiorpcx.rawsocket import RSClient
from collections import defaultdict
import json
import random
from typing import List, Dict, Any, Union, Optional, Callable

ca_path = certifi.where()

MAX_INCOMING_MSG_SIZE = 1_000_000  # in bytes
_KNOWN_NETWORK_PROTOCOLS = {'t', 's'}
PREFERRED_NETWORK_PROTOCOL = 's'
assert PREFERRED_NETWORK_PROTOCOL in _KNOWN_NETWORK_PROTOCOLS

class NetworkException(Exception):
    pass

class RequestCorrupted(Exception): pass

class ErrorParsingSSLCert(Exception): pass
class ErrorGettingSSLCertFromServer(Exception): pass
class ErrorSSLCertFingerprintMismatch(Exception): pass
class InvalidOptionCombination(Exception): pass
class ConnectError(NetworkException): pass


class ProtocolNotSupportedError(BaseException):
    pass


class _RSClient(RSClient):
    async def create_connection(self):
        try:
            return await asyncio.wait_for(super().create_connection(), timeout=10)
        except OSError as e:
            # note: using "from e" here will set __cause__ of ConnectError
            raise ConnectError(e) from e


def read_json(filename, default):
    path = os.path.join(os.path.dirname(__file__), filename)
    try:
        with open(path, 'r') as f:
            r = json.loads(f.read())
    except:
        r = default
    return r



class NetworkException(Exception):
    pass


class GracefulDisconnect(NetworkException):
    pass


class RequestTimedOut(GracefulDisconnect):
    def __str__(self):
        return "Network request timed out."


def _get_cert_path_for_host(appname: str, host: str) -> Path:
    filename = host
    try:
        ip = ip_address(host)
    except ValueError:
        pass
    else:
        if isinstance(ip, IPv6Address):
            filename = f"ipv6_{ip.packed.hex()}"

    user_dir = Path(utils.user_dir(appname))
    cert_path = user_dir / "certs"
    cert_path.mkdir(parents=True, exist_ok=True)
    return cert_path / filename


class NetworkTimeout:
    # seconds
    class Generic:
        NORMAL = 30
        RELAXED = 45
        MOST_RELAXED = 600

    class Urgent(Generic):
        NORMAL = 10
        RELAXED = 20
        MOST_RELAXED = 60


class NotificationSession(RPCSession):

    def __init__(self, *args, **kwargs):
        super(NotificationSession, self).__init__(*args, **kwargs)
        self.subscriptions = defaultdict(list)
        self.cache = {}
        self.default_timeout = NetworkTimeout.Generic.NORMAL
        self._msg_counter = itertools.count(start=1)
        self.cost_hard_limit = 0  # disable aiorpcx resource limits

    async def handle_request(self, request):
        print('Client handling request', request)
        try:
            if isinstance(request, Notification):
                print('Client handling notification', request.args)
                params, result = request.args[:-1], request.args[-1]
                print(params, result)
                key = self.get_hashable_key_for_rpc_call(request.method, params)
                print('hashable key:', key)
                if key in self.subscriptions:
                    self.cache[key] = result
                    for queue in self.subscriptions[key]:
                        print('Adding', request.args, 'to queue', queue)
                        await queue.put(request.args)
                else:
                    raise Exception(f'unexpected notification')
            else:
                raise Exception(f'unexpected request. not a notification')
        finally:
            await self.close()

    async def send_request(self, *args, timeout=None, **kwargs):
        # note: semaphores/timeouts/backpressure etc are handled by
        # aiorpcx. the timeout arg here in most cases should not be set
        msg_id = next(self._msg_counter)
        try:
            # note: RPCSession.send_request raises TaskTimeout in case of a timeout.
            # TaskTimeout is a subclass of CancelledError, which is *suppressed* in TaskGroups
            response = await asyncio.wait_for(
                super().send_request(*args, **kwargs),
                timeout)
        except (TaskTimeout, asyncio.TimeoutError) as e:
            raise RequestTimedOut(f'request timed out: {args} (id: {msg_id})') from e
        else:
            return response

    def set_default_timeout(self, timeout):
        self.sent_request_timeout = timeout
        self.max_send_delay = timeout

    async def subscribe(self, method: str, params: List, queue: asyncio.Queue):
        # note: until the cache is written for the first time,
        # each 'subscribe' call might make a request on the network.
        key = self.get_hashable_key_for_rpc_call(method, params)
        print('subscription hashable key', key)
        self.subscriptions[key].append(queue)
        if key in self.cache:
            result = self.cache[key]
        else:
            result = await self.send_request(method, params)
            self.cache[key] = result
        await queue.put(params + [result])

    def unsubscribe(self, queue):
        """Unsubscribe a callback to free object references to enable GC."""
        # note: we can't unsubscribe from the server, so we keep receiving
        # subsequent notifications
        for v in self.subscriptions.values():
            if queue in v:
                v.remove(queue)

    @classmethod
    def get_hashable_key_for_rpc_call(cls, method, params):
        """Hashable index for subscriptions and cache"""
        return str(method) + repr(params)

    def default_framer(self):
        return NewlineFramer(max_size=MAX_INCOMING_MSG_SIZE)

    async def close(self, *, force_after: int = None):
        """Closes the connection and waits for it to be closed.
        We try to flush buffered data to the wire, which can take some time.
        """
        if force_after is None:
            # We give up after a while and just abort the connection.
            # Note: specifically if the server is running Fulcrum, waiting seems hopeless,
            #       the connection must be aborted (see https://github.com/cculianu/Fulcrum/issues/76)
            # Note: if the ethernet cable was pulled or wifi disconnected, that too might
            #       wait until this timeout is triggered
            force_after = 1  # seconds
        await super().close(force_after=force_after)


class CannotConnectToAnyElectrumXServer(BaseException):
    def __init__(self):
        self.message = "Unable to connect to any ElectrumX Server"
        super().__init__(self.message)


class ElectrumXClient:
    host: str = None
    port: int = None
    server: Dict[str, Any]
    session: Optional[NotificationSession] = None

    def __init__(self, server_file: str = "bitcoin.json", connection_timeout: int = 5,
                 use_ssl: bool = True, client_name: str = constants.CLIENT_NAME, ping_interval: int = 30,
                 accept_self_signed_certs: bool = False):
        self.is_connected = asyncio.Event()
        self._connection_task: Optional[asyncio.Task] = None
        self._use_ssl = use_ssl
        self._accept_self_signed_certs = accept_self_signed_certs
        self.cert_path: Optional[Path] = None
        self.connection_timeout = connection_timeout
        servers = read_json(f"servers/{server_file}", {})
        self._port_key = "s" if self._use_ssl else "t"
        self._servers = {k: v for k, v in servers.items() if v.get(self._port_key)}
        self._lock = asyncio.Lock()
        self._is_closing = False
        self._failed_servers: List[str] = []
        self._subscribe_tasks: List[Union[asyncio.Task, asyncio.Future]] = []  # Should be replaced with TaskGroup in Python 3.11
        self.version = constants.PROTOCOL_VERSION
        self.server_version: Optional[List[str]] = None
        self.client_name = client_name
        self._ping_interval = ping_interval

    def _get_eligible_servers(self) -> Dict[str, Any]:
        return {k: v for k, v in self._servers.items() if k not in self._failed_servers and self._port_key in v.keys()}

    def _choose_new_server(self) -> str:
        eligible = self._get_eligible_servers()
        return random.choice(list(eligible.keys())) if eligible else None

    def _set_new_server(self):
        self.host = self._choose_new_server()
        self.server = self._servers[self.host]
        try:
            self.port = int(self.server[self._port_key])
        except KeyError:
            raise ProtocolNotSupportedError

    async def _get_ssl_context(self) -> Optional[ssl.SSLContext]:
        if not self._use_ssl:
            # using plaintext TCP
            return None

        # see if we already have cert for this server; or get it for the first time
        ca_sslc = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH, cafile=ca_path)
        if self._accept_self_signed_certs:
            ca_sslc.check_hostname = False
            ca_sslc.verify_mode = ssl.CERT_NONE
        return ca_sslc

    async def monitor_connection(self):
        i = 0
        while True:
            await asyncio.sleep(1)
            i += 1
            # If the session/transport is no longer open, we disconnect.
            # e.g. if the remote cleanly sends EOF, we would handle that here.
            # note: If the user pulls the ethernet cable or disconnects wifi,
            #       ideally we would detect that here, so that the GUI/etc can reflect that.
            #       - On Android, this seems to work reliably , where asyncio.BaseProtocol.connection_lost()
            #         gets called with e.g. ConnectionAbortedError(103, 'Software caused connection abort').
            #       - On desktop Linux/Win, it seems BaseProtocol.connection_lost() is not called in such cases.
            #         Hence, in practice the connection issue will only be detected the next time we try
            #         to send a message (plus timeout), which can take minutes...
            if not self.session or self.session.is_closing():
                raise GracefulDisconnect('session was closed')
            elif i == self._ping_interval:
                try:
                    print('Pinging')
                    await self._send_request("server.ping", timeout=self.connection_timeout)
                    print('Ping ok')
                    i = 0
                except TimeoutError:
                    print('Ping not ok')
                    raise GracefulDisconnect('session was closed')

    async def _open_session(self, sslc: Optional[ssl.SSLContext] = None) -> None:
        session_factory = lambda *args, **kwargs: NotificationSession(*args, **kwargs)
        print('Connecting to', self.host, self.port)
        async with _RSClient(session_factory=session_factory,
                             host=self.host, port=self.port,
                             ssl=sslc) as session:
            self.session = session

            self.session.set_default_timeout(NetworkTimeout.Generic.NORMAL)

            print('Connected to', self.host, self.port, "Checking version")
            self.server_version = await self._send_request("server.version", self.client_name, self.version, timeout=10)

            self.is_connected.set()
            await self.monitor_connection()
        self.is_connected.clear()
        self.session = None

    async def _connect(self) -> None:
        sslc = await self._get_ssl_context()
        await self._open_session(sslc=sslc)

    async def _on_connection_failure(self):
        print('Connection to', self.host, 'failed')
        self.session = None
        self._failed_servers.append(self.host)
        if not self._is_closing:
            if len(self._failed_servers) == len(self._servers):
                raise CannotConnectToAnyElectrumXServer
            await self.connect_to_any_server()

    async def connect_to_any_server(self) -> None:
        self._set_new_server()
        try:
            await self._connect()
        except (asyncio.TimeoutError, aiorpcx.jsonrpc.RPCError, OSError, GracefulDisconnect, ConnectError,
                ProtocolNotSupportedError, ssl.SSLError) as e:
            print(e.__class__)
            print(e)
            await self._on_connection_failure()

    async def _ensure_connected(self):
        async with self._lock:
            if not self._is_closing:
                if not self.session:
                    """
                    Wait until successful connection or connection task completes without any successful connections
                    """
                    self._connection_task = asyncio.create_task(self.connect_to_any_server(), name="connection_task")
                    is_connected_task = asyncio.create_task(self.is_connected.wait(), name="is_connected_task")
                    done, pending = await asyncio.wait([is_connected_task, self._connection_task],
                                                       return_when=asyncio.FIRST_COMPLETED)

                    for task in done:
                        if exc := task.exception():
                            raise exc
            else:
                raise ConnectionError("JSONRPC Connection is already closing, cannot send message")

    async def cancel_subscriptions(self) -> None:
        async with self._lock:
            for task in self._subscribe_tasks:
                task.cancel()
            if self._subscribe_tasks:
                await asyncio.wait(self._subscribe_tasks)
            self._subscribe_tasks = []

    async def close(self):
        print('Closing client')
        self._is_closing = True
        await self.cancel_subscriptions()
        if self.session:
            await self.session.close(force_after=5)
        if self._connection_task:
            try:
                await asyncio.wait_for(self._connection_task, timeout=self.connection_timeout)
            except TimeoutError:
                self._connection_task.cancel()
            except asyncio.CancelledError:
                pass
        print('Client closed')

    async def _send_request(self, method: str, *args, timeout: int = 30, **kwargs):
        return await self.session.send_request(method, args, timeout=timeout, **kwargs)

    async def send_request(self, method: str, *args, timeout: int = 30, **kwargs):
        await self._ensure_connected()
        return await self._send_request(method, *args, timeout=timeout, **kwargs)

    def _on_task_complete(self, task: asyncio.Task):
        if task in self._subscribe_tasks:
            self._subscribe_tasks.remove(task)

    async def _subscribe(self, method: str, callback: Callable, *args) -> None:
        queue = asyncio.Queue()
        is_coro = asyncio.iscoroutinefunction(callback)
        await self.session.subscribe(method, list(args), queue)
        try:
            while True:
                for item in await queue.get():
                    if is_coro:
                        print('Running callback as coro with', item)
                        coro = callback(item)
                        task = asyncio.create_task(coro)
                    else:
                        print('Running callback')
                        task = asyncio.get_running_loop().run_in_executor(None, callback, item)
                    print('Creating callback task')
                    self._subscribe_tasks.append(task)
                    task.add_done_callback(self._on_task_complete)
        finally:
            self.session.unsubscribe(queue)

    async def subscribe(self, method: str, callback: Callable, *args) -> None:
        await self._ensure_connected()
        task = asyncio.create_task(self._subscribe(method, callback, *args))
        self._subscribe_tasks.append(task)
        task.add_done_callback(self._on_task_complete)

    def _estimate_fee(self, numblocks):
        return 'blockchain.estimatefee', (numblocks,)

    def estimate_fee(self, numblocks):
        return self.send_request(*self._estimate_fee(numblocks))


class ElectrumXSyncClient:
    async_class = ElectrumXClient
    _client: ElectrumXClient = None
    _thread: threading.Thread = None

    def __init__(self, *args, **kwargs):
        self._client_args = args
        self._client_kwargs = kwargs
        self.is_closing = threading.Event()
        self._request_queue: Optional[janus.Queue[Tuple[Future, str, tuple[Any], dict[str, Any]]]] = None
        self._loop_is_started = threading.Event()

    def __getattr__(self, item):
        return getattr(self._client, item)

    def start(self, *args, **kwargs):
        if not self._thread or not self._thread.is_alive():
            self._thread = threading.Thread(target=self.start_event_loop, daemon=True)
            self._thread.start()
        self._loop_is_started.wait(timeout=10)

    def start_event_loop(self):
        asyncio.run(self.run())

    async def run(self):
        self._request_queue = janus.Queue()
        self._client = ElectrumXClient(*self._client_args, **self._client_kwargs)
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
                if "subscribe" in method and callback:
                    result = await self._client.subscribe(method, callback, *args)
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

    def subscribe(self, method: str, callback: Callable, *args):
        self.start()
        fut = Future()
        kwargs = {'callback': callback}
        self._request_queue.sync_q.put((fut, method, args, kwargs))
        return fut.result()

    def close(self):
        self.is_closing.set()


