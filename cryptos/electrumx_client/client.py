import asyncio
import os.path

import certifi
import itertools
import aiorpcx
from .. import constants
from aiorpcx import RPCSession, Notification, NetAddress, NewlineFramer
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

class GracefulDisconnect(NetworkException):
    pass

class RequestCorrupted(Exception): pass

class ErrorParsingSSLCert(Exception): pass
class ErrorGettingSSLCertFromServer(Exception): pass
class ErrorSSLCertFingerprintMismatch(Exception): pass
class InvalidOptionCombination(Exception): pass
class ConnectError(NetworkException): pass


class _RSClient(RSClient):
    async def create_connection(self):
        try:
            return await super().create_connection()
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
        return _("Network request timed out.")


class ServerAddr:

    def __init__(self, host: str, port: Union[int, str], *, protocol: str = None):
        assert isinstance(host, str), repr(host)
        if protocol is None:
            protocol = 's'
        if not host:
            raise ValueError('host must not be empty')
        if host[0] == '[' and host[-1] == ']':  # IPv6
            host = host[1:-1]
        try:
            net_addr = NetAddress(host, port)  # this validates host and port
        except Exception as e:
            raise ValueError(f"cannot construct ServerAddr: invalid host or port (host={host}, port={port})") from e
        if protocol not in _KNOWN_NETWORK_PROTOCOLS:
            raise ValueError(f"invalid network protocol: {protocol}")
        self.host = str(net_addr.host)  # canonical form (if e.g. IPv6 address)
        self.port = int(net_addr.port)
        self.protocol = protocol
        self._net_addr_str = str(net_addr)

    @classmethod
    def from_str(cls, s: str) -> 'ServerAddr':
        # host might be IPv6 address, hence do rsplit:
        host, port, protocol = str(s).rsplit(':', 2)
        return ServerAddr(host=host, port=port, protocol=protocol)

    @classmethod
    def from_str_with_inference(cls, s: str) -> Optional['ServerAddr']:
        """Construct ServerAddr from str, guessing missing details.
        Ongoing compatibility not guaranteed.
        """
        if not s:
            return None
        items = str(s).rsplit(':', 2)
        if len(items) < 2:
            return None  # although maybe we could guess the port too?
        host = items[0]
        port = items[1]
        if len(items) >= 3:
            protocol = items[2]
        else:
            protocol = PREFERRED_NETWORK_PROTOCOL
        return ServerAddr(host=host, port=port, protocol=protocol)

    def to_friendly_name(self) -> str:
        # note: this method is closely linked to from_str_with_inference
        if self.protocol == 's':  # hide trailing ":s"
            return self.net_addr_str()
        return str(self)

    def __str__(self):
        return '{}:{}'.format(self.net_addr_str(), self.protocol)

    def to_json(self) -> str:
        return str(self)

    def __repr__(self):
        return f'<ServerAddr host={self.host} port={self.port} protocol={self.protocol}>'

    def net_addr_str(self) -> str:
        return self._net_addr_str

    def __eq__(self, other):
        if not isinstance(other, ServerAddr):
            return False
        return (self.host == other.host
                and self.port == other.port
                and self.protocol == other.protocol)

    def __ne__(self, other):
        return not (self == other)

    def __hash__(self):
        return hash((self.host, self.port, self.protocol))


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
        try:
            if isinstance(request, Notification):
                params, result = request.args[:-1], request.args[-1]
                key = self.get_hashable_key_for_rpc_call(request.method, params)
                if key in self.subscriptions:
                    self.cache[key] = result
                    for queue in self.subscriptions[key]:
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
                 use_ssl: bool = True, client_name: str = constants.CLIENT_NAME, ping_interval: int = 30):
        self.is_connected = asyncio.Event()
        self._connection_task: Optional[asyncio.Task] = None
        self._use_ssl = use_ssl
        self.connection_timeout = connection_timeout
        servers = read_json(f"servers/{server_file}", {})
        self._port_key = "s" if self._use_ssl else "t"
        self._servers = {k: v for k, v in servers.items() if v.get(self._port_key)}
        self._lock = asyncio.Lock()
        self._is_closing = False
        self._failed_servers: List[str] = []
        self._subscribe_tasks: List[asyncio.Task] = []  # Should be replaced with TaskGroup in Python 3.11
        self.version = constants.PROTOCOL_VERSION
        self.server_version: Optional[List[str]] = None
        self.client_name = client_name
        self._ping_interval = ping_interval

    def _get_eligible_servers(self) -> Dict[str, Any]:
        return {k: v for k, v in self._servers.items() if k not in self._failed_servers}

    def _choose_new_server(self) -> str:
        eligible = self._get_eligible_servers()
        return random.choice(list(eligible.keys())) if eligible else None

    def _set_new_server(self):
        self.host = self._choose_new_server()
        self.server = self._servers[self.host]
        self.port = int(self.server[self._port_key])

    def _get_ssl_context(self) -> None:
        return None

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
                    await self._send_request("server.ping", timeout=self.connection_timeout)
                    i = 0
                except TimeoutError:
                    raise GracefulDisconnect('session was closed')

    async def _connect(self) -> None:
        sslc = self._get_ssl_context()
        session_factory = lambda *args, **kwargs: NotificationSession(*args, **kwargs)
        async with _RSClient(session_factory=session_factory,
                             host=self.host, port=self.port,
                             ssl=sslc) as session:
            self.session = session
            self.session.set_default_timeout(NetworkTimeout.Generic.NORMAL)

            # if SSL get cert
            # Validate cert
            # Store cert if not stored

            self.server_version = await self._send_request("server.version", self.client_name, self.version, timeout=10)

            self.is_connected.set()
            await self.monitor_connection()
            pass
        self.is_connected.clear()
        self.session = None

    async def _on_connection_failure(self):
        self.session = None
        self._failed_servers.append(self.host)
        if not self._is_closing:
            if len(self._failed_servers) == len(self._servers):
                raise CannotConnectToAnyElectrumXServer
            await self.connect_to_any_server()

    async def connect_to_any_server(self) -> None:
        self._set_new_server()
        try:
            await asyncio.wait_for(self._connect(), self.connection_timeout)
        except (asyncio.TimeoutError, aiorpcx.jsonrpc.RPCError, OSError, GracefulDisconnect) as e:
            await self._on_connection_failure()

    async def _ensure_connected(self):
        async with self._lock:
            if not self._is_closing:
                if not self.session:
                    self._connection_task = asyncio.create_task(self.connect_to_any_server())
                    done, pending = await asyncio.wait([
                        asyncio.create_task(self.is_connected.wait()), self._connection_task],
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

    async def _send_request(self, method: str, *args, timeout: int = 30, **kwargs):
        return await self.session.send_request(method, args, timeout=timeout, **kwargs)

    async def send_request(self, method: str, *args, timeout: int = 30, **kwargs):
        await self._ensure_connected()
        return await self._send_request(method, *args, timeout=timeout, **kwargs)

    def _on_task_complete(self, task: asyncio.Task):
        if task in self._subscribe_tasks:
            self._subscribe_tasks.remove(task)

    async def _subscribe(self, method: str, callback: Callable, *args, **kwargs) -> None:
        queue = asyncio.Queue()
        is_coro = asyncio.iscoroutinefunction(callback)
        await self.session.subscribe(method, *args, queue=queue, **kwargs)
        try:
            while True:
                for item in await queue.get():
                    if is_coro:
                        task = callback(item)
                    else:
                        task = asyncio.get_event_loop().run_in_executor(None, callback, item)
                    self._subscribe_tasks.append(task)
                    task.add_done_callback(self._on_task_complete)
        finally:
            self.session.unsubscribe(queue)

    async def subscribe(self, method: str, callback: Callable, *args, **kwargs) -> None:
        async with self._lock.acquire():
            await self._ensure_connected()
        task = asyncio.create_task(self._subscribe(method, callback, *args, **kwargs))
        self._subscribe_tasks.append(task)
        task.add_done_callback(self._on_task_complete)

    def _estimate_fee(self, numblocks):
        return 'blockchain.estimatefee', (numblocks,)

    def estimate_fee(self, numblocks):
        return self.send_request(*self._estimate_fee(numblocks))
