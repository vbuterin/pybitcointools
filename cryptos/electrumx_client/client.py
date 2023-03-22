import asyncio
import os.path

from pathlib import Path
from packaging.version import parse as parse_version

import certifi
import ssl
import itertools
import aiorpcx
from .. import constants
from aiorpcx import RPCSession, Notification, NewlineFramer
from aiorpcx.curio import TaskTimeout
from aiorpcx.rawsocket import RSClient
from collections import defaultdict
import json
import random
from typing import List, Dict, Any, Optional, Callable
from .types import (ElectrumXBlockResponse, ElectrumXBlockHeadersResponse, BlockHeaderNotificationCallback,
    ElectrumXBalanceResponse, ElectrumXHistoryResponse, ElectrumXMempoolResponse, ElectrumXUnspentResponse,
    AddressNotificationCallback, ElectrumXGetTxResponse, ElectrumXMerkleResponse)


ca_path = certifi.where()

MAX_INCOMING_MSG_SIZE = 1_000_000  # in bytes
_KNOWN_NETWORK_PROTOCOLS = {'t', 's'}
PREFERRED_NETWORK_PROTOCOL = 's'
assert PREFERRED_NETWORK_PROTOCOL in _KNOWN_NETWORK_PROTOCOLS


class NetworkException(Exception):
    pass


class RequestCorrupted(Exception):
    pass


class ErrorParsingSSLCert(Exception):
    pass


class ErrorGettingSSLCertFromServer(Exception):
    pass


class ErrorSSLCertFingerprintMismatch(Exception):
    pass


class InvalidOptionCombination(Exception):
    pass


class ConnectError(NetworkException):
    pass


class ProtocolNotSupportedError(BaseException):
    pass


class _RSClient(RSClient):
    async def create_connection(self):
        try:
            return await asyncio.wait_for(super().create_connection(), timeout=60)
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
        except Exception as e:
            await self.close()
            raise

    async def send_request(self, *args, timeout: int = None, **kwargs):
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
    requires_scripthash: bool = True

    def __init__(self, server_file: str = "bitcoin.json", connection_timeout: int = 5,
                 use_ssl: bool = True, tor: bool = False, client_name: str = constants.CLIENT_NAME,
                 ping_interval: int = 30, accept_self_signed_certs: bool = True):
        self._active_subscriptions: Dict[str, List[asyncio.Task]] = {}
        self._tasks = []
        self.restart_condition = asyncio.Condition()
        self._connection_task: Optional[asyncio.Task] = None
        self._use_ssl = use_ssl
        self._tor = tor
        self._accept_self_signed_certs = accept_self_signed_certs
        self.cert_path: Optional[Path] = None
        self.connection_timeout = connection_timeout
        servers = read_json(f"servers/{server_file}", {})
        self._port_key = "s" if self._use_ssl else "t"
        self._servers = {k: v for k, v in servers.items() if v.get(self._port_key)}
        self._lock = asyncio.Lock()
        self.is_closing = False
        self._failed_servers: List[str] = []
        self.version = constants.PROTOCOL_VERSION
        self.server_version: Optional[List[str]] = None
        self.client_name = client_name
        self._ping_interval = ping_interval

    def compare_versions(self, min_version: str) -> bool:
        if self.server_version:
            version = self.server_version[1]
            server = parse_version(version)
            minimum = parse_version(min_version)
            return server >= minimum
        return False

    def _get_eligible_servers(self) -> Dict[str, Any]:
        return {k: v for k, v in self._servers.items() if k not in self._failed_servers and self._port_key in v.keys() and
                (self._tor and k.endswith('onion') or (not self._tor and not k.endswith('onion')))}

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
                    await self._send_request("server.ping", timeout=self.connection_timeout)
                    i = 0
                except TimeoutError:
                    raise GracefulDisconnect('session was closed')

    async def _open_session(self, sslc: Optional[ssl.SSLContext] = None) -> None:
        session_factory = lambda *args, **kwargs: NotificationSession(*args, **kwargs)
        async with _RSClient(session_factory=session_factory,
                             host=self.host, port=self.port,
                             ssl=sslc) as session:
            self.session = session

            self.session.set_default_timeout(NetworkTimeout.Generic.NORMAL)

            self.server_version = await self._send_request("server.version", self.client_name, self.version, timeout=10)
            async with self.restart_condition:
                self.restart_condition.notify_all()
            await self.monitor_connection()
        self.session = None

    async def _connect(self) -> None:
        sslc = await self._get_ssl_context()
        await self._open_session(sslc=sslc)

    async def redo_connection(self):
        await self.session.close()
        await self.wait_new_start()

    async def _on_connection_failure(self):
        self.session = None
        self._failed_servers.append(self.host)
        if not self.is_closing:
            if len(self._failed_servers) == len(self._servers):
                raise CannotConnectToAnyElectrumXServer
            await self.connect_to_any_server()

    async def connect_to_any_server(self) -> None:
        self._set_new_server()
        connect_task = asyncio.create_task(self._connect())

        try:
            await asyncio.wait_for(self.wait_new_start(), timeout=5)
        except asyncio.TimeoutError:
            if not connect_task.done():
                connect_task.cancel()
        try:
            await connect_task
        except (asyncio.TimeoutError, asyncio.CancelledError, aiorpcx.jsonrpc.RPCError, OSError,
                GracefulDisconnect, ConnectError, ProtocolNotSupportedError, ssl.SSLError) as e:
            await self._on_connection_failure()

    async def wait_new_start(self):
        async with self.restart_condition:
            await self.restart_condition.wait()

    async def _ensure_connected(self):
        async with self._lock:
            if not self.is_closing:
                if not self.session:
                    """
                    Wait until successful connection or connection task completes without any successful connections
                    """
                    self._connection_task = asyncio.create_task(self.connect_to_any_server(), name="connection_task")
                    is_connected_task = asyncio.create_task(self.wait_new_start(), name="is_connected_task")
                    done, pending = await asyncio.wait([is_connected_task, self._connection_task],
                                                       return_when=asyncio.FIRST_COMPLETED)

                    for task in done:
                        if not task.cancelled():
                            if exc := task.exception():
                                for p in pending:
                                    p.cancel()
                                raise exc
            else:
                raise ConnectionError("JSONRPC Connection is already closing, cannot send message")

    async def cancel_subscriptions(self) -> None:
        async with self._lock:
            subscription_tasks = list(itertools.chain(*self._active_subscriptions.values()))
            for task in subscription_tasks:
                task.cancel()
            all_tasks = subscription_tasks + self._tasks
            if all_tasks:
                await asyncio.wait(all_tasks)

    async def close(self):
        self.is_closing = True
        await self.cancel_subscriptions()
        if self.session:
            await self.session.close(force_after=5)
        if self._connection_task:
            try:
                await asyncio.wait_for(self._connection_task, timeout=self.connection_timeout)
            except (TimeoutError, OSError, ConnectError) as e:
                if not self._connection_task.done():
                    self._connection_task.cancel()
            await self._connection_task

    async def _send_request(self, method: str, *args, timeout: int = 30, **kwargs) -> Any:
        return await self.session.send_request(method, args, timeout=timeout, **kwargs)

    async def send_request(self, method: str, *args, timeout: int = 30, **kwargs) -> Any:
        await self._ensure_connected()
        return await self._send_request(method, *args, timeout=timeout, **kwargs)

    def _on_task_complete(self, task: asyncio.Task) -> None:
        if task in self._tasks:
            self._tasks.remove(task)
        if not task.cancelled():
            if exc := task.exception():
                raise exc

    def _on_subscription_task_complete(self, task: asyncio.Task) -> None:
        remove_method = None
        try:
            for method, tasks in self._active_subscriptions.items():
                if task in tasks:
                    tasks.remove(task)
                    if not tasks:
                        remove_method = method
                    break
            if not task.cancelled():
                if exc := task.exception():
                    raise exc
        finally:
            if remove_method:
                del self._active_subscriptions[remove_method]

    async def _subscribe(self, method: str, callback: Callable, *args) -> None:
        queue = asyncio.Queue()
        session = None
        subscribed = False
        just_restarted = False
        last_item = None
        wait_next_start_task = None
        try:
            while True:
                if not subscribed:
                    session = self.session
                    await session.subscribe(method, list(args), queue)
                    subscribed = True
                    just_restarted = True
                    wait_next_start_task = asyncio.create_task(self.wait_new_start())
                queue_task = asyncio.create_task(queue.get())
                done, pending = await asyncio.wait([queue_task, wait_next_start_task],
                                                   return_when=asyncio.FIRST_COMPLETED)
                if wait_next_start_task in done:
                    subscribed = False
                if queue_task in done:
                    item = queue_task.result()
                    """
                    After restarting a subscription we want to avoid processing the item we receive immediately,
                    which was most likely already received on the last connection
                    """
                    if not just_restarted or item != last_item:
                        last_item = item
                        task = asyncio.create_task(callback(*item))
                        self._tasks.append(task)
                        task.add_done_callback(self._on_task_complete)
                    just_restarted = False
                else:
                    queue_task.cancel()
        finally:
            if session:
                session.unsubscribe(queue)
                if "scripthash" in method and not self.is_closing and self.compare_versions("1.4.2"):
                    await self.send_request("blockchain.scripthash.unsubscribe", *args)

    @staticmethod
    def _get_sub_name(method, *args):
        arg0 = " ".join(args)
        return f'{method}[{arg0}]'

    async def unsubscribe(self, method: str, *args):
        name = self._get_sub_name(method, *args)
        tasks = self._active_subscriptions[name]
        if tasks:
            for task in tasks:
                task.cancel()
        await asyncio.wait(tasks)

    def _create_subscribe_task(self, method: str, callback: Callable, *args) -> None:
        task = asyncio.create_task(self._subscribe(method, callback, *args))
        name = self._get_sub_name(method, *args)
        if not self._active_subscriptions.get(name):
            self._active_subscriptions[name] = []
        self._active_subscriptions[name].append(task)
        task.add_done_callback(self._on_subscription_task_complete)

    async def subscribe(self, callback: Callable, method: str, *args) -> None:
        await self._ensure_connected()
        self._create_subscribe_task(method, callback, *args)

    async def block_header(self, height: int, cp_height: int = 0) -> ElectrumXBlockResponse:
        return await self.send_request("blockchain.block.header", height, cp_height)

    async def block_headers(self, start_height: int, count: int, cp_height: int = 0) -> ElectrumXBlockHeadersResponse:
        return await self.send_request("blockchain.block.headers", start_height, count, cp_height)

    async def estimate_fee(self, numblocks: int = 6) -> float:
        return await self.send_request("blockchain.estimatefee", numblocks)

    async def relay_fee(self) -> float:
        return await self.send_request("blockchain.relayfee")

    async def subscribe_to_block_headers(self, callback: BlockHeaderNotificationCallback) -> None:
        await self.subscribe(callback, "blockchain.headers.subscribe")

    async def unsubscribe_from_block_headers(self) -> None:
        await self.unsubscribe("blockchain.headers.subscribe")

    async def get_balance(self, scripthash: str) -> ElectrumXBalanceResponse:
        return await self.send_request("blockchain.scripthash.get_balance", scripthash)

    async def get_history(self, scripthash: str) -> ElectrumXHistoryResponse:
        return await self.send_request("blockchain.scripthash.get_history", scripthash)

    async def get_mempool(self, scripthash: str) -> ElectrumXMempoolResponse:
        return await self.send_request("blockchain.scripthash.get_mempool", scripthash)

    async def unspent(self, scripthash: str) -> ElectrumXUnspentResponse:
        return await self.send_request("blockchain.scripthash.listunspent", scripthash)

    async def subscribe_to_address(self, callback: AddressNotificationCallback, scripthash: str) -> None:
        await self.subscribe(callback, "blockchain.scripthash.subscribe", scripthash)

    async def unsubscribe_from_address(self, scripthash: str) -> None:
        await self.unsubscribe("blockchain.scripthash.subscribe", scripthash)

    async def broadcast_tx(self, raw_tx: str) -> str:
        return await self.send_request("blockchain.transaction.broadcast", raw_tx)

    async def get_tx(self, tx_hash: str, verbose: bool = False) -> ElectrumXGetTxResponse:
        try:
            return await self.send_request("blockchain.transaction.get", tx_hash, verbose)
        except aiorpcx.jsonrpc.ProtocolError as e:
            if any(msg in e.message for msg in ("verbose transactions are currently unsupported",)):
                "Some servers return this even if later than v 1.2 when verbose transactions were introduced"
                await self.redo_connection()
                return await self.get_tx(tx_hash, verbose=verbose)
            raise e

    async def get_merkle(self, tx_hash: str, height: int) -> Optional[ElectrumXMerkleResponse]:
        if height <= 0:
            return None     # Transaction not in blockchain yet
        try:
            return await self.send_request("blockchain.transaction.get_merkle", tx_hash, height)
        except aiorpcx.jsonrpc.RPCError as e:
            if any(msg in e.message for msg in ("No confirmed transaction", "unconfirmed")):
                return None
            raise e

    async def get_donation_address(self) -> str:
        return await self.send_request("server.donation_address")
