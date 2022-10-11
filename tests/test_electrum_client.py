import unittest
import asyncio
from concurrent.futures import Future
from cryptos.electrumx_client.client import ElectrumXClient, NotificationSession, CannotConnectToAnyElectrumXServer, ElectrumXSyncClient
from functools import partial
from unittest.mock import patch
import janus
import ssl
from typing import List
from queue import Queue
from electrum_subscribe_mock_server import run_server, run_server_in_thread, reset_cycles


client_name = "pybitcointools_test"
known_electrum_host = "167.172.42.31"

known_electrum_config = {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.4.2"
    }

known_electrum_expected_version = ["ElectrumX 1.16.0", "1.4"]
known_electrum_ssl_host = "electrum.hodlister.co"
known_electrum_ssl_version = ["ElectrumX 1.10.0", "1.4"]
failed_host = "127.0.0.1"


async def on_scripthash_notification(queue: asyncio.Queue, scripthash: str, status: str):
    await queue.put((scripthash, status))


def on_scripthash_notification_sync_from_async(queue: janus.Queue, scripthash: str, status: str):
    queue.sync_q.put((scripthash, status))

def on_scripthash_notification_sync(queue: Queue, scripthash: str, status: str):
    queue.put((scripthash, status))


class TestElectrumClient(unittest.IsolatedAsyncioTestCase):

    def setUp(self) -> None:
        self.client = ElectrumXClient(use_ssl=False, connection_timeout=10, client_name=client_name)
        self.testnet_client = ElectrumXClient(use_ssl=False, connection_timeout=10, client_name=client_name,
                                              server_file="bitcoin_testnet.json")

    async def asyncTearDown(self) -> None:
        await self.client.close()

    def tearDown(self) -> None:
        reset_cycles()

    @property
    def server_names(self) -> List[str]:
        return list(self.client._servers.keys())

    def test_client(self):
        self.assertGreaterEqual(len(self.client._servers), 10)
        self.assertIsInstance(self.client._servers, dict)
        for k, v in self.client._servers.items():
            self.assertIsInstance(k, str)
            self.assertIsInstance(v["pruning"], str)
            self.assertIsInstance(v["version"], str)
            self.assertTrue(isinstance(v.get('s'), str) or isinstance(v.get('t'), str))

    def test_get_eligible_servers(self):
        eligible = self.client._get_eligible_servers()
        self.client._failed_servers.append(self.server_names[0])
        eligible2 = self.client._get_eligible_servers()
        self.assertEqual(len(eligible) - len(eligible2), 1)

    def test_choose_new_server(self):
        failed_server = self.server_names[0]
        self.client._failed_servers.append(failed_server)
        server = self.client._choose_new_server()
        self.assertIn(server, self.server_names)
        self.assertNotEqual(server, failed_server)

    @patch('random.choice', return_value=known_electrum_host)
    def test_set_new_server(self, mock):
        self.client._set_new_server()
        self.assertEqual(self.client.host, known_electrum_host)
        self.assertEqual(self.client.port, int(known_electrum_config["t"]))

    async def test_get_ssl_context(self):
        self.assertIsNone(await self.client._get_ssl_context())

    @patch('random.choice', return_value=known_electrum_host)
    async def test_connect(self, mock):
        self.assertIsNone(self.client.session)
        self.client._set_new_server()
        task = asyncio.create_task(self.client._connect())
        await asyncio.wait_for(self.client.wait_new_start(), timeout=5)
        self.assertIsInstance(self.client.session, NotificationSession)
        self.assertListEqual(self.client.server_version, known_electrum_expected_version)
        task.cancel()

    @patch('random.choice', return_value=known_electrum_host)
    async def test_connect_to_any_server(self, mock):
        self.assertIsNone(self.client.session)
        task = asyncio.create_task(self.client.connect_to_any_server())
        await asyncio.wait_for(self.client.wait_new_start(), timeout=5)
        self.assertIsInstance(self.client.session, NotificationSession)
        task.cancel()

    @patch('random.choice', return_value=known_electrum_host)
    async def test_on_connection_failure(self, mock):
        self.assertIsNone(self.client.session)
        self.client.host = failed_host
        task = asyncio.create_task(self.client._on_connection_failure())
        await asyncio.wait_for(self.client.wait_new_start(), timeout=5)
        self.assertIsInstance(self.client.session, NotificationSession)
        self.assertIn(failed_host, self.client._failed_servers)
        self.assertEqual(self.client.host, known_electrum_host)
        task.cancel()

    @unittest.skip("Not sure how to catch exceptions in a coroutine")
    async def test_on_connection_failure_servers_raises(self):
        self.client._servers = {failed_host: known_electrum_config}
        self.client.host = failed_host
        self.assertRaises(CannotConnectToAnyElectrumXServer, await self.client._on_connection_failure())
        self.assertIsNone(self.client.session, NotificationSession)
        self.assertIn(failed_host, self.client._failed_servers)

    @patch('random.choice', return_value=known_electrum_host)
    async def test_connect_fails_but_connects_to_other_server(self, mock):
        self.client._servers[failed_host] = known_electrum_config
        self.assertIsNone(self.client.session)
        self.client.host = failed_host
        self.client.port = int(known_electrum_config['t'])
        task = asyncio.create_task(self.client.connect_to_any_server())
        await asyncio.wait_for(self.client.wait_new_start(), timeout=5)
        self.assertEqual(self.client.host, known_electrum_host)
        self.assertIsInstance(self.client.session, NotificationSession)
        task.cancel()

    @patch('random.choice', return_value=known_electrum_host)
    async def test_ensure_connection(self, mock):
        self.assertIsNone(self.client.host)
        self.assertIsNone(self.client.session)
        await self.client._ensure_connected()
        self.assertEqual(self.client.host, known_electrum_host)
        self.assertIsInstance(self.client.session, NotificationSession)
        session = self.client.session
        await self.client._ensure_connected()
        self.assertEqual(self.client.host, known_electrum_host)
        self.assertIsInstance(self.client.session, NotificationSession)
        self.assertEqual(session, self.client.session)

    @patch('random.choice', return_value=known_electrum_host)
    async def test_send_request(self, mock):
        result = await self.client.send_request('blockchain.block.header', 1)
        self.assertEqual(result,
                         "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299")

    async def test_subscribe_no_params_ok(self):
        queue = asyncio.Queue()
        await self.client.subscribe(queue.put, 'blockchain.headers.subscribe')
        result = await queue.get()
        self.assertIsInstance(result['height'], int)
        self.assertIsInstance(result['hex'], str)
        self.assertEqual(len(self.client.session.subscriptions['blockchain.headers.subscribe[]']), 1)
        await self.client.unsubscribe('blockchain.headers.subscribe')
        self.assertEqual(self.client.session.subscriptions['blockchain.headers.subscribe[]'], [])

    async def test_subscribe_with_params_ok(self):
        queue = asyncio.Queue()
        # 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa (Satoshi)
        scripthash = "8b01df4e368ea28f8dc0423bcf7a4923e3a12d307c875e47a0cfbf90b5c39161"
        await self.client.subscribe(partial(on_scripthash_notification, queue), 'blockchain.scripthash.subscribe', scripthash)
        result = await queue.get()
        print("test received result", result)
        self.assertEqual(result[0], scripthash)
        print(result[1])
        self.assertIn(result[1], ["d3963224a9bd533cfbada37a8f05d90ca7fea1aeba699090eac467f01a0355a1",
                                  "f5a9c884b1d2054a8c52ce4d1b453ba1bdbc9ebf7aaaab4b7b458545b64faecf"])
        self.assertEqual(
            len(self.client.session.subscriptions[f"blockchain.scripthash.subscribe['{scripthash}']"]), 1)
        await self.client.unsubscribe('blockchain.scripthash.subscribe')
        self.assertEqual(
            len(self.client.session.subscriptions[f"blockchain.scripthash.subscribe['{scripthash}']"]), 0)

    async def test_subscribe_ok_after_reconnection(self):
        queue = asyncio.Queue()
        await self.client.subscribe(queue.put, 'blockchain.headers.subscribe')
        result1 = await queue.get()
        host1 = self.client.host
        self.assertEqual(len(self.client.session.subscriptions['blockchain.headers.subscribe[]']), 1)
        await self.client.redo_connection()
        await self.client.wait_new_start()
        host2 = self.client.host
        assert host1 != host2
        await asyncio.sleep(2)
        try:
            result2 = queue.get_nowait()
            assert result2 != result1
        except asyncio.QueueEmpty:
            pass
        self.assertEqual(len(self.client.session.subscriptions['blockchain.headers.subscribe[]']), 1)

    async def test_estimate_fee_async(self):
        pass

    async def test_cancel_all_subscriptions_async(self):
        pass

    async def test_close(self):
        pass


class TestElectrumSSLClient(unittest.IsolatedAsyncioTestCase):

    def setUp(self) -> None:
        self.client = ElectrumXClient(use_ssl=True, connection_timeout=10, client_name=client_name)

    async def asyncTearDown(self) -> None:
        await self.client.close()

    def test_choose_new_server(self):
        server = self.client._choose_new_server()
        server_config = self.client._servers[server]
        self.assertIn("s", server_config.keys())

    async def test_get_ssl_context(self,):
        context = await self.client._get_ssl_context()
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)

    @patch('random.choice', return_value=known_electrum_ssl_host)
    async def test_connect(self, mock):
        self.assertIsNone(self.client.session)
        self.client._set_new_server()
        task = asyncio.create_task(self.client._connect())
        await asyncio.wait_for(self.client.wait_new_start(), timeout=5)
        self.assertIsInstance(self.client.session, NotificationSession)
        self.assertListEqual(self.client.server_version, known_electrum_ssl_version)
        self.assertEqual(self.client.port, 50002)
        task.cancel()
    async def test_send_request_async(self):
        result = await self.client.send_request('blockchain.block.header', 1)
        self.assertEqual(result,
                         "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299")


class TestElectrumSSLAcceptSignedClient(unittest.IsolatedAsyncioTestCase):

    def setUp(self) -> None:
        self.client = ElectrumXClient(use_ssl=True, connection_timeout=10, client_name=client_name,
                                      accept_self_signed_certs=True)

    async def asyncTearDown(self) -> None:
        await self.client.close()

    def test_choose_new_server(self):
        server = self.client._choose_new_server()
        server_config = self.client._servers[server]
        self.assertIn("s", server_config.keys())

    async def test_get_ssl_context(self,):
        context = await self.client._get_ssl_context()
        self.assertFalse(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_NONE)

    @patch('random.choice', return_value=known_electrum_host)
    async def test_connect(self, mock):
        self.assertIsNone(self.client.session)
        self.client._set_new_server()
        task = asyncio.create_task(self.client._connect())
        await asyncio.wait_for(self.client.wait_new_start(), timeout=10)
        self.assertIsInstance(self.client.session, NotificationSession)
        self.assertListEqual(self.client.server_version, known_electrum_expected_version)
        self.assertEqual(self.client.port, 50002)
        task.cancel()

    async def test_send_request_async(self):
        result = await self.client.send_request('blockchain.block.header', 1)
        self.assertEqual(result,
                         "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299")


class TestElectrumClientNotifications(unittest.IsolatedAsyncioTestCase):

    def setUp(self) -> None:
        self.client = ElectrumXClient(use_ssl=False, connection_timeout=10,
                                      client_name=client_name, server_file="testing.json")

    def tearDown(self) -> None:
        reset_cycles()

    async def asyncSetUp(self) -> None:
        self.server_is_started = asyncio.Future()
        self.server2_is_started = asyncio.Future()
        self.server_task = asyncio.create_task(run_server(self.server_is_started))
        self.server_task_2 = asyncio.create_task(run_server(self.server2_is_started, host="127.0.0.2"))
        await asyncio.wait([self.server_is_started, self.server2_is_started])

    async def asyncTearDown(self) -> None:
        await self.client.close()
        print('Cancelling servers')
        self.server_task.cancel()
        self.server_task_2.cancel()
        print('Servers cancelled')
        await asyncio.wait([self.server_task, self.server_task_2])
        await asyncio.sleep(1)  # Avoids unfortunate loop closed error

    def test_client(self):
        self.assertEqual(self.client._servers, {
            "127.0.0.1": {
                "pruning": "-",
                "t": "44444",
                "s": "44445",
                "version": "1.4.2"
            },
            "127.0.0.2": {
                "pruning": "-",
                "t": "44444",
                "s": "44445",
                "version": "1.4.2"
            }
})

    async def test_subscribe_async_callback(self):
        queue = asyncio.Queue()
        expected_hex = "0000ff3f7586812b8a8677342ceef85916c2667b63468a8d19d0604c2e000000000000005292d8eba79db851be100996f48147df69386b43bf7fcb5e3361cf46f9ea8ed8a3214463ffff001d51c56337"
        expected_hex2 = "00004a2920c2d8311e12d3e35b8da48ad29b1254e0a0d2be1623d717f69000000000000001aaf14e207eea7f36cdc1cf92a8d43a5db2ac1ce22925e104ccedca3b5d2d26892544630194331933c10227"
        await self.client.subscribe(queue.put, 'blockchain.headers.subscribe', )
        result1 = await asyncio.wait_for(queue.get(), 60)
        self.assertEqual(result1['height'], 2350325)
        self.assertEqual(result1['hex'], expected_hex)
        result2 = await asyncio.wait_for(queue.get(), 60)
        self.assertEqual(result2['height'], 2350326)
        self.assertEqual(result2['hex'], expected_hex2)

    async def test_subscribe_async_callback_with_params(self):
        queue = asyncio.Queue()
        scripthash = "d6d88921b140325198c759d8509563add48c32c65433811a181f7385a6585add"
        expected_status = "e1969d52d5c94cdc9f3839ef720eec70282ce4c76d3634d2bdf138e24b223dc8"
        expected_status2 = "e1969d52d5c94cdc9f3839ef720eec70282ce4c76d3634d2bdf138e24b223d44"
        await self.client.subscribe(partial(on_scripthash_notification, queue),
                                    'blockchain.scripthash.subscribe', scripthash)
        result1 = await asyncio.wait_for(queue.get(), 60)
        self.assertEqual(result1[0], scripthash)
        self.assertEqual(result1[1], expected_status)
        result2 = await asyncio.wait_for(queue.get(), 60)
        self.assertEqual(result2[0], scripthash)
        self.assertEqual(result2[1], expected_status2)


    async def test_subscribe_sync_callback(self):
        queue = janus.Queue()
        expected_hex = "0000ff3f7586812b8a8677342ceef85916c2667b63468a8d19d0604c2e000000000000005292d8eba79db851be100996f48147df69386b43bf7fcb5e3361cf46f9ea8ed8a3214463ffff001d51c56337"
        expected_hex2 = "00004a2920c2d8311e12d3e35b8da48ad29b1254e0a0d2be1623d717f69000000000000001aaf14e207eea7f36cdc1cf92a8d43a5db2ac1ce22925e104ccedca3b5d2d26892544630194331933c10227"
        await self.client.subscribe(queue.sync_q.put, 'blockchain.headers.subscribe')
        result1 = await asyncio.wait_for(queue.async_q.get(), 60)
        self.assertEqual(result1['height'], 2350325)
        self.assertEqual(result1['hex'], expected_hex)
        result2 = await asyncio.wait_for(queue.async_q.get(), 60)
        self.assertEqual(result2['height'], 2350326)
        self.assertEqual(result2['hex'], expected_hex2)

    async def test_subscribe_sync_callback_with_params(self):
        queue = janus.Queue()
        scripthash = "d6d88921b140325198c759d8509563add48c32c65433811a181f7385a6585add"
        expected_status = "e1969d52d5c94cdc9f3839ef720eec70282ce4c76d3634d2bdf138e24b223dc8"
        expected_status2 = "e1969d52d5c94cdc9f3839ef720eec70282ce4c76d3634d2bdf138e24b223d44"
        await self.client.subscribe(partial(on_scripthash_notification_sync_from_async, queue),
                                    'blockchain.scripthash.subscribe', scripthash)
        result1 = await asyncio.wait_for(queue.async_q.get(), 60)
        self.assertEqual(result1[0], scripthash)
        self.assertEqual(result1[1], expected_status)
        result2 = await asyncio.wait_for(queue.async_q.get(), 60)
        self.assertEqual(result2[0], scripthash)
        self.assertEqual(result2[1], expected_status2)

    async def test_subscribe_ok_after_reconnection(self):
        queue = asyncio.Queue()
        await self.client.subscribe(queue.put, 'blockchain.headers.subscribe')
        expected_hex = "0000ff3f7586812b8a8677342ceef85916c2667b63468a8d19d0604c2e000000000000005292d8eba79db851be100996f48147df69386b43bf7fcb5e3361cf46f9ea8ed8a3214463ffff001d51c56337"
        expected_hex2 = "00004a2920c2d8311e12d3e35b8da48ad29b1254e0a0d2be1623d717f69000000000000001aaf14e207eea7f36cdc1cf92a8d43a5db2ac1ce22925e104ccedca3b5d2d26892544630194331933c10227"
        expected_hex3 = "0000552920c2d8311e12d3e35b8da48ad29b1254e0a0d2be1623d717f69000000000000001aaf14e207eea7f36cdc1cf92a8d43a5db2ac1ce22925e104ccedca3b5d2d26892544630194331933c10227"
        result1 = await queue.get()
        self.assertEqual(result1['height'], 2350325)
        self.assertEqual(result1['hex'], expected_hex)
        host1 = self.client.host
        self.assertEqual(len(self.client.session.subscriptions['blockchain.headers.subscribe[]']), 1)
        result2 = await queue.get()
        self.assertEqual(result2['height'], 2350326)
        self.assertEqual(result2['hex'], expected_hex2)
        print('sleeping')
        await asyncio.sleep(3)
        print('Checking queue size')
        print(queue.qsize())
        self.assertRaises(asyncio.QueueEmpty, queue.get_nowait)
        print('Redoing connection')
        await self.client.redo_connection()
        print('Waiting new start')
        await self.client.wait_new_start()
        print('Connection redone')
        host2 = self.client.host
        assert host1 != host2
        print('waiting on result3')
        result3 = await queue.get()
        print('result3 received')
        self.assertEqual(result3['height'], 2350327)
        self.assertEqual(result3['hex'], expected_hex3)
        self.assertRaises(asyncio.QueueEmpty, queue.get_nowait)
        self.assertEqual(len(self.client.session.subscriptions['blockchain.headers.subscribe[]']), 1)


class TestElectrumXSyncClient(unittest.IsolatedAsyncioTestCase):

    def setUp(self) -> None:
        self.client = ElectrumXSyncClient(use_ssl=False, client_name=client_name)

    def tearDown(self) -> None:
        self.client.close()

    def test_send_request(self):
        result = self.client.send_request('blockchain.block.header', 1)
        self.assertEqual(result,
                         "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299")


class TestElectrumXSyncClientSubscriptions(unittest.IsolatedAsyncioTestCase):

    def setUp(self) -> None:
        self.client = ElectrumXSyncClient(use_ssl=False, client_name=client_name, server_file="testing.json")
        self.stop_server_fut = Future()
        run_server_in_thread(self.stop_server_fut)

    def tearDown(self) -> None:
        self.client.close()
        self.stop_server_fut.set_result(None)
        reset_cycles()

    def test_subscribe_sync_callback(self):
        queue = Queue()
        expected_hex = "0000ff3f7586812b8a8677342ceef85916c2667b63468a8d19d0604c2e000000000000005292d8eba79db851be100996f48147df69386b43bf7fcb5e3361cf46f9ea8ed8a3214463ffff001d51c56337"
        expected_hex2 = "00004a2920c2d8311e12d3e35b8da48ad29b1254e0a0d2be1623d717f69000000000000001aaf14e207eea7f36cdc1cf92a8d43a5db2ac1ce22925e104ccedca3b5d2d26892544630194331933c10227"
        self.client.subscribe(queue.put, 'blockchain.headers.subscribe')
        result1 = queue.get(timeout=20)
        self.assertEqual(result1['height'], 2350325)
        self.assertEqual(result1['hex'], expected_hex)
        result2 = queue.get(timeout=20)
        self.assertEqual(result2['height'], 2350326)
        self.assertEqual(result2['hex'], expected_hex2)
        self.assertEqual(len(self.client._client.session.subscriptions['blockchain.headers.subscribe[]']), 1)
        self.client.unsubscribe('blockchain.headers.subscribe')
        self.assertEqual(self.client._client.session.subscriptions['blockchain.headers.subscribe[]'], [])

    def test_subscribe_sync_callback_with_params(self):
        queue = Queue()
        scripthash = "d6d88921b140325198c759d8509563add48c32c65433811a181f7385a6585add"
        expected_status = "e1969d52d5c94cdc9f3839ef720eec70282ce4c76d3634d2bdf138e24b223dc8"
        expected_status2 = "e1969d52d5c94cdc9f3839ef720eec70282ce4c76d3634d2bdf138e24b223d44"
        self.client.subscribe(partial(on_scripthash_notification_sync, queue),
                              'blockchain.scripthash.subscribe', scripthash)
        result1 = queue.get(timeout=60)
        self.assertEqual(result1[0], scripthash)
        self.assertEqual(result1[1], expected_status)
        result2 = queue.get(timeout=60)
        self.assertEqual(result2[0], scripthash)
        self.assertEqual(result2[1], expected_status2)
        self.assertEqual(
            len(self.client._client.session.subscriptions[f"blockchain.scripthash.subscribe['{scripthash}']"]), 1)
        self.client.unsubscribe('blockchain.scripthash.subscribe')
        self.assertEqual(
            len(self.client._client.session.subscriptions[f"blockchain.scripthash.subscribe['{scripthash}']"]), 0)

