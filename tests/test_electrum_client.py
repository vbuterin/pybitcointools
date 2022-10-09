import unittest
import asyncio
from cryptos.electrumx_client.client import ElectrumXClient, NotificationSession, CannotConnectToAnyElectrumXServer, ElectrumXSyncClient
from unittest.mock import patch
import ssl
from typing import List


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


class TestElectrumClient(unittest.IsolatedAsyncioTestCase):

    def setUp(self) -> None:
        self.client = ElectrumXClient(use_ssl=False, connection_timeout=10, client_name=client_name)

    async def asyncTearDown(self) -> None:
        await self.client.close()

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
        await asyncio.wait_for(self.client.is_connected.wait(), timeout=5)
        self.assertIsInstance(self.client.session, NotificationSession)
        self.assertListEqual(self.client.server_version, known_electrum_expected_version)
        task.cancel()

    @patch('random.choice', return_value=known_electrum_host)
    async def test_connect_to_any_server(self, mock):
        self.assertIsNone(self.client.session)
        task = asyncio.create_task(self.client.connect_to_any_server())
        await asyncio.wait_for(self.client.is_connected.wait(), timeout=5)
        self.assertIsInstance(self.client.session, NotificationSession)
        task.cancel()

    @patch('random.choice', return_value=known_electrum_host)
    async def test_on_connection_failure(self, mock):
        self.assertIsNone(self.client.session)
        self.client.host = failed_host
        task = asyncio.create_task(self.client._on_connection_failure())
        await asyncio.wait_for(self.client.is_connected.wait(), timeout=5)
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
        await asyncio.wait_for(self.client.is_connected.wait(), timeout=5)
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
    async def test_send_request_async(self, mock):
        result = await self.client.send_request('blockchain.block.header', 1)
        self.assertEqual(result,
                         "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299")

    async def test_ping_async(self):
        pass

    async def test_estimate_fee_async(self):
        pass

    async def test_subscribe_async(self):
        pass

    async def test_cancel_all_subscriptions_async(self):
        pass

    def send_request(self):
        pass

    def send_notification(self):
        pass

    def test_ping(self):
        pass

    def test_server_version(self):
        pass

    def test_estimate_fee(self):
        pass

    def test_subscribe(self):
        pass

    def test_cancel_all_subscriptions(self):
        pass

    def test_close(self):
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
        await asyncio.wait_for(self.client.is_connected.wait(), timeout=5)
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
        await asyncio.wait_for(self.client.is_connected.wait(), timeout=10)
        self.assertIsInstance(self.client.session, NotificationSession)
        self.assertListEqual(self.client.server_version, known_electrum_expected_version)
        self.assertEqual(self.client.port, 50002)
        task.cancel()

    async def test_send_request_async(self):
        result = await self.client.send_request('blockchain.block.header', 1)
        self.assertEqual(result,
                         "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299")



class TestElectrumXSyncClient(unittest.IsolatedAsyncioTestCase):

    def setUp(self) -> None:
        self.client = ElectrumXSyncClient(use_ssl=False, client_name=client_name)

    def tearDown(self) -> None:
        self.client.close()

    def test_send_request(self):
        result = self.client.send_request('blockchain.block.header', 1)
        self.assertEqual(result,
                         "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299")


