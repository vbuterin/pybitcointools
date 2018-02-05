#!/usr/bin/env python3
#
# Copyright (c) 2016, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Script to send RPC commands to a running ElectrumX server.'''

#https://github.com/kyuupichan/electrumx/blob/master/docs/PROTOCOL.rst

import asyncio
import json
import random
import os
from .. import constants
from functools import partial

from .jsonrpc import JSONSession, JSONRPCv2

class RPCResponseExecption(Exception):
    pass

class RPCClient(JSONSession):

    def __init__(self):
        super().__init__(version=JSONRPCv2)
        self.max_send = 0
        self.max_buffer_size = 5*10**6
        self.result = {}

    async def wait_for_response(self, id_):
        await self.items_events[id_].wait()
        await self.process_pending_items()
        self.items_events[id_].clear()
        del self.items_events[id_]
        return self.result.pop(id_)

    def send_rpc_request(self, method, params):
        handler = partial(self.handle_response, method, params)
        return self.send_request(handler, method, params)

    def handle_response(self, method, params, id_, data, error):
        self.result[id_] = {'data': data, 'error': error, 'method': method, 'params': params}


def read_json(path, default):
    if not os.path.isabs(path):
        path = os.path.join(os.path.dirname(__file__), 'servers', path)
    try:
        with open(path, 'r') as f:
            r = json.loads(f.read())
    except:
        r = default
    return r


class ElectrumXClient(RPCClient):

    def __init__(self, server_file="bitcoin.json", servers=(), host=None, port=50001, timeout=15, max_servers=5,
                 protocol_version=(constants.PROTOCOL_VERSION, constants.PROTOCOL_VERSION),
                 client_name=constants.CLIENT_NAME, loop=None):
        super().__init__()
        self.client_name = client_name
        self.protocol_version = protocol_version
        if loop:
            self.loop = loop
        else:
            self.loop = asyncio.get_event_loop()
        self.timeout = timeout
        self.failed_hosts = []
        self.max_servers = max_servers
        if not servers:
            servers = read_json(server_file, {})
        self.servers = {host: servers[host] for host in servers.keys() if servers[host].get('usable', True)}
        self.host = host
        self.port = port
        self.rpc_client = None
        if not self.host:
            self.host, self.port = self.choose_random_server()
        self.connect_to_server()

    def choose_random_server(self):
        host = random.choice(list(self.servers.keys()))
        try:
            return host, self.servers[host]['t']
        except KeyError:
            del self.servers[host]
            return self.choose_random_server()

    def connect_to_server(self):
        print(self.host, self.port)
        try:
            coro = self.loop.create_connection(RPCClient, self.host, self.port)
            transport, self.rpc_client = self.loop.run_until_complete(coro)
            try:
                result = self.server_version()
                self.server_software = result[0]
                self.server_protocol_version = result[1]
            except RPCResponseExecption:
                self.change_server()
        except OSError:
            self.change_server()

    def change_server(self):
        if self.rpc_client:
            self.rpc_client.close_connection()
        if self.host not in self.failed_hosts:
            self.failed_hosts.append(self.host)
        if len(self.failed_hosts) >= self.max_servers:
            raise Exception("Attempted to connect to %s servers but failed" % len(self.failed_hosts))
        while self.host in self.failed_hosts:
            self.host, self.port = self.choose_random_server()
        self.connect_to_server()

    def get_coroutines(self, requests):
        coroutines = []
        for request in requests:
            method, params = request
            try:
                id_ = self.rpc_client.send_rpc_request(method, params)
                try:
                    coro = self.rpc_client.wait_for_response(id_)
                    coroutines.append(asyncio.wait_for(coro, self.timeout))
                except asyncio.TimeoutError:
                    self.change_server()
                    return self.rpc_multiple_send_and_wait(requests)
            except OSError:
                self.change_server()
                return self.rpc_multiple_send_and_wait(requests)
        return coroutines

    def rpc_multiple_send_and_wait(self, requests):
        coroutines = self.get_coroutines(requests)
        values = self.loop.run_until_complete(asyncio.gather(*coroutines))
        self.failed_hosts = []
        return values

    def _block_header(self, *heights):
        method = 'blockchain.block.get_header'
        return [(method, (height,)) for height in heights]

    def block_header(self, *heights):
        requests = self._block_header(*heights)
        return self.rpc_multiple_send_and_wait(requests)

    def _get_merkle(self, *txs):
        method = 'blockchain.transaction.get_merkle'
        return [(method, (tx['tx_hash'], tx['height'])) for tx in txs]

    def get_merkle(self, *txs):
        requests = self._get_merkle(*txs)
        return self.rpc_multiple_send_and_wait(requests)

    def get_all_merkle_data(self, *txs):
        block_header_requests = self._block_header(*[tx['height'] for tx in txs])
        get_merkle_requests = self._get_merkle(*txs)
        results = self.rpc_multiple_send_and_wait(block_header_requests + get_merkle_requests)
        merkles = []
        for result in results:
            if 'merkle' in result.keys():
                block_header = next(r for r in results if r['height'] == results['block_height'])
                result['merkle_root'] = block_header['merkle_root']
                merkles.append(result)
        return merkles

    def run_command(self, request):
        request = [request]
        result = self.rpc_multiple_send_and_wait(request)[0]
        if result['error']:
            raise RPCResponseExecption(result['error'])
        return result['data']

    def _estimate_fee(self, numblocks):
        return 'blockchain.estimatefee', (numblocks,)

    def estimate_fee(self, numblocks):
        return self.run_command(self._estimate_fee(numblocks))

    def _relay_fee(self):
        return 'blockchain.relayfee', ()

    def relay_fee(self):
        return self.run_command(self._relay_fee())

    def _broadcast_transaction(self, raw_tx):
        return 'blockchain.transaction.broadcast', (raw_tx,)

    def broadcast_transaction(self, raw_tx):
        return self.run_command(self.broadcast_transaction(raw_tx))

    def _server_donation_address(self):
        return 'server.donation_address', ()

    def server_donation_address(self):
        return self.run_command(self._server_donation_address())

    def _server_banner(self):
        return 'server.banner', ()

    def server_banner(self):
        return self.run_command(self.server_banner())

    def _server_version(self, protocol_version=None, client_name=None):
        return 'server.version', (client_name or self.client_name, protocol_version or self.protocol_version)

    def server_version(self, protocol_version=None, client_name=None):
        return self.run_command(self._server_version(protocol_version=protocol_version, client_name=client_name))

    def _server_features(self):
        return 'server.features', ()

    def server_features(self):
        return self.run_command(self.server_features())

    def _get_balance(self, scripthash):
        return "blockchain.scripthash.get_balance", (scripthash,)

    def get_balance(self, addrs_scripthashes):
        requests = [self._get_balance(scripthash) for scripthash in addrs_scripthashes.keys()]
        results = self.rpc_multiple_send_and_wait(requests)
        balances = []
        for result in results:
            if result['error']:
                raise RPCResponseExecption(result['error'])
            b = result['data']
            scripthash = result['params'][0]
            addr = addrs_scripthashes[scripthash]
            b['address'] = addr
            b['total'] = b['confirmed'] + b['unconfirmed']
            balances.append(b)
        return balances

    def _get_unspent(self, scripthash):
        return "blockchain.scripthash.listunspent", (scripthash,)

    def unspent(self, addrs_scripthashes):
        requests = [self._get_unspent(scripthash) for scripthash in addrs_scripthashes.keys()]
        results = self.rpc_multiple_send_and_wait(requests)
        unspents = []
        for i, result in enumerate(results):
            if result['error']:
                raise RPCResponseExecption(result['error'])
            unspent_for_addr = result['data']
            scripthash = result['params'][0]
            addr = addrs_scripthashes[scripthash]
            for u in unspent_for_addr:
                u['address'] = addr
                unspents.append(u)
        return unspents

    def _get_mempool(self, scripthash):
        return "blockchain.scripthash.get_mempool", (scripthash,)

    def get_mempool(self, addrs_scripthashes):
        requests = [self._get_mempool(scripthash) for scripthash in addrs_scripthashes.keys()]
        results = self.rpc_multiple_send_and_wait(requests)
        txs = []
        for i, result in enumerate(results):
            if result['error']:
                raise RPCResponseExecption(result['error'])
            unspent_for_addr = result['data']
            scripthash = result['params'][0]
            addr = addrs_scripthashes[scripthash]
            for tx in unspent_for_addr:
                tx['address'] = addr
                txs.append(tx)
        return txs

    def _get_history(self, scripthash):
        return "blockchain.scripthash.get_history", (scripthash,)

    def history(self, addrs_scripthashes):
        requests = [self._get_history(scripthash) for scripthash in addrs_scripthashes.keys()]
        results = self.rpc_multiple_send_and_wait(requests)
        txs = []
        for i, result in enumerate(results):
            if result['error']:
                raise RPCResponseExecption(result['error'])
            txs_for_addr = result['data']
            scripthash = result['params'][0]
            addr = addrs_scripthashes[scripthash]
            for tx in txs_for_addr:
                tx['address'] = addr
                txs.append(tx)
        return txs

    def _get_tx(self, tx_hash):
        return "blockchain.transaction.get", (tx_hash,)

    def get_txs(self, *tx_hashes):
        requests = [self._get_tx(tx_hash) for tx_hash in tx_hashes]
        return self.rpc_multiple_send_and_wait(requests)