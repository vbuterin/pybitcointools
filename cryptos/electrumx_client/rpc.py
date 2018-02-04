#!/usr/bin/env python3
#
# Copyright (c) 2016, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Script to send RPC commands to a running ElectrumX server.'''


import asyncio
import json
import random
import os
from functools import partial

from .jsonrpc import JSONSession, JSONRPCv2


class RPCClient(JSONSession):

    def __init__(self):
        super().__init__(version=JSONRPCv2)
        self.max_send = 0
        self.max_buffer_size = 5*10**6
        self.result = {}

    async def wait_for_response(self, id_):
        from datetime import datetime
        now = datetime.now()
        await self.items_events[id_].wait()
        print(id_, "event raised:", datetime.now() - now)
        await self.process_pending_items()
        self.items_events[id_].clear()
        del self.items_events[id_]
        return self.result.pop(id_)

    def send_rpc_request(self, method, params):
        handler = partial(self.handle_response, method, params)
        return self.send_request(handler, method, params)

    def handle_response(self, method, params, id_, data, error):
        self.result[id_] = {'data': data, 'error': error, 'method': method, 'params': params}


def read_json(filename, default):
    path = os.path.join(os.path.dirname(__file__), 'servers', filename)
    try:
        with open(path, 'r') as f:
            r = json.loads(f.read())
    except:
        r = default
    return r

class ElectrumXClient(RPCClient):

    def __init__(self, server_file="bitcoin.json", servers=(), host=None, port=50001, timeout=15, max_servers=5, loop=None):
        super().__init__()
        if loop:
            self.loop = loop
        else:
            self.loop = asyncio.get_event_loop()
        self.timeout = timeout
        self.failed_hosts = []
        self.max_servers = max_servers
        if servers:
            self.servers = servers
        else:
            self.servers = read_json(server_file, {})
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
        except OSError:
            self.change_server()

    def change_server(self):
        if self.rpc_client:
            self.rpc_client.close()
        if self.host not in self.failed_hosts:
            self.failed_hosts.append(self.host)
        if len(self.failed_hosts) >= self.max_servers:
            raise Exception("Attempted to connect to %s servers but failed" % len(self.failed_hosts))
        while self.host in self.failed_hosts:
            self.host, self.port = self.choose_random_server()
        self.connect_to_server()

    def rpc_multiple_send_and_wait(self, requests):
        from datetime import datetime
        coroutines = []
        for request in requests:
            method, params = request
            try:
                now = datetime.now()
                id_ = self.rpc_client.send_rpc_request(method, params)
                print(id_, "Request sent:", datetime.now() - now)
                try:
                    coro = self.rpc_client.wait_for_response(id_)
                    coroutines.append(asyncio.wait_for(coro, self.timeout))
                except asyncio.TimeoutError:
                    self.change_server()
                    return self.rpc_multiple_send_and_wait(requests)
            except OSError:
                self.change_server()
                return self.rpc_multiple_send_and_wait(requests)
        now = datetime.now()
        values = self.loop.run_until_complete(asyncio.gather(*coroutines))
        print("Values gathered:", datetime.now() - now)
        self.failed_hosts = []
        return values

    def unspent(self, *addrs):
        requests = [("blockchain.address.listunspent", [addr]) for addr in addrs]
        results = self.rpc_multiple_send_and_wait(requests)
        unspents = []
        for i, result in enumerate(results):
            if result['error']:
                raise Exception(result['error'])
            unspent_for_addr = result['data']
            addr = result['params'][0]
            for u in unspent_for_addr:
                u['address'] = addr
                unspents.append(u)
        return unspents

    