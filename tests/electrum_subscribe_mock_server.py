import asyncio
import json
import itertools
import threading
from concurrent.futures import Future
from ssl import create_default_context, Purpose
from typing import Dict, Union


counters = {}


def reset_counter():
    counters['block'] = itertools.count(2350325)


reset_counter()


async def send_message(writer, data: Dict[str, Union[int, str, dict]]) -> None:
    data['jsonrpc'] = "2.0"

    out_message = (json.dumps(data) + "\n").encode()

    print('sending', out_message)

    writer.write(out_message)
    await writer.drain()


async def handle_rpc(reader, writer):
    while not writer.transport.is_closing():
        print('Server Reading data')
        msg = await reader.readline()
        print('Server received data', msg)
        if msg:
            data = msg.decode()

            data = json.loads(data)
            print("Server json data", data)
            msg_id = data['id']
            method = data['method']
            print("Server received method", method)
            if method == "server.version":
                response = {"result": ["ElectrumXMock 1.16.0", "1.4"], "id": msg_id}
                await send_message(writer, response)
            elif method == "server.ping":
                response = {"result": None, "id": msg_id}
                await send_message(writer, response)
            elif method == "blockchain.headers.subscribe":
                response = {"result": {
                    "height": next(counters['block']),
                    "hex": "0000ff3f7586812b8a8677342ceef85916c2667b63468a8d19d0604c2e000000000000005292d8eba79db851be100996f48147df69386b43bf7fcb5e3361cf46f9ea8ed8a3214463ffff001d51c56337"
                }, "id": msg_id}
                await send_message(writer, response)
                await asyncio.sleep(2)
                response = {
                    "method": method,
                    "params": [{
                        "height": next(counters['block']),
                        "hex": "00004a2920c2d8311e12d3e35b8da48ad29b1254e0a0d2be1623d717f69000000000000001aaf14e207eea7f36cdc1cf92a8d43a5db2ac1ce22925e104ccedca3b5d2d26892544630194331933c10227"
                    }]
                }
                await send_message(writer, response)
            else:
                response = {"error": {"code": -32601, "message": f"Method {method} is not supported by this mock server", "id": msg_id}}
                await send_message(writer, response)
        else:
            print('Closing writer')
            writer.close()
    print('Server stopped while loop')


async def get_server(fut: Union[asyncio.Future, Future], host: str = "127.0.0.1", ssl: bool = False):
    port = 44445 if ssl else 44444
    context = create_default_context(purpose=Purpose.SERVER_AUTH) if ssl else None
    server = await asyncio.start_server(
        handle_rpc, host, port, ssl=context)

    sock = server.sockets[0]
    listening_on = sock.getsockname()

    asyncio.get_running_loop().call_soon(fut.set_result, listening_on)

    return server


async def run_server(fut: asyncio.Future, host: str = "127.0.0.1", ssl: bool = False):
    server = await get_server(fut, host=host, ssl=ssl)
    async with server:
        await server.serve_forever()


async def run_server_until_cancelled(fut: Future, stop_fut: Future, host: str = "127.0.0.1", ssl: bool = False):
    stop_fut_async = asyncio.wrap_future(stop_fut)
    server = await get_server(fut, host=host, ssl=ssl)
    async with server:
        await asyncio.wait([asyncio.create_task(server.serve_forever()), stop_fut_async], return_when=asyncio.FIRST_COMPLETED)


def run_in_loop(fut: Future, stop_fut: Future, host: str = '127.0.0.1', ssl: bool = False):
    asyncio.run(run_server_until_cancelled(fut, stop_fut, host=host, ssl=ssl))


def run_server_in_thread(stop_fut: Future, host: str = '127.0.0.1', ssl: bool = False):
    fut = Future()
    thread = threading.Thread(target=run_in_loop, args=(fut, stop_fut), kwargs={'host': host, 'ssl': ssl}, daemon=True)
    thread.start()
    return fut.result(10)
