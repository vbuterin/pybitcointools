import asyncio
import json
import itertools
from ssl import create_default_context, Purpose
from typing import Dict, Union


counters = {}


def reset_counter():
    counters['block'] = itertools.count(520481)


reset_counter()


async def send_message(writer, data: Dict[str, Union[int, str, dict]]) -> None:
    data['jsonrpc'] = "2.0"

    out_message = json.dumps(data).encode()

    writer.write(out_message)
    await writer.drain()


async def handle_rpc(reader, writer):
    data = await reader.read(100)
    message = data.decode()

    data = json.loads(message)
    msg_id = data['id']
    method = data['method']
    if method == "server.version":
        response = {"result": ["ElectrumXMock 1.16.0", "1.4"], "id": msg_id}
        await send_message(writer, response)
    elif method == "server.ping":
        response = {"result": None, "id": msg_id}
        await send_message(writer, response)
    elif method == "blockchain.headers.subscribe":
        response = {"result": {
            "height": next(counters['block']),
            "hex": "00000020890208a0ae3a3892aa047c5468725846577cfcd9b512b50000000000000000005dc2b02f2d297a9064ee103036c14d678f9afc7e3d9409cf53fd58b82e938e8ecbeca05a2d2103188ce804c4"
        }, "id": msg_id}
        await send_message(writer, response)
        await asyncio.sleep(2)
        response = {"result": {
            "height": next(counters['block']),
            "hex": "00000020890208a0ae3a3892aa047c5468725846577cfcd9b512b50000000000000000005dc2b02f2d297a9064ee103036c14d678f9afc7e3d9409cf53fd58b82e938e8ecbeca05a2d2103188ce804c4"
        }}
        await send_message(writer, response)
    else:
        response = {"error": {"code": -32601, "message": f"Method {method} is not supported by this mock server", "id": msg_id}}
        await send_message(writer, response)


async def run_server(fut: asyncio.Future, ssl: bool = False):
    port = 44445 if ssl else 44444
    if ssl:
        context = create_default_context(purpose=Purpose.SERVER_AUTH)
    else:
        context = None
    server = await asyncio.start_server(
        handle_rpc, '127.0.0.1', port, ssl=context)

    sock = server.sockets[0]
    listening_on = sock.getsockname()

    asyncio.get_running_loop().call_soon(fut.set_result, listening_on)

    async with server:
        await server.serve_forever()
