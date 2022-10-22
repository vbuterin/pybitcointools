import asyncio
from datetime import datetime
from cryptos.coins_async.bitcoin import Bitcoin
from cryptos.types import BlockHeader, ElectrumXTx
import sys
from typing import List

addresses = sys.argv[1:]


c = Bitcoin(testnet=True)


async def print_balances(addr, now):
    for balance in await asyncio.gather(c.get_balance(addr), c.balance_merkle_proven(addr)):
        print(now, addr, balance)


async def on_new_block(height: int, hex_header: str, header: BlockHeader) -> None:
    now = datetime.now()
    print(now, 'New Block at height', height)
    print(now, header)
    await asyncio.wait([asyncio.create_task(print_balances(addr, now)) for addr in addresses])


async def on_address_change(address: str, new_txs: List[ElectrumXTx], newly_confirmed: List[ElectrumXTx],
                            history: List[ElectrumXTx], unspent: List[ElectrumXTx],
                            confirmed_balance: int, unconfirmed_balance: int, proven: int) -> None:
    now = datetime.now()
    print(now, "Address", address, "changed")
    for tx in new_txs:
        print(now, "New tx for address: ", address)
        print(now, tx)
    for tx in newly_confirmed:
        print(now, "TX has been confirmed for address: ", address)
        print(now, tx)
    print(now, 'Confirmed:', confirmed_balance, "Unconfirmed", unconfirmed_balance, 'Proven Balance:', proven)
    for u in unspent:
        u['confirmations'] = await c.confirmations(u['height'])
    print(now, "Unspent:", unspent)


async def subscribe():
    await c.subscribe_to_block_headers(on_new_block)
    await asyncio.wait([asyncio.create_task(c.subscribe_to_address_transactions(on_address_change, a)) for a in addresses])
    fut = asyncio.Future()
    await fut


asyncio.run(subscribe())
