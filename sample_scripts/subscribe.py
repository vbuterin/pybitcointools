import asyncio
from cryptos.coins_async.bitcoin import Bitcoin
from cryptos.types import BlockHeader, ElectrumXTx
from functools import partial
import logging
import sys
from typing import List, Union


logger = logging.getLogger("subscriptions")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler(stream=sys.stdout)
formatter = logging.Formatter(fmt="%(asctime)s - %(message)s")     # %(asctime)s
handler.setFormatter(formatter)
logger.addHandler(handler)


addresses = sys.argv[1:]


c = Bitcoin(testnet=True)


async def log_unspents(address, unspent: List[ElectrumXTx]) -> None:
    for u in unspent:
        u['confirmations'] = await c.confirmations(u['height'])
    logger.info("%s - Unspents: %s", address, unspent)


async def print_balances(addr):
    balances, merkle_proven, unspents = await asyncio.gather(c.get_balance(addr), c.balance_merkle_proven(addr), c.unspent(addr))
    balances['merkle_proven'] = merkle_proven
    logger.info("%s - %s", addr, balances)
    await log_unspents(addr, unspents)


async def on_new_block(start_block: List[Union[int, str, BlockHeader]], height: int, hex_header: str,
                       header: BlockHeader) -> None:
    if start_block:
        logger.info("New Block at height: %s: %s", height, header)
    else:
        start_block += (height, hex_header, header)
        logger.info("Current Block is at height: %s: %s", height, header)
    await asyncio.wait([asyncio.create_task(print_balances(addr)) for addr in addresses])


async def on_address_change(address: str, new_txs: List[ElectrumXTx], newly_confirmed: List[ElectrumXTx],
                            history: List[ElectrumXTx], unspent: List[ElectrumXTx],
                            confirmed_balance: int, unconfirmed_balance: int, proven: int) -> None:
    balances = f'Confirmed: {confirmed_balance} Unconfirmed: {unconfirmed_balance} Proven Balance: {proven}'
    if new_txs or newly_confirmed:
        logger.info("%s - Changed: %s", address, balances)
    else:
        logger.info("%s - Current status is: %s", address, balances)
    for tx in new_txs:
        logger.info("%s - New TX: %s", address, tx)
    for tx in newly_confirmed:
        logger.info("%s -TX has been confirmed: %s", address, tx)
    await log_unspents(address, unspent)


async def subscribe():
    await c.subscribe_to_block_headers(partial(on_new_block, []))
    await asyncio.wait([asyncio.create_task(
        c.subscribe_to_address_transactions(on_address_change, a)) for a in addresses])
    fut = asyncio.Future()
    await fut


asyncio.run(subscribe())
