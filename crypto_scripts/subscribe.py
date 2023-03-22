import asyncio
import argparse
from cryptos.types import BlockHeader, ElectrumXTx
from functools import partial
import logging
import sys
from typing import List, Union, Tuple
from cryptos.coins_async.base import BaseCoin
from cryptos.script_utils import get_coin, coin_list


logger = logging.getLogger("subscriptions")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler(stream=sys.stdout)
formatter = logging.Formatter(fmt="%(asctime)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)


async def log_unspents(coin: BaseCoin, address: str, unspent: List[ElectrumXTx]) -> None:
    for u in unspent:
        u['confirmations'] = await coin.confirmations(u['height'])
    logger.info("%s - Unspents: %s", address, unspent)


async def print_balances(coin: BaseCoin, addr: str) -> None:
    balances, merkle_proven, unspents = await asyncio.gather(
        coin.get_balance(addr), coin.balance_merkle_proven(addr), coin.unspent(addr))
    balances['merkle_proven'] = merkle_proven
    logger.info("%s - %s", addr, balances)
    await log_unspents(coin, addr, unspents)


async def on_new_block(start_block: Tuple[Union[int, str, BlockHeader]], addresses: List[str], coin: BaseCoin,
                       height: int, hex_header: str, header: BlockHeader) -> None:
    if start_block[0] != height:
        logger.info("New Block at height: %s: %s", height, header)
    else:
        start_block += (height, hex_header, header)
        logger.info("Current Block is at height: %s: %s", height, header)
    await asyncio.wait([asyncio.create_task(print_balances(coin, addr)) for addr in addresses])


async def on_address_change(coin: BaseCoin, address: str, new_txs: List[ElectrumXTx], newly_confirmed: List[ElectrumXTx],
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
    await log_unspents(coin, address, unspent)


async def subscribe_to_addresses(addresses: List[str], coin_symbol: str, testnet: bool):
    coin = get_coin(coin_symbol, testnet=testnet)
    initial_block = await coin.block
    await coin.subscribe_to_block_headers(partial(on_new_block, initial_block, addresses, coin))
    await asyncio.wait([asyncio.create_task(
        coin.subscribe_to_address_transactions(partial(on_address_change, coin), a)) for a in addresses]
    )
    fut = asyncio.Future()
    await fut


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("addresses", help="Address to subscribe to", nargs="*")
    parser.add_argument("-x", "--coin", help="Coin",  choices=coin_list, default="btc")
    parser.add_argument("-t", "--testnet", help="For testnet", action="store_true")
    args = parser.parse_args()
    asyncio.run(subscribe_to_addresses(args.addresses, coin_symbol=args.coin, testnet=args.testnet))


if __name__ == "__main__":
    main()
