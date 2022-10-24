import argparse
import binascii
import asyncio
import sys
from cryptos.coins_async import Bitcoin, BaseCoin
from cryptos.main import safe_hexlify
from cryptos.transaction import json_changebase
from pprint import pprint
from typing import Callable, Any, Union, Optional


def get_coin(testnet: bool = False):
    return Bitcoin(testnet=testnet)


async def run_in_executor(func: Callable, *args) -> Any:
    return await asyncio.get_running_loop().run_in_executor(None, func, *args)


def is_block_height(coin: BaseCoin, obj_id: Union[str, int]) -> Optional[int]:
    try:
        return int(obj_id)
    except ValueError:
        return None


def is_tx(coin: BaseCoin, obj_id: str) -> Optional[str]:
    try:
        tx_id = binascii.unhexlify(obj_id)
        if len(tx_id) == coin.txid_bytes_len:
            return obj_id
        return None
    except binascii.Error:
        return None


def is_address(coin: BaseCoin, obj_id: str) -> Optional[str]:
    return obj_id if coin.is_address(obj_id) else None


async def print_item(obj_id: str, testnet: bool = False) -> None:
    coin = get_coin(testnet=testnet)
    try:
        if address := is_address(coin, obj_id):
            history, unspent, balances = await asyncio.gather(coin.history(address), coin.unspent(address), coin.get_balance(address))
            print('HISTORY:')
            for h in history:
                print(' '.join([f"{k}: {v}" for k, v in h.items()]))
            print(f'\nUNSPENTS')
            for u in unspent:
                u['confirmations'] = await coin.confirmations(u['height'])
                print(' '.join([f"{k}: {v}" for k, v in u.items()]))
            print('\n')
            for k, v in balances.items():
                print(f'{k.capitalize()} Balance: {v}')
            len_history = len(history)
            len_unspent = len(unspent)
            plural_history = '' if len_history == 1 else 's'
            plural_unspent = '' if len_unspent == 1 else 's'
            print(f'\nThis address was found in {len_history} transaction{plural_history} and has {len_unspent} unspent{plural_unspent}.')
        elif tx_id := is_tx(coin, obj_id):
            tx = await coin.get_verbose_tx(tx_id)
            pprint(tx)
        elif block_height := is_block_height(coin, obj_id):
            header = await coin.block_header(block_height)
            header = json_changebase(header, lambda x: safe_hexlify(x))
            pprint(header)
        coin_other_net = get_coin(testnet=not testnet)
        try:
            if coin_other_net.is_address(obj_id):
                if testnet:
                    sys.stderr.write(f"{obj_id} is a mainnet address. Try again without --testnet")
                else:
                    sys.stderr.write(f"{obj_id} is a testnet address. Try again with --testnet")
        finally:
            await coin_other_net.close()
            sys.exit(1)
    finally:
        await coin.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("obj", help="Object to search for, either a transaction ID, block height or address")
    parser.add_argument("-t", "--testnet", help="For testnet", action="store_true")
    args = parser.parse_args()
    asyncio.run(print_item(args.obj, testnet=args.testnet))
