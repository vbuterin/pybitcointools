import argparse
import asyncio
from cryptos.script_utils import get_coin, coin_list
from cryptos.transaction import deserialize
from pprint import pprint


async def broadcast_tx(tx: str, coin_symbol: str, testnet: bool):
    c = get_coin(coin_symbol, testnet=testnet)
    try:
        print('Broadcasting transaction:')
        pprint(deserialize(tx))
        await c.pushtx(tx)
    finally:
        await c.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("tx", help="Transaction Hex", type=str)
    parser.add_argument("-x", "--coin", help="Coin",  choices=coin_list, default="btc")
    parser.add_argument("-t", "--testnet", help="For testnet", action="store_true")
    args = parser.parse_args()
    asyncio.run(broadcast_tx(args.tx, coin_symbol=args.coin, testnet=args.testnet))


if __name__ == "__main__":
    main()
