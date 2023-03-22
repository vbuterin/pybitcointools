import argparse
import asyncio
from cryptos.script_utils import get_coin, coin_list


async def print_block_bits(start: int, end: int, coin_symbol: str, testnet: bool):
    c = get_coin(coin_symbol, testnet=testnet)
    try:
        for i in range(start, end):
            block = await c.block_header(i)
            bits = block['bits']
            text = f'Block {i}: {bits}'
            if bits != 486604799:
                text = f'\033[1;3m{text}\033[0m'
            print(text)
    finally:
        await c.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("start", help="First block height", type=int)
    parser.add_argument("end", help="Final block height", type=int)
    parser.add_argument("-x", "--coin", help="Coin",  choices=coin_list, default="btc")
    parser.add_argument("-t", "--testnet", help="For testnet", action="store_true")
    args = parser.parse_args()
    asyncio.run(print_block_bits(args.start, args.end, coin_symbol=args.coin, testnet=args.testnet))


if __name__ == "__main__":
    main()
