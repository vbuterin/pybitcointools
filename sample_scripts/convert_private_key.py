import argparse
from cryptos.coins_async.base import BaseCoin
from cryptos.coins_async import Bitcoin


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("priv", help="Private Key")
    parser.add_argument("output_format", help="Output format", choices=['decimal', 'bin', 'bin_compressed', 'hex',
                                                                        'hex_compressed', 'wif', 'wif_compressed'])
    parser.add_argument("-s", "--script_type", help="Output format",
                        choices=BaseCoin.wif_script_types.keys(), default="p2pkh")
    parser.add_argument("-t", "--testnet", help="For testnet", action="store_true")
    args = parser.parse_args()
    coin = Bitcoin(testnet=args.testnet)
    print(coin.encode_privkey(args.priv, args.output_format, script_type=args.script_type))



