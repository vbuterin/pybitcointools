import argparse
from cryptos.main import generate_private_key, encode_privkey
from cryptos.script_utils import get_coin, coin_list


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-x", "--coin", help="Coin",  choices=coin_list, default="btc")
    parser.add_argument("-t", "--testnet", help="For testnet", action="store_true")
    args = parser.parse_args()

    coin = get_coin(args.coin, testnet=args.testnet)

    private_key = generate_private_key()
    private_key_compressed = encode_privkey(private_key, formt="hex_compressed")
    print(f'Private key: {private_key_compressed}')
    private_key_p2pkh = coin.encode_privkey(private_key, formt="wif_compressed", script_type="p2pkh")
    print(f'WIF P2PKH: {private_key_p2pkh}')
    print(f'P2PKH Address: {coin.privtoaddr(private_key_p2pkh)}')
    if coin.segwit_supported:
        private_key_p2wpkh_p2sh = coin.encode_privkey(private_key, formt="wif_compressed", script_type="p2wpkh-p2sh")
        print(f'WIF P2WPKH-P2SH: {private_key_p2wpkh_p2sh}')
        print(f'P2WPKH-P2SH Segwit Address: {coin.privtop2wpkh_p2sh(private_key_p2wpkh_p2sh)}')
        private_key_p2wpkh = coin.encode_privkey(private_key, formt="wif_compressed", script_type="p2wpkh")
        print(f'WIF Native Segwit P2WPKH: {private_key_p2wpkh}')
        print(f'Native Segwit P2WPKH Address: {coin.privtosegwitaddress(private_key_p2wpkh)}')


if __name__ == "__main__":
    main()
