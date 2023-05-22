import argparse
from cryptos.coins_async.base import BaseCoin
from cryptos.main import privtopub, compress, decompress
from cryptos.script_utils import coin_list, get_coin


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("priv", help="Private Key")
    parser.add_argument("output_format", help="Output format", choices=['decimal', 'bin', 'bin_compressed', 'hex',
                                                                        'hex_compressed', 'wif', 'wif_compressed'])
    parser.add_argument("-s", "--script_type", help="Output format",
                        choices=BaseCoin.wif_script_types.keys(), default="p2pkh")
    parser.add_argument("-x", "--coin", help="Coin",  choices=coin_list, default="btc")
    parser.add_argument("-t", "--testnet", help="For testnet", action="store_true")

    args = parser.parse_args()

    coin = get_coin(args.coin, testnet=args.testnet)
    priv = args.priv
    script_type = args.script_type
    output_format = args.output_format
    encoded_priv_key = coin.encode_privkey(priv, output_format, script_type=script_type)
    output_format_str = output_format.replace("_", " ")
    print(f'Private key {output_format_str} format: {encoded_priv_key}')
    public_key = privtopub(encoded_priv_key)
    print(f'Public key: {public_key}')
    if script_type == "p2pkh":
        address = coin.pubtoaddr(public_key)
        print(f'P2PKH Address: {address}')
    elif script_type == "p2wpkh" and coin.segwit_supported:
        native_segwit_address = coin.pubtosegwitaddress(public_key)
        print(f'P2WPKH Native Segwit address: {native_segwit_address}')
    elif script_type == "p2wpkh-p2sh" and coin.segwit_supported:
        p2pkhw_p2sh = coin.pubtop2wpkh_p2sh(public_key)
        print(f'P2PKHW_P2SH Address: {p2pkhw_p2sh}')


if __name__ == "__main__":
    main()
