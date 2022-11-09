from .base import BaseCoin


class Litecoin(BaseCoin):
    coin_symbol: str = "LTC"
    display_name: str = "Litecoin"
    segwit_supported: bool = True
    magicbyte: int = 48
    script_magicbyte = 50
    # script_magicbyte: int = 5  # Old magicbyte
    minimum_fee: int = 1000
    wif_prefix: int = 0xb0
    segwit_hrp: str = "ltc"
    hd_path: int = 2
    client_kwargs = {
        'server_file': 'litecoin.json',
    }
    testnet_overrides = {
        'display_name': "Litecoin Testnet",
        'coin_symbol': "LTCTEST",
        'magicbyte': 111,
        'script_magicbyte': 58,
        #'script_magicbyte': 196,  # Old magicbyte,
        'wif_prefix': 0xbf,
        'segwit_hrp': "tltc",
        'minimum_fee': 1000,
        'hd_path': 1,
        'client_kwargs': {
            'server_file': 'litecoin_testnet.json',
            'use_ssl': False
        },
        'xpriv_prefix': 0x04358394,
        'xpub_prefix': 0x043587cf
    }
