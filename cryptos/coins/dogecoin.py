from .bitcoin import BaseCoin
from ..explorers import sochain


class Doge(BaseCoin):
    coin_symbol = "DOGE"
    display_name = "Dogecoin"
    segwit_supported = False
    magicbyte = 30
    script_magicbyte = 22
    to_wif = 0x9e
    hd_path = 3
    client_kwargs = {
        'server_file': 'doge.json',
    }
    xpriv_prefix = 0x02facafd
    xpub_prefix = 0x02fac398
    testnet_overrides = {
        'display_name': "Dogecoin Testnet",
        'coin_symbol': "Dogecoin",
        'magicbyte': 113,
        'script_magicbyte': 196,
        'hd_path': 1,
        'client_kwargs': {
            'server_file': 'doge_testnet.json',
        },
        'xpriv_prefix': 0x04358394,
        'xpub_prefix': 0x043587cf
    }