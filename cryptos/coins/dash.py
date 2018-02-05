from .base import BaseCoin
from ..explorers import dash_siampm

class Dash(BaseCoin):
    coin_symbol = "DASH"
    display_name = "Dash"
    segwit_supported = False
    magicbyte = 76
    script_magicbyte = 16
    wif_prefix = 0xcc
    hd_path = 5
    client_kwargs = {
        'server_file': 'dash.json',
    }
    testnet_overrides = {
        'display_name': "Dash Testnet",
        'coin_symbol': "DASHTEST",
        'magicbyte': 140,
        'script_magicbyte': 19,
        'hd_path': 1,
        'client_kwargs': {
            'server_file': 'dash_testnet.json'
        },
        'xpriv_prefix': 0x04358394,
        'xpub_prefix': 0x043587cf
    }
