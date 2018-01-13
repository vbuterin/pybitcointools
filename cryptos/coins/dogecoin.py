from .bitcoin import Bitcoin
from ..explorers import sochain


class Doge(Bitcoin):
    coin_symbol = "DOGE"
    display_name = "Dogecoin"
    segwit_supported = False
    magicbyte = 30
    script_magicbyte = 22
    to_wif = 0x9e
    hd_path = 3
    explorer = sochain
    testnet_overrides = {
        'display_name': "Dogecoin Testnet",
        'coin_symbol': "Dogecoin",
        'magicbyte': 113,
        'script_magicbyte': 196
    }