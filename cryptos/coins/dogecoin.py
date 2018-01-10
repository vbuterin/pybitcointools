from .bitcoin import Bitcoin
from ..explorers import sochain


class Doge(Bitcoin):
    coin_symbol = "DOGE"
    display_name = "Dogecoin"
    segwit_supported = False
    magicbyte = 30
    explorer = sochain
    testnet_overrides = {
        'display_name': "Dogecoin Testnet",
        'coin_symbol': "Dogecoin",
        'magicbyte': 113,
    }