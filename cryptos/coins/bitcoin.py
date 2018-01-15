from ..explorers import blockchain
from .base import BaseCoin


class Bitcoin(BaseCoin):
    coin_symbol = "BTC"
    display_name = "Bitcoin"
    segwit_supported = True
    magicbyte = 0
    script_magicbyte = 5
    hd_path = 0
    wif_prefix = 0x80
    explorer = blockchain
    testnet_overrides = {
        'display_name': "Bitcoin Testnet",
        'coin_symbol': "BTCTEST",
        'magicbyte': 111,
        'script_magicbyte': 196,
        'hd_path': 1,
        'bip39_xpriv_prefix': 0x04358394,
        'bip39_xpub_prefix': 0x043587cf
    }