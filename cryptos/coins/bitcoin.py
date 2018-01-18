from ..explorers import blockchain
from .base import BaseCoin


class Bitcoin(BaseCoin):
    coin_symbol = "BTC"
    display_name = "Bitcoin"
    segwit_supported = True
    explorer = blockchain
    magicbyte = 0
    script_magicbyte = 5
    segwit_hrp = "bc"

    testnet_overrides = {
        'display_name': "Bitcoin Testnet",
        'coin_symbol': "BTCTEST",
        'magicbyte': 111,
        'script_magicbyte': 196,
        'segwit_hrp': 'tb',
        'hd_path': 1,
        'wif_prefix': 0xef,
        'xprv_headers': {
            'standard': 0x04358394,
            'p2wpkh-p2sh': 0x049d7878,
            'p2wsh-p2sh': 0x295b005,
            'p2wpkh': 0x4b2430c,
            'p2wsh': 0x2aa7a99
        },
        'xpub_headers': {
            'standard': 0x043587cf,
            'p2wpkh-p2sh': 0x049d7cb2,
            'p2wsh-p2sh': 0x295b43f,
            'p2wpkh': 0x4b24746,
            'p2wsh': 0x2aa7ed3
        },
    }