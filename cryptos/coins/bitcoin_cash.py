from .base import BaseCoin
from ..transaction import SIGHASH_ALL, SIGHASH_FORKID
from ..explorers import blockdozer

class BitcoinCash(BaseCoin):
    coin_symbol = "bch"
    display_name = "Bitcoin Cash"
    segwit_supported = False
    magicbyte = 0
    script_magicbyte = 5
    wif_prefix = 0x80
    hd_path = 145
    explorer = blockdozer
    hashcode = SIGHASH_ALL | SIGHASH_FORKID
    testnet_overrides = {
        'display_name': "Bitcoin Cash Testnet",
        'coin_symbol': "tbch",
        'magicbyte': 111,
        'script_magicbyte': 196,
        'wif_prefix': 0xef,
        'xprv_headers': {
            'p2pkh': 0x04358394,
        },
        'xpub_headers': {
            'p2pkh': 0x043587cf,
        },
        'hd_path': 1,
    }

    def __init__(self, legacy=False, testnet=False, **kwargs):
        super(BitcoinCash, self).__init__(testnet=testnet, **kwargs)
        self.hd_path = 0 if legacy and testnet else self.hd_path
