from .base import BaseCoin
from ..transaction import SIGHASH_ALL, SIGHASH_FORKID
from ..explorers import blockdozer

class BitcoinCash(BaseCoin):
    coin_symbol = "bcc"
    display_name = "Bitcoin Cash"
    segwit_supported = False
    magicbyte = 0
    script_magicbyte = 5
    to_wif = 0x80
    hd_path = 145
    explorer = blockdozer
    hashcode = SIGHASH_ALL + SIGHASH_FORKID
    testnet_overrides = {
        'display_name': "Bitcoin Cash Testnet",
        'coin_symbol': "tbcc",
        'magicbyte': 111,
        'script_magicbyte': 196
    }

    def __init__(self, *args, hd_prefork=False, **kwargs):
        super(BitcoinCash, self).__init__(*args, **kwargs)
        self.hd_path = 0 if hd_prefork else self.hd_path