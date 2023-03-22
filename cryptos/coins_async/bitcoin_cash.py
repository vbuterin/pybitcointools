from .base import BaseCoin
from typing import Dict
from ..transaction import SIGHASH_ALL, SIGHASH_FORKID


class BitcoinCash(BaseCoin):
    coin_symbol = "BCH"
    display_name = "Bitcoin Cash"
    segwit_supported = False
    cash_address_supported = True
    magicbyte = 0
    script_magicbyte = 5
    wif_prefix = 0x80
    wif_script_types: Dict[str, int] = {
        'p2pkh': 0,
        'p2sh': 5,
    }
    hd_path = 145
    cash_hrp = "bitcoincash"
    hashcode = SIGHASH_ALL | SIGHASH_FORKID
    client_kwargs = {
        'server_file': 'bitcoin_cash.json',
    }
    minimum_fee = 500
    testnet_overrides = {
        'display_name': "Bitcoin Cash Testnet",
        'coin_symbol': "tbcc",
        'magicbyte': 111,
        'script_magicbyte': 196,
        'wif_prefix': 0xef,
        'cash_hrp': "bchtest",
        'xprv_headers': {
            'p2pkh': 0x04358394,
        },
        'xpub_headers': {
            'p2pkh': 0x043587cf,
        },
        'hd_path': 1,
        'client_kwargs': {
            'server_file': 'bitcoin_cash_testnet.json',
            'use_ssl': False
        },
    }

    def __init__(self, legacy=False, testnet=False, **kwargs):
        super(BitcoinCash, self).__init__(testnet=testnet, **kwargs)
        self.hd_path = 0 if legacy and testnet else self.hd_path
