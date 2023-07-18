from .bitcoin import BaseCoin

class Doge(BaseCoin):
    coin_symbol = "DOGE"
    display_name = "Dogecoin"
    segwit_supported = False
    magicbyte = 0x1e
    minimum_fee = 300000
    script_magicbyte = 0x16
    wif_prefix: int = 0x9e
    segwit_hrp = "doge"
    hd_path = 3
    client_kwargs = {
        'server_file': 'doge.json',
        'use_ssl': False
    }
    xpriv_prefix = 0x02facafd
    xpub_prefix = 0x02fac398
    testnet_overrides = {
        'display_name': "Dogecoin Testnet",
        'coin_symbol': "Dogecoin",
        'magicbyte': 0x71,
        'script_magicbyte': 0xc4,
        'hd_path': 1,
        'wif_prefix': 0xf1,
        'segwit_hrp': 'xdoge',
        'minimum_fee': 300000,
        'client_kwargs': {
            'server_file': 'doge_testnet.json',
            'use_ssl': False
        },
        'xpriv_prefix': 0x04358394,
        'xpub_prefix': 0x043587cf
    }
