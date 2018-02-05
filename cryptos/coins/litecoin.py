from .base import BaseCoin

class Litecoin(BaseCoin):
    coin_symbol = "LTC"
    display_name = "Litecoin"
    segwit_supported = True
    magicbyte = 48
    #script_magicbyte = 50 #Supposed to be new magicbyte
    script_magicbyte = 5 #Old magicbyte still recognised by explorers
    wif_prefix = 0xb0
    segwit_hrp = "ltc1"
    hd_path = 2
    client_kwargs = {
        'server_file': 'litecoin.json',
    }
    testnet_overrides = {
        'display_name': "Litecoin Testnet",
        'coin_symbol': "LTCTEST",
        'magicbyte': 111,
        #script_magicbyte: 58   #Supposed to be new magicbyte
        'script_magicbyte': 196, #Old magicbyte still recognised by explorers,
        'segwit_hrp': "tltc1",
        'hd_path': 1,
        'client_kwargs': {
            'server_file': 'litecoin_testnet.json'
        },
        'xpriv_prefix': 0x04358394,
        'xpub_prefix': 0x043587cf
    }
