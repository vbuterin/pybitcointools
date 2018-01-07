from .bitcoin import Bitcoin


class Litecoin(Bitcoin):
    display_name = "Litecoin"
    coin_symbol = "LTC"
    magicbyte = 48
    script_magicbyte = 50
    segwit_supported = True

    def __init__(self, testnet=False, **kwargs):
        super(Litecoin, self).__init__(testnet, **kwargs)
        if self.is_testnet:
            self.display_name = "Litecoin Testnet"
            self.coin_symbol = "LTCTEST"
            self.magicbyte = 111
            self.script_magicbyte = 58
