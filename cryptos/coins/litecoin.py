from .bitcoin import Bitcoin


class Litecoin(Bitcoin):
    display_name = "Litecoin"
    coin_symbol = "LTC"
    magicbyte = 48

    def __init__(self, testnet=False, **kwargs):
        super(Litecoin, self).__init__(testnet, **kwargs)
        if self.is_testnet:
            self.display_name = "Litecoin Testnet"
            self.coin_symbol = "LTCTEST"
            self.magicbyte = 111
