from .bitcoin import Bitcoin


class Doge(Bitcoin):
    display_name = "Dogecoin"
    coin_symbol = "DOGE"
    magicbyte = 30

    def __init__(self, testnet=False, **kwargs):
        super(Doge, self).__init__(testnet, **kwargs)
        if self.is_testnet:
            self.display_name = "Dogecoin Testnet"
            self.coin_symbol = "DOGETEST"
            self.magicbyte = 113
            raise NotImplementedError("Testnet support for this coin has not been implemented yet!")
