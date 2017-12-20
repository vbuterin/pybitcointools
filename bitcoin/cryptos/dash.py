from .bitcoin import Bitcoin


class Dash(Bitcoin):
    display_name = "Dash"
    coin_symbol = "DASH"
    magicbyte = 76

    def __init__(self, testnet=False, **kwargs):
        super(Dash, self).__init__(testnet, **kwargs)
        if self.is_testnet:
            self.display_name = "Dash Testnet"
            self.coin_symbol = "DASHTEST"
            self.magicbyte = 140
            raise NotImplementedError("Testnet support for this coin has not been implemented yet!")
