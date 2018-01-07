from .bitcoin import Bitcoin
from ..explorers import dash_siampm

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

    def unspent(self, *addrs, **kwargs):
        return dash_siampm.unspent(*addrs, testnet=self.is_testnet)

    def history(self, *addrs, **kwargs):
        return dash_siampm.history(*addrs, testnet=self.is_testnet)

    def fetchtx(self, tx):
        return dash_siampm.fetchtx(tx, testnet=self.is_testnet)

    def txinputs(self, tx):
        return dash_siampm.txinputs(tx, testnet=self.is_testnet)

    def pushtx(self, tx):
        return dash_siampm.pushtx(tx, testnet=self.is_testnet)
