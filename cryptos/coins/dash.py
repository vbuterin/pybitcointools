from .bitcoin import Bitcoin
from ..explorers import dash_siampm

class Dash(Bitcoin):
    coin_symbol = "DASH"
    display_name = "Dash"
    segwit_supported = False
    magicbyte = 76
    testnet_overrides = {
        'display_name': "Dash Testnet",
        'coin_symbol': "DASHTEST",
        'magicbyte': 140,
    }

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
