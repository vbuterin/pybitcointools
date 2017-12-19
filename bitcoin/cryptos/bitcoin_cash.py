from .bitcoin import Bitcoin
from .. import composite
from ..explorers import insightapi

class BitcoinCash(Bitcoin):
    coin_symbol = "bch"

    def sign(self, *args, **kwargs):
        #Need to implement SIGHASH_FORK flag
        raise NotImplementedError

    def signall(self, *args):
        # Need to implement SIGHASH_FORK flag
        raise NotImplementedError

    def unspent(self, *args):
        return insightapi.unspent(*args)

    def history(self, *args):
        return insightapi.history(*args)

    def pushtx(self, *args):
        return insightapi.pushtx(*args)

    def preparetx(self, *args, **kwargs):
        return composite.preparetx(*args, magicbyte=self.magicbyte, **kwargs)

    def preparemultitx(self, *args, **kwargs):
        return composite.preparemultitx(*args, magicbyte=self.magicbyte, **kwargs)