from .bitcoin import Bitcoin
from ..transaction import SIGHASH_ALL, SIGHASH_FORKID
from ..explorers import insightapi


class BitcoinCash(Bitcoin):
    display_name = "Bitcoin Cash"
    coin_symbol = "BCH"
    magicbyte = 0
    hashcode = SIGHASH_ALL + SIGHASH_FORKID

    def __init__(self, testnet=False, **kwargs):
        super(BitcoinCash, self).__init__(testnet, **kwargs)
        if self.is_testnet:
            self.display_name = "Bitcoin Cash Testnet"
            self.coin_symbol = "BCHTEST"
            self.magicbyte = 111
            raise NotImplementedError("Testnet support for this coin has not been implemented yet!")

    def unspent(self, *addrs):
        return insightapi.unspent(*addrs)

    def history(self, *addrs):
        return insightapi.history(*addrs)

    def pushtx(self, tx):
        return insightapi.pushtx(tx)
