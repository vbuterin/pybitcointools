from .bitcoin import Bitcoin
from .. import composite
from ..transaction import SIGHASH_ALL, SIGHASH_FORKID
from ..explorers import insightapi

class BitcoinCash(Bitcoin):
    coin_symbol = "bch"
    hashcode = SIGHASH_ALL + SIGHASH_FORKID

    def unspent(self, *addrs):
        return insightapi.unspent(*addrs)

    def history(self, *addrs):
        return insightapi.history(*addrs)

    def pushtx(self, tx):
        return insightapi.pushtx(tx)