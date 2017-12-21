from .bitcoin import Bitcoin
from ..transaction import SIGHASH_ALL, SIGHASH_FORKID
from ..explorers import blockdozer


class BitcoinCash(Bitcoin):
    display_name = "Bitcoin Cash"
    coin_symbol = "bcc"
    magicbyte = 0
    hashcode = SIGHASH_ALL + SIGHASH_FORKID

    def __init__(self, testnet=False, **kwargs):
        super(BitcoinCash, self).__init__(testnet, **kwargs)
        if self.is_testnet:
            self.display_name = "Bitcoin Cash Testnet"
            self.coin_symbol = "tbcc"
            self.magicbyte = 111

    def unspent(self, *addrs):
        return blockdozer.unspent(*addrs, coin_symbol=self.coin_symbol)

    def history(self, *addrs):
        return blockdozer.history(*addrs, coin_symbol=self.coin_symbol)

    def pushtx(self, tx):
        return blockdozer.pushtx(tx, coin_symbol=self.coin_symbol)