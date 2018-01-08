from .bitcoin import Bitcoin
from ..transaction import SIGHASH_ALL, SIGHASH_FORKID
from ..explorers import blockdozer

class BitcoinCash(Bitcoin):
    coin_symbol = "bcc"
    display_name = "Bitcoin Cash"
    segwit_supported = False
    magicbyte = 0
    script_magicbyte = 5
    hashcode = SIGHASH_ALL + SIGHASH_FORKID
    testnet_overrides = {
        'display_name': "Bitcoin Cash Testnet",
        'coin_symbol': "tbcc",
        'magicbyte': 111,
        'script_magicbyte': 196
    }

    def unspent(self, *addrs):
        return blockdozer.unspent(*addrs, coin_symbol=self.coin_symbol)

    def history(self, *addrs):
        return blockdozer.history(*addrs, coin_symbol=self.coin_symbol)

    def fetchtx(self, tx):
        return blockdozer.fetchtx(tx, coin_symbol=self.coin_symbol)

    def txinputs(self, tx):
        return blockdozer.txinputs(tx, coin_symbol=self.coin_symbol)

    def pushtx(self, tx):
        return blockdozer.pushtx(tx, coin_symbol=self.coin_symbol)