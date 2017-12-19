from bitcoin.explorers import blockcypherapi

from .constants import COIN_METADATA
from .. import composite, main, transaction


class Bitcoin(object):
    coin_symbol = "btc"

    def __init__(self):
        self.metadata = COIN_METADATA[self.coin_symbol]
        self.magicbyte = self.metadata['vbyte_pubkey']

    def privtopub(self, *args):
        return main.privtopub(*args)

    def pubtoaddr(self, *args):
        return main.pubtoaddr(*args, magicbyte=self.magicbyte)

    def privtoaddr(self, *args):
        return main.privtoaddr(*args, magicbyte=self.magicbyte)

    def sign(self, *args, **kwargs):
        return transaction.sign(*args, magicbyte=self.magicbyte, **kwargs)

    def signall(self, *args):
        return transaction.signall(*args, magicbyte=self.magicbyte)

    def unspent(self, *args, **kwargs):
        return blockcypherapi.unspent(*args, coin_symbol=self.coin_symbol, **kwargs)

    def history(self, *args, **kwargs):
        return blockcypherapi.history(*args, coin_symbol=self.coin_symbol, **kwargs)

    def pushtx(self, *args):
        return blockcypherapi.pushtx(*args, coin_symbol=self.coin_symbol)

    def preparetx(self, *args, **kwargs):
        return composite.preparetx(*args, magicbyte=self.magicbyte, **kwargs)

    def preparemultitx(self, *args, **kwargs):
        return composite.preparemultitx(*args, magicbyte=self.magicbyte, **kwargs)

    def send(self, *args, **kwargs):
        return composite.send(*args, magicbyte=self.magicbyte, coin_symbol=self.coin_symbol, **kwargs)

    def sendmultitx(self, *args, **kwargs):
        return composite.sendmultitx(*args, magicbyte=self.magicbyte, coin_symbol=self.coin_symbol, **kwargs)