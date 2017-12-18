from blockcypher.constants import COIN_SYMBOL_ODICT_LIST
from .. import blockcypherapi, composite, main, transaction

class Bitcoin(object):
    metadata = COIN_SYMBOL_ODICT_LIST[0]

    @classmethod
    def privtopub(cls, *args):
        return main.privtopub(*args)

    @classmethod
    def pubtoaddr(cls, *args):
        magicbyte = cls.metadata['vbyte_pubkey']
        return main.pubtoaddr(*args, magicbyte=magicbyte)

    @classmethod
    def privtoaddr(cls, *args,):
        magicbyte = cls.metadata['vbyte_pubkey']
        return main.privtoaddr(*args, magicbyte=magicbyte)

    @classmethod
    def sign(cls, *args, **kwargs):
        magicbyte = cls.metadata['vbyte_pubkey']
        return transaction.sign(*args, magicbyte=magicbyte, **kwargs)

    @classmethod
    def signall(cls, *args):
        magicbyte = cls.metadata['vbyte_pubkey']
        return transaction.signall(*args, magicbyte=magicbyte)

    @classmethod
    def unspent(cls, *args, **kwargs):
        coin_symbol = cls.metadata['coin_symbol']
        return blockcypherapi.unspent(*args, coin_symbol=coin_symbol, **kwargs)

    @classmethod
    def history(cls, *args, **kwargs):
        coin_symbol = cls.metadata['coin_symbol']
        return blockcypherapi.history(*args, coin_symbol=coin_symbol, **kwargs)

    @classmethod
    def pushtx(cls, *args):
        coin_symbol = cls.metadata['coin_symbol']
        return blockcypherapi.pushtx(*args, coin_symbol=coin_symbol)

    @classmethod
    def preparetx(cls, *args, **kwargs):
        magicbyte = cls.metadata['vbyte_pubkey']
        return composite.preparetx(*args, magicbyte=magicbyte, **kwargs)

    @classmethod
    def preparemultitx(cls, *args, **kwargs):
        magicbyte = cls.metadata['vbyte_pubkey']
        return composite.preparemultitx(*args, magicbyte=magicbyte, **kwargs)

    @classmethod
    def send(cls, *args, **kwargs):
        coin_symbol = cls.metadata['coin_symbol']
        magicbyte = cls.metadata['vbyte_pubkey']
        return composite.send(*args, magicbyte=magicbyte, coin_symbol=coin_symbol **kwargs)

    @classmethod
    def sendmultitx(cls, *args, **kwargs):
        coin_symbol = cls.metadata['coin_symbol']
        magicbyte = cls.metadata['vbyte_pubkey']
        return composite.sendmultitx(*args, magicbyte=magicbyte, coin_symbol=coin_symbol, **kwargs)

privtopub = Bitcoin.privtopub
pubtoaddr = Bitcoin.pubtoaddr
privtoaddr = Bitcoin.privtoaddr
unspent = Bitcoin.unspent
history = Bitcoin.history
pushtx = Bitcoin.pushtx
sign = Bitcoin.sign
signall = Bitcoin.signall
preparetx = Bitcoin.preparetx
preparemultitx = Bitcoin.preparemultitx
send = Bitcoin.send
sendmultitx = Bitcoin.sendmultitx