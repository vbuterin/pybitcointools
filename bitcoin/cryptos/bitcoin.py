from bitcoin.explorers import blockcypherapi
from ..transaction import SIGHASH_ALL, select, mksend
from .constants import COIN_METADATA
from .. import main, transaction


class Bitcoin(object):
    coin_symbol = "btc"
    hashcode = SIGHASH_ALL
    explorer = blockcypherapi

    def __init__(self):
        self.metadata = COIN_METADATA[self.coin_symbol]
        self.magicbyte = self.metadata['vbyte_pubkey']

    def privtopub(self, privkey):
        return main.privtopub(privkey)

    def pubtoaddr(self, pubkey):
        return main.pubtoaddr(pubkey, magicbyte=self.magicbyte)

    def privtoaddr(self, privkey):
        return main.privtoaddr(privkey, magicbyte=self.magicbyte)

    def sign(self, tx, i, privkey):
        return transaction.sign(tx, i, privkey, magicbyte=self.magicbyte, hashcode=self.hashcode)

    def signall(self, tx, privkey):
        return transaction.signall(tx, privkey, magicbyte=self.magicbyte, hashcode=self.hashcode)

    def unspent(self, *addrs, **kwargs):
        return blockcypherapi.unspent(*addrs, coin_symbol=self.coin_symbol, **kwargs)

    def history(self, *addrs, **kwargs):
        return blockcypherapi.history(*addrs, coin_symbol=self.coin_symbol, **kwargs)

    def pushtx(self, tx):
        return blockcypherapi.pushtx(tx, coin_symbol=self.coin_symbol)

    # Takes privkey, address, value (satoshis), fee (satoshis)
    def send(self, privkey, to, value, fee=10000, **kwargs):
        return self.sendmultitx(privkey, to + ":" + str(value), fee, **kwargs)

    # Takes privkey, address1:value1,address2:value2 (satoshis), fee (satoshis)
    def sendmultitx(self, privkey, *args, **kwargs):
        tv, fee = args[:-1], int(args[-1])
        outs = []
        outvalue = 0
        for a in tv:
            outs.append(a)
            outvalue += int(a.split(":")[1])

        u = self.unspent(self.privtoaddr(privkey))
        u2 = select(u, int(outvalue) + int(fee))
        argz = u2 + outs + [self.privtoaddr(privkey), fee]
        tx = mksend(*argz)
        tx2 = self.signall(tx, privkey)
        return self.pushtx(tx2)

    # Takes address, address, value (satoshis), fee(satoshis)
    def preparetx(self, frm, to, value, fee=10000, **kwargs):
        tovalues = to + ":" + str(value)
        return self.preparemultitx(frm, tovalues, fee, **kwargs)

    # Takes address, address:value, address:value ... (satoshis), fee(satoshis)
    def preparemultitx(self, frm, *args, **kwargs):
        tv, fee = args[:-1], int(args[-1])
        outs = []
        outvalue = 0
        for a in tv:
            outs.append(a)
            outvalue += int(a.split(":")[1])

        u = self.unspent(frm)
        u2 = select(u, int(outvalue) + int(fee))
        argz = u2 + outs + [frm, fee]
        return mksend(*argz)