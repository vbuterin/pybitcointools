from blockcypher.constants import COIN_SYMBOL_ODICT_LIST
from .bitcoin import Bitcoin

class Litecoin(Bitcoin):
    metadata = COIN_SYMBOL_ODICT_LIST[2]

privtopub = Litecoin.privtopub
pubtoaddr = Litecoin.pubtoaddr
privtoaddr = Litecoin.privtoaddr
unspent = Litecoin.unspent
history = Litecoin.history
pushtx = Litecoin.pushtx
sign = Litecoin.sign
signall = Litecoin.signall
preparetx = Litecoin.preparetx
preparemultitx = Litecoin.preparemultitx
send = Litecoin.send
sendmultitx = Litecoin.sendmultitx