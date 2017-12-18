from blockcypher.constants import COIN_SYMBOL_ODICT_LIST
from .bitcoin import Bitcoin

class Dogecoin(Bitcoin):
    metadata = COIN_SYMBOL_ODICT_LIST[3]

privtopub = Dogecoin.privtopub
pubtoaddr = Dogecoin.pubtoaddr
privtoaddr = Dogecoin.privtoaddr
unspent = Dogecoin.unspent
history = Dogecoin.history
pushtx = Dogecoin.pushtx
sign = Dogecoin.sign
signall = Dogecoin.signall
preparetx = Dogecoin.preparetx
preparemultitx = Dogecoin.preparemultitx
send = Dogecoin.send
sendmultitx = Dogecoin.sendmultitx