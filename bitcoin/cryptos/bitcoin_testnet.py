from blockcypher.constants import COIN_SYMBOL_ODICT_LIST
from .bitcoin import Bitcoin

class BitcoinTestnet(Bitcoin):
    metadata = COIN_SYMBOL_ODICT_LIST[1]

privtopub = BitcoinTestnet.privtopub
pubtoaddr = BitcoinTestnet.pubtoaddr
privtoaddr = BitcoinTestnet.privtoaddr
unspent = BitcoinTestnet.unspent
history = BitcoinTestnet.history
pushtx = BitcoinTestnet.pushtx
sign = BitcoinTestnet.sign
signall = BitcoinTestnet.signall
preparetx = BitcoinTestnet.preparetx
preparemultitx = BitcoinTestnet.preparemultitx
send = BitcoinTestnet.send
sendmultitx = BitcoinTestnet.sendmultitx