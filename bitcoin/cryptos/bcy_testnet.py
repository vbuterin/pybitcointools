from blockcypher.constants import COIN_SYMBOL_ODICT_LIST
from .bitcoin import Bitcoin

class BCYTestnet(Bitcoin):
    metadata = COIN_SYMBOL_ODICT_LIST[4]

privtopub = BCYTestnet.privtopub
pubtoaddr = BCYTestnet.pubtoaddr
privtoaddr = BCYTestnet.privtoaddr
unspent = BCYTestnet.unspent
history = BCYTestnet.history
pushtx = BCYTestnet.pushtx
sign = BCYTestnet.sign
signall = BCYTestnet.signall
preparetx = BCYTestnet.preparetx
preparemultitx = BCYTestnet.preparemultitx
send = BCYTestnet.send
sendmultitx = BCYTestnet.sendmultitx