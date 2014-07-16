from main import *
from transaction import *
from bci import *
from deterministic import *


# Takes privkey, address, value (satoshis), fee (satoshis)
def send(frm, to, value, fee=1000):
    u = unspent(privtoaddr(frm))
    u2 = select(u, value+fee)
    argz = u2 + [to+':'+str(value), privtoaddr(to), fee]
    tx = mksend(argz)
    tx2 = signall(tx, privtoaddr(to))
    pushtx(tx2)


def bip32_hdm_script(*args):
    if len(args) == 3:
        keys, req, path = args
    else:
        i, keys, path = 0, [], []
        while len(args[i]) > 40:
            keys.append(args[i])
            i += 1
        req = int(args[i])
        path = map(int, args[i+1:])
    pubs = sorted(map(lambda x: bip32_descend(x, path), keys))
    return mk_multisig_script(pubs, req)


def bip32_hdm_addr(*args):
    return scriptaddr(bip32_hdm_script(*args))


def setup_coinvault_tx(tx, script):
    txobj = deserialize(tx)
    for inp in txobj["ins"]:
        inp["script"] = serialize_script([None, None, None, None, script])
    return serialize(txobj)
