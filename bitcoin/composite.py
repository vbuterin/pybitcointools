from main import *
from transaction import *
from bci import *
from deterministic import *


# Takes privkey, address, value (satoshis), fee (satoshis)
def send(frm, to, value, fee=1000):
    u = unspent(privtoaddr(frm))
    u2 = select(u, int(value)+int(fee))
    argz = u2 + [to+':'+str(value), to, fee]
    tx = mksend(*argz)
    tx2 = signall(tx, frm)
    return pushtx(tx2)


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
    N = deserialize_script(script)[-2]
    for inp in txobj["ins"]:
        inp["script"] = serialize_script([None] * (N+1) + [script])
    return serialize(txobj)


def sign_coinvault_tx(tx, priv):
    pub = privtopub(priv)
    txobj = deserialize(tx)
    subscript = deserialize_script(txobj['ins'][0]['script'])
    oscript = deserialize_script(subscript[-1])
    k, pubs = oscript[0], oscript[1:-2]
    for j in range(len(txobj['ins'])):
        scr = deserialize_script(txobj['ins'][j]['script'])
        for i, p in enumerate(pubs):
            if p == pub:
                scr[i+1] = multisign(tx, j, subscript[-1], priv)
        if len(filter(lambda x: x, scr[1:-1])) >= k:
            scr = [None] + filter(lambda x: x, scr[1:-1])[:k] + [scr[-1]]
        txobj['ins'][j]['script'] = serialize_script(scr)
    return serialize(txobj)
