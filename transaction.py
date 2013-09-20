import re, json, copy
from main import *

def json_changebase(obj,frm,to):
    if isinstance(obj,str): return changebase(obj,frm,to)
    if isinstance(obj,(int,float,long)): return obj
    if isinstance(obj,list): return [json_changebase(x) for x in obj]
    return { x:json_changebase(obj[x],frm,to) for x in obj }

def deserialize(tx):
    if re.match('^[0-9a-fA-F]$',tx):
        return json_changebase(changebase(tx,16,256),256,16)
    pos = 0

    def read_as_int(bytez):
        pos += bytez
        return decode(tx[pos-1:pos-bytez-1:-1],256)

    def read_var_int():
        pos += 1
        if ord(tx[pos-1]) < 253: return ord(tx[pos])
        return read_as_int(ord(tx[pos-1]) - 251)
        
    def read_bytes(bytez):
        pos += bytez
        return tx[pos-bytez:pos]

    def read_var_string():
        size = read_var_int()
        return read_bytes(size)

    obj = { "ins" : [] , "outs" : [] }
    obj["version"] = read_as_int(4)
    ins = read_var_int()
    for i in range(ins):
        obj["ins"].append({
            "outpoint" : {
                "hash" : read_bytes(32),
                "index": read_as_int(4)
            },
            "script" : read_var_string(),
            "sequence" : read_as_int(4)
        })
    outs = read_var_int()
    for i in range(outs):
        obj["outs"].append({
            "value" : read_bytes(8),
            "script": read_var_string()
        })
    obj["locktime"] = read_as_int(4)
    return obj

def serialize(txobj):
    o = []
    if re.match('^[0-9a-fA-F\{\}:\[\]", ]*$',json.dumps(txobj)):
        return changebase(serialize(json_changebase(txobj,16,256)),256,16)
    o.append(encode(txobj["version"],256,4)[::-1])
    o.append(num_to_var_int(len(txobj["ins"])))
    for inp in txobj["ins"]:
        o.append(inp["outpoint"]["hash"])
        o.append(encode(inp["outpoint"]["index"],256,4)[::-1])
        o.append(num_to_var_int(len(inp["script"]))+inp["script"])
        o.append(encode(inp["sequence"],256,4)[::-1])
    o.append(num_to_var_int(len(txobj["outs"])))
    for out in txobj["outs"]:
        o.append(encode(out["value"],256,8)[::-1])
        o.append(num_to_var_int(len(out["script"]))+out["script"])
    o.append(encode(out["locktime"],256,4)[::-1])

SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
SIGHASH_ANYONECANPAY = 80


def signature_form(tx, i, script, hashcode = SIGHASH_ALL):
    if isinstance(tx,"string"):
        return serialize(signature_form(deserialize(tx),i,script))
    newtx = copy.deepcopy(tx)
    for inp in newtx["ins"]: inp["script"] = ""
    newtx["ins"][i]["script"] = script
    if hashcode == SIGHASH_NONE:
        newtx["outs"] = []
    elif hashcode == SIGHASH_SINGLE:
        newtx["outs"] = newtx["outs"][:len(newtx["ins"])]
        for out in range(len(newtx["ins"]) - 1):
            out.value = 2**64 - 1
            out.script = ""
    elif hashcode == SIGHASH_ANYONECANPAY:
        newtx["ins"] = [newtx["ins"][i]]
    else:
        pass
    return serialize(newtx)

def der_encode_sig(v,r,s):
    b1, b2 = encode(r,16,64), encode(s,16,64)
    if r >= 2**255: b1 = '00' + b1
    if s >= 2**255: b2 = '00' + b2
    left = '02'+encode(len(b1)/2,16,2)+b1
    right = '02'+encode(len(b2)/2,16,2)+b2
    return '30'+encode(len(left+right)/2,16,2)+left+right

def der_decode_sig(sig):
    leftlen = decode(sig[6:8],16)*2
    left = sig[8:8+leftlen]
    rightlen = decode(sig[10+leftlen:12+leftlen],16)*2
    right = sig[12+leftlen:12+leftlen+rightlen]
    return (None,decode(left,16),decode(right,16))

def ecdsa_tx_sign(msg,priv,hashcode=SIGHASH_ALL):
    return der_encode_sig(*ecdsa_raw_sign(tx_sig_hash(msg),priv))+encode(hashcode,16,2)

def ecdsa_tx_verify(msg,sig,pub):
    return ecdsa_raw_verify(tx_sig_hash(msg),der_decode_sig(sig),pub)

def ecdsa_tx_recover(msg,sig):
    _,r,s = der_decode_sig(sig)
    h = tx_sig_hash(msg)
    left = ecdsa_raw_recover(h,(0,r,s))
    right = ecdsa_raw_recover(h,(1,r,s))
    return (left, right)

def mk_pubkey_script(addr):
    return '76a914' + b58check_to_hex(addr) + '88ac'

def mk_scripthash_script(addr):
    return 'a914' + b58check_to_hex(addr) + '87'

def deserialize_script(script):
    if re.match('^[0-9a-fA-F]$',script):
        return json_changebase(changebase(script,16,256),256,16)
    out, pos = [], 0
    while pos < len(script):
        code = ord(script[pos])
        if code == 0:
            pos += 1
        elif code <= 75:
            out.append(script[pos+1:pos+1+code])
            pos += 1 + code
        elif code <= 78:
            szsz = pow(2,code - 76)
            sz = decode(script[pos + 1 : pos + 1 + szsz],256)[::-1]
            out.append(script[pos + 1 + szsz:pos + 1 + szsz + sz])
            pos += 1 + szsz + sz
        elif code <= 96:
            out.append(code - 80)
            pos += 1
        else:
            out.append(code)
            pos += 1
    return out

def serialize_script_unit(unit):
    if isinstance(unit,int):
        if unit < 16: return chr(unit + 80)
        else: return chr(unit)
    else:
        if len(unit) <= 75: return chr(len(unit))+unit
        else if len(unit) < 256: return chr(76)+chr(len(unit))+unit
        else if len(unit) < 65536: return chr(77)+encode(len(unit),256,2)[::-1]+unit
        else: return chr(78)+encode(len(unit),256,4)[::-1]+unit

def serialize_script(script):
    if re.match('^[0-9a-fA-F\{\}:\[\]", ]*$',json.dumps(script)):
        return changebase(serialize_script(json_changebase(script,16,256)),16)
    return ''.join(map(serialize_script_unit,script))

# TODO: IN PROGRESS

def verify_tx_input(tx,i,script,sig):
    if re.match('^[0-9a-fA-F]$',tx): tx = changebase(tx,16,256)
    if re.match('^[0-9a-fA-F]$',script): script = changebase(script,16,256)
    if re.match('^[0-9a-fA-F]$',sig): sig = changebase(sig,16,256)
    hashcode = ord(sig[-1])
    modtx = signature_form(tx,i,script)
    script_sig = deserialize(tx)["ins"][i]["script"]
    if script[:3] == '\x76\xa9\x14':
        return ecdsa_tx_verify(modtx,sig,script[3:-2])
    elif script[:2] == '\xa9\x14':
        sc = deserialize_script(script)
        pubs = filter(lambda x: len(x) == 33 or len(x) == 65,sc)
        if hash160(script) != tx[i][]
        return 
