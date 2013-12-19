#!/usr/bin/python
import re, json, copy
from main import *

### Hex to bin converter and vice versa for objects

def json_is_base(obj,base):
    alpha = get_code_string(base)
    if isinstance(obj,(str,unicode)):
        for i in range(len(obj)):
            if alpha.find(obj[i]) == -1: return False
        return True
    elif isinstance(obj,(int,float,long)) or obj is None: return True
    elif isinstance(obj,list):
        for i in range(len(obj)):
            if not json_is_base(obj[i],base): return False
        return True
    else:
        for x in obj:
            if not json_is_base(obj[x],base): return False
        return True

def json_changebase(obj,changer):
    if isinstance(obj,(str,unicode)): return changer(obj)
    elif isinstance(obj,(int,float,long)) or obj is None: return obj
    elif isinstance(obj,list): return [json_changebase(x,changer) for x in obj]
    return dict((x, json_changebase(obj[x], changer)) for x in obj)

### Transaction serialization and deserialization

def deserialize(tx):
    if re.match('^[0-9a-fA-F]*$',tx):
        return json_changebase(deserialize(tx.decode('hex')),lambda x:x.encode('hex'))
    # http://stackoverflow.com/questions/4851463/python-closure-write-to-variable-in-parent-scope
    # Python's scoping rules are demented, requiring me to make pos an object so that it is call-by-reference
    pos = [0]

    def read_as_int(bytez):
        pos[0] += bytez
        return decode(tx[pos[0]-bytez:pos[0]][::-1],256)

    def read_var_int():
        pos[0] += 1
        if ord(tx[pos[0]-1]) < 253: return ord(tx[pos[0]-1])
        return read_as_int(pow(2,ord(tx[pos[0]-1]) - 252))
        
    def read_bytes(bytez):
        pos[0] += bytez
        return tx[pos[0]-bytez:pos[0]]

    def read_var_string():
        size = read_var_int()
        return read_bytes(size)

    obj = { "ins" : [] , "outs" : [] }
    obj["version"] = read_as_int(4)
    ins = read_var_int()
    for i in range(ins):
        obj["ins"].append({
            "outpoint" : {
                "hash" : read_bytes(32)[::-1],
                "index": read_as_int(4)
            },
            "script" : read_var_string(),
            "sequence" : read_as_int(4)
        })
    outs = read_var_int()
    for i in range(outs):
        obj["outs"].append({
            "value" : read_as_int(8),
            "script": read_var_string()
        })
    obj["locktime"] = read_as_int(4)
    return obj

def serialize(txobj):
    o = []
    if json_is_base(txobj,16):
        return serialize(json_changebase(txobj,lambda x: x.decode('hex'))).encode('hex')
    o.append(encode(txobj["version"],256,4)[::-1])
    o.append(num_to_var_int(len(txobj["ins"])))
    for inp in txobj["ins"]:
        o.append(inp["outpoint"]["hash"][::-1])
        o.append(encode(inp["outpoint"]["index"],256,4)[::-1])
        o.append(num_to_var_int(len(inp["script"]))+inp["script"])
        o.append(encode(inp["sequence"],256,4)[::-1])
    o.append(num_to_var_int(len(txobj["outs"])))
    for out in txobj["outs"]:
        o.append(encode(out["value"],256,8)[::-1])
        o.append(num_to_var_int(len(out["script"]))+out["script"])
    o.append(encode(txobj["locktime"],256,4)[::-1])
    return ''.join(o)

### Hashing transactions for signing

SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
SIGHASH_ANYONECANPAY = 80

def signature_form(tx, i, script, hashcode = SIGHASH_ALL):
    i, hashcode = int(i), int(hashcode)
    if isinstance(tx,str):
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
    return newtx

### Making the actual signatures

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

def txhash(tx,hashcode=None):
    if re.match('^[0-9a-fA-F]*$',tx):
        tx = changebase(tx,16,256)
    if hashcode: return dbl_sha256(tx + encode(int(hashcode),256,4)[::-1])
    else: return dbl_sha256(tx)[::-1]

def bin_txhash(tx,hashcode=None):
    return txhash(tx,hashcode).decode('hex')

def ecdsa_tx_sign(tx,priv,hashcode=SIGHASH_ALL):
    rawsig = ecdsa_raw_sign(bin_txhash(tx,hashcode),priv)
    return der_encode_sig(*rawsig)+encode(hashcode,16,2)

def ecdsa_tx_verify(tx,sig,pub,hashcode=SIGHASH_ALL):
    return ecdsa_raw_verify(bin_txhash(tx,hashcode),der_decode_sig(sig),pub)

def ecdsa_tx_recover(tx,sig,hashcode=SIGHASH_ALL):
    z = bin_txhash(tx,hashcode)
    _,r,s = der_decode_sig(sig)
    left = ecdsa_raw_recover(z,(0,r,s))
    right = ecdsa_raw_recover(z,(1,r,s))
    return (encode_pubkey(left,'hex'), encode_pubkey(right,'hex'))

### Scripts

def mk_pubkey_script(addr): # Keep the auxiliary functions around for altcoins' sake
    return '76a914' + b58check_to_hex(addr) + '88ac'

def mk_scripthash_script(addr):
    return 'a914' + b58check_to_hex(addr) + '87'

# Address representation to output script
def address_to_script(addr):
    if addr[0] == '3': return mk_scripthash_script(addr)
    else: return mk_pubkey_script(addr)

# Output script to address representation
def script_to_address(script,vbyte=0):
    if re.match('^[0-9a-fA-F]*$',script):
        script = script.decode('hex')
    if script[:3] == '\x76\xa9\x14' and script[-2:] == '\x88\xac' and len(script) == 25:
        return bin_to_b58check(script[3:-2],vbyte) # pubkey hash addresses
    else:
        return bin_to_b58check(script[2:-1],5) # BIP0016 scripthash addresses

def p2sh_scriptaddr(script):
    if re.match('^[0-9a-fA-F]*$',script): script = script.decode('hex')
    return hex_to_b58check(hash160(script),5)
scriptaddr = p2sh_scriptaddr

def deserialize_script(script):
    if re.match('^[0-9a-fA-F]*$',script):
        return json_changebase(deserialize_script(script.decode('hex')),lambda x:x.encode('hex'))
    out, pos = [], 0
    while pos < len(script):
        code = ord(script[pos])
        if code == 0:
            out.append(None)
            pos += 1
        elif code <= 75:
            out.append(script[pos+1:pos+1+code])
            pos += 1 + code
        elif code <= 78:
            szsz = pow(2,code - 76)
            sz = decode(script[pos + szsz : pos : -1],256)
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
    elif unit is None:
        return '\x00'
    else:
        if len(unit) <= 75: return chr(len(unit))+unit
        elif len(unit) < 256: return chr(76)+chr(len(unit))+unit
        elif len(unit) < 65536: return chr(77)+encode(len(unit),256,2)[::-1]+unit
        else: return chr(78)+encode(len(unit),256,4)[::-1]+unit

def serialize_script(script):
    if json_is_base(script,16):
        return serialize_script(json_changebase(script,lambda x:x.decode('hex'))).encode('hex')
    return ''.join(map(serialize_script_unit,script))

def mk_multisig_script(*args): # [pubs],k,n or pub1,pub2...pub[n],k,n
    if len(args) == 3: pubs, k, n = args[0], int(args[1]), int(args[2])
    else: pubs, k, n = list(args[:-2]), int(args[-2]), int(args[-1])
    return serialize_script([k]+pubs+[n,174])

### Signing and verifying

def verify_tx_input(tx,i,script,sig,pub):
    if re.match('^[0-9a-fA-F]*$',tx): tx = tx.decode('hex')
    if re.match('^[0-9a-fA-F]*$',script): script = script.decode('hex')
    if not re.match('^[0-9a-fA-F]*$',sig): sig = sig.encode('hex')
    hashcode = ord(sig[-1])
    modtx = signature_form(tx,int(i),script)
    return ecdsa_tx_verify(modtx,sig,pub)

def sign(tx,i,priv):
    i = int(i)
    if not re.match('^[0-9a-fA-F]*$',tx):
        return sign(tx.encode('hex'),i,priv).decode('hex')
    if len(priv) <= 33: priv = priv.encode('hex')
    pub = privkey_to_pubkey(priv)
    address = pubkey_to_address(pub)
    signing_tx = signature_form(tx,i,mk_pubkey_script(address))
    sig = ecdsa_tx_sign(signing_tx,priv)
    txobj = deserialize(tx)
    txobj["ins"][i]["script"] = serialize_script([sig,pub])
    return serialize(txobj)

def multisign(tx,i,script,pk):
    if re.match('^[0-9a-fA-F]*$',tx): tx = tx.decode('hex')
    if re.match('^[0-9a-fA-F]*$',script): script = script.decode('hex')
    modtx = signature_form(tx,i,script)
    return ecdsa_tx_sign(modtx,pk)

def apply_multisignatures(*args): # tx,i,script,sigs OR tx,i,script,sig1,sig2...,sig[n]
    tx, i, script = args[0], int(args[1]), args[2]
    sigs = args[3] if isinstance(args[3],list) else list(args[3:])

    txobj = deserialize(tx)
    txobj["ins"][i]["script"] = serialize_script([None]+sigs+[script])
    return serialize(txobj)

def mktx(*args): # [in0, in1...],[out0, out1...] or in0, in1 ... out0 out1 ...
    if isinstance(args[0],list): ins, outs = args[0], args[1]
    else:
        def is_inp(arg): return len(arg) > 64 or "output" in arg or "outpoint" in arg
        ins, outs = filter(is_inp, args), filter(lambda x: not is_inp(x), args)

    txobj = { "locktime" : 0, "version" : 1,"ins" : [], "outs" : [] }
    for i in ins:
        if isinstance(i,dict) and "outpoint" in i:
            txobj["ins"].append(i)
        else:
            if isinstance(i,dict) and "output" in i: i = i["output"]
            txobj["ins"].append({ 
                "outpoint" : { "hash": i[:64], "index": int(i[65:]) },
                "script": "",
                "sequence": 4294967295 
            })
    for o in outs:
        if isinstance(o,str): o = {
            "address": o[:o.find(':')],
            "value": int(o[o.find(':')+1:])
        }
        txobj["outs"].append({
            "script": address_to_script(o["address"]),
            "value": o["value"]
        })
    return serialize(txobj)
