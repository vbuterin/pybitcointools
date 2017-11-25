#!/usr/bin/python
import binascii, re, json, copy, sys
from bitcoin.main import *
from _functools import reduce
import struct

### Hex to bin converter and vice versa for objects


def json_is_base(obj, base):
    if not is_python2 and isinstance(obj, bytes):
        return False
    
    alpha = get_code_string(base)
    if isinstance(obj, string_types):
        for i in range(len(obj)):
            if alpha.find(obj[i]) == -1:
                return False
        return True
    elif isinstance(obj, int_types) or obj is None:
        return True
    elif isinstance(obj, list):
        for i in range(len(obj)):
            if not json_is_base(obj[i], base):
                return False
        return True
    else:
        for x in obj:
            if not json_is_base(obj[x], base):
                return False
        return True


def json_changebase(obj, changer):
    if isinstance(obj, string_or_bytes_types):
        return changer(obj)
    elif isinstance(obj, int_types) or obj is None:
        return obj
    elif isinstance(obj, list):
        return [json_changebase(x, changer) for x in obj]
    return dict((x, json_changebase(obj[x], changer)) for x in obj)

# Transaction serialization and deserialization


def deserialize(tx):
    if isinstance(tx, str) and re.match('^[0-9a-fA-F]*$', tx):
        #tx = bytes(bytearray.fromhex(tx))
        return json_changebase(deserialize(binascii.unhexlify(tx)),
                              lambda x: safe_hexlify(x))
    # http://stackoverflow.com/questions/4851463/python-closure-write-to-variable-in-parent-scope
    # Python's scoping rules are demented, requiring me to make pos an object
    # so that it is call-by-reference
    pos = [0]

    def read_as_int(bytez):
        pos[0] += bytez
        return decode(tx[pos[0]-bytez:pos[0]][::-1], 256)

    def read_var_int():
        pos[0] += 1
        
        val = from_byte_to_int(tx[pos[0]-1])
        if val < 253:
            return val
        return read_as_int(pow(2, val - 252))

    def read_bytes(bytez):
        pos[0] += bytez
        return tx[pos[0]-bytez:pos[0]]

    def read_var_string():
        size = read_var_int()
        return read_bytes(size)

    obj = {"ins": [], "outs": []}
    obj["version"] = read_as_int(4)
    ins = read_var_int()
    for i in range(ins):
        obj["ins"].append({
            "outpoint": {
                "hash": read_bytes(32)[::-1],
                "index": read_as_int(4)
            },
            "script": read_var_string(),
            "sequence": read_as_int(4)
        })
    outs = read_var_int()
    for i in range(outs):
        obj["outs"].append({
            "value": read_as_int(8),
            "script": read_var_string()
        })
    obj["locktime"] = read_as_int(4)
    return obj

def serialize(txobj):
    #if isinstance(txobj, bytes):
    #    txobj = bytes_to_hex_string(txobj)
    o = []
    if json_is_base(txobj, 16):
        json_changedbase = json_changebase(txobj, lambda x: binascii.unhexlify(x))
        hexlified = safe_hexlify(serialize(json_changedbase))
        return hexlified
    o.append(encode(txobj["version"], 256, 4)[::-1])
    o.append(num_to_var_int(len(txobj["ins"])))
    for inp in txobj["ins"]:
        o.append(inp["outpoint"]["hash"][::-1])
        o.append(encode(inp["outpoint"]["index"], 256, 4)[::-1])
        o.append(num_to_var_int(len(inp["script"]))+(inp["script"] if inp["script"] or is_python2 else bytes()))
        o.append(encode(inp["sequence"], 256, 4)[::-1])
    o.append(num_to_var_int(len(txobj["outs"])))
    for out in txobj["outs"]:
        o.append(encode(out["value"], 256, 8)[::-1])
        o.append(num_to_var_int(len(out["script"]))+out["script"])
    o.append(encode(txobj["locktime"], 256, 4)[::-1])

    return ''.join(o) if is_python2 else reduce(lambda x,y: x+y, o, bytes())

# Hashing transactions for signing

SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
SIGHASH_FORKID = 0x40
SIGHASH_ANYONECANPAY = 0x80

def _int_to4bytes(x):
    return struct.pack("<L",x)

def _serialize_outpoint(outpoint):
    return binascii.unhexlify(outpoint['hash'])[::-1]+_int_to4bytes(outpoint['index'])

def _serialize_output(output):
    script=binascii.unhexlify(output['script'])
    return struct.pack("<Q",output['value'])+num_to_var_int(len(script))+script

def _abc_get_prevouthash(tx):
    prevoutstr=bytes()
    for txinput in tx["ins"]:
        outpoint=_serialize_outpoint(txinput['outpoint'])
        #print('outpoint:'+safe_hexlify(outpoint))
        prevoutstr+=outpoint
    
    return bin_dbl_sha256(prevoutstr)

def _abc_get_sequencehash(tx):
    seqoutstr=bytes()
    for txinput in tx["ins"]:
        seqoutstr+=_int_to4bytes(txinput['sequence'])
    return bin_dbl_sha256(seqoutstr)
        
def _abc_get_outputshash(tx):
    outstr=bytes()
    for txoutput in tx["outs"]:
        output=_serialize_output(txoutput)
        #print('output:'+safe_hexlify(output))
        outstr+=output
    return bin_dbl_sha256(outstr)

def check_hash(label,bytesofar,value):
    binsha=bin_dbl_sha256(bytesofar)
    hashout=safe_hexlify(binsha[::-1])
    print("%s: %s" % (label,str(value)))
    print("%s_hashsofar: %s" % (label,hashout))
    
    

def _signature_form_abc(tx, i, script, hashcode, inp):
    input = inp[0]
    if isinstance(tx,string_or_bytes_types):
        tx=deserialize(tx)

    hashprevout=b'\x00'*32
    hashseqout=b'\x00'*32
    hashoutputs=b'\x00'*32

    notsinglenone=((hashcode & 0x1f) != SIGHASH_SINGLE) and ((hashcode & 0x1f) != SIGHASH_NONE)

    if(not (hashcode & SIGHASH_ANYONECANPAY)):
        hashprevout=_abc_get_prevouthash(tx)
        if(notsinglenone):
            hashseqout=_abc_get_sequencehash(tx)

    if(notsinglenone):
        hashoutputs=_abc_get_outputshash(tx)
    elif((hashcode & 0x1f) == SIGHASH_SINGLE and i < len(tx['outs'])):
        txoutstring=_serialize_output(tx['outs'][i])
        hashoutputs=bin_dbl_sha256(txoutstring)

    #print('hashprev:'+safe_hexlify(hashprevout[::-1]))
  #  print('hashseq:'+safe_hexlify(hashseqout))
    sigout=bytes()
    sigout+=_int_to4bytes(tx['version'])
    check_hash("version",sigout,tx['version'])
    sigout+=hashprevout
    check_hash("hashPrevouts",sigout,safe_hexlify(hashprevout[::-1]))
    sigout+=hashseqout
    check_hash("hashSequence",sigout,safe_hexlify(hashseqout[::-1]))
    sigout+=_serialize_outpoint(tx['ins'][i]['outpoint'])
    check_hash("prevout_this",sigout,safe_hexlify(_serialize_outpoint(tx['ins'][i]['outpoint'])))
    if('scriptPubKey' not in input):
        raise Exception("Cannot do bitcoin abc transaction sig without input scriptPubKey value")
    else:
        script=input['scriptPubKey']
        sigout+=num_to_var_int(len(script)//2)+binascii.unhexlify(script)
        check_hash("scriptCode",sigout,script)

    if('value' not in input):
        raise Exception("Cannot do bitcoin abc transaction sig without input bitcoin value")
    else:
        sigout+=struct.pack("<Q",input['value'])
        check_hash("amount",sigout,input['value'])

    sigout+=_int_to4bytes(tx['ins'][i]['sequence'])
    check_hash("nSequence",sigout,tx['ins'][i]['sequence'])
    
    #print('hashoutputs:'+safe_hexlify(hashoutputs))
    sigout+=hashoutputs
    check_hash("hashOutputs",sigout,safe_hexlify(hashoutputs[::-1]))
    #print('partsig:'+safe_hexlify(sigout))
    sigout+=_int_to4bytes(tx['locktime'])
    check_hash("nLockTime",sigout,tx['locktime'])
    forkId=0
    #sigout+=_int_to4bytes(hashcode | (forkId << 8))
    #print('fullsig:'+safe_hexlify(sigout))
    #print('fullsig:'+safe_hexlify(sigout))
    return safe_hexlify(sigout)
        
    
def _signature_form_segwit(): #TODO: this is similar to bitcoin abc but different.
    pass

def _signature_form_classic(tx, i, script, hashcode=SIGHASH_ALL,inp=None):
    hc5= hashcode & 0x1f

    newtx = copy.deepcopy(tx)
    for inp in newtx["ins"]:
        inp["script"] = ""
    newtx["ins"][i]["script"] = script
    if (hc5) == SIGHASH_NONE:
        newtx["outs"] = []
    elif (hc5) == SIGHASH_SINGLE:
        if i >= len(newtx["outs"]):
            raise Exception("You are trying to use SIGHASH_SINGLE to sign an input that does not have a "
                            "corresponding output (" + str(i) + "). This could lead to a irreversible lose "
                                                                    "of funds. Signature process aborted.")
        else:
            newtx["outs"] = newtx["outs"][:i+1]
            for out in newtx["outs"][:i]:
                out["value"] = 2**64 - 1
                out["script"] = ""
    elif (hc5 == SIGHASH_ALL) and (hashcode & SIGHASH_ANYONECANPAY):
        newtx["ins"] = [newtx["ins"][i]]
    else:
        pass

    if hashcode  in [SIGHASH_NONE, SIGHASH_SINGLE]:
        for inp in xrange(len(newtx["ins"])):
            if inp is not i:
                newtx["ins"][inp]['sequence'] = 0
    return newtx




def signature_form(tx, i, script, hashcode=SIGHASH_ALL,inp=None):
    i, hashcode = int(i), int(hashcode)

    if isinstance(tx, string_or_bytes_types):
        return signature_form(deserialize(tx), i, script, hashcode, inp)

    if(hashcode & SIGHASH_FORKID):
        return _signature_form_abc(tx,i,script,hashcode, inp)
    return serialize(_signature_form_classic(tx,i,script,hashcode, inp=None))

# Making the actual signatures


def der_encode_sig(v, r, s):
    b1, b2 = safe_hexlify(encode(r, 256)), safe_hexlify(encode(s, 256))
    if len(b1) and b1[0] in '89abcdef':
        b1 = '00' + b1
    if len(b2) and b2[0] in '89abcdef':
        b2 = '00' + b2
    left = '02'+encode(len(b1)//2, 16, 2)+b1
    right = '02'+encode(len(b2)//2, 16, 2)+b2
    return '30'+encode(len(left+right)//2, 16, 2)+left+right

def der_decode_sig(sig):
    leftlen = decode(sig[6:8], 16)*2
    left = sig[8:8+leftlen]
    rightlen = decode(sig[10+leftlen:12+leftlen], 16)*2
    right = sig[12+leftlen:12+leftlen+rightlen]
    return (None, decode(left, 16), decode(right, 16))

def is_bip66(sig):
    """Checks hex DER sig for BIP66 consistency"""
    #https://raw.githubusercontent.com/bitcoin/bips/master/bip-0066.mediawiki
    #0x30  [total-len]  0x02  [R-len]  [R]  0x02  [S-len]  [S]  [sighash]
    sig = bytearray.fromhex(sig) if re.match('^[0-9a-fA-F]*$', sig) else bytearray(sig)
    if (sig[0] == 0x30) and (sig[1] == len(sig)-2):     # check if sighash is missing
            sig.extend(b"\1")		                   	# add SIGHASH_ALL for testing
    #assert (sig[-1] & 124 == 0) and (not not sig[-1]), "Bad SIGHASH value"
    
    if len(sig) < 9 or len(sig) > 73: return False
    if (sig[0] != 0x30): return False
    if (sig[1] != len(sig)-3): return False
    rlen = sig[3]
    if (5+rlen >= len(sig)): return False
    slen = sig[5+rlen]
    if (rlen + slen + 7 != len(sig)): return False
    if (sig[2] != 0x02): return False
    if (rlen == 0): return False
    if (sig[4] & 0x80): return False
    if (rlen > 1 and (sig[4] == 0x00) and not (sig[5] & 0x80)): return False
    if (sig[4+rlen] != 0x02): return False
    if (slen == 0): return False
    if (sig[rlen+6] & 0x80): return False
    if (slen > 1 and (sig[6+rlen] == 0x00) and not (sig[7+rlen] & 0x80)):
        return False
    return True

def txhash(tx, hashcode=None):
    if isinstance(tx, str) and re.match('^[0-9a-fA-F]*$', tx):
        tx = changebase(tx, 16, 256)
    if hashcode:
        hc=dbl_sha256(from_string_to_bytes(tx) + encode(int(hashcode), 256, 4)[::-1])
        print('sighash:'+hc)
        return hc
    else:
        return safe_hexlify(bin_dbl_sha256(tx)[::-1])


def bin_txhash(tx, hashcode=None):
    return binascii.unhexlify(txhash(tx, hashcode))


def ecdsa_tx_sign(tx, priv, hashcode=SIGHASH_ALL):
    rawsig = ecdsa_raw_sign(bin_txhash(tx, hashcode), priv)
    print(rawsig)
    sig=der_encode_sig(*rawsig)+encode(hashcode, 16, 2)
    print('sig:'+sig)
    return sig


def ecdsa_tx_verify(tx, sig, pub, hashcode=SIGHASH_ALL):
    return ecdsa_raw_verify(bin_txhash(tx, hashcode), der_decode_sig(sig[:-2]), pub)


def ecdsa_tx_recover(tx, sig, hashcode=SIGHASH_ALL):
    z = bin_txhash(tx, hashcode)
    _, r, s = der_decode_sig(sig)
    left = ecdsa_raw_recover(z, (0, r, s))
    right = ecdsa_raw_recover(z, (1, r, s))
    return (encode_pubkey(left, 'hex'), encode_pubkey(right, 'hex'))

# Scripts
def mk_pubkey_script(addr):
    # Keep the auxiliary functions around for altcoins' sake
    return '76a914' + b58check_to_hex(addr) + '88ac'


def mk_scripthash_script(addr):
    return 'a914' + b58check_to_hex(addr) + '87'

# Address representation to output script


def address_to_script(addr):
    if addr[0] == '3' or addr[0] == '2':
        return mk_scripthash_script(addr)
    else:
        return mk_pubkey_script(addr)

# Output script to address representation

def script_to_address(script, vbyte=0):
    if re.match('^[0-9a-fA-F]*$', script):
        script = binascii.unhexlify(script)
    if script[:3] == b'\x76\xa9\x14' and script[-2:] == b'\x88\xac' and len(script) == 25:
        return bin_to_b58check(script[3:-2], vbyte)  # pubkey hash addresses
    else:
        if vbyte in [111, 196]:
            # Testnet
            scripthash_byte = 196
        elif vbyte == 0:
            # Mainnet
            scripthash_byte = 5
        else:
            scripthash_byte = vbyte
        # BIP0016 scripthash addresses
        return bin_to_b58check(script[2:-1], scripthash_byte)


def p2sh_scriptaddr(script, magicbyte=5):
    if re.match('^[0-9a-fA-F]*$', script):
        script = binascii.unhexlify(script)
    return hex_to_b58check(hash160(script), magicbyte)
scriptaddr = p2sh_scriptaddr


def deserialize_script(script):
    if isinstance(script, str) and re.match('^[0-9a-fA-F]*$', script):
       return json_changebase(deserialize_script(binascii.unhexlify(script)),
                              lambda x: safe_hexlify(x))
    out, pos = [], 0
    while pos < len(script):
        code = from_byte_to_int(script[pos])
        if code == 0:
            out.append(None)
            pos += 1
        elif code <= 75:
            out.append(script[pos+1:pos+1+code])
            pos += 1 + code
        elif code <= 78:
            szsz = pow(2, code - 76)
            sz = decode(script[pos+szsz: pos:-1], 256)
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
    if isinstance(unit, int):
        if unit < 16:
            return from_int_to_byte(unit + 80)
        else:
            return from_int_to_byte(unit)
    elif unit is None:
        return b'\x00'
    else:
        if len(unit) <= 75:
            return from_int_to_byte(len(unit))+unit
        elif len(unit) < 256:
            return from_int_to_byte(76)+from_int_to_byte(len(unit))+unit
        elif len(unit) < 65536:
            return from_int_to_byte(77)+encode(len(unit), 256, 2)[::-1]+unit
        else:
            return from_int_to_byte(78)+encode(len(unit), 256, 4)[::-1]+unit


if is_python2:
    def serialize_script(script):
        if json_is_base(script, 16):
            return binascii.hexlify(serialize_script(json_changebase(script,
                                    lambda x: binascii.unhexlify(x))))
        return ''.join(map(serialize_script_unit, script))
else:
    def serialize_script(script):
        if json_is_base(script, 16):
            return safe_hexlify(serialize_script(json_changebase(script,
                                    lambda x: binascii.unhexlify(x))))
        
        result = bytes()
        for b in map(serialize_script_unit, script):
            result += b if isinstance(b, bytes) else bytes(b, 'utf-8')
        return result


def mk_multisig_script(*args):  # [pubs],k or pub1,pub2...pub[n],k
    if isinstance(args[0], list):
        pubs, k = args[0], int(args[1])
    else:
        pubs = list(filter(lambda x: len(str(x)) >= 32, args))
        k = int(args[len(pubs)])
    return serialize_script([k]+pubs+[len(pubs)]+[0xae])

# Signing and verifying


def verify_tx_input(tx, i, script, sig, pub):
    if re.match('^[0-9a-fA-F]*$', tx):
        tx = binascii.unhexlify(tx)
    if re.match('^[0-9a-fA-F]*$', script):
        script = binascii.unhexlify(script)
    if not re.match('^[0-9a-fA-F]*$', sig):
        sig = safe_hexlify(sig)
    hashcode = decode(sig[-2:], 16)
   # print(hashcode)
    modtx = signature_form(tx, int(i), script, hashcode)
    #print('signature_form:'+safe_hexlify(modtx))
    return ecdsa_tx_verify(modtx, sig, pub, hashcode)


def sign(tx, i, priv, hashcode=SIGHASH_ALL,inp=None):
    i = int(i)
    if (not is_python2 and isinstance(re, bytes)) or not re.match('^[0-9a-fA-F]*$', tx):
        return binascii.unhexlify(sign(safe_hexlify(tx), i, priv))
    if len(priv) <= 33:
        priv = safe_hexlify(priv)
    pub = privkey_to_pubkey(priv)
    compressed_pub = encode_pubkey(pub, 'hex_compressed')
    address = pubkey_to_address(compressed_pub)
    script=mk_pubkey_script(address)
    signing_tx = signature_form(tx, i, script, hashcode, inp)
    sig = ecdsa_tx_sign(signing_tx, priv, hashcode)
    #print({'pub':pub,'sig':sig,'script':script})
   # print('signature_form:'+signing_tx)
    txobj = deserialize(tx)
    txobj["ins"][i]["script"] = serialize_script([sig, compressed_pub])
    return serialize(txobj)


def signall(tx, priv, hashcode=SIGHASH_ALL, inps={}):
    # if priv is a dictionary, assume format is
    # { 'txinhash:txinidx' : privkey }
    # if inps is a dictionary, assume format is 
    # { 'txinhash:txinidx' : { 'scriptPubKey':xx,'value':1212 }}
   
    if isinstance(priv, dict):
        for e, i in enumerate(deserialize(tx)["ins"]):
            lv = "%s:%d" % (i["outpoint"]["hash"], i["outpoint"]["index"])
            k = priv[lv]
            tx = sign(tx, e, k, hashcode, inps.get(lv, None))
            
    else:
        for i in range(len(deserialize(tx)["ins"])):
            lv = "%s:%d" % (i["outpoint"]["hash"], i["outpoint"]["index"])
            tx = sign(tx, i, priv, hashcode, inps.get(lv, None))
    return tx


def multisign(tx, i, script, pk, hashcode=SIGHASH_ALL,inps=None):
    if re.match('^[0-9a-fA-F]*$', tx):
        tx = binascii.unhexlify(tx)
    if re.match('^[0-9a-fA-F]*$', script):
        script = binascii.unhexlify(script)
    modtx = signature_form(tx, i, script, hashcode, inps)
    return ecdsa_tx_sign(modtx, pk, hashcode)


def apply_multisignatures(*args):
    # tx,i,script,sigs OR tx,i,script,sig1,sig2...,sig[n]
    tx, i, script = args[0], int(args[1]), args[2]
    sigs = args[3] if isinstance(args[3], list) else list(args[3:])

    if isinstance(script, str) and re.match('^[0-9a-fA-F]*$', script):
        script = binascii.unhexlify(script)
    sigs = [binascii.unhexlify(x) if x[:2] == '30' else x for x in sigs]
    if isinstance(tx, str) and re.match('^[0-9a-fA-F]*$', tx):
        return safe_hexlify(apply_multisignatures(binascii.unhexlify(tx), i, script, sigs))

    # Not pushing empty elements on the top of the stack if passing no
    # script (in case of bare multisig inputs there is no script)
    script_blob = [] if script.__len__() == 0 else [script]

    txobj = deserialize(tx)
    txobj["ins"][i]["script"] = serialize_script([None]+sigs+script_blob)
    return serialize(txobj)


def is_inp(arg):
    return len(arg) > 64 or "output" in arg or "outpoint" in arg


def mktx(*args):
    # [in0, in1...],[out0, out1...] or in0, in1 ... out0 out1 ...
    ins, outs = [], []
    for arg in args:
        if isinstance(arg, list):
            for a in arg: (ins if is_inp(a) else outs).append(a)
        else:
            (ins if is_inp(arg) else outs).append(arg)

    txobj = {"locktime": 0, "version": 1, "ins": [], "outs": []}
    for i in ins:
        if isinstance(i, dict) and "outpoint" in i:
            txobj["ins"].append(i)
        else:
            if isinstance(i, dict) and "output" in i:
                i = i["output"]
            txobj["ins"].append({
                "outpoint": {"hash": i[:64], "index": int(i[65:])},
                "script": "",
                "sequence": 4294967295
            })
    for o in outs:
        if isinstance(o, string_or_bytes_types):
            addr = o[:o.find(':')]
            val = int(o[o.find(':')+1:])
            o = {}
            if re.match('^[0-9a-fA-F]*$', addr):
                o["script"] = addr
            else:
                o["address"] = addr
            o["value"] = val

        outobj = {}
        if "address" in o:
            outobj["script"] = address_to_script(o["address"])
        elif "script" in o:
            outobj["script"] = o["script"]
        else:
            raise Exception("Could not find 'address' or 'script' in output.")
        outobj["value"] = o["value"]
        txobj["outs"].append(outobj)

    return serialize(txobj)


def select(unspent, value):
    value = int(value)
    high = [u for u in unspent if u["value"] >= value]
    high.sort(key=lambda u: u["value"])
    low = [u for u in unspent if u["value"] < value]
    low.sort(key=lambda u: -u["value"])
    if len(high):
        return [high[0]]
    i, tv = 0, 0
    while tv < value and i < len(low):
        tv += low[i]["value"]
        i += 1
    if tv < value:
        raise Exception("Not enough funds")
    return low[:i]

# Only takes inputs of the form { "output": blah, "value": foo }

def mksend(*args):
    argz, change, fee = args[:-2], args[-2], int(args[-1])
    ins, outs = [], []
    for arg in argz:
        if isinstance(arg, list):
            for a in arg:
                (ins if is_inp(a) else outs).append(a)
        else:
            (ins if is_inp(arg) else outs).append(arg)

    isum = sum([i["value"] for i in ins])
    osum, outputs2 = 0, []
    for o in outs:
        if isinstance(o, string_types):
            o2 = {
                "address": o[:o.find(':')],
                "value": int(o[o.find(':')+1:])
            }
        else:
            o2 = o
        outputs2.append(o2)
        osum += o2["value"]

def estimate_fee(tx):
    pass

    if isum < osum+fee:
        raise Exception("Not enough money")
    elif isum > osum+fee+5430:
        outputs2 += [{"address": change, "value": isum-osum-fee}]

    return mktx(ins, outputs2)
