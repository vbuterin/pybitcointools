#!/usr/bin/python
import binascii, re, copy
from .main import *
from _functools import reduce

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

# Hashing transactions for signing

SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
# this works like SIGHASH_ANYONECANPAY | SIGHASH_ALL, might as well make it explicit while
# we fix the constant
SIGHASH_ANYONECANPAY = 0x81
SIGHASH_FORKID = 0x40

def encode_1_byte(val):
    return encode(val, 256, 1)[::-1]

def encode_4_bytes(val):
    return encode(val, 256, 4)[::-1]

def encode_8_bytes(val):
    return encode(val, 256, 8)[::-1]

def list_to_bytes(vals):
    return ''.join(vals) if is_python2 else reduce(lambda x, y: x + y, vals, bytes())

def dbl_sha256_list(vals):
    return bin_dbl_sha256(list_to_bytes(vals))


# Transaction serialization and deserialization

def is_segwit(tx):
    return tx[4] == 0

def deserialize(tx):
    if isinstance(tx, str) and re.match('^[0-9a-fA-F]*$', tx):
        # tx = bytes(bytearray.fromhex(tx))
        return json_changebase(deserialize(binascii.unhexlify(tx)),
                               lambda x: safe_hexlify(x))
    # http://stackoverflow.com/questions/4851463/python-closure-write-to-variable-in-parent-scope
    # Python's scoping rules are demented, requiring me to make pos an object
    # so that it is call-by-reference
    pos = [0]

    def read_as_int(bytez):
        pos[0] += bytez
        return decode(tx[pos[0] - bytez:pos[0]][::-1], 256)

    def read_var_int():
        pos[0] += 1
        val = from_byte_to_int(tx[pos[0] - 1])
        if val < 253:
            return val
        return read_as_int(pow(2, val - 252))

    def read_bytes(bytez):
        pos[0] += bytez
        return tx[pos[0] - bytez:pos[0]]

    def read_var_string():
        size = read_var_int()
        return read_bytes(size)

    def read_segwit_string():
        size = read_var_int()
        return num_to_var_int(size)+read_bytes(size)

    obj = {"ins": [], "outs": []}
    obj["version"] = read_as_int(4)
    has_witness = is_segwit(tx)
    if has_witness:
        obj['marker'] = read_as_int(1)
        obj['flag'] = read_as_int(1)
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
    if has_witness:
        obj['witness'] = []
        for i in range(ins):
            number = read_var_int()
            scriptCode = []
            for i in range(number):
                scriptCode.append(read_segwit_string())
            obj['witness'].append({
                'number': number,
                'scriptCode': list_to_bytes(scriptCode)
            })
    obj["locktime"] = read_as_int(4)
    return obj

def serialize(txobj, include_witness=True):
    if isinstance(txobj, bytes):
        txobj = bytes_to_hex_string(txobj)
    o = []
    if json_is_base(txobj, 16):
        json_changedbase = json_changebase(txobj, lambda x: binascii.unhexlify(x))
        hexlified = safe_hexlify(serialize(json_changedbase, include_witness=include_witness))
        return hexlified
    o.append(encode_4_bytes(txobj["version"]))
    if include_witness and all(k in txobj.keys() for k in ['marker', 'flag']):
        o.append(encode_1_byte(txobj["marker"]))
        o.append(encode_1_byte(txobj["flag"]))
    o.append(num_to_var_int(len(txobj["ins"])))
    for inp in txobj["ins"]:
        o.append(inp["outpoint"]["hash"][::-1])
        o.append(encode_4_bytes(inp["outpoint"]["index"]))
        o.append(num_to_var_int(len(inp["script"])) + (inp["script"] if inp["script"] or is_python2 else bytes()))
        o.append(encode_4_bytes(inp["sequence"]))
    o.append(num_to_var_int(len(txobj["outs"])))
    for out in txobj["outs"]:
        o.append(encode_8_bytes(out["value"]))
        o.append(num_to_var_int(len(out["script"])) + out["script"])
    if include_witness and "witness" in txobj.keys():
        for witness in txobj["witness"]:
            o.append(num_to_var_int(witness["number"]) + (witness["scriptCode"] if witness["scriptCode"] or is_python2 else bytes()))
    o.append(encode_4_bytes(txobj["locktime"]))
    return list_to_bytes(o)

# https://github.com/Bitcoin-UAHF/spec/blob/master/replay-protected-sighash.md#OP_CHECKSIG
def uahf_digest(txobj, i):
    if isinstance(txobj, bytes):
        txobj = bytes_to_hex_string(txobj)
    o = []

    if json_is_base(txobj, 16):
        txobj = json_changebase(txobj, lambda x: binascii.unhexlify(x))
    o.append(encode(txobj["version"], 256, 4)[::-1])

    serialized_ins = []
    for inp in txobj["ins"]:
        serialized_ins.append(inp["outpoint"]["hash"][::-1])
        serialized_ins.append(encode_4_bytes(inp["outpoint"]["index"]))
    inputs_hashed = dbl_sha256_list(serialized_ins)
    o.append(inputs_hashed)

    sequences = dbl_sha256_list([encode_4_bytes(inp["sequence"]) for inp in txobj['ins']])
    o.append(sequences)

    inp = txobj['ins'][i]
    o.append(inp["outpoint"]["hash"][::-1])
    o.append(encode_4_bytes(inp["outpoint"]["index"]))
    o.append(num_to_var_int(len(inp["script"])) + (inp["script"] if inp["script"] or is_python2 else bytes()))
    o.append(encode_8_bytes(inp['amount']))
    o.append(encode_4_bytes(inp['sequence']))

    serialized_outs = []
    for out in txobj["outs"]:
        serialized_outs.append(encode_8_bytes(out["value"]))
        serialized_outs.append(num_to_var_int(len(out["script"])) + out["script"])
    outputs_hashed = dbl_sha256_list(serialized_outs)
    o.append(outputs_hashed)

    o.append(encode_4_bytes(txobj["locktime"]))

    return list_to_bytes(o)

def signature_form(tx, i, script, hashcode=SIGHASH_ALL):
    i, hashcode = int(i), int(hashcode)
    if isinstance(tx, string_or_bytes_types):
        tx = deserialize(tx)
    is_segwit = tx['ins'][i].get('segwit', False) or tx['ins'][i].get('new_segwit', False)
    newtx = copy.deepcopy(tx)
    for inp in newtx["ins"]:
        inp["script"] = ""
    newtx["ins"][i]["script"] = script
    if is_segwit or hashcode & 255 == SIGHASH_ALL + SIGHASH_FORKID:
        return uahf_digest(newtx, i)
    elif hashcode == SIGHASH_NONE:
        newtx["outs"] = []
    elif hashcode == SIGHASH_SINGLE:
        newtx["outs"] = newtx["outs"][:len(newtx["ins"])]
        for out in newtx["outs"][:len(newtx["ins"]) - 1]:
            out['value'] = 2**64 - 1
            out['script'] = ""
    elif hashcode == SIGHASH_ANYONECANPAY:
        newtx["ins"] = [newtx["ins"][i]]
    else:
        pass
    return serialize(newtx, include_witness=False)

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

def txhash(tx, hashcode=None, wtxid=True):
    if isinstance(tx, str) and re.match('^[0-9a-fA-F]*$', tx):
        tx = changebase(tx, 16, 256)
    if not wtxid and is_segwit(tx):
        tx = serialize(deserialize(tx), include_witness=False)
    if hashcode:
        return dbl_sha256(from_string_to_bytes(tx) + encode(int(hashcode), 256, 4)[::-1])
    else:
        return safe_hexlify(bin_dbl_sha256(tx)[::-1])

def public_txhash(tx, hashcode=None):
    return txhash(tx, hashcode=hashcode, wtxid=False)

def bin_txhash(tx, hashcode=None):
    return binascii.unhexlify(txhash(tx, hashcode))


def ecdsa_tx_sign(tx, priv, hashcode=SIGHASH_ALL):
    rawsig = ecdsa_raw_sign(bin_txhash(tx, hashcode), priv)
    return der_encode_sig(*rawsig)+encode(hashcode & 255, 16, 2)


def ecdsa_tx_verify(tx, sig, pub, hashcode=SIGHASH_ALL):
    return ecdsa_raw_verify(bin_txhash(tx, hashcode), der_decode_sig(sig), pub)


def ecdsa_tx_recover(tx, sig, hashcode=SIGHASH_ALL):
    z = bin_txhash(tx, hashcode)
    _, r, s = der_decode_sig(sig)
    left = ecdsa_raw_recover(z, (0, r, s))
    right = ecdsa_raw_recover(z, (1, r, s))
    return (encode_pubkey(left, 'hex'), encode_pubkey(right, 'hex'))

# Scripts

def mk_pubkey_script(addr):
    """
    Used in converting p2pkh address to input or output script
    """
    return '76a914' + b58check_to_hex(addr) + '88ac'

def mk_scripthash_script(addr):
    """
    Used in converting p2sh address to output script
    """
    return 'a914' + b58check_to_hex(addr) + '87'

def output_script_to_address(script, magicbyte=0):
    if script.startswith('76'):
        script = script[6:]
    else:
        script = script[4:]
    if script.endswith('88ac'):
        script = script[:-4]
    else:
        script = script[:-2]
    return bin_to_b58check(safe_from_hex(script), magicbyte=magicbyte)

def mk_p2w_scripthash_script(witver, witprog):
    """
    Used in converting a decoded pay to witness script hash address to output script
    """
    assert (0 <= witver <= 16)
    OP_n = witver + 0x50 if witver > 0 else 0
    return bytes_to_hex_string([OP_n]) + '14' + (bytes_to_hex_string(witprog))

def mk_p2wpkh_redeemscript(pubkey):
    """
    Used in converting public key to p2wpkh script
    """
    return '160014' + pubkey_to_hash_hex(pubkey)

def mk_p2wpkh_script(pubkey):
    """
    Used in converting public key to p2wpkh script
    """
    script = mk_p2wpkh_redeemscript(pubkey)[2:]
    return 'a914'+ hex_to_hash160(script) + '87'

def mk_p2wpkh_scriptcode(pubkey):
    """
    Used in signing for tx inputs
    """
    return '76a914' + pubkey_to_hash_hex(pubkey) + '88ac'

def p2wpkh_nested_script(pubkey):
    return '0014' + hash160(safe_from_hex(pubkey))

# Output script to address representation

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

def mk_multisig_script(*args):  # [pubs],k or pub1,pub2...pub[n],M
    """
    :param args: List of public keys to used to create multisig and M, the number of signatures required to spend
    :return: multisig script
    """
    if isinstance(args[0], list):
        pubs, M = args[0], int(args[1])
    else:
        pubs = list(filter(lambda x: len(str(x)) >= 32, args))
        M = int(args[len(pubs)])
    N = len(pubs)
    return serialize_script([M]+pubs+[N]+[0xae])

# Signing and verifying


def verify_tx_input(tx, i, script, sig, pub):
    if re.match('^[0-9a-fA-F]*$', tx):
        tx = binascii.unhexlify(tx)
    if re.match('^[0-9a-fA-F]*$', script):
        script = binascii.unhexlify(script)
    if not re.match('^[0-9a-fA-F]*$', sig):
        sig = safe_hexlify(sig)
    hashcode = decode(sig[-2:], 16)
    modtx = signature_form(tx, int(i), script, hashcode)
    return ecdsa_tx_verify(modtx, sig, pub, hashcode)

def multisign(tx, i, script, pk, hashcode=SIGHASH_ALL):
    if isinstance(tx, dict):
        tx = serialize(tx)
    if re.match('^[0-9a-fA-F]*$', tx):
        tx = binascii.unhexlify(tx)
    if re.match('^[0-9a-fA-F]*$', script):
        script = binascii.unhexlify(script)
    modtx = signature_form(tx, i, script, hashcode)
    return ecdsa_tx_sign(modtx, pk, hashcode)


def apply_multisignatures(txobj, i, script, *args):
    # tx,i,script,sigs OR tx,i,script,sig1,sig2...,sig[n]
    sigs = args[0] if isinstance(args[0], list) else list(args)

    if isinstance(script, str) and re.match('^[0-9a-fA-F]*$', script):
        script = binascii.unhexlify(script)
    sigs = [binascii.unhexlify(x) if x[:2] == '30' else x for x in sigs]
    if not isinstance(txobj, dict):
        txobj = deserialize(txobj)
    if isinstance(txobj, str) and re.match('^[0-9a-fA-F]*$', txobj):
        return safe_hexlify(apply_multisignatures(binascii.unhexlify(txobj), i, script, sigs))

    # Not pushing empty elements on the top of the stack if passing no
    # script (in case of bare multisig inputs there is no script)
    script_blob = [] if script.__len__() == 0 else [script]

    txobj["ins"][i]["script"] = safe_hexlify(serialize_script([None]+sigs+script_blob))
    return serialize(txobj)


def is_inp(arg):
    return len(arg) > 64 or "output" in arg or "outpoint" in arg

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
    unspents = low[:i]
    actual_value = sum(unspent['value'] for unspent in unspents)
    return low[:i]