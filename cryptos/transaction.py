#!/usr/bin/python
import copy
from .main import *
import binascii
from copy import deepcopy
from .opcodes import opcodes
from . import segwit_addr
from . import cashaddr
from _functools import reduce
from .utils import is_hex

from typing import AnyStr, Union
from .types import Tx, Witness


### Hex to bin converter and vice versa for objects


def json_is_base(obj, base):
    if isinstance(obj, bytes):
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


def list_to_bytes(vals: List[bytes]) -> bytes:
    try:
        return reduce(lambda x, y: x + y, vals, bytes())
    except Exception as e:
        print(e)
        pass


def dbl_sha256_list(vals):
    return bin_dbl_sha256(list_to_bytes(vals))


# Transaction serialization and deserialization

def is_segwit(tx: bytes) -> bool:
    """
    Checks that the marker in a transaction is set to 0. For legacy transactions this would indicate the number of
    inputs so will be at least 1.
    """
    return tx[4] == 0


def deserialize(tx: AnyStr) -> Tx:
    if isinstance(tx, str) and is_hex(tx):
        # tx = bytes(bytearray.fromhex(tx))
        return json_changebase(deserialize(binascii.unhexlify(tx)),
                               lambda x: safe_hexlify(x))
    # http://stackoverflow.com/questions/4851463/python-closure-write-to-variable-in-parent-scope
    # Python's scoping rules are demented, requiring me to make pos an object
    # so that it is call-by-reference
    pos = [0]

    def read_as_int(bytez: int):
        pos[0] += bytez
        return decode(tx[pos[0] - bytez:pos[0]][::-1], 256)

    def read_var_int() -> int:
        pos[0] += 1
        val = from_byte_to_int(tx[pos[0] - 1])
        if val < 253:
            return val
        return read_as_int(pow(2, val - 252))

    def read_bytes(bytez: int) -> str:
        pos[0] += bytez
        return tx[pos[0] - bytez:pos[0]]

    def read_var_string() -> str:
        size = read_var_int()
        return read_bytes(size)

    def read_witness_script_code() -> str:
        size = read_var_int()
        return num_to_var_int(size)+read_bytes(size)

    obj: Tx = {"ins": [], "outs": [], "version": read_as_int(4)}
    has_witness = is_segwit(tx)
    if has_witness:
        obj['marker'] = read_as_int(1)
        obj['flag'] = read_as_int(1)
    ins = read_var_int()
    for _ in range(ins):
        obj["ins"].append({
            "tx_hash": read_bytes(32)[::-1],
            "tx_pos": read_as_int(4),
            "script": read_var_string(),
            "sequence": read_as_int(4)
        })
    outs = read_var_int()
    for _ in range(outs):
        obj["outs"].append({
            "value": read_as_int(8),
            "script": read_var_string()
        })
    if has_witness:
        obj['witness'] = []
        for _ in range(ins):
            number = read_var_int()
            script_code = [read_witness_script_code() for _ in range(number)]
            obj['witness'].append({
                'number': number,
                'scriptCode': list_to_bytes(script_code)
            })
    obj["locktime"] = read_as_int(4)
    return obj


def test_unhexlify(x):
    try:
        return binascii.unhexlify(x)
    except binascii.Error:
        raise Exception('Unhexlify failed for', x)


def serialize(txobj: Tx, include_witness: bool = True) -> AnyStr:
    txobj = deepcopy(txobj)
    for i in txobj['ins']:
        if 'address' in i:
            del i['address']
    if isinstance(txobj, bytes):
        txobj = bytes_to_hex_string(txobj)
    o = []
    if json_is_base(txobj, 16):
        json_changedbase = json_changebase(txobj, test_unhexlify)
        hexlified = safe_hexlify(serialize(json_changedbase, include_witness=include_witness))
        return hexlified
    o.append(encode_4_bytes(txobj["version"]))
    if include_witness and all(k in txobj.keys() for k in ['marker', 'flag']):
        o.append(encode_1_byte(txobj["marker"]))
        o.append(encode_1_byte(txobj["flag"]))
    o.append(num_to_var_int(len(txobj["ins"])))
    for inp in txobj["ins"]:
        o.append(inp["tx_hash"][::-1])
        o.append(encode_4_bytes(inp["tx_pos"]))
        o.append(num_to_var_int(len(inp["script"])) + (inp["script"] if inp["script"] else bytes()))
        o.append(encode_4_bytes(inp["sequence"]))
    o.append(num_to_var_int(len(txobj["outs"])))
    for out in txobj["outs"]:
        o.append(encode_8_bytes(out["value"]))
        o.append(num_to_var_int(len(out["script"])) + out["script"])
    if include_witness and "witness" in txobj.keys():
        for witness in txobj["witness"]:
            o.append(num_to_var_int(witness["number"]) + (witness["scriptCode"] if witness["scriptCode"] else bytes()))
    o.append(encode_4_bytes(txobj["locktime"]))
    return list_to_bytes(o)


def uahf_digest(txobj: Tx, i: int) -> bytes:
    for inp in txobj['ins']:
        inp.pop('address', None)
    if isinstance(txobj, bytes):
        txobj = bytes_to_hex_string(txobj)
    o = []

    if json_is_base(txobj, 16):
        txobj = json_changebase(txobj, lambda x: binascii.unhexlify(x))
    o.append(encode(txobj["version"], 256, 4)[::-1])

    serialized_ins = []
    for inp in txobj["ins"]:
        serialized_ins.append(inp["tx_hash"][::-1])
        serialized_ins.append(encode_4_bytes(inp["tx_pos"]))
    inputs_hashed = dbl_sha256_list(serialized_ins)
    o.append(inputs_hashed)

    sequences = dbl_sha256_list([encode_4_bytes(inp["sequence"]) for inp in txobj['ins']])
    o.append(sequences)

    inp = txobj['ins'][i]
    o.append(inp["tx_hash"][::-1])
    o.append(encode_4_bytes(inp["tx_pos"]))
    o.append(num_to_var_int(len(inp["script"])) + (inp["script"] if inp["script"] else bytes()))
    o.append(encode_8_bytes(inp['value']))
    o.append(encode_4_bytes(inp['sequence']))

    serialized_outs = []
    for out in txobj["outs"]:
        serialized_outs.append(encode_8_bytes(out["value"]))
        serialized_outs.append(num_to_var_int(len(out["script"])) + out["script"])
    outputs_hashed = dbl_sha256_list(serialized_outs)
    o.append(outputs_hashed)

    o.append(encode_4_bytes(txobj["locktime"]))
    # o.append(b'\x01\x00\x00\x00')
    return list_to_bytes(o)


def signature_form(tx: Union[AnyStr, Tx], i: int, script, hashcode: int = SIGHASH_ALL, segwit: bool = False) -> bytes:
    i, hashcode = int(i), int(hashcode)
    if isinstance(tx, string_or_bytes_types):
        tx = deserialize(tx)
    newtx = deepcopy(tx)
    for j, inp in enumerate(newtx["ins"]):
        if j == i:
            newtx['ins'][j]['script'] = script
        else:
            newtx['ins'][j]['script'] = ""
    if segwit or hashcode & 255 == SIGHASH_ALL + SIGHASH_FORKID:
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
    return None, decode(left, 16), decode(right, 16)


def is_bip66(sig: str) -> bool:
    """Checks hex DER sig for BIP66 consistency"""
    #https://raw.githubusercontent.com/bitcoin/bips/master/bip-0066.mediawiki
    #0x30  [total-len]  0x02  [R-len]  [R]  0x02  [S-len]  [S]  [sighash]
    sig = bytearray.fromhex(sig) if is_hex(sig) else bytearray(sig)
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


def txhash(tx: AnyStr, hashcode: int = None, wtxid: bool = True) -> str:
    if isinstance(tx, str) and re.match('^[0-9a-fA-F]*$', tx):
        tx = changebase(tx, 16, 256)
    if isinstance(tx, string_or_bytes_types):
        segwit = is_segwit(tx)
    else:
        segwit = False
    if not wtxid and segwit:
        tx = serialize(deserialize(tx), include_witness=False)
    if hashcode:
        return dbl_sha256(from_string_to_bytes(tx) + encode(int(hashcode), 256, 4)[::-1])
    else:
        return safe_hexlify(bin_dbl_sha256(tx)[::-1])


def public_txhash(tx: AnyStr, hashcode: int = None) -> str:
    return txhash(tx, hashcode=hashcode, wtxid=False)


def bin_txhash(tx: AnyStr, hashcode: int = None) -> bytes:
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


def mk_pubkey_script(pubkey_hash: str) -> str:
    """
    Used in converting public key hash to input or output script
    """
    return opcodes.OP_DUP.hex() + opcodes.OP_HASH160.hex() + '14' + pubkey_hash + opcodes.OP_EQUALVERIFY.hex() + opcodes.OP_CHECKSIG.hex()


def addr_to_pubkey_script(addr: str) -> str:
    """
    Used in converting public key hash address to input or output script
    """
    magicbyte, bin = b58check_to_hex(addr)
    return mk_pubkey_script(bin)


def mk_p2pk_script(pub: str) -> str:
    """
    Used in converting public key to p2pk script
    """
    length = hex(int(len(pub) / 2)).split('0x')[1]
    return length + pub + opcodes.OP_CHECKSIG.hex()


def script_to_pk(script: str) -> str:
    """
    Used in converting p2pk script to public key
    """
    length = int(script[0:2], 16)
    return script[2: (length + 1) * 2]


def hash_to_scripthash_script(hashbin: str) -> str:
    return opcodes.OP_HASH160.hex() + '14' + hashbin + opcodes.OP_EQUAL.hex()


def mk_scripthash_script(addr: str):
    """
    Used in converting p2sh address to output script
    """
    magicbyte, hashbin = b58check_to_hex(addr)
    return hash_to_scripthash_script(hashbin)


def output_script_to_address(script, magicbyte: int = 0, script_magicbyte: int = 5,
                             segwit_hrp: str = None, cash_hrp: str = None ) -> AnyStr:
    if script.startswith('76a914') and script.endswith('88ac'):
        script = script[6:][:-4]
        return bin_to_b58check(safe_from_hex(script), magicbyte=magicbyte)
    elif script.startswith('a914') and script.endswith('87'):
        script = script[4:][:-2]
        return bin_to_b58check(safe_from_hex(script), magicbyte=script_magicbyte)
    elif script.startswith('0') and segwit_hrp:
        return decode_p2w_scripthash_script(script, 0, segwit_hrp)
    elif script.startswith('0') and cash_hrp:
        return decode_cash_scripthash_script(script, 0, cash_hrp)
    elif script.startswith('6a'):
        return binascii.unhexlify("Arbitrary Data: %s" % script[2:].decode('utf-8', 'ignore'))
    raise Exception('Unable to convert script to an address: %s' % script)


def decode_p2w_scripthash_script(script, witver, segwit_hrp):
    witprog = safe_from_hex(script[4:])
    return segwit_addr.encode_segwit_address(segwit_hrp, witver, witprog)


def decode_cash_scripthash_script(script, witver, hrp):
    witprog = safe_from_hex(script[4:])
    return cashaddr.encode(hrp, witver, witprog)


def mk_p2w_scripthash_script(witver: int, witprog: List[int]) -> str:
    """
    Used in converting a decoded pay to witness script hash address to output script
    """
    assert (0 <= witver <= 16)
    OP_n = witver + int(opcodes.OP_RESERVED) if witver > 0 else 0
    length = len(witprog)
    len_hex = hex(length).split('0x')[1]
    return bytes_to_hex_string([OP_n]) + len_hex + (bytes_to_hex_string(witprog))


def mk_p2wpkh_redeemscript(pubkey: str) -> str:
    """
    Used in converting public key to p2wpkh script
    """
    return '16' + opcodes.OP_0.hex() + '14' + pubkey_to_hash_hex(pubkey)


def mk_p2wpkh_script(pubkey: str) -> str:
    """
    Used in converting public key to p2wpkh script
    """
    script = mk_p2wpkh_redeemscript(pubkey)[2:]
    return opcodes.OP_HASH160.hex() + '14' + hex_to_hash160(script) + opcodes.OP_EQUAL.hex()


def mk_p2wpkh_scriptcode(pubkey):
    """
    Used in signing for tx inputs
    """
    return opcodes.OP_DUP.hex() + opcodes.OP_HASH160.hex() + '14' + pubkey_to_hash_hex(
        pubkey) + opcodes.OP_EQUALVERIFY.hex() + opcodes.OP_CHECKSIG.hex()


def p2wpkh_nested_script(pubkey):
    return opcodes.OP_0.hex() + '14' + hash160(safe_from_hex(pubkey))

# Output script to address representation


def deserialize_script(script):
    if isinstance(script, str) and is_hex(script):
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


def serialize_script(script) -> AnyStr:
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
    return serialize_script([M]+pubs+[N]+[opcodes.OP_CHECKMULTISIG])


# Signing and verifying

def verify_tx_input(tx, i, script, sig, pub):
    if is_hex(tx):
        tx = binascii.unhexlify(tx)
    if is_hex(script):
        script = binascii.unhexlify(script)
    if isinstance(script, string_types) and is_hex(script):
        sig = safe_hexlify(sig)
    hashcode = decode(sig[-2:], 16)
    modtx = signature_form(tx, int(i), script, hashcode)
    return ecdsa_tx_verify(modtx, sig, pub, hashcode)


def multisign(tx, i: int, script, pk, hashcode: int = SIGHASH_ALL, segwit: bool = False):
    modtx = signature_form(tx, i, script, hashcode, segwit=segwit)
    return ecdsa_tx_sign(modtx, pk, hashcode)


def apply_multisignatures(txobj: Union[Tx, str], i: int, script, *args, segwit: bool = False):
    # tx,i,script,sigs OR tx,i,script,sig1,sig2...,sig[n]
    sigs = args[0] if isinstance(args[0], list) else list(args)

    if isinstance(script, str) and re.match('^[0-9a-fA-F]*$', script):
        script = binascii.unhexlify(script)
    sigs = [binascii.unhexlify(x) if x[:2] == '30' else x for x in sigs]
    if not isinstance(txobj, dict):
        txobj = deserialize(txobj)
    if isinstance(txobj, str) and re.match('^[0-9a-fA-F]*$', txobj):
        return safe_hexlify(serialize(apply_multisignatures(binascii.unhexlify(txobj), i, script, sigs)))

    if not isinstance(txobj, dict):
        txobj = deserialize(txobj)

    if segwit:
        if 'witness' not in txobj.keys():
            txobj.update({"marker": 0, "flag": 1, "witness": []})
            for _ in range(0, i):
                witness: Witness = {"number": 0, "scriptCode": ''}
                # Pycharm IDE gives a type error for the following line, no idea why...
                # noinspection PyTypeChecker
                txobj["witness"].append(witness)
        txobj["ins"][i]["script"] = ''
        number = len(sigs) + 2
        scriptSig = safe_hexlify(serialize_script([None] + sigs + [len(script)] + deserialize_script(script)))
        witness: Witness = {"number": number, "scriptCode": scriptSig}
        # Pycharm IDE gives a type error for the following line, no idea why...
        # noinspection PyTypeChecker
        txobj["witness"].append(witness)
    else:
        # Not pushing empty elements on the top of the stack if passing no
        # script (in case of bare multisig inputs there is no script)
        script_blob = [] if script.__len__() == 0 else [script]
        scriptSig = safe_hexlify(serialize_script([None] + sigs + script_blob))
        txobj["ins"][i]["script"] = scriptSig
        if "witness" in txobj.keys():
            witness: Witness = {"number": 0, "scriptCode": ''}
            # Pycharm IDE gives a type error for the following line, no idea why...
            # noinspection PyTypeChecker
            txobj["witness"].append(witness)
    return txobj


def select(unspents, value: int):
    value = int(value)
    high = [u for u in unspents if u["value"] >= value]
    high.sort(key=lambda u: u["value"])
    low = [u for u in unspents if u["value"] < value]
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

