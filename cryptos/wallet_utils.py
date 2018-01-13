# -*- coding: utf-8 -*-
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2011 thomasv@gitorious with changes by pycryptools developers
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


import hashlib
import hmac
from .main import *
from . import constants as version

b2hu = safe_hexlify
hfu = binascii.hexlify


def pw_encode(s, password):
    if password:
        secret = Hash(password)
        return EncodeAES(secret, to_bytes(s, "utf8")).decode('utf8')
    else:
        return s

def pw_decode(s, password):
    if password is not None:
        secret = Hash(password)
        try:
            d = to_string(DecodeAES(secret, s), "utf8")
        except Exception:
            raise InvalidPassword()
        return d
    else:
        return s

def is_new_seed(x, prefix=version.SEED_PREFIX):
    from . import mnemonic
    s = mnemonic.mnemonic_to_seed(x, passphrase_prefix=b"Seed version")
    return s.startswith(prefix)

def seed_type(x):
    if is_new_seed(x):
        return 'standard'
    elif is_new_seed(x, version.SEED_PREFIX_SW):
        return 'segwit'
    elif is_new_seed(x, version.SEED_PREFIX_2FA):
        return '2fa'
    return ''

is_seed = lambda x: bool(seed_type(x))

SCRIPT_TYPES = {
    'p2pkh':0,
    'p2wpkh':1,
    'p2wpkh-p2sh':2,
    'p2sh':5,
    'p2wsh':6,
    'p2wsh-p2sh':7
}


def serialize_privkey(secret, compressed, txin_type):
    prefix = bytes([(SCRIPT_TYPES[txin_type]+NetworkConstants.WIF_PREFIX)&255])
    suffix = b'\01' if compressed else b''
    vchIn = secret + suffix
    return bin_to_b58check(vchIn, prefix)


def deserialize_privkey(key):
    # whether the pubkey is compressed should be visible from the keystore
    vch = DecodeBase58Check(key)
    if is_minikey(key):
        return 'p2pkh', minikey_to_private_key(key), True
    elif vch:
        txin_type = inv_dict(SCRIPT_TYPES)[vch[0] - NetworkConstants.WIF_PREFIX]
        assert len(vch) in [33, 34]
        compressed = len(vch) == 34
        return txin_type, vch[1:33], compressed
    else:
        raise BaseException("cannot deserialize", key)

def is_private_key(key):
    try:
        k = deserialize_privkey(key)
        return k is not False
    except:
        return False

###################################### BIP32 ##############################

BIP32_PRIME = 0x80000000


def get_pubkeys_from_secret(secret):
    # public key
    private_key = ecdsa.SigningKey.from_string( secret, curve = SECP256k1 )
    public_key = private_key.get_verifying_key()
    K = public_key.to_string()
    K_compressed = GetPubKey(public_key.pubkey,True)
    return K, K_compressed


# Child private key derivation function (from master private key)
# k = master private key (32 bytes)
# c = master chain code (extra entropy for key derivation) (32 bytes)
# n = the index of the key we want to derive. (only 32 bits will be used)
# If n is negative (i.e. the 32nd bit is set), the resulting private key's
#  corresponding public key can NOT be determined without the master private key.
# However, if n is positive, the resulting private key's corresponding
#  public key can be determined without the master private key.
def CKD_priv(k, c, n):
    is_prime = n & BIP32_PRIME
    return _CKD_priv(k, c, bfh(rev_hex(int_to_hex(n,4))), is_prime)


def _CKD_priv(k, c, s, is_prime):
    order = generator_secp256k1.order()
    keypair = EC_KEY(k)
    cK = GetPubKey(keypair.pubkey,True)
    data = bytes([0]) + k + s if is_prime else cK + s
    I = hmac.new(c, data, hashlib.sha512).digest()
    k_n = number_to_string( (string_to_number(I[0:32]) + string_to_number(k)) % order , order )
    c_n = I[32:]
    return k_n, c_n

# Child public key derivation function (from public key only)
# K = master public key
# c = master chain code
# n = index of key we want to derive
# This function allows us to find the nth public key, as long as n is
#  non-negative. If n is negative, we need the master private key to find it.
def CKD_pub(cK, c, n):
    if n & BIP32_PRIME: raise
    return _CKD_pub(cK, c, bfh(rev_hex(int_to_hex(n,4))))

# helper function, callable with arbitrary string
def _CKD_pub(cK, c, s):
    order = generator_secp256k1.order()
    I = hmac.new(c, cK + s, hashlib.sha512).digest()
    curve = SECP256k1
    pubkey_point = string_to_number(I[0:32])*curve.generator + ser_to_point(cK)
    public_key = ecdsa.VerifyingKey.from_public_point( pubkey_point, curve = SECP256k1 )
    c_n = I[32:]
    cK_n = GetPubKey(public_key.pubkey,True)
    return cK_n, c_n


def xprv_header(xtype):
    return bfh("%08x" % XPRV_HEADERS[xtype])


def xpub_header(xtype):
    return bfh("%08x" % XPUB_HEADERS[xtype])


def serialize_xprv(xtype, c, k, depth=0, fingerprint=b'\x00'*4, child_number=b'\x00'*4):
    xprv = xprv_header(xtype) + bytes([depth]) + fingerprint + child_number + c + bytes([0]) + k
    return EncodeBase58Check(xprv)


def serialize_xpub(xtype, c, cK, depth=0, fingerprint=b'\x00'*4, child_number=b'\x00'*4):
    xpub = xpub_header(xtype) + bytes([depth]) + fingerprint + child_number + c + cK
    return EncodeBase58Check(xpub)


def deserialize_xkey(xkey, prv):
    xkey = DecodeBase58Check(xkey)
    if len(xkey) != 78:
        raise BaseException('Invalid length')
    depth = xkey[4]
    fingerprint = xkey[5:9]
    child_number = xkey[9:13]
    c = xkey[13:13+32]
    header = int('0x' + bh2u(xkey[0:4]), 16)
    headers = XPRV_HEADERS if prv else XPUB_HEADERS
    if header not in headers.values():
        raise BaseException('Invalid xpub format', hex(header))
    xtype = list(headers.keys())[list(headers.values()).index(header)]
    n = 33 if prv else 32
    K_or_k = xkey[13+n:]
    return xtype, depth, fingerprint, child_number, c, K_or_k


def deserialize_xpub(xkey):
    return deserialize_xkey(xkey, False)

def deserialize_xprv(xkey):
    return deserialize_xkey(xkey, True)

def xpub_type(x):
    return deserialize_xpub(x)[0]


def is_xpub(text):
    try:
        deserialize_xpub(text)
        return True
    except:
        return False


def is_xprv(text):
    try:
        deserialize_xprv(text)
        return True
    except:
        return False


def xpub_from_xprv(xprv):
    xtype, depth, fingerprint, child_number, c, k = deserialize_xprv(xprv)
    K, cK = get_pubkeys_from_secret(k)
    return serialize_xpub(xtype, c, cK, depth, fingerprint, child_number)


def bip32_root(seed, xtype):
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    master_k = I[0:32]
    master_c = I[32:]
    K, cK = get_pubkeys_from_secret(master_k)
    xprv = serialize_xprv(xtype, master_c, master_k)
    xpub = serialize_xpub(xtype, master_c, cK)
    return xprv, xpub


def xpub_from_pubkey(xtype, cK):
    assert cK[0] in [0x02, 0x03]
    return serialize_xpub(xtype, b'\x00'*32, cK)


def bip32_derivation(s):
    assert s.startswith('m/')
    s = s[2:]
    for n in s.split('/'):
        if n == '': continue
        i = int(n[:-1]) + BIP32_PRIME if n[-1] == "'" else int(n)
        yield i

def is_bip32_derivation(x):
    try:
        [ i for i in bip32_derivation(x)]
        return True
    except :
        return False

def bip32_private_derivation(xprv, branch, sequence):
    assert sequence.startswith(branch)
    if branch == sequence:
        return xprv, xpub_from_xprv(xprv)
    xtype, depth, fingerprint, child_number, c, k = deserialize_xprv(xprv)
    sequence = sequence[len(branch):]
    for n in sequence.split('/'):
        if n == '': continue
        i = int(n[:-1]) + BIP32_PRIME if n[-1] == "'" else int(n)
        parent_k = k
        k, c = CKD_priv(k, c, i)
        depth += 1
    _, parent_cK = get_pubkeys_from_secret(parent_k)
    fingerprint = hash_160(parent_cK)[0:4]
    child_number = bfh("%08X"%i)
    K, cK = get_pubkeys_from_secret(k)
    xpub = serialize_xpub(xtype, c, cK, depth, fingerprint, child_number)
    xprv = serialize_xprv(xtype, c, k, depth, fingerprint, child_number)
    return xprv, xpub


def bip32_public_derivation(xpub, branch, sequence):
    xtype, depth, fingerprint, child_number, c, cK = deserialize_xpub(xpub)
    assert sequence.startswith(branch)
    sequence = sequence[len(branch):]
    for n in sequence.split('/'):
        if n == '': continue
        i = int(n)
        parent_cK = cK
        cK, c = CKD_pub(cK, c, i)
        depth += 1
    fingerprint = hash_160(parent_cK)[0:4]
    child_number = bfh("%08X"%i)
    return serialize_xpub(xtype, c, cK, depth, fingerprint, child_number)


def bip32_private_key(sequence, k, chain):
    for i in sequence:
        k, chain = CKD_priv(k, chain, i)
    return k
