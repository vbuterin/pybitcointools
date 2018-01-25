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
from .py2specials import *
from .py3specials import *
from . import constants as version

# Version numbers for BIP32 extended keys
# standard: xprv, xpub
# segwit in p2sh: yprv, ypub
# native segwit: zprv, zpub
XPRV_HEADERS = {
    'standard': 0x0488ade4,
    'p2wpkh-p2sh': 0x049d7878,
    'p2wsh-p2sh': 0x295b005,
    'p2wpkh': 0x4b2430c,
    'p2wsh': 0x2aa7a99
}
XPUB_HEADERS = {
    'standard': 0x0488b21e,
    'p2wpkh-p2sh': 0x049d7cb2,
    'p2wsh-p2sh': 0x295b43f,
    'p2wpkh': 0x4b24746,
    'p2wsh': 0x2aa7ed3
}

bh2u = safe_hexlify
hfu = binascii.hexlify
bfh = safe_from_hex
hmac_sha_512 = lambda x, y: hmac.new(x, y, hashlib.sha512).digest()

def rev_hex(s):
    return bh2u(bfh(s)[::-1])

def int_to_hex(i, length=1):
    assert isinstance(i, int)
    s = hex(i)[2:].rstrip('L')
    s = "0"*(2*length - len(s)) + s
    return rev_hex(s)

class InvalidPassword(Exception):
    def __str__(self):
        return "Incorrect password"

try:
    from Cryptodome.Cipher import AES
except:
    AES = None

class InvalidPasswordException(Exception):
    pass

class InvalidPadding(Exception):
    pass

def assert_bytes(*args):
    """
    porting helper, assert args type
    """
    try:
        for x in args:
            assert isinstance(x, (bytes, bytearray))
    except:
        print('assert bytes failed', list(map(type, args)))
        raise

def append_PKCS7_padding(data):
    assert_bytes(data)
    padlen = 16 - (len(data) % 16)
    return data + bytes([padlen]) * padlen


def strip_PKCS7_padding(data):
    assert_bytes(data)
    if len(data) % 16 != 0 or len(data) == 0:
        raise InvalidPadding("invalid length")
    padlen = data[-1]
    if padlen > 16:
        raise InvalidPadding("invalid padding byte (large)")
    for i in data[-padlen:]:
        if i != padlen:
            raise InvalidPadding("invalid padding byte (inconsistent)")
    return data[0:-padlen]

def aes_encrypt_with_iv(key, iv, data):
    assert_bytes(key, iv, data)
    data = append_PKCS7_padding(data)
    if AES:
        e = AES.new(key, AES.MODE_CBC, iv).encrypt(data)
    else:
        aes_cbc = pyaes.AESModeOfOperationCBC(key, iv=iv)
        aes = pyaes.Encrypter(aes_cbc, padding=pyaes.PADDING_NONE)
        e = aes.feed(data) + aes.feed()  # empty aes.feed() flushes buffer
    return e


def aes_decrypt_with_iv(key, iv, data):
    assert_bytes(key, iv, data)
    if AES:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        data = cipher.decrypt(data)
    else:
        aes_cbc = pyaes.AESModeOfOperationCBC(key, iv=iv)
        aes = pyaes.Decrypter(aes_cbc, padding=pyaes.PADDING_NONE)
        data = aes.feed(data) + aes.feed()  # empty aes.feed() flushes buffer
    try:
        return strip_PKCS7_padding(data)
    except InvalidPadding:
        raise InvalidPassword()

def EncodeAES(secret, s):
    assert_bytes(s)
    iv = bytes(os.urandom(16))
    ct = aes_encrypt_with_iv(secret, iv, s)
    e = iv + ct
    return base64.b64encode(e)

def DecodeAES(secret, e):
    e = bytes(base64.b64decode(e))
    iv, e = e[:16], e[16:]
    s = aes_decrypt_with_iv(secret, iv, e)
    return s

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
    x = mnemonic.normalize_text(x)
    s = bh2u(hmac_sha_512(b"Seed version", x.encode('utf8')))
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

__b58chars = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
assert len(__b58chars) == 58

__b43chars = b'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ$*+-./:'
assert len(__b43chars) == 43

def inv_dict(d):
    return {v: k for k, v in d.items()}

def is_minikey(text):
    # Minikeys are typically 22 or 30 characters, but this routine
    # permits any length of 20 or more provided the minikey is valid.
    # A valid minikey must begin with an 'S', be in base58, and when
    # suffixed with '?' have its SHA256 hash begin with a zero byte.
    # They are widely used in Casascius physical bitcoins.
    return (len(text) >= 20 and text[0] == 'S'
            and all(ord(c) in __b58chars for c in text)
            and sha256(text + '?')[0] == 0x00)

def minikey_to_private_key(text):
    return sha256(text)


###################################### BIP32 ##############################

BIP32_PRIME = 0x80000000


def get_pubkeys_from_secret(secret):
    # public key
    pubkey = compress(privtopub(secret))
    return pubkey, True

def xprv_header(xtype):
    return bfh("%08x" % XPRV_HEADERS[xtype])


def xpub_header(xtype):
    return bfh("%08x" % XPUB_HEADERS[xtype])