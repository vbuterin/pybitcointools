#!/usr/bin/env python2
# -*- mode: python -*-
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2016  The Electrum developers with changes by pycryptotools developers
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

from unicodedata import normalize

from .wallet_utils import pw_encode, pw_decode, hfu, InvalidPassword
from .mnemonic import *
from .deterministic import *
from .main import *



class KeyStore(object):

    def __init__(self, coin, addresses=()):
        self.coin=coin
        self.addresses = list(addresses)
        self.root_derivation = None
        self.bip39_prefixes = ()
        self.xtype = ''
        self.electrum = False

    def has_seed(self):
        return False

    def is_watching_only(self):
        return False

    def can_import(self):
        return False

    def get_tx_derivations(self, tx):
        keypairs = {}
        for txin in tx.inputs():
            num_sig = txin.get('num_sig')
            if num_sig is None:
                continue
            x_signatures = txin['signatures']
            signatures = [sig for sig in x_signatures if sig]
            if len(signatures) == num_sig:
                # input is complete
                continue
            for k, x_pubkey in enumerate(txin['x_pubkeys']):
                if x_signatures[k] is not None:
                    # this pubkey already signed
                    continue
                derivation = self.get_pubkey_derivation(x_pubkey)
                if not derivation:
                    continue
                keypairs[x_pubkey] = derivation
        return keypairs

    def can_sign(self, tx):
        if self.is_watching_only():
            return False
        return bool(self.get_tx_derivations(tx))



class Software_KeyStore(KeyStore):

    def may_have_password(self):
        return not self.is_watching_only()

    """TODO
    def sign_message(self, sequence, message, password=None):
        privkey, compressed = self.get_private_key(sequence, password)
        return ecdsa_raw_sign(message, privkey)

    def decrypt_message(self, sequence, message, password=None):
        privkey, compressed = self.get_private_key(sequence, password)
        return ecdsa_raw_recover(message)

    def sign_transaction(self, tx, password=None):
        if self.is_watching_only():
            return
        # Raise if password is not correct.
        self.check_password(password)
        # Add private keys
        keypairs = self.get_tx_derivations(tx)
        for k, v in keypairs.items():
            keypairs[k] = self.get_private_key(v, password)
        # Sign
        if keypairs:
            tx.sign(keypairs)"""


class Imported_KeyStore(Software_KeyStore):
    # keystore for imported private keys

    def __init__(self, d, coin):
        Software_KeyStore.__init__(self, coin)
        self.keypairs = d.get('keypairs', {})

    def is_deterministic(self):
        return False

    def can_change_password(self):
        return True

    def get_master_public_key(self):
        return None

    def dump(self):
        return {
            'type': 'imported',
            'keypairs': self.keypairs,
        }

    def can_import(self):
        return True

    def check_password(self, password=None):
        pubkey = list(self.keypairs.keys())[0]
        self.get_private_key(pubkey, password)

    def import_privkey(self, sec, password=None):
        pubkey = bip32_privtopub(sec, self.bip39_prefixes)
        self.keypairs[pubkey] = pw_encode(sec, password)
        return "p2pkh", pubkey

    def delete_imported_key(self, key):
        self.keypairs.pop(key)

    def get_private_key(self, pubkey, password=None):
        sec = pw_decode(self.keypairs[pubkey], password)
        privkey = bip32_extract_key(sec, self.bip39_prefixes)
        # this checks the password
        if pubkey != privtopub(privkey):
            raise InvalidPassword()
        return privkey, True

    def get_pubkey_derivation(self, x_pubkey):
        if get_pubkey_format(x_pubkey) in ['bin', 'bin_compressed']:
            if x_pubkey in self.keypairs.keys():
                return x_pubkey
        elif x_pubkey[0:2] == 'fd':
            addr = self.coin.p2sh_scriptaddr(x_pubkey[2:])
            if addr in self.addresses:
                return self.addresses[addr].get('pubkey')

    def update_password(self, old_password, new_password):
        self.check_password(old_password)
        if new_password == '':
            new_password = None
        for k, v in self.keypairs.items():
            b = pw_decode(v, old_password)
            c = pw_encode(b, new_password)
            self.keypairs[k] = c



class Deterministic_KeyStore(Software_KeyStore):

    def __init__(self, d, coin):
        Software_KeyStore.__init__(self, coin)
        self.seed = d.get('seed', '')
        self.passphrase = d.get('passphrase', '')

    def is_deterministic(self):
        return True

    def dump(self):
        d = {}
        if self.seed:
            d['seed'] = self.seed
        if self.passphrase:
            d['passphrase'] = self.passphrase
        return d

    def has_seed(self):
        return bool(self.seed)

    def is_watching_only(self):
        return not self.has_seed()

    def can_change_password(self):
        return not self.is_watching_only()

    def add_seed(self, seed):
        if self.seed:
            raise Exception("a seed exists")
        self.seed = self.format_seed(seed)

    def get_seed(self, password):
        return pw_decode(self.seed, password)

    def get_passphrase(self, password):
        return pw_decode(self.passphrase, password) if self.passphrase else ''


class Xpub:

    def __init__(self):
        self.xpub = None
        self.xpub_receive = None
        self.xpub_change = None

    def get_master_public_key(self):
        return self.xpub

    def derive_pubkey(self, for_change, n):
        xpub = self.xpub_change if for_change else self.xpub_receive
        if xpub is None:
            xpub = bip32_ckd(self.xpub, 1 if for_change else 0, self.bip39_prefixes)
            if for_change:
                self.xpub_change = xpub
            else:
                self.xpub_receive = xpub
        return self.get_pubkey_from_xpub(xpub, (n,), self.bip39_prefixes)

    @classmethod
    def get_pubkey_from_xpub(self, xpub, sequence, bip39_prefixes):
        return bip32_derive_key(xpub, sequence, bip39_prefixes)

    """needed?
    def get_xpubkey(self, c, i):
        s = ''.join(map(lambda x: bitcoin.int_to_hex(x,2), (c, i)))
        return 'ff' + bh2u(b58check_to_hex(self.xpub)) + s

    @classmethod
    def parse_xpubkey(self, pubkey):
        assert pubkey[0:2] == 'ff'
        pk = bfh(pubkey)
        pk = pk[1:]
        xkey = bin_to_b58check(pk[0:78])
        dd = pk[78:]
        s = []
        while dd:
            n = int(bitcoin.rev_hex(bh2u(dd[0:2])), 16)
            dd = dd[2:]
            s.append(n)
        assert len(s) == 2
        return xkey, s

    def get_pubkey_derivation(self, x_pubkey):
        if x_pubkey[0:2] != 'ff':
            return
        xpub, derivation = self.parse_xpubkey(x_pubkey)
        if self.xpub != xpub:
            return
        return derivation"""


class BIP32_KeyStore(Deterministic_KeyStore, Xpub):

    def __init__(self, d, coin):
        Xpub.__init__(self)
        Deterministic_KeyStore.__init__(self, d, coin)
        self.xpub = d.get('xpub')
        self.xprv = d.get('xprv')

    def format_seed(self, seed):
        return ' '.join(seed.split())

    def dump(self):
        d = Deterministic_KeyStore.dump(self)
        d['type'] = 'bip32'
        d['xpub'] = self.xpub
        d['xprv'] = self.xprv
        return d

    def get_master_private_key(self, password=None):
        return pw_decode(self.xprv, password)

    def check_password(self, password=None):
        xprv = pw_decode(self.xprv, password)
        if bip32_deserialize(xprv, self.bip39_prefixes)[4] != bip32_deserialize(self.xpub, self.bip39_prefixes)[4]:
            raise InvalidPassword()

    def update_password(self, old_password, new_password,):
        self.check_password(old_password)
        if new_password == '':
            new_password = None
        if self.has_seed():
            decoded = self.get_seed(old_password)
            self.seed = pw_encode(decoded, new_password)
        if self.passphrase:
            decoded = self.get_passphrase(old_password)
            self.passphrase = pw_encode(decoded, new_password)
        if self.xprv is not None:
            b = pw_decode(self.xprv, old_password)
            self.xprv = pw_encode(b, new_password)

    def is_watching_only(self):
        return self.xprv is None

    def add_xprv(self, xprv):
        self.xprv = xprv
        self.xpub = bip32_privtopub(xprv, self.bip39_prefixes)

    def add_xpub(self, xpub, xtype, electrum=False):
        self.xtype = xtype
        self.electrum = electrum
        self.bip39_prefixes = (encode(self.coin.electrum_xprv_headers[xtype], 256, 4),
                               encode(self.coin.electrum_xpub_headers[xtype], 256, 4)) if electrum else (
        encode(self.coin.xprv_headers[xtype], 256, 4), encode(self.coin.xpub_headers[xtype], 256, 4))
        self.xpub = xpub

    def add_xprv_from_seed(self, bip32_seed, xtype, derivation, electrum=False):
        self.root_derivation = derivation
        self.xtype = xtype
        self.electrum = electrum
        self.bip39_prefixes = (encode(self.coin.electrum_xprv_headers[xtype], 256, 4),
                               encode(self.coin.electrum_xpub_headers[xtype], 256, 4)) if electrum else (
        encode(self.coin.xprv_headers[xtype], 256, 4), encode(self.coin.xpub_headers[xtype], 256, 4))
        xprv = bip32_master_key(bip32_seed, self.bip39_prefixes)
        xprv = bip32_ckd(xprv, derivation, self.bip39_prefixes)
        self.add_xprv(xprv)

    def get_private_key(self, sequence, password):
        xprv = self.get_master_private_key(password)
        pk = bip32_derive_key(xprv, sequence, self.bip39_prefixes)
        return pk, True


class Hardware_KeyStore(KeyStore, Xpub):
    # Derived classes must set:
    #   - device
    #   - DEVICE_IDS
    #   - wallet_type

    #restore_wallet_class = BIP32_RD_Wallet
    max_change_outputs = 1

    def __init__(self, d, coin):
        Xpub.__init__(self, coin)
        KeyStore.__init__(self, coin)
        # Errors and other user interaction is done through the wallet's
        # handler.  The handler is per-window and preserved across
        # device reconnects
        self.xpub = d.get('xpub')
        self.label = d.get('label')
        self.derivation = d.get('derivation')
        self.handler = None

    def set_label(self, label):
        self.label = label

    def may_have_password(self):
        return False

    def is_deterministic(self):
        return True

    def dump(self):
        return {
            'type': 'hardware',
            'hw_type': self.hw_type,
            'xpub': self.xpub,
            'derivation':self.derivation,
            'label':self.label,
        }

    def unpaired(self):
        '''A device paired with the wallet was diconnected.  This can be
        called in any thread context.'''
        print("unpaired")

    def paired(self):
        '''A device paired with the wallet was (re-)connected.  This can be
        called in any thread context.'''
        print("paired")

    def can_export(self):
        return False

    def is_watching_only(self):
        '''The wallet is not watching-only; the user will be prompted for
        pin and passphrase as appropriate when needed.'''
        assert not self.has_seed()
        return False

    def can_change_password(self):
        return False

def bip39_to_seed(mnemonic, passphrase):
    return mnemonic_to_seed(mnemonic, passphrase)

# returns tuple (is_checksum_valid, is_wordlist_valid)
def bip39_is_checksum_valid(mnemonic):
    words = [ normalize('NFKD', word) for word in mnemonic.split()]
    words_len = len(words)
    wordlist = wordlist_english
    n = len(wordlist)
    checksum_length = 11*words_len//33
    entropy_length = 32*checksum_length
    i = 0
    words.reverse()
    while words:
        w = words.pop()
        try:
            k = wordlist.index(w)
        except ValueError:
            return False, False
        i = i*n + k
    if words_len not in [12, 15, 18, 21, 24]:
        return False, True
    entropy = i >> checksum_length
    checksum = i % 2**checksum_length
    h = '{:x}'.format(entropy)
    while len(h) < entropy_length/4:
        h = '0'+h
    b = bytearray.fromhex(h)
    hashed = int(hfu(hashlib.sha256(b).digest()), 16)
    calculated_checksum = hashed >> (256 - checksum_length)
    return checksum == calculated_checksum, True

def from_bip39_seed(seed, passphrase, derivation, coin):
    k = BIP32_KeyStore({}, coin)
    bip32_seed = bip39_to_seed(seed, passphrase)
    xtype = xtype_from_derivation(derivation)
    k.add_xprv_from_seed(bip32_seed, xtype, derivation)
    return k

def standard_from_bip39_seed(seed, passphrase, coin):
    derivation = "m/44'/%s'/0'" % coin.hd_path
    return from_bip39_seed(seed, passphrase, derivation, coin)

def p2wpkh_from_bip39_seed(seed, passphrase, coin):
    derivation = "m/84'/%s'/0'" % coin.hd_path
    return from_bip39_seed(seed, passphrase, derivation, coin)

def p2wpkh_p2sh_from_bip39_seed(seed, passphrase, coin):
    derivation = "m/49'/%s'/0'" % coin.hd_path
    return from_bip39_seed(seed, passphrase, derivation, coin)


def xtype_from_derivation(derivation):
    """Returns the script type to be used for this derivation."""
    if derivation.startswith("m/84'"):
        return 'p2wpkh'
    elif derivation.startswith("m/49'"):
        return 'p2wpkh-p2sh'
    else:
        return 'p2pkh'


# extended pubkeys

def is_xpubkey(x_pubkey):
    return x_pubkey[0:2] == 'ff'


def parse_xpubkey(x_pubkey):
    assert x_pubkey[0:2] == 'ff'
    return BIP32_KeyStore.parse_xpubkey(x_pubkey)


def xpubkey_to_address(x_pubkey, coin):
    if x_pubkey[0:2] == 'fd':
        address = coin.p2sh_scriptaddr(x_pubkey[2:])
        return x_pubkey, address
    if x_pubkey[0:2] in ['02', '03', '04']:
        pubkey = x_pubkey
    elif x_pubkey[0:2] == 'ff':
        xpub, s = BIP32_KeyStore.parse_xpubkey(x_pubkey)
        pubkey = BIP32_KeyStore.get_pubkey_from_xpub(xpub, s)
    else:
        raise BaseException("Cannot parse pubkey")
    address = coin.pubtoaddr(pubkey)
    return pubkey, address

def xpubkey_to_pubkey(x_pubkey, coin):
    pubkey, address = xpubkey_to_address(x_pubkey, coin)
    return pubkey

hw_keystores = {}

def register_keystore(hw_type, constructor):
    hw_keystores[hw_type] = constructor

def hardware_keystore(d):
    hw_type = d['hw_type']
    if hw_type in hw_keystores:
        constructor = hw_keystores[hw_type]
        return constructor(d)
    raise BaseException('unknown hardware type', hw_type)

def is_address_list(text, coin):
    parts = text.split()
    return bool(parts) and all(coin.is_address(x) for x in parts)


def get_private_keys(text):
    parts = text.split('\n')
    parts = map(lambda x: ''.join(x.split()), parts)
    parts = list(filter(bool, parts))
    if bool(parts) and all(bitcoin.is_private_key(x) for x in parts):
        return parts

def is_private_key_list(text):
    return bool(get_private_keys(text))

is_mpk = lambda x: is_xpub(x)
is_private = lambda x: is_seed(x) or is_xprv(x) or is_private_key_list(x)
is_master_key = lambda x: is_xprv(x) or is_xpub(x)
is_private_key = lambda x: is_xprv(x) or is_private_key_list(x)
is_bip32_key = lambda x: is_xprv(x) or is_xpub(x)


def from_electrum_seed(seed, passphrase, is_p2sh, coin):
    t = seed_type(seed)
    if t in ['standard', 'segwit']:
        keystore = BIP32_KeyStore({}, coin)
        keystore.add_seed(seed)
        keystore.passphrase = passphrase
        bip32_seed = electrum_mnemonic_to_seed(seed, passphrase)
        if t == 'standard':
            der = "m/"
            xtype = 'p2pkh'
        else:
            der = "m/1'/" if is_p2sh else "m/0'/"
            xtype = 'p2wsh' if is_p2sh else 'p2wpkh'
        keystore.add_xprv_from_seed(bip32_seed, xtype, der, electrum=True)
    else:
        raise BaseException(t)
    return keystore

def from_private_key_list(text, coin):
    keystore = Imported_KeyStore({}, coin)
    for x in get_private_keys(text):
        keystore.import_key(x, None)
    return keystore

def from_xpub(xpub, coin, xtype, electrum=False):
    k = BIP32_KeyStore({}, coin)
    k.add_xpub(xpub, xtype, electrum=electrum)
    return k

def from_xprv(xprv, coin):
    xpub = bip32_privtopub(xprv, coin.bip39_prefixes)
    k = BIP32_KeyStore({}, coin)
    k.xprv = xprv
    k.xpub = xpub
    return k

def from_master_key(text, coin):
    prefixes = coin.bip39_prefixes
    if is_xprv(text, prefixes):
        k = from_xprv(text, coin)
    elif is_xpub(text, prefixes):
        k = from_xpub(text, coin)
    else:
        raise BaseException('Invalid key')
    return k
