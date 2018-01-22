from .main import *
import hmac
import hashlib

# Electrum wallets


def electrum_stretch(seed):
    return slowsha(seed)

# Accepts seed or stretched seed, returns master public key


def electrum_mpk(seed):
    if len(seed) == 32:
        seed = electrum_stretch(seed)
    return privkey_to_pubkey(seed)[2:]

# Accepts (seed or stretched seed), index and secondary index
# (conventionally 0 for ordinary addresses, 1 for change) , returns privkey


def electrum_privkey(seed, n, for_change=0):
    if len(seed) == 32:
        seed = electrum_stretch(seed)
    mpk = electrum_mpk(seed)
    offset = dbl_sha256(from_int_representation_to_bytes(n)+b':'+from_int_representation_to_bytes(for_change)+b':'+binascii.unhexlify(mpk))
    return add_privkeys(seed, offset)

# Accepts (seed or stretched seed or master pubkey), index and secondary index
# (conventionally 0 for ordinary addresses, 1 for change) , returns pubkey


def electrum_pubkey(masterkey, n, for_change=0):
    if len(masterkey) == 32:
        mpk = electrum_mpk(electrum_stretch(masterkey))
    elif len(masterkey) == 64:
        mpk = electrum_mpk(masterkey)
    else:
        mpk = masterkey
    bin_mpk = encode_pubkey(mpk, 'bin_electrum')
    offset = bin_dbl_sha256(from_int_representation_to_bytes(n)+b':'+from_int_representation_to_bytes(for_change)+b':'+bin_mpk)
    return add_pubkeys('04'+mpk, privtopub(offset))

# seed/stretched seed/pubkey -> address (convenience method)


def electrum_address(masterkey, n, for_change=0, magicbyte=0):
    return pubkey_to_address(electrum_pubkey(masterkey, n, for_change), magicbyte)

# Given a master public key, a private key from that wallet and its index,
# cracks the secret exponent which can be used to generate all other private
# keys in the wallet


def crack_electrum_wallet(mpk, pk, n, for_change=0):
    bin_mpk = encode_pubkey(mpk, 'bin_electrum')
    offset = dbl_sha256(str(n)+':'+str(for_change)+':'+bin_mpk)
    return subtract_privkeys(pk, offset)

# Below code ASSUMES binary inputs and compressed pubkeys
MAINNET_PRIVATE = b'\x04\x88\xAD\xE4'
MAINNET_PUBLIC = b'\x04\x88\xB2\x1E'
TESTNET_PRIVATE = b'\x04\x35\x83\x94'
TESTNET_PUBLIC = b'\x04\x35\x87\xCF'
PRIVATE = [MAINNET_PRIVATE, TESTNET_PRIVATE]
PUBLIC = [MAINNET_PUBLIC, TESTNET_PUBLIC]
DEFAULT = (MAINNET_PRIVATE, MAINNET_PUBLIC)

# BIP32 child key derivation


def raw_bip32_ckd(rawtuple, i, prefixes=DEFAULT):
    vbytes, depth, fingerprint, oldi, chaincode, key = rawtuple
    i = int(i)

    private = vbytes == prefixes[0]

    if private:
        priv = key
        pub = privtopub(key)
    else:
        priv = None
        pub = key

    if i >= 2**31:
        if not priv:
            raise Exception("Can't do private derivation on public key!")
        I = hmac.new(chaincode, b'\x00'+priv[:32]+encode(i, 256, 4), hashlib.sha512).digest()
    else:
        I = hmac.new(chaincode, pub+encode(i, 256, 4), hashlib.sha512).digest()
    if private:
        newkey = add_privkeys(I[:32]+B'\x01', priv)
        fingerprint = bin_hash160(privtopub(key))[:4]
    else:
        newkey = add_pubkeys(compress(privtopub(I[:32])), key)
        fingerprint = bin_hash160(key)[:4]

    return (vbytes, depth + 1, fingerprint, i, I[32:], newkey)


def bip32_serialize(rawtuple, prefixes=DEFAULT):
    vbytes, depth, fingerprint, i, chaincode, key = rawtuple
    i = encode(i, 256, 4)
    chaincode = encode(hash_to_int(chaincode), 256, 32)
    keydata = b'\x00'+key[:-1] if vbytes == prefixes[0] else key
    bindata = vbytes + from_int_to_byte(depth % 256) + fingerprint + i + chaincode + keydata
    return changebase(bindata+bin_dbl_sha256(bindata)[:4], 256, 58)


def bip32_deserialize(data, prefixes=DEFAULT):
    dbin = changebase(data, 58, 256)
    if bin_dbl_sha256(dbin[:-4])[:4] != dbin[-4:]:
        raise Exception("Invalid checksum")
    vbytes = dbin[0:4]
    depth = from_byte_to_int(dbin[4])
    fingerprint = dbin[5:9]
    i = decode(dbin[9:13], 256)
    chaincode = dbin[13:45]
    key = dbin[46:78]+b'\x01' if vbytes == prefixes[0] else dbin[45:78]
    return (vbytes, depth, fingerprint, i, chaincode, key)


def is_xprv(text, prefixes=DEFAULT):
    vbytes, depth, fingerprint, i, chaincode, key = bip32_deserialize(text, prefixes)
    return vbytes == prefixes[0]


def is_xpub(text, prefixes=DEFAULT):
    vbytes, depth, fingerprint, i, chaincode, key = bip32_deserialize(text, prefixes)
    return vbytes == prefixes[1]


def raw_bip32_privtopub(rawtuple, prefixes=DEFAULT):
    vbytes, depth, fingerprint, i, chaincode, key = rawtuple
    newvbytes = prefixes[1]
    return (newvbytes, depth, fingerprint, i, chaincode, privtopub(key))


def bip32_privtopub(data, prefixes=DEFAULT):
    return bip32_serialize(raw_bip32_privtopub(bip32_deserialize(data, prefixes), prefixes), prefixes)


def bip32_ckd(key, path, prefixes=DEFAULT, public=False):
    if isinstance(path, (list, tuple)):
        pathlist = map(str, path)
    else:
        path = str(path)
        pathlist = parse_bip32_path(path)
    for i, p in enumerate(pathlist):
        key = bip32_serialize(raw_bip32_ckd(bip32_deserialize(key, prefixes), p, prefixes), prefixes)
    return key if not public else bip32_privtopub(key)

def bip32_master_key(seed, prefixes=DEFAULT):
    I = hmac.new(
            from_string_to_bytes("Bitcoin seed"), 
            from_string_to_bytes(seed), 
            hashlib.sha512
        ).digest()
    return bip32_serialize((prefixes[0], 0, b'\x00'*4, 0, I[32:], I[:32]+b'\x01'), prefixes)


def bip32_bin_extract_key(data, prefixes=DEFAULT):
    return bip32_deserialize(data, prefixes)[-1]


def bip32_extract_key(data, prefixes=DEFAULT):
    return safe_hexlify(bip32_deserialize(data, prefixes)[-1])


def bip32_derive_key(key, path, prefixes=DEFAULT, **kwargs):
    return bip32_extract_key(bip32_ckd(key, path, prefixes, **kwargs), prefixes)

# Exploits the same vulnerability as above in Electrum wallets
# Takes a BIP32 pubkey and one of the child privkeys of its corresponding
# privkey and returns the BIP32 privkey associated with that pubkey


def raw_crack_bip32_privkey(parent_pub, priv, prefixes=DEFAULT):
    vbytes, depth, fingerprint, i, chaincode, key = priv
    pvbytes, pdepth, pfingerprint, pi, pchaincode, pkey = parent_pub
    i = int(i)

    if i >= 2**31:
        raise Exception("Can't crack private derivation!")

    I = hmac.new(pchaincode, pkey+encode(i, 256, 4), hashlib.sha512).digest()

    pprivkey = subtract_privkeys(key, I[:32]+b'\x01')

    newvbytes = prefixes[0]
    return (newvbytes, pdepth, pfingerprint, pi, pchaincode, pprivkey)


def crack_bip32_privkey(parent_pub, priv, prefixes=DEFAULT):
    dsppub = bip32_deserialize(parent_pub, prefixes)
    dspriv = bip32_deserialize(priv, prefixes)
    return bip32_serialize(raw_crack_bip32_privkey(dsppub, dspriv, prefixes), prefixes)


def coinvault_pub_to_bip32(*args, prefixes=DEFAULT):
    if len(args) == 1:
        args = args[0].split(' ')
    vals = map(int, args[34:])
    I1 = ''.join(map(chr, vals[:33]))
    I2 = ''.join(map(chr, vals[35:67]))
    return bip32_serialize((prefixes[1], 0, b'\x00'*4, 0, I2, I1))


def coinvault_priv_to_bip32(*args, prefixes=DEFAULT):
    if len(args) == 1:
        args = args[0].split(' ')
    vals = map(int, args[34:])
    I2 = ''.join(map(chr, vals[35:67]))
    I3 = ''.join(map(chr, vals[72:104]))
    return bip32_serialize((prefixes[0], 0, b'\x00'*4, 0, I2, I3+b'\x01'))


def bip32_descend(*args, prefixes=DEFAULT):
    """Descend masterkey and return privkey"""
    if len(args) == 2 and isinstance(args[1], list):
        key, path = args
    elif len(args) == 2 and isinstance(args[1], string_types):
        key = args[0]
        path = map(int, str(args[1]).lstrip("mM/").split('/'))
    elif len(args):
        key, path = args[0], map(int, args[1:])
    for p in path:
        key = bip32_ckd(key, p, prefixes)
    return bip32_extract_key(key, prefixes)

def parse_bip32_path(path):
    """Takes bip32 path, "m/0'/2H" or "m/0H/1/2H/2/1000000000.pub", returns list of ints """
    path = path.lstrip("m/").rstrip(".pub")
    if not path:
        return []
    #elif path.endswith("/"):       incorrect for electrum segwit
    #    path += "0"
    patharr = []
    for v in path.split('/'):
        if not v: 
            continue
        elif v[-1] in ("'H"):  # hardened path
            v = int(v[:-1]) | 0x80000000
        else:                  # non-hardened path
            v = int(v) & 0x7fffffff
        patharr.append(v)
    return patharr
